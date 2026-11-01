"""Offline acceptance of split publication, immutable recovery and install smoke."""

from __future__ import annotations

import copy
import email.message
import hashlib
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest
import yaml

from scripts import release_publish as publish
from scripts import smoke_release as smoke
from scripts import verify_release as release

VERSION = "3.0.0"
COMMIT = "a" * 40
CONTROL = "b" * 40
CONTRACT = Path("release/distributions.json")
TRAIN = release.load_distributions(CONTRACT)


@pytest.fixture(autouse=True)
def split_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "DISTRIBUTIONS", TRAIN)


@pytest.fixture
def candidate(tmp_path: Path) -> tuple[Path, dict[str, str], str]:
    root = tmp_path / "candidate"
    (root / "dist").mkdir(parents=True)
    files = {}
    for item in TRAIN:
        for name in release.distribution_names(VERSION, item.name):
            content = name.encode()
            (root / "dist" / name).write_bytes(content)
            files[name] = hashlib.sha256(content).hexdigest()
    manifest = root / "release-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": release.MANIFEST_SCHEMA,
                "version": VERSION,
                "commit": COMMIT,
                "workflow_sha": CONTROL,
                "files": files,
            }
        )
    )
    return root, files, hashlib.sha256(manifest.read_bytes()).hexdigest()


def response(name: str, files: dict[str, str], count: int = 2) -> dict[str, object]:
    return {
        "info": {"name": name, "version": VERSION},
        "urls": [publish.file_entry(n, files[n]) for n in release.distribution_names(VERSION, name)[:count]],
    }


@pytest.mark.parametrize("field", ["commit", "version", "run", "digest", "control"])
def test_dispatch_rejects_missing_or_invalid_approval(field: str) -> None:
    values = {"commit": COMMIT, "version": VERSION, "run": "123", "digest": "c" * 64, "control": CONTROL}
    values[field] = ""
    with pytest.raises(release.VerificationError):
        publish.validate_dispatch(
            values["commit"], values["version"], True, values["run"], values["digest"], values["control"]
        )


def test_fresh_dispatch_has_no_recovery_approvals() -> None:
    publish.validate_dispatch(COMMIT, VERSION, False, "", "", "")
    with pytest.raises(release.VerificationError, match="only valid with resume"):
        publish.validate_dispatch(COMMIT, VERSION, False, "123", "c" * 64, CONTROL)
    with pytest.raises(release.VerificationError, match="split release"):
        publish.validate_dispatch(COMMIT, "2.12.0", False, "", "", "")


@pytest.mark.parametrize("exists", [False, True])
def test_commit_first_binding_refuses_an_existing_tag(exists: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        calls.append(args)
        if args == ("rev-parse", "HEAD"):
            return COMMIT
        if args[:2] == ("tag", "--list"):
            return f"v{VERSION}" if exists else ""
        return ""

    monkeypatch.setattr(release, "_version", lambda: VERSION)
    monkeypatch.setattr(release, "_run_git", git)
    monkeypatch.setattr(release, "verify_contract_binding", lambda path, commit=None: None)
    if exists:
        with pytest.raises(release.VerificationError, match="tag must not exist"):
            release.verify_git_binding(tag=f"v{VERSION}", commit=COMMIT, require_landed=True)
    else:
        release.verify_git_binding(tag=f"v{VERSION}", commit=COMMIT, require_landed=True)
        assert ("merge-base", "--is-ancestor", COMMIT, "origin/main") in calls
    assert ("tag", "--list", f"v{VERSION}") in calls


@pytest.mark.parametrize(
    "mutation", ["none", "manifest", "artifact", "commit", "control", "digest", "extra", "missing"]
)
def test_retained_bytes_bind_all_approvals(
    candidate: tuple[Path, dict[str, str], str], mutation: str
) -> None:
    root, files, digest = candidate
    commit, control = COMMIT, CONTROL
    if mutation == "manifest":
        with (root / "release-manifest.json").open("a") as stream:
            stream.write(" ")
    elif mutation == "artifact":
        (root / "dist" / next(iter(files))).write_bytes(b"changed")
    elif mutation == "commit":
        commit = "d" * 40
    elif mutation == "control":
        control = "d" * 40
    elif mutation == "digest":
        digest = "d" * 64
    elif mutation == "extra":
        (root / "dist" / "extra.whl").write_bytes(b"extra")
    elif mutation == "missing":
        (root / "dist" / next(iter(files))).unlink()
    if mutation == "none":
        assert publish.approved_files(root, VERSION, commit, control, digest) == files
    else:
        with pytest.raises(release.VerificationError):
            publish.approved_files(root, VERSION, commit, control, digest)


def run_responses() -> dict[str, object]:
    base = "https://api.github.com/repos/example/audit/actions/runs/123"
    return {
        base: {
            "id": 123,
            "path": ".github/workflows/publish.yml",
            "head_sha": CONTROL,
            "head_branch": "main",
            "event": "workflow_dispatch",
            "status": "completed",
            "repository": {"full_name": "example/audit"},
        },
        f"{base}/jobs?per_page=100&page=1": {
            "jobs": [
                {"name": "Verify and build exact release", "conclusion": "success"},
                {"name": "Smoke disposable copies", "conclusion": "success"},
                {"name": "Publish approved artifacts to PyPI", "conclusion": "failure"},
            ]
        },
        f"{base}/artifacts?per_page=100": {
            "artifacts": [
                {"name": publish.artifact_name(VERSION), "expired": False},
            ]
        },
    }


@pytest.mark.parametrize("field", ["id", "path", "head_sha", "head_branch", "event", "status", "repository"])
def test_resume_refuses_unbound_original_run(field: str) -> None:
    responses = run_responses()
    run = next(iter(responses.values()))
    assert isinstance(run, dict)
    run[field] = "wrong"
    with pytest.raises(release.VerificationError):
        publish.verify_run("123", CONTROL, "example/audit", VERSION, fetch=responses.__getitem__)


@pytest.mark.parametrize(
    "mutation", ["none", "expired", "missing", "duplicate", "build-failed", "smoke-skipped"]
)
def test_resume_requires_retained_artifact_and_original_successful_smoke(mutation: str) -> None:
    responses = run_responses()
    jobs_raw = list(responses.values())[1]
    artifacts_raw = list(responses.values())[2]
    assert isinstance(jobs_raw, dict) and isinstance(artifacts_raw, dict)
    if mutation == "expired":
        artifacts_raw["artifacts"][0]["expired"] = True
    elif mutation == "missing":
        artifacts_raw["artifacts"] = []
    elif mutation == "duplicate":
        artifacts_raw["artifacts"] *= 2
    elif mutation == "build-failed":
        jobs_raw["jobs"][0]["conclusion"] = "failure"
    elif mutation == "smoke-skipped":
        jobs_raw["jobs"][1]["conclusion"] = "skipped"
    if mutation == "none":
        publish.verify_run("123", CONTROL, "example/audit", VERSION, fetch=responses.__getitem__)
    else:
        with pytest.raises(release.VerificationError):
            publish.verify_run("123", CONTROL, "example/audit", VERSION, fetch=responses.__getitem__)


@pytest.mark.parametrize("counts", [(0, 0, 0), (1, 0, 0), (2, 1, 0), (2, 2, 1), (2, 2, 2)])
def test_resume_stages_only_missing_files_and_preserves_exact_bytes(
    candidate: tuple[Path, dict[str, str], str], tmp_path: Path, counts: tuple[int, int, int]
) -> None:
    root, files, _ = candidate
    registry = {
        item.name: response(item.name, files, count) for item, count in zip(TRAIN, counts, strict=True)
    }
    result = publish.stage(
        root, tmp_path / "staged", VERSION, files, resume=True, fetch=lambda url: registry[url.split("/")[-3]]
    )
    for item, count in zip(TRAIN, counts, strict=True):
        expected = release.distribution_names(VERSION, item.name)[count:]
        folder = tmp_path / "staged" / item.name
        assert {path.name for path in folder.iterdir()} == set(expected)
        assert result[item.name] is (count != 2)
        for name in expected:
            assert (folder / name).read_bytes() == (root / "dist" / name).read_bytes()
    if any(counts):
        with pytest.raises(release.VerificationError, match="use resume"):
            publish.stage(
                root, tmp_path / "fresh", VERSION, files, fetch=lambda url: registry[url.split("/")[-3]]
            )


@pytest.mark.parametrize("mutation", ["yanked", "digest", "unexpected", "duplicate", "type", "identity"])
def test_staging_stops_before_any_upload_on_invalid_registry_file(
    candidate: tuple[Path, dict[str, str], str], tmp_path: Path, mutation: str
) -> None:
    root, files, _ = candidate
    raw = response(TRAIN[-1].name, files, 1)
    urls, info = raw["urls"], raw["info"]
    assert isinstance(urls, list) and isinstance(info, dict)
    if mutation == "yanked":
        urls[0]["yanked"] = True
    elif mutation == "digest":
        urls[0]["digests"] = {"sha256": "f" * 64}
    elif mutation == "unexpected":
        urls[0]["filename"] = "unknown.whl"
    elif mutation == "duplicate":
        urls *= 2
    elif mutation == "type":
        urls[0]["packagetype"] = "sdist"
    else:
        info["version"] = "3.0.1"

    def fetch(url: str) -> object:
        name = url.split("/")[-3]
        return raw if name == TRAIN[-1].name else response(name, files)

    with pytest.raises(release.VerificationError):
        publish.stage(root, tmp_path / "staged", VERSION, files, resume=True, fetch=fetch)
    assert not (tmp_path / "staged").exists()


def test_only_404_means_missing_not_network_failure() -> None:
    def fetch(url: str) -> object:
        raise urllib.error.HTTPError(url, 503, "unavailable", email.message.Message(), None)

    with pytest.raises(urllib.error.HTTPError):
        publish.pypi_response(TRAIN[0].name, VERSION, fetch=fetch)


def test_dry_run_rehearsal_cli_recovers_simulated_partial_upload(
    candidate: tuple[Path, dict[str, str], str], tmp_path: Path
) -> None:
    root, _, digest = candidate
    result = subprocess.run(
        [
            sys.executable,
            "scripts/release_publish.py",
            "rehearse",
            "--distributions",
            str(CONTRACT),
            "--version",
            VERSION,
            "--commit",
            COMMIT,
            "--control-sha",
            CONTROL,
            "--manifest-sha256",
            digest,
            "--candidate",
            str(root),
            "--destination",
            str(tmp_path / "rehearsal"),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "partial upload stopped before Labs/Proof" in result.stdout
    assert "all six files verified" in result.stdout
    resumed = list((tmp_path / "rehearsal/resumed").glob("*/*"))
    assert len(resumed) == 5
    for path in resumed:
        assert path.read_bytes() == (root / "dist" / path.name).read_bytes()


def test_smoke_matrix_installs_six_artifacts_and_all_pinned_extras_offline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[tuple[list[str], int]] = []
    notices: list[str] = []

    def run(command: list[str], *, expected: int = 0, stderr_contains: str = "") -> str:
        commands.append((command, expected))
        if stderr_contains:
            notices.append(stderr_contains)
        if command[-1] == "--version":
            name = "proof-before-action" if command[0].endswith("proof-before-action") else "mcp-audit"
            return f"{name}, version {VERSION}"
        if command[-2:-1] == ["-c"] and "print(version(" in command[-1]:
            return VERSION
        return ""

    monkeypatch.setattr(smoke, "run", run)
    smoke.smoke(
        tmp_path / "dist", tmp_path / "deps", tmp_path / "envs", VERSION, Path("build-constraints.txt")
    )
    installs = [command for command, _ in commands if "install" in command]
    assert len(installs) == 18
    assert {command[-1].split("/")[-1] for command in installs[:6]} == {
        name for item in TRAIN for name in release.distribution_names(VERSION, item.name)
    }
    for command in installs:
        assert "--no-index" in command and command.count("--find-links") == 2
        assert "--no-cache" in command and "--build-constraints" in command
    assert {command[-1].rsplit("[", 1)[-1].removesuffix("]") for command in installs[6:]} == {
        "labs",
        "proof",
        "all",
        "watch",
        "llm",
        "otel",
    }
    proof_versions = [c for c, _ in commands if c[0].endswith("proof-before-action") and c[-1] == "--version"]
    assert len(proof_versions) == 6  # Proof wheel/sdist plus core proof/all extras for both formats.
    assert any("mcp_audits_proof-" in c[-1] and c[-1].endswith(".whl") for c in installs)
    lab_checks = [(c, expected) for c, expected in commands if c[-3:] == ["lab", "agent-ui", "--help"]]
    assert len(lab_checks) == 10 and all(expected == 2 for _, expected in lab_checks)
    assert not any(c[-1] == "lab" for c, _ in commands)
    assert notices == [smoke.LAB_NOTICE] * 10


def test_smoke_lab_notice_matches_core_install_notice() -> None:
    from mcp_audit._command_registry import LAB_INSTALL_NOTICE

    assert smoke.LAB_NOTICE in LAB_INSTALL_NOTICE


def test_smoke_fails_on_core_command_in_proof(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], *, expected: int = 0, stderr_contains: str = "") -> str:
        if command[:2] == ["uv", "venv"]:
            folder = Path(command[-1]) / "bin"
            folder.mkdir(parents=True)
            (folder / "mcp-audit").touch()
        if command[-1] == "--version":
            name = "proof-before-action" if command[0].endswith("proof-before-action") else "mcp-audit"
            return f"{name}, version {VERSION}"
        return VERSION

    # Core and Labs environments legitimately carry mcp-audit; only the Proof ones must not.
    monkeypatch.setattr(smoke, "run", run)
    with pytest.raises(RuntimeError, match="Proof unexpectedly installed the core"):
        smoke.smoke(tmp_path, tmp_path, tmp_path / "env", VERSION, Path("build-constraints.txt"))


def test_smoke_fails_on_proof_command_in_core(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def run(command: list[str], *, expected: int = 0, stderr_contains: str = "") -> str:
        if command[:2] == ["uv", "venv"]:
            folder = Path(command[-1]) / "bin"
            folder.mkdir(parents=True)
            (folder / "proof-before-action").touch()
        return VERSION

    monkeypatch.setattr(smoke, "run", run)
    with pytest.raises(RuntimeError, match="unexpectedly installed proof"):
        smoke.smoke(tmp_path, tmp_path, tmp_path / "env", VERSION, Path("build-constraints.txt"))


def test_smoke_run_enforces_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["synthetic"], 0, "", "")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="exited 0"):
        smoke.run(["synthetic", "lab"], expected=2)


def test_smoke_run_enforces_stderr_notice(monkeypatch: pytest.MonkeyPatch) -> None:
    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(["synthetic"], 2, "", "Error: No such command")

    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(RuntimeError, match="stderr lacks"):
        smoke.run(["synthetic"], expected=2, stderr_contains=smoke.LAB_NOTICE)


def _verify_release_calls_lacking_contract(workflow: dict[str, object]) -> list[str]:
    """Return each verify_release.py invocation, continuations joined, that omits --distributions."""
    missing = []
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    for job in jobs.values():
        for step in job["steps"]:
            # Join continuations, then check each logical command line so a flag on a later
            # command cannot satisfy an earlier flagless call.
            for line in step.get("run", "").replace("\\\n", " ").splitlines():
                command = " ".join(line.split())
                for segment in command.split("verify_release.py")[1:]:
                    if "--distributions" not in segment:
                        missing.append(segment)
    return missing


@pytest.mark.parametrize(
    "injected",
    [
        "python scripts/verify_release.py --root . --version 3.0.0",
        "python scripts/verify_release.py --root . \\\n  --version 3.0.0\nsmoke --distributions x",
        "python scripts/verify_release.py --distributions x && python scripts/verify_release.py --root .",
    ],
)
def test_contract_flag_checker_rejects_flagless_verify_call(injected: str) -> None:
    workflow = yaml.safe_load(Path(".github/workflows/publish.yml").read_text())
    assert _verify_release_calls_lacking_contract(workflow) == []
    broken = copy.deepcopy(workflow)
    broken["jobs"]["publish"]["steps"].append({"name": "Injected", "run": injected})
    assert len(_verify_release_calls_lacking_contract(broken)) == 1


def test_workflow_contract_and_ordered_upload_failure_gates() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/publish.yml").read_text())
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert set(inputs) == {
        "commit",
        "version",
        "dry_run",
        "resume",
        "run_id",
        "manifest_sha256",
        "control_sha",
    }
    assert inputs["commit"]["required"] and inputs["version"]["required"]
    assert inputs["dry_run"]["default"] is True
    jobs = workflow["jobs"]
    assert jobs["build"]["if"] == jobs["consumer-smoke"]["if"] == "${{ !inputs.resume }}"
    assert jobs["resume"]["if"] == "${{ inputs.resume }}"
    assert "id-token" not in jobs["resume"].get("permissions", {})
    resume_steps = jobs["resume"]["steps"]
    assert not any(
        "uv build" in step.get("run", "") or "smoke_release.py" in step.get("run", "")
        for step in resume_steps
    )
    download = next(step for step in resume_steps if "download-artifact" in step.get("uses", ""))
    assert download["with"]["run-id"] == "${{ inputs.run_id }}"
    assert any("--require-publishable" in step.get("run", "") for step in resume_steps)
    steps = jobs["publish"]["steps"]
    upload_indices = [i for i, step in enumerate(steps) if "gh-action-pypi-publish" in step.get("uses", "")]
    assert len(upload_indices) == 3
    for item, index in zip(TRAIN, upload_indices, strict=True):
        upload, readback = steps[index], steps[index + 1]
        assert upload["with"]["packages-dir"] == f"staged/{item.name}/"
        assert upload["if"] == f"steps.stage.outputs.{item.name} == 'true'"
        assert "skip-existing" not in upload["with"]
        assert f"--published-through {item.name}" in readback["run"]
        assert "--manifest-sha256" in readback["run"]
    assert "--published-through" not in steps[-1]["run"]
    assert "--publication-check pypi" in steps[-1]["run"]
    for job in jobs.values():
        for step in job["steps"]:
            assert "continue-on-error" not in step
            assert "always()" not in step.get("if", "")
    assert _verify_release_calls_lacking_contract(workflow) == []
    prep = next(
        step
        for step in jobs["consumer-smoke"]["steps"]
        if step.get("name") == "Prepare locked runtime and build dependencies"
    )
    assert "--no-emit-workspace --locked" in prep["run"]
    assert "pip download --only-binary=:all:" in prep["run"]
    assert "-r build-constraints.txt" in prep["run"]
    assert jobs["build"]["steps"][4]["name"] == "Verify release authorization binding"
    sync = next(step for step in jobs["build"]["steps"] if step.get("name") == "Install locked dependencies")
    assert sync["run"] == "uv sync --all-packages --dev --locked"


def test_readback_failure_prevents_later_distribution_checks(
    candidate: tuple[Path, dict[str, str], str],
) -> None:
    _, files, _ = candidate
    requested: list[str] = []

    def fetch(url: str) -> object:
        name = url.split("/")[-3]
        requested.append(name)
        raw = response(name, files)
        if name == TRAIN[0].name:
            raw = copy.deepcopy(raw)
            raw["urls"] = []
        return raw

    with pytest.raises(release.VerificationError):
        publish.readback(VERSION, None, files, fetch=fetch)
    assert requested == [TRAIN[0].name]
