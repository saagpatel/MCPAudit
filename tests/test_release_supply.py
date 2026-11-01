"""Offline negative probes of publication identity and artifact boundaries."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts import verify_release as release


def _version_for_state(state: object) -> str:
    assert isinstance(state, dict)
    status = state.get("status")
    if status == "candidate":
        version_field = "candidate_version"
    elif status == "release":
        version_field = "published_version"
    else:
        raise AssertionError(f"unsupported release status: {status!r}")
    version = state.get(version_field)
    assert isinstance(version, str)
    return version


def _release_state() -> dict[str, object]:
    state = json.loads(Path("docs/release-state.json").read_text(encoding="utf-8"))
    assert isinstance(state, dict)
    return state


def _published_version(state: object) -> str:
    assert isinstance(state, dict)
    version = state.get("published_version")
    assert isinstance(version, str)
    return version


# Artifacts carry the version being built; server.json stays at the published
# version until promotion, so descriptor and registry probes use that one.
VERSION = _version_for_state(_release_state())
PUBLISHED_VERSION = _published_version(_release_state())
# Artifacts are content-bound to a real commit, so fixtures package HEAD's bytes.
COMMIT = subprocess.run(
    ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
).stdout.strip()
WORKFLOW_SHA = "b" * 40
CONTRACT = Path("release/distributions.json")
TRAIN = release.load_distributions(CONTRACT)


@pytest.fixture(autouse=True)
def split_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "DISTRIBUTIONS", TRAIN)


@pytest.mark.parametrize(
    ("status", "expected"),
    [("candidate", "91.2.3"), ("release", "44.5.6")],
)
def test_release_version_uses_state_identity(status: str, expected: str) -> None:
    assert (
        _version_for_state({"status": status, "candidate_version": "91.2.3", "published_version": "44.5.6"})
        == expected
    )


def test_candidate_state_keeps_descriptor_probes_on_published_version() -> None:
    state = {"status": "candidate", "candidate_version": "91.2.3", "published_version": "44.5.6"}
    assert _version_for_state(state) == "91.2.3"
    assert _published_version(state) == "44.5.6"


def test_descriptor_matches_published_version() -> None:
    raw = json.loads(Path("server.json").read_text())
    assert raw["version"] == PUBLISHED_VERSION


def _write_wheel(path: Path, entries: dict[str, bytes]) -> None:
    """Write a wheel whose RECORD lists every member with its digest."""
    record = f"{path.name.removesuffix('-py3-none-any.whl')}.dist-info/RECORD"
    rows = [
        f"{name},sha256={base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b'=').decode()},"
        f"{len(content)}\n"
        for name, content in entries.items()
        if name != record
    ]
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            if name != record:
                archive.writestr(name, content)
        archive.writestr(record, "".join(rows) + f"{record},,\n")


def _wheel_entries(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        return {
            info.filename: archive.read(info.filename) for info in archive.infolist() if not info.is_dir()
        }


@pytest.fixture(scope="session")
def head_distributions(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Use a real HEAD build as the complete template for each synthetic mutation."""
    root = tmp_path_factory.mktemp("head-build")
    source = root / "source"
    source.mkdir()
    export = subprocess.run(["git", "archive", "HEAD"], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(export)) as archive:
        archive.extractall(source, filter="data")
    dist = root / "dist"
    subprocess.run(
        [
            "uv",
            "build",
            "--offline",
            "--all-packages",
            "--no-create-gitignore",
            "--build-constraints",
            str(source / "build-constraints.txt"),
            "--out-dir",
            str(dist),
        ],
        cwd=source,
        capture_output=True,
        check=True,
    )
    # Exports have no Git identity. Supply the approved identity only for the
    # fabricated fixtures; the production verifier still checks it separately.
    provenance = json.dumps({"commit": COMMIT, "dirty": False}).encode()
    for item in TRAIN:
        wheel, sdist = release.distribution_names(VERSION, item.name)
        entries = _wheel_entries(dist / wheel)
        entries[f"{item.module}/_build_provenance.json"] = provenance
        _write_wheel(dist / wheel, entries)
        with tarfile.open(dist / sdist, "r:gz") as archive:
            entries = {}
            for info in archive.getmembers():
                if info.isfile():
                    stream = archive.extractfile(info)
                    assert stream is not None
                    with stream:
                        entries[info.name] = stream.read()
        prefix = f"{item.name.replace('-', '_')}-{VERSION}"
        entries[f"{prefix}/{item.module_root}/{item.module}/_build_provenance.json"] = provenance
        with tarfile.open(dist / sdist, "w:gz") as archive:
            for name, content in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return dist


@pytest.fixture
def distributions(tmp_path: Path, head_distributions: Path) -> Path:
    return Path(shutil.copytree(head_distributions, tmp_path / "dist"))


def _manifest(dist: Path) -> dict[str, object]:
    return {
        "schema_version": release.MANIFEST_SCHEMA,
        "version": VERSION,
        "commit": COMMIT,
        "workflow_sha": WORKFLOW_SHA,
        "files": dict(release.verify_distributions(dist_dir=dist, version=VERSION, commit=COMMIT)),
    }


@pytest.mark.parametrize("extra", ["extra.whl", "extra.tar.gz", "notes.txt", "subdirectory"])
def test_probe_release_rejects_every_extra(distributions: Path, extra: str) -> None:
    path = distributions / extra
    if extra == "subdirectory":
        path.mkdir()
    else:
        path.write_bytes(b"unchecked fixture")
    with pytest.raises(release.VerificationError, match="exactly"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize(
    "name", [name for item in TRAIN for name in release.distribution_names(VERSION, item.name)]
)
def test_probe_release_rejects_symlinks(distributions: Path, name: str, tmp_path: Path) -> None:
    target = tmp_path / name
    (distributions / name).rename(target)
    (distributions / name).symlink_to(target)
    with pytest.raises(release.VerificationError, match="regular files"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_probe_release_rejects_directory_symlink(distributions: Path, tmp_path: Path) -> None:
    link = tmp_path / "dist-link"
    link.symlink_to(distributions, target_is_directory=True)
    with pytest.raises(release.VerificationError, match="regular directory"):
        release.distribution_hashes(link, VERSION)


@pytest.mark.parametrize("mutation", ["none", "extra", "digest"])
def test_dry_run_publication_rechecks_after_consumer_smoke(distributions: Path, mutation: str) -> None:
    manifest = distributions.parent / "release-manifest.json"
    manifest.write_text(json.dumps(_manifest(distributions)))
    command = [
        sys.executable,
        "scripts/verify_release.py",
        "--publication-check",
        "artifacts",
        "--distributions",
        str(CONTRACT),
        "--tag",
        f"v{VERSION}",
        "--commit",
        COMMIT,
        "--workflow-sha",
        WORKFLOW_SHA,
        "--dist-dir",
        str(distributions),
        "--manifest",
        str(manifest),
    ]
    before = subprocess.run(command, capture_output=True, text=True, check=False)
    assert before.returncode == 0, before.stderr
    # Model a consumer-side change between the pre- and post-install checks.
    if mutation == "extra":
        (distributions / "extra.whl").write_bytes(b"unverified fixture")
    elif mutation == "digest":
        with (distributions / release.distribution_names(VERSION)[0]).open("ab") as stream:
            stream.write(b"changed fixture")
    after = subprocess.run(command, capture_output=True, text=True, check=False)
    if mutation == "none":
        assert after.returncode == 0, after.stderr
        return
    assert after.returncode == 1
    assert "release verification failed" in after.stderr


def test_manifest_digest_is_checked_before_pypi_identity(distributions: Path) -> None:
    manifest = distributions.parent / "release-manifest.json"
    manifest.write_text(json.dumps(_manifest(distributions)))
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_release.py",
            "--publication-check",
            "pypi",
            "--distributions",
            str(CONTRACT),
            "--tag",
            f"v{VERSION}",
            "--commit",
            COMMIT,
            "--manifest",
            str(manifest),
            "--manifest-sha256",
            "0" * 64,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "manifest SHA-256 does not match approval" in result.stderr


@pytest.mark.parametrize("field", ["commit", "workflow_sha", "files"])
def test_manifest_rejects_wrong_identity(distributions: Path, field: str) -> None:
    manifest = _manifest(distributions)
    manifest[field] = {} if field == "files" else "c" * 40
    with pytest.raises(release.VerificationError):
        release.verify_manifest(manifest, version=VERSION, commit=COMMIT, workflow_sha=WORKFLOW_SHA)


def _pypi_response(item: release.Distribution, version: str, hashes: dict[str, str]) -> dict[str, object]:
    return {
        "info": {"name": item.name, "version": version},
        "urls": [
            {
                "filename": name,
                "digests": {"sha256": hashes[name]},
                "yanked": False,
                "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
            }
            for name in release.distribution_names(version, item.name)
        ],
    }


@pytest.fixture
def publication_inputs(tmp_path: Path) -> tuple[list[str], dict[str, object]]:
    version = "3.0.0"
    hashes = {
        name: hashlib.sha256(name.encode()).hexdigest()
        for item in TRAIN
        for name in release.distribution_names(version, item.name)
    }
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": release.MANIFEST_SCHEMA,
                "version": version,
                "commit": COMMIT,
                "workflow_sha": WORKFLOW_SHA,
                "files": hashes,
            }
        )
    )
    args = [
        "--tag",
        f"v{version}",
        "--commit",
        COMMIT,
        "--distributions",
        str(CONTRACT),
        "--manifest",
        str(manifest),
        "--manifest-sha256",
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    ]
    return args, {item.name: _pypi_response(item, version, hashes) for item in TRAIN}


def _pypi_readback(path: Path, args: list[str], *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/verify_release.py",
            "--publication-check",
            "pypi",
            *extra,
            "--response-json",
            str(path),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


@pytest.mark.parametrize("through", range(len(TRAIN)), ids=lambda index: TRAIN[index].name)
@pytest.mark.parametrize(
    "mutation",
    ["none", "digest", "yanked", "identity", "missing", "extra", "beyond-prefix", "short-prefix"],
)
def test_published_through_checks_contract_order_prefix(
    tmp_path: Path,
    publication_inputs: tuple[list[str], dict[str, object]],
    through: int,
    mutation: str,
) -> None:
    args, responses = publication_inputs
    prefix = TRAIN[: through + 1]
    readback = {item.name: responses[item.name] for item in prefix}
    raw = readback[prefix[-1].name]
    assert isinstance(raw, dict)
    urls = raw["urls"]
    assert isinstance(urls, list)
    if mutation == "digest":
        urls[0]["digests"] = {"sha256": "0" * 64}
    elif mutation == "yanked":
        urls[0]["yanked"] = True
    elif mutation == "identity":
        raw["info"] = {"name": "other-distribution", "version": "3.0.0"}
    elif mutation == "missing":
        urls.pop()
    elif mutation == "extra":
        urls.append(dict(urls[0]))
    elif mutation == "beyond-prefix":
        # A readback for a distribution past the prefix is never silently ignored.
        beyond = TRAIN[through + 1].name if through + 1 < len(TRAIN) else "mcp-audits-other"
        readback[beyond] = responses.get(beyond, raw)
    elif mutation == "short-prefix":
        del readback[TRAIN[0].name]
    path = tmp_path / "response.json"
    path.write_text(json.dumps(readback))
    result = _pypi_readback(path, args, "--published-through", prefix[-1].name)
    assert result.returncode == (0 if mutation == "none" else 1), result.stderr
    names = ", ".join(item.name for item in prefix)
    if mutation == "none":
        assert result.stdout == (
            f"publication pypi verified for {names} only (partial readback; not release completion)\n"
        )
    elif mutation in {"beyond-prefix", "short-prefix"}:
        assert (
            f"partial PyPI readback must map exactly the distributions published through {prefix[-1].name}"
        ) in result.stderr
    # The aggregate gate still rejects a strict prefix even after its partial
    # readback succeeds; only all three can advance a public pointer.
    if mutation == "none":
        aggregate = _pypi_readback(path, args)
        if len(prefix) < len(TRAIN):
            assert aggregate.returncode == 1
            assert "every distribution" in aggregate.stderr
        else:
            assert aggregate.returncode == 0, aggregate.stderr
            assert aggregate.stdout == "publication pypi verified\n"


def test_core_only_partial_readback_prints_exact_text(
    tmp_path: Path, publication_inputs: tuple[list[str], dict[str, object]]
) -> None:
    args, responses = publication_inputs
    path = tmp_path / "response.json"
    path.write_text(json.dumps({TRAIN[0].name: responses[TRAIN[0].name]}))
    result = _pypi_readback(path, args, "--published-through", "mcp-audits")
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "publication pypi verified for mcp-audits only (partial readback; not release completion)\n"
    )


@pytest.mark.parametrize("mutation", ["none", "missing-response", "digest", "tag-absent", "tag-other"])
def test_final_tag_gate_requires_all_published_files_at_approved_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication_inputs: tuple[list[str], dict[str, object]],
    mutation: str,
) -> None:
    args, responses = publication_inputs
    if mutation == "missing-response":
        del responses[TRAIN[2].name]
    elif mutation == "digest":
        raw = responses[TRAIN[2].name]
        assert isinstance(raw, dict) and isinstance(raw["urls"], list)
        raw["urls"][0]["digests"] = {"sha256": "0" * 64}
    path = tmp_path / "responses.json"
    path.write_text(json.dumps(responses))
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        calls.append(args)
        if args == ("rev-parse", "HEAD"):
            return COMMIT
        if args == ("rev-parse", "refs/tags/v3.0.0^{commit}"):
            if mutation == "tag-absent":
                raise release.VerificationError("missing tag")
            return "c" * 40 if mutation == "tag-other" else COMMIT
        return ""

    monkeypatch.setattr(
        sys, "argv", ["verify_release.py", "--publication-check", "tag", "--response-json", str(path), *args]
    )
    monkeypatch.setattr(release, "_version", lambda: "3.0.0")
    monkeypatch.setattr(release, "_run_git", git)
    monkeypatch.setattr(
        release, "_commit_files", lambda *args: {release.CONTRACT_PATH: CONTRACT.read_bytes()}
    )
    assert release.main() == (0 if mutation == "none" else 1)
    if mutation in {"missing-response", "digest"}:
        assert not calls
    elif mutation == "none":
        assert ("rev-parse", "refs/tags/v3.0.0^{commit}") in calls
        assert ("merge-base", "--is-ancestor", COMMIT, "origin/main") in calls


@pytest.mark.parametrize("version", [None, "3.0.0"], ids=["checkout", "3.0.0"])
@pytest.mark.parametrize("mode", [None, "artifacts", "tag"])
def test_published_through_selector_is_only_for_intermediate_pypi_readbacks(
    mode: str | None,
    version: str | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Passing the contract keeps this exercising the selector guard, not the
    # split-contract gate, once the checkout itself is 3.x.
    args = [
        "verify_release.py",
        "--distributions",
        str(CONTRACT),
        "--published-through",
        TRAIN[0].name,
    ]
    if mode is not None:
        args.extend(["--publication-check", mode])
    monkeypatch.setattr(sys, "argv", args)
    monkeypatch.setattr(release, "DISTRIBUTIONS", release.DISTRIBUTIONS)
    monkeypatch.setattr(release, "RELEASE_BRANCH", release.RELEASE_BRANCH)
    if version is not None:
        monkeypatch.setattr(release, "_version", lambda: version)
    assert release.main() == 1
    assert (
        "release verification failed: --published-through requires --publication-check pypi"
        in capsys.readouterr().err
    )


def _descriptor() -> dict[str, object]:
    raw = json.loads(Path("server.json").read_text())
    assert isinstance(raw, dict)
    return raw


def _packages(raw: dict[str, object]) -> list[object]:
    packages = raw["packages"]
    assert isinstance(packages, list)
    return packages


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("identifier", "other-package"),
        ("runtimeHint", "python"),
        ("transport", {"type": "sse"}),
        ("packageArguments", [{"type": "positional", "value": "scan"}]),
        ("version", "0.0.1"),
    ],
)
def test_probe_release_rejects_wrong_package_descriptor(field: str, value: object) -> None:
    raw = _descriptor()
    package = _packages(raw)[0]
    assert isinstance(package, dict)
    package[field] = value
    with pytest.raises(release.VerificationError, match="exact release tuple"):
        release.verify_descriptor(raw, version=PUBLISHED_VERSION)


def test_descriptor_rejects_extra_packages_and_remotes() -> None:
    raw = _descriptor()
    release.verify_descriptor(raw, version=PUBLISHED_VERSION)
    for field, value in (("packages", _packages(raw) * 2), ("remotes", [{"type": "sse"}])):
        with pytest.raises(release.VerificationError, match="exact release tuple"):
            release.verify_descriptor({**raw, field: value}, version=PUBLISHED_VERSION)


def test_registry_readback_reuses_exact_descriptor_assertion() -> None:
    raw = {
        "server": _descriptor(),
        "_meta": {
            "io.modelcontextprotocol.registry/official": {
                "status": "active",
                "isLatest": True,
            }
        },
    }
    release.verify_registry(raw, version=PUBLISHED_VERSION)
    changed = copy.deepcopy(raw)
    server = changed["server"]
    assert isinstance(server, dict)
    server["repository"] = {"url": "https://example.invalid", "source": "github"}
    with pytest.raises(release.VerificationError, match="exact release tuple"):
        release.verify_registry(changed, version=PUBLISHED_VERSION)


@pytest.mark.parametrize("mutation", ["digest", "filename", "yanked", "extra"])
@pytest.mark.parametrize("item", TRAIN, ids=lambda item: item.name)
def test_probe_release_binds_pypi_to_approved_manifest(
    distributions: Path, mutation: str, item: release.Distribution
) -> None:
    all_hashes = dict(release.distribution_hashes(distributions, VERSION))
    hashes = {name: all_hashes[name] for name in release.distribution_names(VERSION, item.name)}
    urls: list[dict[str, object]] = [
        {
            "filename": name,
            "digests": {"sha256": digest},
            "yanked": False,
            "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
        }
        for name, digest in hashes.items()
    ]
    raw = {"info": {"name": item.name, "version": VERSION}, "urls": urls}
    release.verify_pypi(raw, version=VERSION, hashes=hashes, distribution=item.name)
    if mutation == "digest":
        urls[0]["digests"] = {"sha256": "0" * 64}
    elif mutation == "filename":
        urls[0]["filename"] = "different.whl"
    elif mutation == "yanked":
        urls[0]["yanked"] = True
    else:
        urls.append(dict(urls[0]))
    with pytest.raises(release.VerificationError):
        release.verify_pypi(raw, version=VERSION, hashes=hashes, distribution=item.name)


def test_workflow_isolates_consumer_copies_and_uploads_explicit_paths() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/publish.yml").read_text())
    jobs = workflow["jobs"]
    assert jobs["publish"]["needs"] == ["build", "consumer-smoke"]
    assert jobs["publish"]["if"] == "${{ !inputs.dry_run }}"
    assert jobs["consumer-smoke"]["permissions"] == {"contents": "read", "actions": "read"}
    smoke_steps = jobs["consumer-smoke"]["steps"]
    assert not any("upload-artifact" in step.get("uses", "") for step in smoke_steps)
    assert "Recheck exact file set and digests after smoke" in [step.get("name") for step in smoke_steps]
    upload = next(step for step in jobs["build"]["steps"] if "upload-artifact" in step.get("uses", ""))
    assert "*" not in upload["with"]["path"]
    assert len(upload["with"]["path"].splitlines()) == 3


def test_publish_build_and_advisory_gate_use_the_same_build_constraints() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/publish.yml").read_text())
    steps = {step.get("name"): step for step in workflow["jobs"]["build"]["steps"]}
    constraints = "--build-constraints ../release-controls/build-constraints.txt"
    gate = " ".join(steps["Run release quality gate"]["run"].replace("\\\n", " ").split())
    assert f"check_advisories.py --lock uv.lock {constraints}" in gate
    build = " ".join(steps["Build wheel and sdist"]["run"].replace("\\\n", " ").split())
    assert build == f"uv build --clear --no-create-gitignore {constraints}"
    builds = [step for step in workflow["jobs"]["build"]["steps"] if "uv build" in step.get("run", "")]
    assert builds == [steps["Build wheel and sdist"]]
    names = list(steps)
    identical = steps["Require identical build constraints"]
    assert identical["working-directory"] == "release-source"
    assert "cmp -s ../release-controls/build-constraints.txt build-constraints.txt" in identical["run"]
    assert "exit 1" in identical["run"]
    assert names.index("Require identical build constraints") < names.index("Build wheel and sdist")


def test_publish_workflows_disable_actions_cache() -> None:
    paths = sorted(Path(".github/workflows").glob("publish*.yml"))
    assert paths

    for path in paths:
        workflow = yaml.safe_load(path.read_text())
        for job in workflow["jobs"].values():
            assert "cache-mode" not in job
            for step in job.get("steps", []):
                uses = step.get("uses", "")
                assert not uses.startswith("actions/cache")
                if uses.startswith("astral-sh/setup-uv"):
                    assert step.get("with", {}).get("enable-cache") is False


def _rewrite_sdist(dist: Path, extra: list[tuple[str, bytes]]) -> None:
    sdist = dist / release.distribution_names(VERSION)[1]
    with tarfile.open(sdist, "r:gz") as archive:
        members = [(info, archive.extractfile(info)) for info in archive.getmembers()]
        originals = [(info, stream.read() if stream else b"") for info, stream in members]
    with tarfile.open(sdist, "w:gz") as archive:
        for info, content in originals:
            archive.addfile(info, io.BytesIO(content))
        for name, content in extra:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize(
    "alias",
    [
        f"./mcp_audits-{VERSION}/pyproject.toml",
        f"mcp_audits-{VERSION}//pyproject.toml",
        f"mcp_audits-{VERSION}/./pyproject.toml",
        f"mcp_audits-{VERSION}/pyproject.toml",
        f"mcp_audits-{VERSION}/src/../pyproject.toml",
        f"/mcp_audits-{VERSION}/pyproject.toml",
        "other-root/pyproject.toml",
    ],
)
def test_sdist_member_aliases_cannot_shadow_checked_files(distributions: Path, alias: str) -> None:
    unpinned = b'[project]\nname = "mcp-audits"\ndependencies = ["mcp-audits>=0"]\n'
    _rewrite_sdist(distributions, [(alias, unpinned)])
    with pytest.raises(release.VerificationError, match="canonical path|more than once"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_wheel_duplicate_members_are_rejected(distributions: Path) -> None:
    wheel = distributions / release.distribution_names(VERSION)[0]
    with zipfile.ZipFile(wheel, "a") as archive, pytest.warns(UserWarning, match="Duplicate name"):
        archive.writestr("mcp_audit/_build_provenance.json", b'{"commit": "0", "dirty": true}')
    with pytest.raises(release.VerificationError, match="more than once"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_fixture_matches_the_approved_commit(distributions: Path) -> None:
    assert len(release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)) == 6


@pytest.mark.parametrize("item", TRAIN, ids=lambda item: item.name)
@pytest.mark.parametrize("artifact", [0, 1], ids=["wheel", "sdist"])
def test_split_release_requires_every_artifact(
    distributions: Path, item: release.Distribution, artifact: int
) -> None:
    (distributions / release.distribution_names(VERSION, item.name)[artifact]).unlink()
    with pytest.raises(release.VerificationError, match="exactly"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def _replace_sdist_members(path: Path, replacements: dict[str, bytes | None]) -> None:
    with tarfile.open(path, "r:gz") as archive:
        entries = {}
        for info in archive.getmembers():
            stream = archive.extractfile(info)
            assert stream is not None
            with stream:
                entries[info.name] = stream.read()
    for name, content in replacements.items():
        if content is None:
            del entries[name]
        else:
            entries[name] = content
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize(
    ("artifact", "member"),
    [
        ("wheel", "mcp_audit/cli.py"),
        ("wheel", "mcp_audit/fixtures/demo-mcp-config.json"),
        ("wheel", f"mcp_audits-{VERSION}.dist-info/WHEEL"),
        ("wheel", f"mcp_audits-{VERSION}.dist-info/licenses/LICENSE"),
        ("sdist", "src/mcp_audit/rules/result_injection.py"),
        ("sdist", "src/mcp_audit/fixtures/demo-mcp-config.json"),
        ("sdist", "mcp_audit_build_backend.py"),
        ("sdist", "pyproject.toml.orig"),
    ],
)
def test_packaged_files_cannot_be_omitted(distributions: Path, artifact: str, member: str) -> None:
    wheel, sdist = release.distribution_names(VERSION)
    if artifact == "wheel":
        entries = _wheel_entries(distributions / wheel)
        del entries[member]
        _write_wheel(distributions / wheel, entries)
    else:
        _replace_sdist_members(distributions / sdist, {f"mcp_audits-{VERSION}/{member}": None})
    with pytest.raises(release.VerificationError, match=member):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_wheel_extra_dist_info_member_is_rejected(distributions: Path) -> None:
    wheel = distributions / release.distribution_names(VERSION)[0]
    entries = _wheel_entries(wheel)
    member = f"mcp_audits-{VERSION}.dist-info/unapproved.txt"
    entries[member] = b"not in the reference build\n"
    _write_wheel(wheel, entries)
    with pytest.raises(release.VerificationError, match="unapproved.txt.*extra"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize("member", ["WHEEL", "licenses/LICENSE"])
def test_wheel_install_metadata_matches_reference(distributions: Path, member: str) -> None:
    wheel = distributions / release.distribution_names(VERSION)[0]
    entries = _wheel_entries(wheel)
    path = f"mcp_audits-{VERSION}.dist-info/{member}"
    if member == "WHEEL":
        assert b"Root-Is-Purelib: true" in entries[path]
        entries[path] = entries[path].replace(b"Root-Is-Purelib: true", b"Root-Is-Purelib: false")
    else:
        entries[path] += b"unapproved license amendment\n"
    _write_wheel(wheel, entries)
    with pytest.raises(release.VerificationError, match=f"{member}.*reference build"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_wheel_license_also_matches_approved_commit(
    distributions: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel = distributions / release.distribution_names(VERSION)[0]
    entries = _wheel_entries(wheel)
    license_path = f"mcp_audits-{VERSION}.dist-info/licenses/LICENSE"
    entries[license_path] += b"unapproved license amendment\n"
    _write_wheel(wheel, entries)
    reference_wheel, reference_sdist, requirements = release._reference_build(
        commit=COMMIT, distribution=release.DISTRIBUTIONS[0]
    )
    # Even matching backend output cannot replace the approved source license.
    reference_wheel[license_path] = entries[license_path]
    monkeypatch.setattr(
        release, "_reference_build", lambda **kwargs: (reference_wheel, reference_sdist, requirements)
    )
    with pytest.raises(release.VerificationError, match="licenses/LICENSE.*approved commit"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
@pytest.mark.parametrize("mutation", ["extra", "looser-floor", "duplicate", "missing", "missing-extra"])
def test_requires_dist_is_exactly_the_committed_set(
    distributions: Path, artifact: str, mutation: str
) -> None:
    wheel, sdist = release.distribution_names(VERSION)
    if artifact == "wheel":
        entries = _wheel_entries(distributions / wheel)
        member = f"mcp_audits-{VERSION}.dist-info/METADATA"
        metadata = entries[member]
    else:
        member = f"mcp_audits-{VERSION}/PKG-INFO"
        with tarfile.open(distributions / sdist, "r:gz") as archive:
            stream = archive.extractfile(member)
            assert stream is not None
            with stream:
                metadata = stream.read()
    headers, separator, body = metadata.partition(b"\n\n")
    if mutation in {"extra", "looser-floor", "duplicate"}:
        requirement = {
            "extra": b"attacker-bootstrap==1.0.0",
            "looser-floor": b"anyio>=1.0",
            "duplicate": b"anyio>=4.14.2",
        }[mutation]
        headers += b"\nRequires-Dist: " + requirement
    else:
        prefix = b"Requires-Dist: rich" if mutation == "missing" else b"Requires-Dist: watchfiles"
        lines = headers.splitlines()
        assert any(line.startswith(prefix) for line in lines)
        headers = b"\n".join(line for line in lines if not line.startswith(prefix))
    changed = headers + separator + body
    if artifact == "wheel":
        entries[member] = changed
        _write_wheel(distributions / wheel, entries)
    else:
        _replace_sdist_members(distributions / sdist, {member: changed})
    with pytest.raises(release.VerificationError, match="Requires-Dist"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


def test_sdist_build_backend_must_be_the_approved_one(distributions: Path) -> None:
    # Grok round 3, finding 2: the in-tree PEP 517 backend decides what a rebuild packages.
    sdist = distributions / release.distribution_names(VERSION)[1]
    backend = f"mcp_audits-{VERSION}/mcp_audit_build_backend.py"
    with tarfile.open(sdist, "r:gz") as archive:
        entries = {}
        for info in archive.getmembers():
            stream = archive.extractfile(info)
            assert stream is not None
            entries[info.name] = stream.read()
    entries[backend] += b"\nfrom setuptools.build_meta import build_wheel  # noqa\n"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    with pytest.raises(release.VerificationError, match="approved commit"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize(
    ("member", "content"),
    [
        ("mcp_audit/__init__.py", b"import os\nos.system('true')\n"),
        ("mcp_audit/payload.py", b"print('not from the approved commit')\n"),
        ("mcp_audit_payload.pth", b"import mcp_audit.payload\n"),
    ],
)
def test_wheel_code_must_be_the_approved_commit(distributions: Path, member: str, content: bytes) -> None:
    # Grok round 3, finding 2: copied METADATA/entry points/provenance must not vouch for other code.
    wheel = distributions / release.distribution_names(VERSION)[0]
    entries = _wheel_entries(wheel)
    entries[member] = content
    _write_wheel(wheel, entries)
    with pytest.raises(release.VerificationError, match="approved commit|outside"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize("mutation", ["unlisted", "digest", "escape"])
def test_wheel_record_lists_exactly_the_members(distributions: Path, mutation: str) -> None:
    wheel = distributions / release.distribution_names(VERSION)[0]
    entries = _wheel_entries(wheel)
    record = f"mcp_audits-{VERSION}.dist-info/RECORD"
    lines = entries[record].decode().splitlines()
    if mutation == "unlisted":
        lines = [line for line in lines if not line.startswith("mcp_audit/__init__.py,")]
    elif mutation == "digest":
        lines = [line.replace("sha256=", "sha256=A", 1) if "__init__" in line else line for line in lines]
    else:
        lines.append("../../../bin/python,,")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, "\n".join(lines) + "\n" if name == record else content)
    with pytest.raises(release.VerificationError, match="RECORD"):
        release.verify_distributions(dist_dir=distributions, version=VERSION, commit=COMMIT)
