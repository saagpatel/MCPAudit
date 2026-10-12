"""Synthetic acceptance checks for unsplit and future three-package releases."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import mcp_audit_build_backend as backend
from scripts import verify_release as release

VERSION = "3.0.0"
COMMIT = "a" * 40
TRAIN = (
    release.Distribution(
        "mcp-audits",
        "mcp_audit",
        "pyproject.toml",
        {"mcp-audit": "mcp_audit.cli:main", "mcp-audits": "mcp_audit.cli:main"},
    ),
    release.Distribution("mcp-audits-labs", "mcp_audit_labs", "labs/pyproject.toml", {}),
    release.Distribution(
        "mcp-audits-proof",
        "proof_before_action",
        "proof/pyproject.toml",
        {"proof-before-action": "proof_before_action.proof_cli:main"},
        "python",
    ),
)


def _contract() -> list[dict[str, object]]:
    return [item._asdict() for item in TRAIN]


@pytest.mark.parametrize("module,source", [("mcp_audit", "src"), ("proof_before_action", "python")])
def test_backend_uses_configured_package_and_cleans_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module: str,
    source: str,
) -> None:
    package = tmp_path / source / module
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("")
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.uv.build-backend]\nmodule-name = "{module}"\nmodule-root = "{source}"\n'
    )
    monkeypatch.setattr(backend, "_ROOT", tmp_path)
    monkeypatch.setattr(backend, "_git_root", lambda: tmp_path)
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        output = {
            "rev-parse": COMMIT.encode(),
            "status": b"",
            "ls-files": f"{source}/{module}/__init__.py\0".encode(),
        }[args[0]]
        return subprocess.CompletedProcess(args, 0, output, b"")

    monkeypatch.setattr(backend, "_git", git)
    provenance = package / "_build_provenance.json"
    with pytest.raises(RuntimeError, match="fixture build failed"):
        with backend._generated_provenance():
            assert json.loads(provenance.read_text()) == {
                "schema_version": "mcp-audits.build-provenance.v1",
                "commit": COMMIT,
                "dirty": False,
            }
            assert ("ls-files", "-z", "--", f"{source}/{module}") in calls
            raise RuntimeError("fixture build failed")
    assert not provenance.exists()
    (package / "untracked.py").write_text("")
    assert backend._source_provenance()["dirty"] is True


def test_backend_preserves_sdist_provenance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = tmp_path / "src/proof_before_action"
    package.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[tool.uv.build-backend]\nmodule-name="proof_before_action"\n')
    path = package / "_build_provenance.json"
    payload = json.dumps(
        {"schema_version": "mcp-audits.build-provenance.v1", "commit": COMMIT, "dirty": False}
    )
    path.write_text(payload)
    monkeypatch.setattr(backend, "_ROOT", tmp_path)
    monkeypatch.setattr(backend, "_git_root", lambda: None)
    with backend._generated_provenance():
        assert path.read_text() == payload
    assert path.read_text() == payload


@pytest.mark.parametrize("tracked", [True, False])
def test_nested_build_project_requires_tracked_project_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracked: bool,
) -> None:
    project = tmp_path / "distributions/proof"
    project.mkdir(parents=True)
    monkeypatch.setattr(backend, "_ROOT", project)

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        if args == ("rev-parse", "--show-toplevel"):
            return subprocess.CompletedProcess(args, 0, str(tmp_path).encode(), b"")
        assert args == ("ls-files", "--error-unmatch", "--", "pyproject.toml")
        return subprocess.CompletedProcess(args, 0 if tracked else 1, b"pyproject.toml", b"")

    monkeypatch.setattr(backend, "_git", git)
    assert backend._git_root() == (tmp_path if tracked else None)


@pytest.mark.parametrize("source", ["../outside", "/outside"])
def test_backend_rejects_package_root_escape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        f'[tool.uv.build-backend]\nmodule-name="proof_before_action"\nmodule-root="{source}"\n'
    )
    monkeypatch.setattr(backend, "_ROOT", tmp_path)
    with pytest.raises(RuntimeError, match="inside the project"):
        backend._package_root()


@pytest.mark.parametrize("mutation", ["none", "order", "duplicate-script", "escape"])
def test_distribution_contract_is_explicit_and_ordered(tmp_path: Path, mutation: str) -> None:
    contract = _contract()
    if mutation == "order":
        contract.reverse()
    elif mutation == "duplicate-script":
        contract[1]["scripts"] = contract[0]["scripts"]
    elif mutation == "escape":
        contract[1]["project"] = "../pyproject.toml"
    path = tmp_path / "contract.json"
    path.write_text(json.dumps(contract))
    if mutation == "none":
        assert release.load_distributions(path) == TRAIN
    else:
        with pytest.raises(release.VerificationError):
            release.load_distributions(path)


@pytest.fixture
def train_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(release, "DISTRIBUTIONS", TRAIN)
    dist = tmp_path / "dist"
    dist.mkdir()
    for item in TRAIN:
        metadata = f"Name: {item.name}\nVersion: {VERSION}\n"
        if item.name == "mcp-audits":
            metadata += (
                "Requires-Dist: mcp>=2.2.0,<3.0\nRequires-Dist: cryptography>=50.0.0,<51.0\n"
                "Requires-Dist: click>=8.3.3,<9.0\nRequires-Dist: anyio>=4.14.2\n"
            )
            for extra, packages in (("labs", ("labs",)), ("proof", ("proof",)), ("all", ("labs", "proof"))):
                for package in packages:
                    metadata += f'Requires-Dist: mcp-audits-{package}=={VERSION}; extra == "{extra}"\n'
        else:
            metadata += f"Requires-Dist: mcp-audits=={VERSION}\n"
        provenance = json.dumps({"commit": COMMIT, "dirty": False}).encode()
        wheel, sdist = release.distribution_names(VERSION, item.name)
        stem = item.name.replace("-", "_")
        scripts = "[console_scripts]\n" + "".join(f"{key} = {value}\n" for key, value in item.scripts.items())
        project = "[project.scripts]\n" + "".join(
            f'{key} = "{value}"\n' for key, value in item.scripts.items()
        )
        with zipfile.ZipFile(dist / wheel, "w") as archive:
            archive.writestr(f"{stem}-{VERSION}.dist-info/METADATA", metadata)
            archive.writestr(f"{stem}-{VERSION}.dist-info/entry_points.txt", scripts)
            archive.writestr(f"{item.module}/_build_provenance.json", provenance)
        with tarfile.open(dist / sdist, "w:gz") as archive:
            for name, content in (
                ("PKG-INFO", metadata.encode()),
                (f"{item.module_root}/{item.module}/_build_provenance.json", provenance),
                ("pyproject.toml", project.encode()),
            ):
                info = tarfile.TarInfo(f"{stem}-{VERSION}/{name}")
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return dist


def test_all_six_artifacts_and_manifest_are_verified(train_artifacts: Path) -> None:
    hashes = dict(release.verify_distributions(dist_dir=train_artifacts, version=VERSION, commit=COMMIT))
    assert len(hashes) == 6
    manifest = {
        "schema_version": release.MANIFEST_SCHEMA,
        "version": VERSION,
        "commit": COMMIT,
        "workflow_sha": "b" * 40,
        "files": hashes,
    }
    assert release.verify_manifest(manifest, version=VERSION, commit=COMMIT) == hashes
    del hashes[release.distribution_names(VERSION, TRAIN[2].name)[1]]
    with pytest.raises(release.VerificationError, match="exactly"):
        release.verify_manifest(manifest, version=VERSION, commit=COMMIT)


@pytest.mark.parametrize("mutation", ["missing", "version", "pin", "provenance", "scripts"])
def test_partial_or_inconsistent_train_fails(train_artifacts: Path, mutation: str) -> None:
    proof = TRAIN[2]
    wheel = train_artifacts / release.distribution_names(VERSION, proof.name)[0]
    if mutation == "missing":
        wheel.unlink()
    else:
        with zipfile.ZipFile(wheel) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        for name, content in entries.items():
            if mutation == "version" and name.endswith("/METADATA"):
                entries[name] = content.replace(b"Version: 3.0.0", b"Version: 3.0.1")
            if mutation == "pin" and name.endswith("/METADATA"):
                entries[name] = content.replace(b"mcp-audits==3.0.0", b"mcp-audits>=3.0.0")
            if mutation == "provenance" and name.endswith("_build_provenance.json"):
                entries[name] = json.dumps({"commit": "c" * 40, "dirty": False}).encode()
            if mutation == "scripts" and name.endswith("entry_points.txt"):
                entries[name] = b"[console_scripts]\nwrong=wrong:main\n"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
    with pytest.raises(release.VerificationError):
        release.verify_distributions(dist_dir=train_artifacts, version=VERSION, commit=COMMIT)


def test_maintenance_branch_binds_only_2x_and_its_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "RELEASE_BRANCH", "release/2.x")
    assert release.distribution_names("2.12.1")[0] == "mcp_audits-2.12.1-py3-none-any.whl"
    with pytest.raises(release.VerificationError, match="2.x"):
        release.distribution_names("3.0.0")
    calls: list[tuple[str, ...]] = []

    def git(*args: str) -> str:
        calls.append(args)
        return COMMIT if args == ("rev-parse", "HEAD") else ""

    monkeypatch.setattr(release, "_version", lambda: "2.12.1")
    monkeypatch.setattr(release, "_run_git", git)
    release.verify_git_binding(tag=None, commit=COMMIT, require_landed=True)
    assert ("merge-base", "--is-ancestor", COMMIT, "origin/release/2.x") in calls


def test_maintenance_environment_requires_exact_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(release, "RELEASE_BRANCH", "release/2.x")
    environment = {
        "can_admins_bypass": False,
        "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": False,
                "reviewers": [{"type": "User", "reviewer": {"login": "saagpatel"}}],
            }
        ],
    }
    release.verify_environment_protection(
        environment,
        {"branch_policies": [{"name": "release/2.x", "type": "branch"}]},
    )
    with pytest.raises(release.VerificationError, match="release/2.x"):
        release.verify_environment_protection(
            environment,
            {"branch_policies": [{"name": "main", "type": "branch"}]},
        )


@pytest.mark.parametrize("mutation", ["none", "version", "lock", "scripts", "pin", "extra"])
def test_source_distribution_metadata_is_lockstep(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    project = release._project()
    version = release._version()
    project["scripts"] = TRAIN[0].scripts
    project["optional-dependencies"] = {
        "labs": [f"mcp-audits-labs=={version}"],
        "proof": [f"mcp-audits-proof=={version}"],
        "all": [f"mcp-audits-labs=={version}", f"mcp-audits-proof=={version}"],
    }
    if mutation == "extra":
        project["optional-dependencies"] = {"labs": [f"mcp-audits-labs>={version}"]}
    monkeypatch.setattr(release, "DISTRIBUTIONS", TRAIN)
    monkeypatch.setattr(release, "_project", lambda: project)
    original_read = release._read_text

    def read(path: str) -> str:
        if path == "uv.lock":
            return "\n".join(
                f'[[package]]\nname="{item.name}"\nversion="'
                f'{"9.0.0" if mutation == "lock" and item == TRAIN[2] else version}"\n'
                for item in TRAIN
            )
        for item in TRAIN[1:]:
            if path == item.project:
                other_version = "9.0.0" if mutation == "version" else version
                pin = ">=" if mutation == "pin" else "=="
                scripts = {} if mutation == "scripts" else item.scripts
                return (
                    f'[project]\nname="{item.name}"\nversion="{other_version}"\n'
                    f'dependencies=["mcp-audits{pin}{version}"]\n[project.scripts]\n'
                    + "".join(f'{key}="{value}"\n' for key, value in scripts.items())
                )
        return original_read(path)

    monkeypatch.setattr(release, "_read_text", read)
    if mutation == "none":
        assert release.verify_metadata(require_publishable=False)[0] == version
    else:
        with pytest.raises(release.VerificationError):
            release.verify_metadata(require_publishable=False)


@pytest.mark.parametrize("mutation", ["none", "missing-response", "wrong-hash"])
def test_publication_cli_requires_every_pypi_readback(train_artifacts: Path, mutation: str) -> None:
    hashes = dict(release.distribution_hashes(train_artifacts, VERSION))
    manifest = train_artifacts.parent / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": release.MANIFEST_SCHEMA,
                "version": VERSION,
                "commit": COMMIT,
                "workflow_sha": "b" * 40,
                "files": hashes,
            }
        )
    )
    contract = train_artifacts.parent / "distributions.json"
    contract.write_text(json.dumps(_contract()))
    responses: dict[str, object] = {}
    for item in TRAIN:
        responses[item.name] = {
            "info": {"name": item.name, "version": VERSION},
            "urls": [
                {
                    "filename": name,
                    "digests": {"sha256": hashes[name]},
                    "yanked": False,
                    "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
                }
                for name in release.distribution_names(VERSION, item.name)
            ],
        }
    if mutation == "missing-response":
        del responses[TRAIN[2].name]
    if mutation == "wrong-hash":
        responses[TRAIN[2].name] = {
            "info": {"name": TRAIN[2].name, "version": VERSION},
            "urls": [
                {
                    "filename": name,
                    "digests": {"sha256": "0" * 64},
                    "yanked": False,
                    "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
                }
                for name in release.distribution_names(VERSION, TRAIN[2].name)
            ],
        }
    response_path = train_artifacts.parent / "pypi.json"
    response_path.write_text(json.dumps(responses))
    result = subprocess.run(
        [
            sys.executable,
            "scripts/verify_release.py",
            "--publication-check",
            "pypi",
            "--tag",
            f"v{VERSION}",
            "--commit",
            COMMIT,
            "--distributions",
            str(contract),
            "--manifest",
            str(manifest),
            "--manifest-sha256",
            hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "--response-json",
            str(response_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == (0 if mutation == "none" else 1), result.stderr


def test_maintenance_metadata_uses_checkout_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = {"schema_version": "mcp-audit.release-state.v1", "candidate_version": "2.12.1"}
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/release-state.json").write_text(json.dumps(state))
    monkeypatch.setattr(release, "ROOT", tmp_path)
    monkeypatch.setattr(release, "RELEASE_STATE_PATH", tmp_path / "docs/release-state.json")
    monkeypatch.setattr(release, "RELEASE_BRANCH", "release/2.x")
    assert release._release_state() == state
    monkeypatch.setattr(
        release,
        "_project",
        lambda: {"version": "3.0.0", "name": "mcp-audits", "scripts": release.EXPECTED_SCRIPTS},
    )
    monkeypatch.setattr(release, "_read_text", lambda path: "{}" if path == "server.json" else "")
    with pytest.raises(release.VerificationError, match="2.x"):
        release.verify_metadata(require_publishable=False)
