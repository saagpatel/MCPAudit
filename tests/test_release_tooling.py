"""Synthetic acceptance checks for unsplit and future three-package releases."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

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


@pytest.mark.parametrize(
    "module,source",
    [("mcp_audit", "src"), ("proof_before_action", "python"), ("mcp_audit", ""), ("mcp_audit", ".")],
)
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
            "ls-files": f"{PurePosixPath(source) / module / '__init__.py'}\0".encode(),
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
            assert ("ls-files", "-z", "--", str(PurePosixPath(source) / module)) in calls
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


EXTRAS = (("labs", ("labs",)), ("proof", ("proof",)), ("all", ("labs", "proof")))
BUILD_CONSTRAINTS = (Path(__file__).resolve().parents[1] / "build-constraints.txt").read_text()
BUILD_SYSTEM = (
    f'[build-system]\nrequires = ["{BUILD_CONSTRAINTS.strip()}"]\n'
    'build-backend = "mcp_audit_build_backend"\nbackend-path = ["."]\n'
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "init.defaultBranch=main",
            *args,
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _project_toml(item: release.Distribution) -> str:
    dependencies = (
        ["mcp>=2.2.0,<3.0", "cryptography>=50.0.0,<51.0", "click>=8.3.3,<9.0", "anyio>=4.14.2"]
        if item.name == "mcp-audits"
        else [f"mcp-audits=={VERSION}"]
    )
    project = (
        f'{BUILD_SYSTEM}[project]\nname="{item.name}"\nversion="{VERSION}"\n'
        f"dependencies={json.dumps(dependencies)}\n[project.scripts]\n"
    ) + "".join(f'{key} = "{value}"\n' for key, value in item.scripts.items())
    if item.name == "mcp-audits":
        project += "[project.optional-dependencies]\n" + "".join(
            f"{extra}={json.dumps([f'mcp-audits-{package}=={VERSION}' for package in packages])}\n"
            for extra, packages in EXTRAS
        )
        project += 'conditional=[\'fixture-pkg[cli]>=1,<2; python_version < "3.12" or os_name == "nt"\']\n'
    return (
        project + f'[tool.uv.build-backend]\nmodule-name="{item.module}"\nmodule-root="{item.module_root}"\n'
        'source-include=["mcp_audit_build_backend.py"]\n'
    )


def _commit_train(repo: Path, train: tuple[release.Distribution, ...]) -> str:
    """Commit a synthetic three-project checkout; artifacts are bound to its exact bytes."""
    for item in train:
        base = repo / PurePosixPath(item.project).parent
        package = base / item.module_root / item.module
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(f'"""{item.name} fixture."""\n')
        for target in item.scripts.values():
            module = target.partition(":")[0].removeprefix(f"{item.module}.")
            (package / f"{module}.py").write_text("def main() -> None:\n    pass\n")
        (base / "pyproject.toml").write_text(_project_toml(item))
        (base / "mcp_audit_build_backend.py").write_bytes(Path(backend.__file__).read_bytes())
    (repo / ".gitignore").write_text("__pycache__/\n")
    (repo / "build-constraints.txt").write_text(BUILD_CONSTRAINTS)
    if not (repo / ".git").exists():
        _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fixture")
    return _git(repo, "rev-parse", "HEAD")


def _write_wheel(path: Path, entries: dict[str, bytes]) -> None:
    """Write a wheel whose RECORD lists every member with its digest."""
    (record,) = [name for name in entries if name.endswith(".dist-info/RECORD")] or [
        next(name for name in entries if name.endswith(".dist-info/METADATA")).replace("METADATA", "RECORD")
    ]
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
        return {name: archive.read(name) for name in archive.namelist()}


def _metadata(item: release.Distribution) -> str:
    metadata = f"Name: {item.name}\nVersion: {VERSION}\n"
    if item.name != "mcp-audits":
        return metadata + f"Requires-Dist: mcp-audits=={VERSION}\n"
    metadata += (
        "Requires-Dist: mcp>=2.2.0,<3.0\nRequires-Dist: cryptography>=50.0.0,<51.0\n"
        "Requires-Dist: click>=8.3.3,<9.0\nRequires-Dist: anyio>=4.14.2\n"
    )
    for extra, packages in EXTRAS:
        for package in packages:
            metadata += f'Requires-Dist: mcp-audits-{package}=={VERSION}; extra == "{extra}"\n'
    metadata += (
        "Requires-Dist: fixture-pkg[cli]>=1,<2; "
        '(python_full_version < "3.12" and extra == "conditional") '
        'or (os_name == "nt" and extra == "conditional")\n'
    )
    return metadata


def _pack_train(repo: Path, dist: Path, train: tuple[release.Distribution, ...], commit: str) -> None:
    """Pack each committed project the way the in-tree backend and uv_build do."""
    for item in train:
        base = repo / PurePosixPath(item.project).parent
        package = PurePosixPath(item.module_root) / item.module
        sources = {
            path.relative_to(base).as_posix(): path.read_bytes()
            for path in sorted((base / package).rglob("*"))
            if path.is_file()
        }
        metadata = _metadata(item).encode()
        provenance = json.dumps({"commit": commit, "dirty": False}).encode()
        wheel, sdist = release.distribution_names(VERSION, item.name)
        stem = item.name.replace("-", "_")
        scripts = "[console_scripts]\n" + "".join(f"{key} = {value}\n" for key, value in item.scripts.items())
        reference_wheel, _, _ = release._reference_build(commit=commit, distribution=item)
        _write_wheel(
            dist / wheel,
            {
                f"{stem}-{VERSION}.dist-info/METADATA": metadata,
                f"{stem}-{VERSION}.dist-info/entry_points.txt": scripts.encode(),
                f"{stem}-{VERSION}.dist-info/WHEEL": reference_wheel[f"{stem}-{VERSION}.dist-info/WHEEL"],
                **{
                    str(PurePosixPath(name).relative_to(package.parent)): data
                    for name, data in sources.items()
                },
                f"{item.module}/_build_provenance.json": provenance,
            },
        )
        entries = {
            "PKG-INFO": metadata,
            "pyproject.toml": (base / "pyproject.toml").read_bytes(),
            "pyproject.toml.orig": (base / "pyproject.toml").read_bytes(),
            "mcp_audit_build_backend.py": (base / "mcp_audit_build_backend.py").read_bytes(),
            **sources,
            f"{package}/_build_provenance.json": provenance,
        }
        _write_sdist(dist / sdist, {f"{stem}-{VERSION}/{name}": content for name, content in entries.items()})


def _commit(dist: Path) -> str:
    return (dist.parent / "commit").read_text()


@pytest.fixture
def train_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(release, "DISTRIBUTIONS", TRAIN)
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(release, "ROOT", repo)
    commit = _commit_train(repo, TRAIN)
    (tmp_path / "commit").write_text(commit)
    dist = tmp_path / "dist"
    dist.mkdir()
    _pack_train(repo, dist, TRAIN, commit)
    return dist


def test_all_six_artifacts_and_manifest_are_verified(train_artifacts: Path) -> None:
    hashes = dict(
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )
    )
    assert len(hashes) == 6
    manifest = {
        "schema_version": release.MANIFEST_SCHEMA,
        "version": VERSION,
        "commit": _commit(train_artifacts),
        "workflow_sha": "b" * 40,
        "files": hashes,
    }
    assert release.verify_manifest(manifest, version=VERSION, commit=_commit(train_artifacts)) == hashes
    del hashes[release.distribution_names(VERSION, TRAIN[2].name)[1]]
    with pytest.raises(release.VerificationError, match="exactly"):
        release.verify_manifest(manifest, version=VERSION, commit=_commit(train_artifacts))


def test_real_build_verifies_clean_committed_train(train_artifacts: Path) -> None:
    repo = train_artifacts.parent / "repo"
    for item in TRAIN:
        subprocess.run(
            [
                "uv",
                "build",
                "--offline",
                "--no-create-gitignore",
                "--build-constraints",
                str(repo / "build-constraints.txt"),
                "--out-dir",
                str(train_artifacts),
            ],
            cwd=repo / PurePosixPath(item.project).parent,
            check=True,
            capture_output=True,
        )
    assert (
        len(
            release.verify_distributions(
                dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
            )
        )
        == 6
    )


def test_reference_build_passes_the_committed_build_constraints(
    train_artifacts: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(args: list[str], **kwargs: object) -> object:
        calls.append(list(args))
        return real_run(args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "run", recording_run)
    release._reference_build(commit=_commit(train_artifacts), distribution=TRAIN[0])

    (build,) = [call for call in calls if call[:2] == ["uv", "build"]]
    constraints = Path(build[build.index("--build-constraints") + 1])
    assert constraints.name == "build-constraints.txt"
    assert constraints.parent.name == "source"


def test_reference_build_requires_committed_build_constraints(train_artifacts: Path) -> None:
    repo = train_artifacts.parent / "repo"
    _git(repo, "rm", "-q", "build-constraints.txt")
    _git(repo, "commit", "-q", "-m", "drop constraints")
    commit = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(release.VerificationError, match="build-constraints.txt"):
        release._reference_build(commit=commit, distribution=TRAIN[0])


def test_reference_build_is_constrained_by_the_committed_pin(train_artifacts: Path) -> None:
    repo = train_artifacts.parent / "repo"
    (repo / "build-constraints.txt").write_text("uv_build==0.0.1\n")
    _git(repo, "commit", "-q", "-am", "conflicting constraint")
    commit = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(release.VerificationError, match="reference build failed"):
        release._reference_build(commit=commit, distribution=TRAIN[0])


def _sdist_entries(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as archive:
        entries = {}
        for member in archive.getmembers():
            stream = archive.extractfile(member)
            assert stream is not None
            with stream:
                entries[member.name] = stream.read()
        return entries


def _write_sdist(path: Path, entries: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


@pytest.mark.parametrize("module_root", ["", "."])
def test_sdist_accepts_flat_package_layouts(
    train_artifacts: Path,
    monkeypatch: pytest.MonkeyPatch,
    module_root: str,
) -> None:
    labs = TRAIN[1]._replace(module_root=module_root)
    train = (TRAIN[0], labs, TRAIN[2])
    contract = train_artifacts.parent / "flat-contract.json"
    contract.write_text(json.dumps([item._asdict() for item in train]))
    monkeypatch.setattr(release, "DISTRIBUTIONS", release.load_distributions(contract))
    # The flat layout must be what the approved commit contains, not an archive rewrite.
    repo = train_artifacts.parent / "repo"
    _git(repo, "rm", "-q", "-r", "labs/src")
    commit = _commit_train(repo, train)
    for path in train_artifacts.iterdir():
        path.unlink()
    _pack_train(repo, train_artifacts, train, commit)
    assert len(release.verify_distributions(dist_dir=train_artifacts, version=VERSION, commit=commit)) == 6


@pytest.mark.parametrize(
    "mutation",
    ["pin", "additional-pin", "module", "root", "payload", "package", "provenance", "invalid-toml"],
)
def test_sdist_rebuild_inputs_must_match_contract(train_artifacts: Path, mutation: str) -> None:
    labs = TRAIN[1]
    sdist = train_artifacts / release.distribution_names(VERSION, labs.name)[1]
    entries = _sdist_entries(sdist)
    prefix = f"mcp_audits_labs-{VERSION}"
    project = f"{prefix}/pyproject.toml"
    if mutation in {"pin", "payload"}:
        entries[project] = entries[project].replace(b"mcp-audits==3.0.0", b"mcp-audits>=0")
    if mutation == "additional-pin":
        entries[project] = entries[project].replace(
            b'"mcp-audits==3.0.0"', b'"mcp-audits==3.0.0", "mcp-audits>=0"'
        )
    if mutation == "module":
        entries[project] = entries[project].replace(b'module-name="mcp_audit_labs"', b'module-name="payload"')
    if mutation in {"root", "payload"}:
        entries[project] = entries[project].replace(b'module-root="src"', b'module-root="payload"')
        entries[f"{prefix}/payload/{labs.module}/__init__.py"] = b"# different code\n"
        entries[f"{prefix}/payload/{labs.module}/_build_provenance.json"] = entries[
            f"{prefix}/src/{labs.module}/_build_provenance.json"
        ]
    if mutation in {"package", "provenance"}:
        filename = "__init__.py" if mutation == "package" else "_build_provenance.json"
        entries[f"{prefix}/payload/{labs.module}/{filename}"] = entries.pop(
            f"{prefix}/src/{labs.module}/{filename}"
        )
    if mutation == "invalid-toml":
        entries[project] = b"[project\n"
    _write_sdist(sdist, entries)
    # PKG-INFO and the wheel remain valid; only rebuild inputs have changed.
    with pytest.raises(release.VerificationError):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


def test_sdist_core_extras_must_pin_lockstep_versions(train_artifacts: Path) -> None:
    sdist = train_artifacts / release.distribution_names(VERSION)[1]
    entries = _sdist_entries(sdist)
    project = f"mcp_audits-{VERSION}/pyproject.toml"
    entries[project] = entries[project].replace(b"mcp-audits-labs==3.0.0", b"mcp-audits-labs>=0")
    _write_sdist(sdist, entries)
    with pytest.raises(release.VerificationError, match="exact lockstep"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE])
@pytest.mark.parametrize("filename", ["__init__.py", "_build_provenance.json", "linked.py", "source-root"])
def test_sdist_package_tree_rejects_links(train_artifacts: Path, kind: bytes, filename: str) -> None:
    sdist = train_artifacts / release.distribution_names(VERSION, TRAIN[1].name)[1]
    entries = _sdist_entries(sdist)
    package = f"mcp_audits_labs-{VERSION}/src/mcp_audit_labs"
    entries.pop(f"{package}/{filename}", None)
    with tarfile.open(sdist, "w:gz") as archive:
        for name, content in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        link = tarfile.TarInfo(
            f"mcp_audits_labs-{VERSION}/src" if filename == "source-root" else f"{package}/{filename}"
        )
        link.type = kind
        link.linkname = "../../payload.py"
        archive.addfile(link)
    with pytest.raises(release.VerificationError, match="regular file|without links"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
@pytest.mark.parametrize("collision", [False, True])
def test_gui_script_ownership_is_enforced(train_artifacts: Path, artifact: str, collision: bool) -> None:
    labs = TRAIN[1]
    command = "proof-before-action" if collision else "unexpected-gui"
    target = "proof_before_action.proof_cli:main"
    wheel_name, sdist_name = release.distribution_names(VERSION, labs.name)
    if artifact == "wheel":
        wheel = train_artifacts / wheel_name
        with zipfile.ZipFile(wheel) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        entries[f"mcp_audits_labs-{VERSION}.dist-info/entry_points.txt"] = (
            f"[gui_scripts]\n{command} = {target}\n".encode()
        )
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, content in entries.items():
                archive.writestr(name, content)
    else:
        sdist = train_artifacts / sdist_name
        entries = _sdist_entries(sdist)
        entries[f"mcp_audits_labs-{VERSION}/pyproject.toml"] += (
            f'[project.gui-scripts]\n{command} = "{target}"\n'.encode()
        )
        _write_sdist(sdist, entries)
    with pytest.raises(release.VerificationError, match="GUI entry points"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


@pytest.mark.parametrize("duplicate", [False, True])
def test_script_contract_covers_console_and_gui_union(duplicate: bool) -> None:
    proof = TRAIN[2]
    command, target = next(iter(proof.scripts.items()))
    console = proof.scripts if duplicate else {}
    project: dict[str, object] = {"scripts": console, "gui-scripts": proof.scripts}
    wheel = (
        "[console_scripts]\n"
        + (f"{command} = {target}\n" if duplicate else "")
        + f"[gui_scripts]\n{command} = {target}\n"
    ).encode()
    if duplicate:
        with pytest.raises(release.VerificationError, match="unique owners"):
            release._check_project_scripts(project, distribution=proof, name="fixture project")
        with pytest.raises(release.VerificationError, match="unique owners"):
            release._check_entry_points(wheel, scripts=proof.scripts, name="fixture wheel")
    else:
        release._check_project_scripts(project, distribution=proof, name="fixture project")
        release._check_entry_points(wheel, scripts=proof.scripts, name="fixture wheel")


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
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


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


@pytest.mark.parametrize(
    "mutation", ["none", "version", "lock", "scripts", "pin", "extra", "gui-collision", "core-gui-collision"]
)
def test_source_distribution_metadata_is_lockstep(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    project = release._project()
    version = release._version()
    project["scripts"] = TRAIN[0].scripts
    if mutation == "core-gui-collision":
        project["gui-scripts"] = TRAIN[0].scripts
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
                    + (
                        '[project.gui-scripts]\nproof-before-action="proof_before_action.proof_cli:main"\n'
                        if mutation == "gui-collision" and item == TRAIN[1]
                        else ""
                    )
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


def _rewrite_sdist_entries(path: Path, mutate: dict[str, bytes | None]) -> None:
    entries = _sdist_entries(path)
    for name, content in mutate.items():
        if content is None:
            entries.pop(name)
        else:
            entries[name] = content
    _write_sdist(path, entries)


@pytest.mark.parametrize("artifact", ["wheel", "sdist"])
@pytest.mark.parametrize(
    ("spelling", "accepted"),
    [
        ('mcp-audits-labs=={v}; extra == "labs "', False),
        ('mcp-audits-labs=={v}; extra == " labs"', False),
        ('mcp-audits-labs=={v}; extra == "lab"', False),
        ('mcp-audits-labs[cli]=={v}; extra == "labs"', False),
        ('mcp-audits-labs=={v}; extra == "labs" and python_version < "3"', False),
        ("mcp_audits.labs == {v} ; extra == 'labs'", True),
        ('mcp-audits-labs==={v}; extra == "labs"', False),
    ],
)
def test_core_extras_compare_parsed_requirements(
    train_artifacts: Path, artifact: str, spelling: str, accepted: bool
) -> None:
    # Grok round 3, finding 1: deleting spaces made `extra == "labs "` look pinned,
    # but pip treats it as a different extra, so `[labs]` would not pull the satellite.
    wheel_name, sdist_name = release.distribution_names(VERSION)
    original = f'Requires-Dist: mcp-audits-labs=={VERSION}; extra == "labs"\n'.encode()
    replacement = f"Requires-Dist: {spelling.format(v=VERSION)}\n".encode()
    if artifact == "wheel":
        wheel = train_artifacts / wheel_name
        entries = _wheel_entries(wheel)
        metadata = f"mcp_audits-{VERSION}.dist-info/METADATA"
        assert original in entries[metadata]
        entries[metadata] = entries[metadata].replace(original, replacement)
        entries.pop(f"mcp_audits-{VERSION}.dist-info/RECORD")
        _write_wheel(wheel, entries)
    else:
        sdist = train_artifacts / sdist_name
        name = f"mcp_audits-{VERSION}/PKG-INFO"
        content = _sdist_entries(sdist)[name]
        assert original in content
        _rewrite_sdist_entries(sdist, {name: content.replace(original, replacement)})
    if accepted:
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )
    else:
        with pytest.raises(release.VerificationError, match="exact lockstep"):
            release.verify_distributions(
                dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
            )


def test_sdist_build_system_cannot_switch_to_an_unwalked_tree(train_artifacts: Path) -> None:
    # Grok round 3, finding 2: dependencies, module keys, package and provenance all
    # still look right, but a rebuild would package payload/ with setuptools.
    labs = TRAIN[1]
    sdist = train_artifacts / release.distribution_names(VERSION, labs.name)[1]
    prefix = f"mcp_audits_labs-{VERSION}"
    project = _sdist_entries(sdist)[f"{prefix}/pyproject.toml"]
    switched = project.replace(BUILD_SYSTEM.encode(), b"").replace(
        b"[project]",
        b'[build-system]\nrequires = ["setuptools"]\nbuild-backend = "setuptools.build_meta"\n'
        b'[tool.setuptools.packages.find]\nwhere = ["payload"]\n[project]',
        1,
    )
    assert switched != project
    _rewrite_sdist_entries(
        sdist,
        {
            f"{prefix}/pyproject.toml": switched,
            f"{prefix}/payload/{labs.module}/__init__.py": b"print('unapproved')\n",
        },
    )
    with pytest.raises(release.VerificationError, match="approved commit"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


def test_sdist_pyproject_may_be_reformatted_but_not_changed(train_artifacts: Path) -> None:
    # uv_build rewrites the sdist pyproject.toml and keeps the original as .orig.
    sdist = train_artifacts / release.distribution_names(VERSION, TRAIN[1].name)[1]
    prefix = f"mcp_audits_labs-{VERSION}"
    project = _sdist_entries(sdist)[f"{prefix}/pyproject.toml"]
    _rewrite_sdist_entries(
        sdist,
        {
            f"{prefix}/pyproject.toml": b"# reformatted\n" + project.replace(b'name="', b'name = "'),
            f"{prefix}/pyproject.toml.orig": project,
        },
    )
    release.verify_distributions(dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts))
    _rewrite_sdist_entries(sdist, {f"{prefix}/pyproject.toml.orig": project + b"# edited\n"})
    with pytest.raises(release.VerificationError, match="approved commit"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


@pytest.mark.parametrize(
    "member",
    [
        "scripts/proof-before-action",
        "data/bin/proof-before-action",
        "purelib/mcp_audit_labs/__init__.py",
    ],
)
def test_wheel_data_members_are_rejected(train_artifacts: Path, member: str) -> None:
    # Grok round 3, finding 3: .data/scripts installs a command with no entry point,
    # so an empty script contract would not mean "installs no commands".
    labs = TRAIN[1]
    assert labs.scripts == {}
    wheel = train_artifacts / release.distribution_names(VERSION, labs.name)[0]
    entries = _wheel_entries(wheel)
    entries.pop(f"mcp_audits_labs-{VERSION}.dist-info/RECORD")
    entries[f"mcp_audits_labs-{VERSION}.data/{member}"] = b"#!python\nprint('unlisted command')\n"
    _write_wheel(wheel, entries)
    with pytest.raises(release.VerificationError, match="outside"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )


@pytest.mark.parametrize("item", TRAIN, ids=lambda item: item.name)
def test_wheel_modules_are_the_contracted_commit_sources(
    train_artifacts: Path, item: release.Distribution
) -> None:
    wheel = train_artifacts / release.distribution_names(VERSION, item.name)[0]
    entries = _wheel_entries(wheel)
    stem = item.name.replace("-", "_")
    entries.pop(f"{stem}-{VERSION}.dist-info/RECORD")
    entries[f"{item.module}/__init__.py"] += b"import subprocess\n"
    _write_wheel(wheel, entries)
    with pytest.raises(release.VerificationError, match="approved commit"):
        release.verify_distributions(
            dist_dir=train_artifacts, version=VERSION, commit=_commit(train_artifacts)
        )
