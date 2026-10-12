"""Offline negative probes of publication identity and artifact boundaries."""

from __future__ import annotations

import copy
import io
import json
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
COMMIT = "a" * 40
WORKFLOW_SHA = "b" * 40


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


@pytest.fixture
def distributions(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    metadata = (
        f"Name: mcp-audits\nVersion: {VERSION}\nRequires-Dist: mcp>=2.2.0,<3.0\n"
        "Requires-Dist: cryptography>=50.0.0,<51.0\nRequires-Dist: click>=8.3.3,<9.0\n"
        "Requires-Dist: anyio>=4.14.2\n"
    ).encode()
    provenance = json.dumps({"commit": COMMIT, "dirty": False}).encode()
    entries = "[console_scripts]\n" + "".join(f"{k} = {v}\n" for k, v in release.EXPECTED_SCRIPTS.items())
    project = Path("pyproject.toml").read_text(encoding="utf-8")
    wheel, sdist = release.distribution_names(VERSION)
    with zipfile.ZipFile(dist / wheel, "w") as archive:
        archive.writestr(f"mcp_audits-{VERSION}.dist-info/METADATA", metadata)
        archive.writestr(f"mcp_audits-{VERSION}.dist-info/entry_points.txt", entries)
        archive.writestr("mcp_audit/_build_provenance.json", provenance)
    with tarfile.open(dist / sdist, "w:gz") as archive:
        for name, content in (
            ("PKG-INFO", metadata),
            ("src/mcp_audit/__init__.py", b""),
            ("src/mcp_audit/_build_provenance.json", provenance),
            ("pyproject.toml", project.encode()),
        ):
            info = tarfile.TarInfo(f"mcp_audits-{VERSION}/{name}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return dist


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


@pytest.mark.parametrize("name", release.distribution_names(VERSION))
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
def test_probe_release_binds_pypi_to_approved_manifest(distributions: Path, mutation: str) -> None:
    hashes = dict(release.distribution_hashes(distributions, VERSION))
    urls: list[dict[str, object]] = [
        {
            "filename": name,
            "digests": {"sha256": digest},
            "yanked": False,
            "packagetype": "bdist_wheel" if name.endswith(".whl") else "sdist",
        }
        for name, digest in hashes.items()
    ]
    raw = {"info": {"name": "mcp-audits", "version": VERSION}, "urls": urls}
    release.verify_pypi(raw, version=VERSION, hashes=hashes)
    if mutation == "digest":
        urls[0]["digests"] = {"sha256": "0" * 64}
    elif mutation == "filename":
        urls[0]["filename"] = "different.whl"
    elif mutation == "yanked":
        urls[0]["yanked"] = True
    else:
        urls.append(dict(urls[0]))
    with pytest.raises(release.VerificationError):
        release.verify_pypi(raw, version=VERSION, hashes=hashes)


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
