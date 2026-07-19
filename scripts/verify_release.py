#!/usr/bin/env python3
"""Verify that release metadata, Git identity, and distributions agree."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_STATE_PATH = ROOT / "docs/release-state.json"
EXPECTED_APPROVAL = "publish-mcp-audits"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class VerificationError(RuntimeError):
    """A release invariant is not satisfied."""


def _read_text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _project() -> dict[str, object]:
    project = tomllib.loads(_read_text("pyproject.toml"))["project"]
    if not isinstance(project, dict):
        raise VerificationError("pyproject.toml project table is invalid")
    return project


def _release_state() -> dict[str, object]:
    state = json.loads(RELEASE_STATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(state, dict):
        raise VerificationError("release-state.json must contain an object")
    return state


def _version() -> str:
    version = _project().get("version")
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        raise VerificationError("project.version must be a stable semantic version")
    return version


def _run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise VerificationError(detail)
    return result.stdout.strip()


def verify_metadata(*, require_publishable: bool) -> tuple[str, dict[str, object]]:
    version = _version()
    state = _release_state()
    server = json.loads(_read_text("server.json"))
    changelog = _read_text("CHANGELOG.md")
    readme = _read_text("README.md")
    adoption = _read_text("docs/ADOPTION-GUIDE.md")

    if state.get("schema_version") != "mcp-audit.release-state.v1":
        raise VerificationError("release-state.json schema is unsupported")
    if state.get("candidate_version") != version:
        raise VerificationError("candidate version does not match project.version")
    published = state.get("published_version")
    if not isinstance(published, str) or VERSION_RE.fullmatch(published) is None:
        raise VerificationError("published version is invalid")
    status = state.get("status")
    if status not in {"candidate", "release"}:
        raise VerificationError("release status must be candidate or release")
    if server.get("version") != version or server.get("packages", [{}])[0].get("version") != version:
        raise VerificationError("server.json versions do not match project.version")
    if f"## [{version}] -" not in changelog:
        raise VerificationError("CHANGELOG.md has no candidate release section")

    public_version = version if status == "release" else published
    for path, content in (("README.md", readme), ("docs/ADOPTION-GUIDE.md", adoption)):
        if f"saagpatel/MCPAudit@v{public_version}" not in content:
            raise VerificationError(f"{path} does not reference the usable public release")
    if f"rev: v{public_version}" not in adoption:
        raise VerificationError("pre-commit example does not reference the usable public release")

    dependencies = _project().get("dependencies")
    if not isinstance(dependencies, list) or "mcp>=1.28.1" not in dependencies:
        raise VerificationError("project metadata does not retain the mcp>=1.28.1 security floor")
    if require_publishable and status != "release":
        raise VerificationError("candidate state is intentionally non-publishable")
    return version, state


def verify_git_binding(*, tag: str, commit: str) -> None:
    version = _version()
    if tag != f"v{version}":
        raise VerificationError(f"tag must be exactly v{version}")
    if COMMIT_RE.fullmatch(commit) is None:
        raise VerificationError("commit must be an exact lowercase 40-character Git object ID")
    if _run_git("rev-parse", "HEAD") != commit:
        raise VerificationError("checked-out HEAD does not match the approved commit")
    if _run_git("rev-parse", f"refs/tags/{tag}^{{commit}}") != commit:
        raise VerificationError("release tag does not resolve to the approved commit")
    _run_git("merge-base", "--is-ancestor", commit, "origin/main")
    if _run_git("status", "--porcelain", "--untracked-files=all"):
        raise VerificationError("release checkout is dirty")


def _parse_metadata(raw: bytes) -> email.message.Message:
    return email.parser.BytesParser().parsebytes(raw)


def _check_distribution_metadata(raw: bytes, *, version: str, name: str) -> None:
    metadata = _parse_metadata(raw)
    if metadata.get("Name") != "mcp-audits":
        raise VerificationError(f"{name} has the wrong distribution name")
    if metadata.get("Version") != version:
        raise VerificationError(f"{name} has the wrong version")
    requirements = metadata.get_all("Requires-Dist", [])
    if not any(requirement.replace(" ", "").startswith("mcp>=1.28.1") for requirement in requirements):
        raise VerificationError(f"{name} does not retain the mcp>=1.28.1 security floor")


def _check_provenance(raw: bytes, *, commit: str, name: str) -> None:
    provenance = json.loads(raw)
    if provenance.get("commit") != commit or provenance.get("dirty") is not False:
        raise VerificationError(f"{name} is not bound to the clean approved commit")


def verify_distributions(*, dist_dir: Path, version: str, commit: str) -> list[tuple[str, str]]:
    wheel = dist_dir / f"mcp_audits-{version}-py3-none-any.whl"
    sdist = dist_dir / f"mcp_audits-{version}.tar.gz"
    if not wheel.is_file() or not sdist.is_file():
        raise VerificationError("expected wheel and sdist are missing")
    with zipfile.ZipFile(wheel) as archive:
        _check_distribution_metadata(
            archive.read(f"mcp_audits-{version}.dist-info/METADATA"),
            version=version,
            name=wheel.name,
        )
        _check_provenance(
            archive.read("mcp_audit/_build_provenance.json"),
            commit=commit,
            name=wheel.name,
        )
    with tarfile.open(sdist, mode="r:gz") as archive:
        prefix = f"mcp_audits-{version}"
        metadata_file = archive.extractfile(f"{prefix}/PKG-INFO")
        provenance_file = archive.extractfile(f"{prefix}/src/mcp_audit/_build_provenance.json")
        if metadata_file is None or provenance_file is None:
            raise VerificationError("sdist metadata or provenance is missing")
        _check_distribution_metadata(metadata_file.read(), version=version, name=sdist.name)
        _check_provenance(provenance_file.read(), commit=commit, name=sdist.name)
    return [(path.name, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (wheel, sdist)]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="exact v-prefixed release tag")
    parser.add_argument("--commit", help="exact 40-character approved commit")
    parser.add_argument("--approval-token")
    parser.add_argument("--require-publishable", action="store_true")
    parser.add_argument("--dist-dir", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        version, _state = verify_metadata(require_publishable=args.require_publishable)
        if args.tag is not None or args.commit is not None:
            if args.tag is None or args.commit is None:
                raise VerificationError("--tag and --commit must be supplied together")
            verify_git_binding(tag=args.tag, commit=args.commit)
        if args.approval_token is not None and args.approval_token != EXPECTED_APPROVAL:
            raise VerificationError("publication approval token is invalid")
        if args.require_publishable and args.approval_token is None and args.dist_dir is None:
            raise VerificationError("initial publish verification requires an approval token")
        hashes: list[tuple[str, str]] = []
        if args.dist_dir is not None:
            if args.commit is None:
                raise VerificationError("distribution verification requires --commit")
            hashes = verify_distributions(
                dist_dir=args.dist_dir.resolve(),
                version=version,
                commit=args.commit,
            )
    except (OSError, KeyError, IndexError, json.JSONDecodeError, VerificationError) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"release metadata verified for {version}")
    for filename, digest in hashes:
        print(f"{digest}  {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
