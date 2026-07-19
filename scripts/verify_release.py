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
    if status == "release" and published != version:
        raise VerificationError("release status requires published_version to equal the candidate")
    public_version = version if status == "release" else published
    if (
        server.get("version") != public_version
        or server.get("packages", [{}])[0].get("version") != public_version
    ):
        raise VerificationError("server.json does not reference the usable public release")
    for path, content in (("README.md", readme), ("docs/ADOPTION-GUIDE.md", adoption)):
        if f"saagpatel/MCPAudit@v{public_version}" not in content:
            raise VerificationError(f"{path} does not reference the usable public release")
    if f"rev: v{public_version}" not in adoption:
        raise VerificationError("pre-commit example does not reference the usable public release")

    dependencies = _project().get("dependencies")
    if not isinstance(dependencies, list) or "mcp>=1.28.1" not in dependencies:
        raise VerificationError("project metadata does not retain the mcp>=1.28.1 security floor")
    release_notes = ROOT / f"docs/{version.rsplit('.', maxsplit=1)[0]}-RELEASE-NOTES.md"
    if not release_notes.is_file() or f"MCPAudit {version}" not in release_notes.read_text(encoding="utf-8"):
        raise VerificationError("versioned release notes are missing or mismatched")
    if status == "candidate":
        if f"## [{version}] - Unreleased" not in changelog:
            raise VerificationError("candidate changelog section is not explicitly unreleased")
    else:
        if (
            re.search(
                rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$",
                changelog,
                re.MULTILINE,
            )
            is None
        ):
            raise VerificationError("release changelog section must have a final date")
        if f"[Unreleased]: https://github.com/saagpatel/MCPAudit/compare/v{version}...HEAD" not in changelog:
            raise VerificationError("Unreleased comparison link is not based on the final tag")
        previous = state.get("previous_version")
        if not isinstance(previous, str) or VERSION_RE.fullmatch(previous) is None:
            raise VerificationError("release status requires a valid previous_version")
        expected_link = f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/v{previous}...v{version}"
        if expected_link not in changelog:
            raise VerificationError("release comparison link is not finalized")
    if require_publishable and status != "release":
        raise VerificationError("candidate state is intentionally non-publishable")
    return version, state


def verify_git_binding(*, tag: str | None, commit: str, require_landed: bool) -> None:
    version = _version()
    if COMMIT_RE.fullmatch(commit) is None:
        raise VerificationError("commit must be an exact lowercase 40-character Git object ID")
    if _run_git("rev-parse", "HEAD") != commit:
        raise VerificationError("checked-out HEAD does not match the approved commit")
    if _run_git("status", "--porcelain", "--untracked-files=all"):
        raise VerificationError("release checkout is dirty")
    if tag is not None:
        if tag != f"v{version}":
            raise VerificationError(f"tag must be exactly v{version}")
        if _run_git("rev-parse", f"refs/tags/{tag}^{{commit}}") != commit:
            raise VerificationError("release tag does not resolve to the approved commit")
    if require_landed:
        _run_git("merge-base", "--is-ancestor", commit, "origin/main")


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


def _check_entry_points(raw: bytes, *, name: str) -> None:
    expected = {
        "mcp-audit": "mcp_audit.cli:main",
        "mcp-audits": "mcp_audit.cli:main",
        "proof-before-action": "mcp_audit.proof_cli:main",
    }
    observed: dict[str, str] = {}
    in_console_scripts = False
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("["):
            in_console_scripts = line.strip() == "[console_scripts]"
            continue
        if in_console_scripts and "=" in line:
            command, target = line.split("=", maxsplit=1)
            observed[command.strip()] = target.strip()
    if observed != expected:
        raise VerificationError(f"{name} console entry points do not match the release contract")


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
        _check_entry_points(
            archive.read(f"mcp_audits-{version}.dist-info/entry_points.txt"),
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
        pyproject_file = archive.extractfile(f"{prefix}/pyproject.toml")
        if pyproject_file is None:
            raise VerificationError("sdist pyproject.toml is missing")
        scripts = tomllib.loads(pyproject_file.read().decode("utf-8")).get("project", {}).get("scripts")
        if scripts != {
            "mcp-audit": "mcp_audit.cli:main",
            "mcp-audits": "mcp_audit.cli:main",
            "proof-before-action": "mcp_audit.proof_cli:main",
        }:
            raise VerificationError("sdist console entry points do not match the release contract")
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
        if args.tag is not None and args.commit is None:
            raise VerificationError("--tag requires --commit")
        if args.require_publishable and (args.tag is None or args.commit is None):
            raise VerificationError("publish verification requires --tag and --commit")
        if args.commit is not None:
            verify_git_binding(
                tag=args.tag,
                commit=args.commit,
                require_landed=args.require_publishable,
            )
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
