#!/usr/bin/env python3
"""Verify that release metadata, Git identity, and distributions agree."""

from __future__ import annotations

import argparse
import email.parser
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELEASE_STATE_PATH = ROOT / "docs/release-state.json"
VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DISTRIBUTION_NAME = "mcp-audits"
EXPECTED_SCRIPTS = {
    "mcp-audit": "mcp_audit.cli:main",
    "mcp-audits": "mcp_audit.cli:main",
    "proof-before-action": "mcp_audit.proof_cli:main",
}
SERVER_NAME = "io.github.saagpatel/mcp-audit"
REPOSITORY = {"url": "https://github.com/saagpatel/MCPAudit", "source": "github"}
MANIFEST_SCHEMA = "mcp-audits.release-manifest.v1"


def distribution_names(version: str) -> tuple[str, str]:
    if VERSION_RE.fullmatch(version) is None:
        raise VerificationError("invalid distribution version")
    return f"mcp_audits-{version}-py3-none-any.whl", f"mcp_audits-{version}.tar.gz"


def distribution_hashes(dist_dir: Path, version: str) -> list[tuple[str, str]]:
    names = distribution_names(version)
    if dist_dir.is_symlink() or not dist_dir.is_dir():
        raise VerificationError("distribution directory must be a regular directory")
    paths = list(dist_dir.iterdir())
    if {path.name for path in paths} != set(names):
        raise VerificationError("distribution set must contain exactly the expected wheel and sdist")
    for path in paths:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise VerificationError("distribution files must be regular files, never symlinks")
    return [(name, hashlib.sha256((dist_dir / name).read_bytes()).hexdigest()) for name in names]


def verify_descriptor(raw: object, *, version: str) -> None:
    package = {
        "registryType": "pypi",
        "registryBaseUrl": "https://pypi.org",
        "identifier": DISTRIBUTION_NAME,
        "version": version,
        "runtimeHint": "uvx",
        "transport": {"type": "stdio"},
        "packageArguments": [{"type": "positional", "value": "serve"}],
    }
    if (
        not isinstance(raw, dict)
        or raw.get("name") != SERVER_NAME
        or raw.get("version") != version
        or raw.get("repository") != REPOSITORY
        or raw.get("packages") != [package]
        or raw.get("remotes") not in (None, [])
    ):
        raise VerificationError("Registry descriptor does not match the exact release tuple")


def verify_manifest(
    raw: object, *, version: str, commit: str, workflow_sha: str | None = None
) -> dict[str, str]:
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version",
        "version",
        "commit",
        "workflow_sha",
        "files",
    }:
        raise VerificationError("release manifest fields are invalid")
    control_sha = raw.get("workflow_sha")
    if (
        raw.get("schema_version") != MANIFEST_SCHEMA
        or raw.get("version") != version
        or raw.get("commit") != commit
        or COMMIT_RE.fullmatch(commit) is None
        or not isinstance(control_sha, str)
        or COMMIT_RE.fullmatch(control_sha) is None
        or (workflow_sha is not None and control_sha != workflow_sha)
    ):
        raise VerificationError("release manifest identity does not match approval")
    files = raw.get("files")
    if not isinstance(files, dict) or set(files) != set(distribution_names(version)):
        raise VerificationError("release manifest must name exactly the wheel and sdist")
    hashes: dict[str, str] = {}
    for name, digest in files.items():
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise VerificationError("release manifest digest is invalid")
        hashes[name] = digest
    return hashes


def verify_pypi(raw: object, *, version: str, hashes: dict[str, str]) -> None:
    if not isinstance(raw, dict):
        raise VerificationError("PyPI response must be an object")
    info, urls = raw.get("info"), raw.get("urls")
    if not isinstance(info, dict) or info.get("name") != DISTRIBUTION_NAME or info.get("version") != version:
        raise VerificationError("PyPI release identity is invalid")
    if not isinstance(urls, list) or len(urls) != 2:
        raise VerificationError("PyPI release must contain exactly two files")
    observed: dict[str, str] = {}
    for entry in urls:
        if not isinstance(entry, dict):
            raise VerificationError("PyPI file entry is invalid")
        name, digests = entry.get("filename"), entry.get("digests")
        if not isinstance(name, str) or name in observed or not isinstance(digests, dict):
            raise VerificationError("PyPI filename or digest is invalid")
        digest = digests.get("sha256")
        kind = "bdist_wheel" if name.endswith(".whl") else "sdist"
        if (
            not isinstance(digest, str)
            or entry.get("yanked") is not False
            or entry.get("packagetype") != kind
        ):
            raise VerificationError("PyPI file is yanked or has invalid type/digest")
        observed[name] = digest
    if observed != hashes:
        raise VerificationError("PyPI filenames and SHA-256 do not match the approved manifest")


def verify_registry(raw: object, *, version: str) -> None:
    if not isinstance(raw, dict):
        raise VerificationError("Registry response must be an object")
    verify_descriptor(raw.get("server"), version=version)
    meta = raw.get("_meta")
    official = meta.get("io.modelcontextprotocol.registry/official") if isinstance(meta, dict) else None
    if (
        not isinstance(official, dict)
        or official.get("status") != "active"
        or official.get("isLatest") is not True
    ):
        raise VerificationError("Registry release must be active and latest")


class VerificationError(RuntimeError):
    """A release invariant is not satisfied."""


def _set_root(path: Path) -> None:
    global ROOT, RELEASE_STATE_PATH
    ROOT = path.resolve()
    RELEASE_STATE_PATH = ROOT / "docs/release-state.json"


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


def _locked_project_version() -> str:
    lock = tomllib.loads(_read_text("uv.lock"))
    for package in lock.get("package", []):
        if isinstance(package, dict) and package.get("name") == "mcp-audits":
            version = package.get("version")
            if isinstance(version, str) and VERSION_RE.fullmatch(version):
                return version
    raise VerificationError("uv.lock is missing the mcp-audits project version")


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


def _check_release_notes(raw: str, *, version: str, status: str) -> None:
    if f"MCPAudit {version}" not in raw:
        raise VerificationError("versioned changelog section is missing or mismatched")
    expected_status = "candidate" if status == "candidate" else "approved"
    expected_decision = "NO-GO" if status == "candidate" else "GO"
    status_markers = re.findall(
        r"^Release status: (candidate|approved)$",
        raw,
        re.MULTILINE,
    )
    decision_markers = re.findall(
        r"^Publication decision: (GO|NO-GO)$",
        raw,
        re.MULTILINE,
    )
    if status_markers != [expected_status]:
        raise VerificationError("release notes have a missing or conflicting status marker")
    if decision_markers != [expected_decision]:
        raise VerificationError("release notes have a missing or conflicting publication decision")
    if status == "release" and ("`NO-GO`" in raw or "does not authorize" in raw):
        raise VerificationError("release notes still contain candidate-only publication language")


def verify_environment_protection(raw: object, branch_policies: object = None) -> None:
    if not isinstance(raw, dict):
        raise VerificationError("PyPI environment response must be an object")
    if raw.get("can_admins_bypass") is not False:
        raise VerificationError("PyPI environment permits administrator bypass")
    if raw.get("deployment_branch_policy") != {"protected_branches": False, "custom_branch_policies": True}:
        raise VerificationError("PyPI environment requires custom main-only deployment branches")
    branches = branch_policies.get("branch_policies") if isinstance(branch_policies, dict) else None
    if (
        not isinstance(branches, list)
        or len(branches) != 1
        or not isinstance(branches[0], dict)
        or branches[0].get("name") != "main"
        or branches[0].get("type") != "branch"
    ):
        raise VerificationError("PyPI environment deployment policy must allow only the main branch")
    rules = raw.get("protection_rules")
    if not isinstance(rules, list):
        raise VerificationError("PyPI environment protection rules are unavailable")
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "required_reviewers":
            continue
        reviewers = rule.get("reviewers")
        if not isinstance(reviewers, list) or len(reviewers) != 1 or not isinstance(reviewers[0], dict):
            continue
        reviewer = reviewers[0].get("reviewer")
        if (
            isinstance(rule.get("prevent_self_review"), bool)
            and reviewers[0].get("type") == "User"
            and isinstance(reviewer, dict)
            and reviewer.get("login") == "saagpatel"
        ):
            return
    raise VerificationError("PyPI environment requires a named solo-maintainer reviewer")


def verify_metadata(*, require_publishable: bool) -> tuple[str, dict[str, object]]:
    project = _project()
    version = _version()
    state = _release_state()
    server = json.loads(_read_text("server.json"))
    changelog = _read_text("CHANGELOG.md")
    readme = _read_text("README.md")
    adoption = _read_text("docs/ADOPTION-GUIDE.md")
    precommit = _read_text(".pre-commit-hooks.yaml")

    if project.get("name") != DISTRIBUTION_NAME:
        raise VerificationError("project metadata has the wrong distribution name")
    if project.get("scripts") != EXPECTED_SCRIPTS:
        raise VerificationError("project metadata has the wrong console entry points")

    if state.get("schema_version") != "mcp-audit.release-state.v1":
        raise VerificationError("release-state.json schema is unsupported")
    if state.get("candidate_version") != version:
        raise VerificationError("candidate version does not match project.version")
    if _locked_project_version() != version:
        raise VerificationError("uv.lock project version does not match project.version")
    published = state.get("published_version")
    if not isinstance(published, str) or VERSION_RE.fullmatch(published) is None:
        raise VerificationError("published version is invalid")
    status_value = state.get("status")
    if not isinstance(status_value, str) or status_value not in {"candidate", "release"}:
        raise VerificationError("release status must be candidate or release")
    status = status_value
    if status == "release" and published != version:
        raise VerificationError("release status requires published_version to equal the candidate")
    if status == "candidate" and published == version:
        raise VerificationError("candidate version must differ from the published version")
    if status == "candidate" and state.get("previous_version") != published:
        raise VerificationError("candidate previous_version must equal the published version")
    public_version = version if status == "release" else published
    verify_descriptor(server, version=public_version)
    for path, content in (("README.md", readme), ("docs/ADOPTION-GUIDE.md", adoption)):
        if f"saagpatel/MCPAudit@v{public_version}" not in content:
            raise VerificationError(f"{path} does not reference the usable public release")
    if f"rev: v{public_version}" not in adoption:
        raise VerificationError("pre-commit example does not reference the usable public release")
    if f"#       rev: v{public_version}" not in precommit:
        raise VerificationError("pre-commit usage comment does not reference the usable public release")

    dependencies = project.get("dependencies")
    if not isinstance(dependencies, list) or "mcp>=2.2.0,<3.0" not in dependencies:
        raise VerificationError("project metadata does not retain the tested MCP SDK range")
    if "cryptography>=50.0.0,<51.0" not in dependencies:
        raise VerificationError("project metadata does not retain the cryptography>=50.0.0 security floor")
    if "click>=8.3.3,<9.0" not in dependencies:
        raise VerificationError("project metadata does not retain the click>=8.3.3 security floor")
    if "anyio>=4.14.2" not in dependencies:
        raise VerificationError("project metadata does not retain the anyio>=4.14.2 security floor")
    release_match = re.search(
        rf"(?ms)^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        changelog,
    )
    if release_match is None:
        raise VerificationError("versioned changelog section is missing")
    release_notes = release_match.group(1)
    _check_release_notes(
        release_notes,
        version=version,
        status=status,
    )
    if status == "candidate" and f"mcp-audits=={published}" not in release_notes:
        raise VerificationError("candidate release notes do not retain the published rollback pin")
    if status == "candidate":
        if f"## [{version}] - Unreleased" not in changelog:
            raise VerificationError("candidate changelog section is not explicitly unreleased")
        expected_link = f"[{version}]: https://github.com/saagpatel/MCPAudit/compare/v{published}...HEAD"
        if expected_link not in changelog:
            raise VerificationError("candidate comparison link is not based on the published tag")
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
    if metadata.get("Name") != DISTRIBUTION_NAME:
        raise VerificationError(f"{name} has the wrong distribution name")
    if metadata.get("Version") != version:
        raise VerificationError(f"{name} has the wrong version")
    requirements = metadata.get_all("Requires-Dist", [])
    normalized_requirements = {requirement.replace(" ", "") for requirement in requirements}
    if not ({"mcp>=2.2.0,<3.0", "mcp<3.0,>=2.2.0"} & normalized_requirements):
        raise VerificationError(f"{name} does not retain the tested MCP SDK range")
    normalized = normalized_requirements
    if "cryptography>=50.0.0,<51.0" not in normalized:
        raise VerificationError(f"{name} does not retain the cryptography>=50.0.0 security floor")
    if "click>=8.3.3,<9.0" not in normalized:
        raise VerificationError(f"{name} does not retain the click>=8.3.3 security floor")
    if "anyio>=4.14.2" not in normalized:
        raise VerificationError(f"{name} does not retain the anyio>=4.14.2 security floor")


def _check_provenance(raw: bytes, *, commit: str, name: str) -> None:
    provenance = json.loads(raw)
    if provenance.get("commit") != commit or provenance.get("dirty") is not False:
        raise VerificationError(f"{name} is not bound to the clean approved commit")


def _check_entry_points(raw: bytes, *, name: str) -> None:
    observed: dict[str, str] = {}
    in_console_scripts = False
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("["):
            in_console_scripts = line.strip() == "[console_scripts]"
            continue
        if in_console_scripts and "=" in line:
            command, target = line.split("=", maxsplit=1)
            observed[command.strip()] = target.strip()
    if observed != EXPECTED_SCRIPTS:
        raise VerificationError(f"{name} console entry points do not match the release contract")


def verify_distributions(*, dist_dir: Path, version: str, commit: str) -> list[tuple[str, str]]:
    hashes = distribution_hashes(dist_dir, version)
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
    if distribution_hashes(dist_dir, version) != hashes:
        raise VerificationError("distribution set or digests changed during verification")
    return hashes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="exact v-prefixed release tag")
    parser.add_argument("--commit", help="exact 40-character approved commit")
    parser.add_argument(
        "--environment-json",
        type=Path,
        help="live GitHub response for the protected PyPI environment",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="release source checkout to verify",
    )
    parser.add_argument("--require-publishable", action="store_true")
    parser.add_argument("--dist-dir", type=Path)
    parser.add_argument("--branch-policies-json", type=Path)
    parser.add_argument("--workflow-sha", help="exact workflow/control revision, separate from source commit")
    parser.add_argument("--manifest", type=Path, help="approved release manifest to recheck")
    parser.add_argument("--write-manifest", type=Path)
    parser.add_argument("--manifest-sha256", help="separately approved manifest digest")
    parser.add_argument("--response-json", type=Path)
    parser.add_argument(
        "--publication-check", choices=("environment", "artifacts", "pypi", "descriptor", "registry")
    )
    return parser


def _load_json(path: Path | None) -> object:
    if path is None:
        raise VerificationError("required JSON input is missing")
    return json.loads(path.read_text(encoding="utf-8"))


def _publication_check(args: argparse.Namespace) -> None:
    if args.publication_check == "environment":
        verify_environment_protection(
            _load_json(args.environment_json), _load_json(args.branch_policies_json)
        )
        return
    if args.tag is None or not args.tag.startswith("v") or args.commit is None:
        raise VerificationError("publication check requires tag and approved commit")
    version = args.tag[1:]
    distribution_names(version)
    if COMMIT_RE.fullmatch(args.commit) is None:
        raise VerificationError("approved commit is invalid")
    if args.publication_check == "descriptor":
        verify_descriptor(_load_json(args.response_json), version=version)
    elif args.publication_check == "registry":
        verify_registry(_load_json(args.response_json), version=version)
    else:
        if args.manifest_sha256 is not None:
            if args.manifest is None or re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) is None:
                raise VerificationError("approved manifest SHA-256 is invalid")
            if hashlib.sha256(args.manifest.read_bytes()).hexdigest() != args.manifest_sha256:
                raise VerificationError("manifest SHA-256 does not match approval")
        hashes = verify_manifest(
            _load_json(args.manifest), version=version, commit=args.commit, workflow_sha=args.workflow_sha
        )
        if args.publication_check == "pypi":
            if args.manifest_sha256 is None:
                raise VerificationError("PyPI verification requires separately approved manifest SHA-256")
            verify_pypi(_load_json(args.response_json), version=version, hashes=hashes)
        elif args.dist_dir is None or dict(distribution_hashes(args.dist_dir, version)) != hashes:
            raise VerificationError("distribution digests do not match the approved manifest")


def main() -> int:
    args = _parser().parse_args()
    _set_root(args.root)
    try:
        if args.publication_check is not None:
            _publication_check(args)
            print(f"publication {args.publication_check} verified")
            return 0
        version, _state = verify_metadata(require_publishable=args.require_publishable)
        if args.tag is not None and args.commit is None:
            raise VerificationError("--tag requires --commit")
        if args.require_publishable and (args.tag is None or args.commit is None):
            raise VerificationError("publish verification requires --tag and --commit")
        if args.require_publishable and args.environment_json is None:
            raise VerificationError("publish verification requires live PyPI environment state")
        if args.commit is not None:
            verify_git_binding(
                tag=args.tag,
                commit=args.commit,
                require_landed=args.require_publishable,
            )
        if args.environment_json is not None:
            verify_environment_protection(
                _load_json(args.environment_json), _load_json(args.branch_policies_json)
            )
        hashes: list[tuple[str, str]] = []
        if args.dist_dir is not None:
            if args.commit is None:
                raise VerificationError("distribution verification requires --commit")
            hashes = verify_distributions(
                dist_dir=args.dist_dir,
                version=version,
                commit=args.commit,
            )
        if args.manifest is not None:
            expected = verify_manifest(
                _load_json(args.manifest), version=version, commit=args.commit, workflow_sha=args.workflow_sha
            )
            if dict(hashes) != expected:
                raise VerificationError("distribution digests do not match the approved manifest")
        if args.write_manifest is not None:
            if not hashes or args.workflow_sha is None or COMMIT_RE.fullmatch(args.workflow_sha) is None:
                raise VerificationError("manifest creation requires distributions and exact workflow SHA")
            args.write_manifest.write_text(
                json.dumps(
                    {
                        "schema_version": MANIFEST_SCHEMA,
                        "version": version,
                        "commit": args.commit,
                        "workflow_sha": args.workflow_sha,
                        "files": dict(hashes),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
    except (
        OSError,
        KeyError,
        IndexError,
        ValueError,
        zipfile.BadZipFile,
        tarfile.TarError,
        VerificationError,
    ) as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    print(f"release metadata verified for {version}")
    for filename, digest in hashes:
        print(f"{digest}  {filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
