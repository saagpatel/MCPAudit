#!/usr/bin/env python3
"""Verify that release metadata, Git identity, and distributions agree."""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import email.parser
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from packaging.requirements import Requirement

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
EXTRA_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
PROVENANCE_FILE = "_build_provenance.json"
SECURITY_FLOORS = (
    ("mcp>=2.2.0,<3.0", "the tested MCP SDK range"),
    ("cryptography>=50.0.0,<51.0", "the cryptography>=50.0.0 security floor"),
    ("click>=8.3.3,<9.0", "the click>=8.3.3 security floor"),
    ("anyio>=4.14.2", "the anyio>=4.14.2 security floor"),
)


class Distribution(NamedTuple):
    name: str
    module: str
    project: str
    scripts: dict[str, str]
    module_root: str = "src"


DISTRIBUTIONS: tuple[Distribution, ...] = (
    Distribution(DISTRIBUTION_NAME, "mcp_audit", "pyproject.toml", EXPECTED_SCRIPTS),
)
RELEASE_BRANCH = "main"


def load_distributions(path: Path) -> tuple[Distribution, ...]:
    """Load an explicit release contract; the unsplit train remains the default."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise VerificationError("distribution contract must be a nonempty list")
    distributions = []
    commands: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "module",
            "project",
            "scripts",
            "module_root",
        }:
            raise VerificationError("distribution contract fields are invalid")
        name, module, project, scripts, module_root = (
            entry[key] for key in ("name", "module", "project", "scripts", "module_root")
        )
        if (
            not isinstance(name, str)
            or not isinstance(module, str)
            or not all(part.isidentifier() for part in module.split("."))
            or not isinstance(project, str)
            or not isinstance(module_root, str)
            or any(Path(value).is_absolute() or ".." in Path(value).parts for value in (project, module_root))
            or not project.endswith("pyproject.toml")
            or not isinstance(scripts, dict)
            or not all(isinstance(key, str) and isinstance(value, str) for key, value in scripts.items())
        ):
            raise VerificationError("distribution contract values are invalid")
        if commands.intersection(scripts):
            raise VerificationError("distribution scripts must have unique owners")
        commands.update(scripts)
        distributions.append(Distribution(name, module, project, scripts, module_root))
    if [item.name for item in distributions] not in (
        ["mcp-audits"],
        ["mcp-audits", "mcp-audits-labs", "mcp-audits-proof"],
    ):
        raise VerificationError("distribution contract must follow core, labs, proof publication order")
    if distributions[0].project != "pyproject.toml":
        raise VerificationError("core project must be the repository pyproject.toml")
    return tuple(distributions)


def distribution_names(version: str, distribution: str = DISTRIBUTION_NAME) -> tuple[str, str]:
    if VERSION_RE.fullmatch(version) is None:
        raise VerificationError("invalid distribution version")
    if RELEASE_BRANCH == "release/2.x" and not version.startswith("2."):
        raise VerificationError("release/2.x requires a 2.x distribution version")
    stem = distribution.replace("-", "_")
    return f"{stem}-{version}-py3-none-any.whl", f"{stem}-{version}.tar.gz"


def _all_distribution_names(version: str) -> tuple[str, ...]:
    return tuple(name for item in DISTRIBUTIONS for name in distribution_names(version, item.name))


def distribution_hashes(dist_dir: Path, version: str) -> list[tuple[str, str]]:
    names = _all_distribution_names(version)
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
    if not isinstance(files, dict) or set(files) != set(_all_distribution_names(version)):
        raise VerificationError("release manifest must name exactly the wheel and sdist")
    hashes: dict[str, str] = {}
    for name, digest in files.items():
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise VerificationError("release manifest digest is invalid")
        hashes[name] = digest
    return hashes


def verify_pypi(
    raw: object, *, version: str, hashes: dict[str, str], distribution: str = DISTRIBUTION_NAME
) -> None:
    if not isinstance(raw, dict):
        raise VerificationError("PyPI response must be an object")
    info, urls = raw.get("info"), raw.get("urls")
    if not isinstance(info, dict) or info.get("name") != distribution or info.get("version") != version:
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


def _locked_project_version(distribution: str = DISTRIBUTION_NAME) -> str:
    lock = tomllib.loads(_read_text("uv.lock"))
    for package in lock.get("package", []):
        if isinstance(package, dict) and package.get("name") == distribution:
            version = package.get("version")
            if isinstance(version, str) and VERSION_RE.fullmatch(version):
                return version
    raise VerificationError(f"uv.lock is missing the {distribution} project version")


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
        raise VerificationError("PyPI environment requires custom deployment branches")
    branches = branch_policies.get("branch_policies") if isinstance(branch_policies, dict) else None
    if (
        not isinstance(branches, list)
        or len(branches) != 1
        or not isinstance(branches[0], dict)
        or branches[0].get("name") != RELEASE_BRANCH
        or branches[0].get("type") != "branch"
    ):
        raise VerificationError(f"PyPI environment deployment policy must allow only {RELEASE_BRANCH}")
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
    _check_project_scripts(project, distribution=DISTRIBUTIONS[0], name="project metadata")

    if RELEASE_BRANCH == "release/2.x" and not version.startswith("2."):
        raise VerificationError("release/2.x requires a 2.x project version")
    for distribution in DISTRIBUTIONS[1:]:
        other = tomllib.loads(_read_text(distribution.project)).get("project", {})
        if other.get("name") != distribution.name or other.get("version") != version:
            raise VerificationError("distribution projects must have lockstep names and versions")
        if _locked_project_version(distribution.name) != version:
            raise VerificationError("uv.lock distribution versions must be lockstep")
        _check_project_scripts(other, distribution=distribution, name="distribution project")
        if f"mcp-audits=={version}" not in other.get("dependencies", []):
            raise VerificationError("satellite distributions must pin the exact core version")
    if len(DISTRIBUTIONS) == 3:
        extras = project.get("optional-dependencies")
        expected_extras = {
            "labs": [f"mcp-audits-labs=={version}"],
            "proof": [f"mcp-audits-proof=={version}"],
            "all": [f"mcp-audits-labs=={version}", f"mcp-audits-proof=={version}"],
        }
        if not isinstance(extras, dict) or any(
            extras.get(key) != value for key, value in expected_extras.items()
        ):
            raise VerificationError("core extras must pin exact lockstep satellite versions")

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
    if not re.search(rf"^#\s+rev: v{re.escape(public_version)}\s*$", precommit, re.MULTILINE):
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
        _run_git("merge-base", "--is-ancestor", commit, f"origin/{RELEASE_BRANCH}")


def _parse_metadata(raw: bytes) -> email.message.Message:
    return email.parser.BytesParser().parsebytes(raw)


def _requirement(raw: str, *, name: str) -> Requirement:
    # Imported here so the publication checks keep running on a bare interpreter.
    from packaging.requirements import InvalidRequirement, Requirement

    try:
        return Requirement(raw)
    except InvalidRequirement as exc:
        raise VerificationError(f"{name} requirement {raw!r} is invalid") from exc


def _requirement_key(requirement: Requirement) -> tuple[object, ...]:
    """What an installer acts on: packaging normalizes spacing, never quoted marker values."""
    from packaging.utils import canonicalize_name

    return (
        canonicalize_name(requirement.name),
        requirement.url or "",
        frozenset(canonicalize_name(extra) for extra in requirement.extras),
        requirement.specifier,
        "" if requirement.marker is None else str(requirement.marker),
    )


def _check_requirements(
    requirements: Iterable[Requirement], *, version: str, name: str, distribution: Distribution
) -> None:
    observed = {_requirement_key(requirement) for requirement in requirements}
    lockstep: list[str] = []
    if distribution.name != DISTRIBUTION_NAME:
        lockstep.append(f"mcp-audits=={version}")
    elif len(DISTRIBUTIONS) == 3:
        for extra, packages in (
            ("labs", ("mcp-audits-labs",)),
            ("proof", ("mcp-audits-proof",)),
            ("all", ("mcp-audits-labs", "mcp-audits-proof")),
        ):
            lockstep.extend(f'{package}=={version}; extra == "{extra}"' for package in packages)
    names = {item.name for item in DISTRIBUTIONS}
    if {key for key in observed if key[0] in names} != {
        _requirement_key(_requirement(raw, name=name)) for raw in lockstep
    }:
        raise VerificationError(f"{name} must pin the exact lockstep distribution versions")
    if distribution.name != DISTRIBUTION_NAME:
        return
    for raw, label in SECURITY_FLOORS:
        if _requirement_key(_requirement(raw, name=name)) not in observed:
            raise VerificationError(f"{name} does not retain {label}")


def _check_distribution_metadata(
    raw: bytes, *, version: str, name: str, distribution: Distribution | None = None
) -> None:
    distribution = distribution or DISTRIBUTIONS[0]
    metadata = _parse_metadata(raw)
    if metadata.get("Name") != distribution.name:
        raise VerificationError(f"{name} has the wrong distribution name")
    if metadata.get("Version") != version:
        raise VerificationError(f"{name} has the wrong version")
    _check_requirements(
        (_requirement(str(value), name=name) for value in metadata.get_all("Requires-Dist", [])),
        version=version,
        name=name,
        distribution=distribution,
    )


def _check_provenance(raw: bytes, *, commit: str, name: str) -> None:
    provenance = json.loads(raw)
    if provenance.get("commit") != commit or provenance.get("dirty") is not False:
        raise VerificationError(f"{name} is not bound to the clean approved commit")


def _check_entry_points(raw: bytes, *, name: str, scripts: dict[str, str] | None = None) -> None:
    class EntryPointParser(configparser.ConfigParser):
        def optionxform(self, optionstr: str) -> str:
            return optionstr

    parser = EntryPointParser(interpolation=None)
    try:
        parser.read_string(raw.decode("utf-8"))
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise VerificationError(f"{name} entry points are invalid") from exc
    observed = _installed_scripts(
        dict(parser.items("console_scripts")) if parser.has_section("console_scripts") else {},
        dict(parser.items("gui_scripts")) if parser.has_section("gui_scripts") else {},
        name=name,
    )
    if observed != (DISTRIBUTIONS[0].scripts if scripts is None else scripts):
        raise VerificationError(
            f"{name} console entry points and GUI entry points do not match the release contract"
        )


def _installed_scripts(console: object, gui: object, *, name: str) -> dict[str, str]:
    scripts: dict[str, str] = {}
    for table in (console, gui):
        if not isinstance(table, dict):
            raise VerificationError(f"{name} script table is invalid")
        for command, target in table.items():
            if not isinstance(command, str) or not isinstance(target, str):
                raise VerificationError(f"{name} script entry is invalid")
            if command in scripts:
                raise VerificationError(f"{name} installed scripts must have unique owners")
            scripts[command] = target
    return scripts


def _check_project_scripts(project: dict[str, object], *, distribution: Distribution, name: str) -> None:
    scripts = _installed_scripts(project.get("scripts", {}), project.get("gui-scripts", {}), name=name)
    if scripts != distribution.scripts:
        raise VerificationError(
            f"{name} console entry points and GUI entry points do not match the release contract"
        )


def _check_sdist_project(raw: bytes, *, distribution: Distribution, version: str, name: str) -> None:
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"{name} pyproject.toml is invalid") from exc
    project = data.get("project")
    if not isinstance(project, dict):
        raise VerificationError(f"{name} project table is invalid")
    if project.get("name") != distribution.name or project.get("version") != version:
        raise VerificationError(f"{name} project identity does not match the release contract")
    _check_project_scripts(project, distribution=distribution, name=name)
    tool = data.get("tool")
    uv = tool.get("uv") if isinstance(tool, dict) else None
    settings = uv.get("build-backend") if isinstance(uv, dict) else None
    if (
        not isinstance(settings, dict)
        or settings.get("module-name") != distribution.module
        or settings.get("module-root", "src") != distribution.module_root
    ):
        raise VerificationError(f"{name} build module-name/module-root do not match the release contract")

    dependencies = project.get("dependencies", [])
    extras = project.get("optional-dependencies", {})
    if not isinstance(dependencies, list) or not isinstance(extras, dict):
        raise VerificationError(f"{name} project dependencies are invalid")
    from packaging.markers import Marker

    requirements: list[Requirement] = []
    for extra, values in [(None, dependencies), *extras.items()]:
        if not isinstance(values, list) or (
            extra is not None and (not isinstance(extra, str) or EXTRA_RE.fullmatch(extra) is None)
        ):
            raise VerificationError(f"{name} project dependencies are invalid")
        for value in values:
            if not isinstance(value, str):
                raise VerificationError(f"{name} project dependency is invalid")
            requirement = _requirement(value, name=name)
            if extra is not None:
                # Existing markers remain conditions, never unconditional lockstep pins.
                condition = f'extra == "{extra}"'
                marker = requirement.marker
                requirement.marker = Marker(condition if marker is None else f"({marker}) and {condition}")
            requirements.append(requirement)
    _check_requirements(requirements, version=version, name=name, distribution=distribution)


def _check_archive_names(names: list[str], *, prefix: str, name: str) -> None:
    """Every member has one canonical spelling under the root, so what is checked is what installs.

    Archive readers return the first or last of duplicate names while extraction
    normalizes ``./x`` and ``a//b`` onto the same path, so an alias could show the
    verifier one file and the installer another.
    """
    seen: set[str] = set()
    for raw in names:
        member = raw.rstrip("/")
        path = PurePosixPath(member)
        if (
            not member
            or path.is_absolute()
            or str(path) != member
            or any(part in {"", ".", ".."} for part in member.split("/"))
            or (prefix and path.parts[0] != prefix)
        ):
            raise VerificationError(f"{name} member {raw!r} is not a canonical path under the release root")
        if member in seen:
            raise VerificationError(f"{name} member {raw!r} appears more than once")
        seen.add(member)


def _sdist_file(archive: tarfile.TarFile, member: PurePosixPath) -> bytes:
    try:
        info = archive.getmember(str(member))
    except KeyError as exc:
        raise VerificationError(f"sdist {member.name} is missing from the contracted root") from exc
    if not info.isfile():
        raise VerificationError(f"sdist {member.name} must be a regular file")
    stream = archive.extractfile(info)
    if stream is None:
        raise VerificationError(f"sdist {member.name} is missing")
    with stream:
        return stream.read()


def _commit_files(commit: str, paths: Iterable[str]) -> dict[str, bytes]:
    """Return the bytes of each requested path that is a regular file at the approved commit."""
    wanted = set(paths)
    objects: dict[str, str] = {}
    for entry in _run_git("ls-tree", "-r", "-z", "--full-tree", commit).split("\0"):
        fields, _, path = entry.partition("\t")
        mode, kind, oid = (fields.split(" ") + ["", "", ""])[:3]
        if path in wanted and kind == "blob" and mode in {"100644", "100755"}:
            objects[path] = oid
    if not objects:
        return {}
    result = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "--batch"],
        input="".join(f"{oid}\n" for oid in objects.values()).encode(),
        check=False,
        capture_output=True,
        timeout=60,
    )
    if result.returncode != 0:
        raise VerificationError("approved commit contents are unreadable")
    blobs: dict[str, bytes] = {}
    position = 0
    for _ in objects:
        header_end = result.stdout.index(b"\n", position)
        oid, kind, size = result.stdout[position:header_end].decode().split(" ")
        if kind != "blob":
            raise VerificationError("approved commit contents are unreadable")
        start = header_end + 1
        blobs[oid] = result.stdout[start : start + int(size)]
        position = start + int(size) + 1
    return {path: blobs[oid] for path, oid in objects.items()}


def _check_commit_content(
    contents: dict[str, bytes], sources: dict[str, str], *, commit: str, name: str
) -> None:
    """Every member is byte-identical to its source path at the approved commit."""
    approved = _commit_files(commit, sources.values())
    for member, source in sources.items():
        if approved.get(source) != contents[member]:
            raise VerificationError(f"{name} member {member!r} does not match the approved commit")


def _check_record(archive: zipfile.ZipFile, record: str, *, name: str) -> None:
    """RECORD drives uninstall, so it must name exactly the wheel's files with their digests."""
    try:
        rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        raise VerificationError(f"{name} RECORD is missing or invalid") from exc
    files = {info.filename for info in archive.infolist() if not info.is_dir()}
    listed = {row[0]: row[1:] for row in rows if len(row) == 3}
    if len(listed) != len(rows) or set(listed) != files:
        raise VerificationError(f"{name} RECORD must list exactly the wheel's files")
    for path in files - {record}:
        content = archive.read(path)
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        if listed[path] != [f"sha256={digest}", str(len(content))]:
            raise VerificationError(f"{name} RECORD digest for {path!r} does not match")
    if listed[record] != ["", ""]:
        raise VerificationError(f"{name} RECORD must not list a digest for itself")


def verify_distributions(*, dist_dir: Path, version: str, commit: str) -> list[tuple[str, str]]:
    hashes = distribution_hashes(dist_dir, version)
    for distribution in DISTRIBUTIONS:
        _verify_distribution(dist_dir=dist_dir, version=version, commit=commit, distribution=distribution)
    if distribution_hashes(dist_dir, version) != hashes:
        raise VerificationError("distribution set or digests changed during verification")
    return hashes


def _verify_distribution(*, dist_dir: Path, version: str, commit: str, distribution: Distribution) -> None:
    wheel_name, sdist_name = distribution_names(version, distribution.name)
    wheel, sdist = dist_dir / wheel_name, dist_dir / sdist_name
    stem = distribution.name.replace("-", "_")
    module = distribution.module.replace(".", "/")
    # Paths at the approved commit: the build project's directory and its module source root.
    project_dir = PurePosixPath(distribution.project).parent
    source_root = project_dir / distribution.module_root
    if not wheel.is_file() or not sdist.is_file():
        raise VerificationError("expected wheel and sdist are missing")
    with zipfile.ZipFile(wheel) as archive:
        _check_archive_names(archive.namelist(), prefix="", name=wheel.name)
        dist_info = f"{stem}-{version}.dist-info"
        _check_distribution_metadata(
            archive.read(f"{dist_info}/METADATA"),
            version=version,
            name=wheel.name,
            distribution=distribution,
        )
        _check_provenance(archive.read(f"{module}/{PROVENANCE_FILE}"), commit=commit, name=wheel.name)
        _check_entry_points(
            archive.read(f"{dist_info}/entry_points.txt")
            if f"{dist_info}/entry_points.txt" in archive.namelist()
            else b"",
            name=wheel.name,
            scripts=distribution.scripts,
        )
        # A wheel installs its generated dist-info and the contracted module, nothing else:
        # no .data/ (scripts, headers, data), no other top-level packages or .pth files.
        sources: dict[str, str] = {}
        for info in archive.infolist():
            path = info.filename.rstrip("/")
            if stat.S_IFMT(info.external_attr >> 16) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise VerificationError(f"{wheel.name} must contain regular files without links")
            if path == dist_info or path.startswith(f"{dist_info}/"):
                continue
            if info.is_dir() and (path == module or f"{module}/".startswith(f"{path}/")):
                continue
            if not path.startswith(f"{module}/"):
                raise VerificationError(
                    f"{wheel.name} member {info.filename!r} is outside the contracted module and dist-info"
                )
            if not info.is_dir() and path != f"{module}/{PROVENANCE_FILE}":
                sources[path] = str(source_root / path)
        _check_commit_content(
            {path: archive.read(path) for path in sources}, sources, commit=commit, name=wheel.name
        )
        _check_record(archive, f"{dist_info}/RECORD", name=wheel.name)
    with tarfile.open(sdist, mode="r:gz") as archive:
        prefix = PurePosixPath(f"{stem}-{version}")
        members = archive.getmembers()
        _check_archive_names([info.name for info in members], prefix=str(prefix), name=sdist.name)
        if any(not (info.isfile() or info.isdir()) for info in members):
            raise VerificationError(f"{sdist.name} must contain regular files without links")
        pyproject = _sdist_file(archive, prefix / "pyproject.toml")
        _check_sdist_project(pyproject, distribution=distribution, version=version, name=sdist.name)
        package = prefix / distribution.module_root / module
        if not any(
            info.isfile() and PurePosixPath(info.name).is_relative_to(package) and info.name.endswith(".py")
            for info in members
        ):
            raise VerificationError("sdist package tree is missing from the contracted root")
        _check_distribution_metadata(
            _sdist_file(archive, prefix / "PKG-INFO"),
            version=version,
            name=sdist.name,
            distribution=distribution,
        )
        _check_provenance(_sdist_file(archive, package / PROVENANCE_FILE), commit=commit, name=sdist.name)
        # Everything a rebuild reads (pyproject, in-tree backend, sources) is the approved tree.
        # Generated by the build: PKG-INFO and provenance (checked above), and uv_build's
        # normalized pyproject.toml, which must parse identically while .orig keeps the bytes.
        project_source = str(project_dir / "pyproject.toml")
        generated = {prefix / "PKG-INFO", prefix / "pyproject.toml", package / PROVENANCE_FILE}
        sources = {
            info.name: project_source
            if PurePosixPath(info.name) == prefix / "pyproject.toml.orig"
            else str(project_dir / PurePosixPath(info.name).relative_to(prefix))
            for info in members
            if info.isfile() and PurePosixPath(info.name) not in generated
        }
        _check_commit_content(
            {member: _sdist_file(archive, PurePosixPath(member)) for member in sources},
            sources,
            commit=commit,
            name=sdist.name,
        )
        approved_project = _commit_files(commit, [project_source]).get(project_source)
        try:
            same_project = approved_project is not None and tomllib.loads(
                pyproject.decode("utf-8")
            ) == tomllib.loads(approved_project.decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError):
            same_project = False
        if not same_project:
            raise VerificationError(f"{sdist.name} pyproject.toml does not match the approved commit")


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
    parser.add_argument("--distributions", type=Path, help="reviewed JSON distribution/script contract")
    parser.add_argument("--release-branch", choices=("main", "release/2.x"), default="main")
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
            responses = _load_json(args.response_json)
            if len(DISTRIBUTIONS) == 1:
                responses = {DISTRIBUTION_NAME: responses}
            if not isinstance(responses, dict) or set(responses) != {item.name for item in DISTRIBUTIONS}:
                raise VerificationError("PyPI readback must include every distribution")
            for distribution in DISTRIBUTIONS:
                verify_pypi(
                    responses[distribution.name],
                    version=version,
                    hashes={name: hashes[name] for name in distribution_names(version, distribution.name)},
                    distribution=distribution.name,
                )
        elif args.dist_dir is None or dict(distribution_hashes(args.dist_dir, version)) != hashes:
            raise VerificationError("distribution digests do not match the approved manifest")


def main() -> int:
    global DISTRIBUTIONS, RELEASE_BRANCH
    args = _parser().parse_args()
    _set_root(args.root)
    try:
        RELEASE_BRANCH = args.release_branch
        if args.distributions is not None:
            DISTRIBUTIONS = load_distributions(args.distributions)
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
