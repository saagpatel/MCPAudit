"""Repository-only MCP discovery and local mcp-trust evidence joining."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit, urlunsplit

from mcp_audit.proof_models import (
    DependencyOccurrence,
    DiscoveryDiagnostic,
    ReleaseTrustManifest,
    SubjectSnapshotEvidence,
    TrustEntry,
    TrustEvidence,
    TrustSource,
    canonical_json_bytes,
    sha256_bytes,
)

_REPO_CONFIGS = (".mcp.json", ".vscode/mcp.json", ".cursor/mcp.json")
_EXACT_VERSION = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")
_PYPI_NORMALIZE = re.compile(r"[-_.]+")


def build_release_trust_manifest(
    repo: Path,
    trust_root: Path | None,
    *,
    subject_snapshot: SubjectSnapshotEvidence | None = None,
) -> ReleaseTrustManifest:
    root = repo.resolve()
    if subject_snapshot is None:
        dependencies, diagnostics = discover_repo_mcp(root)
        commit, dirty = _git_state(root)
        staged_tree_sha256 = None
    else:
        dependencies = subject_snapshot.dependencies
        diagnostics = subject_snapshot.diagnostics
        commit = subject_snapshot.repository_commit
        dirty = subject_snapshot.repository_dirty
        staged_tree_sha256 = subject_snapshot.staged_tree_sha256
    if trust_root is None:
        entries = [
            TrustEntry(
                dependency=item,
                evidence=TrustEvidence(
                    state="unmatched",
                    match_state="unmatched",
                    unknown_reasons=["mcp-trust source was not provided"],
                ),
            )
            for item in dependencies
        ]
        return ReleaseTrustManifest(
            repository_commit=commit,
            repository_dirty=dirty,
            repository_staged_tree_sha256=staged_tree_sha256,
            discovery_coverage="partial" if diagnostics else "complete",
            dependencies=dependencies,
            diagnostics=diagnostics,
            trust_source=None,
            entries=entries,
            limitations=[
                "Trust evidence is UNKNOWN because no local mcp-trust source was provided.",
                *_repository_limitations(commit, dirty),
            ],
        )
    return _join_trust(
        trust_root.resolve(),
        dependencies,
        diagnostics,
        repository_commit=commit,
        repository_dirty=dirty,
        repository_staged_tree_sha256=staged_tree_sha256,
    )


def discover_repo_mcp(
    repo: Path,
) -> tuple[list[DependencyOccurrence], list[DiscoveryDiagnostic]]:
    dependencies: list[DependencyOccurrence] = []
    diagnostics: list[DiscoveryDiagnostic] = []
    for relative in _REPO_CONFIGS:
        path = repo / relative
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            diagnostics.append(
                DiscoveryDiagnostic(
                    source_path=relative,
                    source_pointer="/",
                    code="invalid_config",
                    message=f"configuration could not be parsed: {type(exc).__name__}",
                )
            )
            continue
        server_map_key = "mcpServers" if isinstance(payload, dict) and "mcpServers" in payload else "servers"
        servers = payload.get(server_map_key) if isinstance(payload, dict) else None
        if not isinstance(servers, dict):
            diagnostics.append(
                DiscoveryDiagnostic(
                    source_path=relative,
                    source_pointer="/",
                    code="missing_server_map",
                    message="expected an object at mcpServers or servers",
                )
            )
            continue
        for name, config in servers.items():
            pointer = f"/{server_map_key}/{_json_pointer(str(name))}"
            if not isinstance(config, dict):
                diagnostics.append(
                    DiscoveryDiagnostic(
                        source_path=relative,
                        source_pointer=pointer,
                        code="invalid_entry",
                        message="server entry must be an object",
                    )
                )
                continue
            dependencies.append(_config_occurrence(relative, pointer, str(name), config))

    package_json = repo / "package.json"
    if package_json.is_file():
        try:
            package_payload = json.loads(package_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                values = package_payload.get(section, {})
                if not isinstance(values, dict):
                    continue
                for name, version in values.items():
                    if "mcp" not in str(name).lower():
                        continue
                    dependencies.append(
                        _package_occurrence(
                            "package.json",
                            f"/{section}/{_json_pointer(str(name))}",
                            str(name),
                            str(version),
                            "npm",
                        )
                    )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            diagnostics.append(
                DiscoveryDiagnostic(
                    source_path="package.json",
                    source_pointer="/",
                    code="invalid_manifest",
                    message=f"package manifest could not be parsed: {type(exc).__name__}",
                )
            )

    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        try:
            project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get("project", {})
            for index, spec in enumerate(project.get("dependencies", [])):
                if "mcp" not in str(spec).lower():
                    continue
                name, version, exact = _parse_pypi_spec(str(spec))
                dependencies.append(
                    _occurrence(
                        source_path="pyproject.toml",
                        source_pointer=f"/project/dependencies/{index}",
                        config_name=name,
                        transport="package",
                        identity_kind="pypi",
                        identity_name=name,
                        requested_version=version,
                        exact=exact,
                        command_basename=None,
                        args=[],
                    )
                )
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            diagnostics.append(
                DiscoveryDiagnostic(
                    source_path="pyproject.toml",
                    source_pointer="/project/dependencies",
                    code="invalid_manifest",
                    message=f"Python manifest could not be parsed: {type(exc).__name__}",
                )
            )

    descriptor = repo / "server.json"
    if descriptor.is_file():
        try:
            payload = json.loads(descriptor.read_text(encoding="utf-8"))
            packages = payload.get("packages", []) if isinstance(payload, dict) else []
            for index, package in enumerate(packages):
                if not isinstance(package, dict):
                    diagnostics.append(
                        DiscoveryDiagnostic(
                            source_path="server.json",
                            source_pointer=f"/packages/{index}",
                            code="invalid_entry",
                            message="package descriptor must be an object",
                        )
                    )
                    continue
                registry = str(package.get("registryType", "unknown"))
                kind = "npm" if registry == "npm" else "pypi" if registry == "pypi" else "unknown"
                name = str(package.get("identifier", ""))
                version = str(package.get("version", "")) or None
                transport_payload = package.get("transport", {})
                if isinstance(transport_payload, dict):
                    transport = str(transport_payload.get("type", "unknown"))
                else:
                    diagnostics.append(
                        DiscoveryDiagnostic(
                            source_path="server.json",
                            source_pointer=f"/packages/{index}/transport",
                            code="invalid_entry",
                            message="package transport must be an object",
                        )
                    )
                    transport = "unknown"
                dependencies.append(
                    _occurrence(
                        source_path="server.json",
                        source_pointer=f"/packages/{index}",
                        config_name=str(payload.get("name", name)),
                        transport=transport,
                        identity_kind=kind,
                        identity_name=_normalize_package(name, kind),
                        requested_version=version,
                        exact=bool(version and _EXACT_VERSION.fullmatch(version)),
                        command_basename=str(package.get("runtimeHint", "")) or None,
                        args=[],
                    )
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            diagnostics.append(
                DiscoveryDiagnostic(
                    source_path="server.json",
                    source_pointer="/",
                    code="invalid_manifest",
                    message=f"MCP registry descriptor could not be parsed: {type(exc).__name__}",
                )
            )

    dependencies.sort(key=lambda item: (item.source_path, item.source_pointer, item.dependency_id))
    diagnostics.sort(key=lambda item: (item.source_path, item.source_pointer, item.code))
    return dependencies, diagnostics


def _config_occurrence(
    source_path: str, pointer: str, name: str, config: dict[str, Any]
) -> DependencyOccurrence:
    command = config.get("command")
    args = [str(item) for item in config.get("args", [])] if isinstance(config.get("args", []), list) else []
    url = config.get("url")
    kind = "unknown"
    identity: str | None = None
    version: str | None = None
    exact = False
    if isinstance(url, str):
        kind = "remote"
        identity = _normalize_remote(url)
        exact = True
    elif isinstance(command, str):
        basename = Path(command).name.lower()
        if basename in {"npx", "npm", "pnpm", "yarn"}:
            kind, identity, version, exact = _parse_npm_args(args)
        elif basename in {"uvx", "uv"}:
            kind, identity, version, exact = _parse_pypi_args(args)
        elif basename in {"git"}:
            kind = "git"
        else:
            kind = "binary"
            identity = basename
            exact = True
    env_keys = sorted(str(key) for key in config.get("env", {}) if isinstance(key, str))
    headers = config.get("headers", {})
    header_keys = sorted(str(key) for key in headers if isinstance(headers, dict))
    return _occurrence(
        source_path=source_path,
        source_pointer=pointer,
        config_name=name,
        transport="remote" if isinstance(url, str) else "stdio",
        identity_kind=kind,
        identity_name=identity,
        requested_version=version,
        exact=exact,
        command_basename=Path(command).name if isinstance(command, str) else None,
        args=args,
        env_key_names=env_keys,
        header_key_names=header_keys,
    )


def _package_occurrence(
    source_path: str, pointer: str, name: str, spec: str, kind: str
) -> DependencyOccurrence:
    normalized = _normalize_package(name, kind)
    version = spec if _EXACT_VERSION.fullmatch(spec) else None
    return _occurrence(
        source_path=source_path,
        source_pointer=pointer,
        config_name=name,
        transport="package",
        identity_kind=kind,
        identity_name=normalized,
        requested_version=version,
        exact=version is not None,
        command_basename=None,
        args=[],
    )


def _occurrence(
    *,
    source_path: str,
    source_pointer: str,
    config_name: str,
    transport: str,
    identity_kind: str,
    identity_name: str | None,
    requested_version: str | None,
    exact: bool,
    command_basename: str | None,
    args: list[str],
    env_key_names: list[str] | None = None,
    header_key_names: list[str] | None = None,
) -> DependencyOccurrence:
    material = f"{source_path}\0{source_pointer}\0{identity_kind}\0{identity_name or ''}".encode()
    dependency_id = "dep_" + hashlib.sha256(material).hexdigest()[:20]
    return DependencyOccurrence(
        dependency_id=dependency_id,
        source_path=source_path,
        source_pointer=source_pointer,
        config_name=config_name,
        transport=transport,
        identity_kind=identity_kind,  # type: ignore[arg-type]
        identity_name=identity_name,
        requested_version=requested_version,
        version_source="config_exact"
        if exact and requested_version
        else ("not_applicable" if exact else "unresolved"),
        command_basename=command_basename,
        args_sha256=sha256_bytes(canonical_json_bytes(args)),
        env_key_names=env_key_names or [],
        header_key_names=header_key_names or [],
    )


def _join_trust(
    trust_root: Path,
    dependencies: list[DependencyOccurrence],
    diagnostics: list[DiscoveryDiagnostic],
    *,
    repository_commit: str | None,
    repository_dirty: bool | None,
    repository_staged_tree_sha256: str | None,
) -> ReleaseTrustManifest:
    files = {
        "catalog_snapshot.json": trust_root / "src/mcp_trust/catalog_snapshot.json",
        "seed_servers.json": trust_root / "src/mcp_trust/catalog/seed_servers.json",
        "masked-grades.json": trust_root / "masked-grades.json",
        "spec_shift_verdicts.json": trust_root / "src/mcp_trust/core/spec_shift_verdicts.json",
    }
    missing = [name for name, path in files.items() if not path.is_file()]
    if missing:
        diagnostics = [
            *diagnostics,
            DiscoveryDiagnostic(
                source_path="<mcp-trust>",
                source_pointer="/",
                code="trust_source_incomplete",
                message=f"missing required trust inputs: {', '.join(sorted(missing))}",
            ),
        ]
        return _unknown_trust_manifest(
            dependencies,
            diagnostics,
            repository_commit,
            repository_dirty,
            repository_staged_tree_sha256,
            f"mcp-trust source is incomplete: {', '.join(sorted(missing))}",
        )
    try:
        input_bytes = {name: path.read_bytes() for name, path in files.items()}
        snapshot = json.loads(input_bytes["catalog_snapshot.json"])
        seed = json.loads(input_bytes["seed_servers.json"])
        masked_payload = json.loads(input_bytes["masked-grades.json"])
        spec_shift = json.loads(input_bytes["spec_shift_verdicts.json"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _unknown_trust_manifest(
            dependencies,
            diagnostics,
            repository_commit,
            repository_dirty,
            repository_staged_tree_sha256,
            f"mcp-trust source could not be parsed: {type(exc).__name__}",
        )
    if not _valid_trust_input_shapes(snapshot, seed, masked_payload, spec_shift):
        return _unknown_trust_manifest(
            dependencies,
            diagnostics,
            repository_commit,
            repository_dirty,
            repository_staged_tree_sha256,
            "mcp-trust source has an unsupported data shape",
        )
    masked = set(masked_payload)
    trust_commit, trust_dirty = _git_state(trust_root)
    trust_inputs_bound = bool(
        trust_commit
        and _input_bytes_match_git_commit(
            trust_root,
            trust_commit,
            {files[name]: value for name, value in input_bytes.items()},
        )
    )
    snapshot_generated_at = str(snapshot.get("generated_at", "")) or "unknown"
    evaluated_at = datetime.now(UTC).date().isoformat() + "T23:59:59.999999+00:00"
    source = TrustSource(
        repository_commit=trust_commit,
        dirty=trust_dirty,
        schema_versions={
            "catalog_snapshot": snapshot.get("schema_version", "unknown"),
            "spec_shift": spec_shift.get("format_version", "unknown"),
        },
        file_sha256={name: sha256_bytes(input_bytes[name]) for name in sorted(files)},
        snapshot_generated_at=snapshot_generated_at,
        evaluated_at=evaluated_at,
    )
    seed_rows = seed if isinstance(seed, list) else seed.get("servers", [])
    records = snapshot.get("servers", [])
    entries = [
        TrustEntry(
            dependency=dependency,
            evidence=_match_dependency(
                dependency,
                seed_rows if isinstance(seed_rows, list) else [],
                records if isinstance(records, list) else [],
                masked,
                evaluated_at,
            ),
        )
        for dependency in dependencies
    ]
    trust_authority_reason: str | None = None
    if trust_commit is None:
        trust_authority_reason = (
            "mcp-trust source commit could not be verified; entry-level trust evidence is non-authoritative"
        )
    elif trust_dirty is not False:
        trust_authority_reason = (
            "mcp-trust source worktree is dirty; entry-level trust evidence is non-authoritative"
        )
    elif not trust_inputs_bound:
        trust_authority_reason = (
            "required mcp-trust inputs are not byte-identical to the trust commit; "
            "entry-level trust evidence is non-authoritative"
        )
    if trust_authority_reason is not None:
        entries = [
            entry.model_copy(
                update={
                    "evidence": _without_trust_source_authority(
                        entry.evidence,
                        trust_authority_reason,
                    )
                }
            )
            for entry in entries
        ]
    limitations = [
        "mcp-trust grades describe an observed MCP surface, not runtime safety or endorsement.",
        "Version applicability is UNKNOWN when mcp-trust evidence is not bound to the "
        "exact dependency version.",
        "Freshness is evaluated at the recorded current UTC date; the snapshot generation "
        "timestamp remains separately bound.",
        *_repository_limitations(repository_commit, repository_dirty),
    ]
    if trust_dirty:
        limitations.append("The mcp-trust source worktree is dirty; trust-source authority is UNKNOWN.")
    if trust_commit is None:
        limitations.append("The mcp-trust source commit is UNKNOWN; trust-source authority is UNKNOWN.")
    elif not trust_inputs_bound:
        limitations.append(
            "Required mcp-trust inputs are not byte-identical to the trust commit; "
            "trust-source authority is UNKNOWN."
        )
    return ReleaseTrustManifest(
        repository_commit=repository_commit,
        repository_dirty=repository_dirty,
        repository_staged_tree_sha256=repository_staged_tree_sha256,
        discovery_coverage="partial" if diagnostics else "complete",
        dependencies=dependencies,
        diagnostics=diagnostics,
        trust_source=source,
        entries=entries,
        limitations=limitations,
    )


def _valid_trust_input_shapes(
    snapshot: Any,
    seed: Any,
    masked: Any,
    spec_shift: Any,
) -> bool:
    if not isinstance(snapshot, dict) or not isinstance(spec_shift, dict):
        return False
    if (
        not isinstance(snapshot.get("schema_version"), (int, str))
        or not isinstance(snapshot.get("generated_at"), str)
        or not isinstance(spec_shift.get("format_version"), (int, str))
        or not isinstance(spec_shift.get("servers"), dict)
    ):
        return False
    records = snapshot.get("servers")
    if not isinstance(records, list) or not all(_valid_snapshot_record(item) for item in records):
        return False
    generated_at = _trust_timestamp(snapshot["generated_at"])
    if generated_at is None or generated_at > datetime.now(UTC):
        return False
    scanned_at = [_trust_timestamp(item["scanned_at"]) for item in records]
    if any(value is None or value > generated_at for value in scanned_at):
        return False
    seed_rows = seed if isinstance(seed, list) else seed.get("servers") if isinstance(seed, dict) else None
    if not isinstance(seed_rows, list) or not all(_valid_seed_row(item) for item in seed_rows):
        return False
    return isinstance(masked, list) and all(isinstance(item, str) for item in masked)


def _trust_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return None
        return timestamp.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def _valid_seed_row(value: Any) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("slug"), str) or not value["slug"]:
        return False
    source = value.get("source")
    return (
        isinstance(source, dict)
        and isinstance(source.get("kind"), str)
        and bool(source["kind"])
        and isinstance(source.get("reference"), str)
        and bool(source["reference"])
    )


def _valid_snapshot_record(value: Any) -> bool:
    required_strings = (
        "slug",
        "grade",
        "transparency",
        "scanned_at",
        "engine",
        "engine_version",
        "scan_mode",
    )
    if not isinstance(value, dict) or not all(
        isinstance(value.get(field), str) and bool(value[field]) for field in required_strings
    ):
        return False
    sandbox = value.get("sandbox")
    return (
        isinstance(sandbox, dict)
        and isinstance(sandbox.get("mode"), str)
        and bool(sandbox["mode"])
        and isinstance(sandbox.get("network"), str)
        and bool(sandbox["network"])
    )


def _without_trust_source_authority(
    evidence: TrustEvidence,
    reason: str,
) -> TrustEvidence:
    return TrustEvidence(
        state="unverifiable",
        match_state=evidence.match_state,
        slug=evidence.slug,
        network_isolation="unknown",
        version_alignment=evidence.version_alignment,
        unknown_reasons=list(dict.fromkeys([*evidence.unknown_reasons, reason])),
    )


def _match_dependency(
    dependency: DependencyOccurrence,
    seed: list[dict[str, Any]],
    records: list[dict[str, Any]],
    masked: set[str],
    evaluated_at: str,
) -> TrustEvidence:
    if dependency.identity_name is None:
        return TrustEvidence(
            state="unmatched",
            match_state="unmatched",
            unknown_reasons=["dependency identity could not be normalized"],
        )
    candidates = [item for item in seed if _source_key(item.get("source", {})) == _dependency_key(dependency)]
    if len(candidates) > 1:
        return TrustEvidence(
            state="ambiguous",
            match_state="ambiguous",
            unknown_reasons=["multiple mcp-trust catalog identities matched"],
        )
    if not candidates:
        return TrustEvidence(
            state="unmatched",
            match_state="unmatched",
            unknown_reasons=["no mcp-trust catalog identity matched"],
        )
    slug = cast(str, candidates[0]["slug"])
    if slug in masked:
        return TrustEvidence(
            state="masked",
            match_state="exact",
            slug=slug,
            version_alignment="unknown",
            unknown_reasons=["operator-masked evidence is intentionally withheld"],
        )
    matches = [item for item in records if item.get("slug") == slug]
    if len(matches) != 1:
        return TrustEvidence(
            state="unverifiable",
            match_state="exact",
            slug=slug,
            unknown_reasons=["grade-bearing snapshot record is missing or ambiguous"],
        )
    record = matches[0]
    stale = _is_stale(record.get("scanned_at"), evaluated_at)
    version_alignment: Literal[
        "exact",
        "dependency_unresolved",
        "evidence_unversioned",
        "not_applicable",
        "unknown",
    ] = (
        "dependency_unresolved"
        if dependency.version_source == "unresolved"
        else "evidence_unversioned"
        if dependency.requested_version
        else "not_applicable"
    )
    unknowns: list[str] = []
    state = "stale" if stale is True else "current"
    if stale is None:
        state = "unverifiable"
        unknowns.append("scan freshness could not be verified")
    if version_alignment in {"dependency_unresolved", "evidence_unversioned"}:
        state = "unverifiable" if state == "current" else state
        unknowns.append("evidence is not bound to an exact dependency version")
    sandbox = cast(dict[str, Any], record["sandbox"])
    network: Literal["verified_none", "unknown", "not_applicable"] = (
        "verified_none"
        if record.get("scan_mode") == "mcpaudit-local-network-off"
        and isinstance(sandbox, dict)
        and sandbox.get("network") == "none"
        else "not_applicable"
        if isinstance(sandbox, dict) and sandbox.get("mode") == "not_applicable"
        else "unknown"
    )
    if network != "verified_none":
        state = "unverifiable" if state == "current" else state
        unknowns.append(
            "mcp-trust record does not prove network isolation"
            if network == "unknown"
            else "network isolation was not applicable to the recorded scan"
        )
    return TrustEvidence(
        state=state,  # type: ignore[arg-type]
        match_state="exact",
        slug=slug,
        grade=cast(str, record["grade"]),
        transparency=cast(str, record["transparency"]),
        scanned_at=cast(str, record["scanned_at"]),
        engine=cast(str, record["engine"]),
        engine_version=cast(str, record["engine_version"]),
        scan_mode=cast(str, record["scan_mode"]),
        network_isolation=network,
        version_alignment=version_alignment,
        unknown_reasons=unknowns,
    )


def _unknown_trust_manifest(
    dependencies: list[DependencyOccurrence],
    diagnostics: list[DiscoveryDiagnostic],
    repository_commit: str | None,
    repository_dirty: bool | None,
    repository_staged_tree_sha256: str | None,
    reason: str,
) -> ReleaseTrustManifest:
    return ReleaseTrustManifest(
        repository_commit=repository_commit,
        repository_dirty=repository_dirty,
        repository_staged_tree_sha256=repository_staged_tree_sha256,
        discovery_coverage="unknown",
        dependencies=dependencies,
        diagnostics=diagnostics,
        trust_source=None,
        entries=[
            TrustEntry(
                dependency=item,
                evidence=TrustEvidence(
                    state="unverifiable",
                    match_state="unmatched",
                    unknown_reasons=[reason],
                ),
            )
            for item in dependencies
        ],
        limitations=[reason, *_repository_limitations(repository_commit, repository_dirty)],
    )


def _source_key(source: Any) -> tuple[str, str] | None:
    if not isinstance(source, dict):
        return None
    kind = str(source.get("kind", ""))
    reference = source.get("reference")
    if not isinstance(reference, str):
        return None
    if kind == "npm":
        return "npm", _normalize_package(reference, "npm")
    if kind == "pypi":
        return "pypi", _normalize_package(reference, "pypi")
    if kind == "remote":
        return "remote", _normalize_remote(reference)
    return kind, reference


def _dependency_key(dependency: DependencyOccurrence) -> tuple[str, str]:
    return dependency.identity_kind, dependency.identity_name or ""


def _parse_npm_args(args: list[str]) -> tuple[str, str | None, str | None, bool]:
    candidates = [item for item in args if item and not item.startswith("-")]
    if not candidates:
        return "npm", None, None, False
    raw = candidates[0]
    name, version = raw, None
    split_at = raw.rfind("@")
    if split_at > 0:
        name, candidate = raw[:split_at], raw[split_at + 1 :]
        if candidate:
            version = candidate
    exact = bool(version and _EXACT_VERSION.fullmatch(version))
    return "npm", _normalize_package(name, "npm"), version if exact else None, exact


def _parse_pypi_args(args: list[str]) -> tuple[str, str | None, str | None, bool]:
    candidates = [item for item in args if item and not item.startswith("-") and item not in {"run", "tool"}]
    if not candidates:
        return "pypi", None, None, False
    name, version, exact = _parse_pypi_spec(candidates[0])
    return "pypi", name, version, exact


def _parse_pypi_spec(spec: str) -> tuple[str, str | None, bool]:
    base = spec.split("[", 1)[0]
    if "==" in base:
        name, version = base.split("==", 1)
        exact = "*" not in version and bool(_EXACT_VERSION.fullmatch(version))
        return _normalize_package(name.strip(), "pypi"), version if exact else None, exact
    name = re.split(r"[<>=!~ ]", base, maxsplit=1)[0]
    return _normalize_package(name.strip(), "pypi"), None, False


def _normalize_package(name: str, kind: str) -> str:
    value = name.strip().lower()
    if kind == "pypi":
        return _PYPI_NORMALIZE.sub("-", value)
    return value


def _normalize_remote(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "sha256:" + hashlib.sha256(url.encode()).hexdigest()
    host = parsed.hostname or ""
    try:
        private = ipaddress.ip_address(host).is_private
    except ValueError:
        private = host in {"localhost"} or host.endswith(".local")
    if private:
        return "sha256:" + hashlib.sha256(url.encode()).hexdigest()
    netloc = host.lower()
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path.rstrip("/"), "", ""))


def _is_stale(scanned_at: Any, evaluated_at: str) -> bool | None:
    if not isinstance(scanned_at, str) or not evaluated_at:
        return None
    try:
        scanned = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
        evaluated = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if scanned.tzinfo is None:
        scanned = scanned.replace(tzinfo=UTC)
    if evaluated.tzinfo is None:
        evaluated = evaluated.replace(tzinfo=UTC)
    if scanned > evaluated:
        return None
    return (evaluated - scanned).days > 90


def _git_state(root: Path) -> tuple[str | None, bool | None]:
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        return commit, bool(status)
    except (OSError, subprocess.SubprocessError):
        return None, None


def _input_bytes_match_git_commit(
    root: Path,
    commit: str,
    inputs: dict[Path, bytes],
) -> bool:
    for path, loaded_bytes in inputs.items():
        try:
            relative = path.relative_to(root).as_posix()
            committed = subprocess.run(
                ["git", "-C", str(root), "show", f"{commit}:{relative}"],
                check=False,
                capture_output=True,
                timeout=5,
            )
            if committed.returncode != 0 or committed.stdout != loaded_bytes:
                return False
        except (OSError, ValueError, subprocess.SubprocessError):
            return False
    return True


def _repository_limitations(commit: str | None, dirty: bool | None) -> list[str]:
    limitations: list[str] = []
    if commit is None:
        limitations.append("Subject repository commit is UNKNOWN; release evidence is not commit-bound.")
    if dirty is None:
        limitations.append(
            "Subject staged-tree binding is UNKNOWN; the repository commit cannot be treated as binding."
        )
    elif dirty:
        limitations.append(
            "Subject repository is dirty; its commit does not bind the inspected working tree."
        )
    return limitations


def _json_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")
