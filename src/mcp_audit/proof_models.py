"""Versioned contracts for the local-first Proof Before Action product."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DECLARATION_SCHEMA: Final = "proof-before-action.declaration.v1"
OBSERVATION_SCHEMA: Final = "proof-before-action.observation.v1"
TRUST_MANIFEST_SCHEMA: Final = "proof-before-action.trust-manifest.v1"
CAPSULE_SCHEMA: Final = "proof-before-action.capsule.v1"
CAPSULE_INDEX_SCHEMA: Final = "proof-before-action.capsule-index.v1"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EffectIntent(StrEnum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    ATTEMPT = "attempt"
    CONNECT = "connect"


class DeclaredDestinations(StrictModel):
    files: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    network: list[str] = Field(default_factory=list)


class DeclaredEffects(StrictModel):
    filesystem: EffectIntent = EffectIntent.NONE
    database: EffectIntent = EffectIntent.NONE
    network: EffectIntent = EffectIntent.NONE


class ActionDeclaration(StrictModel):
    schema_version: Literal["proof-before-action.declaration.v1"] = DECLARATION_SCHEMA
    name: str = Field(min_length=1)
    tools: list[str] = Field(min_length=1)
    permissions: list[str] = Field(default_factory=list)
    destinations: DeclaredDestinations = Field(default_factory=DeclaredDestinations)
    side_effects: DeclaredEffects = Field(default_factory=DeclaredEffects)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def normalize_unique_fields(self) -> ActionDeclaration:
        for field_name in ("tools", "permissions"):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must not contain duplicates")
        if (
            self.side_effects.filesystem == EffectIntent.WRITE or "file_write" in self.permissions
        ) and not self.destinations.files:
            raise ValueError("file-write authority requires at least one file destination")
        if (
            self.side_effects.database == EffectIntent.WRITE or "database_write" in self.permissions
        ) and not self.destinations.databases:
            raise ValueError("database-write authority requires at least one database destination")
        if (
            self.side_effects.network in {EffectIntent.ATTEMPT, EffectIntent.CONNECT}
            or "network" in self.permissions
        ) and not self.destinations.network:
            raise ValueError("network authority requires at least one network destination")
        return self


class FileChange(StrictModel):
    path: str
    change: Literal["added", "modified", "deleted", "type_changed"]
    before_sha256: str | None = None
    after_sha256: str | None = None


class DatabaseChange(StrictModel):
    path: str
    change: Literal["added", "modified", "deleted", "unreadable"]
    before_sha256: str | None = None
    after_sha256: str | None = None
    changed_tables: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class SurfaceObservation(StrictModel):
    attempted: bool | None
    decision: Literal["allowed", "blocked", "unknown", "not_applicable"]
    outcome: Literal["succeeded", "failed", "unknown", "not_applicable"]
    persisted: Literal["changed", "unchanged", "unknown"]
    mechanism: str
    complete: bool
    limitations: list[str] = Field(default_factory=list)


class CommandRuntimeProfile(StrictModel):
    uids: tuple[Literal[65534], Literal[65534], Literal[65534], Literal[65534]]
    gids: tuple[Literal[65534], Literal[65534], Literal[65534], Literal[65534]]
    supplementary_groups: list[int] = Field(max_length=0)
    capabilities_inheritable: Literal[0]
    capabilities_permitted: Literal[0]
    capabilities_effective: Literal[0]
    capabilities_bounding: Literal[0]
    capabilities_ambient: Literal[0]
    no_new_privileges: Literal[True]


class IsolationEvidence(StrictModel):
    provider: Literal["docker", "docker-in-colima"] = "docker"
    image_reference: str
    image_id: str
    runtime_user: Literal["65534:65534"]
    container_network_mode: str
    log_driver: Literal["none"]
    root_filesystem_read_only: bool
    capabilities_dropped: bool
    no_new_privileges: bool
    pids_limit: Literal[128]
    memory_bytes: Literal[536870912]
    nano_cpus: Literal[1000000000]
    tmpfs_paths: list[str]
    host_mounts: list[str] = Field(default_factory=list)
    secrets_forwarded: list[str] = Field(default_factory=list)
    containment: Literal["partial"]
    limitations: list[str] = Field(default_factory=list)
    observer_user: Literal["0:0"] | None = None
    observer_capabilities: list[Literal["KILL", "SETGID", "SETPCAP", "SETUID"]] = Field(default_factory=list)
    command_runtime_profile: CommandRuntimeProfile | None = None


class CommandEvidence(StrictModel):
    argv: list[str]
    argv_sha256: str
    executable: str
    exit_code: int | None
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_bytes: int
    stderr_bytes: int


class NetworkEvidence(StrictModel):
    surface: SurfaceObservation
    counters: dict[str, int] = Field(default_factory=dict)
    external_contact_count: Literal[0] = 0


class ComparisonFinding(StrictModel):
    code: str
    severity: Literal["error", "unknown", "info"]
    message: str
    evidence: list[str] = Field(default_factory=list)


class BillComparison(StrictModel):
    declared_tools: list[str]
    observed_tools: list[str]
    declared_permissions: list[str]
    observed_capabilities: list[str]
    findings: list[ComparisonFinding] = Field(default_factory=list)
    verdict: Literal["pass", "block", "unknown"]


class DependencyOccurrence(StrictModel):
    dependency_id: str
    source_path: str
    source_pointer: str
    config_name: str
    transport: str
    identity_kind: Literal["npm", "pypi", "remote", "git", "binary", "unknown"]
    identity_name: str | None = None
    requested_version: str | None = None
    version_source: Literal["config_exact", "unresolved", "not_applicable"]
    command_basename: str | None = None
    args_sha256: str
    env_key_names: list[str] = Field(default_factory=list)
    header_key_names: list[str] = Field(default_factory=list)


class DiscoveryDiagnostic(StrictModel):
    source_path: str
    source_pointer: str
    code: str
    message: str


class SubjectSnapshotEvidence(StrictModel):
    repository_commit: str | None
    repository_dirty: bool | None
    staged_tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    dependencies: list[DependencyOccurrence] = Field(default_factory=list)
    diagnostics: list[DiscoveryDiagnostic] = Field(default_factory=list)


class Observation(StrictModel):
    schema_version: Literal["proof-before-action.observation.v1"] = OBSERVATION_SCHEMA
    subject_snapshot: SubjectSnapshotEvidence | None = None
    isolation: IsolationEvidence
    command: CommandEvidence
    filesystem: SurfaceObservation
    file_changes: list[FileChange] = Field(default_factory=list)
    database: SurfaceObservation
    database_changes: list[DatabaseChange] = Field(default_factory=list)
    network: NetworkEvidence
    limitations: list[str] = Field(default_factory=list)


class TrustEvidence(StrictModel):
    state: Literal[
        "current",
        "stale",
        "masked",
        "unmatched",
        "unverifiable",
        "ambiguous",
    ]
    match_state: Literal["exact", "name_only", "ambiguous", "unmatched"]
    slug: str | None = None
    grade: str | None = None
    transparency: str | None = None
    scanned_at: str | None = None
    engine: str | None = None
    engine_version: str | None = None
    scan_mode: str | None = None
    network_isolation: Literal["verified_none", "unknown", "not_applicable"] = "unknown"
    version_alignment: Literal[
        "exact",
        "dependency_unresolved",
        "evidence_unversioned",
        "not_applicable",
        "unknown",
    ] = "unknown"
    unknown_reasons: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_cross_field_consistency(self) -> TrustEvidence:
        scan_details = (
            self.grade,
            self.transparency,
            self.scanned_at,
            self.engine,
            self.engine_version,
            self.scan_mode,
        )
        if self.state == "masked" and any(value is not None for value in scan_details):
            raise ValueError("masked trust evidence must not expose withheld scan details")
        if self.state in {"current", "stale"} and self.match_state != "exact":
            raise ValueError("current or stale trust evidence requires an exact match")
        if self.state == "current" and self.network_isolation != "verified_none":
            raise ValueError("current trust evidence requires verified network isolation")
        if self.state == "current" and self.version_alignment not in {"exact", "not_applicable"}:
            raise ValueError("current trust evidence requires authoritative version alignment")
        if self.state == "masked" and self.match_state != "exact":
            raise ValueError("masked trust evidence requires an exact match")
        if self.state == "unmatched" and self.match_state != "unmatched":
            raise ValueError("unmatched trust evidence requires an unmatched match state")
        if self.state == "ambiguous" and self.match_state != "ambiguous":
            raise ValueError("ambiguous trust evidence requires an ambiguous match state")
        if self.match_state != "exact" and any(value is not None for value in scan_details):
            raise ValueError("non-exact trust evidence must not expose scan details")
        if self.state in {"current", "stale"}:
            if not self.slug or not all(isinstance(value, str) and bool(value) for value in scan_details):
                raise ValueError("current or stale trust evidence requires a complete scan record")
            if self.scanned_at is None:
                raise ValueError("current or stale trust evidence requires a scan timestamp")
            try:
                scanned_at = datetime.fromisoformat(self.scanned_at.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("trust evidence scan timestamp must be valid") from exc
            if scanned_at.tzinfo is None:
                raise ValueError("trust evidence scan timestamp must be timezone-aware")
        if self.state == "current" and self.unknown_reasons:
            raise ValueError("current trust evidence must not retain unknown reasons")
        if self.state in {"masked", "unmatched", "unverifiable", "ambiguous"} and not (self.unknown_reasons):
            raise ValueError("non-authoritative trust evidence requires an unknown reason")
        if self.state == "unverifiable" and any(value is not None for value in scan_details):
            if not self.slug or not all(isinstance(value, str) and bool(value) for value in scan_details):
                raise ValueError(
                    "unverifiable trust evidence must expose either a complete scan record or none"
                )
        return self


class TrustEntry(StrictModel):
    dependency: DependencyOccurrence
    evidence: TrustEvidence


class TrustSource(StrictModel):
    kind: Literal["mcp-trust-local"] = "mcp-trust-local"
    repository_commit: str | None
    dirty: bool | None
    schema_versions: dict[str, int | str]
    file_sha256: dict[str, str]
    snapshot_generated_at: str
    evaluated_at: str

    @model_validator(mode="after")
    def timestamps_are_chronological(self) -> TrustSource:
        generated = _aware_datetime(self.snapshot_generated_at, "trust snapshot generation")
        evaluated = _aware_datetime(self.evaluated_at, "trust evaluation")
        if generated > evaluated:
            raise ValueError("trust snapshot generation must not follow evaluation")
        return self


class ReleaseTrustManifest(StrictModel):
    schema_version: Literal["proof-before-action.trust-manifest.v1"] = TRUST_MANIFEST_SCHEMA
    repository_commit: str | None
    repository_dirty: bool | None
    repository_staged_tree_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    discovery_coverage: Literal["complete", "partial", "unknown"]
    dependencies: list[DependencyOccurrence]
    diagnostics: list[DiscoveryDiagnostic] = Field(default_factory=list)
    trust_source: TrustSource | None = None
    entries: list[TrustEntry]
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def every_dependency_has_one_entry(self) -> ReleaseTrustManifest:
        dependencies_by_id = {item.dependency_id: item for item in self.dependencies}
        entries_by_id = {item.dependency.dependency_id: item for item in self.entries}
        if len(dependencies_by_id) != len(self.dependencies):
            raise ValueError("dependency occurrence IDs must be unique")
        if len(entries_by_id) != len(self.entries):
            raise ValueError("trust entry dependency IDs must be unique")
        if dependencies_by_id.keys() != entries_by_id.keys():
            raise ValueError("every dependency occurrence must have exactly one trust entry")
        if any(
            entry.dependency != dependencies_by_id[dependency_id]
            for dependency_id, entry in entries_by_id.items()
        ):
            raise ValueError("every trust entry must bind the full dependency occurrence")
        chronological_entries = [
            entry for entry in self.entries if entry.evidence.state in {"current", "stale"}
        ]
        if chronological_entries:
            if (
                self.trust_source is None
                or self.trust_source.repository_commit is None
                or self.trust_source.dirty is not False
            ):
                raise ValueError("current or stale trust evidence requires a clean committed source")
            generated = _aware_datetime(
                self.trust_source.snapshot_generated_at,
                "trust snapshot generation",
            )
            evaluated = _aware_datetime(self.trust_source.evaluated_at, "trust evaluation")
            for entry in chronological_entries:
                scanned = _aware_datetime(entry.evidence.scanned_at, "trust scan")
                if scanned > generated or scanned > evaluated:
                    raise ValueError("trust scan must not follow snapshot generation or evaluation")
                stale = (evaluated - scanned).days > 90
                if (entry.evidence.state == "stale") != stale:
                    raise ValueError("trust evidence state does not match recorded freshness")
        if any(entry.evidence.state == "current" for entry in self.entries) and (
            self.discovery_coverage != "complete" or self.diagnostics
        ):
            raise ValueError("current trust evidence requires complete diagnostic-free discovery")
        return self


class ProducerEvidence(StrictModel):
    name: Literal["mcp-audits"] = "mcp-audits"
    version: str
    commit: str | None
    dirty: bool | None
    provenance_source: Literal["build-metadata", "source-checkout"] | None = None
    aigccore_primitive_source_commit: str = "d8c570cf148bb502b7ed0cc7fd58f1e054697180"


class CapsulePayload(StrictModel):
    declaration: ActionDeclaration
    observation: Observation
    comparison: BillComparison
    trust_manifest: ReleaseTrustManifest
    producer: ProducerEvidence
    limitations: list[str] = Field(default_factory=list)


class CapsuleIntegrity(StrictModel):
    algorithm: Literal["sha256"] = "sha256"
    payload_sha256: str


class EvidenceCapsule(StrictModel):
    schema_version: Literal["proof-before-action.capsule.v1"] = CAPSULE_SCHEMA
    payload: CapsulePayload
    integrity: CapsuleIntegrity


class IndexedArtifact(StrictModel):
    path: str
    sha256: str
    bytes: int
    content_type: str
    logical_role: Literal["evidence", "view"]


class CapsuleIndex(StrictModel):
    schema_version: Literal["proof-before-action.capsule-index.v1"] = CAPSULE_INDEX_SCHEMA
    capsule_schema_version: Literal["proof-before-action.capsule.v1"] = CAPSULE_SCHEMA
    subject_commit: str | None
    producer_commit: str | None
    artifacts: list[IndexedArtifact]

    @model_validator(mode="after")
    def artifact_set_is_fixed(self) -> CapsuleIndex:
        by_path = {item.path: item for item in self.artifacts}
        if sorted(by_path) != ["capsule.json", "report.html"] or len(by_path) != len(self.artifacts):
            raise ValueError("capsule index must contain exactly capsule.json and report.html")
        if (
            by_path["capsule.json"].content_type != "application/json"
            or by_path["capsule.json"].logical_role != "evidence"
            or by_path["report.html"].content_type != "text/html"
            or by_path["report.html"].logical_role != "view"
        ):
            raise ValueError("capsule artifact roles and content types are fixed")
        return self


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    """AIGCCore-compatible compact, sorted JSON for this integer-only contract."""
    payload: Any = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    _reject_floats(payload)
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _aware_datetime(value: str | None, label: str) -> datetime:
    if not value:
        raise ValueError(f"{label} timestamp is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} timestamp must be valid") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} timestamp must be timezone-aware")
    return parsed


def _reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise ValueError("canonical Proof Before Action JSON forbids floating-point numbers")
    if isinstance(value, dict):
        for nested in value.values():
            _reject_floats(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_floats(nested)
