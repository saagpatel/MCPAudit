"""Versioned contracts for the local-first Proof Before Action product."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, GetJsonSchemaHandler, model_validator
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema

DECLARATION_SCHEMA: Final = "proof-before-action.declaration.v1"
OBSERVATION_SCHEMA_V1: Final = "proof-before-action.observation.v1"
OBSERVATION_SCHEMA: Final = "proof-before-action.observation.v2"
TRUST_MANIFEST_SCHEMA: Final = "proof-before-action.trust-manifest.v1"
CAPSULE_SCHEMA_V1: Final = "proof-before-action.capsule.v1"
CAPSULE_SCHEMA: Final = "proof-before-action.capsule.v2"
CAPSULE_INDEX_SCHEMA_V1: Final = "proof-before-action.capsule-index.v1"
CAPSULE_INDEX_SCHEMA: Final = "proof-before-action.capsule-index.v2"
SUPPORTED_OBSERVATION_SCHEMAS: Final = (OBSERVATION_SCHEMA_V1, OBSERVATION_SCHEMA)
SUPPORTED_CAPSULE_SCHEMAS: Final = (CAPSULE_SCHEMA_V1, CAPSULE_SCHEMA)
SUPPORTED_CAPSULE_INDEX_SCHEMAS: Final = (CAPSULE_INDEX_SCHEMA_V1, CAPSULE_INDEX_SCHEMA)
ATTEMPT_EVIDENCE_RULE_IDS: Final = (
    "PBA-FS-TRANSIENT-001",
    "PBA-DB-NO-DELTA-001",
    "PBA-NET-DESTINATION-001",
    "PBA-UNIX-SOCKET-001",
)
_ATTEMPT_EVIDENCE_RULES: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "PBA-FS-TRANSIENT-001": (
        "filesystem.transient_attempt",
        ("create_delete", "write_restore"),
    ),
    "PBA-DB-NO-DELTA-001": (
        "database.no_delta_attempt",
        ("query_no_delta", "transaction_rollback"),
    ),
    "PBA-NET-DESTINATION-001": (
        "network.requested_destination",
        ("connect_ip", "resolve_hostname"),
    ),
    "PBA-UNIX-SOCKET-001": (
        "network.unix_socket",
        ("abstract_socket", "filesystem_socket"),
    ),
}


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


class AttemptEvidenceProvenance(StrictModel):
    kind: Literal[
        "workspace_final_state",
        "sqlite_final_state",
        "network_namespace_counters",
        "observer_contract",
    ]
    source: str = Field(min_length=1)
    observer_owned: bool


class AttemptEvidence(StrictModel):
    rule_id: Literal[
        "PBA-FS-TRANSIENT-001",
        "PBA-DB-NO-DELTA-001",
        "PBA-NET-DESTINATION-001",
        "PBA-UNIX-SOCKET-001",
    ]
    surface: Literal[
        "filesystem.transient_attempt",
        "database.no_delta_attempt",
        "network.requested_destination",
        "network.unix_socket",
    ]
    operations: list[
        Literal[
            "create_delete",
            "write_restore",
            "query_no_delta",
            "transaction_rollback",
            "connect_ip",
            "resolve_hostname",
            "abstract_socket",
            "filesystem_socket",
        ]
    ] = Field(min_length=1)
    state: Literal["observed", "blocked", "incomplete", "unknown"]
    attribution_confidence: Literal["high", "medium", "low", "none"]
    platform: str = Field(min_length=1)
    backend: str = Field(min_length=1)
    support: Literal["supported", "partial", "unsupported"]
    provenance: list[AttemptEvidenceProvenance] = Field(min_length=1)
    unknown_reasons: list[str] = Field(default_factory=list)

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        schema = handler(core_schema)
        rule_bindings = [
            {
                "if": {
                    "properties": {"rule_id": {"const": rule_id}},
                    "required": ["rule_id"],
                },
                "then": {
                    "properties": {
                        "surface": {"const": surface},
                        "operations": {"const": list(operations)},
                    }
                },
            }
            for rule_id, (surface, operations) in _ATTEMPT_EVIDENCE_RULES.items()
        ]
        schema["allOf"] = [
            *rule_bindings,
            {
                "if": {
                    "properties": {
                        "state": {"enum": ["incomplete", "unknown"]},
                    },
                    "required": ["state"],
                },
                "then": {
                    "properties": {
                        "unknown_reasons": {"minItems": 1},
                    },
                    "required": ["unknown_reasons"],
                },
            },
            {
                "if": {
                    "properties": {"state": {"const": "unknown"}},
                    "required": ["state"],
                },
                "then": {
                    "properties": {
                        "attribution_confidence": {"const": "none"},
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "state": {"enum": ["observed", "blocked"]},
                    },
                    "required": ["state"],
                },
                "then": {
                    "properties": {
                        "attribution_confidence": {"not": {"const": "none"}},
                        "unknown_reasons": {"maxItems": 0},
                        "provenance": {
                            "items": {
                                "properties": {
                                    "observer_owned": {"const": True},
                                },
                                "required": ["observer_owned"],
                            }
                        },
                    }
                },
            },
            {
                "if": {
                    "properties": {"support": {"const": "unsupported"}},
                    "required": ["support"],
                },
                "then": {
                    "properties": {"state": {"const": "unknown"}},
                },
            },
        ]
        return schema

    @model_validator(mode="after")
    def state_and_rule_are_consistent(self) -> AttemptEvidence:
        expected_surface, expected_operations = _ATTEMPT_EVIDENCE_RULES[self.rule_id]
        if self.surface != expected_surface or tuple(self.operations) != expected_operations:
            raise ValueError("attempt evidence rule ID must bind its stable surface and operations")
        if len(self.operations) != len(set(self.operations)):
            raise ValueError("attempt evidence operations must not contain duplicates")
        if self.state in {"incomplete", "unknown"} and not self.unknown_reasons:
            raise ValueError("unresolved attempt evidence requires an unknown reason")
        if self.state == "unknown" and self.attribution_confidence != "none":
            raise ValueError("unknown attempt evidence must use no attribution confidence")
        if self.state in {"observed", "blocked"} and self.attribution_confidence == "none":
            raise ValueError("observed or blocked attempt evidence requires attribution confidence")
        if self.state in {"observed", "blocked"} and self.unknown_reasons:
            raise ValueError("observed or blocked attempt evidence must not retain unknown reasons")
        if self.state in {"observed", "blocked"} and not all(item.observer_owned for item in self.provenance):
            raise ValueError("observed or blocked attempt evidence requires observer-owned provenance")
        if self.support == "unsupported" and self.state != "unknown":
            raise ValueError("unsupported attempt evidence must remain unknown")
        return self


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
    argv: list[str] = Field(min_length=1)
    argv_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable: str = Field(min_length=1)
    exit_code: int | None
    timed_out: bool
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_bytes: int = Field(ge=0)
    stderr_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def executable_and_argv_are_bound(self) -> CommandEvidence:
        if self.executable != Path(self.argv[0]).name:
            raise ValueError("command executable must match argv[0]")
        if self.argv_sha256 != sha256_bytes(canonical_json_bytes(self.argv)):
            raise ValueError("command argv hash does not match recorded argv")
        return self


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
    schema_version: Literal[
        "proof-before-action.observation.v1",
        "proof-before-action.observation.v2",
    ] = OBSERVATION_SCHEMA
    subject_snapshot: SubjectSnapshotEvidence | None = None
    isolation: IsolationEvidence
    command: CommandEvidence
    filesystem: SurfaceObservation
    file_changes: list[FileChange] = Field(default_factory=list)
    database: SurfaceObservation
    database_changes: list[DatabaseChange] = Field(default_factory=list)
    network: NetworkEvidence
    attempt_evidence: list[AttemptEvidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        schema = handler(core_schema)
        attempt_evidence_schema = schema["properties"]["attempt_evidence"]
        attempt_evidence_schema["allOf"] = [
            {
                "contains": {
                    "properties": {"rule_id": {"const": rule_id}},
                    "required": ["rule_id"],
                },
                "minContains": 0,
                "maxContains": 1,
            }
            for rule_id in ATTEMPT_EVIDENCE_RULE_IDS
        ]
        schema["allOf"] = [
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": OBSERVATION_SCHEMA_V1},
                    },
                    "required": ["schema_version"],
                },
                "then": {"not": {"required": ["attempt_evidence"]}},
            }
        ]
        return schema

    @model_validator(mode="after")
    def attempt_evidence_rule_ids_are_unique(self) -> Observation:
        rule_ids = [item.rule_id for item in self.attempt_evidence]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("attempt evidence rule IDs must be unique")
        if self.schema_version == OBSERVATION_SCHEMA_V1 and "attempt_evidence" in self.model_fields_set:
            raise ValueError("observation v1 cannot contain v2 attempt-evidence semantics")
        return self


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
    schema_version: Literal[
        "proof-before-action.capsule.v1",
        "proof-before-action.capsule.v2",
    ] = CAPSULE_SCHEMA
    payload: CapsulePayload
    integrity: CapsuleIntegrity

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        schema = handler(core_schema)
        schema["allOf"] = [
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": CAPSULE_SCHEMA_V1},
                    },
                    "required": ["schema_version"],
                },
                "then": {
                    "properties": {
                        "payload": {
                            "properties": {
                                "observation": {
                                    "properties": {
                                        "schema_version": {
                                            "const": OBSERVATION_SCHEMA_V1,
                                        }
                                    },
                                    "required": ["schema_version"],
                                }
                            }
                        }
                    }
                },
                "else": {
                    "properties": {
                        "payload": {
                            "properties": {
                                "observation": {
                                    "properties": {
                                        "schema_version": {
                                            "const": OBSERVATION_SCHEMA,
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        ]
        return schema

    @model_validator(mode="after")
    def capsule_and_observation_versions_match(self) -> EvidenceCapsule:
        expected_observation = (
            OBSERVATION_SCHEMA_V1 if self.schema_version == CAPSULE_SCHEMA_V1 else OBSERVATION_SCHEMA
        )
        if self.payload.observation.schema_version != expected_observation:
            raise ValueError("capsule and observation schema versions must match")
        return self


class IndexedArtifact(StrictModel):
    path: str
    sha256: str
    bytes: int
    content_type: str
    logical_role: Literal["evidence", "view"]


class CapsuleIndex(StrictModel):
    schema_version: Literal[
        "proof-before-action.capsule-index.v1",
        "proof-before-action.capsule-index.v2",
    ] = CAPSULE_INDEX_SCHEMA
    capsule_schema_version: Literal[
        "proof-before-action.capsule.v1",
        "proof-before-action.capsule.v2",
    ] = CAPSULE_SCHEMA
    subject_commit: str | None
    producer_commit: str | None
    artifacts: list[IndexedArtifact]

    @classmethod
    def __get_pydantic_json_schema__(
        cls,
        core_schema: CoreSchema,
        handler: GetJsonSchemaHandler,
    ) -> JsonSchemaValue:
        schema = handler(core_schema)
        schema["allOf"] = [
            {
                "if": {
                    "properties": {
                        "schema_version": {"const": CAPSULE_INDEX_SCHEMA_V1},
                    },
                    "required": ["schema_version"],
                },
                "then": {
                    "properties": {
                        "capsule_schema_version": {
                            "const": CAPSULE_SCHEMA_V1,
                        }
                    },
                    "required": ["capsule_schema_version"],
                },
                "else": {
                    "properties": {
                        "capsule_schema_version": {
                            "const": CAPSULE_SCHEMA,
                        }
                    }
                },
            }
        ]
        return schema

    @model_validator(mode="after")
    def artifact_set_is_fixed(self) -> CapsuleIndex:
        expected_capsule_schema = (
            CAPSULE_SCHEMA_V1 if self.schema_version == CAPSULE_INDEX_SCHEMA_V1 else CAPSULE_SCHEMA
        )
        if self.capsule_schema_version != expected_capsule_schema:
            raise ValueError("capsule index and capsule schema versions must match")
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
