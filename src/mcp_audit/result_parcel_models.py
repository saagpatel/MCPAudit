"""Versioned contracts for the offline MCP Result Parcel Lab.

These are MCPAudit-owned scenario and report formats. They are not MCP wire
messages and they deliberately distinguish core protocol behavior from
negotiated extensions and local/provider patterns.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCENARIO_SCHEMA: Final = "mcpaudit.result-parcel.scenario.v1"
REPORT_SCHEMA: Final = "mcpaudit.result-parcel.report.v1"
CURRENT_PROTOCOL_VERSION: Final = "2026-07-28"
TASKS_EXTENSION: Final = "io.modelcontextprotocol/tasks"

MAX_INPUT_BYTES: Final = 2_097_152
MAX_DECLARED_PAYLOAD_BYTES: Final = 1_099_511_627_776
INLINE_ADVISORY_BYTES: Final = 65_536
MAX_CHUNKS: Final = 4_096
MAX_FINDINGS: Final = 128
MAX_JSON_DEPTH: Final = 32
MAX_JSON_KEY_LENGTH: Final = 256
MAX_LOGICAL_MS: Final = 9_007_199_254_740_991


class StrictModel(BaseModel):
    """Closed, strict base model for every parcel contract."""

    model_config = ConfigDict(extra="forbid", strict=True)


class SupportState(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class PayloadClass(StrEnum):
    TEXT = "text"
    JSON = "json"
    BINARY = "binary"
    MIXED = "mixed"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    UNKNOWN = "unknown"


class SemanticsClass(StrEnum):
    MCP_CORE = "mcp_core"
    MCP_EXTENSION = "mcp_extension"
    PROVIDER_EXTENSION = "provider_extension"
    LOCAL_FIXTURE = "local_fixture"


class PayloadProfile(StrictModel):
    payload_class: Literal["text", "json", "binary", "mixed"]
    sensitivity: Literal["public", "internal", "confidential", "secret", "unknown"]
    size_bytes: int = Field(ge=0, le=MAX_DECLARED_PAYLOAD_BYTES)
    content_type: str = Field(min_length=1, max_length=255)
    synthetic: Literal[True]


class RetentionProfile(StrictModel):
    retained: bool
    ttl_ms: int | None = Field(default=None, ge=0, le=MAX_LOGICAL_MS)
    created_at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)
    observed_at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)
    cleanup_owner: Literal["none", "server", "client", "operator", "unknown"]
    delete_supported: Literal["supported", "unsupported", "unknown"]

    @model_validator(mode="after")
    def time_is_monotonic(self) -> RetentionProfile:
        if self.observed_at_ms < self.created_at_ms:
            raise ValueError("observed_at_ms must not precede created_at_ms")
        if not self.retained and self.ttl_ms is not None:
            raise ValueError("non-retained payloads cannot declare a TTL")
        return self


class IntegrityProfile(StrictModel):
    algorithm: Literal["sha256", "none", "unknown"]
    expected_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    declared_content_type: str = Field(min_length=1, max_length=255)
    observed_content_type: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def digest_shape_matches_algorithm(self) -> IntegrityProfile:
        if self.algorithm == "sha256" and self.expected_digest is None:
            raise ValueError("sha256 integrity requires expected_digest")
        if self.algorithm != "sha256" and (
            self.expected_digest is not None or self.observed_digest is not None
        ):
            raise ValueError("digest values require sha256 integrity")
        return self


class RetrievalAuthority(StrictModel):
    required: bool
    enforcement: Literal["enforced", "not_enforced", "unknown"]
    principal_bound: bool | None
    outcome: Literal["allowed", "denied", "unknown"]

    @model_validator(mode="after")
    def authority_is_coherent(self) -> RetrievalAuthority:
        if not self.required and self.outcome == "denied":
            raise ValueError("retrieval cannot be denied when authority is not required")
        if self.enforcement == "enforced" and self.principal_bound is None:
            raise ValueError("enforced retrieval requires a principal binding assertion")
        return self


class RedactionProfile(StrictModel):
    required: bool
    stage: Literal["before_packaging", "after_packaging", "none", "unknown"]
    raw_payload_retained: bool | None

    @model_validator(mode="after")
    def redaction_is_coherent(self) -> RedactionProfile:
        if not self.required and self.stage not in {"none", "unknown"}:
            raise ValueError("redaction stage requires redaction.required=true")
        if self.stage == "before_packaging" and self.raw_payload_retained is None:
            raise ValueError("pre-packaging redaction must state whether raw payload is retained")
        return self


class EvidenceReference(StrictModel):
    evidence_class: Literal["standard", "extension", "design_inference", "local_fixture"]
    title: str = Field(min_length=1, max_length=160)
    url: str | None = Field(default=None, max_length=2_048)
    version: str = Field(min_length=1, max_length=80)
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")


class InlineDelivery(StrictModel):
    mode: Literal["inline"]
    semantics: Literal["mcp_core"]
    host_support: Literal["supported", "unsupported", "unknown"]
    result_complete: bool


class ChunkRecord(StrictModel):
    index: int = Field(ge=0, le=MAX_CHUNKS - 1)
    size_bytes: int = Field(ge=0, le=MAX_DECLARED_PAYLOAD_BYTES)
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ChunkStreamDelivery(StrictModel):
    mode: Literal["chunk_stream_extension"]
    semantics: Literal["provider_extension", "local_fixture"]
    host_support: Literal["supported", "unsupported", "unknown"]
    expected_chunks: int = Field(ge=1, le=MAX_CHUNKS)
    chunks: list[ChunkRecord] = Field(max_length=MAX_CHUNKS)
    interrupted: bool
    idempotency_key_present: bool


class ProgressDelivery(StrictModel):
    mode: Literal["progress_extension"]
    semantics: Literal["provider_extension", "local_fixture"]
    host_support: Literal["supported", "unsupported", "unknown"]
    progress_values: list[float] = Field(max_length=MAX_CHUNKS)
    carries_result_payload: bool
    final_result_present: bool

    @model_validator(mode="after")
    def progress_values_are_finite(self) -> ProgressDelivery:
        if any(value != value or value in {float("inf"), float("-inf")} for value in self.progress_values):
            raise ValueError("progress values must be finite")
        return self


class ReferenceDelivery(StrictModel):
    mode: Literal["resource_link"]
    semantics: Literal["mcp_core"]
    host_support: Literal["supported", "unsupported", "unknown"]
    uri: str = Field(min_length=1, max_length=2_048)
    retrieval_status: Literal["available", "missing", "stale", "expired", "denied", "partial", "unknown"]
    bytes_retrieved: int | None = Field(default=None, ge=0, le=MAX_DECLARED_PAYLOAD_BYTES)


class TaskDelivery(StrictModel):
    mode: Literal["tasks_extension"]
    semantics: Literal["mcp_extension"]
    extension_id: Literal["io.modelcontextprotocol/tasks"]
    host_support: Literal["supported", "unsupported", "unknown"]
    task_status: Literal["completed", "failed", "cancelled", "unknown"]
    final_result_present: bool


DeliveryProfile = Annotated[
    InlineDelivery | ChunkStreamDelivery | ProgressDelivery | ReferenceDelivery | TaskDelivery,
    Field(discriminator="mode"),
]


class ParcelScenario(StrictModel):
    schema_version: Literal["mcpaudit.result-parcel.scenario.v1"]
    scenario_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    title: str = Field(min_length=1, max_length=160)
    protocol_version: str = Field(min_length=1, max_length=32)
    payload: PayloadProfile
    retention: RetentionProfile
    integrity: IntegrityProfile
    retrieval_authority: RetrievalAuthority
    redaction: RedactionProfile
    delivery: DeliveryProfile
    evidence_provenance: list[EvidenceReference] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def cross_field_contract(self) -> ParcelScenario:
        if self.integrity.declared_content_type != self.payload.content_type:
            raise ValueError("integrity declared content type must match the payload content type")
        if isinstance(self.delivery, ReferenceDelivery) and not self.retention.retained:
            raise ValueError("resource-linked parcels require retained payload state")
        if isinstance(self.delivery, (InlineDelivery, ProgressDelivery)) and self.retention.retained:
            raise ValueError("inline and progress-only scenarios cannot claim retained parcel state")
        if isinstance(self.delivery, ReferenceDelivery):
            status = self.delivery.retrieval_status
            if status == "denied" and self.retrieval_authority.outcome != "denied":
                raise ValueError("denied retrieval must agree with retrieval authority")
            if status == "available" and self.delivery.bytes_retrieved != self.payload.size_bytes:
                raise ValueError("available retrieval must return the declared payload size")
            if status == "partial" and (
                self.delivery.bytes_retrieved is None
                or self.delivery.bytes_retrieved >= self.payload.size_bytes
            ):
                raise ValueError("partial retrieval must return fewer bytes than declared")
        evidence_classes = {item.evidence_class for item in self.evidence_provenance}
        required_evidence = {
            SemanticsClass.MCP_CORE: "standard",
            SemanticsClass.MCP_EXTENSION: "extension",
            SemanticsClass.PROVIDER_EXTENSION: "design_inference",
            SemanticsClass.LOCAL_FIXTURE: "local_fixture",
        }
        semantics = SemanticsClass(self.delivery.semantics)
        if required_evidence[semantics] not in evidence_classes:
            raise ValueError("delivery semantics are not backed by matching evidence provenance")
        return self


class ParcelFinding(StrictModel):
    rule_id: str = Field(pattern=r"^MCPPARCEL[0-9]{3}$")
    severity: Literal["error", "warning", "info", "unknown"]
    title: str
    evidence_code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    explanation: str
    input_fields: list[str] = Field(min_length=1, max_length=12)


class DecisionDimension(StrictModel):
    state: Literal["low", "moderate", "high", "unknown"]
    reasons: list[str] = Field(min_length=1, max_length=12)


class ParcelDimensions(StrictModel):
    information_exposure: DecisionDimension
    durability: DecisionDimension
    retry_idempotency_risk: DecisionDimension
    cleanup_burden: DecisionDimension


class ParcelRecommendation(StrictModel):
    suitability: Literal["suitable", "conditional", "unsuitable", "unknown"]
    selected_mode: Literal[
        "inline",
        "chunk_stream_extension",
        "progress_extension",
        "resource_link",
        "tasks_extension",
    ]
    reasons: list[str] = Field(min_length=1, max_length=16)
    conditions: list[str] = Field(max_length=16)


class ParcelCoverage(StrictModel):
    input_state: Literal["valid", "malformed", "unsupported"]
    state: Literal["complete", "unknown"]
    limitations: list[str] = Field(max_length=16)


class ParcelAnalysisReport(StrictModel):
    schema_version: Literal["mcpaudit.result-parcel.report.v1"] = REPORT_SCHEMA
    scenario_schema_version: str | None
    scenario_id: str | None
    scenario_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_version: str | None
    verdict: Literal["pass", "fail", "unknown"]
    recommendation: ParcelRecommendation | None
    dimensions: ParcelDimensions | None
    findings: list[ParcelFinding] = Field(max_length=MAX_FINDINGS)
    unknowns: list[str] = Field(max_length=32)
    coverage: ParcelCoverage
    assumptions: list[str]
    claim: Literal[
        "synthetic_scenario_suitable_under_declared_conditions",
        "synthetic_scenario_has_material_delivery_risk",
        "synthetic_scenario_recommendation_unknown",
    ]


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    """Return stable JSON bytes with one terminal newline."""

    payload: Any = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )
