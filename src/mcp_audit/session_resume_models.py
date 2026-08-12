"""Strict contracts for the deterministic MCP session-resume fault lab.

These are synthetic transport observations, not captured HTTP transcripts.  The
contracts intentionally stop at transport session and resumability behavior;
they do not model task lifecycle or result payload policy.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCENARIO_SCHEMA: Final = "mcpaudit.session-resume.scenario.v1"
TRANSCRIPT_SCHEMA: Final = "mcpaudit.session-resume.transcript.v1"
REPORT_SCHEMA: Final = "mcpaudit.session-resume.report.v1"
SUITE_REPORT_SCHEMA: Final = "mcpaudit.session-resume.suite-report.v1"
SPEC_PROFILE: Final = "mcp-streamable-http-2025-03-26..2026-07-28"

MAX_INPUT_BYTES: Final = 1_048_576
MAX_JSON_DEPTH: Final = 32
MAX_STEPS: Final = 256
MAX_FINDINGS: Final = 256
MAX_RECONNECT_ATTEMPTS: Final = 32
MAX_LOGICAL_MS: Final = 9_007_199_254_740_991


class StrictModel(BaseModel):
    """Closed, non-coercing base for every public contract."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ProtocolProfile(StrEnum):
    V2025_03_26 = "2025-03-26"
    V2025_06_18 = "2025-06-18"
    V2025_11_25 = "2025-11-25"
    V2026_07_28 = "2026-07-28"


class AssumptionSource(StrEnum):
    STANDARD_REQUIREMENT = "standard_requirement"
    DESIGN_INFERENCE = "design_inference"
    FIXTURE_BEHAVIOR = "fixture_behavior"


class ModeledAssumption(StrictModel):
    assumption_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    source: AssumptionSource
    statement: str = Field(min_length=1, max_length=1_024)
    references: list[str] = Field(min_length=1, max_length=8)

    @field_validator("source", mode="before")
    @classmethod
    def parse_source_literal(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return AssumptionSource(value)
            except ValueError:
                return value
        return value

    @field_validator("references")
    @classmethod
    def references_are_primary_https_urls(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("assumption references must be unique")
        if any(not item.startswith("https://") or len(item) > 2_048 for item in value):
            raise ValueError("assumption references must be bounded HTTPS URLs")
        return value


class ServerPolicy(StrictModel):
    session_mode: Literal["required", "optional", "none"]
    replay_mode: Literal["supported", "unsupported", "implementation_defined"]
    duplicate_suppression: Literal["proven", "absent", "unknown"]
    retry_limit: int = Field(default=3, ge=0, le=MAX_RECONNECT_ATTEMPTS)


class BaseStep(StrictModel):
    step_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)


class InitializeStep(BaseStep):
    type: Literal["initialize"]
    session_id: str | None = Field(default=None, min_length=1, max_length=128)


class SendRequestStep(BaseStep):
    type: Literal["send_request"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    session_id: str | None = Field(default=None, min_length=1, max_length=128)


class AcceptRequestStep(BaseStep):
    type: Literal["accept_request"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    server_instance: str = Field(default="server-a", pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


class CompleteRequestStep(BaseStep):
    type: Literal["complete_request"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    result_marker: Literal["<synthetic-result>"] = "<synthetic-result>"


class EmitEventStep(BaseStep):
    type: Literal["emit_event"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    event_kind: Literal["prime", "progress", "result"]


class DeliverEventStep(BaseStep):
    type: Literal["deliver_event"]
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


class DropEventStep(BaseStep):
    type: Literal["drop_event"]
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


class DuplicateEventStep(BaseStep):
    type: Literal["duplicate_event"]
    event_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    copies: int = Field(default=2, ge=2, le=8)


class DisconnectStep(BaseStep):
    type: Literal["disconnect"]
    request_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    phase: Literal["before_acceptance", "after_acceptance_before_response", "after_event"]


class ReconnectStep(BaseStep):
    type: Literal["reconnect"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    attempt: int = Field(ge=1, le=MAX_RECONNECT_ATTEMPTS)
    session_id: str | None = Field(default=None, min_length=1, max_length=128)
    last_event_id: str | None = Field(default=None, min_length=1, max_length=128)


class ReplayStep(BaseStep):
    type: Literal["replay"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    event_ids: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("event_ids")
    @classmethod
    def replay_ids_are_unique_and_bounded(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("replay event_ids must be unique")
        if any(not item or len(item) > 128 for item in value):
            raise ValueError("replay event_ids must be non-empty and bounded")
        return value


class TerminateSessionStep(BaseStep):
    type: Literal["terminate_session"]
    session_id: str = Field(min_length=1, max_length=128)
    reason: Literal["expiry", "client_delete", "server_terminate"]


class RestartServerStep(BaseStep):
    type: Literal["restart_server"]
    new_instance: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    preserves_sessions: bool
    preserves_replay_log: bool


class RotateSessionStep(BaseStep):
    type: Literal["rotate_session"]
    old_session_id: str = Field(min_length=1, max_length=128)
    new_session_id: str = Field(min_length=1, max_length=128)
    migration_declared: bool


class CancelStep(BaseStep):
    type: Literal["cancel"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    mode: Literal["transport_close", "notification"]


class RejectStep(BaseStep):
    type: Literal["reject"]
    request_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    status: Literal[400, 404, 405, 409]
    reason: str = Field(min_length=1, max_length=256)


ScenarioStep = Annotated[
    InitializeStep
    | SendRequestStep
    | AcceptRequestStep
    | CompleteRequestStep
    | EmitEventStep
    | DeliverEventStep
    | DropEventStep
    | DuplicateEventStep
    | DisconnectStep
    | ReconnectStep
    | ReplayStep
    | TerminateSessionStep
    | RestartServerStep
    | RotateSessionStep
    | CancelStep
    | RejectStep,
    Field(discriminator="type"),
]


class SessionResumeScenario(StrictModel):
    schema_version: Literal["mcpaudit.session-resume.scenario.v1"]
    scenario_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    description: str = Field(min_length=1, max_length=1_024)
    protocol_version: ProtocolProfile
    trace_complete: bool
    server_policy: ServerPolicy
    assumptions: list[ModeledAssumption] = Field(min_length=1, max_length=32)
    steps: list[ScenarioStep] = Field(min_length=1, max_length=MAX_STEPS)

    @field_validator("protocol_version", mode="before")
    @classmethod
    def parse_protocol_version_literal(cls, value: object) -> object:
        if isinstance(value, str):
            try:
                return ProtocolProfile(value)
            except ValueError:
                return value
        return value

    @model_validator(mode="after")
    def identities_and_clock_are_deterministic(self) -> SessionResumeScenario:
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("step_id values must be unique")
        times = [step.at_ms for step in self.steps]
        if times != sorted(times):
            raise ValueError("step at_ms values must be nondecreasing")
        assumption_ids = [item.assumption_id for item in self.assumptions]
        if len(assumption_ids) != len(set(assumption_ids)):
            raise ValueError("assumption_id values must be unique")
        return self


TranscriptOutcome: TypeAlias = Literal["applied", "ambiguous", "rejected", "unsupported"]


class TranscriptEntry(StrictModel):
    order: int = Field(ge=1, le=MAX_STEPS)
    at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)
    step_id: str
    actor: Literal["client", "server", "link"]
    action: str
    outcome: TranscriptOutcome
    request_id: str | None = None
    session_id: str | None = None
    event_id: str | None = None
    detail: str = Field(min_length=1, max_length=512)


class SessionResumeTranscript(StrictModel):
    schema_version: Literal["mcpaudit.session-resume.transcript.v1"] = TRANSCRIPT_SCHEMA
    scenario_id: str
    protocol_version: ProtocolProfile
    entries: list[TranscriptEntry] = Field(max_length=MAX_STEPS)


class FindingSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RequirementLevel(StrEnum):
    PROTOCOL_MUST = "protocol_must"
    PROTOCOL_SHOULD = "protocol_should"
    PROTOCOL_MAY = "protocol_may"
    DESIGN_INFERENCE = "design_inference"
    FIXTURE_POLICY = "fixture_policy"
    UNSUPPORTED = "unsupported"


class DeliveryClassification(StrEnum):
    AT_MOST_ONCE = "at_most_once"
    AT_LEAST_ONCE = "at_least_once"
    DUPLICATE_RISK = "duplicate_risk"
    LOST_RESULT_RISK = "lost_result_risk"
    UNKNOWN = "unknown"


class ProofState(StrEnum):
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    UNKNOWN = "unknown"


class RiskState(StrEnum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNKNOWN = "unknown"


FindingRuleId: TypeAlias = Literal[
    "MCPSR000",
    "MCPSR001",
    "MCPSR002",
    "MCPSR003",
    "MCPSR004",
    "MCPSR005",
    "MCPSR006",
    "MCPSR007",
    "MCPSR008",
    "MCPSR009",
]


class SessionResumeFinding(StrictModel):
    rule_id: FindingRuleId
    severity: FindingSeverity
    requirement_level: RequirementLevel
    title: str
    target: str
    evidence: str
    remediation: str
    step_ids: list[str] = Field(default_factory=list, max_length=MAX_STEPS)
    references: list[str] = Field(default_factory=list, max_length=8)


class DeliverySafety(StrictModel):
    at_most_once: ProofState
    at_least_once: ProofState
    duplicate_risk: RiskState
    lost_result_risk: RiskState
    classifications: list[DeliveryClassification]
    rationale: list[str]


ReportVerdict: TypeAlias = Literal["pass", "risk", "unknown"]


class SessionResumeReport(StrictModel):
    schema_version: Literal["mcpaudit.session-resume.report.v1"] = REPORT_SCHEMA
    scenario_schema_version: Literal["mcpaudit.session-resume.scenario.v1"] = SCENARIO_SCHEMA
    transcript_schema_version: Literal["mcpaudit.session-resume.transcript.v1"] = TRANSCRIPT_SCHEMA
    spec_profile: Literal["mcp-streamable-http-2025-03-26..2026-07-28"] = SPEC_PROFILE
    scenario_id: str
    scenario_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_version: ProtocolProfile
    verdict: ReportVerdict
    trace_complete: bool
    safety: DeliverySafety
    findings: list[SessionResumeFinding] = Field(max_length=MAX_FINDINGS)
    transcript: SessionResumeTranscript
    assumptions: list[ModeledAssumption]
    claim_ceiling: Literal["local_model_observations_only_exactly_once_unproven"] = (
        "local_model_observations_only_exactly_once_unproven"
    )


class SessionResumeSuiteReport(StrictModel):
    schema_version: Literal["mcpaudit.session-resume.suite-report.v1"] = SUITE_REPORT_SCHEMA
    reports: list[SessionResumeReport]
    scenario_count: int = Field(ge=0)
    risk_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    claim_ceiling: Literal["local_model_observations_only_exactly_once_unproven"] = (
        "local_model_observations_only_exactly_once_unproven"
    )


def canonical_json_bytes(value: BaseModel | dict[str, object] | list[object]) -> bytes:
    """Return deterministic compact JSON with one terminal newline."""

    payload: object = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
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
