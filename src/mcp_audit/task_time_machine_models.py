"""Strict contracts for the offline MCP Task Time Machine.

These are program-owned simulation contracts, not MCP wire messages. The
simulator intentionally keeps arbitrary task results and error data out of its
report so synthetic fixtures cannot become a path for credential reflection.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

SCENARIO_SCHEMA: Final = "mcpaudit.task-time-machine.scenario.v1"
RESULT_SCHEMA: Final = "mcpaudit.task-time-machine.result.v1"
CURRENT_PROTOCOL_VERSION: Final = "2026-07-28"
SPEC_PROFILE: Final = "mcp-tasks-extension-sep-2663"
SPEC_REVISION: Final = "2c1425d9a288b9b1f489430fe1e00bb392b47e48"
SPEC_AS_OF: Final = "2026-08-11"

MAX_INPUT_BYTES: Final = 1_048_576
MAX_EVENTS: Final = 1_024
MAX_FINDINGS: Final = 2_048
MAX_LOGICAL_MS: Final = 9_007_199_254_740_991
MAX_JSON_DEPTH: Final = 32
MAX_JSON_NODES: Final = 20_000


class StrictModel(BaseModel):
    """Strict closed model shared by every P01 contract."""

    model_config = ConfigDict(extra="forbid", strict=True)


class TaskStatus(StrEnum):
    WORKING = "working"
    INPUT_REQUIRED = "input_required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES: Final = {
    TaskStatus.COMPLETED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
}


class RetryPolicy(StrictModel):
    """Explicit local-fixture retry policy; MCP does not define one."""

    max_attempts: int = Field(default=3, ge=1, le=32)
    initial_backoff_ms: int = Field(default=1_000, ge=0, le=86_400_000)
    multiplier: int = Field(default=2, ge=1, le=16)
    max_backoff_ms: int = Field(default=60_000, ge=0, le=86_400_000)

    @model_validator(mode="after")
    def cap_is_not_below_initial(self) -> RetryPolicy:
        if self.max_backoff_ms < self.initial_backoff_ms:
            raise ValueError("max_backoff_ms must be >= initial_backoff_ms")
        return self


class JsonRpcError(StrictModel):
    code: int
    message: str = Field(min_length=1, max_length=1_024)
    data: JsonValue = None


class BaseEvent(StrictModel):
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    sequence: int = Field(ge=0, le=1_000_000)
    at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)


class CreateEvent(BaseEvent):
    type: Literal["create"]


class WorkStartedEvent(BaseEvent):
    type: Literal["work_started"]


class PollEvent(BaseEvent):
    type: Literal["poll"]
    observed_version: int | None = Field(default=None, ge=1, le=1_000_000)


class RetryableErrorEvent(BaseEvent):
    type: Literal["retryable_error"]


class RetryEvent(BaseEvent):
    type: Literal["retry"]


class InputRequiredEvent(BaseEvent):
    type: Literal["input_required"]
    request_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


class InputSubmittedEvent(BaseEvent):
    type: Literal["input_submitted"]
    request_key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")


class ResumeWorkingEvent(BaseEvent):
    type: Literal["resume_working"]


class CancelRequestedEvent(BaseEvent):
    type: Literal["cancel_requested"]


class CancelAppliedEvent(BaseEvent):
    type: Literal["cancel_applied"]


class CompleteEvent(BaseEvent):
    type: Literal["complete"]
    result: dict[str, Any] = Field(default_factory=dict)


class FailEvent(BaseEvent):
    type: Literal["fail"]
    error: JsonRpcError


class ExpireEvent(BaseEvent):
    type: Literal["expire"]


TaskEvent = Annotated[
    CreateEvent
    | WorkStartedEvent
    | PollEvent
    | RetryableErrorEvent
    | RetryEvent
    | InputRequiredEvent
    | InputSubmittedEvent
    | ResumeWorkingEvent
    | CancelRequestedEvent
    | CancelAppliedEvent
    | CompleteEvent
    | FailEvent
    | ExpireEvent,
    Field(discriminator="type"),
]


class TaskScenario(StrictModel):
    """One bounded, explicit-virtual-clock task lifecycle scenario."""

    schema_version: Literal["mcpaudit.task-time-machine.scenario.v1"]
    scenario_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    description: str = Field(min_length=1, max_length=1_024)
    protocol_version: str = Field(min_length=1, max_length=32)
    spec_profile: Literal["mcp-tasks-extension-sep-2663"]
    task_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    initial_clock_ms: int = Field(default=0, ge=0, le=MAX_LOGICAL_MS)
    ttl_ms: int | None = Field(default=None, ge=0, le=MAX_LOGICAL_MS)
    poll_interval_ms: int = Field(default=1_000, ge=1, le=86_400_000)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    expiry_policy: Literal["unknown", "mark_failed", "delete"] = "unknown"
    assumptions: list[str] = Field(default_factory=list, max_length=64)
    events: list[TaskEvent] = Field(min_length=1, max_length=MAX_EVENTS)

    @model_validator(mode="after")
    def deterministic_coordinates(self) -> TaskScenario:
        sequences = [event.sequence for event in self.events]
        if len(sequences) != len(set(sequences)):
            raise ValueError("event sequence values must be unique")
        if any(event.at_ms < self.initial_clock_ms for event in self.events):
            raise ValueError("event at_ms must be >= initial_clock_ms")
        return self


class FindingSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RequirementLevel(StrEnum):
    PROTOCOL_MUST = "protocol_must"
    PROTOCOL_SHOULD = "protocol_should"
    DESIGN_INFERENCE = "design_inference"
    LOCAL_FIXTURE = "local_fixture"
    UNKNOWN = "unknown"


class TransitionAuthority(StrEnum):
    PROTOCOL_REQUIREMENT = "protocol_requirement"
    PROTOCOL_RECOMMENDATION = "protocol_recommendation"
    DESIGN_INFERENCE = "design_inference"
    LOCAL_FIXTURE_POLICY = "local_fixture_policy"
    UNKNOWN = "unknown"


class TaskFinding(StrictModel):
    rule_id: Literal[
        "MCPTASK000",
        "MCPTASK001",
        "MCPTASK002",
        "MCPTASK003",
        "MCPTASK004",
        "MCPTASK005",
        "MCPTASK006",
        "MCPTASK007",
        "MCPTASK008",
    ]
    severity: FindingSeverity
    requirement_level: RequirementLevel
    title: str
    evidence: str
    remediation: str
    event_sequences: list[int] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class TaskTransition(StrictModel):
    event_id: str
    sequence: int
    at_ms: int
    event_type: str
    before_status: str
    after_status: str
    disposition: Literal["applied", "observed", "ignored", "rejected", "ambiguous"]
    authority: TransitionAuthority
    explanation: str
    state_version: int = Field(ge=0)
    attempt: int = Field(ge=0)


class FinalTaskState(StrictModel):
    task_id: str
    status: TaskStatus
    availability: Literal["available", "expired", "deleted"]
    state_version: int = Field(ge=1)
    created_at_ms: int = Field(ge=0)
    last_updated_at_ms: int = Field(ge=0)
    expires_at_ms: int | None = Field(default=None, ge=0)
    attempt: int = Field(ge=0)
    cancel_requested: bool
    result_present: bool
    error_present: bool
    outstanding_input_keys: list[str]


class TaskCoverage(StrictModel):
    state: Literal["complete", "incomplete", "unknown"]
    input_state: Literal["valid", "malformed", "unsupported"]
    total_events: int = Field(ge=0, le=MAX_EVENTS)
    processed_events: int = Field(ge=0, le=MAX_EVENTS)
    final_clock_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)
    limitations: list[str]


class TaskSimulationResult(StrictModel):
    """Deterministic, standalone P01 result contract."""

    schema_version: Literal["mcpaudit.task-time-machine.result.v1"] = RESULT_SCHEMA
    scenario_schema_version: str | None
    scenario_id: str | None
    scenario_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_version: str | None
    spec_profile: Literal["mcp-tasks-extension-sep-2663"] = SPEC_PROFILE
    spec_revision: Literal["2c1425d9a288b9b1f489430fe1e00bb392b47e48"] = SPEC_REVISION
    spec_as_of: Literal["2026-08-11"] = SPEC_AS_OF
    deterministic_order: Literal["at_ms_then_sequence"] = "at_ms_then_sequence"
    seed: None = None
    verdict: Literal["pass", "fail", "unknown"]
    coverage: TaskCoverage
    transitions: list[TaskTransition] = Field(max_length=MAX_EVENTS)
    findings: list[TaskFinding] = Field(max_length=MAX_FINDINGS)
    final_task: FinalTaskState | None
    assumptions: list[str]
    claim: Literal[
        "scenario_satisfies_supported_task_invariants",
        "scenario_violates_supported_task_invariants",
        "scenario_semantics_unknown",
    ]


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    """Return sorted compact UTF-8 JSON with one terminal newline."""

    payload: dict[str, Any] | list[Any]
    if isinstance(value, BaseModel):
        payload = value.model_dump(mode="json")
    else:
        payload = value
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
