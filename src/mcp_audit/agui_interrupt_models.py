"""Strict contracts for the fixture-first AG-UI interrupt integrity auditor."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)

FIXTURE_SCHEMA = "mcpaudit.ag-ui-interrupt.fixture.v1"
REPORT_SCHEMA = "mcpaudit.ag-ui-interrupt.report.v1"
AGUI_CORE_VERSION = "@ag-ui/core@0.0.57"
AGUI_CONTRACT_REVISION = "34c3e0ceda257dd1366c6bdfe01c52777611e4bf"
AGUI_CONTRACT_ID = f"{AGUI_CORE_VERSION}+interrupt-draft@{AGUI_CONTRACT_REVISION}"

_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


def _parse_timestamp(value: Any) -> Any:
    if isinstance(value, str):
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class FixtureManifest(StrictModel):
    schema_version: Literal["mcpaudit.ag-ui-interrupt.fixture.v1"] = "mcpaudit.ag-ui-interrupt.fixture.v1"
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    control_kind: Literal["vulnerable", "negative", "near-miss"]
    protocol: Literal["ag-ui"]
    protocol_version: Literal["@ag-ui/core@0.0.57"]
    contract_revision: Literal["34c3e0ceda257dd1366c6bdfe01c52777611e4bf"]
    complete: bool
    required_boundary_events: list[Literal["STATE_SNAPSHOT", "MESSAGES_SNAPSHOT"]] = Field(
        default_factory=list,
        max_length=2,
    )

    @field_validator("required_boundary_events")
    @classmethod
    def boundary_events_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("required boundary events must be unique")
        return value


class ManifestEnvelope(StrictModel):
    fixture: FixtureManifest


class ResumeEntry(StrictModel):
    interrupt_id: str = Field(alias="interruptId", pattern=_SAFE_ID_PATTERN)
    status: Literal["resolved", "cancelled"]
    payload: Any | None = None

    @property
    def payload_was_supplied(self) -> bool:
        return "payload" in self.model_fields_set

    @model_validator(mode="after")
    def cancelled_has_no_payload(self) -> ResumeEntry:
        if self.status == "cancelled" and self.payload_was_supplied:
            raise ValueError("cancelled resume entries must omit payload")
        return self


class RunInputProjection(StrictModel):
    thread_id: str = Field(alias="threadId", pattern=_SAFE_ID_PATTERN)
    run_id: str = Field(alias="runId", pattern=_SAFE_ID_PATTERN)
    parent_run_id: str | None = Field(default=None, alias="parentRunId", pattern=_SAFE_ID_PATTERN)
    resume: list[ResumeEntry] | None = Field(default=None, max_length=128)


class InterruptProjection(StrictModel):
    id: str = Field(pattern=_SAFE_ID_PATTERN)
    reason: str = Field(min_length=1, max_length=128)
    message: str | None = Field(default=None, max_length=8192)
    tool_call_id: str | None = Field(default=None, alias="toolCallId", pattern=_SAFE_ID_PATTERN)
    response_schema: dict[str, Any] | None = Field(default=None, alias="responseSchema")
    expires_at: datetime | None = Field(default=None, alias="expiresAt")
    metadata: dict[str, Any] | None = None

    @field_validator("expires_at", mode="before")
    @classmethod
    def expiry_is_timezone_aware(cls, value: Any) -> datetime | None:
        value = _parse_timestamp(value)
        if value is not None and not isinstance(value, datetime):
            raise ValueError("expiresAt must be RFC 3339")
        if value is not None and value.tzinfo is None:
            raise ValueError("expiresAt must include a timezone")
        return value


class SuccessOutcome(StrictModel):
    type: Literal["success"]


class InterruptOutcome(StrictModel):
    type: Literal["interrupt"]
    interrupts: list[InterruptProjection] = Field(min_length=1, max_length=128)


RunFinishedOutcome = Annotated[SuccessOutcome | InterruptOutcome, Field(discriminator="type")]


class RunStartedEvent(StrictModel):
    type: Literal["RUN_STARTED"]
    thread_id: str = Field(alias="threadId", pattern=_SAFE_ID_PATTERN)
    run_id: str = Field(alias="runId", pattern=_SAFE_ID_PATTERN)
    parent_run_id: str | None = Field(default=None, alias="parentRunId", pattern=_SAFE_ID_PATTERN)


class RunFinishedEvent(StrictModel):
    type: Literal["RUN_FINISHED"]
    thread_id: str = Field(alias="threadId", pattern=_SAFE_ID_PATTERN)
    run_id: str = Field(alias="runId", pattern=_SAFE_ID_PATTERN)
    outcome: RunFinishedOutcome | None = None
    result: Any | None = None


class RunErrorEvent(StrictModel):
    type: Literal["RUN_ERROR"]
    message: str = Field(min_length=1, max_length=8192)
    code: str | None = Field(default=None, max_length=128)


class StateSnapshotEvent(StrictModel):
    type: Literal["STATE_SNAPSHOT"]
    snapshot: Any


class MessagesSnapshotEvent(StrictModel):
    type: Literal["MESSAGES_SNAPSHOT"]
    messages: list[Any] = Field(max_length=256)


class StateDeltaEvent(StrictModel):
    type: Literal["STATE_DELTA"]
    delta: list[Any] = Field(max_length=256)


class ToolCallStartEvent(StrictModel):
    type: Literal["TOOL_CALL_START"]
    tool_call_id: str = Field(alias="toolCallId", pattern=_SAFE_ID_PATTERN)
    tool_call_name: str = Field(alias="toolCallName", min_length=1, max_length=256)
    parent_message_id: str | None = Field(
        default=None,
        alias="parentMessageId",
        pattern=_SAFE_ID_PATTERN,
    )


class ToolCallArgsEvent(StrictModel):
    type: Literal["TOOL_CALL_ARGS"]
    tool_call_id: str = Field(alias="toolCallId", pattern=_SAFE_ID_PATTERN)
    delta: str = Field(max_length=8192)


class ToolCallEndEvent(StrictModel):
    type: Literal["TOOL_CALL_END"]
    tool_call_id: str = Field(alias="toolCallId", pattern=_SAFE_ID_PATTERN)


class ToolCallResultEvent(StrictModel):
    type: Literal["TOOL_CALL_RESULT"]
    message_id: str = Field(alias="messageId", pattern=_SAFE_ID_PATTERN)
    tool_call_id: str = Field(alias="toolCallId", pattern=_SAFE_ID_PATTERN)
    content: str = Field(max_length=8192)
    role: Literal["tool"] | None = None


AGUIEvent = Annotated[
    RunStartedEvent
    | RunFinishedEvent
    | RunErrorEvent
    | StateSnapshotEvent
    | MessagesSnapshotEvent
    | StateDeltaEvent
    | ToolCallStartEvent
    | ToolCallArgsEvent
    | ToolCallEndEvent
    | ToolCallResultEvent,
    Field(discriminator="type"),
]


class RunInputRecord(StrictModel):
    kind: Literal["run_input"]
    sequence: int = Field(ge=1, le=1_000_000)
    timestamp: datetime
    input: RunInputProjection

    @field_validator("timestamp", mode="before")
    @classmethod
    def timestamp_is_timezone_aware(cls, value: Any) -> datetime:
        value = _parse_timestamp(value)
        if not isinstance(value, datetime):
            raise ValueError("record timestamp must be RFC 3339")
        if value.tzinfo is None:
            raise ValueError("record timestamp must include a timezone")
        return value


class EventRecord(StrictModel):
    kind: Literal["event"]
    sequence: int = Field(ge=1, le=1_000_000)
    timestamp: datetime
    stream_id: str = Field(alias="streamId", pattern=_SAFE_ID_PATTERN)
    event: AGUIEvent

    @field_validator("timestamp", mode="before")
    @classmethod
    def timestamp_is_timezone_aware(cls, value: Any) -> datetime:
        value = _parse_timestamp(value)
        if not isinstance(value, datetime):
            raise ValueError("record timestamp must be RFC 3339")
        if value.tzinfo is None:
            raise ValueError("record timestamp must include a timezone")
        return value


TranscriptRecord = Annotated[RunInputRecord | EventRecord, Field(discriminator="kind")]
TRANSCRIPT_RECORD_ADAPTER: TypeAdapter[TranscriptRecord] = TypeAdapter(TranscriptRecord)


class AGUISeverity(StrEnum):
    HIGH = "high"
    UNKNOWN = "unknown"


class FindingKind(StrEnum):
    MALFORMED_TRANSCRIPT = "malformed_transcript"
    INCOMPLETE_TRANSCRIPT = "incomplete_transcript"
    UNSUPPORTED_CONSTRUCT = "unsupported_construct"
    MISSING_RESUME = "missing_resume"
    WRONG_THREAD = "wrong_thread"
    WRONG_SOURCE_RUN = "wrong_source_run"
    SAME_RUN_REUSE = "same_run_reuse"
    PARTIAL_RESPONSE_SET = "partial_response_set"
    EXTRA_RESPONSE = "extra_response"
    DUPLICATE_RESPONSE = "duplicate_response"
    SCHEMA_MISMATCH = "schema_mismatch"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    MISSING_TOOL_BINDING = "missing_tool_binding"
    MISSING_TOOL_RESULT = "missing_tool_result"
    UNBOUND_TOOL_RESULT = "unbound_tool_result"
    REEMITTED_TOOL_CALL = "reemitted_tool_call"
    TOOL_RESULT_BEFORE_INTERRUPT = "tool_result_before_interrupt"
    INVALID_TOOL_EVENT_ORDER = "invalid_tool_event_order"
    DUPLICATE_TOOL_EVENT = "duplicate_tool_event"
    MISSING_BOUNDARY_SNAPSHOT = "missing_boundary_snapshot"
    DUPLICATE_RESUME_APPLIED = "duplicate_resume_applied"
    EXPIRED_REOPENED = "expired_reopened"
    SUPERSEDED_REOPENED = "superseded_reopened"
    INTERRUPT_SET_SUPERSEDED = "interrupt_set_superseded"
    TERMINAL_REOPENED = "terminal_reopened"
    RESOLVED_REOPENED = "resolved_reopened"
    INTERRUPT_ID_REUSED = "interrupt_id_reused"
    TERMINAL_WITH_OPEN_INTERRUPTS = "terminal_with_open_interrupts"


class AGUIFinding(StrictModel):
    rule_id: Literal[
        "AGUI000",
        "AGUI001",
        "AGUI002",
        "AGUI003",
        "AGUI004",
        "AGUI005",
        "AGUI006",
    ]
    severity: AGUISeverity
    kind: FindingKind
    title: str
    target: str
    sequence: int | None = None
    evidence: list[str] = Field(min_length=1)
    remediation: str


class InterruptStateView(StrictModel):
    thread_id: str
    source_run_id: str
    interrupt_id: str
    status: Literal["open", "resolved", "cancelled", "superseded", "expired"]
    tool_call_id: str | None = None
    opened_sequence: int
    closed_sequence: int | None = None


class ReducerSummary(StrictModel):
    open_count: int = Field(ge=0)
    resolved_count: int = Field(ge=0)
    cancelled_count: int = Field(ge=0)
    superseded_count: int = Field(ge=0)
    expired_count: int = Field(ge=0)
    interrupts: list[InterruptStateView]


class AGUIInterruptReport(StrictModel):
    schema_version: Literal["mcpaudit.ag-ui-interrupt.report.v1"] = "mcpaudit.ag-ui-interrupt.report.v1"
    fixture_id: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol: Literal["ag-ui", "unknown"]
    protocol_version: str
    contract_id: str
    complete: bool
    verdict: Literal["pass", "fail", "unknown"]
    findings: list[AGUIFinding]
    state: ReducerSummary
    assumptions: list[str] = Field(min_length=1)
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode()


def canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
