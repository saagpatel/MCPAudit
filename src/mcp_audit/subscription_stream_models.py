"""Strict models for the fixture-first MCP subscription stream auditor.

These contracts describe program-owned synthetic traces. They are not wire
captures, transport clients, live server sessions, or log ingestion schemas.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TRACE_SCHEMA: Final = "mcpaudit.mcp-subscription-trace.v1"
REPORT_SCHEMA: Final = "mcpaudit.mcp-subscription-report.v1"
SUPPORTED_PROTOCOL_REVISION: Final = "2026-07-28"

MAX_INPUT_BYTES: Final = 2_097_152
MAX_STREAMS: Final = 64
MAX_EVENTS: Final = 2_048
MAX_EVENT_BYTES: Final = 16_384
MAX_JSON_DEPTH: Final = 16
MAX_JSON_NODES: Final = 131_072
MAX_ID_CHARS: Final = 128
MAX_RESOURCE_URI_CHARS: Final = 2_048
MAX_RESOURCE_SUBSCRIPTIONS: Final = 64
MAX_DURATION_MS: Final = 86_400_000

RequestId = str | int


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class StreamKind(StrEnum):
    REQUEST = "request"
    SUBSCRIPTION = "subscription"


class Direction(StrEnum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class Lifecycle(StrEnum):
    OPEN = "open"
    MESSAGE = "message"
    CLOSE = "close"
    CANCEL = "cancel"
    DISCONNECT = "disconnect"
    REPLACE = "replace"


class FindingOutcome(StrEnum):
    VIOLATION = "violation"
    UNKNOWN = "unknown"


class FindingSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


def _validate_request_id(value: RequestId | None) -> RequestId | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("request identifiers cannot be booleans")
    if isinstance(value, str):
        if not value or len(value) > MAX_ID_CHARS:
            raise ValueError(f"string identifiers must contain 1-{MAX_ID_CHARS} characters")
        return value
    if not (-(2**63) <= value <= (2**63) - 1):
        raise ValueError("numeric identifiers must fit in a signed 64-bit integer")
    return value


class TraceEvent(StrictModel):
    stream_id: str = Field(min_length=1, max_length=MAX_ID_CHARS)
    stream_kind: StreamKind
    request_id: RequestId
    subscription_id: RequestId | None
    direction: Direction
    lifecycle: Lifecycle
    protocol_version: str = Field(min_length=1, max_length=32)
    offset_ms: int = Field(ge=0, le=MAX_DURATION_MS)
    message: dict[str, Any] | None = None
    declared_resource_subscription: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_RESOURCE_URI_CHARS,
    )
    replaces_stream_id: str | None = Field(default=None, min_length=1, max_length=MAX_ID_CHARS)

    @field_validator("request_id", "subscription_id")
    @classmethod
    def ids_are_bounded(cls, value: RequestId | None) -> RequestId | None:
        return _validate_request_id(value)

    @model_validator(mode="after")
    def event_shape_is_explicit(self) -> TraceEvent:
        if self.stream_kind is StreamKind.SUBSCRIPTION and self.subscription_id is None:
            raise ValueError("subscription stream events require subscription_id")
        if self.stream_kind is StreamKind.REQUEST and self.subscription_id is not None:
            raise ValueError("request stream events must not declare subscription_id")
        if self.lifecycle is Lifecycle.DISCONNECT:
            if self.message is not None:
                raise ValueError("disconnect events must not carry a JSON-RPC message")
        elif self.message is None:
            raise ValueError(f"{self.lifecycle.value} events require a JSON-RPC message")
        if self.lifecycle is Lifecycle.REPLACE:
            if self.stream_kind is not StreamKind.SUBSCRIPTION or self.replaces_stream_id is None:
                raise ValueError("replace events require a subscription stream and replaces_stream_id")
        elif self.replaces_stream_id is not None:
            raise ValueError("replaces_stream_id is only valid on replace events")
        if (
            self.declared_resource_subscription is not None
            and self.stream_kind is not StreamKind.SUBSCRIPTION
        ):
            raise ValueError("declared resource bindings are only valid on subscription streams")
        event_bytes = canonical_json_bytes(self.model_dump(mode="json"))
        if len(event_bytes) > MAX_EVENT_BYTES:
            raise ValueError(f"event exceeds the {MAX_EVENT_BYTES}-byte event limit")
        return self


class SubscriptionTrace(StrictModel):
    schema_version: Literal["mcpaudit.mcp-subscription-trace.v1"] = TRACE_SCHEMA
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    control_kind: Literal["vulnerable", "negative", "near_miss"]
    trace_complete: bool
    observed_duration_ms: int = Field(ge=0, le=MAX_DURATION_MS)
    events: list[TraceEvent] = Field(min_length=1, max_length=MAX_EVENTS)

    @model_validator(mode="after")
    def trace_is_bounded(self) -> SubscriptionTrace:
        stream_kinds: dict[str, StreamKind] = {}
        for event in self.events:
            prior_kind = stream_kinds.setdefault(event.stream_id, event.stream_kind)
            if prior_kind is not event.stream_kind:
                raise ValueError("one stream_id cannot change between request and subscription kinds")
        if len(stream_kinds) > MAX_STREAMS:
            raise ValueError(f"trace exceeds the {MAX_STREAMS}-stream limit")
        if any(event.offset_ms > self.observed_duration_ms for event in self.events):
            raise ValueError("event offset exceeds observed_duration_ms")
        return self


class SubscriptionFinding(StrictModel):
    rule_id: Literal[
        "MCPSUB000",
        "MCPSUB001",
        "MCPSUB002",
        "MCPSUB003",
        "MCPSUB004",
        "MCPSUB005",
        "MCPSUB006",
        "MCPSUB007",
    ]
    outcome: FindingOutcome
    severity: FindingSeverity
    title: str
    target: str
    event_index: int | None = Field(default=None, ge=0)
    evidence: list[str] = Field(min_length=1)
    remediation: str
    assumptions: list[str] = Field(min_length=1)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class TraceStats(StrictModel):
    stream_count: int = Field(ge=0, le=MAX_STREAMS)
    request_stream_count: int = Field(ge=0, le=MAX_STREAMS)
    subscription_stream_count: int = Field(ge=0, le=MAX_STREAMS)
    event_count: int = Field(ge=0, le=MAX_EVENTS)
    evaluated_event_count: int = Field(ge=0, le=MAX_EVENTS)


class CompatibilitySummary(StrictModel):
    status: Literal["current_only", "legacy_only", "mixed", "unsupported", "unknown"]
    current_event_count: int = Field(ge=0, le=MAX_EVENTS)
    legacy_event_count: int = Field(ge=0, le=MAX_EVENTS)
    unsupported_event_count: int = Field(ge=0, le=MAX_EVENTS)


class AnalyzerLimits(StrictModel):
    input_bytes: int = MAX_INPUT_BYTES
    streams: int = MAX_STREAMS
    events: int = MAX_EVENTS
    event_bytes: int = MAX_EVENT_BYTES
    json_depth: int = MAX_JSON_DEPTH
    json_nodes: int = MAX_JSON_NODES
    id_chars: int = MAX_ID_CHARS
    resource_uri_chars: int = MAX_RESOURCE_URI_CHARS
    resource_subscriptions: int = MAX_RESOURCE_SUBSCRIPTIONS
    duration_ms: int = MAX_DURATION_MS


class SubscriptionReport(StrictModel):
    schema_version: Literal["mcpaudit.mcp-subscription-report.v1"] = REPORT_SCHEMA
    fixture_schema_version: str
    fixture_id: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_revision: Literal["2026-07-28"] = SUPPORTED_PROTOCOL_REVISION
    verdict: Literal["pass", "fail", "unknown"]
    coverage: Literal["complete", "unknown"]
    findings: list[SubscriptionFinding] = Field(default_factory=list)
    stats: TraceStats
    compatibility: CompatibilitySummary
    limits: AnalyzerLimits = Field(default_factory=AnalyzerLimits)
    assumptions: list[str] = Field(min_length=1)
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
