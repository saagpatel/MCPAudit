"""Strict synthetic contracts for the offline MCP cache auditor.

The trace is a program-owned evidence format, not an MCP wire message or a
general-purpose cache representation. Arbitrary response bodies are retained
only long enough to evaluate the bounded observable rules.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

TRACE_SCHEMA: Final = "mcpaudit.cache-contract.trace.v1"
REPORT_SCHEMA: Final = "mcpaudit.cache-contract.report.v1"
CURRENT_PROTOCOL_VERSION: Final = "2026-07-28"

MAX_INPUT_BYTES: Final = 1_048_576
MAX_EVENTS: Final = 2_048
MAX_RETAINED_ENTRIES: Final = 512
MAX_RESULT_BYTES: Final = 262_144
MAX_KEY_BYTES: Final = 8_192
MAX_JSON_DEPTH: Final = 32
MAX_JSON_KEY_LENGTH: Final = 256
MAX_LOGICAL_MS: Final = 9_007_199_254_740_991
MAX_FINDINGS: Final = 2_048


class StrictModel(BaseModel):
    """Strict, closed model used by every versioned cache contract."""

    model_config = ConfigDict(extra="forbid", strict=True)


class CacheRequest(StrictModel):
    """The complete synthetic request identity used as the cache key."""

    protocol_version: str = Field(min_length=1, max_length=32)
    principal: str = Field(min_length=1, max_length=128)
    cache_partition: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


class BaseTraceEvent(StrictModel):
    event_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    sequence: int = Field(ge=0, le=1_000_000)
    at_ms: int = Field(ge=0, le=MAX_LOGICAL_MS)


class ResponseEvent(BaseTraceEvent):
    type: Literal["response"]
    request: CacheRequest
    result: dict[str, Any]
    page_group: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )


class RefreshEvent(BaseTraceEvent):
    type: Literal["refresh"]
    source_event_id: str = Field(min_length=1, max_length=128)
    request: CacheRequest
    result: dict[str, Any]
    page_group: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )


class RefreshErrorEvent(BaseTraceEvent):
    type: Literal["refresh_error"]
    source_event_id: str = Field(min_length=1, max_length=128)
    request: CacheRequest


class UseEvent(BaseTraceEvent):
    type: Literal["use"]
    source_event_id: str = Field(min_length=1, max_length=128)
    request: CacheRequest


class NotificationEvent(BaseTraceEvent):
    type: Literal["notification"]
    principal: str = Field(min_length=1, max_length=128)
    cache_partition: str = Field(min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=96)
    params: dict[str, Any] = Field(default_factory=dict)
    subscription_validated: bool


CacheTraceEvent = Annotated[
    ResponseEvent | RefreshEvent | RefreshErrorEvent | UseEvent | NotificationEvent,
    Field(discriminator="type"),
]


class CacheTrace(StrictModel):
    """A bounded, explicit-logical-clock synthetic cache trace."""

    schema_version: Literal["mcpaudit.cache-contract.trace.v1"]
    trace_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    protocol_version: str = Field(min_length=1, max_length=32)
    trace_complete: bool
    events: list[CacheTraceEvent] = Field(min_length=1, max_length=MAX_EVENTS)

    @model_validator(mode="after")
    def unique_event_identity(self) -> CacheTrace:
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event_id values must be unique")
        sequences = [event.sequence for event in self.events]
        if len(sequences) != len(set(sequences)):
            raise ValueError("event sequence values must be unique")
        return self


class CacheSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RequirementLevel(StrEnum):
    PROTOCOL_MUST = "protocol_must"
    PROTOCOL_SHOULD = "protocol_should"
    PROTOCOL_CONTRACT = "protocol_contract"
    SIMULATOR_POLICY = "simulator_policy"
    UNKNOWN = "unknown"


class CacheFinding(StrictModel):
    rule_id: Literal[
        "MCPCACHE000",
        "MCPCACHE001",
        "MCPCACHE002",
        "MCPCACHE003",
        "MCPCACHE004",
        "MCPCACHE005",
        "MCPCACHE006",
        "MCPCACHE007",
        "MCPCACHE008",
        "MCPCACHE009",
    ]
    severity: CacheSeverity
    requirement_level: RequirementLevel
    title: str
    target: str
    evidence: str
    remediation: str
    protocol_version: str | None = None
    event_sequences: list[int] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class CacheCoverage(StrictModel):
    state: Literal["complete", "incomplete", "unknown"]
    input_state: Literal["valid", "malformed", "unsupported"]
    total_events: int = Field(ge=0, le=MAX_EVENTS)
    analyzed_events: int = Field(ge=0, le=MAX_EVENTS)
    retained_entries: int = Field(ge=0, le=MAX_RETAINED_ENTRIES)
    limitations: list[str] = Field(default_factory=list)


class CacheAuditReport(StrictModel):
    """Deterministic standalone report; intentionally separate from AuditReport."""

    schema_version: Literal["mcpaudit.cache-contract.report.v1"] = "mcpaudit.cache-contract.report.v1"
    trace_schema_version: str | None
    trace_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    protocol_versions: list[str]
    verdict: Literal["pass", "fail", "unknown"]
    coverage: CacheCoverage
    findings: list[CacheFinding] = Field(max_length=MAX_FINDINGS)
    assumptions: list[str]
    claim: Literal[
        "supplied_trace_satisfies_observable_contract",
        "supplied_trace_violates_observable_contract",
        "supplied_trace_contract_unknown",
    ]


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    """Return compact, sorted UTF-8 JSON with one terminal newline."""

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
