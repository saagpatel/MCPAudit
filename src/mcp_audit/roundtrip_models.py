"""Strict contracts for the offline MCP 2026 stateless round-trip auditor.

These models describe program-owned synthetic traces. They are intentionally
not a capture format for production logs or a claim of live MCP conformance.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

TRACE_SCHEMA: Final = "mcpaudit.mcp-roundtrip.trace.v1"
JSONL_MANIFEST_SCHEMA: Final = "mcpaudit.mcp-roundtrip.trace-jsonl.v1"
WITNESS_SCHEMA: Final = "mcpaudit.mcp-roundtrip.request-state-witness.v1"
REPORT_SCHEMA: Final = "mcpaudit.mcp-roundtrip.report.v1"
SUPPORTED_PROTOCOL_REVISION: Final = "2026-07-28"


class StrictModel(BaseModel):
    """Base model that rejects coercion and undeclared fields."""

    model_config = ConfigDict(extra="forbid", strict=True)


JsonRpcId = str | int


class HttpObservation(StrictModel):
    """Synthetic HTTP metadata observed beside one MCP JSON-RPC message."""

    method: Literal["POST"] = "POST"
    status: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict, max_length=64)

    @field_validator("headers")
    @classmethod
    def headers_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if not name or len(name) > 128 or len(header_value) > 4_096:
                raise ValueError("HTTP header name or value exceeds the supported limit")
            try:
                name.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("HTTP header names must be ASCII") from exc
        return value


class TraceEvent(StrictModel):
    """One ordered, synthetic observation from an HTTP or stdio exchange."""

    sequence: int = Field(ge=0)
    kind: Literal[
        "client_request",
        "server_response",
        "server_request",
        "server_notification",
        "stream_broken",
    ]
    observed_at: datetime
    principal: str | None = Field(default=None, pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    message: dict[str, JsonValue] | None = None
    http: HttpObservation | None = None
    request_id: JsonRpcId | None = None
    retry_of: JsonRpcId | None = None

    @model_validator(mode="after")
    def event_shape_matches_kind(self) -> TraceEvent:
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() is None:
            raise ValueError("observed_at must include a timezone")
        if self.kind == "stream_broken":
            if self.request_id is None or self.message is not None:
                raise ValueError("stream_broken events require request_id and cannot carry a message")
        elif self.message is None:
            raise ValueError("message events require a JSON-RPC message object")
        if self.kind == "client_request" and self.principal is None:
            raise ValueError("client_request events require a synthetic principal alias")
        if self.retry_of is not None and self.kind != "client_request":
            raise ValueError("retry_of is valid only on client_request events")
        if self.message is None:
            return self
        if self.message.get("jsonrpc") != "2.0":
            raise ValueError("message events require jsonrpc 2.0")
        message_id = self.message.get("id")
        valid_id = not isinstance(message_id, bool) and isinstance(message_id, (str, int))
        if self.kind in {"client_request", "server_request"}:
            if not valid_id or not isinstance(self.message.get("method"), str):
                raise ValueError("request events require a string method and string or integer id")
        elif self.kind == "server_response":
            if not valid_id or (("result" in self.message) == ("error" in self.message)):
                raise ValueError("response events require an id and exactly one of result or error")
        elif self.kind == "server_notification":
            if "id" in self.message or not isinstance(self.message.get("method"), str):
                raise ValueError("notification events require a method and cannot carry an id")
        return self


class RequestStateWitness(StrictModel):
    """Explicit program-owned witness for otherwise-unobservable state binding."""

    schema_version: Literal["mcpaudit.mcp-roundtrip.request-state-witness.v1"] = WITNESS_SCHEMA
    trust: Literal["trusted-program-witness"]
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity_verified: bool
    principal_binding_verified: bool
    method_binding_verified: bool
    parameters_binding_verified: bool
    verified_at: datetime
    expires_at: datetime

    @model_validator(mode="after")
    def witness_times_are_ordered(self) -> RequestStateWitness:
        if (
            self.verified_at.tzinfo is None
            or self.verified_at.utcoffset() is None
            or self.expires_at.tzinfo is None
            or self.expires_at.utcoffset() is None
        ):
            raise ValueError("request-state witness timestamps must include timezones")
        if self.verified_at > self.expires_at:
            raise ValueError("request-state witness verification occurs after expiry")
        return self


class TraceManifest(StrictModel):
    """Fields shared by JSON traces and the first record of JSONL traces."""

    schema_version: str
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    protocol_revision: str = Field(min_length=1, max_length=32)
    transport: str = Field(min_length=1, max_length=32)
    witnesses: list[RequestStateWitness] = Field(default_factory=list, max_length=128)


class RoundTripTrace(TraceManifest):
    """Versioned JSON input envelope."""

    events: list[TraceEvent] = Field(min_length=1, max_length=512)

    @field_validator("events")
    @classmethod
    def sequences_are_strictly_increasing(cls, value: list[TraceEvent]) -> list[TraceEvent]:
        sequences = [event.sequence for event in value]
        if any(current >= following for current, following in zip(sequences, sequences[1:], strict=False)):
            raise ValueError("event sequences must be strictly increasing in file order")
        return value


class RoundTripJsonlManifest(TraceManifest):
    """Versioned first record for JSONL input."""

    schema_version: str = JSONL_MANIFEST_SCHEMA


RuleStatus = Literal["PASS", "FAIL", "UNKNOWN", "UNSUPPORTED", "NOT_APPLICABLE"]
FindingSeverity = Literal["error", "warning", "note"]


class RoundTripRuleResult(StrictModel):
    """Stable result for one independently evaluated rule surface."""

    rule_id: str = Field(pattern=r"^MCPRT[0-9]{3}$")
    status: RuleStatus
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    event_sequences: list[int] = Field(default_factory=list)


class RoundTripFinding(StrictModel):
    """Machine-readable failure or uncertainty finding."""

    rule_id: str = Field(pattern=r"^MCPRT[0-9]{3}$")
    severity: FindingSeverity
    status: Literal["FAIL", "UNKNOWN", "UNSUPPORTED"]
    title: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    event_sequences: list[int] = Field(default_factory=list)


class RoundTripLimits(StrictModel):
    """Input limits recorded in every report."""

    maximum_bytes: int
    maximum_depth: int
    maximum_events: int
    maximum_nodes: int
    maximum_string_bytes: int


class RoundTripReport(StrictModel):
    """Deterministic report for one accepted synthetic trace."""

    schema_version: Literal["mcpaudit.mcp-roundtrip.report.v1"] = REPORT_SCHEMA
    fixture_id: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trace_schema: str
    protocol_revision: str
    transport: str
    verdict: Literal["pass", "fail", "unknown", "unsupported"]
    rules: list[RoundTripRuleResult]
    findings: list[RoundTripFinding]
    assumptions: list[str]
    supported_claims: list[str]
    unsupported_claims: list[str]
    limits: RoundTripLimits
