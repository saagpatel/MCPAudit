"""Deterministic reducer for synthetic MCP 2026 subscription stream traces."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import date
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as package_version
from pathlib import Path
from typing import Any, Never

from pydantic import ValidationError

from mcp_audit.subscription_stream_models import (
    MAX_EVENT_BYTES,
    MAX_EVENTS,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_RESOURCE_SUBSCRIPTIONS,
    MAX_RESOURCE_URI_CHARS,
    REPORT_SCHEMA,
    SUPPORTED_PROTOCOL_REVISION,
    TRACE_SCHEMA,
    AnalyzerLimits,
    CompatibilitySummary,
    Direction,
    FindingOutcome,
    FindingSeverity,
    Lifecycle,
    RequestId,
    StreamKind,
    SubscriptionFinding,
    SubscriptionReport,
    SubscriptionTrace,
    TraceEvent,
    TraceStats,
    canonical_json_bytes,
    sha256_bytes,
)

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
_PROTOCOL_VERSION_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_ASSUMPTIONS = [
    "Event list order is the observed delivery order; offset_ms is bounded descriptive evidence.",
    "Stream and message identifiers are fixture assertions, not authenticated identities.",
    "A non-exact resource URI is bound only by declared_resource_subscription in the same event.",
    "Legacy protocol events are classified but not evaluated as MCP 2026-07-28 success.",
]
_SUPPORTED_INPUTS = [
    "Program-owned mcpaudit.mcp-subscription-trace.v1 JSON fixtures.",
    "MCP protocol revision 2026-07-28 request and subscription stream observations.",
    "Bounded JSON-RPC request, notification, close, cancellation, disconnect, and replacement events.",
]
_UNSUPPORTED_INPUTS = [
    "Network streams, SSE connections, stdio processes, MCP hosts or servers, and live subscriptions.",
    "Real logs, private transcripts, arbitrary referenced files, credentials, and authentication stores.",
    (
        "Delivery reliability, server-side state, authorization effectiveness, "
        "encryption, and production isolation."
    ),
    "General per-request metadata, MRTR correctness, and transport-header round-trip analysis.",
]
_CLAIM_CEILING = [
    (
        "The supplied synthetic streams satisfy or violate the implemented "
        "observable routing and lifecycle invariants."
    ),
    (
        "A pass does not prove delivery reliability, authorization, absence of "
        "server-side leakage, or production safety."
    ),
    (
        "Unknown, legacy, malformed, ambiguous, or incomplete evidence is never "
        "promoted to current-protocol success."
    ),
]


@dataclass(frozen=True)
class _Rule:
    severity: FindingSeverity
    title: str
    remediation: str
    description: str


_RULES: dict[str, _Rule] = {
    "MCPSUB000": _Rule(
        FindingSeverity.UNKNOWN,
        "Subscription stream coverage is unknown",
        "Provide a complete, unambiguous, schema-valid synthetic trace within all documented limits.",
        "The trace is incomplete, malformed, ambiguous, unsupported, or otherwise cannot support a verdict.",
    ),
    "MCPSUB001": _Rule(
        FindingSeverity.HIGH,
        "Subscription delivered an unrequested notification type",
        "Deliver only notification types present in both the listen request and its acknowledgment.",
        (
            "A subscription stream carried a notification type the listener did "
            "not request or the server did not acknowledge."
        ),
    ),
    "MCPSUB002": _Rule(
        FindingSeverity.HIGH,
        "Subscription identifier was missing or changed",
        "Preserve the listen request ID in every subscription notification and graceful close response.",
        "A subscription message omitted or changed io.modelcontextprotocol/subscriptionId.",
    ),
    "MCPSUB003": _Rule(
        FindingSeverity.HIGH,
        "Request and subscription streams were confused",
        (
            "Keep progress and log messages on their request response stream and "
            "change notifications on the listener stream."
        ),
        (
            "A request-scoped notification leaked to a subscription stream or a "
            "subscription notification appeared on a request stream."
        ),
    ),
    "MCPSUB004": _Rule(
        FindingSeverity.HIGH,
        "Resource update was bound to the wrong listener",
        "Route the update only to a listener that acknowledged the declared resource subscription.",
        "A resource update was associated with a resource subscription not acknowledged by that listener.",
    ),
    "MCPSUB005": _Rule(
        FindingSeverity.HIGH,
        "Subscription received a message after termination",
        (
            "Stop delivery after close, cancellation, disconnect, or replacement "
            "and use a fresh listener identity on reconnect."
        ),
        "A terminated or replaced subscription stream received a later server message.",
    ),
    "MCPSUB006": _Rule(
        FindingSeverity.HIGH,
        "Subscription acknowledgment is missing or out of order",
        (
            "Acknowledge the listener first, preserve its ID, and acknowledge only "
            "the requested supported filters."
        ),
        "The acknowledgment was absent, duplicated, late, or expanded beyond the listen request.",
    ),
    "MCPSUB007": _Rule(
        FindingSeverity.UNKNOWN,
        "Compatibility-era evidence is not current-protocol proof",
        (
            "Evaluate legacy behavior with its matching protocol contract or "
            "provide a complete 2026-07-28 trace."
        ),
        "One or more events use an older MCP protocol era and are excluded from current-protocol success.",
    ),
}

_SEVERITY_ORDER = {
    FindingSeverity.HIGH: 0,
    FindingSeverity.MEDIUM: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.UNKNOWN: 3,
}
_SUBSCRIPTION_METHODS = {
    "notifications/tools/list_changed",
    "notifications/prompts/list_changed",
    "notifications/resources/list_changed",
    "notifications/resources/updated",
}
_REQUEST_SCOPED_METHODS = {"notifications/progress", "notifications/message"}
_ACK_METHOD = "notifications/subscriptions/acknowledged"
_SUBSCRIPTION_ID_KEY = "io.modelcontextprotocol/subscriptionId"
_SAFE_VALIDATION_LOCATIONS = {
    "schema_version",
    "program_owned",
    "fixture_id",
    "control_kind",
    "trace_complete",
    "observed_duration_ms",
    "events",
    "stream_id",
    "stream_kind",
    "request_id",
    "subscription_id",
    "direction",
    "lifecycle",
    "protocol_version",
    "offset_ms",
    "message",
    "declared_resource_subscription",
    "replaces_stream_id",
}


class SubscriptionStreamInputError(ValueError):
    """The fixture could not be read within the local safety boundary."""


@dataclass(frozen=True)
class _SubscriptionFilter:
    tools_list_changed: bool = False
    prompts_list_changed: bool = False
    resources_list_changed: bool = False
    resource_subscriptions: tuple[str, ...] = ()

    def allows(self, method: str) -> bool:
        if method == "notifications/tools/list_changed":
            return self.tools_list_changed
        if method == "notifications/prompts/list_changed":
            return self.prompts_list_changed
        if method == "notifications/resources/list_changed":
            return self.resources_list_changed
        if method == "notifications/resources/updated":
            return bool(self.resource_subscriptions)
        return False


@dataclass(frozen=True)
class _SubscriptionState:
    stream_id: str
    request_id: RequestId
    subscription_id: RequestId
    requested: _SubscriptionFilter | None
    acknowledged: _SubscriptionFilter | None
    active: bool
    start_event_index: int
    terminal_reason: str | None = None
    server_notification_seen: bool = False


@dataclass(frozen=True)
class _ReducerState:
    subscriptions: tuple[_SubscriptionState, ...] = ()
    findings: tuple[SubscriptionFinding, ...] = ()
    evaluated_event_count: int = 0

    def subscription(self, stream_id: str) -> _SubscriptionState | None:
        return next((item for item in self.subscriptions if item.stream_id == stream_id), None)

    def with_subscription(self, subscription: _SubscriptionState) -> _ReducerState:
        existing = tuple(item for item in self.subscriptions if item.stream_id != subscription.stream_id)
        return replace(self, subscriptions=existing + (subscription,))

    def with_finding(self, finding: SubscriptionFinding) -> _ReducerState:
        return replace(self, findings=self.findings + (finding,))


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _load_json_value(value: bytes) -> Any:
    return json.loads(
        value,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_json_constant,
    )


def _load_trace_payload(raw: bytes) -> tuple[Any, bytes]:
    try:
        payload = _load_json_value(raw)
        return payload, raw
    except json.JSONDecodeError as json_error:
        lines = raw.splitlines()
        if len(lines) < 2 or any(not line.strip() for line in lines):
            raise json_error from None
        if len(lines) > MAX_EVENTS + 1:
            raise ValueError(f"JSONL trace exceeds {MAX_EVENTS} event lines") from json_error
        if any(len(line) > MAX_EVENT_BYTES for line in lines):
            raise ValueError(f"JSONL line exceeds {MAX_EVENT_BYTES} bytes") from json_error
        values = [_load_json_value(line) for line in lines]
        header = values[0]
        if not isinstance(header, dict) or "events" in header:
            raise ValueError("JSONL header must be an object without an events field") from json_error
        if not all(isinstance(event, dict) for event in values[1:]):
            raise ValueError("every JSONL event line must be an object") from json_error
        payload = {**header, "events": values[1:]}
        return payload, canonical_json_bytes(payload)


def _validate_json_nesting(value: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in value:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def _validate_json_node_budget(value: Any) -> None:
    nodes = 0
    stack = [value]
    while stack:
        item = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError(f"JSON node count exceeds {MAX_JSON_NODES}")
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _validation_evidence(exc: ValidationError) -> str:
    error = exc.errors(include_input=False, include_url=False)[0]
    location = (
        "/".join(
            (
                str(item)
                if isinstance(item, int)
                else item
                if item in _SAFE_VALIDATION_LOCATIONS
                else "<field>"
            )
            for item in error.get("loc", ())
        )
        or "<root>"
    )
    return f"schema validation failed at {location}: {error.get('type', 'invalid')}"


def _json_error_evidence(exc: BaseException) -> str:
    message = str(exc)
    if message.startswith("JSON nesting exceeds"):
        return f"JSON nesting exceeds {MAX_JSON_DEPTH} levels"
    if message.startswith("JSON node count exceeds"):
        return f"JSON node count exceeds {MAX_JSON_NODES}"
    if message.startswith("duplicate JSON key"):
        return "input JSON contains a duplicate object key"
    if message.startswith("unsupported JSON constant"):
        return "input JSON contains a non-standard numeric constant"
    if message.startswith("JSONL"):
        return message
    if message.startswith("every JSONL"):
        return message
    return f"input JSON is malformed or unsupported: {type(exc).__name__}"


def _safe_fixture_identity(payload: Any) -> tuple[str, str]:
    if not isinstance(payload, dict):
        return "unknown", "unknown-input"
    schema = payload.get("schema_version")
    fixture_id = payload.get("fixture_id")
    safe_schema = TRACE_SCHEMA if schema == TRACE_SCHEMA else "unknown"
    if (
        isinstance(fixture_id, str)
        and 3 <= len(fixture_id) <= 128
        and re.fullmatch(r"[a-z0-9][a-z0-9._-]+", fixture_id)
    ):
        return safe_schema, fixture_id
    return safe_schema, "unknown-input"


def _opaque_ref(label: str, value: object) -> str:
    digest = sha256_bytes(repr(value).encode("utf-8"))[:12]
    return f"{label}:sha256:{digest}"


def _event_target(event: TraceEvent, event_index: int) -> str:
    return f"event:{event_index}:{_opaque_ref('stream', event.stream_id)}"


def _finding(
    rule_id: str,
    *,
    outcome: FindingOutcome,
    target: str,
    evidence: Iterable[str],
    event_index: int | None,
) -> SubscriptionFinding:
    rule = _RULES[rule_id]
    evidence_items = sorted(set(evidence))
    fingerprint_material = canonical_json_bytes(
        {
            "rule_id": rule_id,
            "outcome": outcome.value,
            "target": target,
            "event_index": event_index,
            "evidence": evidence_items,
        }
    )
    return SubscriptionFinding(
        rule_id=rule_id,  # type: ignore[arg-type]
        outcome=outcome,
        severity=rule.severity if outcome is FindingOutcome.VIOLATION else FindingSeverity.UNKNOWN,
        title=rule.title,
        target=target,
        event_index=event_index,
        evidence=evidence_items,
        remediation=rule.remediation,
        assumptions=_ASSUMPTIONS,
        fingerprint=sha256_bytes(fingerprint_material),
    )


def _add_finding(
    state: _ReducerState,
    rule_id: str,
    *,
    outcome: FindingOutcome,
    target: str,
    evidence: Iterable[str],
    event_index: int | None,
) -> _ReducerState:
    return state.with_finding(
        _finding(
            rule_id,
            outcome=outcome,
            target=target,
            evidence=evidence,
            event_index=event_index,
        )
    )


def _sort_findings(findings: Iterable[SubscriptionFinding]) -> list[SubscriptionFinding]:
    grouped: dict[tuple[str, FindingOutcome, str, int | None], set[str]] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.outcome,
            finding.target,
            finding.event_index,
        )
        grouped.setdefault(key, set()).update(finding.evidence)
    unique = [
        _finding(
            rule_id,
            outcome=outcome,
            target=target,
            evidence=evidence,
            event_index=event_index,
        )
        for (rule_id, outcome, target, event_index), evidence in grouped.items()
    ]
    return sorted(
        unique,
        key=lambda item: (
            _SEVERITY_ORDER[item.severity],
            item.rule_id,
            item.event_index if item.event_index is not None else -1,
            item.target,
            item.fingerprint,
        ),
    )


def _verdict(findings: Iterable[SubscriptionFinding]) -> str:
    items = list(findings)
    if any(item.outcome is FindingOutcome.VIOLATION for item in items):
        return "fail"
    if items:
        return "unknown"
    return "pass"


def _coverage(findings: Iterable[SubscriptionFinding]) -> str:
    return "unknown" if any(item.outcome is FindingOutcome.UNKNOWN for item in findings) else "complete"


def _read_fixture_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SubscriptionStreamInputError("fixture is inaccessible or is a symlink") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SubscriptionStreamInputError("fixture is not a regular file")
        if opened.st_size > MAX_INPUT_BYTES:
            raise SubscriptionStreamInputError(f"fixture exceeds the {MAX_INPUT_BYTES}-byte input limit")
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_INPUT_BYTES:
            raise SubscriptionStreamInputError(f"fixture exceeds the {MAX_INPUT_BYTES}-byte input limit")
        closed = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            closed.st_dev,
            closed.st_ino,
            closed.st_size,
        ):
            raise SubscriptionStreamInputError("fixture changed while it was being read")
        return raw
    finally:
        os.close(descriptor)


def _empty_stats() -> TraceStats:
    return TraceStats(
        stream_count=0,
        request_stream_count=0,
        subscription_stream_count=0,
        event_count=0,
        evaluated_event_count=0,
    )


def _unknown_report(
    raw: bytes,
    *,
    evidence: str,
    payload: Any = None,
) -> SubscriptionReport:
    schema, fixture_id = _safe_fixture_identity(payload)
    finding = _finding(
        "MCPSUB000",
        outcome=FindingOutcome.UNKNOWN,
        target="trace",
        evidence=[evidence],
        event_index=None,
    )
    return SubscriptionReport(
        schema_version=REPORT_SCHEMA,
        fixture_schema_version=schema,
        fixture_id=fixture_id,
        input_sha256=sha256_bytes(raw),
        verdict="unknown",
        coverage="unknown",
        findings=[finding],
        stats=_empty_stats(),
        compatibility=CompatibilitySummary(
            status="unknown",
            current_event_count=0,
            legacy_event_count=0,
            unsupported_event_count=0,
        ),
        limits=AnalyzerLimits(),
        assumptions=_ASSUMPTIONS,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def scan_subscription_stream_path(path: Path) -> SubscriptionReport:
    """Read and scan one bounded synthetic trace without opening any stream."""
    raw = _read_fixture_bytes(path)
    return scan_subscription_stream_bytes(raw)


def scan_subscription_stream_bytes(raw: bytes) -> SubscriptionReport:
    """Scan already-loaded fixture bytes and return a canonical report model."""
    if len(raw) > MAX_INPUT_BYTES:
        raise SubscriptionStreamInputError(f"fixture exceeds the {MAX_INPUT_BYTES}-byte input limit")
    payload: Any = None
    try:
        _validate_json_nesting(raw)
        payload, validation_bytes = _load_trace_payload(raw)
        _validate_json_node_budget(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        return _unknown_report(
            raw,
            evidence=_json_error_evidence(exc),
            payload=payload,
        )
    try:
        trace = SubscriptionTrace.model_validate_json(validation_bytes, strict=True)
    except ValidationError as exc:
        return _unknown_report(raw, evidence=_validation_evidence(exc), payload=payload)
    return _scan_trace(trace, sha256_bytes(raw))


def _protocol_relation(version: str) -> str:
    if version == SUPPORTED_PROTOCOL_REVISION:
        return "current"
    if _PROTOCOL_VERSION_RE.fullmatch(version):
        try:
            date.fromisoformat(version)
        except ValueError:
            return "unsupported"
        return "legacy" if version < SUPPORTED_PROTOCOL_REVISION else "unsupported"
    return "unsupported"


def _compatibility(events: Iterable[TraceEvent]) -> CompatibilitySummary:
    current = 0
    legacy = 0
    unsupported = 0
    for event in events:
        relation = _protocol_relation(event.protocol_version)
        current += relation == "current"
        legacy += relation == "legacy"
        unsupported += relation == "unsupported"
    if unsupported:
        status = "unsupported"
    elif current and legacy:
        status = "mixed"
    elif legacy:
        status = "legacy_only"
    else:
        status = "current_only"
    return CompatibilitySummary(
        status=status,  # type: ignore[arg-type]
        current_event_count=current,
        legacy_event_count=legacy,
        unsupported_event_count=unsupported,
    )


def _stats(trace: SubscriptionTrace, evaluated_event_count: int) -> TraceStats:
    request_streams = {event.stream_id for event in trace.events if event.stream_kind is StreamKind.REQUEST}
    subscription_streams = {
        event.stream_id for event in trace.events if event.stream_kind is StreamKind.SUBSCRIPTION
    }
    return TraceStats(
        stream_count=len(request_streams | subscription_streams),
        request_stream_count=len(request_streams),
        subscription_stream_count=len(subscription_streams),
        event_count=len(trace.events),
        evaluated_event_count=evaluated_event_count,
    )


def _scan_trace(trace: SubscriptionTrace, digest: str) -> SubscriptionReport:
    compatibility = _compatibility(trace.events)
    state = _ReducerState()
    for event_index, event in enumerate(trace.events):
        relation = _protocol_relation(event.protocol_version)
        if relation != "current":
            continue
        state = replace(state, evaluated_event_count=state.evaluated_event_count + 1)
        state = _reduce_event(state, event, event_index)

    if compatibility.legacy_event_count:
        state = _add_finding(
            state,
            "MCPSUB007",
            outcome=FindingOutcome.UNKNOWN,
            target="trace",
            evidence=[
                (
                    f"{compatibility.legacy_event_count} compatibility-era event(s) "
                    "excluded from current evaluation"
                )
            ],
            event_index=None,
        )
    if compatibility.unsupported_event_count:
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target="trace",
            evidence=[
                f"{compatibility.unsupported_event_count} event(s) use an unsupported protocol version"
            ],
            event_index=None,
        )
    if not trace.trace_complete:
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target="trace",
            evidence=["trace_complete is false; absence of later events is not observable"],
            event_index=None,
        )
    for subscription in state.subscriptions:
        if subscription.acknowledged is None:
            state = _add_finding(
                state,
                "MCPSUB006",
                outcome=FindingOutcome.UNKNOWN,
                target=_opaque_ref("stream", subscription.stream_id),
                evidence=["no valid acknowledgment was observed for this listener"],
                event_index=subscription.start_event_index,
            )
    if (
        compatibility.current_event_count
        and not state.subscriptions
        and any(event.stream_kind is StreamKind.SUBSCRIPTION for event in trace.events)
    ):
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target="trace",
            evidence=["no valid current-protocol subscription opening was established"],
            event_index=None,
        )
    if not any(event.stream_kind is StreamKind.SUBSCRIPTION for event in trace.events):
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target="trace",
            evidence=["trace contains no subscription stream evidence"],
            event_index=None,
        )

    findings = _sort_findings(state.findings)
    return SubscriptionReport(
        schema_version=REPORT_SCHEMA,
        fixture_schema_version=TRACE_SCHEMA,
        fixture_id=trace.fixture_id,
        input_sha256=digest,
        verdict=_verdict(findings),  # type: ignore[arg-type]
        coverage=_coverage(findings),  # type: ignore[arg-type]
        findings=findings,
        stats=_stats(trace, state.evaluated_event_count),
        compatibility=compatibility,
        limits=AnalyzerLimits(),
        assumptions=_ASSUMPTIONS,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def _reduce_event(
    state: _ReducerState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    if event.stream_kind is StreamKind.REQUEST:
        return _reduce_request_event(state, event, event_index)
    if event.lifecycle in {Lifecycle.OPEN, Lifecycle.REPLACE}:
        return _open_subscription(state, event, event_index)
    subscription = state.subscription(event.stream_id)
    if subscription is None:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=_event_target(event, event_index),
            evidence=["subscription event has no preceding opening for its stream"],
            event_index=event_index,
        )
    if event.lifecycle is Lifecycle.MESSAGE:
        return _subscription_message(state, subscription, event, event_index)
    if event.lifecycle is Lifecycle.CLOSE:
        return _close_subscription(state, subscription, event, event_index)
    if event.lifecycle is Lifecycle.CANCEL:
        return _cancel_subscription(state, subscription, event, event_index)
    if event.lifecycle is Lifecycle.DISCONNECT:
        if not subscription.active:
            return _terminal_delivery_finding(state, subscription, event, event_index)
        return state.with_subscription(replace(subscription, active=False, terminal_reason="disconnect"))
    return _add_finding(
        state,
        "MCPSUB000",
        outcome=FindingOutcome.UNKNOWN,
        target=_event_target(event, event_index),
        evidence=["unsupported subscription lifecycle transition"],
        event_index=event_index,
    )


def _reduce_request_event(
    state: _ReducerState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    message = event.message
    if not isinstance(message, dict):
        return state
    method = message.get("method")
    if (
        event.direction is Direction.SERVER_TO_CLIENT
        and isinstance(method, str)
        and (method in _SUBSCRIPTION_METHODS or method == _ACK_METHOD)
    ):
        return _add_finding(
            state,
            "MCPSUB003",
            outcome=FindingOutcome.VIOLATION,
            target=_event_target(event, event_index),
            evidence=[f"{method} appeared on a request response stream"],
            event_index=event_index,
        )
    if (
        event.direction is Direction.SERVER_TO_CLIENT
        and method in _REQUEST_SCOPED_METHODS
        and _notification_subscription_id(message)[0]
    ):
        return _add_finding(
            state,
            "MCPSUB003",
            outcome=FindingOutcome.VIOLATION,
            target=_event_target(event, event_index),
            evidence=[f"{method} on a request stream carried subscription metadata"],
            event_index=event_index,
        )
    return state


def _open_subscription(
    state: _ReducerState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    target = _event_target(event, event_index)
    if state.subscription(event.stream_id) is not None:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["stream_id was reopened without a new stream identity"],
            event_index=event_index,
        )
    if event.direction is not Direction.CLIENT_TO_SERVER or not isinstance(event.message, dict):
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription opening is not a client-to-server JSON-RPC request"],
            event_index=event_index,
        )
    message = event.message
    if message.get("jsonrpc") != "2.0" or message.get("method") != "subscriptions/listen":
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription opening is not a subscriptions/listen JSON-RPC 2.0 request"],
            event_index=event_index,
        )
    subscription_id = event.subscription_id
    if subscription_id is None:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription opening lacks an envelope subscription identifier"],
            event_index=event_index,
        )
    if event.request_id != subscription_id or message.get("id") != subscription_id:
        state = _add_finding(
            state,
            "MCPSUB002",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["listen request, envelope request, and subscription identifiers do not match"],
            event_index=event_index,
        )
    requested, filter_error = _listen_filter(message)
    if filter_error is not None:
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=[filter_error],
            event_index=event_index,
        )

    if event.lifecycle is Lifecycle.REPLACE:
        old = state.subscription(event.replaces_stream_id or "")
        if old is None:
            state = _add_finding(
                state,
                "MCPSUB000",
                outcome=FindingOutcome.UNKNOWN,
                target=target,
                evidence=["replacement references an unknown prior stream"],
                event_index=event_index,
            )
        else:
            state = state.with_subscription(replace(old, active=False, terminal_reason="replacement"))
            if old.subscription_id == subscription_id:
                state = _add_finding(
                    state,
                    "MCPSUB000",
                    outcome=FindingOutcome.UNKNOWN,
                    target=target,
                    evidence=["replacement reuses the prior subscription identifier"],
                    event_index=event_index,
                )

    same_identifier = [
        item
        for item in state.subscriptions
        if item.subscription_id == subscription_id and item.stream_id != event.stream_id
    ]
    if any(item.active for item in same_identifier):
        state = _add_finding(
            state,
            "MCPSUB005",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["a concurrent listener already uses this subscription identifier"],
            event_index=event_index,
        )
    elif same_identifier:
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription identifier reuse makes stale delivery attribution ambiguous"],
            event_index=event_index,
        )
    return state.with_subscription(
        _SubscriptionState(
            stream_id=event.stream_id,
            request_id=event.request_id,
            subscription_id=subscription_id,
            requested=requested,
            acknowledged=None,
            active=True,
            start_event_index=event_index,
        )
    )


def _listen_filter(message: dict[str, Any]) -> tuple[_SubscriptionFilter | None, str | None]:
    params = message.get("params")
    if not isinstance(params, dict):
        return None, "listen request params are absent or malformed"
    notifications = params.get("notifications")
    return _parse_filter(notifications, context="listen request")


def _parse_filter(
    value: Any,
    *,
    context: str,
) -> tuple[_SubscriptionFilter | None, str | None]:
    if not isinstance(value, dict):
        return None, f"{context} notification filter is absent or malformed"
    allowed_keys = {
        "toolsListChanged",
        "promptsListChanged",
        "resourcesListChanged",
        "resourceSubscriptions",
    }
    if set(value) - allowed_keys:
        return None, f"{context} notification filter contains unsupported fields"
    booleans: dict[str, bool] = {}
    for key in ("toolsListChanged", "promptsListChanged", "resourcesListChanged"):
        item = value.get(key, False)
        if not isinstance(item, bool):
            return None, f"{context} {key} filter is not boolean"
        booleans[key] = item
    resources = value.get("resourceSubscriptions", [])
    if (
        not isinstance(resources, list)
        or len(resources) > MAX_RESOURCE_SUBSCRIPTIONS
        or not all(isinstance(item, str) and 0 < len(item) <= MAX_RESOURCE_URI_CHARS for item in resources)
        or len(resources) != len(set(resources))
    ):
        return None, f"{context} resourceSubscriptions is malformed or exceeds its limit"
    return (
        _SubscriptionFilter(
            tools_list_changed=booleans["toolsListChanged"],
            prompts_list_changed=booleans["promptsListChanged"],
            resources_list_changed=booleans["resourcesListChanged"],
            resource_subscriptions=tuple(resources),
        ),
        None,
    )


def _subscription_message(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    target = _event_target(event, event_index)
    if event.direction is not Direction.SERVER_TO_CLIENT or not isinstance(event.message, dict):
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription message is not a server-to-client JSON-RPC notification"],
            event_index=event_index,
        )
    if not subscription.active:
        return _terminal_delivery_finding(state, subscription, event, event_index)
    message = event.message
    method = message.get("method")
    if isinstance(method, str) and method.startswith("notifications/"):
        state = _check_subscription_meta(
            state,
            subscription,
            message,
            event,
            event_index,
        )
    if method == _ACK_METHOD:
        return _acknowledge_subscription(state, subscription, event, event_index)
    if method in _REQUEST_SCOPED_METHODS:
        state = _add_finding(
            state,
            "MCPSUB003",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=[f"{method} appeared on a long-lived subscription stream"],
            event_index=event_index,
        )
        return state.with_subscription(replace(subscription, server_notification_seen=True))
    if not isinstance(method, str):
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["subscription JSON-RPC notification has no method"],
            event_index=event_index,
        )
        return state.with_subscription(replace(subscription, server_notification_seen=True))
    if method not in _SUBSCRIPTION_METHODS:
        state = _add_finding(
            state,
            "MCPSUB001",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["subscription stream carried a notification outside the closed opt-in filter"],
            event_index=event_index,
        )
        return state.with_subscription(replace(subscription, server_notification_seen=True))

    if subscription.acknowledged is None:
        state = _add_finding(
            state,
            "MCPSUB006",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=[f"{method} was delivered before a valid acknowledgment"],
            event_index=event_index,
        )
    if subscription.requested is None:
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["listen request filter was not valid enough to evaluate opt-in"],
            event_index=event_index,
        )
    elif not subscription.requested.allows(method):
        state = _add_finding(
            state,
            "MCPSUB001",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=[f"{method} was not enabled by the listen request"],
            event_index=event_index,
        )
    if subscription.acknowledged is not None and not subscription.acknowledged.allows(method):
        state = _add_finding(
            state,
            "MCPSUB001",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=[f"{method} was not included in the acknowledged filter"],
            event_index=event_index,
        )
    if method == "notifications/resources/updated":
        state = _check_resource_binding(state, subscription, event, event_index)
    return state.with_subscription(replace(subscription, server_notification_seen=True))


def _acknowledge_subscription(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    target = _event_target(event, event_index)
    message = event.message
    if not isinstance(message, dict):
        return state
    if subscription.acknowledged is not None:
        state = _add_finding(
            state,
            "MCPSUB006",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["listener received more than one acknowledgment"],
            event_index=event_index,
        )
    if subscription.server_notification_seen:
        state = _add_finding(
            state,
            "MCPSUB006",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["acknowledgment was not the listener's first server notification"],
            event_index=event_index,
        )
    params = message.get("params")
    acknowledged, filter_error = _parse_filter(
        params.get("notifications") if isinstance(params, dict) else None,
        context="acknowledgment",
    )
    if filter_error is not None:
        state = _add_finding(
            state,
            "MCPSUB006",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=[filter_error],
            event_index=event_index,
        )
    if (
        acknowledged is not None
        and subscription.requested is not None
        and not _filter_is_subset(acknowledged, subscription.requested)
    ):
        state = _add_finding(
            state,
            "MCPSUB006",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["acknowledgment expands beyond the requested notification filter"],
            event_index=event_index,
        )
    return state.with_subscription(
        replace(
            subscription,
            acknowledged=acknowledged,
            server_notification_seen=True,
        )
    )


def _filter_is_subset(
    acknowledged: _SubscriptionFilter,
    requested: _SubscriptionFilter,
) -> bool:
    return (
        (not acknowledged.tools_list_changed or requested.tools_list_changed)
        and (not acknowledged.prompts_list_changed or requested.prompts_list_changed)
        and (not acknowledged.resources_list_changed or requested.resources_list_changed)
        and set(acknowledged.resource_subscriptions).issubset(requested.resource_subscriptions)
    )


def _notification_subscription_id(message: dict[str, Any]) -> tuple[bool, Any]:
    params = message.get("params")
    if not isinstance(params, dict):
        return False, None
    metadata = params.get("_meta")
    if not isinstance(metadata, dict) or _SUBSCRIPTION_ID_KEY not in metadata:
        return False, None
    return True, metadata[_SUBSCRIPTION_ID_KEY]


def _check_subscription_meta(
    state: _ReducerState,
    subscription: _SubscriptionState,
    message: dict[str, Any],
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    present, observed = _notification_subscription_id(message)
    if present and observed == subscription.subscription_id:
        return state
    evidence = (
        ["notification omitted io.modelcontextprotocol/subscriptionId"]
        if not present
        else [
            "notification subscription identifier does not match the listener",
            _opaque_ref("observed-id", observed),
            _opaque_ref("expected-id", subscription.subscription_id),
        ]
    )
    return _add_finding(
        state,
        "MCPSUB002",
        outcome=FindingOutcome.VIOLATION,
        target=_event_target(event, event_index),
        evidence=evidence,
        event_index=event_index,
    )


def _check_resource_binding(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    message = event.message
    params = message.get("params") if isinstance(message, dict) else None
    resource_uri = params.get("uri") if isinstance(params, dict) else None
    target = _event_target(event, event_index)
    if not isinstance(resource_uri, str) or len(resource_uri) > MAX_RESOURCE_URI_CHARS:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["resource update URI is absent, malformed, or exceeds its limit"],
            event_index=event_index,
        )
    acknowledged = subscription.acknowledged
    if acknowledged is None:
        return state
    current_resources = set(acknowledged.resource_subscriptions)
    binding = event.declared_resource_subscription
    if binding is None and resource_uri in current_resources:
        binding = resource_uri
    if binding is None:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=[
                "non-exact resource update has no declared_resource_subscription binding",
                _opaque_ref("resource", resource_uri),
            ],
            event_index=event_index,
        )
    owners = [
        item
        for item in state.subscriptions
        if item.active
        and item.acknowledged is not None
        and binding in item.acknowledged.resource_subscriptions
    ]
    if len(owners) > 1:
        return _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=[
                "declared resource binding is acknowledged by multiple active listeners",
                _opaque_ref("resource-subscription", binding),
            ],
            event_index=event_index,
        )
    if binding not in current_resources:
        other_listener = any(item.stream_id != subscription.stream_id for item in owners)
        evidence = [
            (
                "declared resource binding belongs to another active listener"
                if other_listener
                else "declared resource binding is absent from this listener"
            ),
            _opaque_ref("resource-subscription", binding),
        ]
        return _add_finding(
            state,
            "MCPSUB004",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=evidence,
            event_index=event_index,
        )
    return state


def _close_subscription(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    if not subscription.active:
        return _terminal_delivery_finding(state, subscription, event, event_index)
    target = _event_target(event, event_index)
    message = event.message
    if event.direction is not Direction.SERVER_TO_CLIENT or not isinstance(message, dict):
        state = _add_finding(
            state,
            "MCPSUB000",
            outcome=FindingOutcome.UNKNOWN,
            target=target,
            evidence=["graceful close is not a server-to-client response"],
            event_index=event_index,
        )
    else:
        result = message.get("result")
        metadata = result.get("_meta") if isinstance(result, dict) else None
        observed = metadata.get(_SUBSCRIPTION_ID_KEY) if isinstance(metadata, dict) else None
        if message.get("id") != subscription.subscription_id or observed != subscription.subscription_id:
            state = _add_finding(
                state,
                "MCPSUB002",
                outcome=FindingOutcome.VIOLATION,
                target=target,
                evidence=["graceful close did not preserve the subscription identifier"],
                event_index=event_index,
            )
    return state.with_subscription(replace(subscription, active=False, terminal_reason="graceful-close"))


def _cancel_subscription(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    if not subscription.active:
        return _terminal_delivery_finding(state, subscription, event, event_index)
    target = _event_target(event, event_index)
    message = event.message
    params = message.get("params") if isinstance(message, dict) else None
    if (
        not isinstance(message, dict)
        or message.get("method") != "notifications/cancelled"
        or not isinstance(params, dict)
        or params.get("requestId") != subscription.subscription_id
    ):
        state = _add_finding(
            state,
            "MCPSUB002",
            outcome=FindingOutcome.VIOLATION,
            target=target,
            evidence=["cancellation did not reference the listener's request identifier"],
            event_index=event_index,
        )
    return state.with_subscription(replace(subscription, active=False, terminal_reason="cancellation"))


def _terminal_delivery_finding(
    state: _ReducerState,
    subscription: _SubscriptionState,
    event: TraceEvent,
    event_index: int,
) -> _ReducerState:
    return _add_finding(
        state,
        "MCPSUB005",
        outcome=FindingOutcome.VIOLATION,
        target=_event_target(event, event_index),
        evidence=[f"event followed terminal lifecycle: {subscription.terminal_reason or 'unknown'}"],
        event_index=event_index,
    )


def report_json_bytes(report: SubscriptionReport) -> bytes:
    return canonical_json_bytes(report)


def report_sarif(report: SubscriptionReport) -> dict[str, Any]:
    """Project the canonical report into deterministic SARIF 2.1.0."""
    try:
        tool_version = package_version("mcp-audits")
    except PackageNotFoundError:
        tool_version = "0.0.0"
    rules = [
        {
            "id": rule_id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.remediation},
            "helpUri": "https://github.com/saagpatel/MCPAudit#readme",
            "properties": {
                "category": "mcp_subscription_stream_integrity",
                "defaultSeverity": rule.severity.value,
            },
        }
        for rule_id, rule in sorted(_RULES.items())
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "level": (
                "error"
                if finding.outcome is FindingOutcome.VIOLATION and finding.severity is FindingSeverity.HIGH
                else "warning"
                if finding.outcome is FindingOutcome.VIOLATION
                else "note"
            ),
            "message": {"text": f"{finding.title}: {'; '.join(finding.evidence)}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"fixture://program-owned/{report.fixture_id}"}
                    }
                }
            ],
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "outcome": finding.outcome.value,
                "eventIndex": finding.event_index,
                "coverage": report.coverage,
                "protocolRevision": report.protocol_revision,
                "target": finding.target,
            },
        }
        for finding in report.findings
    ]
    return {
        "version": "2.1.0",
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit-subscription-stream",
                        "version": tool_version,
                        "informationUri": "https://github.com/saagpatel/MCPAudit",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSchema": report.schema_version,
                    "traceSchema": report.fixture_schema_version,
                    "protocolRevision": report.protocol_revision,
                    "verdict": report.verdict,
                    "coverage": report.coverage,
                    "inputSha256": report.input_sha256,
                },
            }
        ],
    }


def report_sarif_bytes(report: SubscriptionReport) -> bytes:
    return canonical_json_bytes(report_sarif(report))
