"""Immutable observable-state reducer for AG-UI interrupt/resume transcripts."""

from __future__ import annotations

import json
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Any

from mcp_audit.agui_interrupt_models import (
    AGUIFinding,
    AGUISeverity,
    EventRecord,
    FindingKind,
    FixtureManifest,
    InterruptOutcome,
    InterruptStateView,
    MessagesSnapshotEvent,
    ReducerSummary,
    ResumeEntry,
    RunErrorEvent,
    RunFinishedEvent,
    RunInputRecord,
    RunStartedEvent,
    StateDeltaEvent,
    StateSnapshotEvent,
    ToolCallArgsEvent,
    ToolCallEndEvent,
    ToolCallResultEvent,
    ToolCallStartEvent,
    TranscriptRecord,
    canonical_digest,
)


class InterruptStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    CANCELLED = "cancelled"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"


@dataclass(frozen=True)
class InterruptState:
    thread_id: str
    source_run_id: str
    interrupt_id: str
    status: InterruptStatus
    tool_call_id: str | None
    response_schema_json: str | None
    response_schema_supported: bool | None
    expires_at: datetime | None
    opened_sequence: int
    closed_sequence: int | None = None


@dataclass(frozen=True)
class ResumeTarget:
    interrupt_key: tuple[str, str, str]
    status: str


@dataclass(frozen=True)
class ResumeAttempt:
    thread_id: str
    run_id: str
    sequence: int
    fingerprint: str
    targets: tuple[ResumeTarget, ...]
    valid: bool
    duplicate_of_run_id: str | None = None
    stale_statuses: tuple[InterruptStatus, ...] = ()
    started: bool = False
    terminal: str | None = None


@dataclass(frozen=True)
class RunState:
    stream_id: str
    thread_id: str
    run_id: str
    started_sequence: int
    boundary_events: tuple[str, ...] = ()
    proposed_tool_ids: tuple[str, ...] = ()
    args_tool_ids: tuple[str, ...] = ()
    ended_tool_ids: tuple[str, ...] = ()
    result_tool_ids: tuple[str, ...] = ()
    resumed_tool_ids: tuple[str, ...] = ()
    terminal: str | None = None


@dataclass(frozen=True)
class ReducerState:
    interrupts: tuple[InterruptState, ...] = ()
    attempts: tuple[ResumeAttempt, ...] = ()
    observed_inputs: tuple[tuple[str, str], ...] = ()
    runs: tuple[RunState, ...] = ()
    findings: tuple[AGUIFinding, ...] = ()


_RULES: dict[str, tuple[AGUISeverity, str, str]] = {
    "AGUI000": (
        AGUISeverity.UNKNOWN,
        "Transcript coverage is malformed, incomplete, or unsupported",
        "Regenerate a complete program-owned transcript using the pinned fixture contract.",
    ),
    "AGUI001": (
        AGUISeverity.HIGH,
        "Resume is bound to the wrong thread or interrupted run",
        "Start a new run on the same thread and bind every response to the exact latest open interrupt set.",
    ),
    "AGUI002": (
        AGUISeverity.HIGH,
        "Resume response set does not exactly cover the open interrupts",
        "Submit exactly one response for every open interrupt from the interrupted run.",
    ),
    "AGUI003": (
        AGUISeverity.HIGH,
        "Resume payload or tool-call identity violates the advertised contract",
        "Validate the payload against responseSchema and preserve the original toolCallId across runs.",
    ),
    "AGUI004": (
        AGUISeverity.HIGH,
        "Required interrupt-boundary snapshot is missing or causally invalid",
        "Emit every declared required snapshot on the interrupted run before its interrupting RUN_FINISHED.",
    ),
    "AGUI005": (
        AGUISeverity.HIGH,
        "Duplicate resume tuple was observably applied twice",
        "Deduplicate exact resume tuples or terminate the replayed request with RUN_ERROR.",
    ),
    "AGUI006": (
        AGUISeverity.HIGH,
        "Expired, superseded, terminal, or resolved interrupt was reopened",
        "Reject stale interrupt identifiers and allocate a fresh identifier for each new interrupt.",
    ),
}


def _finding(
    rule_id: str,
    kind: FindingKind,
    *,
    target: str,
    evidence: Iterable[str],
    sequence: int | None,
) -> AGUIFinding:
    severity, title, remediation = _RULES[rule_id]
    return AGUIFinding(
        rule_id=rule_id,  # type: ignore[arg-type]
        severity=severity,
        kind=kind,
        title=title,
        target=target,
        sequence=sequence,
        evidence=sorted(set(evidence)),
        remediation=remediation,
    )


def unknown_finding(
    kind: FindingKind,
    evidence: str,
    *,
    target: str = "transcript",
    sequence: int | None = None,
) -> AGUIFinding:
    return _finding("AGUI000", kind, target=target, evidence=[evidence], sequence=sequence)


def _interrupt_key(item: InterruptState) -> tuple[str, str, str]:
    return (item.thread_id, item.source_run_id, item.interrupt_id)


def _replace_interrupts(
    state: ReducerState,
    replacements: dict[tuple[str, str, str], InterruptState],
) -> ReducerState:
    return replace(
        state,
        interrupts=tuple(replacements.get(_interrupt_key(item), item) for item in state.interrupts),
    )


def _append_findings(state: ReducerState, *findings: AGUIFinding) -> ReducerState:
    return replace(state, findings=state.findings + tuple(findings))


def _resume_entry_fingerprint(entry: ResumeEntry) -> dict[str, Any]:
    return {
        "interruptId": entry.interrupt_id,
        "status": entry.status,
        "payloadSupplied": entry.payload_was_supplied,
        "payload": entry.payload if entry.payload_was_supplied else None,
    }


def _resume_fingerprint(record: RunInputRecord) -> str:
    entries = record.input.resume or []
    normalized = sorted(
        (_resume_entry_fingerprint(entry) for entry in entries),
        key=lambda item: (
            str(item["interruptId"]),
            str(item["status"]),
            canonical_digest(item["payload"]),
        ),
    )
    return canonical_digest({"threadId": record.input.thread_id, "resume": normalized})


def _historical_interrupts(state: ReducerState, interrupt_id: str) -> tuple[InterruptState, ...]:
    return tuple(item for item in state.interrupts if item.interrupt_id == interrupt_id)


def _open_interrupts(state: ReducerState, thread_id: str) -> tuple[InterruptState, ...]:
    return tuple(
        item
        for item in state.interrupts
        if item.thread_id == thread_id and item.status is InterruptStatus.OPEN
    )


def _schema_type_matches(expected: str, payload: Any) -> bool:
    if expected == "object":
        return isinstance(payload, dict)
    if expected == "array":
        return isinstance(payload, list)
    if expected == "string":
        return isinstance(payload, str)
    if expected == "integer":
        return isinstance(payload, int) and not isinstance(payload, bool)
    if expected == "number":
        return isinstance(payload, (int, float)) and not isinstance(payload, bool)
    if expected == "boolean":
        return isinstance(payload, bool)
    if expected == "null":
        return payload is None
    return False


def _schema_supported(
    schema: Any,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> bool:
    """Validate the complete declared schema shape before inspecting a payload."""
    if budget is None:
        budget = [1_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 12 or not isinstance(schema, dict):
        return False
    allowed = {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "description",
        "title",
        "default",
        "examples",
    }
    if set(schema) - allowed:
        return False
    expected = schema.get("type")
    if not isinstance(expected, str) or expected not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        return False
    if "enum" in schema and (not isinstance(schema["enum"], list) or len(schema["enum"]) > 128):
        return False

    properties = schema.get("properties", {})
    if not isinstance(properties, dict) or len(properties) > 128:
        return False
    for key, child_schema in properties.items():
        if not isinstance(key, str) or not _schema_supported(
            child_schema,
            depth=depth + 1,
            budget=budget,
        ):
            return False

    required = schema.get("required", [])
    if (
        not isinstance(required, list)
        or any(not isinstance(item, str) for item in required)
        or len(required) != len(set(required))
        or (expected == "object" and any(item not in properties for item in required))
    ):
        return False
    additional = schema.get("additionalProperties", True)
    if not isinstance(additional, bool):
        return False

    if "items" in schema and not _schema_supported(
        schema["items"],
        depth=depth + 1,
        budget=budget,
    ):
        return False

    for lower_name, upper_name, hard_max in (
        ("minItems", "maxItems", 128),
        ("minLength", "maxLength", 8_192),
    ):
        lower = schema.get(lower_name, 0)
        upper = schema.get(upper_name, hard_max)
        if (
            not isinstance(lower, int)
            or isinstance(lower, bool)
            or not isinstance(upper, int)
            or isinstance(upper, bool)
            or lower < 0
            or upper < lower
            or upper > hard_max
        ):
            return False

    for bound_name in ("minimum", "maximum"):
        bound = schema.get(bound_name)
        if bound is not None and (
            not isinstance(bound, (int, float))
            or isinstance(bound, bool)
            or (isinstance(bound, float) and not math.isfinite(bound))
        ):
            return False
    return True


def _json_semantic_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int type conflation."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_semantic_equal(a, b) for a, b in zip(left, right, strict=True))
        )
    if isinstance(left, dict) or isinstance(right, dict):
        return (
            isinstance(left, dict)
            and isinstance(right, dict)
            and left.keys() == right.keys()
            and all(_json_semantic_equal(left[key], right[key]) for key in left)
        )
    return False


def _validate_schema(
    schema: Any,
    payload: Any,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> tuple[bool, bool]:
    """Return (supported, valid) for MCPAudit's bounded JSON Schema projection."""
    if budget is None:
        if not _schema_supported(schema):
            return False, False
        budget = [1_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 12 or not isinstance(schema, dict):
        return False, False
    allowed = {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "enum",
        "const",
        "description",
        "title",
        "default",
        "examples",
    }
    if set(schema) - allowed:
        return False, False
    expected = schema.get("type")
    if not isinstance(expected, str) or expected not in {
        "object",
        "array",
        "string",
        "integer",
        "number",
        "boolean",
        "null",
    }:
        return False, False
    if not _schema_type_matches(expected, payload):
        return True, False
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list) or len(enum) > 128:
            return False, False
        if not any(_json_semantic_equal(payload, candidate) for candidate in enum):
            return True, False
    if "const" in schema and not _json_semantic_equal(payload, schema["const"]):
        return True, False
    if expected == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)
        if (
            not isinstance(properties, dict)
            or len(properties) > 128
            or not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(required) != len(set(required))
            or not isinstance(additional, bool)
        ):
            return False, False
        if any(item not in properties for item in required):
            return False, False
        assert isinstance(payload, dict)
        if any(item not in payload for item in required):
            return True, False
        if not additional and set(payload) - set(properties):
            return True, False
        for key, child_schema in properties.items():
            if not isinstance(key, str):
                return False, False
            if key in payload:
                supported, valid = _validate_schema(
                    child_schema,
                    payload[key],
                    depth=depth + 1,
                    budget=budget,
                )
                if not supported or not valid:
                    return supported, valid
    elif expected == "array":
        assert isinstance(payload, list)
        minimum = schema.get("minItems", 0)
        maximum = schema.get("maxItems", 128)
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or minimum < 0
            or maximum < minimum
            or maximum > 128
        ):
            return False, False
        if not minimum <= len(payload) <= maximum:
            return True, False
        if "items" in schema:
            for item in payload:
                supported, valid = _validate_schema(
                    schema["items"],
                    item,
                    depth=depth + 1,
                    budget=budget,
                )
                if not supported or not valid:
                    return supported, valid
    elif expected == "string":
        assert isinstance(payload, str)
        minimum = schema.get("minLength", 0)
        maximum = schema.get("maxLength", 8192)
        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or minimum < 0
            or maximum < minimum
            or maximum > 8192
        ):
            return False, False
        if not minimum <= len(payload) <= maximum:
            return True, False
    elif expected in {"integer", "number"}:
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and (not isinstance(minimum, (int, float)) or isinstance(minimum, bool)):
            return False, False
        if maximum is not None and (not isinstance(maximum, (int, float)) or isinstance(maximum, bool)):
            return False, False
        if minimum is not None and payload < minimum:
            return True, False
        if maximum is not None and payload > maximum:
            return True, False
    return True, True


def _validate_resume_payload(
    state: ReducerState,
    record: RunInputRecord,
    target: InterruptState,
    entry: ResumeEntry,
) -> tuple[ReducerState, bool]:
    if entry.status == "cancelled" or target.response_schema_json is None:
        return state, True
    if target.response_schema_supported is False:
        return state, False
    schema = json.loads(target.response_schema_json)
    supported, valid = _validate_schema(schema, entry.payload)
    if not supported:
        return (
            _append_findings(
                state,
                unknown_finding(
                    FindingKind.UNSUPPORTED_SCHEMA,
                    "responseSchema uses a construct outside the bounded supported profile",
                    target=target.interrupt_id,
                    sequence=record.sequence,
                ),
            ),
            False,
        )
    if not valid:
        return (
            _append_findings(
                state,
                _finding(
                    "AGUI003",
                    FindingKind.SCHEMA_MISMATCH,
                    target=target.interrupt_id,
                    evidence=["resume payload does not satisfy the advertised responseSchema"],
                    sequence=record.sequence,
                ),
            ),
            False,
        )
    return state, True


def _reduce_input(state: ReducerState, record: RunInputRecord) -> ReducerState:
    state = replace(
        state,
        observed_inputs=state.observed_inputs + ((record.input.thread_id, record.input.run_id),),
    )
    resume = record.input.resume
    open_for_thread = _open_interrupts(state, record.input.thread_id)
    if not resume:
        if open_for_thread:
            state = _append_findings(
                state,
                _finding(
                    "AGUI001",
                    FindingKind.MISSING_RESUME,
                    target=record.input.run_id,
                    evidence=[f"open_interrupt_count={len(open_for_thread)}"],
                    sequence=record.sequence,
                ),
            )
        return state

    fingerprint = _resume_fingerprint(record)
    same_run_attempts = tuple(
        item
        for item in state.attempts
        if item.thread_id == record.input.thread_id and item.run_id == record.input.run_id
    )
    semantic_run = next(
        (
            item
            for item in state.runs
            if item.thread_id == record.input.thread_id and item.run_id == record.input.run_id
        ),
        None,
    )
    if semantic_run is not None and not any(item.fingerprint == fingerprint for item in same_run_attempts):
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "a conflicting resume input arrived after its semantic run had started",
                target=record.input.run_id,
                sequence=record.sequence,
            ),
        )
    prior_same = tuple(
        item
        for item in state.attempts
        if item.thread_id == record.input.thread_id
        and item.fingerprint == fingerprint
        and item.terminal != "error"
    )
    duplicate_of = prior_same[0].run_id if prior_same else None
    if duplicate_of is not None:
        return replace(
            state,
            attempts=state.attempts
            + (
                ResumeAttempt(
                    thread_id=record.input.thread_id,
                    run_id=record.input.run_id,
                    sequence=record.sequence,
                    fingerprint=fingerprint,
                    targets=(),
                    valid=False,
                    duplicate_of_run_id=duplicate_of,
                ),
            ),
        )
    ids = [entry.interrupt_id for entry in resume]
    counts = Counter(ids)
    unique_ids = set(ids)
    targets_by_id = {item.interrupt_id: item for item in open_for_thread}
    expected_ids = set(targets_by_id)
    valid = True

    duplicates = sorted(item for item, count in counts.items() if count > 1)
    if duplicates:
        state = _append_findings(
            state,
            _finding(
                "AGUI002",
                FindingKind.DUPLICATE_RESPONSE,
                target=record.input.run_id,
                evidence=[f"duplicate_interrupt_count={len(duplicates)}"],
                sequence=record.sequence,
            ),
        )
        valid = False
    missing = sorted(expected_ids - unique_ids)
    if missing:
        state = _append_findings(
            state,
            _finding(
                "AGUI002",
                FindingKind.PARTIAL_RESPONSE_SET,
                target=record.input.run_id,
                evidence=[
                    f"expected_interrupt_count={len(expected_ids)}",
                    f"missing_interrupt_count={len(missing)}",
                ],
                sequence=record.sequence,
            ),
        )
        valid = False
    extra = sorted(unique_ids - expected_ids)
    if extra:
        wrong_thread = any(
            historical.thread_id != record.input.thread_id and historical.status is InterruptStatus.OPEN
            for interrupt_id in extra
            for historical in _historical_interrupts(state, interrupt_id)
        )
        historical = tuple(
            item for interrupt_id in extra for item in _historical_interrupts(state, interrupt_id)
        )
        if wrong_thread:
            state = _append_findings(
                state,
                _finding(
                    "AGUI001",
                    FindingKind.WRONG_THREAD,
                    target=record.input.run_id,
                    evidence=[f"foreign_interrupt_count={len(extra)}"],
                    sequence=record.sequence,
                ),
            )
        elif historical:
            if expected_ids:
                statuses = sorted({item.status.value for item in historical})
                state = _append_findings(
                    state,
                    _finding(
                        "AGUI001",
                        FindingKind.WRONG_SOURCE_RUN,
                        target=record.input.run_id,
                        evidence=[
                            f"stale_interrupt_count={len(extra)}",
                            f"historical_statuses={','.join(statuses)}",
                        ],
                        sequence=record.sequence,
                    ),
                )
        else:
            state = _append_findings(
                state,
                _finding(
                    "AGUI002",
                    FindingKind.EXTRA_RESPONSE,
                    target=record.input.run_id,
                    evidence=[f"extra_interrupt_count={len(extra)}"],
                    sequence=record.sequence,
                ),
            )
        valid = False

    source_runs = {item.source_run_id for item in targets_by_id.values() if item.interrupt_id in unique_ids}
    if len(source_runs) > 1:
        state = _append_findings(
            state,
            _finding(
                "AGUI001",
                FindingKind.WRONG_SOURCE_RUN,
                target=record.input.run_id,
                evidence=[f"source_run_count={len(source_runs)}"],
                sequence=record.sequence,
            ),
        )
        valid = False
    if source_runs and record.input.run_id in source_runs:
        state = _append_findings(
            state,
            _finding(
                "AGUI001",
                FindingKind.SAME_RUN_REUSE,
                target=record.input.run_id,
                evidence=["AG-UI resume must start a new run, not reuse the interrupted runId"],
                sequence=record.sequence,
            ),
        )
        valid = False

    targets: list[ResumeTarget] = []
    expired_target = False
    for entry in resume:
        target = targets_by_id.get(entry.interrupt_id)
        if target is None:
            continue
        state, payload_valid = _validate_resume_payload(state, record, target, entry)
        valid = valid and payload_valid
        if target.expires_at is not None and record.timestamp > target.expires_at:
            valid = False
            expired_target = True
            state = _replace_interrupts(
                state,
                {
                    _interrupt_key(target): replace(
                        target,
                        status=InterruptStatus.EXPIRED,
                        closed_sequence=record.sequence,
                    )
                },
            )
        targets.append(ResumeTarget(_interrupt_key(target), entry.status))

    stale_statuses = tuple(
        sorted(
            {
                historical.status
                for interrupt_id in extra
                for historical in _historical_interrupts(state, interrupt_id)
                if historical.thread_id == record.input.thread_id
            },
            key=str,
        )
    )
    if expired_target:
        stale_statuses = tuple(sorted(set(stale_statuses) | {InterruptStatus.EXPIRED}, key=str))
    attempt = ResumeAttempt(
        thread_id=record.input.thread_id,
        run_id=record.input.run_id,
        sequence=record.sequence,
        fingerprint=fingerprint,
        targets=tuple(targets),
        valid=valid,
        duplicate_of_run_id=duplicate_of,
        stale_statuses=stale_statuses,
    )
    return replace(state, attempts=state.attempts + (attempt,))


def _run_for_stream(state: ReducerState, stream_id: str) -> RunState | None:
    return next((item for item in state.runs if item.stream_id == stream_id), None)


def _replace_run(state: ReducerState, run: RunState) -> ReducerState:
    return replace(
        state,
        runs=tuple(run if item.stream_id == run.stream_id else item for item in state.runs),
    )


def _replace_attempt(state: ReducerState, attempt: ResumeAttempt) -> ReducerState:
    return replace(
        state,
        attempts=tuple(
            attempt
            if item.thread_id == attempt.thread_id
            and item.run_id == attempt.run_id
            and item.sequence == attempt.sequence
            else item
            for item in state.attempts
        ),
    )


def _start_run(state: ReducerState, record: EventRecord, event: RunStartedEvent) -> ReducerState:
    if _run_for_stream(state, record.stream_id) is not None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "stream contains more than one RUN_STARTED",
                target=record.stream_id,
                sequence=record.sequence,
            ),
        )
    semantic_collision = next(
        (
            item
            for item in state.runs
            if item.thread_id == event.thread_id
            and item.run_id == event.run_id
            and item.stream_id != record.stream_id
        ),
        None,
    )
    if semantic_collision is not None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "distinct streams claim the same threadId/runId identity",
                target=event.run_id,
                sequence=record.sequence,
            ),
        )
    run = RunState(
        stream_id=record.stream_id,
        thread_id=event.thread_id,
        run_id=event.run_id,
        started_sequence=record.sequence,
    )
    state = replace(state, runs=state.runs + (run,))
    if (event.thread_id, event.run_id) not in state.observed_inputs and _open_interrupts(
        state, event.thread_id
    ):
        state = _append_findings(
            state,
            _finding(
                "AGUI001",
                FindingKind.MISSING_RESUME,
                target=event.run_id,
                evidence=["RUN_STARTED has no observed resume while the thread has open interrupts"],
                sequence=record.sequence,
            ),
        )
    matching = tuple(
        item for item in state.attempts if item.thread_id == event.thread_id and item.run_id == event.run_id
    )
    if not matching:
        return state
    fingerprints = {item.fingerprint for item in matching}
    if len(fingerprints) > 1:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "one runId has conflicting resume messages",
                target=event.run_id,
                sequence=record.sequence,
            ),
        )
    attempt = matching[0]
    for duplicate in matching:
        state = _replace_attempt(state, replace(duplicate, started=True))
    resumed_tool_ids: list[str] = []
    if attempt.valid:
        replacements: dict[tuple[str, str, str], InterruptState] = {}
        target_status = {item.interrupt_key: item.status for item in attempt.targets}
        for interrupt in state.interrupts:
            status = target_status.get(_interrupt_key(interrupt))
            if status is None:
                continue
            new_status = InterruptStatus.RESOLVED if status == "resolved" else InterruptStatus.CANCELLED
            replacements[_interrupt_key(interrupt)] = replace(
                interrupt,
                status=new_status,
                closed_sequence=record.sequence,
            )
            if new_status is InterruptStatus.RESOLVED and interrupt.tool_call_id is not None:
                resumed_tool_ids.append(interrupt.tool_call_id)
        state = _replace_interrupts(state, replacements)
    updated_run = _run_for_stream(state, record.stream_id)
    assert updated_run is not None
    return _replace_run(
        state,
        replace(updated_run, resumed_tool_ids=tuple(sorted(resumed_tool_ids))),
    )


def _add_boundary_event(state: ReducerState, run: RunState, event_type: str) -> ReducerState:
    return _replace_run(
        state,
        replace(run, boundary_events=run.boundary_events + (event_type,)),
    )


def _finish_interrupt_run(
    state: ReducerState,
    manifest: FixtureManifest,
    record: EventRecord,
    run: RunState,
    outcome: InterruptOutcome,
) -> ReducerState:
    required_events: set[str] = set(manifest.required_boundary_events)
    missing = sorted(required_events - set(run.boundary_events))
    if missing:
        state = _append_findings(
            state,
            _finding(
                "AGUI004",
                FindingKind.MISSING_BOUNDARY_SNAPSHOT,
                target=run.run_id,
                evidence=[f"missing_boundary_events={','.join(missing)}"],
                sequence=record.sequence,
            ),
        )
    existing_open = _open_interrupts(state, run.thread_id)
    if existing_open:
        state = _append_findings(
            state,
            _finding(
                "AGUI006",
                FindingKind.INTERRUPT_SET_SUPERSEDED,
                target=run.run_id,
                evidence=[f"superseded_interrupt_count={len(existing_open)}"],
                sequence=record.sequence,
            ),
        )
        replacements = {
            _interrupt_key(item): replace(
                item,
                status=InterruptStatus.SUPERSEDED,
                closed_sequence=record.sequence,
            )
            for item in existing_open
        }
        state = _replace_interrupts(state, replacements)

    seen_ids: set[str] = set()
    additions: list[InterruptState] = []
    for interrupt in outcome.interrupts:
        if interrupt.id in seen_ids:
            state = _append_findings(
                state,
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "interrupt outcome contains duplicate interrupt IDs",
                    target=run.run_id,
                    sequence=record.sequence,
                ),
            )
            continue
        seen_ids.add(interrupt.id)
        history = _historical_interrupts(state, interrupt.id)
        if history:
            state = _append_findings(
                state,
                _finding(
                    "AGUI006",
                    FindingKind.INTERRUPT_ID_REUSED,
                    target=interrupt.id,
                    evidence=[f"historical_instance_count={len(history)}"],
                    sequence=record.sequence,
                ),
            )
        if interrupt.reason == "tool_call":
            if (
                interrupt.tool_call_id is None
                or interrupt.tool_call_id not in run.args_tool_ids
                or interrupt.tool_call_id not in run.ended_tool_ids
            ):
                state = _append_findings(
                    state,
                    _finding(
                        "AGUI003",
                        FindingKind.MISSING_TOOL_BINDING,
                        target=interrupt.id,
                        evidence=["tool_call interrupt is not bound to a completed ToolCall sequence"],
                        sequence=record.sequence,
                    ),
                )
            if interrupt.tool_call_id is not None and interrupt.tool_call_id in run.result_tool_ids:
                state = _append_findings(
                    state,
                    _finding(
                        "AGUI003",
                        FindingKind.TOOL_RESULT_BEFORE_INTERRUPT,
                        target=interrupt.id,
                        evidence=["tool-bound interrupt appeared after its ToolCallResult on the same run"],
                        sequence=record.sequence,
                    ),
                )
        schema_supported = (
            _schema_supported(interrupt.response_schema) if interrupt.response_schema is not None else None
        )
        if schema_supported is False:
            state = _append_findings(
                state,
                unknown_finding(
                    FindingKind.UNSUPPORTED_SCHEMA,
                    "responseSchema uses a construct outside the bounded supported profile",
                    target=interrupt.id,
                    sequence=record.sequence,
                ),
            )
        schema_json = (
            json.dumps(
                interrupt.response_schema,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            if interrupt.response_schema is not None
            else None
        )
        status = (
            InterruptStatus.EXPIRED
            if interrupt.expires_at is not None and record.timestamp > interrupt.expires_at
            else InterruptStatus.OPEN
        )
        additions.append(
            InterruptState(
                thread_id=run.thread_id,
                source_run_id=run.run_id,
                interrupt_id=interrupt.id,
                status=status,
                tool_call_id=interrupt.tool_call_id,
                response_schema_json=schema_json,
                response_schema_supported=schema_supported,
                expires_at=interrupt.expires_at,
                opened_sequence=record.sequence,
            )
        )
    return replace(state, interrupts=state.interrupts + tuple(additions))


def _check_resumed_tool_results(
    state: ReducerState,
    record: EventRecord,
    run: RunState,
) -> ReducerState:
    missing_results = sorted(
        tool_call_id for tool_call_id in run.resumed_tool_ids if run.result_tool_ids.count(tool_call_id) != 1
    )
    if missing_results:
        state = _append_findings(
            state,
            _finding(
                "AGUI003",
                FindingKind.MISSING_TOOL_RESULT,
                target=run.run_id,
                evidence=[f"missing_tool_result_count={len(missing_results)}"],
                sequence=record.sequence,
            ),
        )
    return state


def _finish_success_run(
    state: ReducerState,
    record: EventRecord,
    run: RunState,
) -> ReducerState:
    open_items = _open_interrupts(state, run.thread_id)
    if open_items:
        state = _append_findings(
            state,
            _finding(
                "AGUI006",
                FindingKind.TERMINAL_WITH_OPEN_INTERRUPTS,
                target=run.run_id,
                evidence=[f"open_interrupt_count={len(open_items)}"],
                sequence=record.sequence,
            ),
        )
        state = _replace_interrupts(
            state,
            {
                _interrupt_key(item): replace(
                    item,
                    status=InterruptStatus.SUPERSEDED,
                    closed_sequence=record.sequence,
                )
                for item in open_items
            },
        )
    return state


def _finalize_resume_attempts(
    state: ReducerState,
    record: EventRecord,
    run: RunState,
    terminal: str,
) -> ReducerState:
    attempts = tuple(
        item for item in state.attempts if item.thread_id == run.thread_id and item.run_id == run.run_id
    )
    for attempt in attempts:
        state = _replace_attempt(state, replace(attempt, terminal=terminal))
        if terminal == "error":
            continue
        if attempt.duplicate_of_run_id is not None and attempt.duplicate_of_run_id != attempt.run_id:
            state = _append_findings(
                state,
                _finding(
                    "AGUI005",
                    FindingKind.DUPLICATE_RESUME_APPLIED,
                    target=run.run_id,
                    evidence=[f"first_applied_run_id={attempt.duplicate_of_run_id}"],
                    sequence=record.sequence,
                ),
            )
        elif attempt.stale_statuses:
            status = attempt.stale_statuses[0]
            kind = {
                InterruptStatus.EXPIRED: FindingKind.EXPIRED_REOPENED,
                InterruptStatus.SUPERSEDED: FindingKind.SUPERSEDED_REOPENED,
                InterruptStatus.RESOLVED: FindingKind.RESOLVED_REOPENED,
                InterruptStatus.CANCELLED: FindingKind.TERMINAL_REOPENED,
                InterruptStatus.OPEN: FindingKind.TERMINAL_REOPENED,
            }[status]
            state = _append_findings(
                state,
                _finding(
                    "AGUI006",
                    kind,
                    target=run.run_id,
                    evidence=[f"historical_status={status.value}"],
                    sequence=record.sequence,
                ),
            )
    return state


def _finish_run(
    state: ReducerState,
    manifest: FixtureManifest,
    record: EventRecord,
    event: RunFinishedEvent | RunErrorEvent,
) -> ReducerState:
    run = _run_for_stream(state, record.stream_id)
    if run is None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "terminal event appeared before RUN_STARTED",
                target=record.stream_id,
                sequence=record.sequence,
            ),
        )
    if run.terminal is not None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "stream contains multiple terminal events",
                target=record.stream_id,
                sequence=record.sequence,
            ),
        )
    terminal = "error" if isinstance(event, RunErrorEvent) else "success"
    if isinstance(event, RunErrorEvent):
        applied_tool_ids = set(run.resumed_tool_ids) & set(run.result_tool_ids)
        if applied_tool_ids:
            state = _append_findings(
                state,
                _finding(
                    "AGUI006",
                    FindingKind.TERMINAL_REOPENED,
                    target=run.run_id,
                    evidence=[
                        "RunError followed an observed resumed ToolCallResult; "
                        "the applied interrupt cannot be safely reopened"
                    ],
                    sequence=record.sequence,
                ),
            )
        replacements: dict[tuple[str, str, str], InterruptState] = {}
        for attempt in state.attempts:
            if attempt.thread_id != run.thread_id or attempt.run_id != run.run_id or not attempt.valid:
                continue
            for target in attempt.targets:
                interrupt = next(
                    (item for item in state.interrupts if _interrupt_key(item) == target.interrupt_key),
                    None,
                )
                if interrupt is not None and interrupt.tool_call_id not in applied_tool_ids:
                    replacements[target.interrupt_key] = replace(
                        interrupt,
                        status=InterruptStatus.OPEN,
                        closed_sequence=None,
                    )
        state = _replace_interrupts(state, replacements)
    if isinstance(event, RunFinishedEvent):
        state = _check_resumed_tool_results(state, record, run)
        if event.thread_id != run.thread_id or event.run_id != run.run_id:
            state = _append_findings(
                state,
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "RUN_FINISHED identity disagrees with its stream RUN_STARTED",
                    target=record.stream_id,
                    sequence=record.sequence,
                ),
            )
        if isinstance(event.outcome, InterruptOutcome):
            terminal = "interrupt"
            state = _finish_interrupt_run(state, manifest, record, run, event.outcome)
        else:
            state = _finish_success_run(state, record, run)
    state = _finalize_resume_attempts(state, record, run, terminal)
    run = _run_for_stream(state, record.stream_id)
    assert run is not None
    return _replace_run(state, replace(run, terminal=terminal))


def _reduce_event(state: ReducerState, manifest: FixtureManifest, record: EventRecord) -> ReducerState:
    event = record.event
    if isinstance(event, RunStartedEvent):
        return _start_run(state, record, event)
    run = _run_for_stream(state, record.stream_id)
    if isinstance(event, (RunFinishedEvent, RunErrorEvent)):
        return _finish_run(state, manifest, record, event)
    if run is None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.MALFORMED_TRANSCRIPT,
                "event appeared before RUN_STARTED",
                target=record.stream_id,
                sequence=record.sequence,
            ),
        )
    if run.terminal is not None:
        return _append_findings(
            state,
            unknown_finding(
                FindingKind.INCOMPLETE_TRANSCRIPT,
                "event appeared after the stream terminal event",
                target=record.stream_id,
                sequence=record.sequence,
            ),
        )
    if isinstance(event, (StateSnapshotEvent, MessagesSnapshotEvent)):
        return _add_boundary_event(state, run, event.type)
    if isinstance(event, StateDeltaEvent):
        return state
    if isinstance(event, ToolCallStartEvent):
        if event.tool_call_id in run.resumed_tool_ids:
            return _append_findings(
                state,
                _finding(
                    "AGUI003",
                    FindingKind.REEMITTED_TOOL_CALL,
                    target=event.tool_call_id,
                    evidence=["resumed run re-emitted ToolCallStart for the original toolCallId"],
                    sequence=record.sequence,
                ),
            )
        if event.tool_call_id in run.proposed_tool_ids:
            return _append_findings(
                state,
                unknown_finding(
                    FindingKind.DUPLICATE_TOOL_EVENT,
                    "TOOL_CALL_START repeats an existing toolCallId on its stream",
                    target=event.tool_call_id,
                    sequence=record.sequence,
                ),
            )
        return _replace_run(
            state,
            replace(run, proposed_tool_ids=run.proposed_tool_ids + (event.tool_call_id,)),
        )
    if isinstance(event, ToolCallArgsEvent):
        if event.tool_call_id not in run.proposed_tool_ids or event.tool_call_id in run.ended_tool_ids:
            return _append_findings(
                state,
                unknown_finding(
                    FindingKind.INVALID_TOOL_EVENT_ORDER,
                    "TOOL_CALL_ARGS must follow START and precede END on its stream",
                    target=event.tool_call_id,
                    sequence=record.sequence,
                ),
            )
        return _replace_run(
            state,
            replace(run, args_tool_ids=run.args_tool_ids + (event.tool_call_id,)),
        )
    if isinstance(event, ToolCallEndEvent):
        if (
            event.tool_call_id not in run.proposed_tool_ids
            or event.tool_call_id not in run.args_tool_ids
            or event.tool_call_id in run.ended_tool_ids
        ):
            return _append_findings(
                state,
                unknown_finding(
                    FindingKind.INVALID_TOOL_EVENT_ORDER,
                    "TOOL_CALL_END must follow START and at least one ARGS event exactly once",
                    target=event.tool_call_id,
                    sequence=record.sequence,
                ),
            )
        return _replace_run(
            state,
            replace(run, ended_tool_ids=run.ended_tool_ids + (event.tool_call_id,)),
        )
    if isinstance(event, ToolCallResultEvent):
        if event.tool_call_id in run.result_tool_ids:
            return _append_findings(
                state,
                unknown_finding(
                    FindingKind.DUPLICATE_TOOL_EVENT,
                    "TOOL_CALL_RESULT repeats an existing toolCallId on its stream",
                    target=event.tool_call_id,
                    sequence=record.sequence,
                ),
            )
        if event.tool_call_id in run.proposed_tool_ids and event.tool_call_id not in run.ended_tool_ids:
            return _append_findings(
                state,
                unknown_finding(
                    FindingKind.INVALID_TOOL_EVENT_ORDER,
                    "TOOL_CALL_RESULT for a current-run tool must follow TOOL_CALL_END",
                    target=event.tool_call_id,
                    sequence=record.sequence,
                ),
            )
        if event.tool_call_id not in run.resumed_tool_ids and event.tool_call_id not in run.proposed_tool_ids:
            return _append_findings(
                state,
                _finding(
                    "AGUI003",
                    FindingKind.UNBOUND_TOOL_RESULT,
                    target=event.tool_call_id,
                    evidence=["ToolCallResult is not bound to an original resumed or current-run tool call"],
                    sequence=record.sequence,
                ),
            )
        return _replace_run(
            state,
            replace(run, result_tool_ids=run.result_tool_ids + (event.tool_call_id,)),
        )
    return state


def reduce_transcript(
    manifest: FixtureManifest,
    records: tuple[TranscriptRecord, ...],
    initial_findings: tuple[AGUIFinding, ...] = (),
) -> ReducerState:
    """Reduce records in file order, returning a fresh immutable state per transition."""
    state = ReducerState(findings=initial_findings)
    for record in records:
        if isinstance(record, RunInputRecord):
            state = _reduce_input(state, record)
        else:
            state = _reduce_event(state, manifest, record)
    if manifest.complete:
        for run in state.runs:
            if run.terminal is None:
                state = _append_findings(
                    state,
                    unknown_finding(
                        FindingKind.INCOMPLETE_TRANSCRIPT,
                        "complete fixture contains a run without a terminal event",
                        target=run.run_id,
                    ),
                )
        for attempt in state.attempts:
            if attempt.started:
                continue
            benign_delivery_retry = any(
                other.thread_id == attempt.thread_id
                and other.run_id == attempt.run_id
                and other.fingerprint == attempt.fingerprint
                and other.started
                for other in state.attempts
            )
            if not benign_delivery_retry:
                state = _append_findings(
                    state,
                    unknown_finding(
                        FindingKind.INCOMPLETE_TRANSCRIPT,
                        "complete fixture contains a resume input without a run outcome",
                        target=attempt.run_id,
                    ),
                )
    else:
        state = _append_findings(
            state,
            unknown_finding(
                FindingKind.INCOMPLETE_TRANSCRIPT,
                "fixture manifest declares incomplete transcript coverage",
            ),
        )
    return state


def summarize_state(state: ReducerState) -> ReducerSummary:
    ordered = sorted(
        state.interrupts,
        key=lambda item: (
            item.thread_id,
            item.source_run_id,
            item.interrupt_id,
            item.opened_sequence,
        ),
    )
    views = [
        InterruptStateView(
            thread_id=item.thread_id,
            source_run_id=item.source_run_id,
            interrupt_id=item.interrupt_id,
            status=item.status.value,
            tool_call_id=item.tool_call_id,
            opened_sequence=item.opened_sequence,
            closed_sequence=item.closed_sequence,
        )
        for item in ordered
    ]
    counts = Counter(item.status for item in ordered)
    return ReducerSummary(
        open_count=counts[InterruptStatus.OPEN],
        resolved_count=counts[InterruptStatus.RESOLVED],
        cancelled_count=counts[InterruptStatus.CANCELLED],
        superseded_count=counts[InterruptStatus.SUPERSEDED],
        expired_count=counts[InterruptStatus.EXPIRED],
        interrupts=views,
    )
