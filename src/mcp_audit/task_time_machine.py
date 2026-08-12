"""Seed-free virtual-clock laboratory for the MCP Tasks extension.

``simulate_scenario`` is deliberately pure: it accepts a validated model and
does not read files, environment variables, credentials, clocks, or the
network. File loading is isolated in ``load_scenario_path``.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from mcp_audit.task_time_machine_models import (
    CURRENT_PROTOCOL_VERSION,
    MAX_EVENTS,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    SPEC_PROFILE,
    TERMINAL_STATUSES,
    CancelAppliedEvent,
    CancelRequestedEvent,
    CompleteEvent,
    CreateEvent,
    ExpireEvent,
    FailEvent,
    FinalTaskState,
    FindingSeverity,
    InputRequiredEvent,
    InputSubmittedEvent,
    PollEvent,
    RequirementLevel,
    ResumeWorkingEvent,
    RetryableErrorEvent,
    RetryEvent,
    TaskCoverage,
    TaskEvent,
    TaskFinding,
    TaskScenario,
    TaskSimulationResult,
    TaskStatus,
    TaskTransition,
    TransitionAuthority,
    WorkStartedEvent,
    canonical_json_bytes,
)

_STANDARD_ASSUMPTIONS: Final = [
    "SEP-2663 defines status shapes but no exhaustive normative transition matrix; "
    "terminal immutability is a design inference reinforced by the official Tasks overview.",
    "Retry attempts and exponential backoff are local fixture policy; MCP Tasks "
    "does not define retry scheduling.",
    "work_started is local laboratory phase evidence and is not an MCP status or wire method.",
    "Expiry is server-discretionary after ttlMs; each scenario must select unknown, "
    "mark_failed, or delete behavior explicitly.",
]


class TaskTimeMachineInputError(ValueError):
    """Raised for a filesystem boundary failure, not scenario validation."""


@dataclass
class _Machine:
    scenario: TaskScenario
    status: TaskStatus | None = None
    availability: str = "available"
    version: int = 0
    clock_ms: int = 0
    created_at_ms: int | None = None
    updated_at_ms: int | None = None
    expires_at_ms: int | None = None
    attempt: int = 0
    work_started: bool = False
    retry_due_ms: int | None = None
    cancel_requested: bool = False
    result_present: bool = False
    error_present: bool = False
    last_poll_ms: int | None = None
    issued_input_keys: set[str] = field(default_factory=set)
    outstanding_input_keys: set[str] = field(default_factory=set)
    transitions: list[TaskTransition] = field(default_factory=list)
    findings: list[TaskFinding] = field(default_factory=list)
    seen_event_ids: set[str] = field(default_factory=set)

    def status_label(self) -> str:
        return "not_created" if self.status is None else self.status.value


def _scenario_digest(scenario: TaskScenario) -> str:
    payload = scenario.model_dump(mode="json")
    payload["events"] = sorted(payload["events"], key=lambda item: (item["at_ms"], item["sequence"]))
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _finding(
    machine: _Machine,
    rule_id: str,
    severity: FindingSeverity,
    level: RequirementLevel,
    title: str,
    evidence: str,
    remediation: str,
    sequence: int,
    *assumptions: str,
) -> None:
    machine.findings.append(
        TaskFinding(
            rule_id=rule_id,  # type: ignore[arg-type]
            severity=severity,
            requirement_level=level,
            title=title,
            evidence=evidence,
            remediation=remediation,
            event_sequences=[sequence],
            assumptions=list(assumptions),
        )
    )


def _transition(
    machine: _Machine,
    event: TaskEvent,
    before: str,
    disposition: str,
    authority: TransitionAuthority,
    explanation: str,
) -> None:
    machine.transitions.append(
        TaskTransition(
            event_id=event.event_id,
            sequence=event.sequence,
            at_ms=event.at_ms,
            event_type=event.type,
            before_status=before,
            after_status=machine.status_label(),
            disposition=disposition,  # type: ignore[arg-type]
            authority=authority,
            explanation=explanation,
            state_version=machine.version,
            attempt=machine.attempt,
        )
    )


def _terminal_rejection(machine: _Machine, event: TaskEvent, before: str) -> bool:
    if machine.status not in TERMINAL_STATUSES:
        return False
    _finding(
        machine,
        "MCPTASK002",
        FindingSeverity.HIGH,
        RequirementLevel.DESIGN_INFERENCE,
        "Forbidden post-terminal transition",
        "A state-changing event targeted a terminal task.",
        "Remove the event or start a new task with a distinct task ID.",
        event.sequence,
        "The official Tasks overview calls completed, failed, and cancelled terminal; "
        "SEP-2663 does not publish an exhaustive transition table.",
    )
    _transition(
        machine,
        event,
        before,
        "rejected",
        TransitionAuthority.DESIGN_INFERENCE,
        "Terminal task states are immutable in this laboratory model.",
    )
    return True


def _require_created(machine: _Machine, event: TaskEvent, before: str) -> bool:
    if machine.status is not None:
        return True
    _finding(
        machine,
        "MCPTASK001",
        FindingSeverity.HIGH,
        RequirementLevel.PROTOCOL_MUST,
        "Event preceded durable task creation",
        "The event referenced a task before its create event was applied.",
        "Create the task first and preserve deterministic event ordering.",
        event.sequence,
    )
    _transition(
        machine,
        event,
        before,
        "rejected",
        TransitionAuthority.PROTOCOL_REQUIREMENT,
        "CreateTaskResult must not be returned before tasks/get can resolve the task.",
    )
    return False


def _apply_create(machine: _Machine, event: CreateEvent, before: str) -> None:
    if machine.status is not None:
        _finding(
            machine,
            "MCPTASK001",
            FindingSeverity.HIGH,
            RequirementLevel.PROTOCOL_MUST,
            "Task created more than once",
            "A second create event targeted the same task ID.",
            "Use a distinct receiver-generated task ID for a new task.",
            event.sequence,
        )
        _transition(
            machine,
            event,
            before,
            "rejected",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "A task ID identifies one durable task.",
        )
        return
    machine.status = TaskStatus.WORKING
    machine.version = 1
    machine.created_at_ms = event.at_ms
    machine.updated_at_ms = event.at_ms
    if machine.scenario.ttl_ms is not None:
        machine.expires_at_ms = event.at_ms + machine.scenario.ttl_ms
    _transition(
        machine,
        event,
        before,
        "applied",
        TransitionAuthority.LOCAL_FIXTURE_POLICY,
        "Task durably created in working status; SEP-2663 says working is typical, not mandatory.",
    )


def _apply_poll(machine: _Machine, event: PollEvent, before: str) -> None:
    if not _require_created(machine, event, before):
        return
    if machine.availability == "deleted":
        _finding(
            machine,
            "MCPTASK007",
            FindingSeverity.MEDIUM,
            RequirementLevel.PROTOCOL_MUST,
            "Deleted task was polled as available",
            "The local expiry policy deleted the task before this poll.",
            "Treat tasks/get as Invalid Params after deletion.",
            event.sequence,
        )
        _transition(
            machine,
            event,
            before,
            "rejected",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "Expired deleted tasks no longer resolve through tasks/get.",
        )
        return
    if machine.last_poll_ms is not None:
        elapsed = event.at_ms - machine.last_poll_ms
        if elapsed < machine.scenario.poll_interval_ms:
            _finding(
                machine,
                "MCPTASK003",
                FindingSeverity.LOW,
                RequirementLevel.PROTOCOL_SHOULD,
                "Poll cadence was too aggressive",
                "A poll occurred before the advertised poll interval elapsed.",
                "Advance the virtual clock to the advertised pollIntervalMs before polling again.",
                event.sequence,
            )
    machine.last_poll_ms = event.at_ms
    if event.observed_version is not None and event.observed_version > machine.version:
        _finding(
            machine,
            "MCPTASK003",
            FindingSeverity.HIGH,
            RequirementLevel.LOCAL_FIXTURE,
            "Impossible future task state was claimed",
            "The poll observed a state version newer than the current simulated task version.",
            "Return the current state version or advance the task through explicit causal events first.",
            event.sequence,
            "state_version is a local monotonic observation aid, not an MCP field.",
        )
        _transition(
            machine,
            event,
            before,
            "rejected",
            TransitionAuthority.LOCAL_FIXTURE_POLICY,
            "A poll cannot observe a future local state version without causal transition evidence.",
        )
        return
    if event.observed_version is not None and event.observed_version < machine.version:
        _finding(
            machine,
            "MCPTASK003",
            FindingSeverity.HIGH,
            RequirementLevel.PROTOCOL_MUST,
            "Stale task state was returned",
            "The poll observed a state version older than the current simulated task version.",
            "Return the task's current DetailedTask state from tasks/get.",
            event.sequence,
            "state_version is a local monotonic observation aid, not an MCP field.",
        )
    _transition(
        machine,
        event,
        before,
        "observed",
        TransitionAuthority.PROTOCOL_REQUIREMENT,
        "tasks/get observes the current task state without mutating it.",
    )


def _backoff_ms(machine: _Machine) -> int:
    policy = machine.scenario.retry_policy
    exponent = max(0, machine.attempt - 1)
    value = policy.initial_backoff_ms * (policy.multiplier**exponent)
    return int(min(value, policy.max_backoff_ms))


def _apply_event(machine: _Machine, event: TaskEvent) -> None:
    machine.clock_ms = event.at_ms
    before = machine.status_label()

    if event.event_id in machine.seen_event_ids:
        _finding(
            machine,
            "MCPTASK006",
            FindingSeverity.MEDIUM,
            RequirementLevel.LOCAL_FIXTURE,
            "Duplicate event ID ignored",
            "A later event reused an earlier event_id and was not re-applied.",
            "Assign every causal event a stable unique event_id; retries should use new IDs.",
            event.sequence,
        )
        _transition(
            machine,
            event,
            before,
            "ignored",
            TransitionAuthority.LOCAL_FIXTURE_POLICY,
            "Duplicate IDs are idempotently ignored after the first application.",
        )
        return
    machine.seen_event_ids.add(event.event_id)

    if isinstance(event, CreateEvent):
        _apply_create(machine, event, before)
        return
    if isinstance(event, PollEvent):
        _apply_poll(machine, event, before)
        return
    if not _require_created(machine, event, before):
        return

    if isinstance(event, WorkStartedEvent):
        if _terminal_rejection(machine, event, before):
            return
        if machine.status != TaskStatus.WORKING or machine.work_started:
            _finding(
                machine,
                "MCPTASK001",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Invalid local work-start phase",
                "work_started requires one created working task that has not started.",
                "Emit work_started once while the task is working.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "Local phase preconditions were not met.",
            )
            return
        machine.work_started = True
        machine.attempt = 1
        _transition(
            machine,
            event,
            before,
            "observed",
            TransitionAuthority.LOCAL_FIXTURE_POLICY,
            "The first local work attempt started without changing MCP status.",
        )
        return

    if isinstance(event, RetryableErrorEvent):
        if _terminal_rejection(machine, event, before):
            return
        if machine.status != TaskStatus.WORKING or machine.attempt < 1:
            _finding(
                machine,
                "MCPTASK004",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Retryable error without an active attempt",
                "No active working attempt existed.",
                "Start work before injecting a retryable error.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "Retry preconditions were not met.",
            )
            return
        if machine.attempt >= machine.scenario.retry_policy.max_attempts:
            machine.status = TaskStatus.FAILED
            machine.version += 1
            machine.updated_at_ms = event.at_ms
            machine.error_present = True
            machine.retry_due_ms = None
            _transition(
                machine,
                event,
                before,
                "applied",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "Retry budget exhausted; local policy materialized a JSON-RPC execution failure.",
            )
            return
        machine.retry_due_ms = event.at_ms + _backoff_ms(machine)
        _transition(
            machine,
            event,
            before,
            "observed",
            TransitionAuthority.LOCAL_FIXTURE_POLICY,
            "Transient error recorded; next retry is eligible at virtual millisecond "
            f"{machine.retry_due_ms}.",
        )
        return

    if isinstance(event, RetryEvent):
        if _terminal_rejection(machine, event, before):
            return
        if machine.status != TaskStatus.WORKING or machine.retry_due_ms is None:
            _finding(
                machine,
                "MCPTASK004",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Retry had no pending transient failure",
                "The retry event had no retry_due_ms precondition.",
                "Inject a retryable_error before retrying.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "No retry was pending.",
            )
            return
        if event.at_ms < machine.retry_due_ms:
            _finding(
                machine,
                "MCPTASK004",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Retry violated backoff",
                "The retry occurred before its deterministic retry_due_ms.",
                "Advance the virtual clock through the configured backoff.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "Backoff had not elapsed.",
            )
            return
        machine.attempt += 1
        machine.retry_due_ms = None
        _transition(
            machine,
            event,
            before,
            "observed",
            TransitionAuthority.LOCAL_FIXTURE_POLICY,
            "The next local attempt started after deterministic backoff.",
        )
        return

    if isinstance(event, InputRequiredEvent):
        if _terminal_rejection(machine, event, before):
            return
        if machine.status != TaskStatus.WORKING or event.request_key in machine.issued_input_keys:
            _finding(
                machine,
                "MCPTASK008",
                FindingSeverity.HIGH,
                RequirementLevel.PROTOCOL_MUST,
                "Invalid or reused input request key",
                "input_required requires working status and a task-lifetime-unique key.",
                "Use a new key while the task is working.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.PROTOCOL_REQUIREMENT,
                "Input request preconditions were not met.",
            )
            return
        machine.issued_input_keys.add(event.request_key)
        machine.outstanding_input_keys.add(event.request_key)
        machine.status = TaskStatus.INPUT_REQUIRED
        machine.version += 1
        machine.updated_at_ms = event.at_ms
        _transition(
            machine,
            event,
            before,
            "applied",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "The task now exposes one outstanding input request.",
        )
        return

    if isinstance(event, InputSubmittedEvent):
        if _terminal_rejection(machine, event, before):
            return
        if (
            machine.status != TaskStatus.INPUT_REQUIRED
            or event.request_key not in machine.outstanding_input_keys
        ):
            _finding(
                machine,
                "MCPTASK008",
                FindingSeverity.MEDIUM,
                RequirementLevel.PROTOCOL_SHOULD,
                "Input response did not match an outstanding request",
                "The response key was unknown, already satisfied, or the task did not require input.",
                "Ignore unknown responses and submit each outstanding key at most once.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "ignored",
                TransitionAuthority.PROTOCOL_RECOMMENDATION,
                "SEP-2663 says unknown or already-satisfied responses should be ignored.",
            )
            return
        machine.outstanding_input_keys.remove(event.request_key)
        _transition(
            machine,
            event,
            before,
            "observed",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "tasks/update acknowledged input; observable status remains eventually consistent.",
        )
        return

    if isinstance(event, ResumeWorkingEvent):
        if _terminal_rejection(machine, event, before):
            return
        if machine.status != TaskStatus.INPUT_REQUIRED or machine.outstanding_input_keys:
            _finding(
                machine,
                "MCPTASK008",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Task resumed before input was satisfied",
                "resume_working requires input_required with no outstanding keys.",
                "Submit all required input before the local worker resumes.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "Outstanding input still blocks local work.",
            )
            return
        machine.status = TaskStatus.WORKING
        machine.version += 1
        machine.updated_at_ms = event.at_ms
        _transition(
            machine,
            event,
            before,
            "applied",
            TransitionAuthority.DESIGN_INFERENCE,
            "After eventual processing of tasks/update, the task returned to working.",
        )
        return

    if isinstance(event, CancelRequestedEvent):
        if machine.status in TERMINAL_STATUSES:
            _finding(
                machine,
                "MCPTASK005",
                FindingSeverity.MEDIUM,
                RequirementLevel.PROTOCOL_MUST,
                "Cancellation targeted a terminal task",
                "tasks/cancel signals intent for an in-progress task.",
                "Do not send cancellation after a terminal observation.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.PROTOCOL_REQUIREMENT,
                "The task was no longer in progress.",
            )
            return
        machine.cancel_requested = True
        _transition(
            machine,
            event,
            before,
            "observed",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "Cancellation intent was acknowledged without implying a state transition.",
        )
        return

    if isinstance(event, CancelAppliedEvent):
        if _terminal_rejection(machine, event, before):
            return
        if not machine.cancel_requested:
            _finding(
                machine,
                "MCPTASK005",
                FindingSeverity.HIGH,
                RequirementLevel.LOCAL_FIXTURE,
                "Cancellation applied without intent",
                "No prior cancel_requested event existed.",
                "Acknowledge cancellation intent before applying it.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "No cooperative cancellation request was pending.",
            )
            return
        machine.status = TaskStatus.CANCELLED
        machine.version += 1
        machine.updated_at_ms = event.at_ms
        _transition(
            machine,
            event,
            before,
            "applied",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "The cooperative worker honored cancellation.",
        )
        return

    if isinstance(event, CompleteEvent):
        if _terminal_rejection(machine, event, before):
            return
        machine.status = TaskStatus.COMPLETED
        machine.version += 1
        machine.updated_at_ms = event.at_ms
        machine.result_present = True
        machine.outstanding_input_keys.clear()
        _transition(
            machine,
            event,
            before,
            "applied",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "The original request completed and a result became available.",
        )
        return

    if isinstance(event, FailEvent):
        if _terminal_rejection(machine, event, before):
            return
        machine.status = TaskStatus.FAILED
        machine.version += 1
        machine.updated_at_ms = event.at_ms
        machine.error_present = True
        machine.outstanding_input_keys.clear()
        _transition(
            machine,
            event,
            before,
            "applied",
            TransitionAuthority.PROTOCOL_REQUIREMENT,
            "A JSON-RPC execution error moved the task to failed.",
        )
        return

    if isinstance(event, ExpireEvent):
        if machine.expires_at_ms is None:
            _finding(
                machine,
                "MCPTASK007",
                FindingSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Expiry requested for an unlimited task",
                "ttl_ms was null, so no finite expiry instant exists.",
                "Set a finite ttl_ms or remove the expiry event.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "ambiguous",
                TransitionAuthority.UNKNOWN,
                "No finite TTL was configured.",
            )
            return
        if event.at_ms < machine.expires_at_ms:
            _finding(
                machine,
                "MCPTASK007",
                FindingSeverity.MEDIUM,
                RequirementLevel.LOCAL_FIXTURE,
                "Task expired before ttlMs elapsed",
                "The expiry event preceded createdAt plus ttlMs.",
                "Advance the virtual clock to the calculated expiry instant.",
                event.sequence,
            )
            _transition(
                machine,
                event,
                before,
                "rejected",
                TransitionAuthority.LOCAL_FIXTURE_POLICY,
                "The local expiry instant had not arrived.",
            )
            return
        if machine.scenario.expiry_policy == "delete":
            machine.availability = "deleted"
            _transition(
                machine,
                event,
                before,
                "applied",
                TransitionAuthority.PROTOCOL_RECOMMENDATION,
                "The server exercised its permission to delete the task after TTL.",
            )
            return
        if machine.scenario.expiry_policy == "mark_failed":
            if machine.status in TERMINAL_STATUSES:
                machine.availability = "expired"
                _finding(
                    machine,
                    "MCPTASK007",
                    FindingSeverity.UNKNOWN,
                    RequirementLevel.UNKNOWN,
                    "Post-terminal TTL behavior is underspecified",
                    "SEP-2663 permits failure after TTL while official guidance also "
                    "describes terminal states as immutable.",
                    "Choose delete or preserve the terminal state; do not claim a protocol guarantee.",
                    event.sequence,
                )
                _transition(
                    machine,
                    event,
                    before,
                    "ambiguous",
                    TransitionAuthority.UNKNOWN,
                    "The laboratory preserved the terminal status and flagged the specification tension.",
                )
                return
            machine.status = TaskStatus.FAILED
            machine.version += 1
            machine.updated_at_ms = event.at_ms
            machine.error_present = True
            machine.availability = "expired"
            _transition(
                machine,
                event,
                before,
                "applied",
                TransitionAuthority.PROTOCOL_RECOMMENDATION,
                "The server exercised its permission to mark a non-terminal task failed after TTL.",
            )
            return
        machine.availability = "expired"
        _finding(
            machine,
            "MCPTASK007",
            FindingSeverity.UNKNOWN,
            RequirementLevel.UNKNOWN,
            "Expiry outcome intentionally unknown",
            "MCP permits multiple post-TTL outcomes and the scenario selected expiry_policy=unknown.",
            "Select mark_failed or delete only when modeling a declared implementation policy.",
            event.sequence,
        )
        _transition(
            machine,
            event,
            before,
            "ambiguous",
            TransitionAuthority.UNKNOWN,
            "The task may be unusable, failed, retained, or deleted after TTL; no guarantee was invented.",
        )


def _final_task(machine: _Machine) -> FinalTaskState | None:
    if machine.status is None or machine.created_at_ms is None or machine.updated_at_ms is None:
        return None
    return FinalTaskState(
        task_id=machine.scenario.task_id,
        status=machine.status,
        availability=machine.availability,  # type: ignore[arg-type]
        state_version=machine.version,
        created_at_ms=machine.created_at_ms,
        last_updated_at_ms=machine.updated_at_ms,
        expires_at_ms=machine.expires_at_ms,
        attempt=machine.attempt,
        cancel_requested=machine.cancel_requested,
        result_present=machine.result_present,
        error_present=machine.error_present,
        outstanding_input_keys=sorted(machine.outstanding_input_keys),
    )


def simulate_scenario(scenario: TaskScenario) -> TaskSimulationResult:
    """Evaluate a validated scenario without consulting ambient state."""

    digest = _scenario_digest(scenario)
    assumptions = sorted(set(_STANDARD_ASSUMPTIONS + scenario.assumptions))
    if scenario.protocol_version != CURRENT_PROTOCOL_VERSION:
        finding = TaskFinding(
            rule_id="MCPTASK000",
            severity=FindingSeverity.UNKNOWN,
            requirement_level=RequirementLevel.UNKNOWN,
            title="Unsupported MCP protocol version",
            evidence="The scenario protocol_version is outside this simulator profile.",
            remediation=f"Use protocol_version {CURRENT_PROTOCOL_VERSION} or a future simulator contract.",
            event_sequences=[],
            assumptions=["Legacy 2025-11-25 Tasks and the 2026-07-28 extension are not wire-compatible."],
        )
        return TaskSimulationResult(
            scenario_schema_version=scenario.schema_version,
            scenario_id=scenario.scenario_id,
            scenario_digest_sha256=digest,
            protocol_version=scenario.protocol_version,
            verdict="unknown",
            coverage=TaskCoverage(
                state="unknown",
                input_state="unsupported",
                total_events=len(scenario.events),
                processed_events=0,
                final_clock_ms=scenario.initial_clock_ms,
                limitations=["unsupported_protocol_version"],
            ),
            transitions=[],
            findings=[finding],
            final_task=None,
            assumptions=assumptions,
            claim="scenario_semantics_unknown",
        )

    machine = _Machine(scenario=scenario, clock_ms=scenario.initial_clock_ms)
    ordered = sorted(scenario.events, key=lambda item: (item.at_ms, item.sequence))
    for event in ordered:
        _apply_event(machine, event)
    if machine.status is None:
        _finding(
            machine,
            "MCPTASK001",
            FindingSeverity.HIGH,
            RequirementLevel.PROTOCOL_MUST,
            "Scenario never created a task",
            "No create event was successfully applied.",
            "Add one create event before task operations.",
            ordered[-1].sequence,
        )

    machine.findings.sort(
        key=lambda item: (
            item.event_sequences[0] if item.event_sequences else MAX_EVENTS + 1,
            item.rule_id,
            item.evidence,
        )
    )
    has_violation = any(item.severity != FindingSeverity.UNKNOWN for item in machine.findings)
    has_unknown = any(item.severity == FindingSeverity.UNKNOWN for item in machine.findings)
    verdict = "fail" if has_violation else "unknown" if has_unknown else "pass"
    claim = {
        "pass": "scenario_satisfies_supported_task_invariants",
        "fail": "scenario_violates_supported_task_invariants",
        "unknown": "scenario_semantics_unknown",
    }[verdict]
    coverage_state = "unknown" if verdict == "unknown" else "complete"
    limitations = ["experimental_extension", "offline_synthetic_fixture_only"]
    if has_unknown:
        limitations.append("ambiguous_or_unsupported_semantics")
    return TaskSimulationResult(
        scenario_schema_version=scenario.schema_version,
        scenario_id=scenario.scenario_id,
        scenario_digest_sha256=digest,
        protocol_version=scenario.protocol_version,
        verdict=verdict,  # type: ignore[arg-type]
        coverage=TaskCoverage(
            state=coverage_state,  # type: ignore[arg-type]
            input_state="valid",
            total_events=len(ordered),
            processed_events=len(ordered),
            final_clock_ms=machine.clock_ms,
            limitations=limitations,
        ),
        transitions=machine.transitions,
        findings=machine.findings,
        final_task=_final_task(machine),
        assumptions=assumptions,
        claim=claim,  # type: ignore[arg-type]
    )


def malformed_result(raw: bytes, reason: str) -> TaskSimulationResult:
    """Return a bounded structured UNKNOWN result for invalid scenario bytes."""

    return TaskSimulationResult(
        scenario_schema_version=None,
        scenario_id=None,
        scenario_digest_sha256=hashlib.sha256(raw).hexdigest(),
        protocol_version=None,
        verdict="unknown",
        coverage=TaskCoverage(
            state="incomplete",
            input_state="malformed",
            total_events=0,
            processed_events=0,
            final_clock_ms=0,
            limitations=[reason],
        ),
        transitions=[],
        findings=[
            TaskFinding(
                rule_id="MCPTASK000",
                severity=FindingSeverity.UNKNOWN,
                requirement_level=RequirementLevel.UNKNOWN,
                title="Malformed task scenario",
                evidence=reason,
                remediation="Validate against the scenario schema and retry with synthetic input.",
                event_sequences=[],
                assumptions=[],
            )
        ],
        final_task=None,
        assumptions=sorted(_STANDARD_ASSUMPTIONS),
        claim="scenario_semantics_unknown",
    )


def parse_scenario_bytes(raw: bytes) -> TaskScenario | TaskSimulationResult:
    """Strictly parse bounded JSON, rejecting duplicate object keys."""

    if len(raw) > MAX_INPUT_BYTES:
        return malformed_result(raw[: MAX_INPUT_BYTES + 1], "input_size_limit_exceeded")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non_finite_json_number")

    try:
        payload = json.loads(
            raw,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return malformed_result(raw, "invalid_strict_json")
    stack: list[tuple[Any, int]] = [(payload, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH:
            return malformed_result(raw, "json_depth_limit_exceeded")
        if nodes > MAX_JSON_NODES:
            return malformed_result(raw, "json_node_limit_exceeded")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
    try:
        return TaskScenario.model_validate(payload)
    except ValidationError:
        return malformed_result(raw, "scenario_schema_validation_failed")


def load_scenario_path(path: Path) -> TaskScenario | TaskSimulationResult:
    """Read one regular non-symlink fixture through a bounded descriptor."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TaskTimeMachineInputError("scenario_input_open_failed") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TaskTimeMachineInputError("scenario_input_not_regular_file")
        raw = os.read(descriptor, MAX_INPUT_BYTES + 1)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        expected_read = min(before.st_size, MAX_INPUT_BYTES + 1)
        if identity != after_identity or len(raw) != expected_read:
            raise TaskTimeMachineInputError("scenario_input_changed_during_read")
    finally:
        os.close(descriptor)
    return parse_scenario_bytes(raw)


def scan_scenario_path(path: Path) -> TaskSimulationResult:
    parsed = load_scenario_path(path)
    return parsed if isinstance(parsed, TaskSimulationResult) else simulate_scenario(parsed)


def result_json_bytes(result: TaskSimulationResult) -> bytes:
    return canonical_json_bytes(result)


def _scenario(
    scenario_id: str, description: str, events: list[dict[str, Any]], **overrides: Any
) -> TaskScenario:
    payload: dict[str, Any] = {
        "schema_version": "mcpaudit.task-time-machine.scenario.v1",
        "scenario_id": scenario_id,
        "description": description,
        "protocol_version": CURRENT_PROTOCOL_VERSION,
        "spec_profile": SPEC_PROFILE,
        "task_id": f"task-{scenario_id}",
        "initial_clock_ms": 0,
        "ttl_ms": 60_000,
        "poll_interval_ms": 1_000,
        "retry_policy": {
            "max_attempts": 3,
            "initial_backoff_ms": 1_000,
            "multiplier": 2,
            "max_backoff_ms": 8_000,
        },
        "expiry_policy": "unknown",
        "assumptions": [],
        "events": events,
    }
    payload.update(overrides)
    return TaskScenario.model_validate(payload)


def builtin_scenarios() -> dict[str, TaskScenario]:
    """Return fresh validated built-ins so callers cannot mutate shared state."""

    raw: dict[str, TaskScenario] = {
        "happy-path": _scenario(
            "happy-path",
            "Create, work, poll, and complete.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 10, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 1_000, "type": "poll"},
                {"event_id": "e4", "sequence": 4, "at_ms": 2_000, "type": "complete", "result": {"ok": True}},
                {"event_id": "e5", "sequence": 5, "at_ms": 2_000, "type": "poll", "observed_version": 2},
            ],
        ),
        "transient-retry": _scenario(
            "transient-retry",
            "Retry once after deterministic backoff.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 0, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 100, "type": "retryable_error"},
                {"event_id": "e4", "sequence": 4, "at_ms": 1_100, "type": "retry"},
                {"event_id": "e5", "sequence": 5, "at_ms": 2_000, "type": "complete", "result": {"ok": True}},
            ],
        ),
        "retry-exhaustion": _scenario(
            "retry-exhaustion",
            "Exhaust two local attempts and fail.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 0, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 10, "type": "retryable_error"},
                {"event_id": "e4", "sequence": 4, "at_ms": 1_010, "type": "retry"},
                {"event_id": "e5", "sequence": 5, "at_ms": 1_020, "type": "retryable_error"},
            ],
            retry_policy={
                "max_attempts": 2,
                "initial_backoff_ms": 1_000,
                "multiplier": 2,
                "max_backoff_ms": 8_000,
            },
        ),
        "poll-cadence": _scenario(
            "poll-cadence",
            "Flag a poll before pollIntervalMs.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1_000, "type": "poll"},
                {"event_id": "e3", "sequence": 3, "at_ms": 1_500, "type": "poll"},
            ],
        ),
        "cancel-before-start": _scenario(
            "cancel-before-start",
            "Honor cancellation before local work starts.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "cancel_requested"},
                {"event_id": "e3", "sequence": 3, "at_ms": 2, "type": "cancel_applied"},
            ],
        ),
        "cancel-during-work": _scenario(
            "cancel-during-work",
            "Honor cancellation during work.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 100, "type": "cancel_requested"},
                {"event_id": "e4", "sequence": 4, "at_ms": 200, "type": "cancel_applied"},
            ],
        ),
        "completion-vs-cancel-race": _scenario(
            "completion-vs-cancel-race",
            "Completion wins after cooperative cancellation intent.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 1_000, "type": "cancel_requested"},
                {
                    "event_id": "e4",
                    "sequence": 4,
                    "at_ms": 1_000,
                    "type": "complete",
                    "result": {"winner": "completion"},
                },
            ],
        ),
        "expiry": _scenario(
            "expiry",
            "Preserve UNKNOWN for discretionary expiry.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "work_started"},
                {"event_id": "e3", "sequence": 3, "at_ms": 5_000, "type": "expire"},
            ],
            ttl_ms=5_000,
            expiry_policy="unknown",
        ),
        "duplicate-events": _scenario(
            "duplicate-events",
            "Idempotently reject a duplicate event ID.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "work_started"},
                {"event_id": "e2", "sequence": 3, "at_ms": 2, "type": "work_started"},
            ],
        ),
        "stale-polling": _scenario(
            "stale-polling",
            "Flag a stale terminal poll.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1_000, "type": "complete", "result": {"ok": True}},
                {"event_id": "e3", "sequence": 3, "at_ms": 2_000, "type": "poll", "observed_version": 1},
            ],
        ),
        "input-required": _scenario(
            "input-required",
            "Round-trip input through eventual status update.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "work_started"},
                {
                    "event_id": "e3",
                    "sequence": 3,
                    "at_ms": 100,
                    "type": "input_required",
                    "request_key": "approval",
                },
                {
                    "event_id": "e4",
                    "sequence": 4,
                    "at_ms": 200,
                    "type": "input_submitted",
                    "request_key": "approval",
                },
                {"event_id": "e5", "sequence": 5, "at_ms": 300, "type": "resume_working"},
                {"event_id": "e6", "sequence": 6, "at_ms": 400, "type": "complete", "result": {"ok": True}},
            ],
        ),
        "forbidden-post-terminal": _scenario(
            "forbidden-post-terminal",
            "Reject completion followed by failure.",
            [
                {"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"},
                {"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "complete", "result": {"ok": True}},
                {
                    "event_id": "e3",
                    "sequence": 3,
                    "at_ms": 2,
                    "type": "fail",
                    "error": {"code": -32603, "message": "late failure", "data": None},
                },
            ],
        ),
    }
    return {name: scenario.model_copy(deep=True) for name, scenario in raw.items()}
