"""Deterministic, offline virtual transport for MCP session/resume faults."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Final, Literal

from pydantic import ValidationError

from mcp_audit.session_resume_models import (
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    AcceptRequestStep,
    CancelStep,
    CompleteRequestStep,
    DeliverEventStep,
    DeliveryClassification,
    DeliverySafety,
    DisconnectStep,
    DropEventStep,
    DuplicateEventStep,
    EmitEventStep,
    FindingRuleId,
    FindingSeverity,
    InitializeStep,
    ModeledAssumption,
    ProofState,
    ProtocolProfile,
    ReconnectStep,
    RejectStep,
    ReplayStep,
    ReportVerdict,
    RequirementLevel,
    RestartServerStep,
    RiskState,
    RotateSessionStep,
    ScenarioStep,
    SendRequestStep,
    SessionResumeFinding,
    SessionResumeReport,
    SessionResumeScenario,
    SessionResumeSuiteReport,
    SessionResumeTranscript,
    TerminateSessionStep,
    TranscriptEntry,
    TranscriptOutcome,
    canonical_json_bytes,
)

MCP_2025_11_TRANSPORT: Final = "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports"
MCP_2026_07_TRANSPORT: Final = (
    "https://github.com/modelcontextprotocol/modelcontextprotocol/blob/"
    "0cb6c6a31768cbb16129b35e6b569a31fecfe1b6/docs/specification/2026-07-28/"
    "basic/transports/streamable-http.mdx"
)
SSE_STANDARD: Final = "https://html.spec.whatwg.org/multipage/server-sent-events.html"
HTTP_SEMANTICS: Final = "https://www.rfc-editor.org/rfc/rfc9110.html"


class SessionResumeInputError(ValueError):
    """A bounded, sanitized input-contract failure."""


class _DuplicateKeyError(ValueError):
    pass


@dataclass
class _RequestState:
    successful_sends: int = 0
    accepted: int = 0
    completed: int = 0
    acceptance_ambiguous: bool = False
    completion_ambiguous: bool = False
    disconnected: bool = False
    canceled: bool = False
    reconnects: int = 0
    open_reconnects: int = 0
    step_ids: list[str] = field(default_factory=list)


@dataclass
class _EventState:
    request_id: str
    kind: str
    deliveries: int = 0
    dropped: bool = False
    drop_step_ids: list[str] = field(default_factory=list)
    replay_available: bool = True


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON object key")
        result[key] = value
    return result


def _json_depth(value: object, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_json_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_json_depth(item, depth + 1) for item in value), default=depth)
    return depth


def _parse_scenario_bytes(raw: bytes) -> SessionResumeScenario:
    if len(raw) > MAX_INPUT_BYTES:
        raise SessionResumeInputError(f"scenario exceeds {MAX_INPUT_BYTES} bytes")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKeyError, RecursionError) as exc:
        raise SessionResumeInputError("scenario is not valid bounded JSON") from exc
    if _json_depth(payload) > MAX_JSON_DEPTH:
        raise SessionResumeInputError(f"scenario exceeds {MAX_JSON_DEPTH} JSON levels")
    try:
        return SessionResumeScenario.model_validate(payload)
    except (ValidationError, RecursionError) as exc:
        raise SessionResumeInputError("scenario does not satisfy the strict v1 contract") from exc


def load_scenario_path(path: Path) -> SessionResumeScenario:
    """Read one regular, non-symlink scenario from a single descriptor."""

    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SessionResumeInputError("scenario path must be a regular non-symlink file")
        if metadata.st_size > MAX_INPUT_BYTES:
            raise SessionResumeInputError(f"scenario exceeds {MAX_INPUT_BYTES} bytes")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                metadata.st_dev,
                metadata.st_ino,
            ):
                raise SessionResumeInputError("scenario identity changed during bounded read")
            chunks: list[bytes] = []
            remaining = MAX_INPUT_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(descriptor)
            opened_identity = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            after_identity = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            if opened_identity != after_identity or len(raw) != opened.st_size:
                raise SessionResumeInputError("scenario identity changed during bounded read")
        finally:
            os.close(descriptor)
    except SessionResumeInputError:
        raise
    except OSError as exc:
        raise SessionResumeInputError("scenario could not be read safely") from exc
    return _parse_scenario_bytes(raw)


def load_builtin_scenarios() -> dict[str, SessionResumeScenario]:
    """Load the checked-in synthetic fixture corpus from package resources."""

    try:
        raw = resources.files("mcp_audit").joinpath("session_resume_scenarios_v1.json").read_bytes()
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, json.JSONDecodeError, _DuplicateKeyError, RecursionError) as exc:
        raise SessionResumeInputError("built-in scenario corpus is unavailable or malformed") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "scenarios"}:
        raise SessionResumeInputError("built-in scenario corpus has an invalid envelope")
    if payload["schema_version"] != "mcpaudit.session-resume.builtin-corpus.v1":
        raise SessionResumeInputError("built-in scenario corpus version is unsupported")
    scenarios = payload["scenarios"]
    if not isinstance(scenarios, list):
        raise SessionResumeInputError("built-in scenario corpus scenarios must be an array")
    result: dict[str, SessionResumeScenario] = {}
    try:
        for item in scenarios:
            scenario = SessionResumeScenario.model_validate(item)
            if scenario.scenario_id in result:
                raise SessionResumeInputError("built-in scenario IDs must be unique")
            result[scenario.scenario_id] = scenario
    except (ValidationError, RecursionError) as exc:
        raise SessionResumeInputError("built-in scenario violates the strict v1 contract") from exc
    return dict(sorted(result.items()))


class VirtualSessionTransport:
    """Replay one declarative scenario with isolated in-memory state."""

    def __init__(self, scenario: SessionResumeScenario) -> None:
        self.scenario = scenario
        self.sessions: set[str] = set()
        self.terminated_sessions: set[str] = set()
        self.requests: dict[str, _RequestState] = {}
        self.events: dict[str, _EventState] = {}
        self.entries: list[TranscriptEntry] = []
        self.findings: list[SessionResumeFinding] = []
        self._finding_keys: set[tuple[str, str, str, tuple[str, ...]]] = set()
        self._session_aliases: dict[str, str] = {}
        self.server_instance = "server-a"
        self._replay_gap = False

    @property
    def _legacy(self) -> bool:
        return self.scenario.protocol_version != ProtocolProfile.V2026_07_28

    def _request(self, request_id: str) -> _RequestState:
        state = self.requests.get(request_id)
        if state is None:
            state = _RequestState()
            self.requests[request_id] = state
        return state

    def _session_alias(self, session_id: str | None) -> str | None:
        """Return a deterministic report-local pseudonym for a bearer-like ID."""

        if session_id is None:
            return None
        alias = self._session_aliases.get(session_id)
        if alias is None:
            alias = f"session-ref-{len(self._session_aliases) + 1:03d}"
            self._session_aliases[session_id] = alias
        return alias

    def _entry(
        self,
        step: ScenarioStep,
        actor: Literal["client", "server", "link"],
        outcome: TranscriptOutcome,
        detail: str,
        *,
        request_id: str | None = None,
        session_id: str | None = None,
        event_id: str | None = None,
    ) -> None:
        self.entries.append(
            TranscriptEntry(
                order=len(self.entries) + 1,
                at_ms=step.at_ms,
                step_id=step.step_id,
                actor=actor,
                action=step.type,
                outcome=outcome,
                request_id=request_id,
                session_id=self._session_alias(session_id),
                event_id=event_id,
                detail=detail,
            )
        )

    def _finding(
        self,
        rule_id: FindingRuleId,
        severity: FindingSeverity,
        requirement_level: RequirementLevel,
        title: str,
        target: str,
        evidence: str,
        remediation: str,
        step_ids: list[str],
        references: list[str],
    ) -> None:
        key = (rule_id, title, target, tuple(step_ids))
        if key in self._finding_keys:
            return
        self._finding_keys.add(key)
        self.findings.append(
            SessionResumeFinding(
                rule_id=rule_id,
                severity=severity,
                requirement_level=requirement_level,
                title=title,
                target=target,
                evidence=evidence,
                remediation=remediation,
                step_ids=step_ids,
                references=references,
            )
        )

    def _unknown_transition(self, step: ScenarioStep, target: str, detail: str) -> None:
        self._finding(
            "MCPSR000",
            FindingSeverity.UNKNOWN,
            RequirementLevel.FIXTURE_POLICY,
            "Transition lacks enough modeled state",
            target,
            detail,
            "Add the missing synthetic state transition or mark the trace incomplete.",
            [step.step_id],
            [],
        )

    def _session_valid(self, session_id: str | None) -> bool:
        if self.scenario.server_policy.session_mode == "none":
            return session_id is None
        if session_id is None:
            return self.scenario.server_policy.session_mode == "optional"
        return session_id in self.sessions

    def run(self) -> SessionResumeReport:
        for step in self.scenario.steps:
            self._apply(step)
        safety = self._classify_safety()
        recovered_drop_step_ids = {
            step_id
            for event in self.events.values()
            if event.kind == "result" and event.dropped and event.deliveries > 0
            for step_id in event.drop_step_ids
        }
        findings = sorted(
            (
                item
                for item in self.findings
                if not (item.rule_id == "MCPSR006" and recovered_drop_step_ids.intersection(item.step_ids))
            ),
            key=lambda item: (item.step_ids[0] if item.step_ids else "", item.rule_id, item.target),
        )
        observed_delivery_risk = (
            safety.duplicate_risk == RiskState.OBSERVED or safety.lost_result_risk == RiskState.OBSERVED
        )
        verdict: ReportVerdict = (
            "risk"
            if observed_delivery_risk or any(item.severity != FindingSeverity.UNKNOWN for item in findings)
            else "pass"
        )
        if any(item.severity == FindingSeverity.UNKNOWN for item in findings) or (
            DeliveryClassification.UNKNOWN in safety.classifications
        ):
            verdict = "unknown" if verdict == "pass" else "risk"
        scenario_digest = hashlib.sha256(canonical_json_bytes(self.scenario)).hexdigest()
        return SessionResumeReport(
            scenario_id=self.scenario.scenario_id,
            scenario_digest_sha256=scenario_digest,
            protocol_version=self.scenario.protocol_version,
            verdict=verdict,
            trace_complete=self.scenario.trace_complete,
            safety=safety,
            findings=findings,
            transcript=SessionResumeTranscript(
                scenario_id=self.scenario.scenario_id,
                protocol_version=self.scenario.protocol_version,
                entries=self.entries,
            ),
            assumptions=self.scenario.assumptions,
        )

    def _apply(self, step: ScenarioStep) -> None:  # noqa: C901, PLR0912
        if isinstance(step, InitializeStep):
            if not self._legacy:
                self._entry(step, "client", "unsupported", "2026-07-28 removed initialization and sessions.")
                self._finding(
                    "MCPSR001",
                    FindingSeverity.HIGH,
                    RequirementLevel.UNSUPPORTED,
                    "Protocol profile does not support sessions",
                    self.scenario.scenario_id,
                    "The scenario attempts protocol-level initialization under MCP 2026-07-28.",
                    "Use a legacy profile for session faults or remove protocol-level session behavior.",
                    [step.step_id],
                    [MCP_2026_07_TRANSPORT],
                )
            else:
                if step.session_id is not None:
                    self.sessions.add(step.session_id)
                self._entry(
                    step,
                    "server",
                    "applied",
                    "Legacy initialization completed with synthetic session policy.",
                    session_id=step.session_id,
                )
            return

        if isinstance(step, SendRequestStep):
            request = self._request(step.request_id)
            request.step_ids.append(step.step_id)
            if not self._legacy and step.session_id is not None:
                self._entry(
                    step,
                    "client",
                    "unsupported",
                    "Current protocol profile forbids protocol-level session routing.",
                    request_id=step.request_id,
                    session_id=step.session_id,
                )
                self._finding(
                    "MCPSR001",
                    FindingSeverity.HIGH,
                    RequirementLevel.UNSUPPORTED,
                    "MCP-Session-Id is unsupported by this profile",
                    step.request_id,
                    "A 2026-07-28 request carries a modeled protocol session ID.",
                    "Remove the session header or select a legacy compatibility profile.",
                    [step.step_id],
                    [MCP_2026_07_TRANSPORT],
                )
            elif not self._session_valid(step.session_id):
                missing = step.session_id is None
                self._entry(
                    step,
                    "server",
                    "rejected",
                    "Required session ID is missing." if missing else "Session ID is unknown or terminated.",
                    request_id=step.request_id,
                    session_id=step.session_id,
                )
                self._finding(
                    "MCPSR002" if missing else "MCPSR003",
                    FindingSeverity.MEDIUM if missing else FindingSeverity.HIGH,
                    RequirementLevel.PROTOCOL_SHOULD if missing else RequirementLevel.PROTOCOL_MUST,
                    "Required session ID is missing" if missing else "Session ID is unavailable",
                    step.request_id,
                    "The virtual server cannot bind the request to an active legacy session.",
                    "Return 400 for a required missing session or 404 for a terminated/unknown "
                    "session, then reinitialize.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            else:
                request.successful_sends += 1
                self._entry(
                    step,
                    "client",
                    "applied",
                    "Request entered the virtual link; server acceptance is not implied.",
                    request_id=step.request_id,
                    session_id=step.session_id,
                )
            return

        if isinstance(step, AcceptRequestStep):
            request = self._request(step.request_id)
            if request.successful_sends == 0:
                self._unknown_transition(
                    step, step.request_id, "Server acceptance has no modeled client send."
                )
                self._entry(
                    step,
                    "server",
                    "ambiguous",
                    "Acceptance has no preceding send.",
                    request_id=step.request_id,
                )
            else:
                request.accepted += 1
                request.step_ids.append(step.step_id)
                self.server_instance = step.server_instance
                self._entry(
                    step,
                    "server",
                    "applied",
                    "Server accepted the synthetic operation; completion is not implied.",
                    request_id=step.request_id,
                )
            return

        if isinstance(step, CompleteRequestStep):
            request = self._request(step.request_id)
            if request.accepted == 0:
                self._unknown_transition(step, step.request_id, "Completion has no modeled acceptance.")
                self._entry(
                    step,
                    "server",
                    "ambiguous",
                    "Completion has no preceding acceptance.",
                    request_id=step.request_id,
                )
            else:
                request.completed += 1
                request.step_ids.append(step.step_id)
                self._entry(
                    step,
                    "server",
                    "applied",
                    "Synthetic operation completed; delivery is not implied.",
                    request_id=step.request_id,
                )
            return

        if isinstance(step, EmitEventStep):
            request = self._request(step.request_id)
            if step.event_id in self.events:
                self._unknown_transition(step, step.event_id, "SSE event ID is reused in the modeled stream.")
                self._entry(
                    step,
                    "server",
                    "rejected",
                    "Event ID reuse rejected.",
                    request_id=step.request_id,
                    event_id=step.event_id,
                )
            elif step.event_kind == "result" and request.completed == 0:
                self._unknown_transition(step, step.request_id, "Result event has no modeled completion.")
                self._entry(
                    step,
                    "server",
                    "ambiguous",
                    "Result event has no completion evidence.",
                    request_id=step.request_id,
                    event_id=step.event_id,
                )
            else:
                self.events[step.event_id] = _EventState(step.request_id, step.event_kind)
                self._entry(
                    step,
                    "server",
                    "applied",
                    "SSE event entered the virtual link.",
                    request_id=step.request_id,
                    event_id=step.event_id,
                )
            return

        if isinstance(step, DeliverEventStep):
            event = self.events.get(step.event_id)
            if event is None:
                self._unknown_transition(
                    step, step.event_id, "Delivery references an event that was not emitted."
                )
                self._entry(
                    step, "link", "ambiguous", "Unknown event cannot be delivered.", event_id=step.event_id
                )
            else:
                event.deliveries += 1
                self._entry(
                    step,
                    "link",
                    "applied",
                    "Event delivered to the virtual client.",
                    request_id=event.request_id,
                    event_id=step.event_id,
                )
            return

        if isinstance(step, DropEventStep):
            event = self.events.get(step.event_id)
            if event is None:
                self._unknown_transition(
                    step, step.event_id, "Drop references an event that was not emitted."
                )
                self._entry(
                    step, "link", "ambiguous", "Unknown event cannot be dropped.", event_id=step.event_id
                )
            else:
                event.dropped = True
                event.drop_step_ids.append(step.step_id)
                self._entry(
                    step,
                    "link",
                    "applied",
                    "Event dropped before client delivery.",
                    request_id=event.request_id,
                    event_id=step.event_id,
                )
                if event.kind == "result":
                    self._finding(
                        "MCPSR006",
                        FindingSeverity.HIGH,
                        RequirementLevel.DESIGN_INFERENCE,
                        "Completed result was lost in transit",
                        event.request_id,
                        "A modeled result event was emitted and dropped without delivery.",
                        "Persist replayable results or expose a bounded recovery/status mechanism.",
                        [step.step_id],
                        [MCP_2025_11_TRANSPORT, HTTP_SEMANTICS],
                    )
            return

        if isinstance(step, DuplicateEventStep):
            event = self.events.get(step.event_id)
            if event is None:
                self._unknown_transition(
                    step, step.event_id, "Duplication references an event that was not emitted."
                )
                self._entry(
                    step, "link", "ambiguous", "Unknown event cannot be duplicated.", event_id=step.event_id
                )
            else:
                event.deliveries += step.copies
                self._entry(
                    step,
                    "link",
                    "applied",
                    f"Event delivered {step.copies} duplicate copies.",
                    request_id=event.request_id,
                    event_id=step.event_id,
                )
                self._finding(
                    "MCPSR005",
                    FindingSeverity.HIGH,
                    RequirementLevel.DESIGN_INFERENCE,
                    "Duplicate delivery observed",
                    event.request_id,
                    "The same SSE event reached the virtual client more than once.",
                    "Deduplicate by durable event ID and bind the cursor to one originating stream.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT, SSE_STANDARD],
                )
            return

        if isinstance(step, DisconnectStep):
            request_id = step.request_id
            outcome: TranscriptOutcome = "applied"
            if request_id is not None:
                disconnected_request = self._request(request_id)
                disconnected_request.disconnected = True
                disconnected_request.step_ids.append(step.step_id)
                if step.phase == "before_acceptance":
                    disconnected_request.acceptance_ambiguous = True
                    outcome = "ambiguous"
                    self._finding(
                        "MCPSR000",
                        FindingSeverity.UNKNOWN,
                        RequirementLevel.DESIGN_INFERENCE,
                        "Acceptance outcome is ambiguous",
                        request_id,
                        "The link disconnected after send but before observable server acceptance.",
                        "Require an idempotency key or an authoritative status/recovery surface "
                        "before retrying.",
                        [step.step_id],
                        [HTTP_SEMANTICS],
                    )
                elif step.phase == "after_acceptance_before_response":
                    disconnected_request.completion_ambiguous = True
                    outcome = "ambiguous"
                    self._finding(
                        "MCPSR006",
                        FindingSeverity.UNKNOWN,
                        RequirementLevel.DESIGN_INFERENCE,
                        "Accepted operation has no delivered outcome",
                        request_id,
                        "The request was accepted before disconnection, but no response was observed.",
                        "Resume by event cursor or query authoritative operation state; blind retry "
                        "can duplicate work.",
                        [step.step_id],
                        [MCP_2025_11_TRANSPORT, HTTP_SEMANTICS],
                    )
            self._entry(
                step, "link", outcome, f"Connection interrupted at {step.phase}.", request_id=request_id
            )
            return

        if isinstance(step, ReconnectStep):
            request = self._request(step.request_id)
            request.reconnects += 1
            request.open_reconnects += 1
            request.step_ids.append(step.step_id)
            if not self._legacy:
                self._entry(
                    step,
                    "client",
                    "unsupported",
                    "Last-Event-ID resumption is not supported in 2026-07-28.",
                    request_id=step.request_id,
                    session_id=step.session_id,
                    event_id=step.last_event_id,
                )
                self._finding(
                    "MCPSR001",
                    FindingSeverity.HIGH,
                    RequirementLevel.UNSUPPORTED,
                    "Resumption is unsupported by this protocol profile",
                    step.request_id,
                    "The scenario attempts GET/Last-Event-ID behavior removed in MCP 2026-07-28.",
                    "Use request-scoped recovery semantics or a legacy compatibility adapter.",
                    [step.step_id],
                    [MCP_2026_07_TRANSPORT],
                )
                return
            if request.open_reconnects > 1:
                self._finding(
                    "MCPSR007",
                    FindingSeverity.HIGH,
                    RequirementLevel.DESIGN_INFERENCE,
                    "Concurrent reconnects are not serialized",
                    step.request_id,
                    "More than one reconnect is open for the same interrupted stream.",
                    "Elect one reconnect owner or make replay consumption idempotent and single-writer.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            if step.attempt > self.scenario.server_policy.retry_limit:
                self._finding(
                    "MCPSR007",
                    FindingSeverity.MEDIUM,
                    RequirementLevel.FIXTURE_POLICY,
                    "Reconnect retry bound exceeded",
                    step.request_id,
                    f"Reconnect attempt {step.attempt} exceeds the fixture limit "
                    f"{self.scenario.server_policy.retry_limit}.",
                    "Stop at the declared bound and surface an actionable UNKNOWN outcome.",
                    [step.step_id],
                    [],
                )
            if not self._session_valid(step.session_id):
                self._finding(
                    "MCPSR003" if step.session_id is not None else "MCPSR002",
                    FindingSeverity.HIGH,
                    RequirementLevel.PROTOCOL_MUST,
                    "Reconnect session is unavailable",
                    step.request_id,
                    "The reconnect cannot bind to an active legacy session.",
                    "Treat 404 as session loss and initialize a new session without assuming replay "
                    "continuity.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            if self.scenario.server_policy.replay_mode == "unsupported":
                self._finding(
                    "MCPSR004",
                    FindingSeverity.UNKNOWN,
                    RequirementLevel.PROTOCOL_MAY,
                    "Server does not provide replay",
                    step.request_id,
                    "The legacy profile permits resumability but the modeled server does not implement it.",
                    "Surface lost-result risk and avoid assuming Last-Event-ID is honored.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            if step.last_event_id is not None and step.last_event_id not in self.events:
                self._finding(
                    "MCPSR004",
                    FindingSeverity.UNKNOWN,
                    RequirementLevel.DESIGN_INFERENCE,
                    "Last-Event-ID is stale or unknown",
                    step.request_id,
                    "The supplied cursor is absent from the modeled replay log.",
                    "Define a fail-closed stale-cursor response and an authoritative full-recovery path.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT, SSE_STANDARD],
                )
            self._entry(
                step,
                "client",
                "applied",
                "Reconnect opened against the modeled legacy stream.",
                request_id=step.request_id,
                session_id=step.session_id,
                event_id=step.last_event_id,
            )
            return

        if isinstance(step, ReplayStep):
            request = self._request(step.request_id)
            if request.open_reconnects == 0:
                self._unknown_transition(step, step.request_id, "Replay has no open reconnect.")
            gap_ids: list[str] = []
            for event_id in step.event_ids:
                event = self.events.get(event_id)
                if event is None or not event.replay_available or event.request_id != step.request_id:
                    gap_ids.append(event_id)
                    continue
                if event.deliveries > 0:
                    self._finding(
                        "MCPSR005",
                        FindingSeverity.HIGH,
                        RequirementLevel.DESIGN_INFERENCE,
                        "Replay redelivered an already observed event",
                        step.request_id,
                        "The modeled replay duplicates an event already delivered to the client.",
                        "Bind replay to the acknowledged cursor and deduplicate durable event IDs.",
                        [step.step_id],
                        [MCP_2025_11_TRANSPORT],
                    )
                event.deliveries += 1
            if gap_ids:
                self._replay_gap = True
                self._finding(
                    "MCPSR004",
                    FindingSeverity.HIGH,
                    RequirementLevel.DESIGN_INFERENCE,
                    "Replay log has a gap",
                    step.request_id,
                    f"Replay could not supply {len(gap_ids)} requested event(s).",
                    "Retain a bounded contiguous replay log or expose a terminal recovery response.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            request.open_reconnects = 0
            self._entry(
                step,
                "server",
                "applied" if not gap_ids else "ambiguous",
                f"Replay processed {len(step.event_ids)} event ID(s).",
                request_id=step.request_id,
            )
            return

        if isinstance(step, TerminateSessionStep):
            self.sessions.discard(step.session_id)
            self.terminated_sessions.add(step.session_id)
            self._entry(
                step,
                "server" if step.reason != "client_delete" else "client",
                "applied",
                f"Legacy session ended by {step.reason}.",
                session_id=step.session_id,
            )
            return

        if isinstance(step, RestartServerStep):
            self.server_instance = step.new_instance
            if not step.preserves_sessions:
                self.terminated_sessions.update(self.sessions)
                self.sessions.clear()
            if not step.preserves_replay_log:
                for event in self.events.values():
                    event.replay_available = False
            self._entry(
                step,
                "server",
                "applied",
                "Virtual server instance restarted with declared persistence behavior.",
            )
            self._finding(
                "MCPSR009",
                FindingSeverity.UNKNOWN,
                RequirementLevel.DESIGN_INFERENCE,
                "Restart persistence is implementation-defined",
                self.scenario.scenario_id,
                "The MCP legacy transport does not define session or replay-log durability across restart.",
                "Document and test the adapter's persistence and invalidation contract.",
                [step.step_id],
                [MCP_2025_11_TRANSPORT],
            )
            return

        if isinstance(step, RotateSessionStep):
            self.sessions.discard(step.old_session_id)
            self.terminated_sessions.add(step.old_session_id)
            self.sessions.add(step.new_session_id)
            self._entry(
                step,
                "server",
                "applied" if step.migration_declared else "ambiguous",
                "Virtual session identifier rotated.",
                session_id=step.new_session_id,
            )
            if not step.migration_declared:
                self._finding(
                    "MCPSR009",
                    FindingSeverity.UNKNOWN,
                    RequirementLevel.DESIGN_INFERENCE,
                    "Session rotation has no protocol contract",
                    self._session_alias(step.old_session_id) or "session-ref-redacted",
                    "The fixture rotates a legacy session without a declared migration mapping.",
                    "Expose an explicit adapter-level migration contract or force clean reinitialization.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT],
                )
            return

        if isinstance(step, CancelStep):
            request = self._request(step.request_id)
            request.canceled = True
            expected = "notification" if self._legacy else "transport_close"
            cancel_outcome: TranscriptOutcome = (
                "applied" if step.mode == expected and not request.disconnected else "ambiguous"
            )
            self._entry(
                step,
                "client",
                cancel_outcome,
                f"Cancellation attempted via {step.mode}.",
                request_id=step.request_id,
            )
            if request.disconnected or step.mode != expected:
                self._finding(
                    "MCPSR008",
                    FindingSeverity.UNKNOWN,
                    RequirementLevel.PROTOCOL_SHOULD if self._legacy else RequirementLevel.PROTOCOL_MUST,
                    "Cancellation outcome after disconnect is ambiguous",
                    step.request_id,
                    "The cancellation path cannot prove that the interrupted server operation stopped.",
                    "Use the version-correct cancellation path and expose authoritative "
                    "completion/cancellation state.",
                    [step.step_id],
                    [MCP_2025_11_TRANSPORT if self._legacy else MCP_2026_07_TRANSPORT],
                )
            return

        if isinstance(step, RejectStep):
            self._entry(
                step, "server", "rejected", f"HTTP {step.status}: {step.reason}", request_id=step.request_id
            )
            return

        raise AssertionError(f"unhandled step type: {type(step).__name__}")

    def _classify_safety(self) -> DeliverySafety:
        requests = list(self.requests.values())
        events = list(self.events.values())
        acceptance_ambiguous = any(item.acceptance_ambiguous for item in requests)
        reconnects = sum(item.reconnects for item in requests)
        result_deliveries_by_request = {request_id: 0 for request_id in self.requests}
        for event in events:
            if event.kind == "result":
                result_deliveries_by_request[event.request_id] = (
                    result_deliveries_by_request.get(event.request_id, 0) + event.deliveries
                )
        duplicate_observed = (
            any(item.accepted > 1 or item.completed > 1 for item in requests)
            or any(item.deliveries > 1 for item in events)
            or any(deliveries > 1 for deliveries in result_deliveries_by_request.values())
        )
        duplicate_unknown = acceptance_ambiguous or (
            reconnects > 0 and self.scenario.server_policy.duplicate_suppression == "unknown"
        )
        completed = sum(item.completed for item in requests)
        accepted = sum(item.accepted for item in requests)
        delivered_results = sum(item.deliveries for item in events if item.kind == "result")
        incomplete = not self.scenario.trace_complete
        accepted_request_ids = {
            request_id for request_id, request in self.requests.items() if request.accepted > 0
        }
        accepted_without_completion = {
            request_id for request_id in accepted_request_ids if self.requests[request_id].completed == 0
        }
        completion_unknown_requests = {
            request_id
            for request_id in accepted_without_completion
            if incomplete or self.requests[request_id].completion_ambiguous
        }
        completion_missing_requests = accepted_without_completion - completion_unknown_requests
        dropped_result = any(
            item.kind == "result" and item.dropped and item.deliveries == 0 for item in events
        )
        missing_result_requests = {
            request_id
            for request_id, request in self.requests.items()
            if request.completed > 0 and result_deliveries_by_request.get(request_id, 0) == 0
        }
        lost_observed = (
            bool(missing_result_requests)
            or bool(completion_missing_requests)
            or dropped_result
            or self._replay_gap
        )
        lost_unknown = not lost_observed and (incomplete or bool(completion_unknown_requests))

        if duplicate_observed:
            at_most_once = ProofState.CONTRADICTED
        elif duplicate_unknown:
            at_most_once = ProofState.UNKNOWN
        else:
            at_most_once = ProofState.SUPPORTED

        if accepted_request_ids and not accepted_without_completion:
            at_least_once = ProofState.SUPPORTED
        elif completion_missing_requests:
            at_least_once = ProofState.CONTRADICTED
        elif accepted_without_completion or incomplete or acceptance_ambiguous:
            at_least_once = ProofState.UNKNOWN
        else:
            at_least_once = ProofState.CONTRADICTED

        duplicate_risk = (
            RiskState.OBSERVED
            if duplicate_observed
            else RiskState.UNKNOWN
            if duplicate_unknown
            else RiskState.NOT_OBSERVED
        )
        lost_result_risk = (
            RiskState.OBSERVED
            if lost_observed
            else RiskState.UNKNOWN
            if lost_unknown
            else RiskState.NOT_OBSERVED
        )

        classifications: list[DeliveryClassification] = []
        if at_most_once == ProofState.SUPPORTED:
            classifications.append(DeliveryClassification.AT_MOST_ONCE)
        if at_least_once == ProofState.SUPPORTED:
            classifications.append(DeliveryClassification.AT_LEAST_ONCE)
        if duplicate_risk == RiskState.OBSERVED:
            classifications.append(DeliveryClassification.DUPLICATE_RISK)
        if lost_result_risk == RiskState.OBSERVED:
            classifications.append(DeliveryClassification.LOST_RESULT_RISK)
        if (
            at_most_once == ProofState.UNKNOWN
            or at_least_once == ProofState.UNKNOWN
            or duplicate_risk == RiskState.UNKNOWN
            or lost_result_risk == RiskState.UNKNOWN
        ):
            classifications.append(DeliveryClassification.UNKNOWN)
        return DeliverySafety(
            at_most_once=at_most_once,
            at_least_once=at_least_once,
            duplicate_risk=duplicate_risk,
            lost_result_risk=lost_result_risk,
            classifications=classifications,
            rationale=[
                f"modeled requests accepted={accepted}, completed={completed}",
                f"modeled result deliveries={delivered_results}, reconnects={reconnects}",
                f"accepted requests without completion={len(accepted_without_completion)}",
                f"completed requests without a result delivery={len(missing_result_requests)}",
                "Exactly-once is never inferred from these local observations.",
            ],
        )


def run_scenario(scenario: SessionResumeScenario) -> SessionResumeReport:
    """Run one scenario with fresh, non-shared virtual state."""

    return VirtualSessionTransport(scenario).run()


def run_builtin_suite() -> SessionResumeSuiteReport:
    reports = [run_scenario(scenario) for scenario in load_builtin_scenarios().values()]
    return SessionResumeSuiteReport(
        reports=reports,
        scenario_count=len(reports),
        risk_count=sum(item.verdict == "risk" for item in reports),
        unknown_count=sum(item.verdict == "unknown" for item in reports),
    )


def report_json_bytes(report: SessionResumeReport | SessionResumeSuiteReport) -> bytes:
    return canonical_json_bytes(report)


def scenario_json_bytes(scenario: SessionResumeScenario) -> bytes:
    return canonical_json_bytes(scenario)


def builtin_assumption_summary(scenarios: dict[str, SessionResumeScenario]) -> list[ModeledAssumption]:
    """Return unique provenance rows for user-facing list/debug surfaces."""

    unique: dict[str, ModeledAssumption] = {}
    for scenario in scenarios.values():
        for assumption in scenario.assumptions:
            unique.setdefault(assumption.assumption_id, assumption)
    return [unique[key] for key in sorted(unique)]
