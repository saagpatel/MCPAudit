"""Offline scanner and output projections for AG-UI interrupt fixtures."""

from __future__ import annotations

import json
import math
import os
import re
import stat
from decimal import Decimal
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from mcp_audit.agui_interrupt_models import (
    AGUI_CONTRACT_ID,
    AGUI_CORE_VERSION,
    TRANSCRIPT_RECORD_ADAPTER,
    AGUIFinding,
    AGUIInterruptReport,
    AGUISeverity,
    EventRecord,
    FindingKind,
    FixtureManifest,
    InterruptOutcome,
    ManifestEnvelope,
    ReducerSummary,
    RunFinishedEvent,
    TranscriptRecord,
    canonical_json_bytes,
    sha256_bytes,
)
from mcp_audit.agui_interrupt_reducer import (
    reduce_transcript,
    summarize_state,
    unknown_finding,
)

_MAX_INPUT_BYTES = 4_194_304
_MAX_LINE_BYTES = 262_144
_MAX_RECORDS = 5_000
_MAX_INTERRUPTS = 4_096
_MAX_JSON_DEPTH = 24
_MAX_JSON_NODES = 50_000
_MAX_STRING_BYTES = 8_192
_MAX_STATE_BYTES = 1_048_576
_CREDENTIAL_BYTES = re.compile(
    rb"(?i)(authorization|access[_-]?token|api[_-]?key|client[_-]?secret|password|"
    rb"private[_-]?key|cookie|bearer[ \t]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    rb"\bsk-[A-Za-z0-9_-]{12,}|\bgh[pousr]_[A-Za-z0-9]{12,}|\bAKIA[A-Z0-9]{12,})"
)
_CREDENTIAL_KEY = re.compile(
    r"(?i)^(authorization|access[_-]?token|api[_-]?key|client[_-]?secret|password|"
    r"private[_-]?key|cookie)$"
)
_CREDENTIAL_TEXT = re.compile(
    r"(?i)(authorization|access[_-]?token|api[_-]?key|client[_-]?secret|password|"
    r"private[_-]?key|cookie|bearer[ \t]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bsk-[A-Za-z0-9_-]{12,}|\bgh[pousr]_[A-Za-z0-9]{12,}|\bAKIA[A-Z0-9]{12,})"
)

_ASSUMPTIONS = [
    "File order is the observed delivery order; streamId is a program-owned transport projection "
    "that binds events without threadId/runId to their RUN_STARTED stream.",
    "A resume starts a new run on the same thread. parentRunId remains orthogonal to interrupt linkage, "
    "as required by the pinned AG-UI draft.",
    "required_boundary_events is a program-owned sidecar declaring which state/message snapshots the "
    "specific interrupted workflow needs for observable recovery.",
]
_SUPPORTED_INPUTS = [
    "Program-owned JSONL using mcpaudit.ag-ui-interrupt.fixture.v1.",
    "Pinned AG-UI interrupt projections for RunAgentInput.resume, RUN_STARTED, RUN_FINISHED, RUN_ERROR, "
    "STATE_SNAPSHOT, MESSAGES_SNAPSHOT, STATE_DELTA, and ToolCall start/args/end/result events.",
    "Bounded JSON Schema response contracts using type, object properties/required/additionalProperties, "
    "array items/bounds, scalar bounds, enum, and const.",
]
_UNSUPPORTED_INPUTS = [
    "Live agents, browsers, workflow/framework runtimes, network streams, private transcripts, logs, "
    "credentials, user content, or production traces.",
    "Framework checkpoints, durable recovery internals, transport retries without a complete observable "
    "run outcome, and JSON Schema constructs outside the documented bounded profile.",
    "Claims about UI quality, human consent, authorization effectiveness, workflow durability, or "
    "end-to-end agent safety.",
]
_CLAIM_CEILING = [
    "The report states only whether the provided synthetic event/resume transcript satisfies the "
    "implemented observable interrupt state-machine invariants.",
    "A passing report does not prove framework-internal correctness, transport delivery, user intent, "
    "authorization enforcement, durable recovery, tool side effects, or production safety.",
    "Malformed, incomplete, unsupported, or unverifiable transcript coverage remains UNKNOWN.",
]


class AGUIInterruptInputError(ValueError):
    """Raised for an unsafe input artifact or unsafe filesystem boundary."""


class _DuplicateKeyError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON object key")
        result[key] = value
    return result


def _load_json(line: bytes) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value} is unsupported")

    def exact_float(value: str) -> float:
        try:
            decimal_value = Decimal(value)
            float_value = float(decimal_value)
            if not math.isfinite(float_value) or Decimal.from_float(float_value) != decimal_value:
                raise ValueError("JSON decimal is outside the exact binary64 profile")
            return float_value
        except ArithmeticError as exc:
            raise ValueError("JSON decimal is outside the exact binary64 profile") from exc

    return json.loads(
        line.decode("utf-8"),
        object_pairs_hook=_no_duplicate_keys,
        parse_constant=reject_constant,
        parse_float=exact_float,
    )


def _read_fixture_bytes(path: Path) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AGUIInterruptInputError(f"cannot inspect input fixture: {path}") from exc
    if not stat.S_ISREG(before.st_mode):
        raise AGUIInterruptInputError("input fixture must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AGUIInterruptInputError("input fixture must be a regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AGUIInterruptInputError("input fixture must be a regular non-symlink file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AGUIInterruptInputError("input fixture changed while it was being opened")
        if opened.st_size > _MAX_INPUT_BYTES:
            raise AGUIInterruptInputError(f"input fixture exceeds {_MAX_INPUT_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = _MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _MAX_INPUT_BYTES:
            raise AGUIInterruptInputError(f"input fixture exceeds {_MAX_INPUT_BYTES} bytes")
        return raw, (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)


def _validate_safe_content(raw: bytes) -> None:
    if _CREDENTIAL_BYTES.search(raw):
        raise AGUIInterruptInputError("fixture rejected: credential-like content is not accepted")


def _bound_json(value: Any, *, state_counter: list[int] | None = None) -> None:
    budget = [_MAX_JSON_NODES]

    def walk(item: Any, depth: int) -> None:
        budget[0] -= 1
        if budget[0] < 0:
            raise ValueError("JSON node limit exceeded")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON nesting limit exceeded")
        if isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_STRING_BYTES:
                raise ValueError("JSON string limit exceeded")
            if _CREDENTIAL_TEXT.search(item):
                raise AGUIInterruptInputError("fixture rejected: credential-like content is not accepted")
            return
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON number is unsupported")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object key must be a string")
                if _CREDENTIAL_KEY.fullmatch(key):
                    raise AGUIInterruptInputError("fixture rejected: credential-like content is not accepted")
                walk(key, depth + 1)
                walk(child, depth + 1)
            return
        if isinstance(item, list):
            if len(item) > 1_024:
                raise ValueError("JSON array limit exceeded")
            for child in item:
                walk(child, depth + 1)

    walk(value, 0)
    if state_counter is not None:
        state_counter[0] += len(
            json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        )
        if state_counter[0] > _MAX_STATE_BYTES:
            raise ValueError("aggregate state/message snapshot limit exceeded")


def _validation_location(exc: ValidationError) -> str:
    locations = sorted(
        {
            ".".join(str(part) for part in item["loc"])
            for item in exc.errors(include_url=False, include_input=False)
        }
    )
    return f"strict contract validation failed at {','.join(locations[:8]) or 'root'}"


def _empty_summary() -> ReducerSummary:
    return ReducerSummary(
        open_count=0,
        resolved_count=0,
        cancelled_count=0,
        superseded_count=0,
        expired_count=0,
        interrupts=[],
    )


def _ordered_findings(findings: tuple[AGUIFinding, ...] | list[AGUIFinding]) -> list[AGUIFinding]:
    unique: dict[tuple[str, str, str, int | None, tuple[str, ...]], AGUIFinding] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.kind.value,
            finding.target,
            finding.sequence,
            tuple(finding.evidence),
        )
        unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda item: (
            0 if item.severity is AGUISeverity.HIGH else 1,
            item.rule_id,
            item.sequence if item.sequence is not None else 1_000_001,
            item.kind.value,
            item.target,
            item.evidence,
        ),
    )


def _verdict(findings: list[AGUIFinding]) -> str:
    if any(item.severity is AGUISeverity.HIGH for item in findings):
        return "fail"
    if findings:
        return "unknown"
    return "pass"


def _report(
    *,
    fixture_id: str,
    digest: str,
    protocol: str,
    protocol_version: str,
    complete: bool,
    findings: tuple[AGUIFinding, ...] | list[AGUIFinding],
    state: ReducerSummary,
) -> AGUIInterruptReport:
    ordered = _ordered_findings(findings)
    return AGUIInterruptReport(
        fixture_id=fixture_id,
        input_sha256=digest,
        protocol=protocol,  # type: ignore[arg-type]
        protocol_version=protocol_version,
        contract_id=AGUI_CONTRACT_ID,
        complete=complete,
        verdict=_verdict(ordered),  # type: ignore[arg-type]
        findings=ordered,
        state=state,
        assumptions=_ASSUMPTIONS,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def _unknown_report(digest: str, evidence: str, *, fixture_id: str = "unknown") -> AGUIInterruptReport:
    return _report(
        fixture_id=fixture_id,
        digest=digest,
        protocol="unknown",
        protocol_version="unknown",
        complete=False,
        findings=[unknown_finding(FindingKind.MALFORMED_TRANSCRIPT, evidence)],
        state=_empty_summary(),
    )


def _parse_manifest(line: bytes) -> tuple[FixtureManifest | None, str, str | None]:
    try:
        payload = _load_json(line)
        _bound_json(payload)
    except AGUIInterruptInputError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        return None, "unknown", f"manifest JSON is invalid: {type(exc).__name__}"
    fixture_id = "unknown"
    if isinstance(payload, dict):
        fixture = payload.get("fixture")
        if isinstance(fixture, dict) and isinstance(fixture.get("fixture_id"), str):
            fixture_id = fixture["fixture_id"]
    try:
        envelope = ManifestEnvelope.model_validate(payload, strict=True)
    except ValidationError as exc:
        return None, fixture_id, _validation_location(exc)
    return envelope.fixture, envelope.fixture.fixture_id, None


def _parse_records(
    lines: list[bytes],
) -> tuple[tuple[TranscriptRecord, ...], tuple[AGUIFinding, ...]]:
    records: list[TranscriptRecord] = []
    findings: list[AGUIFinding] = []
    prior_sequence = 0
    prior_timestamp = None
    state_bytes = [0]
    interrupt_count = 0
    for line_number, line in enumerate(lines, start=2):
        if not line.strip():
            findings.append(
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "blank JSONL record",
                    sequence=line_number - 1,
                )
            )
            continue
        if len(line) > _MAX_LINE_BYTES:
            findings.append(
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "JSONL record exceeds the per-line byte limit",
                    sequence=line_number - 1,
                )
            )
            continue
        try:
            payload = _load_json(line)
            _bound_json(payload)
            record = TRANSCRIPT_RECORD_ADAPTER.validate_python(payload, strict=True)
            if (
                isinstance(record, EventRecord)
                and isinstance(record.event, RunFinishedEvent)
                and isinstance(record.event.outcome, InterruptOutcome)
            ):
                interrupt_count += len(record.event.outcome.interrupts)
                if interrupt_count > _MAX_INTERRUPTS:
                    raise AGUIInterruptInputError(
                        f"transcript exceeds the {_MAX_INTERRUPTS}-interrupt aggregate limit"
                    )
            if isinstance(record, EventRecord) and record.event.type in {
                "STATE_SNAPSHOT",
                "MESSAGES_SNAPSHOT",
                "STATE_DELTA",
            }:
                _bound_json(record.event.model_dump(mode="json", by_alias=True), state_counter=state_bytes)
        except AGUIInterruptInputError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            findings.append(
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    f"record contract is invalid: {type(exc).__name__}",
                    sequence=line_number - 1,
                )
            )
            continue
        if record.sequence <= prior_sequence:
            findings.append(
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "record sequences must be strictly increasing",
                    sequence=record.sequence,
                )
            )
        if prior_timestamp is not None and record.timestamp < prior_timestamp:
            findings.append(
                unknown_finding(
                    FindingKind.MALFORMED_TRANSCRIPT,
                    "record timestamps must be nondecreasing",
                    sequence=record.sequence,
                )
            )
        prior_sequence = max(prior_sequence, record.sequence)
        prior_timestamp = max(prior_timestamp, record.timestamp) if prior_timestamp else record.timestamp
        records.append(record)
    return tuple(records), tuple(findings)


def scan_agui_interrupt_path(path: Path) -> AGUIInterruptReport:
    report, _ = scan_agui_interrupt_path_with_identity(path)
    return report


def scan_agui_interrupt_path_with_identity(
    path: Path,
) -> tuple[AGUIInterruptReport, tuple[int, int]]:
    if path.suffix != ".jsonl":
        raise AGUIInterruptInputError("input fixture must be an explicit .jsonl synthetic transcript")
    raw, identity = _read_fixture_bytes(path)
    _validate_safe_content(raw)
    digest = sha256_bytes(raw)
    lines = raw.splitlines()
    if not lines:
        return _unknown_report(digest, "transcript fixture is empty"), identity
    if len(lines) - 1 > _MAX_RECORDS:
        raise AGUIInterruptInputError(f"transcript exceeds the {_MAX_RECORDS}-record limit")
    manifest, fixture_id, error = _parse_manifest(lines[0])
    if manifest is None:
        report = _unknown_report(
            digest,
            error or "manifest contract is invalid",
            fixture_id=fixture_id,
        )
        return report, identity
    records, initial_findings = _parse_records(lines[1:])
    state = reduce_transcript(manifest, records, initial_findings)
    effective_complete = manifest.complete and not any(
        finding.severity is AGUISeverity.UNKNOWN for finding in state.findings
    )
    return (
        _report(
            fixture_id=manifest.fixture_id,
            digest=digest,
            protocol="ag-ui",
            protocol_version=AGUI_CORE_VERSION,
            complete=effective_complete,
            findings=state.findings,
            state=summarize_state(state),
        ),
        identity,
    )


def report_json_bytes(report: AGUIInterruptReport) -> bytes:
    return canonical_json_bytes(report)


_SARIF_RULES: dict[str, tuple[str, str]] = {
    "AGUI000": ("TranscriptCoverageUnknown", "Malformed, incomplete, or unsupported transcript coverage."),
    "AGUI001": ("ResumeBinding", "Resume thread or source-interrupt binding is invalid."),
    "AGUI002": ("ResumeResponseSet", "Resume responses do not exactly cover the open interrupt set."),
    "AGUI003": ("ResumeContract", "Resume payload or tool-call identity violates its contract."),
    "AGUI004": ("InterruptBoundaryState", "Required interrupt-boundary state is missing or misordered."),
    "AGUI005": ("ResumeIdempotency", "An exact duplicate resume tuple was applied twice."),
    "AGUI006": ("InterruptLifecycle", "A stale or terminal interrupt was reopened."),
}


def render_sarif(report: AGUIInterruptReport) -> dict[str, Any]:
    rules = [
        {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": description},
            "help": {"text": description},
        }
        for rule_id, (name, description) in sorted(_SARIF_RULES.items())
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity is AGUISeverity.HIGH else "note",
            "message": {
                "text": f"{finding.title}: {finding.kind.value} at {finding.target}",
            },
            "properties": {
                "kind": finding.kind.value,
                "sequence": finding.sequence,
            },
        }
        for finding in report.findings
    ]
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPAudit AG-UI Interrupt Integrity Auditor",
                        "informationUri": "https://github.com/saagpatel/MCPAudit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_json_bytes(report: AGUIInterruptReport) -> bytes:
    return canonical_json_bytes(render_sarif(report))
