"""Deterministic offline analysis of paired A2UI return-path fixtures."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import ValidationError

from mcp_audit.a2ui_duplex_models import (
    A2UIDuplexFixture,
    A2UIDuplexReport,
    DuplexActionContract,
    DuplexFinding,
    DuplexStatistics,
    DuplexSurfaceDisclosureRule,
    DuplexTranscriptEnvelope,
    duplex_canonical_json_bytes,
    duplex_sha256_bytes,
)
from mcp_audit.agent_ui_scanner import (
    AgentUIInputError,
    _load_json,
    _read_fixture_bytes,
    _validate_json_nesting,
)

_MAX_ENVELOPES: Final = 512
_MAX_COMPONENTS: Final = 2_048
_MAX_GENERIC_NODES: Final = 20_000
_MAX_STRING_BYTES: Final = 16_384
_MAX_SCHEMA_DEPTH: Final = 16
_MAX_SCHEMA_NODES: Final = 512

_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"password|passwd|authorization|cookie|private[_-]?key|secret)(?:$|[_-])",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"^(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]+PRIVATE KEY-----)"
)
_PRIVATE_PATH_VALUE = re.compile(
    r"^(?:/Users/[^/]+/|/home/[^/]+/|[A-Za-z]:\\Users\\[^\\]+\\|file://)",
    re.IGNORECASE,
)

_SUPPORTED_SCHEMA_KEYWORDS = {
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "enum",
    "const",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
}

_SUPPORTED_INPUTS = [
    "One strict program-owned mcpaudit.a2ui-duplex.fixture.v1 JSON artifact.",
    "Paired A2UI v0.9 production-family or v1.0 candidate common surface/action/error envelopes.",
    "Synthetic web-core-react and flutter-a2ui producer profiles using explicit transcript sequence ids.",
]

_UNSUPPORTED_INPUTS = [
    "Live renderers, browsers, MCP connections, AG-UI streams, UI automation, user transcripts, "
    "and telemetry.",
    "A2UI v0.8, transport interoperability, inline catalog execution, function calls/responses, "
    "and action RPC.",
    "JavaScript or HTML safety, visual correctness, accessibility, consent, authorization, or "
    "renderer integrity.",
    "JSON Schema references, composition, conditionals, regex patterns, remote schemas, and "
    "executable validation.",
]

_ASSUMPTIONS = [
    "Transcript sequence ids are fixture-owned causal ordering evidence; input array order is not "
    "authoritative.",
    "Surface and component revisions are computed from the supplied server messages, not asserted "
    "by a renderer.",
    "Timestamps are compared only inside fixture-single-clock-v1 and never serve as replay identity.",
    "Action schemas and disclosure policies are explicit program-owned sidecars, not A2UI wire fields.",
]

_CLAIM_CEILING = [
    "A result covers only the supplied paired envelopes and the implemented observable duplex invariants.",
    "A passing result does not establish host consent, agent authorization, renderer integrity, protocol "
    "interoperability, AG-UI conformance, JavaScript or HTML safety, accessibility, or real-world "
    "resistance.",
    "Missing, malformed-but-parseable, unsupported, or uncorrelated evidence remains UNKNOWN or UNSUPPORTED.",
    "Payload values, returned data-model values, and error messages are never copied into findings or SARIF.",
]

_RULES: dict[str, tuple[str, str, str]] = {
    "MCPDUP001": (
        "high",
        "Returned surface or component revision does not resolve",
        "Bind the return to the active surface, source component, component revision, surface revision, and "
        "server message that actually emitted the action.",
    ),
    "MCPDUP002": (
        "high",
        "Returned action violates its component declaration or schema",
        "Return only an action declared by the source component and validate its resolved context "
        "and payload against the explicit program-owned contract.",
    ),
    "MCPDUP003": (
        "medium",
        "Return envelope is duplicate, replayed, stale, or causally impossible",
        "Use unique observable envelope/action identifiers and bind each return to an earlier "
        "active revision; do not reuse return identities.",
    ),
    "MCPDUP004": (
        "medium",
        "Client capability declaration disagrees with the used surface catalog",
        "Declare the active surface catalog in the client capability metadata before returning "
        "actions or errors.",
    ),
    "MCPDUP005": (
        "medium",
        "Renderer error is mismatched or unacknowledged",
        "Correlate each error to the real active surface, component, and server message, then "
        "include a later server acknowledgement in the paired transcript.",
    ),
    "MCPDUP006": (
        "high",
        "Returned full data model violates explicit disclosure policy",
        "Return a surface data model only when createSurface requested it and a program-owned "
        "disclosure rule explicitly allows the surface and returned top-level keys.",
    ),
}

_UNKNOWN_TITLE = "Duplex evidence is missing, malformed, or unsupported"
_UNKNOWN_REMEDIATION = (
    "Supply a supported program-owned paired fixture with explicit correlation, capability, "
    "revision, schema, and disclosure evidence for the invariant being evaluated."
)

_SEVERITY_ORDER = {"high": 0, "medium": 1, "unknown": 2}
_STATUS_ORDER = {"finding": 0, "unknown": 1, "unsupported": 2}


@dataclass
class _ComponentState:
    component_id: str
    revision: int
    last_message_id: str
    last_sequence: int
    last_observed_at: datetime
    action_declaration_supported: bool
    action_name: str | None
    context_keys: frozenset[str]


@dataclass
class _SurfaceState:
    surface_id: str
    revision: int
    catalog_id: str
    send_data_model: bool
    active: bool
    last_message_id: str
    last_sequence: int
    last_observed_at: datetime
    components: dict[str, _ComponentState] = field(default_factory=dict)


@dataclass(frozen=True)
class _ServerRecord:
    sequence: int
    surface_id: str
    kind: str
    component_ids: frozenset[str]
    observed_at: datetime


@dataclass
class _ScanCounts:
    server_messages: int = 0
    client_returns: int = 0
    actions: int = 0
    errors: int = 0
    data_model_returns: int = 0


@dataclass
class _SchemaBudget:
    nodes: int = 0


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise ValueError("timestamp must use UTC Z form")
    return parsed


def _validation_evidence(exc: ValidationError) -> str:
    error = exc.errors(include_input=False, include_url=False)[0]
    return f"fixture schema validation failed: {error.get('type', 'invalid')}"


def _generic_limits_and_credentials(value: Any) -> None:
    stack: list[tuple[Any, str | None]] = [(value, None)]
    nodes = 0
    components = 0
    while stack:
        current, parent_key = stack.pop()
        nodes += 1
        if nodes > _MAX_GENERIC_NODES:
            raise AgentUIInputError(f"fixture exceeds {_MAX_GENERIC_NODES} bounded JSON nodes")
        if isinstance(current, str):
            if len(current.encode("utf-8")) > _MAX_STRING_BYTES:
                raise AgentUIInputError(f"fixture string exceeds {_MAX_STRING_BYTES} bytes")
            if _SECRET_VALUE.search(current):
                raise AgentUIInputError("fixture contains a credential-looking value")
            if parent_key != "path" and _PRIVATE_PATH_VALUE.search(current):
                raise AgentUIInputError("fixture contains a private path-looking value")
        elif isinstance(current, Mapping):
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise AgentUIInputError("fixture object keys must be strings")
                if len(key.encode("utf-8")) > _MAX_STRING_BYTES:
                    raise AgentUIInputError(f"fixture string exceeds {_MAX_STRING_BYTES} bytes")
                if _SECRET_KEY.search(key):
                    raise AgentUIInputError("fixture contains a credential-looking field name")
                if key == "components" and isinstance(nested, list):
                    components += len(nested)
                    if components > _MAX_COMPONENTS:
                        raise AgentUIInputError(
                            f"fixture exceeds {_MAX_COMPONENTS} cumulative component definitions"
                        )
                stack.append((nested, key))
        elif isinstance(current, Sequence) and not isinstance(current, (bytes, bytearray)):
            stack.extend((item, parent_key) for item in current)


def _finding(
    rule_id: str,
    *,
    target: str,
    evidence: Iterable[str],
    observable_basis: Iterable[str],
) -> DuplexFinding:
    severity, title, remediation = _RULES[rule_id]
    return DuplexFinding(
        rule_id=rule_id,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        status="finding",
        title=title,
        target=target,
        evidence=sorted(set(evidence)),
        remediation=remediation,
        observable_basis=sorted(set(observable_basis)),
    )


def _unknown(
    *,
    target: str,
    evidence: str,
    status: str = "unknown",
) -> DuplexFinding:
    return DuplexFinding(
        rule_id="MCPDUP000",
        severity="unknown",
        status=status,  # type: ignore[arg-type]
        title=_UNKNOWN_TITLE,
        target=target,
        evidence=[evidence],
        remediation=_UNKNOWN_REMEDIATION,
        observable_basis=["Only supplied program-owned fixture fields were evaluated."],
    )


def _sort_findings(findings: list[DuplexFinding]) -> list[DuplexFinding]:
    unique: dict[tuple[str, str, str, tuple[str, ...]], DuplexFinding] = {}
    for item in findings:
        key = (item.rule_id, item.status, item.target, tuple(item.evidence))
        unique[key] = item
    return sorted(
        unique.values(),
        key=lambda item: (
            _SEVERITY_ORDER[item.severity],
            _STATUS_ORDER[item.status],
            item.rule_id,
            item.target,
            item.evidence,
        ),
    )


def _verdict(findings: list[DuplexFinding]) -> str:
    if any(item.status == "finding" for item in findings):
        return "fail"
    if findings:
        return "unknown"
    return "pass"


def _redacted_identifier(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _apply_redaction(report: A2UIDuplexReport) -> A2UIDuplexReport:
    redacted_findings = [
        item.model_copy(update={"target": _redacted_identifier("target", item.target)})
        for item in report.findings
    ]
    return report.model_copy(
        update={
            "fixture_id": _redacted_identifier("fixture", report.fixture_id),
            "producer_id": _redacted_identifier("producer", report.producer_id),
            "redacted": True,
            "findings": redacted_findings,
        }
    )


def _empty_statistics(envelopes: int = 0) -> DuplexStatistics:
    return DuplexStatistics(
        envelopes=envelopes,
        server_messages=0,
        client_returns=0,
        surfaces_observed=0,
        actions_observed=0,
        errors_observed=0,
        data_model_returns_observed=0,
    )


def _unknown_report(
    digest: str,
    evidence: str,
    *,
    fixture_id: str = "unknown",
    producer_id: str = "unknown",
    producer_profile: str = "unknown",
    protocol_version: str = "unknown",
    status: str = "unknown",
    redacted: bool = False,
    envelopes: int = 0,
) -> A2UIDuplexReport:
    report = A2UIDuplexReport(
        fixture_id=fixture_id,
        producer_id=producer_id,
        producer_profile=producer_profile,  # type: ignore[arg-type]
        protocol_version=protocol_version,  # type: ignore[arg-type]
        input_sha256=digest,
        verdict="unknown",
        redacted=False,
        findings=[_unknown(target=fixture_id, evidence=evidence, status=status)],
        statistics=_empty_statistics(envelopes),
        assumptions=_ASSUMPTIONS,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )
    return _apply_redaction(report) if redacted else report


def scan_a2ui_duplex_path(path: Path, *, redact: bool = False) -> A2UIDuplexReport:
    report, _ = scan_a2ui_duplex_path_with_identity(path, redact=redact)
    return report


def scan_a2ui_duplex_path_with_identity(
    path: Path,
    *,
    redact: bool = False,
) -> tuple[A2UIDuplexReport, tuple[int, int]]:
    raw, input_identity = _read_fixture_bytes(path)
    digest = duplex_sha256_bytes(raw)
    if path.suffix != ".json":
        return (
            _unknown_report(
                digest,
                "only .json paired-envelope fixtures are supported",
                status="unsupported",
                redacted=redact,
            ),
            input_identity,
        )
    try:
        _validate_json_nesting(raw)
        payload = _load_json(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise AgentUIInputError("invalid JSON duplex fixture") from exc
    _generic_limits_and_credentials(payload)
    if not isinstance(payload, dict):
        return (
            _unknown_report(digest, "duplex fixture root must be an object", redacted=redact),
            input_identity,
        )
    try:
        fixture = A2UIDuplexFixture.model_validate(payload, strict=True)
    except ValidationError as exc:
        fixture_id_value = payload.get("fixture_id")
        fixture_id = fixture_id_value if isinstance(fixture_id_value, str) else "unknown"
        producer = payload.get("producer")
        producer_id = "unknown"
        profile = "unknown"
        if isinstance(producer, dict):
            producer_id_value = producer.get("producer_id")
            profile_value = producer.get("profile")
            if isinstance(producer_id_value, str):
                producer_id = producer_id_value
            if profile_value in {"web-core-react", "flutter-a2ui"}:
                assert isinstance(profile_value, str)
                profile = profile_value
        version = payload.get("protocol_version")
        if version not in {"v0.9", "v1.0"}:
            version = "unknown"
        transcript = payload.get("transcript")
        envelope_count = len(transcript) if isinstance(transcript, list) else 0
        return (
            _unknown_report(
                digest,
                _validation_evidence(exc),
                fixture_id=fixture_id,
                producer_id=producer_id,
                producer_profile=profile,
                protocol_version=version,
                redacted=redact,
                envelopes=envelope_count,
            ),
            input_identity,
        )
    if len(fixture.transcript) > _MAX_ENVELOPES:
        raise AgentUIInputError(f"fixture exceeds {_MAX_ENVELOPES} transcript envelopes")
    report = _scan_fixture(fixture, digest)
    return (_apply_redaction(report) if redact else report, input_identity)


def _scan_fixture(fixture: A2UIDuplexFixture, digest: str) -> A2UIDuplexReport:
    findings: list[DuplexFinding] = []
    surfaces: dict[str, _SurfaceState] = {}
    surfaces_seen: set[str] = set()
    deleted_surface_ids: set[str] = set()
    server_records: dict[str, _ServerRecord] = {}
    counts = _ScanCounts()
    seen_action_ids: set[str] = set()
    message_id_counts = Counter(item.message_id for item in fixture.transcript)
    processed_ids: set[str] = set()
    ordered = sorted(fixture.transcript, key=lambda item: item.sequence)
    envelope_by_id: dict[str, DuplexTranscriptEnvelope] = {}
    for envelope in ordered:
        envelope_by_id.setdefault(envelope.message_id, envelope)

    action_contracts = {
        (item.surface_id, item.component_id, item.action_name): item for item in fixture.action_contracts
    }
    disclosure_rules = (
        {item.surface_id: item for item in fixture.disclosure_policy.surface_rules}
        if fixture.disclosure_policy is not None
        else {}
    )

    for envelope in ordered:
        is_duplicate = message_id_counts[envelope.message_id] > 1
        if is_duplicate and envelope.direction == "client_to_server":
            findings.append(
                _finding(
                    "MCPDUP003",
                    target=envelope.message_id,
                    evidence=["client return message_id is duplicated in the paired transcript"],
                    observable_basis=["Duplicate identity is proven by exact message_id equality."],
                )
            )
        elif is_duplicate:
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="server message_id is duplicated, so return correlation is ambiguous",
                )
            )
        if envelope.message_id in processed_ids:
            continue
        processed_ids.add(envelope.message_id)
        if envelope.direction == "server_to_client":
            counts.server_messages += 1
            _process_server_envelope(
                fixture,
                envelope,
                surfaces,
                surfaces_seen,
                deleted_surface_ids,
                server_records,
                findings,
            )
        else:
            counts.client_returns += 1
            _process_client_envelope(
                fixture,
                envelope,
                surfaces,
                server_records,
                envelope_by_id,
                action_contracts,
                disclosure_rules,
                seen_action_ids,
                findings,
                counts,
            )

    if counts.client_returns == 0:
        findings.append(
            _unknown(
                target=fixture.fixture_id,
                evidence="paired fixture contains no client-to-server return envelopes",
            )
        )

    statistics = DuplexStatistics(
        envelopes=len(fixture.transcript),
        server_messages=counts.server_messages,
        client_returns=counts.client_returns,
        surfaces_observed=len(surfaces_seen),
        actions_observed=counts.actions,
        errors_observed=counts.errors,
        data_model_returns_observed=counts.data_model_returns,
    )
    ordered_findings = _sort_findings(findings)
    return A2UIDuplexReport(
        fixture_id=fixture.fixture_id,
        producer_id=fixture.producer.producer_id,
        producer_profile=fixture.producer.profile,
        protocol_version=fixture.protocol_version,
        input_sha256=digest,
        verdict=_verdict(ordered_findings),  # type: ignore[arg-type]
        redacted=False,
        findings=ordered_findings,
        statistics=statistics,
        assumptions=_ASSUMPTIONS,
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def _top_message(
    envelope: DuplexTranscriptEnvelope,
    protocol_version: str,
    *,
    server: bool,
    findings: list[DuplexFinding],
) -> tuple[str, dict[str, Any]] | None:
    payload = envelope.message
    if payload.get("version") != protocol_version:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="nested A2UI message version does not match the fixture protocol_version",
            )
        )
        return None
    keys = [key for key in payload if key != "version"]
    supported = (
        {"createSurface", "updateComponents", "updateDataModel", "deleteSurface"}
        if server
        else {"action", "error"}
    )
    if len(keys) != 1:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="A2UI message must contain exactly one supported envelope payload",
            )
        )
        return None
    kind = keys[0]
    if kind not in supported:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="A2UI message type is outside the supported duplex subset",
                status="unsupported",
            )
        )
        return None
    nested = payload.get(kind)
    if not isinstance(nested, dict):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence=f"A2UI {kind} payload must be an object",
            )
        )
        return None
    if set(payload) != {"version", kind}:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="A2UI envelope contains unsupported top-level fields",
            )
        )
        return None
    return kind, nested


def _require_fields(
    value: Mapping[str, Any],
    *,
    required: set[str],
    allowed: set[str],
    envelope: DuplexTranscriptEnvelope,
    findings: list[DuplexFinding],
) -> bool:
    if not required.issubset(value):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="A2UI payload is missing required observable fields",
            )
        )
        return False
    if not set(value).issubset(allowed):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="A2UI payload contains unsupported fields",
            )
        )
        return False
    return True


def _process_server_envelope(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    surfaces: dict[str, _SurfaceState],
    surfaces_seen: set[str],
    deleted_surface_ids: set[str],
    server_records: dict[str, _ServerRecord],
    findings: list[DuplexFinding],
) -> None:
    parsed = _top_message(envelope, fixture.protocol_version, server=True, findings=findings)
    if parsed is None:
        return
    kind, payload = parsed
    observed_at = _parse_utc(envelope.observed_at)
    if kind == "createSurface":
        allowed = {"surfaceId", "catalogId", "sendDataModel"}
        if fixture.protocol_version == "v0.9":
            allowed.add("theme")
        else:
            allowed.update({"surfaceProperties", "components", "dataModel"})
        if not _require_fields(
            payload,
            required={"surfaceId", "catalogId"},
            allowed=allowed,
            envelope=envelope,
            findings=findings,
        ):
            return
        surface_id = payload.get("surfaceId")
        catalog_id = payload.get("catalogId")
        send_data_model = payload.get("sendDataModel", False)
        if not isinstance(surface_id, str) or not surface_id:
            findings.append(
                _unknown(target=envelope.message_id, evidence="createSurface surfaceId must be a string")
            )
            return
        if not isinstance(catalog_id, str) or not catalog_id:
            findings.append(
                _unknown(target=envelope.message_id, evidence="createSurface catalogId must be a string")
            )
            return
        if type(send_data_model) is not bool:
            findings.append(
                _unknown(target=envelope.message_id, evidence="createSurface sendDataModel must be boolean")
            )
            return
        previous = surfaces.get(surface_id)
        if previous is not None and previous.active:
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="createSurface repeats an active surfaceId",
                )
            )
            return
        if fixture.protocol_version == "v1.0" and surface_id in deleted_surface_ids:
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="v1.0 surfaceId reuse is outside the globally-unique surface contract",
                )
            )
            return
        created_surface = _SurfaceState(
            surface_id=surface_id,
            revision=1,
            catalog_id=catalog_id,
            send_data_model=send_data_model,
            active=True,
            last_message_id=envelope.message_id,
            last_sequence=envelope.sequence,
            last_observed_at=observed_at,
        )
        surfaces[surface_id] = created_surface
        surfaces_seen.add(surface_id)
        created_component_ids: set[str] = set()
        if fixture.protocol_version == "v1.0" and "components" in payload:
            components = payload.get("components")
            created_component_ids = _apply_components(
                components,
                created_surface,
                envelope,
                findings,
            )
        server_records[envelope.message_id] = _ServerRecord(
            sequence=envelope.sequence,
            surface_id=surface_id,
            kind=kind,
            component_ids=frozenset(created_component_ids),
            observed_at=observed_at,
        )
        return

    surface_id = payload.get("surfaceId")
    if not isinstance(surface_id, str) or not surface_id:
        findings.append(_unknown(target=envelope.message_id, evidence=f"{kind} surfaceId must be a string"))
        return
    active_surface = surfaces.get(surface_id)
    if active_surface is None or not active_surface.active:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence=f"{kind} targets a surface that is not active in supplied server evidence",
            )
        )
        return

    component_ids: set[str] = set()
    if kind == "updateComponents":
        if not _require_fields(
            payload,
            required={"surfaceId", "components"},
            allowed={"surfaceId", "components"},
            envelope=envelope,
            findings=findings,
        ):
            return
        active_surface.revision += 1
        component_ids = _apply_components(
            payload.get("components"),
            active_surface,
            envelope,
            findings,
        )
    elif kind == "updateDataModel":
        if not _require_fields(
            payload,
            required={"surfaceId"},
            allowed={"surfaceId", "path", "value"},
            envelope=envelope,
            findings=findings,
        ):
            return
        path = payload.get("path", "/")
        if not isinstance(path, str) or (path != "/" and not path.startswith("/")):
            findings.append(
                _unknown(
                    target=envelope.message_id, evidence="updateDataModel path is not an absolute pointer"
                )
            )
            return
        active_surface.revision += 1
    else:
        if not _require_fields(
            payload,
            required={"surfaceId"},
            allowed={"surfaceId"},
            envelope=envelope,
            findings=findings,
        ):
            return
        active_surface.revision += 1
        active_surface.active = False
        active_surface.components.clear()
        deleted_surface_ids.add(surface_id)
    active_surface.last_message_id = envelope.message_id
    active_surface.last_sequence = envelope.sequence
    active_surface.last_observed_at = observed_at
    server_records[envelope.message_id] = _ServerRecord(
        sequence=envelope.sequence,
        surface_id=surface_id,
        kind=kind,
        component_ids=frozenset(component_ids),
        observed_at=observed_at,
    )


def _apply_components(
    value: Any,
    surface: _SurfaceState,
    envelope: DuplexTranscriptEnvelope,
    findings: list[DuplexFinding],
) -> set[str]:
    if not isinstance(value, list) or not value:
        findings.append(_unknown(target=envelope.message_id, evidence="components must be a non-empty array"))
        return set()
    identifiers: list[str] = []
    for component in value:
        if isinstance(component, dict) and isinstance(component.get("id"), str):
            identifiers.append(component["id"])
    if len(identifiers) != len(value) or len(identifiers) != len(set(identifiers)):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="component ids must be present, string-valued, and unique within an update",
            )
        )
        return set()
    observed_at = _parse_utc(envelope.observed_at)
    for component in value:
        assert isinstance(component, dict)
        component_id = component["id"]
        component_type = component.get("component")
        action_declaration_supported = True
        if not isinstance(component_type, str) or not component_type:
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="component discriminator must be a non-empty string",
                    status="unsupported",
                )
            )
            action_declaration_supported = False
        action_name: str | None = None
        context_keys: frozenset[str] = frozenset()
        action = component.get("action")
        if action is not None:
            if not isinstance(action, dict) or set(action) != {"event"}:
                action_declaration_supported = False
                findings.append(
                    _unknown(
                        target=envelope.message_id,
                        evidence="component action uses an unsupported declaration shape",
                        status="unsupported",
                    )
                )
            else:
                event = action.get("event")
                if not isinstance(event, dict) or not {"name", "context"}.issubset(event):
                    action_declaration_supported = False
                    findings.append(
                        _unknown(
                            target=envelope.message_id,
                            evidence="component action event is missing name or context",
                        )
                    )
                elif not isinstance(event.get("name"), str) or not isinstance(event.get("context"), dict):
                    action_declaration_supported = False
                    findings.append(
                        _unknown(
                            target=envelope.message_id,
                            evidence="component action event name/context types are malformed",
                        )
                    )
                else:
                    action_name = event["name"]
                    context_keys = frozenset(event["context"])
        previous = surface.components.get(component_id)
        revision = 1 if previous is None else previous.revision + 1
        surface.components[component_id] = _ComponentState(
            component_id=component_id,
            revision=revision,
            last_message_id=envelope.message_id,
            last_sequence=envelope.sequence,
            last_observed_at=observed_at,
            action_declaration_supported=action_declaration_supported,
            action_name=action_name,
            context_keys=context_keys,
        )
    return set(identifiers)


def _process_client_envelope(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    surfaces: dict[str, _SurfaceState],
    server_records: dict[str, _ServerRecord],
    envelope_by_id: dict[str, DuplexTranscriptEnvelope],
    action_contracts: dict[tuple[str, str, str], DuplexActionContract],
    disclosure_rules: dict[str, DuplexSurfaceDisclosureRule],
    seen_action_ids: set[str],
    findings: list[DuplexFinding],
    counts: _ScanCounts,
) -> None:
    parsed = _top_message(envelope, fixture.protocol_version, server=False, findings=findings)
    if parsed is None:
        return
    kind, payload = parsed
    if kind == "action":
        counts.actions += 1
        _check_action(
            fixture,
            envelope,
            payload,
            surfaces,
            server_records,
            action_contracts,
            seen_action_ids,
            findings,
        )
        surface_id = payload.get("surfaceId") if isinstance(payload.get("surfaceId"), str) else None
        if surface_id is not None:
            _check_capabilities(fixture, envelope, surface_id, surfaces, findings)
    else:
        counts.errors += 1
        _check_error(
            fixture,
            envelope,
            payload,
            surfaces,
            server_records,
            envelope_by_id,
            findings,
        )
        surface_id = payload.get("surfaceId") if isinstance(payload.get("surfaceId"), str) else None
        if surface_id is not None:
            _check_capabilities(fixture, envelope, surface_id, surfaces, findings)
    if envelope.metadata is not None and envelope.metadata.client_data_model is not None:
        counts.data_model_returns += 1
        _check_data_model_return(
            fixture,
            envelope,
            surfaces,
            disclosure_rules,
            findings,
        )


def _check_action(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    action: dict[str, Any],
    surfaces: dict[str, _SurfaceState],
    server_records: dict[str, _ServerRecord],
    action_contracts: dict[tuple[str, str, str], DuplexActionContract],
    seen_action_ids: set[str],
    findings: list[DuplexFinding],
) -> None:
    allowed = {"name", "surfaceId", "sourceComponentId", "timestamp", "context"}
    if fixture.protocol_version == "v1.0":
        allowed.update({"wantResponse", "actionId"})
    if not _require_fields(
        action,
        required={"name", "surfaceId", "sourceComponentId", "timestamp", "context"},
        allowed=allowed,
        envelope=envelope,
        findings=findings,
    ):
        return
    name = action.get("name")
    surface_id = action.get("surfaceId")
    component_id = action.get("sourceComponentId")
    timestamp = action.get("timestamp")
    context = action.get("context")
    if (
        not isinstance(name, str)
        or not name
        or not isinstance(surface_id, str)
        or not surface_id
        or not isinstance(component_id, str)
        or not component_id
        or not isinstance(timestamp, str)
        or not timestamp
    ):
        findings.append(
            _unknown(
                target=envelope.message_id, evidence="action identity and timestamp fields must be strings"
            )
        )
        return
    if not isinstance(context, dict):
        findings.append(_unknown(target=envelope.message_id, evidence="action context must be an object"))
        return
    try:
        action_time = _parse_utc(timestamp)
    except ValueError:
        findings.append(_unknown(target=envelope.message_id, evidence="action timestamp must be UTC Z form"))
        return
    observed_at = _parse_utc(envelope.observed_at)

    if fixture.protocol_version == "v1.0":
        want_response = action.get("wantResponse", False)
        action_id = action.get("actionId")
        if type(want_response) is not bool:
            findings.append(
                _unknown(target=envelope.message_id, evidence="v1.0 wantResponse must be boolean")
            )
        elif want_response and (not isinstance(action_id, str) or not action_id):
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="v1.0 actionId is required when wantResponse is true",
                )
            )
        if isinstance(action_id, str) and action_id:
            if action_id in seen_action_ids:
                findings.append(
                    _finding(
                        "MCPDUP003",
                        target=envelope.message_id,
                        evidence=["v1.0 actionId is replayed by more than one client return"],
                        observable_basis=["Replay identity is proven by exact actionId equality."],
                    )
                )
            seen_action_ids.add(action_id)

    surface = surfaces.get(surface_id)
    component = surface.components.get(component_id) if surface is not None and surface.active else None
    if surface is None or not surface.active:
        findings.append(
            _finding(
                "MCPDUP001",
                target=envelope.message_id,
                evidence=["returned surfaceId does not resolve to an active supplied surface"],
                observable_basis=["Active surface lifecycle is computed from createSurface/deleteSurface."],
            )
        )
    elif component is None:
        findings.append(
            _finding(
                "MCPDUP001",
                target=envelope.message_id,
                evidence=["sourceComponentId does not resolve in the returned active surface"],
                observable_basis=["Component membership is indexed per active surface revision."],
            )
        )
    if envelope.origin is None:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="action return lacks the fixture-owned revision origin sidecar",
            )
        )
    elif surface is not None and surface.active and component is not None:
        origin = envelope.origin
        origin_mismatches: list[str] = []
        if origin.surface_revision != surface.revision:
            origin_mismatches.append("surface revision")
        if origin.component_revision != component.revision:
            origin_mismatches.append("component revision")
        if origin.server_message_id != component.last_message_id:
            origin_mismatches.append("emitting server message")
        if origin_mismatches:
            findings.append(
                _finding(
                    "MCPDUP001",
                    target=envelope.message_id,
                    evidence=["return origin does not match the active " + ", ".join(origin_mismatches)],
                    observable_basis=[
                        "Expected revisions are computed from earlier supplied server messages."
                    ],
                )
            )
        origin_record = server_records.get(origin.server_message_id)
        if origin_record is None or origin_record.sequence >= envelope.sequence:
            findings.append(
                _finding(
                    "MCPDUP003",
                    target=envelope.message_id,
                    evidence=["return origin does not identify an earlier server message"],
                    observable_basis=["Causality is proven by explicit transcript sequence ids."],
                )
            )
        if action_time < surface.last_observed_at or action_time > observed_at:
            findings.append(
                _finding(
                    "MCPDUP003",
                    target=envelope.message_id,
                    evidence=["action timestamp is impossible within the declared fixture single clock"],
                    observable_basis=[
                        "The action timestamp is outside its active-surface-revision to observed-return "
                        "interval.",
                        "Timestamp comparison is not used as replay identity.",
                    ],
                )
            )

    if component is not None and component.action_declaration_supported:
        if component.action_name != name:
            findings.append(
                _finding(
                    "MCPDUP002",
                    target=envelope.message_id,
                    evidence=["returned action name is not declared by the source component"],
                    observable_basis=["The declaration is read from the source component action.event.name."],
                )
            )
        elif set(context) != set(component.context_keys):
            findings.append(
                _finding(
                    "MCPDUP002",
                    target=envelope.message_id,
                    evidence=["returned context keys differ from the component action declaration"],
                    observable_basis=[
                        "Only key membership is compared; context values are never copied into output."
                    ],
                )
            )
        contract = action_contracts.get((surface_id, component_id, name))
        if contract is not None:
            _check_action_schema(contract, action, context, envelope, findings)


def _check_action_schema(
    contract: DuplexActionContract,
    action: dict[str, Any],
    context: dict[str, Any],
    envelope: DuplexTranscriptEnvelope,
    findings: list[DuplexFinding],
) -> None:
    for label, schema, value in (
        ("context", contract.context_schema, context),
        ("payload", contract.payload_schema, action),
    ):
        if schema is None:
            continue
        budget = _SchemaBudget()
        violations: list[str] = []
        unsupported: set[str] = set()
        try:
            _validate_schema_value(
                schema,
                value,
                depth=0,
                budget=budget,
                violations=violations,
                unsupported=unsupported,
            )
        except ValueError:
            unsupported.add("invalid schema shape or resource bound")
        if unsupported:
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence=f"action {label} schema uses unsupported or invalid bounded keywords",
                    status="unsupported",
                )
            )
        elif violations:
            findings.append(
                _finding(
                    "MCPDUP002",
                    target=envelope.message_id,
                    evidence=[f"returned action {label} fails its explicit schema"],
                    observable_basis=[
                        "Validation uses the documented bounded local JSON Schema subset.",
                        "Violation paths and values are not copied into output.",
                    ],
                )
            )


def _json_type_matches(expected: str, value: Any) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _validate_schema_value(
    schema: Any,
    value: Any,
    *,
    depth: int,
    budget: _SchemaBudget,
    violations: list[str],
    unsupported: set[str],
) -> None:
    if depth > _MAX_SCHEMA_DEPTH:
        raise ValueError("schema depth exceeded")
    budget.nodes += 1
    if budget.nodes > _MAX_SCHEMA_NODES:
        raise ValueError("schema node budget exceeded")
    if not isinstance(schema, dict):
        raise ValueError("schema node must be object")
    extra = set(schema) - _SUPPORTED_SCHEMA_KEYWORDS
    if extra:
        unsupported.update(extra)
        return
    expected = schema.get("type")
    if expected is not None:
        if not isinstance(expected, str) or expected not in {
            "object",
            "array",
            "string",
            "integer",
            "number",
            "boolean",
            "null",
        }:
            raise ValueError("unsupported type")
        if not _json_type_matches(expected, value):
            violations.append("type")
            return
    if "const" in schema and value != schema["const"]:
        violations.append("const")
    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not enum:
            raise ValueError("enum must be non-empty array")
        if value not in enum:
            violations.append("enum")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        additional = schema.get("additionalProperties", True)
        if not isinstance(properties, dict):
            raise ValueError("properties must be object")
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(required) != len(set(required))
        ):
            raise ValueError("required must contain unique strings")
        if type(additional) is not bool:
            raise ValueError("additionalProperties must be boolean")
        if any(item not in value for item in required):
            violations.append("required")
        if not additional and any(item not in properties for item in value):
            violations.append("additionalProperties")
        for key, nested_schema in properties.items():
            if not isinstance(key, str):
                raise ValueError("property names must be strings")
            if key in value:
                _validate_schema_value(
                    nested_schema,
                    value[key],
                    depth=depth + 1,
                    budget=budget,
                    violations=violations,
                    unsupported=unsupported,
                )
    if isinstance(value, list):
        for keyword in ("minItems", "maxItems"):
            bound = schema.get(keyword)
            if bound is not None and (not isinstance(bound, int) or isinstance(bound, bool) or bound < 0):
                raise ValueError("array bound must be non-negative integer")
        if isinstance(schema.get("minItems"), int) and len(value) < schema["minItems"]:
            violations.append("minItems")
        if isinstance(schema.get("maxItems"), int) and len(value) > schema["maxItems"]:
            violations.append("maxItems")
        items = schema.get("items")
        if items is not None:
            for item in value:
                _validate_schema_value(
                    items,
                    item,
                    depth=depth + 1,
                    budget=budget,
                    violations=violations,
                    unsupported=unsupported,
                )
    if isinstance(value, str):
        for keyword in ("minLength", "maxLength"):
            bound = schema.get(keyword)
            if bound is not None and (not isinstance(bound, int) or isinstance(bound, bool) or bound < 0):
                raise ValueError("string bound must be non-negative integer")
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            violations.append("minLength")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            violations.append("maxLength")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        for keyword in ("minimum", "maximum"):
            bound = schema.get(keyword)
            if bound is not None and (not isinstance(bound, (int, float)) or isinstance(bound, bool)):
                raise ValueError("numeric bound must be a number")
        if isinstance(schema.get("minimum"), (int, float)) and value < schema["minimum"]:
            violations.append("minimum")
        if isinstance(schema.get("maximum"), (int, float)) and value > schema["maximum"]:
            violations.append("maximum")


def _check_capabilities(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    surface_id: str,
    surfaces: dict[str, _SurfaceState],
    findings: list[DuplexFinding],
) -> None:
    surface = surfaces.get(surface_id)
    metadata = envelope.metadata
    if metadata is None or metadata.client_capabilities is None:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="client return lacks a2uiClientCapabilities evidence",
            )
        )
        return
    capabilities = metadata.client_capabilities
    if set(capabilities) != {fixture.protocol_version}:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="client capability version does not match the fixture protocol version",
            )
        )
        return
    version_capabilities = capabilities.get(fixture.protocol_version)
    if not isinstance(version_capabilities, dict):
        findings.append(
            _unknown(target=envelope.message_id, evidence="client capability payload must be an object")
        )
        return
    if "inlineCatalogs" in version_capabilities:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="inline client catalogs are outside this renderer-neutral analyzer",
                status="unsupported",
            )
        )
        return
    if set(version_capabilities) != {"supportedCatalogIds"}:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="client capability payload contains unsupported fields",
            )
        )
        return
    catalogs = version_capabilities.get("supportedCatalogIds")
    if (
        not isinstance(catalogs, list)
        or any(not isinstance(item, str) for item in catalogs)
        or len(catalogs) != len(set(catalogs))
    ):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="supportedCatalogIds must contain unique strings",
            )
        )
        return
    if surface is not None and surface.catalog_id not in catalogs:
        findings.append(
            _finding(
                "MCPDUP004",
                target=envelope.message_id,
                evidence=["client return uses a surface catalog absent from supportedCatalogIds"],
                observable_basis=[
                    "The active catalogId is compared to return-time client capability metadata.",
                    "No static catalog descriptor or component implementation is audited.",
                ],
            )
        )


def _check_error(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    error: dict[str, Any],
    surfaces: dict[str, _SurfaceState],
    server_records: dict[str, _ServerRecord],
    envelope_by_id: dict[str, DuplexTranscriptEnvelope],
    findings: list[DuplexFinding],
) -> None:
    required = {"code", "surfaceId", "message"}
    allowed = {"code", "surfaceId", "message", "path"}
    if fixture.protocol_version == "v1.0":
        allowed.add("functionCallId")
    if not _require_fields(
        error,
        required=required,
        allowed=allowed,
        envelope=envelope,
        findings=findings,
    ):
        return
    code = error.get("code")
    surface_id = error.get("surfaceId")
    message = error.get("message")
    if (
        not isinstance(code, str)
        or not code
        or not isinstance(surface_id, str)
        or not surface_id
        or not isinstance(message, str)
        or not message
    ):
        findings.append(
            _unknown(
                target=envelope.message_id, evidence="error code, surfaceId, and message must be strings"
            )
        )
        return
    if code == "VALIDATION_FAILED" and not isinstance(error.get("path"), str):
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="VALIDATION_FAILED error requires a JSON pointer path",
            )
        )
        return
    correlation = envelope.correlation
    if correlation is None:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="renderer error lacks fixture-owned component/message correlation evidence",
            )
        )
    else:
        surface = surfaces.get(surface_id)
        record = server_records.get(correlation.server_message_id)
        mismatch = (
            surface is None
            or not surface.active
            or correlation.source_component_id not in surface.components
            or record is None
            or record.sequence >= envelope.sequence
            or record.surface_id != surface_id
            or correlation.source_component_id not in record.component_ids
        )
        if mismatch:
            findings.append(
                _finding(
                    "MCPDUP005",
                    target=envelope.message_id,
                    evidence=[
                        "renderer error correlation does not resolve to its surface, component, and message"
                    ],
                    observable_basis=[
                        "Correlation is checked against earlier supplied server message and active "
                        "component indexes."
                    ],
                )
            )
    acknowledgements = [
        item
        for item in envelope_by_id.values()
        if _is_matching_error_acknowledgement(
            item,
            error_message_id=envelope.message_id,
            error_sequence=envelope.sequence,
            surface_id=surface_id,
            protocol_version=fixture.protocol_version,
        )
    ]
    if not acknowledgements:
        findings.append(
            _finding(
                "MCPDUP005",
                target=envelope.message_id,
                evidence=["renderer error has no later server acknowledgement in the paired transcript"],
                observable_basis=["Acknowledgement is an explicit fixture envelope correlation field."],
            )
        )


def _is_matching_error_acknowledgement(
    envelope: DuplexTranscriptEnvelope,
    *,
    error_message_id: str,
    error_sequence: int,
    surface_id: str,
    protocol_version: str,
) -> bool:
    if (
        envelope.direction != "server_to_client"
        or error_message_id not in envelope.acknowledges
        or envelope.sequence <= error_sequence
        or envelope.message.get("version") != protocol_version
    ):
        return False
    keys = [key for key in envelope.message if key != "version"]
    if len(keys) != 1 or keys[0] not in {
        "createSurface",
        "updateComponents",
        "updateDataModel",
        "deleteSurface",
    }:
        return False
    payload = envelope.message.get(keys[0])
    return isinstance(payload, dict) and payload.get("surfaceId") == surface_id


def _check_data_model_return(
    fixture: A2UIDuplexFixture,
    envelope: DuplexTranscriptEnvelope,
    surfaces: dict[str, _SurfaceState],
    disclosure_rules: dict[str, DuplexSurfaceDisclosureRule],
    findings: list[DuplexFinding],
) -> None:
    assert envelope.metadata is not None
    model = envelope.metadata.client_data_model
    assert model is not None
    if fixture.disclosure_policy is None:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="full data-model return is present but no explicit disclosure policy was supplied",
            )
        )
        return
    if set(model) != {"version", "surfaces"} or model.get("version") != fixture.protocol_version:
        findings.append(
            _unknown(
                target=envelope.message_id,
                evidence="a2uiClientDataModel shape/version is malformed or unsupported",
            )
        )
        return
    returned_surfaces = model.get("surfaces")
    if not isinstance(returned_surfaces, dict):
        findings.append(
            _unknown(target=envelope.message_id, evidence="client data-model surfaces must be an object")
        )
        return
    for surface_id, returned_model in returned_surfaces.items():
        if not isinstance(surface_id, str) or not isinstance(returned_model, dict):
            findings.append(
                _unknown(
                    target=envelope.message_id,
                    evidence="returned surface data models must be object-valued",
                )
            )
            continue
        surface = surfaces.get(surface_id)
        policy = disclosure_rules.get(surface_id)
        violation = (
            surface is None
            or not surface.active
            or not surface.send_data_model
            or policy is None
            or not policy.allow_full_data_model_return
            or (
                bool(policy.allowed_top_level_keys)
                and not set(returned_model).issubset(policy.allowed_top_level_keys)
            )
        )
        if violation:
            findings.append(
                _finding(
                    "MCPDUP006",
                    target=envelope.message_id,
                    evidence=["returned full data model is outside the explicit surface disclosure policy"],
                    observable_basis=[
                        "The check uses createSurface sendDataModel and the program-owned disclosure rule.",
                        "Returned data values and disallowed key names are not copied into output.",
                    ],
                )
            )


def a2ui_duplex_report_json_bytes(report: A2UIDuplexReport) -> bytes:
    return duplex_canonical_json_bytes(report)


def render_a2ui_duplex_sarif(report: A2UIDuplexReport) -> bytes:
    rules = []
    for rule_id in ["MCPDUP000", *sorted(_RULES)]:
        if rule_id == "MCPDUP000":
            title = _UNKNOWN_TITLE
            description = _UNKNOWN_REMEDIATION
        else:
            _, title, description = _RULES[rule_id]
        rules.append(
            {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "help": {"text": description},
            }
        )
    level = {"high": "error", "medium": "warning", "unknown": "note"}
    results = [
        {
            "ruleId": item.rule_id,
            "level": level[item.severity],
            "message": {"text": f"{item.title}: {item.evidence[0]}"},
            "locations": [
                {
                    "physicalLocation": {"artifactLocation": {"uri": "synthetic-a2ui-duplex-fixture"}},
                    "logicalLocations": [{"name": item.target}],
                }
            ],
            "properties": {
                "status": item.status,
                "observableBasis": item.observable_basis,
                "redacted": report.redacted,
            },
        }
        for item in report.findings
    ]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPAudit A2UI Duplex Return-Path Auditor",
                        "informationUri": "https://github.com/saagpatel/MCPAudit",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "fixtureSchema": "mcpaudit.a2ui-duplex.fixture.v1",
                    "reportSchema": report.schema_version,
                    "verdict": report.verdict,
                },
            }
        ],
    }
    return duplex_canonical_json_bytes(sarif)
