"""Deterministic offline analysis for synthetic MCP 2026 round-trip traces."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Final, Never, TypeVar

from pydantic import BaseModel, ValidationError

from mcp_audit.roundtrip_models import (
    JSONL_MANIFEST_SCHEMA,
    REPORT_SCHEMA,
    SUPPORTED_PROTOCOL_REVISION,
    TRACE_SCHEMA,
    FindingSeverity,
    RequestStateWitness,
    RoundTripFinding,
    RoundTripJsonlManifest,
    RoundTripLimits,
    RoundTripReport,
    RoundTripRuleResult,
    RoundTripTrace,
    TraceEvent,
)

MAXIMUM_BYTES: Final = 2_097_152
MAXIMUM_DEPTH: Final = 40
MAXIMUM_EVENTS: Final = 512
MAXIMUM_NODES: Final = 50_000
MAXIMUM_STRING_BYTES: Final = 16_384
MAXIMUM_JSONL_LINE_BYTES: Final = 131_072

_PROTOCOL_META = "io.modelcontextprotocol/protocolVersion"
_CLIENT_CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities"
_MRTR_METHODS = {"tools/call", "prompts/get", "resources/read"}
_CAPABILITY_FOR_METHOD = {
    "tools": "tools",
    "prompts": "prompts",
    "resources": "resources",
}
_CLIENT_CAPABILITY_FOR_INPUT = {
    "elicitation/create": "elicitation",
    "sampling/createMessage": "sampling",
    "roots/list": "roots",
}
_CREDENTIAL_KEYS = {
    "authorization",
    "cookie",
    "set_cookie",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
}
_BEARER = re.compile(r"(?i)^bearer\s+\S")
_OPENAI_KEY = re.compile(r"^sk-[A-Za-z0-9_-]{16,}$")
_JWT = re.compile(r"^[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}$")
_BASE64_SENTINEL = re.compile(r"^=\?base64\?([A-Za-z0-9+/]*={0,2})\?=$")
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

_RULES: dict[str, tuple[str, str]] = {
    "MCPRT000": (
        "Supported trace profile",
        "Use the documented program-owned trace schema, supported revision, and supported transport.",
    ),
    "MCPRT001": (
        "Per-request version and client capabilities",
        "Include the 2026 protocol revision and client capabilities in every request, "
        "and reject unsupported versions explicitly.",
    ),
    "MCPRT002": (
        "Discovery consistency",
        "Make server/discover advertisements agree with later protocol and capability behavior.",
    ),
    "MCPRT003": (
        "Streamable HTTP metadata mirroring",
        "Derive MCP request headers from the body and reject any header/body mismatch.",
    ),
    "MCPRT004": (
        "Result discrimination and MRTR correlation",
        "Use required resultType values and correlate input requests, responses, state, "
        "capabilities, and fresh request IDs.",
    ),
    "MCPRT005": (
        "Observable requestState replay boundaries",
        "Reject requestState across principal, method, parameter, or expiry boundaries and "
        "provide a trusted witness for cryptographic binding claims.",
    ),
    "MCPRT006": (
        "Broken-stream request ID renewal",
        "Retry a request whose response stream broke with a fresh JSON-RPC request ID.",
    ),
}

_ASSUMPTIONS = [
    "The input is a program-owned synthetic trace ordered by the explicit sequence field.",
    "Principal values are inert synthetic aliases supplied by the fixture producer.",
    "HTTP observations describe one POST and its body; stdio observations omit HTTP metadata.",
]
_SUPPORTED_CLAIMS = [
    "The supplied trace does or does not satisfy the implemented observable MCP 2026-07-28 invariants.",
    "A trusted program witness can make the listed requestState integrity and binding "
    "checks observable for this fixture only.",
]
_UNSUPPORTED_CLAIMS = [
    "Real-host security, runtime isolation, authorization correctness, credential handling, "
    "and production conformance.",
    "Cryptographic requestState protection without a matching trusted program witness.",
    "Interoperability, live server behavior, transport implementation safety, and behavior "
    "absent from the supplied trace.",
]

ModelT = TypeVar("ModelT", bound=BaseModel)


class RoundTripInputError(ValueError):
    """The input could not be safely accepted as a synthetic trace."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return newline-terminated canonical JSON bytes."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    )


def report_json_bytes(report: RoundTripReport) -> bytes:
    """Serialize a report without timestamps, paths, or other volatile fields."""
    return canonical_json_bytes(report)


def scan_roundtrip_path(path: Path) -> RoundTripReport:
    """Scan one JSON or JSONL synthetic trace without external effects."""
    report, _ = scan_roundtrip_path_with_identity(path)
    return report


def scan_roundtrip_path_with_identity(
    path: Path,
) -> tuple[RoundTripReport, tuple[int, int]]:
    """Scan a trace and return the identity of the exact file descriptor read."""
    raw, identity = _read_fixture_bytes(path)
    digest = hashlib.sha256(raw).hexdigest()
    if path.suffix == ".json":
        trace = _parse_json_trace(raw)
        expected_schema = TRACE_SCHEMA
    elif path.suffix == ".jsonl":
        trace = _parse_jsonl_trace(raw)
        expected_schema = JSONL_MANIFEST_SCHEMA
    else:
        raise RoundTripInputError("only .json and .jsonl synthetic trace inputs are supported")
    return _scan_trace(trace, digest, expected_schema), identity


def _read_fixture_bytes(path: Path) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RoundTripInputError("cannot inspect input fixture") from exc
    if not stat.S_ISREG(before.st_mode):
        raise RoundTripInputError("input fixture must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RoundTripInputError("input fixture must be a regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise RoundTripInputError("input fixture must be a regular non-symlink file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RoundTripInputError("input fixture changed while it was being opened")
        if opened.st_size > MAXIMUM_BYTES:
            raise RoundTripInputError(f"input fixture exceeds {MAXIMUM_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = MAXIMUM_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAXIMUM_BYTES:
            raise RoundTripInputError(f"input fixture exceeds {MAXIMUM_BYTES} bytes")
        return raw, (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON object key")
        output[key] = value
    return output


def _load_json(raw: bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=_object_without_duplicates,
        parse_constant=_reject_json_constant,
    )


def _parse_json_trace(raw: bytes) -> RoundTripTrace:
    payload = _parse_one_json(raw, "JSON trace")
    if not isinstance(payload, dict):
        raise RoundTripInputError("JSON trace root must be an object")
    _validate_resource_shape(payload)
    _reject_credentials(payload)
    return _validate_model(RoundTripTrace, payload, "JSON trace")


def _parse_jsonl_trace(raw: bytes) -> RoundTripTrace:
    lines = raw.splitlines()
    if len(lines) < 2:
        raise RoundTripInputError("JSONL trace requires a manifest and at least one event")
    if len(lines) > MAXIMUM_EVENTS + 1:
        raise RoundTripInputError(f"JSONL trace exceeds {MAXIMUM_EVENTS} events")
    if any(not line.strip() for line in lines):
        raise RoundTripInputError("blank JSONL lines are unsupported")
    if any(len(line) > MAXIMUM_JSONL_LINE_BYTES for line in lines):
        raise RoundTripInputError(f"JSONL line exceeds {MAXIMUM_JSONL_LINE_BYTES} bytes")
    manifest_payload = _parse_one_json(lines[0], "JSONL manifest")
    if not isinstance(manifest_payload, dict):
        raise RoundTripInputError("JSONL manifest must be an object")
    _validate_resource_shape(manifest_payload)
    _reject_credentials(manifest_payload)
    manifest = _validate_model(RoundTripJsonlManifest, manifest_payload, "JSONL manifest")
    events: list[Any] = []
    for line_number, line in enumerate(lines[1:], start=2):
        payload = _parse_one_json(line, f"JSONL line {line_number}")
        if not isinstance(payload, dict):
            raise RoundTripInputError(f"JSONL line {line_number} must be an event object")
        _validate_resource_shape(payload)
        _reject_credentials(payload)
        events.append(payload)
    combined = {**manifest.model_dump(mode="json"), "events": events}
    _validate_resource_shape(combined)
    return _validate_model(RoundTripTrace, combined, "JSONL trace")


def _parse_one_json(raw: bytes, label: str) -> Any:
    _validate_json_nesting(raw)
    try:
        return _load_json(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise RoundTripInputError(f"invalid {label}: {type(exc).__name__}") from exc


def _validate_model(model: type[ModelT], payload: Any, label: str) -> ModelT:
    try:
        # Re-encode parsed JSON so strict Pydantic JSON rules accept RFC 3339 datetimes
        # without permitting Python-side coercion of integers, booleans, or containers.
        return model.model_validate_json(canonical_json_bytes(payload), strict=True)
    except ValidationError as exc:
        error = exc.errors(include_input=False, include_url=False)[0]
        location = "/".join(str(item) for item in error.get("loc", ())) or "<root>"
        detail = str(error.get("msg", error.get("type", "invalid")))
        raise RoundTripInputError(f"{label} schema validation failed at {location}: {detail}") from exc


def _validate_json_nesting(raw: bytes) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
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
            if depth > MAXIMUM_DEPTH:
                raise RoundTripInputError(f"JSON nesting exceeds {MAXIMUM_DEPTH} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def _validate_resource_shape(value: Any) -> None:
    nodes = 0
    stack: list[Any] = [value]
    while stack:
        current = stack.pop()
        nodes += 1
        if nodes > MAXIMUM_NODES:
            raise RoundTripInputError(f"JSON value exceeds the {MAXIMUM_NODES}-node limit")
        if isinstance(current, str) and len(current.encode("utf-8")) > MAXIMUM_STRING_BYTES:
            raise RoundTripInputError(f"JSON string exceeds {MAXIMUM_STRING_BYTES} bytes")
        if isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _reject_credentials(value: Any) -> None:
    stack: list[tuple[str | None, Any]] = [(None, value)]
    while stack:
        key, current = stack.pop()
        if key is not None and key.lower().replace("-", "_") in _CREDENTIAL_KEYS:
            raise RoundTripInputError("credential-looking material is not accepted")
        if isinstance(current, str) and (
            _BEARER.match(current)
            or _OPENAI_KEY.match(current)
            or _JWT.match(current)
            or "-----BEGIN PRIVATE KEY-----" in current
        ):
            raise RoundTripInputError("credential-looking material is not accepted")
        if isinstance(current, dict):
            stack.extend((str(child_key), child) for child_key, child in current.items())
        elif isinstance(current, list):
            stack.extend((None, child) for child in current)


def _scan_trace(
    trace: RoundTripTrace,
    digest: str,
    expected_schema: str,
) -> RoundTripReport:
    if (
        trace.schema_version != expected_schema
        or trace.protocol_revision != SUPPORTED_PROTOCOL_REVISION
        or trace.transport not in {"streamable-http", "stdio"}
    ):
        summary = "The trace schema, protocol revision, or transport is unsupported."
        unsupported_rules = [
            _rule_result(
                rule_id,
                "UNSUPPORTED",
                summary if rule_id == "MCPRT000" else "Rule was not evaluated.",
            )
            for rule_id in _RULES
        ]
        finding = _finding(
            "MCPRT000",
            "UNSUPPORTED",
            summary,
            (),
        )
        return _report(trace, digest, "unsupported", unsupported_rules, [finding])

    evaluators = (
        _evaluate_profile,
        _evaluate_request_envelopes,
        _evaluate_discovery,
        _evaluate_http_mirroring,
        _evaluate_mrtr,
        _evaluate_request_state,
        _evaluate_stream_retries,
    )
    rules: list[RoundTripRuleResult] = []
    findings: list[RoundTripFinding] = []
    for evaluator in evaluators:
        result, rule_findings = evaluator(trace)
        rules.append(result)
        findings.extend(rule_findings)
    findings.sort(
        key=lambda item: (
            {"error": 0, "warning": 1, "note": 2}[item.severity],
            item.rule_id,
            item.event_sequences,
            item.evidence,
        )
    )
    statuses = {item.status for item in rules}
    if "FAIL" in statuses:
        verdict = "fail"
    elif "UNKNOWN" in statuses:
        verdict = "unknown"
    elif "UNSUPPORTED" in statuses:
        verdict = "unsupported"
    else:
        verdict = "pass"
    return _report(trace, digest, verdict, rules, findings)


def _report(
    trace: RoundTripTrace,
    digest: str,
    verdict: str,
    rules: list[RoundTripRuleResult],
    findings: list[RoundTripFinding],
) -> RoundTripReport:
    return RoundTripReport(
        schema_version=REPORT_SCHEMA,
        fixture_id=trace.fixture_id,
        input_sha256=digest,
        trace_schema=trace.schema_version,
        protocol_revision=trace.protocol_revision,
        transport=trace.transport,
        verdict=verdict,  # type: ignore[arg-type]
        rules=rules,
        findings=findings,
        assumptions=_ASSUMPTIONS,
        supported_claims=_SUPPORTED_CLAIMS,
        unsupported_claims=_UNSUPPORTED_CLAIMS,
        limits=RoundTripLimits(
            maximum_bytes=MAXIMUM_BYTES,
            maximum_depth=MAXIMUM_DEPTH,
            maximum_events=MAXIMUM_EVENTS,
            maximum_nodes=MAXIMUM_NODES,
            maximum_string_bytes=MAXIMUM_STRING_BYTES,
        ),
    )


def _rule_result(
    rule_id: str,
    status: str,
    summary: str,
    sequences: Iterable[int] = (),
) -> RoundTripRuleResult:
    title, _ = _RULES[rule_id]
    return RoundTripRuleResult(
        rule_id=rule_id,
        status=status,  # type: ignore[arg-type]
        title=title,
        summary=summary,
        event_sequences=sorted(set(sequences)),
    )


def _finding(
    rule_id: str,
    status: str,
    evidence: str,
    sequences: Iterable[int],
) -> RoundTripFinding:
    title, remediation = _RULES[rule_id]
    severity: FindingSeverity = "error" if status == "FAIL" else "warning" if status == "UNKNOWN" else "note"
    return RoundTripFinding(
        rule_id=rule_id,
        severity=severity,
        status=status,  # type: ignore[arg-type]
        title=title,
        evidence=evidence,
        remediation=remediation,
        event_sequences=sorted(set(sequences)),
    )


def _evaluate_profile(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    if not _request_events(trace):
        evidence = "The supported trace contains no client request to evaluate."
        return _rule_result("MCPRT000", "UNKNOWN", evidence), [_finding("MCPRT000", "UNKNOWN", evidence, ())]
    return _rule_result("MCPRT000", "PASS", "The strict supported trace profile was accepted."), []


def _request_events(trace: RoundTripTrace) -> list[TraceEvent]:
    return [event for event in trace.events if event.kind == "client_request"]


def _message_mapping(event: TraceEvent) -> Mapping[str, Any]:
    return event.message if event.message is not None else {}


def _params(event: TraceEvent) -> Mapping[str, Any]:
    value = _message_mapping(event).get("params")
    return value if isinstance(value, dict) else {}


def _meta(event: TraceEvent) -> Mapping[str, Any]:
    value = _params(event).get("_meta")
    return value if isinstance(value, dict) else {}


def _method(event: TraceEvent) -> str | None:
    value = _message_mapping(event).get("method")
    return value if isinstance(value, str) else None


def _message_id(event: TraceEvent) -> str | int | None:
    value = _message_mapping(event).get("id")
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    return value


def _id_key(value: str | int) -> tuple[str, str]:
    return ("int", str(value)) if isinstance(value, int) else ("str", value)


def _responses_by_id(trace: RoundTripTrace) -> dict[tuple[str, str], list[TraceEvent]]:
    output: dict[tuple[str, str], list[TraceEvent]] = {}
    for event in trace.events:
        if event.kind != "server_response":
            continue
        message_id = _message_id(event)
        if message_id is not None:
            output.setdefault(_id_key(message_id), []).append(event)
    return output


def _requests_by_id(trace: RoundTripTrace) -> dict[tuple[str, str], list[TraceEvent]]:
    output: dict[tuple[str, str], list[TraceEvent]] = {}
    for event in _request_events(trace):
        message_id = _message_id(event)
        if message_id is not None:
            output.setdefault(_id_key(message_id), []).append(event)
    return output


def _responses_after_request(
    response_map: Mapping[tuple[str, str], list[TraceEvent]],
    request: TraceEvent,
) -> list[TraceEvent]:
    message_id = _message_id(request)
    if message_id is None:
        return []
    return [
        response
        for response in response_map.get(_id_key(message_id), [])
        if response.sequence > request.sequence
    ]


def _origin_before_response(
    request_map: Mapping[tuple[str, str], list[TraceEvent]],
    response: TraceEvent,
) -> TraceEvent | None:
    message_id = _message_id(response)
    origins = request_map.get(_id_key(message_id), []) if message_id is not None else []
    return next(
        (request for request in reversed(origins) if request.sequence < response.sequence),
        None,
    )


def _response_is_explicit_version_rejection(
    event: TraceEvent,
    requested: str,
    *,
    require_http_status: bool,
) -> bool:
    message = _message_mapping(event)
    error = message.get("error")
    if not isinstance(error, dict) or error.get("code") != -32022:
        return False
    data = error.get("data")
    if not isinstance(data, dict):
        return False
    supported = data.get("supported")
    structured_rejection = (
        data.get("requested") == requested
        and isinstance(supported, list)
        and SUPPORTED_PROTOCOL_REVISION in supported
    )
    if not structured_rejection:
        return False
    return not require_http_status or (event.http is not None and event.http.status == 400)


def _evaluate_request_envelopes(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    requests = _request_events(trace)
    responses = _responses_by_id(trace)
    failures: list[int] = []
    for event in requests:
        meta = _meta(event)
        version = meta.get(_PROTOCOL_META)
        capabilities = meta.get(_CLIENT_CAPABILITIES_META)
        if not isinstance(version, str) or not isinstance(capabilities, dict):
            failures.append(event.sequence)
            continue
        if version == SUPPORTED_PROTOCOL_REVISION:
            continue
        candidates = _responses_after_request(responses, event)
        if not any(
            _response_is_explicit_version_rejection(
                item,
                version,
                require_http_status=trace.transport == "streamable-http",
            )
            for item in candidates
        ):
            failures.append(event.sequence)
    if failures:
        evidence = (
            "One or more requests omitted required metadata or used a mismatched version "
            "without an explicit rejection."
        )
        return _rule_result("MCPRT001", "FAIL", evidence, failures), [
            _finding("MCPRT001", "FAIL", evidence, failures)
        ]
    return _rule_result(
        "MCPRT001",
        "PASS",
        f"All {len(requests)} requests carried required metadata; any version mismatch was "
        "explicitly rejected.",
    ), []


def _evaluate_discovery(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    discover = [event for event in _request_events(trace) if _method(event) == "server/discover"]
    if not discover:
        return _rule_result(
            "MCPRT002",
            "NOT_APPLICABLE",
            "No optional server/discover exchange was supplied.",
        ), []
    responses = _responses_by_id(trace)
    failures: list[int] = []
    unknown: list[int] = []
    advertised: list[tuple[set[str], set[str], int]] = []
    for request in discover:
        message_id = _message_id(request)
        candidates = _responses_after_request(responses, request) if message_id is not None else []
        if not candidates:
            unknown.append(request.sequence)
            continue
        result = _message_mapping(candidates[0]).get("result")
        if not isinstance(result, dict):
            failures.append(candidates[0].sequence)
            continue
        versions = result.get("supportedVersions")
        capabilities = result.get("capabilities")
        if (
            not isinstance(versions, list)
            or not versions
            or not all(isinstance(item, str) for item in versions)
            or len(versions) != len(set(versions))
            or not isinstance(capabilities, dict)
        ):
            failures.append(candidates[0].sequence)
            continue
        request_version = _meta(request).get(_PROTOCOL_META)
        if not isinstance(request_version, str) or request_version not in versions:
            failures.extend((request.sequence, candidates[0].sequence))
        advertised.append((set(versions), set(capabilities), candidates[0].sequence))
    later_requests = [event for event in _request_events(trace) if _method(event) != "server/discover"]
    response_map = _responses_by_id(trace)
    for versions, capabilities, response_sequence in advertised:
        observed_later_behavior = False
        for event in later_requests:
            if event.sequence <= response_sequence:
                continue
            observed_later_behavior = True
            candidates = _responses_after_request(response_map, event)
            if not candidates:
                unknown.append(event.sequence)
                continue
            version = _meta(event).get(_PROTOCOL_META)
            succeeded = any("result" in _message_mapping(item) for item in candidates)
            version_rejected = isinstance(version, str) and any(
                _response_is_explicit_version_rejection(
                    item,
                    version,
                    require_http_status=trace.transport == "streamable-http",
                )
                for item in candidates
            )
            if isinstance(version, str):
                if version not in versions and succeeded:
                    failures.extend((response_sequence, event.sequence))
                if version in versions and version_rejected:
                    failures.extend((response_sequence, event.sequence))
            method = _method(event)
            family = method.split("/", 1)[0] if method and "/" in method else None
            required_capability = _CAPABILITY_FOR_METHOD.get(family or "")
            if required_capability is None:
                continue
            method_missing = any(
                isinstance(_message_mapping(item).get("error"), dict)
                and _message_mapping(item)["error"].get("code") == -32601
                for item in candidates
            )
            if succeeded and required_capability not in capabilities:
                failures.extend((response_sequence, event.sequence))
            if method_missing and required_capability in capabilities:
                failures.extend((response_sequence, event.sequence))
        if not observed_later_behavior:
            unknown.append(response_sequence)
    if failures:
        evidence = "A discovery advertisement conflicts with later version or capability behavior."
        return _rule_result("MCPRT002", "FAIL", evidence, failures), [
            _finding("MCPRT002", "FAIL", evidence, failures)
        ]
    if unknown:
        evidence = "A discovery or later behavior request has no observable response."
        return _rule_result("MCPRT002", "UNKNOWN", evidence, unknown), [
            _finding("MCPRT002", "UNKNOWN", evidence, unknown)
        ]
    return _rule_result(
        "MCPRT002",
        "PASS",
        "Observed discovery advertisements agree with later version and capability behavior.",
    ), []


def _decode_mirrored_header(value: str) -> str | None:
    match = _BASE64_SENTINEL.fullmatch(value)
    if match is None:
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value):
            return None
        return value
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


HeaderBinding = tuple[str, tuple[str, ...], str]


def _schema_header_bindings(schema: Any) -> list[HeaderBinding] | None:
    bindings: list[HeaderBinding] = []
    invalid = False

    def walk(node: Any, path: tuple[str, ...], reachable: bool) -> None:
        nonlocal invalid
        if isinstance(node, list):
            for child in node:
                walk(child, path, False)
            return
        if not isinstance(node, dict):
            return
        annotation = node.get("x-mcp-header")
        if annotation is not None:
            value_type = node.get("type")
            if (
                not reachable
                or not path
                or not isinstance(annotation, str)
                or _HEADER_TOKEN.fullmatch(annotation) is None
                or value_type not in {"string", "integer", "boolean"}
            ):
                invalid = True
            else:
                bindings.append((annotation, path, value_type))
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                walk(child, (*path, name), reachable and isinstance(name, str))
        for key, child in node.items():
            if key not in {"properties", "x-mcp-header"} and isinstance(child, (dict, list)):
                walk(child, path, False)

    walk(schema, (), True)
    names = [name.lower() for name, _, _ in bindings]
    if invalid or len(names) != len(set(names)):
        return None
    return bindings


def _tool_header_snapshots(
    trace: RoundTripTrace,
) -> dict[str, list[tuple[int, list[HeaderBinding] | None]]]:
    requests = _requests_by_id(trace)
    snapshots: dict[str, list[tuple[int, list[HeaderBinding] | None]]] = {}
    for response in trace.events:
        if response.kind != "server_response":
            continue
        origin = _origin_before_response(requests, response)
        if origin is None or _method(origin) != "tools/list":
            continue
        result = _message_mapping(response).get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        if not isinstance(tools, list):
            continue
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name")
            schema = tool.get("inputSchema")
            if isinstance(name, str) and isinstance(schema, dict):
                snapshots.setdefault(name, []).append((response.sequence, _schema_header_bindings(schema)))
    return snapshots


def _value_at_path(value: Any, path: tuple[str, ...]) -> tuple[bool, Any]:
    current = value
    for part in path:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _header_source_value(value: Any, value_type: str) -> str | None:
    if value_type == "string" and isinstance(value, str):
        return value
    if value_type == "boolean" and isinstance(value, bool):
        return "true" if value else "false"
    if value_type == "integer" and isinstance(value, int) and not isinstance(value, bool):
        if -(2**53) + 1 <= value <= 2**53 - 1:
            return str(value)
    return None


def _custom_headers_match(
    event: TraceEvent,
    headers: Mapping[str, str],
    snapshots: Mapping[str, list[tuple[int, list[HeaderBinding] | None]]],
) -> bool:
    if _method(event) != "tools/call":
        return True
    name = _params(event).get("name")
    if not isinstance(name, str) or name not in snapshots:
        return True
    prior = [item for item in snapshots[name] if item[0] < event.sequence]
    if not prior:
        return True
    bindings = max(prior, key=lambda item: item[0])[1]
    if bindings is None:
        return False
    arguments = _params(event).get("arguments")
    if not isinstance(arguments, dict):
        arguments = {}
    for header_name, path, value_type in bindings:
        mirrored = headers.get(f"mcp-param-{header_name.lower()}")
        present, value = _value_at_path(arguments, path)
        if not present or value is None:
            if mirrored is not None:
                return False
            continue
        source = _header_source_value(value, value_type)
        if source is None or mirrored is None or _decode_mirrored_header(mirrored) != source:
            return False
    return True


def _evaluate_http_mirroring(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    if trace.transport == "stdio":
        return _rule_result(
            "MCPRT003",
            "NOT_APPLICABLE",
            "HTTP metadata is not part of a stdio trace.",
        ), []
    failures: list[int] = []
    snapshots = _tool_header_snapshots(trace)
    for event in _request_events(trace):
        if event.http is None:
            failures.append(event.sequence)
            continue
        headers = {name.lower(): value for name, value in event.http.headers.items()}
        method = _method(event)
        version = _meta(event).get(_PROTOCOL_META)
        if headers.get("mcp-protocol-version") != version:
            failures.append(event.sequence)
            continue
        if method is None or headers.get("mcp-method") != method:
            failures.append(event.sequence)
            continue
        if method in _MRTR_METHODS:
            field = "uri" if method == "resources/read" else "name"
            source = _params(event).get(field)
            mirrored = headers.get("mcp-name")
            if not isinstance(source, str) or mirrored is None or _decode_mirrored_header(mirrored) != source:
                failures.append(event.sequence)
                continue
        if not _custom_headers_match(event, headers, snapshots):
            failures.append(event.sequence)
    if failures:
        evidence = (
            "Required Streamable HTTP metadata is missing, malformed, or differs from the JSON-RPC body."
        )
        return _rule_result("MCPRT003", "FAIL", evidence, failures), [
            _finding("MCPRT003", "FAIL", evidence, failures)
        ]
    return _rule_result(
        "MCPRT003",
        "PASS",
        "All observed HTTP request metadata agrees with the body source of truth.",
    ), []


def _salient_params(event: TraceEvent) -> dict[str, Any]:
    params = dict(_params(event))
    params.pop("_meta", None)
    params.pop("inputResponses", None)
    params.pop("requestState", None)
    return params


def _params_digest(event: TraceEvent) -> str:
    return hashlib.sha256(canonical_json_bytes(_salient_params(event))).hexdigest()


def _input_request_methods(
    result: Mapping[str, Any],
) -> tuple[set[str], set[str], bool]:
    input_requests = result.get("inputRequests")
    if input_requests is None:
        return set(), set(), True
    if not isinstance(input_requests, dict):
        return set(), set(), False
    keys: set[str] = set()
    methods: set[str] = set()
    for key, value in input_requests.items():
        if isinstance(key, str):
            keys.add(key)
        if not isinstance(value, dict) or not isinstance(value.get("method"), str):
            return keys, methods, False
        methods.add(value["method"])
    return keys, methods, True


def _matching_mrtr_retries(
    trace: RoundTripTrace,
    origin: TraceEvent,
    response: TraceEvent,
) -> list[TraceEvent]:
    result = _message_mapping(response).get("result")
    if not isinstance(result, dict):
        return []
    state = result.get("requestState")
    request_keys, _, input_requests_valid = _input_request_methods(result)
    if not input_requests_valid:
        return []
    output: list[TraceEvent] = []
    for candidate in _request_events(trace):
        if candidate.sequence <= response.sequence or _method(candidate) != _method(origin):
            continue
        params = _params(candidate)
        if state is not None and params.get("requestState") != state:
            continue
        if request_keys and "inputResponses" not in params:
            continue
        output.append(candidate)
    return output


def _evaluate_mrtr(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    failures: list[int] = [event.sequence for event in trace.events if event.kind == "server_request"]
    unknown: list[int] = []
    requests = _request_events(trace)
    response_map = _responses_by_id(trace)
    request_map = _requests_by_id(trace)
    for candidates in response_map.values():
        if len(candidates) > 1:
            failures.extend(item.sequence for item in candidates)
    breaks = [event for event in trace.events if event.kind == "stream_broken"]
    for request in requests:
        message_id = _message_id(request)
        if message_id is None:
            unknown.append(request.sequence)
            continue
        has_response = bool(_responses_after_request(response_map, request))
        has_later_break = any(
            item.sequence > request.sequence and item.request_id == message_id for item in breaks
        )
        if not has_response and not has_later_break:
            unknown.append(request.sequence)
    for response in [event for event in trace.events if event.kind == "server_response"]:
        message = _message_mapping(response)
        origin = _origin_before_response(request_map, response)
        if origin is None:
            unknown.append(response.sequence)
            continue
        if "error" in message:
            continue
        result = message.get("result")
        if not isinstance(result, dict):
            failures.append(response.sequence)
            continue
        result_type = result.get("resultType")
        if result_type not in {"complete", "input_required"}:
            failures.append(response.sequence)
            continue
        if result_type != "input_required":
            if "inputRequests" in result or "requestState" in result:
                failures.append(response.sequence)
            continue
        if _method(origin) not in _MRTR_METHODS:
            failures.extend((origin.sequence, response.sequence))
            continue
        request_keys, input_methods, input_requests_valid = _input_request_methods(result)
        state = result.get("requestState")
        if (
            not input_requests_valid
            or ("requestState" in result and not isinstance(state, str))
            or (not request_keys and not isinstance(state, str))
        ):
            failures.append(response.sequence)
            continue
        if any(method not in _CLIENT_CAPABILITY_FOR_INPUT for method in input_methods):
            failures.append(response.sequence)
        client_capabilities = _meta(origin).get(_CLIENT_CAPABILITIES_META)
        capability_names = set(client_capabilities) if isinstance(client_capabilities, dict) else set()
        for input_method in input_methods:
            required = _CLIENT_CAPABILITY_FOR_INPUT.get(input_method)
            if required is None:
                continue
            if required not in capability_names:
                failures.extend((origin.sequence, response.sequence))
        retries = _matching_mrtr_retries(trace, origin, response)
        if not retries:
            unknown.append(response.sequence)
            continue
        retry = retries[0]
        retry_id = _message_id(retry)
        origin_id = _message_id(origin)
        responses = _params(retry).get("inputResponses")
        if retry_id is None or retry_id == origin_id:
            failures.extend((origin.sequence, retry.sequence))
        if request_keys and (not isinstance(responses, dict) or set(responses) != request_keys):
            failures.extend((response.sequence, retry.sequence))
        if not request_keys and responses not in (None, {}):
            failures.extend((response.sequence, retry.sequence))
        if _params_digest(retry) != _params_digest(origin):
            failures.extend((origin.sequence, retry.sequence))
        if isinstance(state, str) and _params(retry).get("requestState") != state:
            failures.extend((response.sequence, retry.sequence))
    if failures:
        evidence = (
            "A resultType, MRTR request/response correlation, capability, method, or "
            "request-ID invariant failed."
        )
        return _rule_result("MCPRT004", "FAIL", evidence, failures), [
            _finding("MCPRT004", "FAIL", evidence, failures)
        ]
    if unknown:
        evidence = "A request, response, or MRTR retry is not fully correlated in the supplied trace."
        return _rule_result("MCPRT004", "UNKNOWN", evidence, unknown), [
            _finding("MCPRT004", "UNKNOWN", evidence, unknown)
        ]
    return _rule_result(
        "MCPRT004",
        "PASS",
        "All ordinary and interim results use valid discrimination and observed MRTR rounds correlate.",
    ), []


def _state_witness(
    trace: RoundTripTrace,
    state: str,
) -> RequestStateWitness | None:
    digest = hashlib.sha256(state.encode("utf-8")).hexdigest()
    return next((item for item in trace.witnesses if item.state_sha256 == digest), None)


def _evaluate_request_state(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    request_map = _requests_by_id(trace)
    issued: list[tuple[str, TraceEvent, TraceEvent]] = []
    for response in trace.events:
        if response.kind != "server_response":
            continue
        result = _message_mapping(response).get("result")
        state = result.get("requestState") if isinstance(result, dict) else None
        origin = _origin_before_response(request_map, response)
        if isinstance(state, str) and origin is not None:
            issued.append((state, origin, response))
    if not issued:
        return _rule_result(
            "MCPRT005",
            "NOT_APPLICABLE",
            "No observable requestState round trip was supplied.",
        ), []
    failures: list[int] = []
    unknown: list[int] = []
    for state, origin, response in issued:
        retries = [
            event
            for event in _request_events(trace)
            if event.sequence > response.sequence and _params(event).get("requestState") == state
        ]
        if not retries:
            unknown.append(response.sequence)
            continue
        for retry in retries:
            if (
                retry.principal != origin.principal
                or _method(retry) != _method(origin)
                or _params_digest(retry) != _params_digest(origin)
            ):
                failures.extend((origin.sequence, retry.sequence))
        witness = _state_witness(trace, state)
        if witness is None:
            unknown.extend((response.sequence, *(item.sequence for item in retries)))
            continue
        for retry in retries:
            if retry.observed_at > witness.expires_at:
                failures.extend((response.sequence, retry.sequence))
        if not (
            witness.integrity_verified
            and witness.principal_binding_verified
            and witness.method_binding_verified
            and witness.parameters_binding_verified
        ):
            failures.append(response.sequence)
    if failures:
        evidence = (
            "Observable requestState use crossed a bound principal, method, parameter, "
            "expiry, or trusted-witness boundary."
        )
        findings = [_finding("MCPRT005", "FAIL", evidence, failures)]
        if unknown:
            findings.append(
                _finding(
                    "MCPRT005",
                    "UNKNOWN",
                    "Cryptographic protection remains unobservable for requestState values "
                    "without a matching trusted witness.",
                    unknown,
                )
            )
        return _rule_result("MCPRT005", "FAIL", evidence, failures), findings
    if unknown:
        evidence = (
            "Observable replay boundaries are consistent, but cryptographic protection or "
            "completion is not witnessed."
        )
        return _rule_result("MCPRT005", "UNKNOWN", evidence, unknown), [
            _finding("MCPRT005", "UNKNOWN", evidence, unknown)
        ]
    return _rule_result(
        "MCPRT005",
        "PASS",
        "Observable state boundaries and the explicit trusted witness agree.",
    ), []


def _evaluate_stream_retries(
    trace: RoundTripTrace,
) -> tuple[RoundTripRuleResult, list[RoundTripFinding]]:
    requests = _request_events(trace)
    ids = [_id_key(value) for event in requests if (value := _message_id(event)) is not None]
    duplicate_ids = {item for item, count in Counter(ids).items() if count > 1}
    failures = [
        event.sequence
        for event in requests
        if (value := _message_id(event)) is not None and _id_key(value) in duplicate_ids
    ]
    unknown: list[int] = []
    breaks = [event for event in trace.events if event.kind == "stream_broken"]
    if failures:
        evidence = "A client request ID was reused, including on a broken-stream retry."
        return _rule_result("MCPRT006", "FAIL", evidence, failures), [
            _finding("MCPRT006", "FAIL", evidence, failures)
        ]
    if trace.transport == "stdio":
        if breaks:
            evidence = "Broken response stream events are unsupported for stdio traces."
            sequences = [item.sequence for item in breaks]
            return _rule_result("MCPRT006", "UNSUPPORTED", evidence, sequences), [
                _finding("MCPRT006", "UNSUPPORTED", evidence, sequences)
            ]
        return _rule_result(
            "MCPRT006",
            "NOT_APPLICABLE",
            "Broken HTTP response streams are not part of a stdio trace.",
        ), []
    for broken in breaks:
        origins = [
            event
            for event in requests
            if event.sequence < broken.sequence and _message_id(event) == broken.request_id
        ]
        if not origins:
            unknown.append(broken.sequence)
            continue
        retries = [
            event
            for event in requests
            if event.sequence > broken.sequence and event.retry_of == broken.request_id
        ]
        if not retries:
            unknown.append(broken.sequence)
            continue
        for retry in retries:
            retry_id = _message_id(retry)
            if retry_id is None or retry_id == broken.request_id:
                failures.extend((broken.sequence, retry.sequence))
    if failures:
        evidence = "A broken-stream retry reused its interrupted request ID."
        return _rule_result("MCPRT006", "FAIL", evidence, failures), [
            _finding("MCPRT006", "FAIL", evidence, failures)
        ]
    if unknown:
        evidence = "A broken response stream has no correlated retry in the supplied trace."
        return _rule_result("MCPRT006", "UNKNOWN", evidence, unknown), [
            _finding("MCPRT006", "UNKNOWN", evidence, unknown)
        ]
    if not breaks:
        return _rule_result(
            "MCPRT006",
            "NOT_APPLICABLE",
            "No broken response stream was supplied and request IDs were unique.",
        ), []
    return _rule_result(
        "MCPRT006",
        "PASS",
        "Every observed broken-stream retry used a fresh request ID.",
    ), []
