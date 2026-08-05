"""Deterministic offline review of McpAuthorizationPostureV1 JSON."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Never

from pydantic import ValidationError

from mcp_audit.authorization_posture_models import (
    MAX_AUTHORIZATION_SERVERS,
    MAX_FETCHES,
    MAX_URL_LENGTH,
    SPEC_REFERENCES,
    AuthorizationPostureAuthorityFlow,
    AuthorizationPostureFinding,
    AuthorizationPostureParserLimits,
    AuthorizationPostureReport,
    AuthorizationServerSummary,
    McpAuthorizationPostureV1,
    canonical_json_bytes,
    sha256_bytes,
)

MAX_INPUT_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4_096

_SUPPORTED_INPUTS = [
    "One bounded JSON object conforming exactly to McpAuthorizationPostureV1 contract version 1.0.0.",
    "Credential-free public MCP protected-resource and authorization-server metadata posture "
    "declared by the producer.",
    "Metadata-ready and fail-closed unknown outcomes bound to one saved official Registry manifest digest.",
]

_UNSUPPORTED_INPUTS = [
    "URLs, Registry records, metadata endpoints, authorization servers, MCP servers, browsers, "
    "and DNS are never contacted.",
    "Credentials, OAuth flows, authorization codes, tokens, cookies, keychains, accounts, "
    "endpoint sessions, and private transcripts are unsupported.",
    "The input file is not authenticated as an mcp-trust artifact; its declared producer "
    "observations and timestamp remain unverified.",
    "Metadata posture cannot authorize a scan, prove authorization or runtime security, or "
    "change a trust grade.",
]

_CLAIM_CEILING = [
    "The supplied JSON is structurally consistent with McpAuthorizationPostureV1 version 1.0.0 "
    "and has been projected deterministically.",
    "A metadata-ready result means policy review only; it does not authorize endpoint contact "
    "or an authenticated scan.",
    "The consumer does not authenticate producer provenance, remote observations, timestamps, "
    "metadata bodies, or the current freshness of a saved posture.",
    "Authorization, credential availability, runtime security, trust grade, deployment, "
    "adoption, and production safety remain unproved.",
]

_ASSUMPTIONS = [
    "The input was intentionally supplied by the operator as public, credential-free posture evidence.",
    "The declared Registry binding and remote observations are producer assertions, not "
    "independently re-fetched by MCPAudit.",
    "Unknown, malformed, widened, or internally inconsistent evidence must not become "
    "policy-review eligibility.",
]


class AuthorizationPostureInputError(ValueError):
    """The posture artifact could not be safely accepted."""


def _reject_json_constant(_value: str) -> Never:
    raise ValueError("unsupported JSON constant")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


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
            if depth > MAX_JSON_DEPTH:
                raise AuthorizationPostureInputError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def _count_json_nodes(value: Any, *, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise AuthorizationPostureInputError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
    count = 1
    children: list[Any]
    if isinstance(value, dict):
        children = list(value.values())
    elif isinstance(value, list):
        children = value
    else:
        children = []
    for child in children:
        count += _count_json_nodes(child, depth=depth + 1)
        if count > MAX_JSON_NODES:
            raise AuthorizationPostureInputError(f"JSON structure exceeds {MAX_JSON_NODES} nodes")
    return count


def _read_posture_bytes(path: Path) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AuthorizationPostureInputError("cannot inspect posture input") from exc
    if not stat.S_ISREG(before.st_mode):
        raise AuthorizationPostureInputError("posture input must be a regular non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthorizationPostureInputError("posture input must be a regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AuthorizationPostureInputError("posture input must be a regular non-symlink file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AuthorizationPostureInputError("posture input changed while it was opened")
        if opened.st_size > MAX_INPUT_BYTES:
            raise AuthorizationPostureInputError(f"posture input exceeds {MAX_INPUT_BYTES} bytes")
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
            raise AuthorizationPostureInputError(f"posture input exceeds {MAX_INPUT_BYTES} bytes")
        return raw, (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)


def parse_authorization_posture_bytes(raw: bytes) -> McpAuthorizationPostureV1:
    """Parse one bounded posture artifact without reflecting untrusted values."""
    if len(raw) > MAX_INPUT_BYTES:
        raise AuthorizationPostureInputError(f"posture input exceeds {MAX_INPUT_BYTES} bytes")
    _validate_json_nesting(raw)
    parse_error: str | None = None
    payload: Any = None
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        parse_error = f"invalid JSON posture: {type(exc).__name__}"
    if parse_error is not None:
        raise AuthorizationPostureInputError(parse_error)
    _count_json_nodes(payload)
    validation_error: str | None = None
    try:
        return McpAuthorizationPostureV1.model_validate(payload, strict=True)
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False)[0]
        validation_error = f"posture schema validation failed: {first.get('type', 'invalid')}"
    raise AuthorizationPostureInputError(validation_error or "posture schema validation failed")


def parse_authorization_posture_path(
    path: Path,
) -> tuple[McpAuthorizationPostureV1, bytes, tuple[int, int]]:
    raw, identity = _read_posture_bytes(path)
    return parse_authorization_posture_bytes(raw), raw, identity


def _finding(posture: McpAuthorizationPostureV1) -> AuthorizationPostureFinding:
    ready = sum(item.state == "metadata-ready" for item in posture.authorization_servers)
    declared = len(posture.authorization_servers)
    if posture.state == "metadata-ready":
        return AuthorizationPostureFinding(
            rule_id="MCPPOSTURE001",
            severity="low",
            outcome="advisory",
            title="Declared public authorization metadata is ready for policy review",
            target="authorization-metadata-posture",
            evidence=[
                f"metadata-ready authorization servers: {ready} of {declared} declared",
                "the protected-resource metadata is bound to the selected Registry resource",
                "the producer capability and claim ceilings remain credential-free and non-authoritative",
            ],
            remediation=(
                "Perform an explicit operator policy review before any separately authorized endpoint "
                "or OAuth workflow."
            ),
            references=SPEC_REFERENCES,
            assumptions=_ASSUMPTIONS,
        )
    return AuthorizationPostureFinding(
        rule_id="MCPPOSTURE000",
        severity="unknown",
        outcome="unknown",
        title="Authorization metadata posture is incomplete or unavailable",
        target="authorization-metadata-posture",
        evidence=[f"producer reason code: {reason}" for reason in posture.reason_codes],
        remediation=(
            "Keep endpoint contact and authenticated scanning blocked until a current, valid producer "
            "artifact reaches metadata-ready and passes policy review."
        ),
        references=SPEC_REFERENCES,
        assumptions=_ASSUMPTIONS,
    )


def review_authorization_posture(
    posture: McpAuthorizationPostureV1,
    input_sha256: str,
) -> AuthorizationPostureReport:
    """Project producer metadata posture without adding authority or network effects."""
    ready = sum(item.state == "metadata-ready" for item in posture.authorization_servers)
    metadata_ready = posture.state == "metadata-ready"
    return AuthorizationPostureReport(
        input_sha256=input_sha256,
        observed_at=posture.observed_at,
        binding=posture.binding,
        disposition="policy-review-only" if metadata_ready else "blocked",
        metadata_state=("producer-declared-ready" if metadata_ready else "producer-declared-unknown"),
        authorization_servers=AuthorizationServerSummary(
            declared=len(posture.authorization_servers),
            metadata_ready=ready,
        ),
        reason_codes=posture.reason_codes,
        findings=[_finding(posture)],
        authority_flow=AuthorizationPostureAuthorityFlow(
            input_provenance="unverified",
            input_freshness="unverified",
            remote_observation_authority="producer-asserted",
            consumer_decision_authority="operator-policy-review",
            network_used=False,
            credentials_used=False,
            endpoint_session_used=False,
            scan_authorized=False,
            trust_grade_changed=False,
        ),
        parser_limits=AuthorizationPostureParserLimits(
            input_bytes=MAX_INPUT_BYTES,
            json_depth=MAX_JSON_DEPTH,
            json_nodes=MAX_JSON_NODES,
            authorization_servers=MAX_AUTHORIZATION_SERVERS,
            fetches=MAX_FETCHES,
            url_length=MAX_URL_LENGTH,
        ),
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def review_authorization_posture_path(
    path: Path,
) -> AuthorizationPostureReport:
    report, _ = review_authorization_posture_path_with_identity(path)
    return report


def review_authorization_posture_path_with_identity(
    path: Path,
) -> tuple[AuthorizationPostureReport, tuple[int, int]]:
    posture, raw, identity = parse_authorization_posture_path(path)
    return review_authorization_posture(posture, sha256_bytes(raw)), identity


def report_json_bytes(report: AuthorizationPostureReport) -> bytes:
    return canonical_json_bytes(report)
