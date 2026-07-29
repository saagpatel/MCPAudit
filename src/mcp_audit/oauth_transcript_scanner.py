"""Deterministic offline analysis for synthetic MCP OAuth transcript fixtures."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Never, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import ValidationError

from mcp_audit.oauth_transcript_models import (
    MAX_OBSERVATIONS,
    MAX_URL_LENGTH,
    AudienceEvidenceSource,
    AuthorizationRequest,
    AuthorizationResponse,
    AuthorizationServerMetadata,
    ClientKind,
    DocumentState,
    EvidenceState,
    FindingOutcome,
    FindingSeverity,
    MetadataKind,
    OAuthTranscriptFinding,
    OAuthTranscriptFixture,
    OAuthTranscriptReport,
    ParserLimits,
    ProtectedResourceChallenge,
    ProtectedResourceMetadata,
    ProtectedResourceUse,
    RegistrationMethod,
    RequirementLevel,
    ResponseHandling,
    TokenRequest,
    TokenResponse,
    canonical_json_bytes,
    sha256_bytes,
)

MAX_INPUT_BYTES = 1_048_576
MAX_JSON_DEPTH = 32
MAX_METADATA_DOCUMENTS = 8
MAX_REDIRECTS = 5

_SUPPORTED_INPUTS = [
    "One strict, program-owned synthetic transcript using mcpaudit.oauth-transcript.fixture.v1.",
    "Normalized HTTP observations for MCP 401 discovery, protected-resource metadata, authorization "
    "server metadata, authorization, token exchange, and protected-resource use.",
    "Redacted issuer-bound registration state and synthetic JWT-claim or introspection audience evidence.",
]

_UNSUPPORTED_INPUTS = [
    "Live HTTP, DNS, browsers, OAuth or MCP connections, authorization servers, identity providers, "
    "accounts, keychains, cookies, credential stores, and private transcripts.",
    "Token signature or cryptographic validation, PKCE correctness, client-authentication strength, "
    "identity-provider compromise resistance, consent, or production authorization.",
    "Arbitrary HTTP bodies, unredacted authorization codes or tokens, redirects beyond the recorded "
    "bounded observations, and URL fetching of any kind.",
    "Authorization-server mappings from resource indicators to general or abstract token audiences; "
    "such fixtures must mark audience evidence unverifiable.",
]

_CLAIM_CEILING = [
    "The supplied synthetic transcript satisfies or violates only the implemented observable MCP/OAuth "
    "binding invariants.",
    "A clean report does not establish token authenticity, PKCE correctness, client authentication "
    "strength, identity-provider security, consent, real-world authorization, or production safety.",
    "Audience evidence is treated as a supplied synthetic observation; JWT signatures and introspection "
    "server authenticity are not validated.",
    "Incomplete, redacted, malformed, unsupported, or unverifiable binding evidence remains UNKNOWN.",
]

_ASSUMPTIONS = [
    "Every observation is program-owned, synthetic, redacted, and ordered exactly as recorded.",
    "Issuer comparison uses exact string equality; resource comparison only tolerates scheme and host case.",
    "No URL, endpoint, metadata location, redirect, or credential reference found in the fixture is used.",
    "Current audience evidence uses exact resource-URI audiences; authorization-server audience mappings "
    "are unsupported rather than inferred.",
]


@dataclass(frozen=True)
class RuleDefinition:
    severity: FindingSeverity
    requirement_level: RequirementLevel
    title: str
    remediation: str
    references: tuple[str, ...]


_RULES: dict[str, RuleDefinition] = {
    "MCPOAUTH000": RuleDefinition(
        FindingSeverity.UNKNOWN,
        RequirementLevel.UNSUPPORTED,
        "Incomplete or unverifiable OAuth transcript evidence",
        "Supply a complete redacted synthetic observation for the missing binding; do not infer a pass.",
        (
            "MCP Authorization 2025-11-25",
            "RFC 9728 Sections 3.3 and 5",
        ),
    ),
    "MCPOAUTH001": RuleDefinition(
        FindingSeverity.HIGH,
        RequirementLevel.REQUIRED,
        "Discovery chain is stale, incomplete, or bound to the wrong authority",
        "Use the latest 401 resource_metadata location, validate the protected resource identity, and "
        "validate authorization-server metadata against the selected issuer before authorization.",
        (
            "MCP Authorization 2025-11-25: Authorization Server Discovery",
            "RFC 9728 Sections 3.3, 5.1, and 5.2",
            "RFC 8414 Section 3.3",
        ),
    ),
    "MCPOAUTH002": RuleDefinition(
        FindingSeverity.HIGH,
        RequirementLevel.REQUIRED,
        "Resource indicator or returned audience is bound to the wrong protected resource",
        "Send the canonical MCP resource in authorization and token requests and reject token evidence "
        "unless the protected resource is an observed intended audience.",
        (
            "MCP Authorization 2025-11-25: Resource Parameter Implementation",
            "MCP Authorization 2025-11-25: Token Audience Binding and Validation",
            "RFC 8707 Section 2",
        ),
    ),
    "MCPOAUTH003": RuleDefinition(
        FindingSeverity.HIGH,
        RequirementLevel.REQUIRED,
        "Authorization response issuer was not safely bound before code redemption",
        "Record the validated issuer per request, compare every present or advertised-required iss value "
        "with exact string equality, and reject mismatches before sending the code to a token endpoint.",
        (
            "MCP Authorization draft retrieved 2026-07-28: Authorization Response Validation",
            "RFC 9207 Sections 2.3 and 2.4",
        ),
    ),
    "MCPOAUTH004": RuleDefinition(
        FindingSeverity.HIGH,
        RequirementLevel.REQUIRED,
        "Issuer-bound client credentials were reused for another authorization server",
        "Key persisted pre-registered, dynamically registered, and user-supplied client state by the "
        "validated issuer and re-register or stop when protected-resource metadata selects another issuer.",
        (
            "MCP Authorization draft retrieved 2026-07-28: Authorization Server Binding",
            "RFC 6749 Section 2.2",
            "RFC 7591 Sections 1 and 3.2.1",
        ),
    ),
    "MCPOAUTH005": RuleDefinition(
        FindingSeverity.MEDIUM,
        RequirementLevel.REQUIRED,
        "Client registration selection or application type is incompatible",
        "Use pre-registration first when available, otherwise CIMD when advertised, and use DCR only as "
        "a supported deprecated fallback with the client kind's appropriate application_type.",
        (
            "MCP Authorization 2025-11-25: Client Registration Approaches",
            "MCP Authorization draft retrieved 2026-07-28: Client Registration",
            "OpenID Connect Dynamic Client Registration 1.0 Section 2",
        ),
    ),
    "MCPOAUTH006": RuleDefinition(
        FindingSeverity.MEDIUM,
        RequirementLevel.RECOMMENDED,
        "Requested or returned scopes do not preserve the challenged resource boundary",
        "Treat the current resource challenge as authoritative, retain previously granted scopes only "
        "during reauthorization, and do not silently widen or drop the resulting scope set.",
        (
            "MCP Authorization 2025-11-25: Scope Selection Strategy",
            "MCP Authorization draft retrieved 2026-07-28: Scope Selection Strategy",
            "RFC 6750 Section 3",
        ),
    ),
}

_SEVERITY_ORDER = {
    FindingSeverity.HIGH: 0,
    FindingSeverity.MEDIUM: 1,
    FindingSeverity.LOW: 2,
    FindingSeverity.UNKNOWN: 3,
}
_OUTCOME_ORDER = {
    FindingOutcome.VIOLATION: 0,
    FindingOutcome.UNKNOWN: 1,
    FindingOutcome.ADVISORY: 2,
}

_SENSITIVE_KEYS = {
    "access_token",
    "authorization",
    "authorization_code",
    "client_assertion",
    "client_secret",
    "code",
    "cookie",
    "id_token",
    "refresh_token",
    "registration_access_token",
    "set-cookie",
}
_ALLOWED_MARKERS = {"<redacted>", "SYNTHETIC_CLIENT_ID"}
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"(?i)\b(?:sk|ghp|xox[baprs])[-_][A-Za-z0-9_-]{8,}"),
    re.compile(r"[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"SYNTHETIC_SECRET_DO_NOT_LEAK[A-Za-z0-9_-]*"),
)


class OAuthTranscriptInputError(ValueError):
    """The input could not be safely parsed as a redacted synthetic fixture."""


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"unsupported JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


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
                raise OAuthTranscriptInputError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def _reject_credential_looking_values(value: Any, key: str | None = None) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            _reject_credential_looking_values(child_value, child_key.lower())
        return
    if isinstance(value, list):
        for child in value:
            _reject_credential_looking_values(child, key)
        return
    if not isinstance(value, str):
        return
    if key in _SENSITIVE_KEYS and value not in _ALLOWED_MARKERS:
        raise OAuthTranscriptInputError(
            "credential-looking input rejected; sensitive values must be redacted"
        )
    if value not in _ALLOWED_MARKERS and any(pattern.search(value) for pattern in _CREDENTIAL_PATTERNS):
        raise OAuthTranscriptInputError(
            "credential-looking input rejected; sensitive values must be redacted"
        )


def _validation_evidence(exc: ValidationError) -> str:
    error = exc.errors(include_input=False, include_url=False)[0]
    return f"schema validation failed: {error.get('type', 'invalid')}"


def _read_fixture_bytes(path: Path) -> tuple[bytes, tuple[int, int]]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise OAuthTranscriptInputError("cannot inspect input fixture") from exc
    if not stat.S_ISREG(before.st_mode):
        raise OAuthTranscriptInputError("input fixture must be a regular non-symlink file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OAuthTranscriptInputError("input fixture must be a regular non-symlink file") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise OAuthTranscriptInputError("input fixture must be a regular non-symlink file")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OAuthTranscriptInputError("input fixture changed while it was being opened")
        if opened.st_size > MAX_INPUT_BYTES:
            raise OAuthTranscriptInputError(f"input fixture exceeds {MAX_INPUT_BYTES} bytes")
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
            raise OAuthTranscriptInputError(f"input fixture exceeds {MAX_INPUT_BYTES} bytes")
        return raw, (opened.st_dev, opened.st_ino)
    finally:
        os.close(descriptor)


def parse_oauth_transcript_bytes(raw: bytes) -> OAuthTranscriptFixture:
    """Parse one bounded fixture without reflecting its values in errors."""
    if len(raw) > MAX_INPUT_BYTES:
        raise OAuthTranscriptInputError(f"input fixture exceeds {MAX_INPUT_BYTES} bytes")
    _validate_json_nesting(raw)
    try:
        payload = json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise OAuthTranscriptInputError(f"invalid JSON fixture: {type(exc).__name__}") from exc
    _reject_credential_looking_values(payload)
    try:
        return OAuthTranscriptFixture.model_validate(payload, strict=True)
    except ValidationError as exc:
        raise OAuthTranscriptInputError(_validation_evidence(exc)) from exc


def parse_oauth_transcript_path(path: Path) -> tuple[OAuthTranscriptFixture, bytes, tuple[int, int]]:
    raw, identity = _read_fixture_bytes(path)
    return parse_oauth_transcript_bytes(raw), raw, identity


def _finding(
    rule_id: str,
    *,
    target: str,
    evidence: Iterable[str],
    outcome: FindingOutcome = FindingOutcome.VIOLATION,
    severity: FindingSeverity | None = None,
    requirement_level: RequirementLevel | None = None,
) -> OAuthTranscriptFinding:
    definition = _RULES[rule_id]
    return OAuthTranscriptFinding(
        rule_id=cast(Any, rule_id),
        severity=severity or definition.severity,
        outcome=outcome,
        requirement_level=requirement_level or definition.requirement_level,
        title=definition.title,
        target=target,
        evidence=sorted(set(evidence)),
        remediation=definition.remediation,
        references=list(definition.references),
        assumptions=_ASSUMPTIONS,
    )


def _unknown(target: str, evidence: str) -> OAuthTranscriptFinding:
    return _finding(
        "MCPOAUTH000",
        target=target,
        evidence=[evidence],
        outcome=FindingOutcome.UNKNOWN,
    )


def _resource_key(value: str) -> tuple[str, str, int | None, str, str]:
    parsed = urlsplit(value)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port,
        parsed.path,
        parsed.query,
    )


def _resource_equal(first: str, second: str) -> bool:
    return _resource_key(first) == _resource_key(second)


def _metadata_candidates(issuer: str) -> dict[MetadataKind, set[str]]:
    parsed = urlsplit(issuer)
    base = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    issuer_path = parsed.path.rstrip("/")
    suffix = issuer_path.lstrip("/")
    oauth_path = "/.well-known/oauth-authorization-server"
    oidc_inserted = "/.well-known/openid-configuration"
    if suffix:
        oauth_path = f"{oauth_path}/{suffix}"
        oidc_inserted = f"{oidc_inserted}/{suffix}"
    oidc_appended = f"{issuer_path}/.well-known/openid-configuration"
    return {
        MetadataKind.OAUTH: {f"{base}{oauth_path}"},
        MetadataKind.OPENID_CONNECT: {f"{base}{oidc_inserted}", f"{base}{oidc_appended}"},
    }


@dataclass
class Flow:
    authorization_request: AuthorizationRequest | None
    authorization_response: AuthorizationResponse | None
    token_request: TokenRequest | None
    token_response: TokenResponse | None
    challenge: ProtectedResourceChallenge | None
    resource_metadata: ProtectedResourceMetadata | None
    authorization_metadata: AuthorizationServerMetadata | None
    resource_uses: list[ProtectedResourceUse]


def _flow(fixture: OAuthTranscriptFixture) -> Flow:
    authorization_requests = [item for item in fixture.observations if isinstance(item, AuthorizationRequest)]
    authorization_request = authorization_requests[0] if authorization_requests else None
    authorization_responses = [
        item for item in fixture.observations if isinstance(item, AuthorizationResponse)
    ]
    authorization_response = authorization_responses[0] if authorization_responses else None
    token_requests = [item for item in fixture.observations if isinstance(item, TokenRequest)]
    token_request = token_requests[0] if token_requests else None
    token_responses = [item for item in fixture.observations if isinstance(item, TokenResponse)]
    token_response = token_responses[0] if token_responses else None
    authorization_sequence = authorization_request.sequence if authorization_request is not None else 257
    challenges = [
        item
        for item in fixture.observations
        if isinstance(item, ProtectedResourceChallenge) and item.sequence < authorization_sequence
    ]
    challenge = challenges[-1] if challenges else None
    resource_metadata_items = [
        item
        for item in fixture.observations
        if isinstance(item, ProtectedResourceMetadata) and item.sequence < authorization_sequence
    ]
    resource_metadata: ProtectedResourceMetadata | None = None
    if challenge is not None and challenge.resource_metadata_url is not None:
        matching = [
            item
            for item in resource_metadata_items
            if item.sequence > challenge.sequence and item.request_url == challenge.resource_metadata_url
        ]
        if matching:
            resource_metadata = matching[-1]
    if resource_metadata is None and resource_metadata_items:
        resource_metadata = resource_metadata_items[-1]
    authorization_metadata_items = [
        item
        for item in fixture.observations
        if isinstance(item, AuthorizationServerMetadata) and item.sequence < authorization_sequence
    ]
    authorization_metadata = authorization_metadata_items[-1] if authorization_metadata_items else None
    resource_uses = [item for item in fixture.observations if isinstance(item, ProtectedResourceUse)]
    return Flow(
        authorization_request=authorization_request,
        authorization_response=authorization_response,
        token_request=token_request,
        token_response=token_response,
        challenge=challenge,
        resource_metadata=resource_metadata,
        authorization_metadata=authorization_metadata,
        resource_uses=resource_uses,
    )


def _evaluate_structure(fixture: OAuthTranscriptFixture, flow: Flow) -> list[OAuthTranscriptFinding]:
    required_types = (
        (AuthorizationRequest, "authorization request"),
        (AuthorizationResponse, "authorization response"),
        (TokenRequest, "token request"),
        (TokenResponse, "token response"),
    )
    evidence: list[str] = []
    for observation_type, label in required_types:
        count = sum(isinstance(item, observation_type) for item in fixture.observations)
        if count > 1:
            evidence.append(f"multiple {label} observations make the evaluated flow ambiguous")
    ordered = (
        flow.authorization_request,
        flow.authorization_response,
        flow.token_request,
        flow.token_response,
    )
    if all(item is not None for item in ordered):
        sequences = [item.sequence for item in ordered if item is not None]
        if sequences != sorted(sequences):
            evidence.append("authorization and token observations are not in protocol order")
    if flow.token_response is not None and fixture.audience_evidence.state == EvidenceState.CURRENT.value:
        if fixture.audience_evidence.token_response_exchange_id != flow.token_response.exchange_id:
            evidence.append("current audience evidence is not bound to the observed token response")
    if flow.token_response is None and fixture.audience_evidence.state == EvidenceState.CURRENT.value:
        evidence.append("current audience evidence has no observed token response")
    if (
        flow.authorization_response is not None
        and flow.authorization_response.handling == ResponseHandling.ACCEPTED.value
        and flow.authorization_response.code_marker is None
    ):
        evidence.append("an accepted authorization response has no redacted code evidence")
    if flow.token_response is not None:
        successful_token_response = 200 <= flow.token_response.response_status < 300
        if successful_token_response and flow.token_response.access_token_marker is None:
            evidence.append("a successful token response has no redacted access-token evidence")
        if not successful_token_response and flow.token_response.access_token_marker is not None:
            evidence.append("a failed token response contains contradictory access-token evidence")
        if fixture.audience_evidence.state == EvidenceState.CURRENT.value and not successful_token_response:
            evidence.append("current audience evidence is bound to an unsuccessful token response")
        if any(item.sequence <= flow.token_response.sequence for item in flow.resource_uses):
            evidence.append("protected-resource token use is not ordered after the token response")
    return [_unknown("transcript-structure", item) for item in evidence]


def _evaluate_discovery(fixture: OAuthTranscriptFixture, flow: Flow) -> list[OAuthTranscriptFinding]:
    unknown_evidence: list[str] = []
    violations: list[str] = []
    challenge = flow.challenge
    metadata = flow.resource_metadata
    authority = flow.authorization_metadata
    if challenge is None:
        unknown_evidence.append("no pre-authorization 401 challenge observation is available")
    else:
        if not _resource_equal(challenge.request_url, fixture.intended_resource):
            violations.append("the latest 401 challenge belongs to a different protected resource")
        if challenge.resource_metadata_url is None:
            unknown_evidence.append("the 401 challenge omits or redacts resource_metadata")
    if metadata is None:
        unknown_evidence.append("no protected-resource metadata observation is available")
    elif challenge is not None:
        if (
            challenge.resource_metadata_url is not None
            and metadata.request_url != challenge.resource_metadata_url
        ):
            violations.append("protected-resource metadata was read from a stale or unchallenged location")
        if metadata.document_state != DocumentState.COMPLETE.value:
            unknown_evidence.append("protected-resource metadata is malformed, missing, or redacted")
        elif metadata.response_status != 200:
            violations.append("protected-resource metadata did not return a successful document")
        else:
            if metadata.resource is None:
                unknown_evidence.append("protected-resource metadata omits the resource identifier")
            elif metadata.resource != challenge.request_url:
                violations.append(
                    "protected-resource metadata resource does not exactly match the challenged URL"
                )
            if not metadata.authorization_servers:
                unknown_evidence.append("protected-resource metadata has no authorization server")
            elif fixture.intended_authorization_server not in metadata.authorization_servers:
                violations.append("selected authorization server is absent from protected-resource metadata")
    if authority is None:
        unknown_evidence.append("no authorization-server metadata observation is available")
    elif authority.document_state != DocumentState.COMPLETE.value:
        unknown_evidence.append("authorization-server metadata is malformed, missing, or redacted")
    elif authority.response_status != 200:
        violations.append("authorization-server metadata did not return a successful document")
    else:
        if authority.issuer is None:
            unknown_evidence.append("authorization-server metadata omits issuer")
        elif authority.issuer != fixture.intended_authorization_server:
            violations.append("authorization-server metadata issuer differs from the selected issuer")
        metadata_kind = MetadataKind(authority.metadata_kind)
        allowed = _metadata_candidates(fixture.intended_authorization_server)[metadata_kind]
        if authority.request_url not in allowed:
            violations.append("authorization-server metadata URL is not a supported issuer-derived endpoint")
        if authority.authorization_endpoint is None or authority.token_endpoint is None:
            unknown_evidence.append("authorization-server metadata omits an endpoint needed by the flow")
        if (
            flow.authorization_request is not None
            and authority.authorization_endpoint is not None
            and flow.authorization_request.request_url != authority.authorization_endpoint
        ):
            violations.append("authorization request endpoint differs from validated server metadata")
        if (
            flow.token_request is not None
            and authority.token_endpoint is not None
            and flow.token_request.request_url != authority.token_endpoint
        ):
            violations.append("token request endpoint differs from validated server metadata")
    findings: list[OAuthTranscriptFinding] = []
    if violations:
        findings.append(_finding("MCPOAUTH001", target="discovery-chain", evidence=violations))
    findings.extend(_unknown("discovery-chain", item) for item in unknown_evidence)
    return findings


def _evaluate_resource_binding(
    fixture: OAuthTranscriptFixture,
    flow: Flow,
) -> list[OAuthTranscriptFinding]:
    violations: list[str] = []
    unknown_evidence: list[str] = []
    authorization = flow.authorization_request
    token = flow.token_request
    if authorization is None:
        unknown_evidence.append("authorization request observation is missing")
    else:
        if not authorization.resources:
            violations.append("authorization request omits the required resource indicator")
        elif not any(_resource_equal(item, fixture.intended_resource) for item in authorization.resources):
            violations.append("authorization request does not include the intended MCP resource")
    if token is None:
        unknown_evidence.append("token request observation is missing")
    else:
        if not token.resources:
            violations.append("token request omits the required resource indicator")
        elif not any(_resource_equal(item, fixture.intended_resource) for item in token.resources):
            violations.append("token request does not include the intended MCP resource")
        if authorization is not None:
            authorized = {_resource_key(item) for item in authorization.resources}
            if any(_resource_key(item) not in authorized for item in token.resources):
                violations.append("token request widens the authorization grant's resource set")

    audience = fixture.audience_evidence
    if audience.state != EvidenceState.CURRENT.value:
        unknown_evidence.append("current audience evidence is missing, redacted, or unverifiable")
    else:
        accepted_resources = [
            item.request_url for item in flow.resource_uses if 200 <= item.response_status < 300
        ]
        if audience.accepted_for_resource is not None:
            accepted_resources.append(audience.accepted_for_resource)
        for accepted_resource in accepted_resources:
            if not any(_resource_equal(item, accepted_resource) for item in audience.audiences):
                violations.append(
                    "token evidence was accepted for a resource absent from its observed audience"
                )
            if token is not None and not any(
                _resource_equal(item, accepted_resource) for item in token.resources
            ):
                violations.append("token evidence was accepted for a resource absent from the token request")
            if _resource_equal(accepted_resource, fixture.intended_resource) and not any(
                _resource_equal(item, fixture.intended_resource) for item in audience.audiences
            ):
                violations.append("the intended MCP resource accepted evidence for a different audience")
        intended_decision_observed = any(
            _resource_equal(item, fixture.intended_resource) for item in accepted_resources
        ) or any(
            _resource_equal(item.request_url, fixture.intended_resource)
            and item.response_status in {401, 403}
            for item in flow.resource_uses
        )
        if not intended_decision_observed:
            unknown_evidence.append(
                "token audience acceptance or rejection at the intended resource is not observable"
            )
        if audience.source == AudienceEvidenceSource.NONE.value:
            unknown_evidence.append("audience evidence has no supported synthetic source")
    findings: list[OAuthTranscriptFinding] = []
    if violations:
        findings.append(_finding("MCPOAUTH002", target="resource-audience-binding", evidence=violations))
    findings.extend(_unknown("resource-audience-binding", item) for item in unknown_evidence)
    return findings


def _evaluate_issuer_binding(fixture: OAuthTranscriptFixture, flow: Flow) -> list[OAuthTranscriptFinding]:
    authority = flow.authorization_metadata
    request = flow.authorization_request
    response = flow.authorization_response
    token = flow.token_request
    if authority is None or authority.document_state != DocumentState.COMPLETE.value:
        return [_unknown("authorization-response", "validated issuer metadata is unavailable")]
    if request is None:
        return [_unknown("authorization-response", "authorization request observation is missing")]
    if response is None:
        return [_unknown("authorization-response", "authorization response observation is missing")]
    unknown_evidence: list[str] = []
    violations: list[str] = []
    if request.recorded_issuer is None:
        unknown_evidence.append("the per-request recorded issuer is missing")
    elif authority.issuer is not None and request.recorded_issuer != authority.issuer:
        violations.append("the recorded issuer differs from validated authorization-server metadata")

    supported = authority.authorization_response_iss_parameter_supported is True
    mismatch = (
        response.issuer is not None
        and request.recorded_issuer is not None
        and response.issuer != request.recorded_issuer
    )
    token_after_response = token is not None and token.sequence > response.sequence
    accepted = response.handling == ResponseHandling.ACCEPTED.value or token_after_response
    if mismatch and accepted:
        violations.append("a mismatched authorization response issuer was accepted before code redemption")
    if supported and response.issuer is None and accepted:
        violations.append(
            "advertised-required authorization response issuer is absent but the response was accepted"
        )
    if response.handling == ResponseHandling.UNKNOWN.value:
        unknown_evidence.append("authorization response handling is not observable")
    if response.issuer is not None and request.recorded_issuer is None:
        unknown_evidence.append("a present authorization response issuer cannot be compared")
    findings: list[OAuthTranscriptFinding] = []
    if violations:
        findings.append(_finding("MCPOAUTH003", target="authorization-response", evidence=violations))
    findings.extend(_unknown("authorization-response", item) for item in unknown_evidence)
    return findings


def _evaluate_credential_binding(
    fixture: OAuthTranscriptFixture,
    flow: Flow,
) -> list[OAuthTranscriptFinding]:
    method = fixture.registration.method
    if method == RegistrationMethod.CLIENT_ID_METADATA_DOCUMENT.value:
        return []
    token = flow.token_request
    authority = flow.authorization_metadata
    if token is None:
        return [_unknown("client-credential-binding", "token request observation is missing")]
    if token.credential_record_id is None:
        return [_unknown("client-credential-binding", "issuer-bound credential selection is missing")]
    record = next(
        (item for item in fixture.credential_records if item.record_id == token.credential_record_id),
        None,
    )
    if record is None:
        return [_unknown("client-credential-binding", "selected credential record is unavailable")]
    if authority is None or authority.issuer is None:
        return [_unknown("client-credential-binding", "selected authorization-server issuer is unavailable")]
    violations: list[str] = []
    if record.method != method:
        violations.append("selected credential record method differs from the registration selection")
    if record.issuer != authority.issuer:
        violations.append("selected client credentials were issued by a different authorization server")
    if fixture.registration.issuer is None:
        return [
            *(
                [_finding("MCPOAUTH004", target="client-credential-binding", evidence=violations)]
                if violations
                else []
            ),
            _unknown("client-credential-binding", "registration issuer binding is missing"),
        ]
    if fixture.registration.issuer != authority.issuer:
        violations.append("persisted registration issuer differs from the currently selected issuer")
    if not violations:
        return []
    return [_finding("MCPOAUTH004", target="client-credential-binding", evidence=violations)]


def _evaluate_registration(fixture: OAuthTranscriptFixture, flow: Flow) -> list[OAuthTranscriptFinding]:
    authority = flow.authorization_metadata
    if authority is None or authority.document_state != DocumentState.COMPLETE.value:
        return [
            _unknown(
                "client-registration",
                "authorization-server registration capabilities are unavailable",
            )
        ]
    registration = fixture.registration
    violations: list[str] = []
    advisory: list[str] = []
    unknown_evidence: list[str] = []
    cimd_supported = authority.client_id_metadata_document_supported is True
    dcr_supported = authority.registration_endpoint is not None
    if flow.authorization_request is None:
        unknown_evidence.append("authorization request client identity is unavailable")
    elif (
        registration.method == RegistrationMethod.CLIENT_ID_METADATA_DOCUMENT.value
        and flow.authorization_request.client_id_kind != "https_metadata_url"
    ):
        violations.append("Client ID Metadata Documents were selected with a non-URL client identifier")
    elif (
        registration.method != RegistrationMethod.CLIENT_ID_METADATA_DOCUMENT.value
        and flow.authorization_request.client_id_kind == "https_metadata_url"
    ):
        violations.append("an HTTPS metadata client identifier was attributed to another registration method")
    if (
        registration.pre_registered_available
        and registration.method != RegistrationMethod.PRE_REGISTERED.value
    ):
        advisory.append("pre-registered client information was available but not selected first")
    if registration.method == RegistrationMethod.CLIENT_ID_METADATA_DOCUMENT.value and not cimd_supported:
        violations.append("Client ID Metadata Documents were selected without advertised server support")
    elif registration.method == RegistrationMethod.DYNAMIC_CLIENT_REGISTRATION.value:
        if not dcr_supported:
            violations.append("Dynamic Client Registration was selected without a registration endpoint")
        if registration.application_type is None:
            violations.append("Dynamic Client Registration omits application_type")
        elif (
            registration.client_kind == ClientKind.NATIVE.value and registration.application_type != "native"
        ):
            violations.append("native client uses a web application_type")
        elif registration.client_kind == ClientKind.WEB.value and registration.application_type != "web":
            violations.append("web client uses a native application_type")
        if authority.metadata_kind == MetadataKind.OPENID_CONNECT.value:
            for redirect_uri in registration.redirect_uris:
                parsed = urlsplit(redirect_uri)
                loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
                if registration.client_kind == ClientKind.NATIVE.value and not (
                    parsed.scheme == "http" and loopback
                ):
                    violations.append(
                        "OIDC native client uses a redirect URI outside the supported loopback profile"
                    )
                if registration.client_kind == ClientKind.WEB.value and (
                    parsed.scheme != "https" or loopback
                ):
                    violations.append(
                        "OIDC web client uses a redirect URI outside the HTTPS non-loopback profile"
                    )
        if dcr_supported:
            if cimd_supported:
                advisory.append("deprecated DCR was selected even though CIMD support is advertised")
            else:
                advisory.append("DCR is a deprecated but supported backwards-compatible fallback")
    elif registration.method == RegistrationMethod.USER_SUPPLIED.value and (cimd_supported or dcr_supported):
        advisory.append(
            "manual client input was selected while an automatic registration method is available"
        )
    findings: list[OAuthTranscriptFinding] = []
    if violations:
        findings.append(_finding("MCPOAUTH005", target="client-registration", evidence=violations))
    if advisory:
        findings.append(
            _finding(
                "MCPOAUTH005",
                target="client-registration",
                evidence=advisory,
                outcome=FindingOutcome.ADVISORY,
                severity=FindingSeverity.LOW,
                requirement_level=RequirementLevel.DEPRECATED,
            )
        )
    findings.extend(_unknown("client-registration", item) for item in unknown_evidence)
    return findings


def _evaluate_scopes(fixture: OAuthTranscriptFixture, flow: Flow) -> list[OAuthTranscriptFinding]:
    request = flow.authorization_request
    if request is None:
        return [_unknown("scope-binding", "authorization request observation is missing")]
    challenge_scopes = flow.challenge.scopes if flow.challenge is not None else []
    if flow.challenge is None:
        return [_unknown("scope-binding", "scope challenge evidence is unavailable")]
    if not challenge_scopes and (
        flow.resource_metadata is None
        or flow.resource_metadata.document_state != DocumentState.COMPLETE.value
    ):
        return [
            _unknown(
                "scope-binding",
                "neither a challenged scope set nor complete protected-resource metadata is available",
            )
        ]
    metadata_scopes = (
        flow.resource_metadata.scopes_supported
        if flow.resource_metadata is not None
        and flow.resource_metadata.document_state == DocumentState.COMPLETE.value
        else None
    )
    expected = set(challenge_scopes)
    if not expected and metadata_scopes is not None:
        expected = set(metadata_scopes)
    if fixture.scope_context.reauthorization:
        expected.update(fixture.scope_context.previously_granted_scopes)
    requested = set(request.scopes or [])
    violations: list[str] = []
    if expected - requested:
        violations.append("authorization request silently drops challenged or previously granted scopes")
    if requested - expected:
        violations.append("authorization request widens scopes beyond the resource challenge and prior grant")
    if flow.challenge is not None and not _resource_equal(
        flow.challenge.request_url,
        fixture.intended_resource,
    ):
        violations.append("challenged scopes are attributed to a different protected resource")
    token_scopes = flow.token_response.scopes if flow.token_response is not None else None
    effective_returned = requested if token_scopes is None else set(token_scopes)
    successful_use = any(
        _resource_equal(item.request_url, fixture.intended_resource) and 200 <= item.response_status < 300
        for item in flow.resource_uses
    )
    if expected - effective_returned and successful_use:
        violations.append("the protected resource accepted a token that silently dropped required scopes")
    if not violations:
        return []
    return [_finding("MCPOAUTH006", target="scope-binding", evidence=violations)]


def _sort_findings(findings: list[OAuthTranscriptFinding]) -> list[OAuthTranscriptFinding]:
    unique: dict[tuple[str, str, str, tuple[str, ...]], OAuthTranscriptFinding] = {}
    for finding in findings:
        key = (
            finding.rule_id,
            finding.outcome.value,
            finding.target,
            tuple(finding.evidence),
        )
        unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda item: (
            _OUTCOME_ORDER[item.outcome],
            _SEVERITY_ORDER[item.severity],
            item.rule_id,
            item.target,
            item.evidence,
        ),
    )


def _verdict(findings: list[OAuthTranscriptFinding]) -> str:
    if any(item.outcome is FindingOutcome.VIOLATION for item in findings):
        return "fail"
    if any(item.outcome is FindingOutcome.UNKNOWN for item in findings):
        return "unknown"
    return "pass"


def scan_oauth_transcript(fixture: OAuthTranscriptFixture, input_sha256: str) -> OAuthTranscriptReport:
    """Evaluate only observable binding invariants in one parsed fixture."""
    flow = _flow(fixture)
    findings = _sort_findings(
        [
            *_evaluate_structure(fixture, flow),
            *_evaluate_discovery(fixture, flow),
            *_evaluate_resource_binding(fixture, flow),
            *_evaluate_issuer_binding(fixture, flow),
            *_evaluate_credential_binding(fixture, flow),
            *_evaluate_registration(fixture, flow),
            *_evaluate_scopes(fixture, flow),
        ]
    )
    return OAuthTranscriptReport(
        fixture_id=fixture.fixture_id,
        spec_profile=fixture.spec_profile,
        input_sha256=input_sha256,
        verdict=cast(Any, _verdict(findings)),
        findings=findings,
        parser_limits=ParserLimits(
            input_bytes=MAX_INPUT_BYTES,
            json_depth=MAX_JSON_DEPTH,
            observations=MAX_OBSERVATIONS,
            metadata_documents=MAX_METADATA_DOCUMENTS,
            redirects=MAX_REDIRECTS,
            url_length=MAX_URL_LENGTH,
        ),
        supported_inputs=_SUPPORTED_INPUTS,
        unsupported_inputs=_UNSUPPORTED_INPUTS,
        claim_ceiling=_CLAIM_CEILING,
    )


def scan_oauth_transcript_path(path: Path) -> OAuthTranscriptReport:
    report, _ = scan_oauth_transcript_path_with_identity(path)
    return report


def scan_oauth_transcript_path_with_identity(
    path: Path,
) -> tuple[OAuthTranscriptReport, tuple[int, int]]:
    fixture, raw, identity = parse_oauth_transcript_path(path)
    return scan_oauth_transcript(fixture, sha256_bytes(raw)), identity


def report_json_bytes(report: OAuthTranscriptReport) -> bytes:
    return canonical_json_bytes(report)
