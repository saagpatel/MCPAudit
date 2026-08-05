"""Strict contracts for offline McpAuthorizationPostureV1 adoption."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any, Final, Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

INPUT_SCHEMA: Final = "McpAuthorizationPostureV1"
INPUT_CONTRACT_VERSION: Final = "1.0.0"
REPORT_SCHEMA: Final = "mcpaudit.authorization-posture.report.v1"
SPEC_PROFILE: Final = "mcp-authorization-2025-11-25"
SPEC_REFERENCES: Final = [
    "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization",
    "https://datatracker.ietf.org/doc/html/rfc9728",
    "https://datatracker.ietf.org/doc/html/rfc8414",
    "https://openid.net/specs/openid-connect-discovery-1_0.html",
]
MAX_URL_LENGTH: Final = 2_048
MAX_REASON_CODES: Final = 32
MAX_SCOPES: Final = 64
MAX_AUTHORIZATION_SERVERS: Final = 8
MAX_FETCHES: Final = 32


class StrictModel(BaseModel):
    """Forbid undeclared fields and implicit coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


def _require_https_url(value: str, *, query_allowed: bool = True) -> str:
    if not value or value != value.strip() or len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is empty, padded, or too long")
    if "\\" in value or any(ord(character) < 32 for character in value):
        raise ValueError("URL contains a forbidden character")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL authority is malformed") from exc
    if parsed.scheme.lower() != "https" or not hostname:
        raise ValueError("URL must use HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("URL user information and fragments are forbidden")
    if not query_allowed and parsed.query:
        raise ValueError("URL query is forbidden")
    try:
        normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL host is invalid") from exc
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError("localhost URL authorities are forbidden")
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal URL authorities are forbidden")
    decoded_path = unquote(parsed.path or "/")
    if "\\" in decoded_path or any(ord(character) < 32 for character in decoded_path):
        raise ValueError("URL path contains a forbidden character")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("URL port is outside the valid range")
    return value


def _require_timestamp(value: str) -> str:
    if len(value) != 20 or not value.endswith("Z"):
        raise ValueError("timestamp must be canonical UTC seconds")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is invalid") from exc
    canonical = parsed.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    if canonical != value:
        raise ValueError("timestamp must be canonical UTC seconds")
    return value


def _require_unique_strings(values: list[str], *, maximum: int, label: str) -> list[str]:
    if len(values) > maximum or len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique and bounded")
    if any(not item or len(item) > 512 or item != item.strip() for item in values):
        raise ValueError(f"{label} contains an invalid value")
    return values


def _require_header(value: str | None) -> str | None:
    if value is not None and (len(value) > 8_192 or "\r" in value or "\n" in value):
        raise ValueError("header value is invalid")
    return value


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def _expected_resource_metadata_url(resource: str, discovery: str) -> str | None:
    if discovery == "www-authenticate":
        return None
    parsed = urlsplit(resource)
    origin = _origin(resource)
    resource_path = parsed.path.rstrip("/")
    if discovery == "well-known-path" and resource_path:
        return f"{origin}/.well-known/oauth-protected-resource{resource_path}"
    if discovery == "well-known-root":
        return f"{origin}/.well-known/oauth-protected-resource"
    raise ValueError("protected-resource discovery does not match the resource path")


def _expected_authorization_metadata_url(issuer: str, discovery: str) -> str:
    parsed = urlsplit(issuer)
    origin = _origin(issuer)
    issuer_path = parsed.path.strip("/")
    if not issuer_path:
        if discovery == "rfc8414":
            return f"{origin}/.well-known/oauth-authorization-server"
        if discovery == "openid-connect":
            return f"{origin}/.well-known/openid-configuration"
        raise ValueError("authorization-server discovery does not match a root issuer")
    if discovery == "rfc8414-path-insertion":
        return f"{origin}/.well-known/oauth-authorization-server/{issuer_path}"
    if discovery == "openid-connect-path-insertion":
        return f"{origin}/.well-known/openid-configuration/{issuer_path}"
    if discovery == "openid-connect-path-append":
        return f"{origin}/{issuer_path}/.well-known/openid-configuration"
    raise ValueError("authorization-server discovery does not match an issuer path")


class ProducerSpecification(StrictModel):
    profile: Literal["mcp-authorization-2025-11-25"]
    references: list[str] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def references_match_profile(self) -> ProducerSpecification:
        if self.references != SPEC_REFERENCES:
            raise ValueError("specification references do not match the contract profile")
        return self


class ProducerBinding(StrictModel):
    stable_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,255}$")
    resource_url: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: Literal["official-mcp-registry-export"]

    @field_validator("resource_url")
    @classmethod
    def resource_url_is_bound_https(cls, value: str) -> str:
        return _require_https_url(value, query_allowed=False)


class ProducerCapabilityBoundary(StrictModel):
    network_methods: list[Literal["GET"]] = Field(min_length=1, max_length=1)
    credentials_supported: Literal[False]
    proxy_environment_used: Literal[False]
    redirects_followed: Literal[False]
    dns_addresses_pinned: Literal[True]
    non_public_addresses_allowed: Literal[False]
    mutation_capabilities: list[str] = Field(max_length=0)

    @model_validator(mode="after")
    def exact_boundary(self) -> ProducerCapabilityBoundary:
        if self.network_methods != ["GET"] or self.mutation_capabilities:
            raise ValueError("producer capability boundary is wider than supported")
        return self


class ProducerClaimCeiling(StrictModel):
    authorization_proven: Literal[False]
    credentials_available: Literal[False]
    trust_grade_authority: Literal[False]
    runtime_security_proven: Literal[False]


class ProducerFreshness(StrictModel):
    state: Literal["current", "unknown"]
    http_date: str | None = None
    last_modified: str | None = None
    cache_control: str | None = None
    age_header_seconds: int | None = Field(default=None, ge=0)
    effective_age_seconds: float | None = Field(default=None, ge=0)
    policy_freshness_seconds: int | None = Field(default=None, ge=0, le=86_400)

    @field_validator("http_date")
    @classmethod
    def http_date_is_canonical(cls, value: str | None) -> str | None:
        return None if value is None else _require_timestamp(value)

    @field_validator("last_modified", "cache_control")
    @classmethod
    def response_headers_are_bounded(cls, value: str | None) -> str | None:
        return _require_header(value)

    @model_validator(mode="after")
    def state_is_coherent(self) -> ProducerFreshness:
        evidence = (
            self.http_date,
            self.last_modified,
            self.cache_control,
            self.age_header_seconds,
            self.effective_age_seconds,
            self.policy_freshness_seconds,
        )
        if self.state == "unknown" and any(item is not None for item in evidence):
            raise ValueError("unknown freshness cannot carry freshness evidence")
        if self.state == "current" and (
            self.http_date is None
            or self.effective_age_seconds is None
            or self.policy_freshness_seconds is None
        ):
            raise ValueError("current freshness requires time and policy evidence")
        return self


class ProducerFetch(StrictModel):
    kind: str = Field(pattern=r"^[a-z0-9][a-z0-9:-]{0,127}$")
    url: str
    status: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = None
    body_bytes: int | None = Field(default=None, ge=0, le=65_536)
    body_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    freshness: ProducerFreshness
    state: Literal["unknown", "invalid", "validated"]
    reason_code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")

    @field_validator("url")
    @classmethod
    def fetch_url_is_https(cls, value: str) -> str:
        return _require_https_url(value, query_allowed=False)

    @field_validator("content_type")
    @classmethod
    def content_type_is_bounded(cls, value: str | None) -> str | None:
        return _require_header(value)

    @model_validator(mode="after")
    def result_is_coherent(self) -> ProducerFetch:
        if (self.body_bytes is None) != (self.body_sha256 is None):
            raise ValueError("fetch body size and digest must appear together")
        if self.state == "validated" and (
            self.status != 200
            or self.body_sha256 is None
            or self.freshness.state != "current"
            or self.reason_code not in {"resource_metadata_valid", "authorization_server_metadata_valid"}
        ):
            raise ValueError("validated fetch lacks successful bounded evidence")
        if self.state != "validated" and self.reason_code in {
            "resource_metadata_valid",
            "authorization_server_metadata_valid",
        }:
            raise ValueError("non-validated fetch claims validated metadata")
        return self


class ProducerResourceMetadata(StrictModel):
    resource: str
    authorization_servers: list[str] = Field(min_length=1, max_length=MAX_AUTHORIZATION_SERVERS)
    scopes_supported: list[str] = Field(max_length=MAX_SCOPES)
    metadata_url: str
    discovery: Literal["www-authenticate", "well-known-path", "well-known-root"]

    @field_validator("resource", "metadata_url")
    @classmethod
    def resource_urls_are_https(cls, value: str) -> str:
        return _require_https_url(value, query_allowed=False)

    @field_validator("authorization_servers")
    @classmethod
    def authorization_servers_are_unique_https(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_https_url(item, query_allowed=False)
        return _require_unique_strings(
            value,
            maximum=MAX_AUTHORIZATION_SERVERS,
            label="authorization servers",
        )

    @field_validator("scopes_supported")
    @classmethod
    def scopes_are_unique(cls, value: list[str]) -> list[str]:
        return _require_unique_strings(value, maximum=MAX_SCOPES, label="scopes")


class ProducerAuthorizationMetadata(StrictModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    code_challenge_methods_supported: list[str] = Field(min_length=1, max_length=16)
    scopes_supported: list[str] = Field(max_length=MAX_SCOPES)
    client_id_metadata_document_supported: bool | None
    registration_endpoint: str | None

    @field_validator("issuer")
    @classmethod
    def issuer_is_https(cls, value: str) -> str:
        return _require_https_url(value, query_allowed=False)

    @field_validator("authorization_endpoint", "token_endpoint", "registration_endpoint")
    @classmethod
    def endpoints_are_https(cls, value: str | None) -> str | None:
        return None if value is None else _require_https_url(value)

    @field_validator("code_challenge_methods_supported")
    @classmethod
    def methods_are_unique_and_include_s256(cls, value: list[str]) -> list[str]:
        _require_unique_strings(value, maximum=16, label="code challenge methods")
        if "S256" not in value:
            raise ValueError("metadata-ready authorization server requires PKCE S256")
        return value

    @field_validator("scopes_supported")
    @classmethod
    def scopes_are_unique(cls, value: list[str]) -> list[str]:
        return _require_unique_strings(value, maximum=MAX_SCOPES, label="scopes")


class ProducerAuthorizationServer(StrictModel):
    issuer: str
    state: Literal["metadata-ready", "unknown"]
    metadata_url: str | None
    discovery: (
        Literal[
            "rfc8414",
            "openid-connect",
            "rfc8414-path-insertion",
            "openid-connect-path-insertion",
            "openid-connect-path-append",
        ]
        | None
    )
    metadata: ProducerAuthorizationMetadata | None
    reason_codes: list[str] = Field(min_length=1, max_length=MAX_REASON_CODES)

    @field_validator("issuer", "metadata_url")
    @classmethod
    def server_urls_are_https(cls, value: str | None) -> str | None:
        return None if value is None else _require_https_url(value, query_allowed=False)

    @field_validator("reason_codes")
    @classmethod
    def reasons_are_bounded(cls, value: list[str]) -> list[str]:
        return _require_unique_strings(value, maximum=MAX_REASON_CODES, label="reason codes")

    @model_validator(mode="after")
    def state_is_coherent(self) -> ProducerAuthorizationServer:
        if self.state == "metadata-ready":
            if (
                self.metadata_url is None
                or self.discovery is None
                or self.metadata is None
                or self.reason_codes != ["metadata_ready"]
                or self.metadata.issuer != self.issuer
            ):
                raise ValueError("metadata-ready authorization server is internally inconsistent")
        elif self.metadata_url is not None or self.discovery is not None or self.metadata is not None:
            raise ValueError("unknown authorization server cannot carry accepted metadata")
        return self


class McpAuthorizationPostureV1(StrictModel):
    schema_version: Literal["McpAuthorizationPostureV1"]
    contract_version: Literal["1.0.0"]
    observed_at: str
    specification: ProducerSpecification
    binding: ProducerBinding
    state: Literal["metadata-ready", "unknown"]
    scan_eligibility: Literal["policy-review-only", "blocked"]
    authorization_required: Literal[True] | None
    challenge_scopes: list[str] = Field(max_length=MAX_SCOPES)
    resource_metadata: ProducerResourceMetadata | None
    authorization_servers: list[ProducerAuthorizationServer] = Field(max_length=MAX_AUTHORIZATION_SERVERS)
    fetches: list[ProducerFetch] = Field(max_length=MAX_FETCHES)
    reason_codes: list[str] = Field(min_length=1, max_length=MAX_REASON_CODES)
    capability_boundary: ProducerCapabilityBoundary
    claim_ceiling: ProducerClaimCeiling

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_canonical(cls, value: str) -> str:
        return _require_timestamp(value)

    @field_validator("challenge_scopes")
    @classmethod
    def challenge_scopes_are_unique(cls, value: list[str]) -> list[str]:
        return _require_unique_strings(value, maximum=MAX_SCOPES, label="challenge scopes")

    @field_validator("reason_codes")
    @classmethod
    def reasons_are_bounded(cls, value: list[str]) -> list[str]:
        return _require_unique_strings(value, maximum=MAX_REASON_CODES, label="reason codes")

    @model_validator(mode="after")
    def posture_is_coherent(self) -> McpAuthorizationPostureV1:
        ready_servers = [item for item in self.authorization_servers if item.state == "metadata-ready"]
        if self.authorization_required is None and self.challenge_scopes:
            raise ValueError("challenge scopes require an observed authorization challenge")
        expected_validated_fetches: set[tuple[str, str, str]] = set()
        if self.resource_metadata is None:
            if self.authorization_servers:
                raise ValueError("authorization-server results require protected-resource metadata")
        else:
            if self.resource_metadata.resource != self.binding.resource_url:
                raise ValueError("resource metadata is not bound to the selected Registry resource")
            if self.resource_metadata.authorization_servers != [
                item.issuer for item in self.authorization_servers
            ]:
                raise ValueError("authorization-server results do not match resource metadata")
            expected_metadata_url = _expected_resource_metadata_url(
                self.resource_metadata.resource,
                self.resource_metadata.discovery,
            )
            if expected_metadata_url is None:
                if self.authorization_required is not True or _origin(
                    self.resource_metadata.metadata_url
                ) != _origin(self.resource_metadata.resource):
                    raise ValueError("challenge metadata URL is outside the resource authority")
            elif self.resource_metadata.metadata_url != expected_metadata_url:
                raise ValueError("protected-resource metadata URL does not match discovery")
            expected_validated_fetches.add(
                (
                    f"resource-metadata:{self.resource_metadata.discovery}",
                    self.resource_metadata.metadata_url,
                    "resource_metadata_valid",
                )
            )
        for server in ready_servers:
            if server.metadata_url is None or server.discovery is None:
                raise ValueError("metadata-ready authorization server lacks discovery identity")
            if server.metadata_url != _expected_authorization_metadata_url(
                server.issuer,
                server.discovery,
            ):
                raise ValueError("authorization-server metadata URL does not match discovery")
            expected_validated_fetches.add(
                (
                    f"authorization-server:{server.discovery}",
                    server.metadata_url,
                    "authorization_server_metadata_valid",
                )
            )
        validated_fetches = [item for item in self.fetches if item.state == "validated"]
        actual_validated_fetches = {(item.kind, item.url, item.reason_code) for item in validated_fetches}
        if (
            len(actual_validated_fetches) != len(validated_fetches)
            or actual_validated_fetches != expected_validated_fetches
        ):
            raise ValueError("accepted metadata is not exactly bound to validated fetch evidence")
        if self.state == "metadata-ready":
            if (
                self.scan_eligibility != "policy-review-only"
                or self.resource_metadata is None
                or not ready_servers
            ):
                raise ValueError("metadata-ready posture is internally inconsistent")
            expected_reasons = ["metadata_ready"]
            if len(ready_servers) != len(self.authorization_servers):
                expected_reasons.append("authorization_server_partial")
            if self.reason_codes != expected_reasons:
                raise ValueError("metadata-ready reason codes do not match server state")
        elif self.scan_eligibility != "blocked" or ready_servers:
            raise ValueError("unknown posture must remain blocked")
        elif self.resource_metadata is not None:
            if self.reason_codes != ["authorization_server_metadata_unavailable"]:
                raise ValueError("unknown authorization-server posture has inconsistent reasons")
        elif "metadata_ready" in self.reason_codes or "authorization_server_partial" in self.reason_codes:
            raise ValueError("unknown posture cannot claim metadata readiness")
        return self


class AuthorizationPostureFinding(StrictModel):
    rule_id: Literal["MCPPOSTURE000", "MCPPOSTURE001"]
    severity: Literal["low", "unknown"]
    outcome: Literal["advisory", "unknown"]
    title: str
    target: Literal["authorization-metadata-posture"]
    evidence: list[str] = Field(min_length=1)
    remediation: str
    references: list[str] = Field(min_length=1)
    assumptions: list[str] = Field(min_length=1)


class AuthorizationServerSummary(StrictModel):
    declared: int = Field(ge=0, le=MAX_AUTHORIZATION_SERVERS)
    metadata_ready: int = Field(ge=0, le=MAX_AUTHORIZATION_SERVERS)


class AuthorizationPostureParserLimits(StrictModel):
    input_bytes: int
    json_depth: int
    json_nodes: int
    authorization_servers: int
    fetches: int
    url_length: int


class AuthorizationPostureAuthorityFlow(StrictModel):
    input_provenance: Literal["unverified"]
    input_freshness: Literal["unverified"]
    remote_observation_authority: Literal["producer-asserted"]
    consumer_decision_authority: Literal["operator-policy-review"]
    network_used: Literal[False]
    credentials_used: Literal[False]
    endpoint_session_used: Literal[False]
    scan_authorized: Literal[False]
    trust_grade_changed: Literal[False]


class AuthorizationPostureReport(StrictModel):
    schema_version: Literal["mcpaudit.authorization-posture.report.v1"] = REPORT_SCHEMA
    input_schema_version: Literal["McpAuthorizationPostureV1"] = INPUT_SCHEMA
    input_contract_version: Literal["1.0.0"] = INPUT_CONTRACT_VERSION
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_at: str
    binding: ProducerBinding
    disposition: Literal["policy-review-only", "blocked"]
    metadata_state: Literal["producer-declared-ready", "producer-declared-unknown"]
    authorization_servers: AuthorizationServerSummary
    reason_codes: list[str] = Field(min_length=1)
    findings: list[AuthorizationPostureFinding] = Field(min_length=1, max_length=1)
    authority_flow: AuthorizationPostureAuthorityFlow
    parser_limits: AuthorizationPostureParserLimits
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
