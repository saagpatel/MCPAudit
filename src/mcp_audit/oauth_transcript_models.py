"""Strict, redacted contracts for synthetic MCP OAuth transcript fixtures."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FIXTURE_SCHEMA: Final = "mcpaudit.oauth-transcript.fixture.v1"
REPORT_SCHEMA: Final = "mcpaudit.oauth-transcript.report.v1"
SPEC_PROFILE: Final = "mcp-authorization-2025-11-25+draft-2026-07-28"
MAX_URL_LENGTH: Final = 2_048
MAX_OBSERVATIONS: Final = 64
MAX_CREDENTIAL_RECORDS: Final = 8


class StrictModel(BaseModel):
    """Forbid undeclared transcript fields and coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


def _require_synthetic_url(value: str, *, redirect: bool = False) -> str:
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds {MAX_URL_LENGTH} characters")
    parsed = urlsplit(value)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL user information is forbidden")
    if parsed.fragment:
        raise ValueError("URL fragments are forbidden")
    try:
        host = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("URL authority is malformed") from exc
    if not host:
        raise ValueError("URL requires a host")
    synthetic_host = host == "example" or host.endswith(".example")
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if not synthetic_host and not (redirect and loopback):
        raise ValueError("fixture URLs must use reserved .example hosts or loopback redirects")
    if parsed.scheme != "https" and not (redirect and loopback and parsed.scheme == "http"):
        raise ValueError("fixture URLs must use HTTPS except loopback redirect URIs")
    return value


def _require_issuer_url(value: str) -> str:
    _require_synthetic_url(value)
    if urlsplit(value).query:
        raise ValueError("issuer URLs cannot contain a query")
    return value


def _require_unique(values: list[str], label: str) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} entries must be unique")
    return values


class ControlKind(StrEnum):
    VULNERABLE = "vulnerable"
    NEGATIVE = "negative"
    NEAR_MISS = "near_miss"
    SPECIAL = "special"


class DocumentState(StrEnum):
    COMPLETE = "complete"
    MALFORMED = "malformed"
    REDACTED = "redacted"
    MISSING = "missing"


class MetadataKind(StrEnum):
    OAUTH = "oauth"
    OPENID_CONNECT = "openid_connect"


class RegistrationMethod(StrEnum):
    CLIENT_ID_METADATA_DOCUMENT = "client_id_metadata_document"
    PRE_REGISTERED = "pre_registered"
    DYNAMIC_CLIENT_REGISTRATION = "dynamic_client_registration"
    USER_SUPPLIED = "user_supplied"


class ClientKind(StrEnum):
    NATIVE = "native"
    WEB = "web"


class ResponseHandling(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class EvidenceState(StrEnum):
    CURRENT = "current"
    MISSING = "missing"
    REDACTED = "redacted"
    UNVERIFIABLE = "unverifiable"


class AudienceEvidenceSource(StrEnum):
    SYNTHETIC_JWT_CLAIM = "synthetic_jwt_claim"
    SYNTHETIC_INTROSPECTION = "synthetic_introspection"
    NONE = "none"


class FindingSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class FindingOutcome(StrEnum):
    VIOLATION = "violation"
    ADVISORY = "advisory"
    UNKNOWN = "unknown"


class RequirementLevel(StrEnum):
    REQUIRED = "required"
    RECOMMENDED = "recommended"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class ObservationBase(StrictModel):
    exchange_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    sequence: int = Field(ge=1, le=256)
    redirects_followed: int = Field(default=0, ge=0, le=5)


class ProtectedResourceChallenge(ObservationBase):
    kind: Literal["protected_resource_challenge"]
    request_url: str
    response_status: Literal[401]
    resource_metadata_url: str | None
    scopes: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("request_url", "resource_metadata_url")
    @classmethod
    def urls_are_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_synthetic_url(value)

    @field_validator("scopes")
    @classmethod
    def scopes_are_unique(cls, value: list[str]) -> list[str]:
        return _require_unique(value, "scope")


class ProtectedResourceMetadata(ObservationBase):
    kind: Literal["protected_resource_metadata"]
    request_url: str
    response_status: int = Field(ge=100, le=599)
    document_state: Literal["complete", "malformed", "redacted", "missing"]
    resource: str | None
    authorization_servers: list[str] = Field(default_factory=list, max_length=8)
    scopes_supported: list[str] | None = Field(default=None, max_length=32)

    @field_validator("request_url", "resource")
    @classmethod
    def scalar_urls_are_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_synthetic_url(value)

    @field_validator("authorization_servers")
    @classmethod
    def authorization_server_urls_are_synthetic(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_issuer_url(item)
        return _require_unique(value, "authorization server")

    @field_validator("scopes_supported")
    @classmethod
    def supported_scopes_are_unique(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _require_unique(value, "supported scope")


class AuthorizationServerMetadata(ObservationBase):
    kind: Literal["authorization_server_metadata"]
    request_url: str
    response_status: int = Field(ge=100, le=599)
    document_state: Literal["complete", "malformed", "redacted", "missing"]
    metadata_kind: Literal["oauth", "openid_connect"]
    issuer: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    registration_endpoint: str | None = None
    client_id_metadata_document_supported: bool | None = None
    authorization_response_iss_parameter_supported: bool | None = None

    @field_validator(
        "request_url",
        "authorization_endpoint",
        "token_endpoint",
        "registration_endpoint",
    )
    @classmethod
    def urls_are_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_synthetic_url(value)

    @field_validator("issuer")
    @classmethod
    def issuer_is_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_issuer_url(value)


class AuthorizationRequest(ObservationBase):
    kind: Literal["authorization_request"]
    request_url: str
    resources: list[str] = Field(default_factory=list, max_length=8)
    scopes: list[str] | None = Field(default=None, max_length=32)
    recorded_issuer: str | None
    redirect_uri: str
    client_id_kind: Literal["https_metadata_url", "opaque"]

    @field_validator("request_url")
    @classmethod
    def urls_are_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_synthetic_url(value)

    @field_validator("recorded_issuer")
    @classmethod
    def issuer_is_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_issuer_url(value)

    @field_validator("redirect_uri")
    @classmethod
    def redirect_is_synthetic(cls, value: str) -> str:
        return _require_synthetic_url(value, redirect=True)

    @field_validator("resources")
    @classmethod
    def resources_are_synthetic(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_synthetic_url(item)
        return _require_unique(value, "authorization resource")

    @field_validator("scopes")
    @classmethod
    def scopes_are_unique(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _require_unique(value, "authorization scope")


class AuthorizationResponse(ObservationBase):
    kind: Literal["authorization_response"]
    response_status: Literal[302, 303]
    redirect_uri: str
    issuer: str | None
    code_marker: Literal["<redacted>"] | None
    handling: Literal["accepted", "rejected", "unknown"]

    @field_validator("redirect_uri")
    @classmethod
    def redirect_is_synthetic(cls, value: str) -> str:
        return _require_synthetic_url(value, redirect=True)

    @field_validator("issuer")
    @classmethod
    def issuer_is_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_issuer_url(value)


class TokenRequest(ObservationBase):
    kind: Literal["token_request"]
    request_url: str
    grant_type: Literal["authorization_code"]
    code_marker: Literal["<redacted>"]
    resources: list[str] = Field(default_factory=list, max_length=8)
    scopes: list[str] | None = Field(default=None, max_length=32)
    credential_record_id: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$",
    )

    @field_validator("request_url")
    @classmethod
    def request_url_is_synthetic(cls, value: str) -> str:
        return _require_synthetic_url(value)

    @field_validator("resources")
    @classmethod
    def resources_are_synthetic(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_synthetic_url(item)
        return _require_unique(value, "token resource")

    @field_validator("scopes")
    @classmethod
    def scopes_are_unique(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _require_unique(value, "token scope")


class TokenResponse(ObservationBase):
    kind: Literal["token_response"]
    response_status: int = Field(ge=100, le=599)
    access_token_marker: Literal["<redacted>"] | None
    scopes: list[str] | None = Field(default=None, max_length=32)

    @field_validator("scopes")
    @classmethod
    def scopes_are_unique(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _require_unique(value, "returned scope")


class ProtectedResourceUse(ObservationBase):
    kind: Literal["protected_resource_use"]
    request_url: str
    authorization_marker: Literal["<redacted>"]
    response_status: int = Field(ge=100, le=599)

    @field_validator("request_url")
    @classmethod
    def request_url_is_synthetic(cls, value: str) -> str:
        return _require_synthetic_url(value)


TranscriptObservation = Annotated[
    ProtectedResourceChallenge
    | ProtectedResourceMetadata
    | AuthorizationServerMetadata
    | AuthorizationRequest
    | AuthorizationResponse
    | TokenRequest
    | TokenResponse
    | ProtectedResourceUse,
    Field(discriminator="kind"),
]


class RegistrationSelection(StrictModel):
    method: Literal[
        "client_id_metadata_document",
        "pre_registered",
        "dynamic_client_registration",
        "user_supplied",
    ]
    client_kind: Literal["native", "web"]
    application_type: Literal["native", "web"] | None
    issuer: str | None
    redirect_uris: list[str] = Field(min_length=1, max_length=8)
    pre_registered_available: bool

    @field_validator("issuer")
    @classmethod
    def issuer_is_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_issuer_url(value)

    @field_validator("redirect_uris")
    @classmethod
    def redirects_are_synthetic(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_synthetic_url(item, redirect=True)
        return _require_unique(value, "redirect URI")


class CredentialRecord(StrictModel):
    record_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$")
    method: Literal["pre_registered", "dynamic_client_registration", "user_supplied"]
    issuer: str
    client_id_marker: Literal["SYNTHETIC_CLIENT_ID"]
    client_secret_marker: Literal["<redacted>"] | None = None

    @field_validator("issuer")
    @classmethod
    def issuer_is_synthetic(cls, value: str) -> str:
        return _require_issuer_url(value)


class AudienceEvidence(StrictModel):
    state: Literal["current", "missing", "redacted", "unverifiable"]
    source: Literal["synthetic_jwt_claim", "synthetic_introspection", "none"]
    token_response_exchange_id: str | None = Field(
        default=None,
        pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$",
    )
    audiences: list[str] = Field(default_factory=list, max_length=8)
    accepted_for_resource: str | None

    @field_validator("audiences")
    @classmethod
    def audiences_are_synthetic(cls, value: list[str]) -> list[str]:
        for item in value:
            _require_synthetic_url(item)
        return _require_unique(value, "audience")

    @field_validator("accepted_for_resource")
    @classmethod
    def accepted_resource_is_synthetic(cls, value: str | None) -> str | None:
        return None if value is None else _require_synthetic_url(value)

    @model_validator(mode="after")
    def evidence_state_is_consistent(self) -> AudienceEvidence:
        if self.state == EvidenceState.CURRENT.value:
            if self.source == AudienceEvidenceSource.NONE.value or not self.audiences:
                raise ValueError("current audience evidence requires a source and at least one audience")
        elif (
            self.source != AudienceEvidenceSource.NONE.value
            or self.token_response_exchange_id is not None
            or self.audiences
            or self.accepted_for_resource is not None
        ):
            raise ValueError(
                "non-current audience evidence cannot expose source, token, audience, or acceptance values"
            )
        return self


class ScopeContext(StrictModel):
    reauthorization: bool = False
    previously_granted_scopes: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("previously_granted_scopes")
    @classmethod
    def scopes_are_unique(cls, value: list[str]) -> list[str]:
        return _require_unique(value, "previously granted scope")


class OAuthTranscriptFixture(StrictModel):
    schema_version: Literal["mcpaudit.oauth-transcript.fixture.v1"] = FIXTURE_SCHEMA
    program_owned: Literal[True]
    synthetic: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    control_kind: Literal["vulnerable", "negative", "near_miss", "special"]
    spec_profile: Literal["mcp-authorization-2025-11-25+draft-2026-07-28"] = SPEC_PROFILE
    intended_resource: str
    intended_authorization_server: str
    registration: RegistrationSelection
    credential_records: list[CredentialRecord] = Field(
        default_factory=list,
        max_length=MAX_CREDENTIAL_RECORDS,
    )
    audience_evidence: AudienceEvidence
    scope_context: ScopeContext = Field(default_factory=ScopeContext)
    observations: list[TranscriptObservation] = Field(
        min_length=1,
        max_length=MAX_OBSERVATIONS,
    )

    @field_validator("intended_resource")
    @classmethod
    def intended_resource_is_synthetic(cls, value: str) -> str:
        return _require_synthetic_url(value)

    @field_validator("intended_authorization_server")
    @classmethod
    def intended_issuer_is_synthetic(cls, value: str) -> str:
        return _require_issuer_url(value)

    @model_validator(mode="after")
    def transcript_identity_is_unambiguous(self) -> OAuthTranscriptFixture:
        sequences = [item.sequence for item in self.observations]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("observation sequence values must be unique and strictly increasing")
        exchange_ids = [item.exchange_id for item in self.observations]
        if len(exchange_ids) != len(set(exchange_ids)):
            raise ValueError("exchange identifiers must be unique")
        record_ids = [item.record_id for item in self.credential_records]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("credential record identifiers must be unique")
        metadata_documents = sum(
            isinstance(item, (ProtectedResourceMetadata, AuthorizationServerMetadata))
            for item in self.observations
        )
        if metadata_documents > 8:
            raise ValueError("metadata document budget exceeded")
        if sum(item.redirects_followed for item in self.observations) > 5:
            raise ValueError("redirect traversal budget exceeded")
        return self


class OAuthTranscriptFinding(StrictModel):
    rule_id: Literal[
        "MCPOAUTH000",
        "MCPOAUTH001",
        "MCPOAUTH002",
        "MCPOAUTH003",
        "MCPOAUTH004",
        "MCPOAUTH005",
        "MCPOAUTH006",
    ]
    severity: FindingSeverity
    outcome: FindingOutcome
    requirement_level: RequirementLevel
    title: str
    target: str
    evidence: list[str] = Field(min_length=1)
    remediation: str
    references: list[str] = Field(min_length=1)
    assumptions: list[str] = Field(min_length=1)


class ParserLimits(StrictModel):
    input_bytes: int
    json_depth: int
    observations: int
    metadata_documents: int
    redirects: int
    url_length: int


class OAuthTranscriptReport(StrictModel):
    schema_version: Literal["mcpaudit.oauth-transcript.report.v1"] = REPORT_SCHEMA
    fixture_id: str
    spec_profile: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: Literal["pass", "fail", "unknown"]
    findings: list[OAuthTranscriptFinding] = Field(default_factory=list)
    parser_limits: ParserLimits
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
