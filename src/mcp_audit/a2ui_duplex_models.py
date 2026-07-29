"""Strict contracts for the experimental A2UI duplex return-path auditor.

The outer fixture and correlation fields are MCPAudit-owned synthetic test
sidecars. The nested ``message`` and transport metadata objects preserve the
observable A2UI envelope shapes supplied by the fixture; they are not claims
that MCPAudit implements an A2UI transport or renderer.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DUPLEX_FIXTURE_SCHEMA: Final = "mcpaudit.a2ui-duplex.fixture.v1"
DUPLEX_DISCLOSURE_POLICY_SCHEMA: Final = "mcpaudit.a2ui-duplex.disclosure-policy.v1"
DUPLEX_REPORT_SCHEMA: Final = "mcpaudit.a2ui-duplex.report.v1"

_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_FIXTURE_ID_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,127}$"
_UTC_TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


class DuplexStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _unique_strings(value: list[str], label: str) -> list[str]:
    if len(value) != len(set(value)):
        raise ValueError(f"{label} must be unique")
    return value


class DuplexProducer(DuplexStrictModel):
    producer_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    profile: Literal["web-core-react", "flutter-a2ui"]


class DuplexActionContract(DuplexStrictModel):
    surface_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    component_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action_name: str = Field(pattern=_IDENTIFIER_PATTERN)
    context_schema: dict[str, Any] | None = None
    payload_schema: dict[str, Any] | None = None


class DuplexSurfaceDisclosureRule(DuplexStrictModel):
    surface_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    allow_full_data_model_return: bool
    allowed_top_level_keys: list[str] = Field(default_factory=list)

    @field_validator("allowed_top_level_keys")
    @classmethod
    def top_level_keys_are_unique(cls, value: list[str]) -> list[str]:
        return _unique_strings(value, "allowed top-level keys")


class DuplexDisclosurePolicy(DuplexStrictModel):
    schema_version: Literal["mcpaudit.a2ui-duplex.disclosure-policy.v1"] = DUPLEX_DISCLOSURE_POLICY_SCHEMA
    surface_rules: list[DuplexSurfaceDisclosureRule] = Field(min_length=1)

    @field_validator("surface_rules")
    @classmethod
    def surface_rules_are_unique(
        cls,
        value: list[DuplexSurfaceDisclosureRule],
    ) -> list[DuplexSurfaceDisclosureRule]:
        surface_ids = [item.surface_id for item in value]
        if len(surface_ids) != len(set(surface_ids)):
            raise ValueError("disclosure policy surface rules must be unique")
        return value


class DuplexClientMetadata(DuplexStrictModel):
    client_capabilities: dict[str, Any] | None = Field(
        default=None,
        alias="a2uiClientCapabilities",
    )
    client_data_model: dict[str, Any] | None = Field(
        default=None,
        alias="a2uiClientDataModel",
    )


class DuplexReturnOrigin(DuplexStrictModel):
    surface_revision: int = Field(ge=1, alias="surfaceRevision")
    component_revision: int = Field(ge=1, alias="componentRevision")
    server_message_id: str = Field(pattern=_IDENTIFIER_PATTERN, alias="serverMessageId")


class DuplexErrorCorrelation(DuplexStrictModel):
    source_component_id: str = Field(pattern=_IDENTIFIER_PATTERN, alias="sourceComponentId")
    server_message_id: str = Field(pattern=_IDENTIFIER_PATTERN, alias="serverMessageId")


class DuplexTranscriptEnvelope(DuplexStrictModel):
    sequence: int = Field(ge=1)
    direction: Literal["server_to_client", "client_to_server"]
    message_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    observed_at: str = Field(pattern=_UTC_TIMESTAMP_PATTERN)
    message: dict[str, Any]
    metadata: DuplexClientMetadata | None = None
    origin: DuplexReturnOrigin | None = None
    correlation: DuplexErrorCorrelation | None = None
    acknowledges: list[str] = Field(default_factory=list)

    @field_validator("acknowledges")
    @classmethod
    def acknowledgements_are_unique(cls, value: list[str]) -> list[str]:
        return _unique_strings(value, "acknowledged message ids")

    @model_validator(mode="after")
    def direction_fields_are_consistent(self) -> DuplexTranscriptEnvelope:
        if self.direction == "server_to_client":
            if self.metadata is not None or self.origin is not None or self.correlation is not None:
                raise ValueError(
                    "server_to_client envelopes cannot carry client metadata, origin, or error correlation"
                )
        else:
            if self.acknowledges:
                raise ValueError("client_to_server envelopes cannot acknowledge earlier client messages")
        return self


class A2UIDuplexFixture(DuplexStrictModel):
    schema_version: Literal["mcpaudit.a2ui-duplex.fixture.v1"] = DUPLEX_FIXTURE_SCHEMA
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=_FIXTURE_ID_PATTERN)
    control_kind: Literal["negative", "vulnerable", "near-miss"]
    protocol: Literal["a2ui"]
    protocol_version: Literal["v0.9", "v1.0"]
    clock_domain: Literal["fixture-single-clock-v1"]
    producer: DuplexProducer
    action_contracts: list[DuplexActionContract] = Field(default_factory=list)
    disclosure_policy: DuplexDisclosurePolicy | None = None
    transcript: list[DuplexTranscriptEnvelope] = Field(min_length=1)

    @field_validator("action_contracts")
    @classmethod
    def action_contract_keys_are_unique(
        cls,
        value: list[DuplexActionContract],
    ) -> list[DuplexActionContract]:
        keys = [(item.surface_id, item.component_id, item.action_name) for item in value]
        if len(keys) != len(set(keys)):
            raise ValueError("action contract keys must be unique")
        return value

    @field_validator("transcript")
    @classmethod
    def transcript_sequences_are_unique(
        cls,
        value: list[DuplexTranscriptEnvelope],
    ) -> list[DuplexTranscriptEnvelope]:
        sequences = [item.sequence for item in value]
        if len(sequences) != len(set(sequences)):
            raise ValueError("transcript sequence numbers must be unique")
        return value


class DuplexFinding(DuplexStrictModel):
    rule_id: Literal[
        "MCPDUP000",
        "MCPDUP001",
        "MCPDUP002",
        "MCPDUP003",
        "MCPDUP004",
        "MCPDUP005",
        "MCPDUP006",
    ]
    severity: Literal["high", "medium", "unknown"]
    status: Literal["finding", "unknown", "unsupported"]
    title: str
    target: str
    evidence: list[str] = Field(min_length=1)
    remediation: str
    observable_basis: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def status_matches_rule_and_severity(self) -> DuplexFinding:
        if self.rule_id == "MCPDUP000":
            if self.status == "finding" or self.severity != "unknown":
                raise ValueError("MCPDUP000 must be unknown/unsupported with unknown severity")
        elif self.status != "finding" or self.severity == "unknown":
            raise ValueError("MCPDUP001-MCPDUP006 must be findings with non-unknown severity")
        return self


class DuplexStatistics(DuplexStrictModel):
    envelopes: int = Field(ge=0)
    server_messages: int = Field(ge=0)
    client_returns: int = Field(ge=0)
    surfaces_observed: int = Field(ge=0)
    actions_observed: int = Field(ge=0)
    errors_observed: int = Field(ge=0)
    data_model_returns_observed: int = Field(ge=0)


class A2UIDuplexReport(DuplexStrictModel):
    schema_version: Literal["mcpaudit.a2ui-duplex.report.v1"] = DUPLEX_REPORT_SCHEMA
    fixture_id: str
    producer_id: str
    producer_profile: Literal["web-core-react", "flutter-a2ui", "unknown"]
    protocol_version: Literal["v0.9", "v1.0", "unknown"]
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: Literal["pass", "fail", "unknown"]
    redacted: bool
    findings: list[DuplexFinding] = Field(default_factory=list)
    statistics: DuplexStatistics
    assumptions: list[str] = Field(min_length=1)
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def verdict_matches_findings(self) -> A2UIDuplexReport:
        expected = (
            "fail"
            if any(item.status == "finding" for item in self.findings)
            else "unknown"
            if self.findings
            else "pass"
        )
        if self.verdict != expected:
            raise ValueError("report verdict must match finding status")
        return self


def duplex_canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def duplex_sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
