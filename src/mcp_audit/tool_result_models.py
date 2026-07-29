"""Strict fixture and report contracts for the Tool Result Contract Auditor.

The fixture envelope is program-owned test evidence, not an MCP wire format.
The request and response objects inside it are evaluated against the selected
MCP revision by :mod:`mcp_audit.tool_result_scanner`.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Final, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

FIXTURE_SCHEMA: Final = "mcpaudit.tool-result.fixture.v1"
REPORT_SCHEMA: Final = "mcpaudit.tool-result.report.v1"
CURRENT_PROTOCOL_REVISION: Final = "2026-07-28"
ToolResultRuleId: TypeAlias = Literal[
    "MCPTR000",
    "MCPTR001",
    "MCPTR002",
    "MCPTR003",
    "MCPTR004",
    "MCPTR005",
    "MCPTR006",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class ToolResultSeverity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RPCExchange(StrictModel):
    request: dict[str, Any]
    response: dict[str, Any]


class ChannelPolicy(StrictModel):
    required_channels: list[Literal["content", "structuredContent", "resource_link", "embedded_resource"]] = (
        Field(default_factory=list, alias="requiredChannels")
    )
    representation: Literal["independent", "json_equivalent"] | None = None
    text_content_index: int | None = Field(default=None, ge=0, alias="textContentIndex")

    @field_validator("required_channels")
    @classmethod
    def required_channels_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("required channel entries must be unique")
        return value

    @model_validator(mode="after")
    def representation_options_are_coherent(self) -> ChannelPolicy:
        if self.representation == "json_equivalent" and self.text_content_index is None:
            raise ValueError("json_equivalent requires textContentIndex")
        if self.representation != "json_equivalent" and self.text_content_index is not None:
            raise ValueError("textContentIndex is only valid for json_equivalent")
        return self


class ToolUseCorrelation(StrictModel):
    tool_use_id: str = Field(min_length=1, max_length=256, alias="toolUseId")
    result_tool_use_id: str = Field(min_length=1, max_length=256, alias="resultToolUseId")
    tool_name: str = Field(min_length=1, max_length=256, alias="toolName")


class CallExchange(RPCExchange):
    channel_policy: ChannelPolicy | None = Field(default=None, alias="channelPolicy")
    tool_use_correlation: ToolUseCorrelation | None = Field(
        default=None,
        alias="toolUseCorrelation",
    )


class ToolResultFixture(StrictModel):
    schema_version: Literal["mcpaudit.tool-result.fixture.v1"] = Field(
        default=FIXTURE_SCHEMA,
        alias="schemaVersion",
    )
    program_owned: Literal[True] = Field(alias="programOwned")
    fixture_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9._-]+$",
        alias="fixtureId",
    )
    control_kind: Literal["vulnerable", "negative", "near-miss"] = Field(alias="controlKind")
    protocol_revision: str = Field(min_length=1, max_length=32, alias="protocolRevision")
    tools_list: RPCExchange | None = Field(alias="toolsList")
    calls: list[CallExchange] = Field(default_factory=list, max_length=64)
    application_only_metadata_keys: list[str] = Field(
        default_factory=list,
        max_length=64,
        alias="applicationOnlyMetadataKeys",
    )

    @field_validator("application_only_metadata_keys")
    @classmethod
    def metadata_keys_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("application-only metadata keys must be unique")
        if any(not key or len(key) > 256 for key in value):
            raise ValueError("application-only metadata keys must contain 1-256 characters")
        return value


class ToolResultFinding(StrictModel):
    rule_id: ToolResultRuleId
    severity: ToolResultSeverity
    title: str
    target: str
    evidence: list[str] = Field(min_length=1)
    remediation: str


class ToolResultReport(StrictModel):
    schema_version: Literal["mcpaudit.tool-result.report.v1"] = Field(
        default=REPORT_SCHEMA,
        alias="schemaVersion",
    )
    fixture_id: str = Field(alias="fixtureId")
    protocol_revision: str = Field(alias="protocolRevision")
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", alias="inputSha256")
    verdict: Literal["pass", "fail", "unknown"]
    coverage: Literal["complete", "incomplete", "unsupported"]
    findings: list[ToolResultFinding] = Field(default_factory=list)
    supported_inputs: list[str] = Field(min_length=1, alias="supportedInputs")
    unsupported_inputs: list[str] = Field(min_length=1, alias="unsupportedInputs")
    claim_ceiling: list[str] = Field(min_length=1, alias="claimCeiling")


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
