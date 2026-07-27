"""Strict contracts for the experimental Agent UI Contract Auditor.

These models describe program-owned synthetic fixtures. They are not wire
contracts for MCP Apps, ChatGPT plugins, or A2UI hosts.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MCP_APPS_FIXTURE_SCHEMA: Final = "mcpaudit.agent-ui.mcp-apps-fixture.v1"
A2UI_FIXTURE_SCHEMA: Final = "mcpaudit.agent-ui.a2ui-fixture.v1"
A2UI_MESSAGE_SCHEMA: Final = "mcpaudit.agent-ui.a2ui-message.v0.9"
REPORT_SCHEMA: Final = "mcpaudit.agent-ui.report.v1"
A2UI_CATALOG_ID: Final = "urn:mcpaudit:agent-ui-audit:catalog:v1"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def _require_json_pointer(value: str) -> str:
    if not value.startswith("/"):
        raise ValueError("value must be an absolute JSON Pointer")
    index = 0
    while index < len(value):
        if value[index] == "~":
            if index + 1 >= len(value) or value[index + 1] not in {"0", "1"}:
                raise ValueError("JSON Pointer contains an invalid tilde escape")
            index += 1
        index += 1
    return value


class ControlKind(StrEnum):
    POSITIVE = "positive"
    VULNERABLE = "vulnerable"
    NEGATIVE = "negative"


class HostProfile(StrEnum):
    GENERIC_MCP_APPS = "generic-mcp-apps"
    OPENAI_CHATGPT = "openai-chatgpt"
    PROGRAM_OWNED_A2UI = "program-owned-a2ui-renderer-v1"


class EvidenceState(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    UNKNOWN = "unknown"
    UNVERIFIABLE = "unverifiable"


class VisualState(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NEUTRAL = "neutral"


class DataProvenance(StrEnum):
    STATIC_FIXTURE = "static_fixture"
    TRUSTED_MANIFEST = "trusted_manifest"
    OPERATOR_INPUT = "operator_input"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"
    UNKNOWN = "unknown"


class AgentUISeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class MCPAppsCsp(StrictModel):
    connect_domains: list[str] = Field(default_factory=list, alias="connectDomains")
    resource_domains: list[str] = Field(default_factory=list, alias="resourceDomains")
    frame_domains: list[str] = Field(default_factory=list, alias="frameDomains")


class OpenAIWidgetCsp(StrictModel):
    connect_domains: list[str] = Field(default_factory=list)
    resource_domains: list[str] = Field(default_factory=list)
    frame_domains: list[str] = Field(default_factory=list)
    redirect_domains: list[str] = Field(default_factory=list)


def _default_tool_visibility() -> list[Literal["model", "app"]]:
    return ["model", "app"]


class ToolUIMetadata(StrictModel):
    resource_uri: str | None = Field(default=None, alias="resourceUri")
    visibility: list[Literal["model", "app"]] = Field(default_factory=_default_tool_visibility)


class ResourceUIMetadata(StrictModel):
    csp: MCPAppsCsp = Field(default_factory=MCPAppsCsp)
    domain: str | None = None
    prefers_border: bool | None = Field(default=None, alias="prefersBorder")


class MCPAppsToolMeta(StrictModel):
    ui: ToolUIMetadata = Field(default_factory=ToolUIMetadata)
    openai_output_template: str | None = Field(default=None, alias="openai/outputTemplate")
    openai_widget_accessible: bool | None = Field(default=None, alias="openai/widgetAccessible")
    openai_visibility: Literal["public", "private"] | None = Field(
        default=None,
        alias="openai/visibility",
    )


class MCPAppsResourceMeta(StrictModel):
    ui: ResourceUIMetadata = Field(default_factory=ResourceUIMetadata)
    openai_widget_description: str | None = Field(
        default=None,
        alias="openai/widgetDescription",
    )
    openai_widget_csp: OpenAIWidgetCsp = Field(
        default_factory=OpenAIWidgetCsp,
        alias="openai/widgetCSP",
    )
    openai_widget_domain: str | None = Field(default=None, alias="openai/widgetDomain")


class ToolAnnotations(StrictModel):
    read_only_hint: bool | None = Field(default=None, alias="readOnlyHint")
    destructive_hint: bool | None = Field(default=None, alias="destructiveHint")
    open_world_hint: bool | None = Field(default=None, alias="openWorldHint")


class ToolAuditContract(StrictModel):
    authority: list[str] = Field(min_length=1)
    requires_approval: bool
    approval_version: str | None = None

    @field_validator("authority")
    @classmethod
    def authority_is_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("authority entries must be unique")
        return value


class MCPAppsToolDescriptor(StrictModel):
    name: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    annotations: ToolAnnotations = Field(default_factory=ToolAnnotations)
    meta: MCPAppsToolMeta = Field(alias="_meta")
    audit_contract: ToolAuditContract


class MCPAppsResourceDescriptor(StrictModel):
    uri: str = Field(min_length=1)
    mime_type: Literal["text/html;profile=mcp-app"] = Field(alias="mimeType")
    meta: MCPAppsResourceMeta = Field(alias="_meta")


class UIAction(StrictModel):
    kind: Literal["tool_call", "external_link", "data_sink", "local_state"]
    target: str = Field(min_length=1)
    destination: str | None = None
    sends_data: bool = False

    @model_validator(mode="after")
    def destination_matches_action(self) -> UIAction:
        if self.kind in {"external_link", "data_sink"} and self.destination is None:
            raise ValueError("external_link and data_sink actions require destination")
        if self.kind in {"tool_call", "local_state"} and self.destination is not None:
            raise ValueError("tool_call and local_state actions cannot declare destination")
        return self


class ApprovalPresentation(StrictModel):
    required: bool
    expected_version: str | None = None
    displayed_version: str | None = None
    evidence_state: Literal["current", "stale", "unknown", "unverifiable"]
    visual_state: Literal["pass", "fail", "unknown", "neutral"]
    input_sources: list[
        Literal[
            "static_fixture",
            "trusted_manifest",
            "operator_input",
            "untrusted_tool_output",
            "unknown",
        ]
    ] = Field(min_length=1)

    @field_validator("input_sources")
    @classmethod
    def input_sources_are_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("approval input sources must be unique")
        return value


class RenderedControl(StrictModel):
    component_id: str = Field(min_length=1)
    resource_uri: str = Field(min_length=1)
    label: str = Field(min_length=1)
    visible: bool
    disclosed: bool
    disclosed_authority: list[str] = Field(default_factory=list)
    action: UIAction
    approval: ApprovalPresentation | None = None


class MCPAppsFixture(StrictModel):
    schema_version: Literal["mcpaudit.agent-ui.mcp-apps-fixture.v1"] = MCP_APPS_FIXTURE_SCHEMA
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    control_kind: Literal["positive", "vulnerable", "negative"]
    protocol: Literal["mcp-apps"]
    protocol_profile: Literal["mcp-apps-ext-apps-v1"]
    host_profile: Literal["generic-mcp-apps", "openai-chatgpt"]
    tools: list[MCPAppsToolDescriptor] = Field(default_factory=list)
    resources: list[MCPAppsResourceDescriptor] = Field(min_length=1)
    rendered_controls: list[RenderedControl] = Field(min_length=1)
    declared_external_destinations: list[str] = Field(default_factory=list)


class A2UIActionContract(StrictModel):
    action_name: str = Field(min_length=1)
    authority: list[str] = Field(min_length=1)
    requires_approval: bool
    expected_approval_version: str | None = None

    @field_validator("authority")
    @classmethod
    def authority_is_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("authority entries must be unique")
        return value


class A2UIEvidenceContract(StrictModel):
    component_id: str = Field(min_length=1)
    evidence_state_path: str

    @field_validator("evidence_state_path")
    @classmethod
    def evidence_path_is_pointer(cls, value: str) -> str:
        return _require_json_pointer(value)


class A2UIFixtureManifest(StrictModel):
    schema_version: Literal["mcpaudit.agent-ui.a2ui-fixture.v1"] = A2UI_FIXTURE_SCHEMA
    program_owned: Literal[True]
    fixture_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,127}$")
    control_kind: Literal["positive", "vulnerable", "negative"]
    protocol: Literal["a2ui"]
    protocol_version: Literal["v0.9"]
    host_profile: Literal["program-owned-a2ui-renderer-v1"]
    catalog_id: Literal["urn:mcpaudit:agent-ui-audit:catalog:v1"] = A2UI_CATALOG_ID
    action_contracts: list[A2UIActionContract] = Field(default_factory=list)
    evidence_contracts: list[A2UIEvidenceContract] = Field(default_factory=list)
    data_provenance: dict[
        str,
        Literal[
            "static_fixture",
            "trusted_manifest",
            "operator_input",
            "untrusted_tool_output",
            "unknown",
        ],
    ] = Field(default_factory=dict)
    declared_external_destinations: list[str] = Field(default_factory=list)

    @field_validator("data_provenance")
    @classmethod
    def provenance_keys_are_json_pointers(
        cls,
        value: dict[
            str,
            Literal[
                "static_fixture",
                "trusted_manifest",
                "operator_input",
                "untrusted_tool_output",
                "unknown",
            ],
        ],
    ) -> dict[
        str,
        Literal[
            "static_fixture",
            "trusted_manifest",
            "operator_input",
            "untrusted_tool_output",
            "unknown",
        ],
    ]:
        for key in value:
            _require_json_pointer(key)
        return value


class A2UIFixtureEnvelope(StrictModel):
    fixture: A2UIFixtureManifest


class A2UICreateSurface(StrictModel):
    surface_id: str = Field(min_length=1, alias="surfaceId")
    catalog_id: str = Field(min_length=1, alias="catalogId")
    theme: dict[str, Any] | None = None
    send_data_model: bool = Field(default=False, alias="sendDataModel")


class A2UIDataBinding(StrictModel):
    path: str

    @field_validator("path")
    @classmethod
    def path_is_pointer(cls, value: str) -> str:
        return _require_json_pointer(value)


A2UIBoundValue = str | int | float | bool | None | A2UIDataBinding


class A2UIColumnComponent(StrictModel):
    id: str = Field(min_length=1)
    component: Literal["Column"]
    children: list[str]


class A2UITextComponent(StrictModel):
    id: str = Field(min_length=1)
    component: Literal["Text"]
    text: A2UIBoundValue
    variant: str | None = None


class A2UIEvent(StrictModel):
    name: str = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)


class A2UIButtonAction(StrictModel):
    event: A2UIEvent


class A2UIButtonComponent(StrictModel):
    id: str = Field(min_length=1)
    component: Literal["Button"]
    text: A2UIBoundValue = None
    child: str | None = None
    variant: str | None = None
    action: A2UIButtonAction | None = None
    disclosed_authority: list[str] | None = Field(default=None, alias="disclosedAuthority")
    approval_version: A2UIBoundValue = Field(default=None, alias="approvalVersion")
    evidence_state: A2UIBoundValue = Field(default=None, alias="evidenceState")
    visual_state: A2UIBoundValue = Field(default=None, alias="visualState")
    checks: list[A2UIBoundValue] = Field(default_factory=list)
    enabled: A2UIBoundValue = True


class A2UIStatusBadgeComponent(StrictModel):
    id: str = Field(min_length=1)
    component: Literal["StatusBadge"]
    label: A2UIBoundValue
    state: A2UIBoundValue
    tone: Literal["neutral", "green", "yellow", "red"]


class A2UIExternalLinkComponent(StrictModel):
    id: str = Field(min_length=1)
    component: Literal["ExternalLink"]
    label: A2UIBoundValue
    url: str = Field(min_length=1)
    sends_data: bool = Field(alias="sendsData")


A2UIComponent = Annotated[
    A2UIColumnComponent
    | A2UITextComponent
    | A2UIButtonComponent
    | A2UIStatusBadgeComponent
    | A2UIExternalLinkComponent,
    Field(discriminator="component"),
]


class A2UIUpdateComponents(StrictModel):
    surface_id: str = Field(min_length=1, alias="surfaceId")
    components: list[A2UIComponent] = Field(min_length=1)

    @field_validator("components")
    @classmethod
    def component_ids_are_unique(cls, value: list[A2UIComponent]) -> list[A2UIComponent]:
        identifiers = [component.id for component in value]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("component ids must be unique within one update")
        return value


class A2UIUpdateDataModel(StrictModel):
    surface_id: str = Field(min_length=1, alias="surfaceId")
    path: str = "/"
    value: Any = None

    @field_validator("path")
    @classmethod
    def path_is_absolute(cls, value: str) -> str:
        return _require_json_pointer(value)


class A2UIDeleteSurface(StrictModel):
    surface_id: str = Field(min_length=1, alias="surfaceId")


class A2UIMessage(StrictModel):
    version: Literal["v0.9"]
    create_surface: A2UICreateSurface | None = Field(default=None, alias="createSurface")
    update_components: A2UIUpdateComponents | None = Field(default=None, alias="updateComponents")
    update_data_model: A2UIUpdateDataModel | None = Field(default=None, alias="updateDataModel")
    delete_surface: A2UIDeleteSurface | None = Field(default=None, alias="deleteSurface")

    @model_validator(mode="after")
    def exactly_one_message(self) -> A2UIMessage:
        messages = (
            self.create_surface,
            self.update_components,
            self.update_data_model,
            self.delete_surface,
        )
        if sum(item is not None for item in messages) != 1:
            raise ValueError("A2UI messages must contain exactly one supported message type")
        return self


class AgentUIFinding(StrictModel):
    rule_id: Literal[
        "MCPUI000",
        "MCPUI001",
        "MCPUI002",
        "MCPUI003",
        "MCPUI004",
        "MCPUI005",
        "MCPUI006",
    ]
    severity: AgentUISeverity
    title: str
    target: str
    evidence: list[str] = Field(min_length=1)
    remediation: str
    protocol: Literal["mcp-apps", "a2ui", "unknown"]
    host_profile: str
    assumptions: list[str] = Field(min_length=1)


class AgentUIReport(StrictModel):
    schema_version: Literal["mcpaudit.agent-ui.report.v1"] = REPORT_SCHEMA
    fixture_id: str
    input_kind: Literal["mcp-apps-metadata", "a2ui-jsonl", "unknown"]
    protocol: Literal["mcp-apps", "a2ui", "unknown"]
    protocol_version: str
    host_profile: str
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    verdict: Literal["pass", "fail", "unknown"]
    findings: list[AgentUIFinding] = Field(default_factory=list)
    assumptions: list[str] = Field(min_length=1)
    supported_inputs: list[str] = Field(min_length=1)
    unsupported_inputs: list[str] = Field(min_length=1)
    claim_ceiling: list[str] = Field(min_length=1)


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else value
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
