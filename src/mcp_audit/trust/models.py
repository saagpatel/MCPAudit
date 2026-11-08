"""Data shapes for Trust Before Connect: resolution, observation, and the verdict card."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

CARD_SCHEMA = "mcp-audit.trust-card/1"
PIN_SCHEMA = "mcp-audit.trust-pin/1"

TargetKind = Literal["registry", "npm", "pypi", "url"]
CheckStatus = Literal["pass", "warn", "fail", "unknown", "info"]
Severity = Literal["high", "medium", "low", "info"]
Verdict = Literal["no_mismatches_observed", "review", "do_not_install", "incomplete"]
ObservationMode = Literal["container", "outside", "none"]
ObservationStatus = Literal["complete", "partial", "failed", "skipped"]


class Check(BaseModel):
    """One resolver check on server.json, its namespace, or the package behind it."""

    id: str
    status: CheckStatus
    summary: str


class EnvVar(BaseModel):
    """A declared environment variable. Only the key name is ever recorded."""

    name: str
    required: bool = False
    secret: bool = False
    has_default: bool = False
    description: str | None = None


class PackageRef(BaseModel):
    registry_type: Literal["npm", "pypi", "oci", "other"]
    identifier: str
    version: str | None = None
    transport: str | None = None
    runtime_hint: str | None = None
    env: list[EnvVar] = Field(default_factory=list)
    arguments: list[str] = Field(default_factory=list)
    install_scripts: list[str] = Field(default_factory=list)


class RemoteRef(BaseModel):
    type: str
    url: str


class Resolution(BaseModel):
    """What the target is and what its published metadata claims."""

    input: str
    kind: TargetKind
    server_name: str | None = None
    registry_listed: bool | None = None
    registry_status: str | None = None
    server_version: str | None = None
    title: str | None = None
    description: str | None = None
    repository_url: str | None = None
    package: PackageRef | None = None
    remote: RemoteRef | None = None
    checks: list[Check] = Field(default_factory=list)


class FileChange(BaseModel):
    path: str
    change: Literal["added", "changed", "deleted"]
    in_home: bool


class NetworkEvent(BaseModel):
    """One attempt the sinkhole recorded. Never a request path, header, or body."""

    kind: Literal["dns", "tcp", "udp"]
    host: str | None = None
    ip: str | None = None
    port: int | None = None
    sni: str | None = None
    http_method: str | None = None
    http_host: str | None = None
    qtype: int | None = None

    def label(self) -> str:
        if self.kind == "dns":
            return f"DNS lookup {self.host}"
        if self.kind == "udp":
            return "UDP datagram (destination not recorded)"
        host = self.sni or self.http_host or self.host or self.ip or "unknown"
        via = " (TLS)" if self.sni else f" (HTTP {self.http_method})" if self.http_method else ""
        return f"TCP connect {host}:{self.port}{via}"


class Phase(BaseModel):
    """Effects observed during one stretch of the session (startup, one tool call, shutdown)."""

    name: str
    tool: str | None = None
    arguments: dict[str, object] | None = None
    is_error: bool | None = None
    error: str | None = None
    file_changes: list[FileChange] = Field(default_factory=list)
    file_changes_truncated: int = 0
    network: list[NetworkEvent] = Field(default_factory=list)


class ToolSummary(BaseModel):
    name: str
    description: str | None = None
    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    open_world_hint: bool | None = None
    inferred: list[str] = Field(default_factory=list)
    injection: list[str] = Field(default_factory=list)
    exercised: bool = False
    skip_reason: str | None = None


class Observation(BaseModel):
    mode: ObservationMode
    status: ObservationStatus
    error: str | None = None
    runtime: str | None = None
    image: str | None = None
    network_policy: str | None = None
    protocol_version: str | None = None
    protocol_era: str | None = None
    server_info: dict[str, str] | None = None
    tools: list[ToolSummary] = Field(default_factory=list)
    prompts: list[str] = Field(default_factory=list)
    resources: int | None = None
    phases: list[Phase] = Field(default_factory=list)
    synthetic_env: list[str] = Field(default_factory=list)
    sandbox: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)


class Mismatch(BaseModel):
    severity: Severity
    summary: str
    tool: str | None = None
    rule: str


class Suggestion(BaseModel):
    title: str
    format: Literal["json", "text"]
    body: str
    note: str | None = None


class VerdictCard(BaseModel):
    schema_: str = Field(default=CARD_SCHEMA, alias="schema")
    generated_at: str
    mcp_audit_version: str
    target: Resolution
    observation: Observation
    mismatches: list[Mismatch] = Field(default_factory=list)
    verdict: Verdict
    headline: str
    suggestions: list[Suggestion] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class PinnedTool(BaseModel):
    name: str
    description: str | None = None
    description_sha256: str
    input_schema_sha256: str
    annotations: dict[str, bool | None] = Field(default_factory=dict)


class TrustPin(BaseModel):
    schema_: str = Field(default=PIN_SCHEMA, alias="schema")
    created_at: str
    target: str
    server_name: str | None = None
    package: str | None = None
    version: str | None = None
    protocol_version: str | None = None
    surface_sha256: str
    tools: list[PinnedTool]

    model_config = {"populate_by_name": True}
