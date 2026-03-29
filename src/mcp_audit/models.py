"""All Pydantic data models for mcp-audit."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class TransportType(StrEnum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"  # legacy — detect and warn


class ClientType(StrEnum):
    CLAUDE_DESKTOP = "claude_desktop"
    CLAUDE_CODE = "claude_code"
    CURSOR = "cursor"
    VSCODE = "vscode"
    WINDSURF = "windsurf"


class PermissionCategory(StrEnum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK = "network"
    SHELL_EXEC = "shell_execution"
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfiltration"


class Confidence(StrEnum):
    DECLARED = "declared"  # From MCP tool annotations
    HIGH = "high"  # Multiple strong keyword matches
    MEDIUM = "medium"  # Single strong or multiple moderate
    LOW = "low"  # Weak/inferred
    MANUAL = "manual"  # From user override config
    LLM = "llm"  # Classified by LLM — treated like HIGH confidence


class InjectionSeverity(StrEnum):
    HIGH = "high"  # Clear instruction override attempt
    MEDIUM = "medium"  # Suspicious framing or hidden text
    LOW = "low"  # Weak signal (unusual Unicode, odd formatting)


class DriftStatus(StrEnum):
    NEW = "new"  # Tool in current scan but not in pins
    CHANGED = "changed"  # Tool hash differs from stored pin
    REMOVED = "removed"  # Tool in pins but missing from current scan


class ServerConfig(BaseModel):
    """Represents a single MCP server entry from a client config file."""

    name: str
    client: ClientType
    config_path: str
    project_path: str | None = None  # None = global scope, str = project-scoped
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # Key names only, NEVER values
    transport: TransportType = TransportType.STDIO
    url: str | None = None  # For HTTP/SSE transport
    headers_keys: list[str] = Field(default_factory=list)  # Header key names for HTTP, NEVER values


class ToolAnnotations(BaseModel):
    """MCP tool annotations (hints about behavior)."""

    title: str | None = None
    read_only_hint: bool | None = None  # MCP default: false
    destructive_hint: bool | None = None  # MCP default: true
    idempotent_hint: bool | None = None  # MCP default: false
    open_world_hint: bool | None = None  # MCP default: true


class ToolInfo(BaseModel):
    """A single tool exposed by an MCP server."""

    name: str
    description: str | None = None
    input_schema: dict[str, object] | None = None
    annotations: ToolAnnotations | None = None


class PermissionFinding(BaseModel):
    """A single permission inference for a tool."""

    category: PermissionCategory
    confidence: Confidence
    evidence: list[str]  # What triggered this finding (pattern matches, annotation values)
    tool_name: str


class InjectionFinding(BaseModel):
    """A prompt injection threat detected in a tool's description or name."""

    tool_name: str
    severity: InjectionSeverity
    pattern_name: str  # e.g. "ignore_instructions"
    matched_text: str  # excerpt (max 200 chars)
    description: str  # human-readable explanation


class DriftFinding(BaseModel):
    """A change detected between pinned and current tool schema."""

    server_name: str
    tool_name: str
    status: DriftStatus
    stored_hash: str | None = None  # None for NEW
    current_hash: str | None = None  # None for REMOVED
    pinned_at: datetime | None = None


class RiskScore(BaseModel):
    """Multi-dimensional risk score for a server."""

    composite: float = Field(ge=0, le=10)
    file_access: float = Field(ge=0, le=10)
    network_access: float = Field(ge=0, le=10)
    shell_execution: float = Field(ge=0, le=10)
    destructive: float = Field(ge=0, le=10)
    exfiltration: float = Field(ge=0, le=10)


class ServerAudit(BaseModel):
    """Complete audit result for a single MCP server."""

    server: ServerConfig
    connection_status: str  # "connected", "failed", "timeout", "skipped"
    connection_error: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    permissions: list[PermissionFinding] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    has_annotations: bool = False
    annotation_coverage: float = 0.0  # Percentage of tools with annotations
    injection_findings: list[InjectionFinding] = Field(default_factory=list)
    drift_findings: list[DriftFinding] = Field(default_factory=list)


class AuditReport(BaseModel):
    """Top-level audit report containing all server audits."""

    scan_timestamp: datetime
    hostname: str
    os_platform: str
    servers_discovered: int
    servers_connected: int
    servers_failed: int
    total_tools: int
    high_risk_servers: int  # composite >= 7.0
    audits: list[ServerAudit]
    scan_duration_seconds: float
