"""All Pydantic data models for mcp-audit."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, computed_field


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


class SsrfSeverity(StrEnum):
    HIGH = "high"  # Caller-controlled URL param on a server-side fetch tool
    MEDIUM = "medium"  # URL-shaped input, or remote resource with host template var
    LOW = "low"  # Weak signal (host/address param, path-only template var)


class EgressKind(StrEnum):
    DESTINATION_OUTSIDE_ALLOWLIST = "destination_outside_allowlist"  # Fixed host not on the allowlist
    UNBOUNDED_EGRESS = "unbounded_egress"  # Caller-controlled target; not allowlistable
    TRUSTED_DESTINATION_RESIDUAL = "trusted_destination_residual"  # D1 — Cowork class


class EgressSeverity(StrEnum):
    HIGH = "high"  # Unbounded, caller-steerable outbound destination
    MEDIUM = "medium"  # Fixed destination outside the allowlist
    LOW = "low"  # Trusted-destination residual (advisory)


class TrifectaSeverity(StrEnum):
    HIGH = "high"  # Single server holds all three legs (lethal trifecta)
    MEDIUM = "medium"  # Fleet-level: trifecta formed only by combining servers (advisory)


class ShadowingKind(StrEnum):
    EXACT = "exact"  # Identical tool name on ≥2 servers
    NORMALIZED = "normalized"  # Same after case-fold + separator strip
    HOMOGLYPH = "homoglyph"  # Non-ASCII confusable maps to same ASCII skeleton


class ShadowingSeverity(StrEnum):
    HIGH = "high"  # Exact or homoglyph collision
    MEDIUM = "medium"  # Normalised-only collision
    LOW = "low"  # Reserved for future use


class EscalationKind(StrEnum):
    CAPABILITY = "capability"  # Tool gained a dangerous permission category vs its pin baseline
    DESCRIPTION_INJECTION = "description_injection"  # Description gained injection pattern(s)


class EscalationSeverity(StrEnum):
    HIGH = "high"  # Gained exfiltration/shell/destructive, or description gained injection
    MEDIUM = "medium"  # Gained file_write/network


class ProvenanceKind(StrEnum):
    COMMAND = "command"  # Launch command/binary or transport changed
    ARGS = "args"  # Launch arguments changed (version float, package swap, new flag)
    URL = "url"  # HTTP endpoint/URL changed
    CREDENTIALS = "credentials"  # Declared env/header key-name set changed


class ProvenanceSeverity(StrEnum):
    HIGH = "high"  # Command/transport or URL change, or a dangerous flag gained
    MEDIUM = "medium"  # Benign arg drift or credential-key-set change


class IntegrityKind(StrEnum):
    ARTIFACT_DRIFT = "artifact_drift"  # On-disk launch artifact bytes changed/vanished since pin


class IntegritySeverity(StrEnum):
    HIGH = "high"  # Pinned artifact's bytes changed (content differs)
    MEDIUM = "medium"  # Pinned artifact is no longer present at its path


class PackageVerifyKind(StrEnum):
    REGISTRY_DRIFT = "registry_drift"  # Registry-published hash for a pinned package@version changed


class PackageVerifySeverity(StrEnum):
    HIGH = "high"  # Published hash changed (republish-in-place / tampering)
    MEDIUM = "medium"  # Could not verify (registry unreachable / package absent)


class ArtifactVerifyKind(StrEnum):
    # Served bytes' hash differs from the registry's own published hash for the version
    PUBLISHED_MISMATCH = "published_mismatch"
    # Served bytes' hash differs from the byte-hash captured at pin time
    BASELINE_MISMATCH = "baseline_mismatch"
    # Could not download/hash the artifact (unreachable, too large, host not allowlisted)
    UNVERIFIED = "unverified"


class ArtifactVerifySeverity(StrEnum):
    HIGH = "high"  # Bytes don't match the published hash, or differ from the pinned bytes
    MEDIUM = "medium"  # Could not download/hash to verify


class DriftStatus(StrEnum):
    NEW = "new"  # Tool in current scan but not in pins
    CHANGED = "changed"  # Tool hash differs from stored pin
    REMOVED = "removed"  # Tool in pins but missing from current scan


class ConfigHealthSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


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


class PromptInfo(BaseModel):
    """A prompt exposed by an MCP server."""

    name: str
    description: str | None = None
    arguments: list[str] = Field(default_factory=list)


class ResourceInfo(BaseModel):
    """A resource exposed by an MCP server."""

    uri: str
    name: str | None = None
    description: str | None = None
    mime_type: str | None = None


class CapabilityTarget(StrEnum):
    TOOL = "tool"
    PROMPT = "prompt"
    RESOURCE = "resource"


class PermissionFinding(BaseModel):
    """A single permission inference for a tool."""

    category: PermissionCategory
    confidence: Confidence
    evidence: list[str]  # What triggered this finding (pattern matches, annotation values)
    tool_name: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_type(self) -> str:
        return CapabilityTarget.TOOL.value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_name(self) -> str:
        return self.tool_name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).description

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).remediation


class CapabilityFinding(BaseModel):
    """A permission inference for a non-tool MCP capability."""

    target_type: CapabilityTarget
    target_name: str
    category: PermissionCategory
    confidence: Confidence
    evidence: list[str]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).description

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import permission_metadata

        return permission_metadata(self.category).remediation


class InjectionFinding(BaseModel):
    """A prompt injection threat detected in a tool's description or name."""

    tool_name: str
    target_type: CapabilityTarget = CapabilityTarget.TOOL
    target_name: str | None = None
    severity: InjectionSeverity
    pattern_name: str  # e.g. "ignore_instructions"
    matched_text: str  # excerpt (max 200 chars)
    description: str  # human-readable explanation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import injection_metadata

        return injection_metadata(self.severity).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import injection_metadata

        return injection_metadata(self.severity).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import injection_metadata

        return injection_metadata(self.severity).remediation


class SsrfFinding(BaseModel):
    """A server-side request forgery (SSRF) capability detected in a tool or resource.

    Flags interfaces where the server may perform a fetch to a caller-influenceable
    network target (URL/host/endpoint). Static, schema-derived signal only — no
    request is ever made and no credential value is read.
    """

    target_type: CapabilityTarget = CapabilityTarget.TOOL
    target_name: str
    severity: SsrfSeverity
    pattern_name: str  # e.g. "url_param_with_fetch_verb"
    evidence: list[str]  # param names, fetch verbs, or URI scheme/template signals
    description: str  # human-readable explanation

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import ssrf_metadata

        return ssrf_metadata(self.severity).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import ssrf_metadata

        return ssrf_metadata(self.severity).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import ssrf_metadata

        return ssrf_metadata(self.severity).remediation


class EgressFinding(BaseModel):
    """An outbound-destination finding: where an MCP server may send data.

    Where SSRF asks "can a caller steer where the server connects?", egress asks
    "is the destination one we trust?". It flags fixed destinations outside a
    caller-supplied allowlist, caller-controlled (unbounded) destinations, and a
    trusted-destination residual for multi-tenant or credential-bearing hosts.

    Static, schema/URI-derived signal only — no request is ever made and no
    credential value is read; credential signals are param-name / userinfo-template
    only. Metadata is keyed by ``kind`` (the residual kind spans LOW and MEDIUM, so
    severity is not 1:1 with kind); the finding's own ``severity`` is authoritative.
    """

    target_type: CapabilityTarget = CapabilityTarget.TOOL
    target_name: str
    severity: EgressSeverity
    kind: EgressKind
    destination_host: str | None = None  # None when caller-controlled / unbounded
    evidence: list[str]  # hosts, allowlist state, or credential/multi-tenant signals

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import egress_metadata

        return egress_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import egress_metadata

        return egress_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        from mcp_audit.taxonomy import egress_metadata

        return egress_metadata(self.kind).description

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import egress_metadata

        return egress_metadata(self.kind).remediation


class TrifectaFinding(BaseModel):
    """A lethal-trifecta / toxic-flow finding.

    Fires when a server (or fleet) covers all three exfiltration legs:
      Leg 1 — sensitive data access  (FILE_READ)
      Leg 2 — untrusted-content ingestion  (SSRF-flagged or fetch-verb tool/resource)
      Leg 3 — exfiltration  (EXFILTRATION)

    Per-server findings are HIGH; fleet-level advisory findings are MEDIUM.
    Static, permission-inference-derived only — no new inference is performed.
    """

    severity: TrifectaSeverity
    # Leg contributors: maps leg label to list of (server_name, tool_name) pairs
    # For per-server findings server_name is the same for all legs.
    leg1_contributors: list[tuple[str, str]]  # (server_name, tool_name)
    leg2_contributors: list[tuple[str, str]]  # (server_name, tool_name)
    leg3_contributors: list[tuple[str, str]]  # (server_name, tool_name)
    description: str
    is_fleet: bool = False  # True for fleet-level advisory finding

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import trifecta_metadata

        return trifecta_metadata(self.severity).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import trifecta_metadata

        return trifecta_metadata(self.severity).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import trifecta_metadata

        return trifecta_metadata(self.severity).remediation


class EscalationFinding(BaseModel):
    """A capability-escalation / rug-pull finding detected against the pin baseline.

    Fires only when a tool DIFFERS from its operator-blessed pin baseline in a
    security-significant way:
      CAPABILITY            — the tool gained a dangerous permission category it
                              did not hold when pinned (e.g. read-only → file_write,
                              exfiltration, shell_execution, destructive).
      DESCRIPTION_INJECTION — the tool's description gained prompt-injection
                              pattern(s) absent from the pinned baseline.

    Purely a delta against the pin store: a tool matching its baseline produces no
    finding, so the false-positive rate is near-zero by construction.  Requires a
    pin baseline (``--escalation-check`` implies pin comparison).
    """

    kind: EscalationKind
    severity: EscalationSeverity
    server_name: str
    tool_name: str
    gained_categories: list[PermissionCategory] = Field(default_factory=list)
    gained_patterns: list[str] = Field(default_factory=list)  # injection pattern names
    description: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import escalation_metadata

        return escalation_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import escalation_metadata

        return escalation_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import escalation_metadata

        return escalation_metadata(self.kind).remediation


class ProvenanceFinding(BaseModel):
    """A launch-config / provenance change detected against the pin baseline.

    Fires when a server's LAUNCH configuration changed since it was pinned — a
    supply-chain signal independent of the tool schemas:
      COMMAND      — the command/binary or transport changed (HIGH).
      ARGS         — the launch arguments changed: version float, package swap,
                     or a new flag.  MEDIUM, or HIGH if a known-dangerous flag was
                     gained.
      URL          — the HTTP endpoint/URL changed (HIGH).
      CREDENTIALS  — the declared env/header KEY-NAME set changed (MEDIUM).

    Pure delta vs the pinned config snapshot — an unchanged launch config produces
    nothing.  Credential surface is compared by KEY NAME only; values are never
    captured, stored, or displayed.  Requires a pin baseline that includes a
    config snapshot (``--provenance-check`` implies a pin comparison; baselines
    pinned before this feature are skipped until re-pinned).
    """

    kind: ProvenanceKind
    severity: ProvenanceSeverity
    server_name: str
    summary: str  # one-line human description of what changed
    baseline: str  # prior value (command line / url / joined args / joined key names)
    current: str  # current value
    gained_flags: list[str] = Field(default_factory=list)  # dangerous flags newly present (ARGS)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import provenance_metadata

        return provenance_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import provenance_metadata

        return provenance_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import provenance_metadata

        return provenance_metadata(self.kind).remediation


class IntegrityFinding(BaseModel):
    """A launch-artifact integrity change detected against the pin baseline.

    Fires when the on-disk artifact that a server launches (the resolved command
    binary, or a local script passed as an argument) has different bytes than
    when it was pinned — a supply-chain signal the schema and provenance checks
    cannot see, because the command string can stay byte-identical while the file
    it points at is swapped underneath you.

    ARTIFACT_DRIFT covers two cases: the file's SHA-256 changed (HIGH), or the
    pinned file is gone from its path (MEDIUM — often a relocation, but worth a
    look). Offline and deterministic: only on-disk bytes are hashed; nothing is
    fetched. Requires a pin baseline that captured artifact hashes
    (``--integrity-check`` implies a pin comparison; baselines pinned before this
    feature are skipped until re-pinned). Package-runner launches (``npx``/``uvx``)
    hash the runner binary, not the remote package — registry-artifact
    verification is a separate, network-gated follow-up.
    """

    kind: IntegrityKind
    severity: IntegritySeverity
    server_name: str
    artifact_path: str  # absolute on-disk path that was pinned
    baseline_hash: str  # SHA-256 captured at pin time
    current_hash: str | None  # current SHA-256, or None if the file is gone
    summary: str  # one-line human description of what changed

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import integrity_metadata

        return integrity_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import integrity_metadata

        return integrity_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import integrity_metadata

        return integrity_metadata(self.kind).remediation


class PackageVerifyFinding(BaseModel):
    """A registry-published package hash change detected against the pin baseline.

    The on-disk integrity check (MCP024) hashes local bytes; for package-runner
    launches (``npx pkg@x`` / ``uvx pkg``) the meaningful artifact is the remote
    package, not the runner binary. This finding compares the registry-published
    hash for a pinned ``package@version`` against the hash captured at pin time:

      REGISTRY_DRIFT — the registry's published hash for the exact pinned version
                       changed (HIGH, a republish-in-place / tampering signal), or
                       it could not be re-fetched to verify (MEDIUM).

    Network-gated: only populated under ``--verify-artifacts`` (opt-in), and the
    baseline hash is captured only when pinning with ``--verify-artifacts``. A
    version *float* (different version than pinned) is provenance's job (MCP021),
    not this check, which keys by exact ``package@version``.
    """

    kind: PackageVerifyKind
    severity: PackageVerifySeverity
    server_name: str
    ecosystem: str  # "npm" | "pypi"
    package: str
    version: str
    baseline_hash: str
    current_hash: str | None  # None when re-fetch failed (MEDIUM)
    summary: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import package_verify_metadata

        return package_verify_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import package_verify_metadata

        return package_verify_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import package_verify_metadata

        return package_verify_metadata(self.kind).remediation


class ArtifactVerifyFinding(BaseModel):
    """A byte-level artifact verification result against the pin baseline (MCP026).

    MCP025 compares the registry's *published* hash across time; this check
    downloads the actual bytes the registry serves, hashes them, and compares
    against both the registry's published hash (``PUBLISHED_MISMATCH``) and the
    byte-hash captured at pin time (``BASELINE_MISMATCH``). It catches a CDN /
    mirror serving bytes inconsistent with its own metadata — which a
    metadata-to-metadata compare cannot see — and a republish-in-place proven at
    the byte level. ``UNVERIFIED`` (MEDIUM) when the bytes could not be fetched
    or hashed (unreachable, size cap exceeded, download host not allowlisted).

    Network-gated: only populated under ``--download-artifacts`` (opt-in), with
    the byte-hash baseline captured only when pinning with that flag. Keys by
    exact ``package@version``; a version float stays provenance's job (MCP021).
    """

    kind: ArtifactVerifyKind
    severity: ArtifactVerifySeverity
    server_name: str
    ecosystem: str  # "npm" | "pypi"
    package: str
    version: str
    baseline_hash: str
    current_hash: str | None  # sha256 we computed now; None when the fetch failed
    summary: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import artifact_verify_metadata

        return artifact_verify_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import artifact_verify_metadata

        return artifact_verify_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import artifact_verify_metadata

        return artifact_verify_metadata(self.kind).remediation


class DriftFinding(BaseModel):
    """A change detected between pinned and current tool schema."""

    server_name: str
    tool_name: str
    status: DriftStatus
    stored_hash: str | None = None  # None for NEW
    current_hash: str | None = None  # None for REMOVED
    pinned_at: datetime | None = None
    summary: str = ""
    details: list[str] = Field(default_factory=list)
    remediation: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_type(self) -> str:
        return CapabilityTarget.TOOL.value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_name(self) -> str:
        return self.tool_name


class RiskScore(BaseModel):
    """Multi-dimensional risk score for a server."""

    composite: float = Field(ge=0, le=10)
    file_access: float = Field(ge=0, le=10)
    network_access: float = Field(ge=0, le=10)
    shell_execution: float = Field(ge=0, le=10)
    destructive: float = Field(ge=0, le=10)
    exfiltration: float = Field(ge=0, le=10)


class NonToolRisk(BaseModel):
    """Additive prompt/resource risk indicator for non-tool MCP capabilities."""

    composite: float = Field(ge=0, le=10)
    capability_score: float = Field(ge=0, le=10)
    injection_score: float = Field(ge=0, le=10)
    prompt_findings: int = Field(ge=0)
    resource_findings: int = Field(ge=0)
    high_severity_findings: int = Field(ge=0)
    note: str = "Additive prompt/resource risk indicator; does not affect risk_score.composite."


class PolicyViolation(BaseModel):
    """A local policy rule violation detected in an audit report."""

    rule: str
    message: str
    server_name: str | None = None
    tool_name: str | None = None
    severity: str = "high"


class PolicyResult(BaseModel):
    """Result of evaluating an audit report against a local policy file."""

    passed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)


class ConfigHealthFinding(BaseModel):
    """A configuration health warning found before connecting to an MCP server."""

    finding_type: str
    severity: ConfigHealthSeverity
    server_name: str | None = None
    summary: str
    details: list[str] = Field(default_factory=list)
    remediation: str


class ServerAudit(BaseModel):
    """Complete audit result for a single MCP server."""

    server: ServerConfig
    connection_status: str  # "connected", "failed", "timeout", "skipped"
    connection_error: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    permissions: list[PermissionFinding] = Field(default_factory=list)
    capability_findings: list[CapabilityFinding] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    non_tool_risk: NonToolRisk | None = None
    has_annotations: bool = False
    annotation_coverage: float = 0.0  # Percentage of tools with annotations
    injection_findings: list[InjectionFinding] = Field(default_factory=list)
    ssrf_findings: list[SsrfFinding] = Field(default_factory=list)
    egress_findings: list[EgressFinding] = Field(default_factory=list)
    drift_findings: list[DriftFinding] = Field(default_factory=list)
    trifecta_findings: list[TrifectaFinding] = Field(default_factory=list)
    escalation_findings: list[EscalationFinding] = Field(default_factory=list)
    provenance_findings: list[ProvenanceFinding] = Field(default_factory=list)
    integrity_findings: list[IntegrityFinding] = Field(default_factory=list)
    package_verify_findings: list[PackageVerifyFinding] = Field(default_factory=list)
    artifact_verify_findings: list[ArtifactVerifyFinding] = Field(default_factory=list)


class ShadowingFinding(BaseModel):
    """A cross-server tool-name shadowing finding.

    Fires when ≥2 servers expose tools with colliding or confusable names,
    potentially allowing an AI agent to be tricked into routing a call to the
    wrong (possibly malicious) server.  Fleet-level only — tool names are
    unique within a single server by the MCP spec.
    """

    kind: ShadowingKind
    severity: ShadowingSeverity
    name: str  # canonical / colliding tool name
    collisions: list[tuple[str, str]]  # (server_name, tool_name) pairs
    description: str

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import shadowing_metadata

        return shadowing_metadata(self.kind).rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import shadowing_metadata

        return shadowing_metadata(self.kind).title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import shadowing_metadata

        return shadowing_metadata(self.kind).remediation


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
    config_health_findings: list[ConfigHealthFinding] = Field(default_factory=list)
    policy_result: PolicyResult | None = None
    fleet_trifecta_findings: list[TrifectaFinding] = Field(default_factory=list)
    shadowing_findings: list[ShadowingFinding] = Field(default_factory=list)
