"""All Pydantic data models for mcp-audit."""

from datetime import date, datetime
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import (
    BaseModel,
    Field,
    SerializerFunctionWrapHandler,
    computed_field,
    field_validator,
    model_serializer,
    model_validator,
)


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


class ConnectionMode(StrEnum):
    """Whether this scan attempted to connect to configured MCP servers."""

    UNKNOWN = "unknown"
    ATTEMPTED = "attempted"
    SKIPPED = "skipped"


class PinVerificationState(StrEnum):
    """Result of checking a stored pin's schema and signature."""

    VERIFIED = "verified"
    UNSIGNED = "unsigned"
    UNTRUSTED_SIGNER = "untrusted_signer"
    BAD_SIGNATURE = "bad_signature"
    TAMPERED_ENTRY = "tampered_entry"
    RETIRED_KEY = "retired_key"
    SCHEMA_OUTDATED = "schema_outdated"


def _pin_kid(value: object) -> str | None:
    """Keep only the canonical public key identifier shape in reports."""
    if isinstance(value, str) and len(value) == 16 and all(char in "0123456789abcdef" for char in value):
        return value
    return None


class PinVerification(BaseModel):
    """Structured pin verification status, independent from drift findings."""

    state: PinVerificationState
    kid: str | None = None

    @field_validator("kid", mode="before")
    @classmethod
    def validate_kid(cls, value: object) -> str | None:
        return _pin_kid(value)


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


class FindingSourceTrust(StrEnum):
    """Trust label for the material that produced a permission finding."""

    UNTRUSTED_SERVER_METADATA = "untrusted_server_metadata"
    OPERATOR_OVERRIDE = "operator_override"


class LLMAnalysisStatus(StrEnum):
    """Whether optional LLM augmentation produced an admissible result."""

    COMPLETE = "complete"
    UNKNOWN = "unknown"


class LLMAnalysisReasonCode(StrEnum):
    """Stable reason vocabulary for optional LLM-analysis coverage."""

    COMPLETE = "complete"
    NO_CANDIDATES = "no_candidates"
    INJECTION_DETECTED = "injection_detected"
    PROVIDER_ERROR = "provider_error"
    PROVIDER_REFUSAL = "provider_refusal"
    PROVIDER_INCOMPLETE = "provider_incomplete"
    MALFORMED_OUTPUT = "malformed_output"
    OMITTED_TOOLS = "omitted_tools"
    MISSING_CREDENTIAL = "missing_credential"
    MISSING_DEPENDENCY = "missing_dependency"


class LLMAnalysisSummary(BaseModel):
    """Machine-readable status and provenance for one server's LLM pass.

    The model only augments deterministic findings. ``UNKNOWN`` means the LLM
    result contributed no findings and must not be interpreted as a clean
    classification.
    """

    schema_version: str = "mcp-audit.llm-analysis.v1"
    status: LLMAnalysisStatus
    reason_code: LLMAnalysisReasonCode
    source_trust: FindingSourceTrust = FindingSourceTrust.UNTRUSTED_SERVER_METADATA
    analyzer: str = "anthropic"
    model: str
    candidate_tools: int = 0
    analyzed_tools: int = 0
    findings_added: int = 0


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
    ANNOTATION_DELTA = "annotation_delta"  # Security-relevant annotation hint flip


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


class ReferencedFinding(BaseModel):
    """Core findings carry an offline reference without changing existing fields."""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def reference_url(self) -> str:
        from mcp_audit.taxonomy import config_health_rule_id, finding_url

        rule_id = getattr(self, "rule_id", None)
        if isinstance(rule_id, str):
            return finding_url(rule_id)
        if isinstance(self, ConfigHealthFinding):
            return finding_url(config_health_rule_id(self.finding_type))
        return finding_url("MCP009" if isinstance(self, DriftFinding) else "MCP010")


class ServerConfig(BaseModel):
    """Represents a single MCP server entry from a client config file."""

    name: str
    client: ClientType
    config_path: str
    config_source: Literal["explicit file; parsed as Claude-style config"] | None = None
    config_pointer: str | None = None  # JSON Pointer to the parsed server entry; null on legacy records
    project_path: str | None = None  # None = global scope, str = project-scoped
    scope: Literal["workstation", "project"] = "workstation"
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)  # Key names only, NEVER values
    transport: TransportType = TransportType.STDIO
    url: str | None = None  # For HTTP/SSE transport
    headers_keys: list[str] = Field(default_factory=list)  # Header key names for HTTP, NEVER values

    @property
    def source_label(self) -> str:
        """Display the selected-file source without changing the legacy client identity."""
        return self.config_source or self.client.value

    @model_validator(mode="after")
    def tag_project_scope(self) -> Self:
        if self.project_path is not None:
            self.scope = "project"
        return self


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
    title: str | None = None
    output_schema: dict[str, object] | None = None
    icons: list[dict[str, object]] | None = None
    meta: dict[str, object] | None = None


class PromptArgumentInfo(BaseModel):
    """Agent-visible prompt argument metadata."""

    name: str
    description: str | None = None
    required: bool | None = None


class PromptInfo(BaseModel):
    """A prompt exposed by an MCP server."""

    name: str
    description: str | None = None
    arguments: list[str] = Field(default_factory=list)
    argument_details: list[PromptArgumentInfo] = Field(default_factory=list)


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


class AnnotationFinding(ReferencedFinding):
    """An explicit served annotation contradicts keyword capability evidence."""

    kind: Literal["annotation_contradiction"] = "annotation_contradiction"
    tool_name: str
    hint: str
    declared_value: bool
    category: PermissionCategory
    confidence: Confidence
    severity: Literal["medium", "high"]
    evidence: list[str]
    field_paths: list[str] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        from mcp_audit.taxonomy import ANNOTATION_CONTRADICTION

        return ANNOTATION_CONTRADICTION.rule_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import ANNOTATION_CONTRADICTION

        return ANNOTATION_CONTRADICTION.title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import ANNOTATION_CONTRADICTION

        return ANNOTATION_CONTRADICTION.remediation


class PermissionFinding(ReferencedFinding):
    """A single permission inference for a tool."""

    category: PermissionCategory
    confidence: Confidence
    evidence: list[str]  # What triggered this finding (pattern matches, annotation values)
    tool_name: str
    field_paths: list[str] = Field(default_factory=list)
    source_trust: FindingSourceTrust = FindingSourceTrust.UNTRUSTED_SERVER_METADATA
    analyzer: str = "mcp-audit.permission-analyzer"
    analyzer_model: str | None = None
    analysis_status: LLMAnalysisStatus = LLMAnalysisStatus.COMPLETE

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


class CapabilityFinding(ReferencedFinding):
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


class InjectionFinding(ReferencedFinding):
    """A prompt injection threat detected in a tool's description or name."""

    tool_name: str
    target_type: CapabilityTarget = CapabilityTarget.TOOL
    target_name: str | None = None
    severity: InjectionSeverity
    pattern_name: str  # e.g. "ignore_instructions"
    after_call: int | None = None  # Set for runtime tool-result findings
    matched_text: str  # excerpt (max 200 chars)
    matched_span: tuple[int, int] | None = None  # Display offsets in redacted matched_text, end-exclusive
    description: str  # human-readable explanation
    field_path: str | None = None

    instruction_pattern: str | None = None  # Static pattern name for free-text matches
    hunt_targets: list[str] = Field(default_factory=list)  # Target names/paths, never values

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

        if self.after_call is not None:
            return (
                "Review the tool's returned content or prompt body and the server's behavior. "
                "Do not let the agent act on instructions found in tool results or prompt bodies. "
                "Consider removing the server."
            )
        return injection_metadata(self.severity).remediation


class SsrfFinding(ReferencedFinding):
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


class EgressFinding(ReferencedFinding):
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


class RuleOfTwoPosture(BaseModel):
    """Advisory Rule-of-Two remediation attached to a fired trifecta finding.

    Meta's Oct 2025 framing: an agent should hold at most two of {untrusted input,
    sensitive data access, external communication}. Dropping any one leg breaks the
    trifecta. This posture names the legs present, recommends the single best leg to
    drop (prefer Leg 3 / exfiltration when present, else the leg with the fewest
    contributing tools), and lists the other legs as alternatives so the operator can
    pick a different trade-off. Purely advisory — it never changes when the trifecta fires.
    """

    legs_present: list[int]  # subset of [1, 2, 3]
    recommended_drop: int  # the leg to remove (1 | 2 | 3)
    action: str  # concrete remediation text for the recommended drop
    affected_tools: list[str]  # tool names tied to the dropped leg
    alternatives: list[tuple[int, str]]  # (leg, action) for the other legs


class TrifectaFinding(ReferencedFinding):
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
    rule_of_two: RuleOfTwoPosture | None = None  # advisory remediation (attached when fired)

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


class EscalationFinding(ReferencedFinding):
    """A capability-escalation / rug-pull finding detected against the pin baseline.

    Fires only when a tool DIFFERS from its operator-blessed pin baseline in a
    security-significant way:
      CAPABILITY            — the tool gained a dangerous permission category it
                              did not hold when pinned (e.g. read-only → file_write,
                              exfiltration, shell_execution, destructive).
      DESCRIPTION_INJECTION — the tool's description gained prompt-injection
                              pattern(s) absent from the pinned baseline.

    Purely a delta against the pin store: a tool matching its baseline produces no
    finding, so findings stay scoped to reviewed baseline deltas.  Requires a pin
    baseline (``--escalation-check`` implies pin comparison).
    """

    kind: EscalationKind
    severity: EscalationSeverity
    server_name: str
    tool_name: str
    gained_categories: list[PermissionCategory] = Field(default_factory=list)
    gained_patterns: list[str] = Field(default_factory=list)  # injection pattern names
    annotation_changes: list[str] = Field(default_factory=list)  # hint names, never raw metadata
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


class ProvenanceFinding(ReferencedFinding):
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


class IntegrityFinding(ReferencedFinding):
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


class PackageVerifyFinding(ReferencedFinding):
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


class ArtifactVerifyFinding(ReferencedFinding):
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


class SurfaceFieldChange(BaseModel):
    """A field-level diff retaining hashes rather than untrusted/secret values."""

    path: str  # JSON Pointer within the capability
    before_hash: str | None = None  # None means absent
    after_hash: str | None = None


CANARY_NOT_EXCLUDED: dict[str, str] = {
    "time": "elapsed time",
    "randomness": "randomness",
    "call_count_gt_budget": "more than {budget} calls",
    "client_identity": "client identity",
    "arguments": "other arguments",
    "other_tool_sequences": "other call sequences",
    "later_sessions": "later sessions",
}


class CanarySummary(BaseModel):
    """Bounded runtime exercise coverage; complete does not mean trustworthy."""

    requested_calls: int
    client_identity: str = ""  # Older reports did not record the presented identity.
    client_identities: list[str] = Field(default_factory=list)
    baseline_source: Literal["session", "pin"] = "session"
    elapsed_seconds: float | None = None
    call_budget: int = Field(default_factory=lambda data: data["requested_calls"])
    not_excluded: list[str] = Field(default_factory=lambda: list(CANARY_NOT_EXCLUDED))
    completed_calls: int = 0
    prompt_get_calls: int = 0
    baseline_hash: str | None = None
    current_hash: str | None = None
    status: Literal["complete", "partial", "no_safe_tools"] = "partial"
    warnings: list[str] = Field(default_factory=list)

    @property
    def not_excluded_descriptions(self) -> list[str]:
        return [
            CANARY_NOT_EXCLUDED.get(identifier, identifier).replace("{budget}", str(self.call_budget))
            for identifier in self.not_excluded
        ]


class DriftFinding(ReferencedFinding):
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
    source: Literal["pin", "session"] = "pin"
    requirement_level: Literal["protocol_must", "heuristic"] = "heuristic"
    kind: Literal["IDENTITY_CONDITIONED_SURFACE"] | None = None
    severity: Literal["low", "medium", "high"] = "medium"
    after_call: int | None = None
    surface_type: CapabilityTarget = CapabilityTarget.TOOL
    surface: str | None = None  # tools, prompts, prompt_results, or resources for a session
    field_changes: list[SurfaceFieldChange] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _serialize_requirement(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if self.requirement_level == "heuristic":
            data.pop("requirement_level", None)
        return data

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_type(self) -> str:
        return self.surface_type.value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_name(self) -> str:
        return self.tool_name


class PinIntegrityFinding(ReferencedFinding):
    """A signed pin failed verification, so its baseline cannot be trusted."""

    state: Literal["untrusted_signer", "bad_signature", "tampered_entry"]
    server_name: str
    kid: str | None = None
    summary: str
    severity: Literal["high"] = "high"

    @field_validator("kid", mode="before")
    @classmethod
    def validate_kid(cls, value: object) -> str | None:
        return _pin_kid(value)

    @field_validator("summary")
    @classmethod
    def sanitize_summary(cls, value: str) -> str:
        from mcp_audit.redaction import redact_text
        from mcp_audit.terminal_text import strip_controls

        return " ".join(strip_controls(redact_text(value)).split())

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        return "MCP027"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        from mcp_audit.taxonomy import PIN_INTEGRITY_FINDING

        return PIN_INTEGRITY_FINDING.title

    @computed_field  # type: ignore[prop-decorator]
    @property
    def description(self) -> str:
        return self.summary

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import PIN_INTEGRITY_FINDING

        return PIN_INTEGRITY_FINDING.remediation


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


class PolicyViolation(ReferencedFinding):
    """A local policy rule violation detected in an audit report."""

    rule: str
    message: str
    server_name: str | None = None
    tool_name: str | None = None
    severity: str = "high"
    audit_index: int | None = Field(default=None, ge=0)  # Source row; null for fleet or legacy violations.


class PolicyResult(BaseModel):
    """Result of evaluating an audit report against a local policy file."""

    passed: bool
    violations: list[PolicyViolation] = Field(default_factory=list)


class ConfigHealthFinding(ReferencedFinding):
    """A configuration health warning found before connecting to an MCP server."""

    finding_type: str
    severity: ConfigHealthSeverity
    server_name: str | None = None
    summary: str
    details: list[str] = Field(default_factory=list)
    remediation: str
    config_paths: list[str] = Field(default_factory=list)


class SchemaFinding(ReferencedFinding):
    """A static finding on a served tool schema or icon declaration."""

    tool_name: str
    kind: str
    evidence: list[str]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def rule_id(self) -> str:
        return {
            "header_invalid": "MCP051",
            "header_duplicate": "MCP051",
            "header_type": "MCP051",
            "header_unreachable": "MCP051",
            "credential_header": "MCP052",
            "external_ref": "MCP053",
            "icon_source": "MCP054",
            "icon_origin": "MCP054",
        }[self.kind]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity(self) -> str:
        return "medium" if self.kind.startswith("header_") else "low"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def title(self) -> str:
        return {
            "header_invalid": "Invalid MCP header declaration",
            "header_duplicate": "Duplicate MCP header declaration",
            "header_type": "Non-primitive MCP header value",
            "header_unreachable": "Unreachable MCP header declaration",
            "credential_header": "Credential parameter mirrored to a header",
            "external_ref": "External schema reference",
            "icon_source": "Unsupported icon source",
            "icon_origin": "Cross-origin icon source",
        }[self.kind]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def target_name(self) -> str:
        return self.tool_name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remediation(self) -> str:
        from mcp_audit.taxonomy import FINDING_COPY

        # Per-finding detail keeps distinct schema problems as distinct summary actions.
        detail = f" ({self.evidence[0]})" if self.evidence else ""
        return FINDING_COPY[self.rule_id].how_to_fix + detail


class CacheHintObservation(BaseModel):
    """Wire hints for one page; presence flags distinguish absent from invalid."""

    method: str
    listing: int = Field(ge=0)
    page: int = Field(ge=0)
    ttl_ms: int | None = None
    cache_scope: Literal["public", "private"] | None = None
    ttl_ms_present: bool = False
    cache_scope_present: bool = False


class ProtocolObservation(BaseModel):
    """SDK observations, without interpreting unavailable evidence as a violation."""

    negotiated_version: str | None = None
    era: Literal["modern", "legacy", "unknown"] = "unknown"
    discover_supported: bool | None = None
    server_info: dict[str, str] | None = None
    session_id_minted: bool | None = None
    extensions: list[str] = Field(default_factory=list)
    cache_hints: list[CacheHintObservation] = Field(default_factory=list)
    tools_order: list[list[str]] = Field(default_factory=list)
    logging_advertised: bool | None = None


class ProtocolFinding(ReferencedFinding):
    """An advisory supported by observed protocol evidence only."""

    rule_id: str
    title: str
    summary: str
    remediation: str
    severity: Literal["low"] = "low"
    requirement_level: Literal["protocol_must", "protocol_should", "advisory"] = "advisory"
    target_type: str = "server"
    target_name: str = ""


class ServerAudit(BaseModel):
    """Complete audit result for a single MCP server."""

    server: ServerConfig
    presentation_id: str | None = None  # Compatibility field; review_summary now owns grouping identities.
    connection_status: str  # "connected", "partial", "failed", "timeout", "skipped"
    connection_error: str | None = None
    protocol: ProtocolObservation | None = None
    protocol_findings: list[ProtocolFinding] = Field(default_factory=list)
    pin_verification: PinVerification | None = None
    pin_integrity_findings: list[PinIntegrityFinding] = Field(default_factory=list)
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    permissions: list[PermissionFinding] = Field(default_factory=list)
    annotation_findings: list[AnnotationFinding] = Field(default_factory=list)
    capability_findings: list[CapabilityFinding] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    permission_alert_score: float | None = Field(default=None, ge=0, le=10)
    non_tool_risk: NonToolRisk | None = None
    has_annotations: bool = False
    annotation_coverage: float = 0.0  # Percentage of tools with annotations
    annotations_missing: bool = False  # Informational; missing hints are not capability evidence.
    injection_findings: list[InjectionFinding] = Field(default_factory=list)
    schema_findings: list[SchemaFinding] = Field(default_factory=list)
    ssrf_findings: list[SsrfFinding] = Field(default_factory=list)
    egress_findings: list[EgressFinding] = Field(default_factory=list)
    drift_findings: list[DriftFinding] = Field(default_factory=list)
    trifecta_findings: list[TrifectaFinding] = Field(default_factory=list)
    escalation_findings: list[EscalationFinding] = Field(default_factory=list)
    provenance_findings: list[ProvenanceFinding] = Field(default_factory=list)
    integrity_findings: list[IntegrityFinding] = Field(default_factory=list)
    package_verify_findings: list[PackageVerifyFinding] = Field(default_factory=list)
    artifact_verify_findings: list[ArtifactVerifyFinding] = Field(default_factory=list)
    llm_analysis: LLMAnalysisSummary | None = None
    canary: CanarySummary | None = None

    @model_serializer(mode="wrap")
    def _serialize_protocol(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        # Preserve legacy/config-only output when no protocol was observed.
        if self.protocol is None:
            data.pop("protocol", None)
        if not self.protocol_findings:
            data.pop("protocol_findings", None)
        if self.pin_verification is None:
            data.pop("pin_verification", None)
        if not self.pin_integrity_findings:
            data.pop("pin_integrity_findings", None)
        return data


class ShadowingFinding(ReferencedFinding):
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


class ScanWarning(BaseModel):
    """A non-fatal condition that reduced scan coverage.

    Emitted when a requested check could not run (no pin baseline, missing
    credential or dependency) or an option had no effect. Structured so JSON
    and MCP consumers — which see no console output — can distinguish
    "checked, clean" from "check silently skipped".

    ``code`` is a stable machine key from the vocabulary documented in
    docs/OUTPUT-CONTRACT.md. The vocabulary is additive: consumers must
    tolerate codes they do not recognize.
    """

    code: str
    message: str  # plain text, remediation included; no console markup
    check: str | None = None  # the ScanOptions field whose coverage was reduced
    servers: list[str] = Field(default_factory=list)  # affected servers; empty = whole scan


AUDIT_REPORT_SCHEMA_VERSION = 1
"""Version of the AuditReport JSON contract.

Bump on breaking shape changes (field removals/renames/retypes) so downstream
consumers — mcp-trust's engine adapter, shadow-mcp's grading path, hosted
callers of :mod:`mcp_audit.api` — can detect drift at runtime instead of
failing on attribute access. Additive fields do NOT bump this.
"""


CoverageState = Literal["complete", "partial", "not_run", "not_requested"]


class CheckCoverage(BaseModel):
    """Completion of a bounded check, independent of whether it found a risk."""

    state: CoverageState
    reason: str


class ReviewActionDisplay(BaseModel):
    """Precomputed terminal copy and reach; contains display text only."""

    severity: str
    title: str
    consequence: str
    step: str
    sources: tuple[str, ...]
    identities: tuple[str, ...]
    rule: str
    related: int = 0
    flags: tuple[str, ...] = ()
    connected: bool = False
    observed: str = ""
    confidence: str = ""
    time_to_fix: str = ""
    manual_step: str = ""
    reference: str = ""


class ReviewAction(BaseModel):
    """One pre-grouped action; identities are report-local ordinals, never identifiers."""

    identity: str = Field(pattern=r"^action-[0-9]{4,}$")
    owner: str = Field(pattern=r"^owner-[0-9]{4,}$")
    severity: str
    title: str
    steps: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    terminal: ReviewActionDisplay | None = None
    card_group: str | None = Field(default=None, pattern=r"^card-[0-9]{4,}$")


ReviewGrade = Literal["A", "B", "C", "D", "F"]


class ReviewSummary(BaseModel):
    """Snapshot of review decisions made before any display redaction."""

    actions: list[ReviewAction]
    action_counts: dict[str, int]
    action_count: int
    grade: ReviewGrade | None
    review_minutes: int


class UxSummary(BaseModel):
    """Presentation rubric, independent of numeric capability exposure."""

    grade: Literal["A", "B", "C", "D", "F"] | None
    caveat: str = "reach and hygiene, not a safety certificate"


class SuppressedFinding(BaseModel):
    """An explicit policy exception; the original finding remains in the report."""

    finding_path: str
    rule_id: str
    reason: str = Field(min_length=1)
    source: Literal["config", "cli"]
    expires: date | None = None


class AuditReport(BaseModel):
    """Top-level audit report containing all server audits."""

    schema_version: int = AUDIT_REPORT_SCHEMA_VERSION
    scan_timestamp: datetime
    hostname: str
    os_platform: str
    connection_mode: ConnectionMode = ConnectionMode.UNKNOWN
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
    warnings: list[ScanWarning] = Field(default_factory=list)
    coverage: dict[str, CheckCoverage] = Field(default_factory=dict)
    review_summary: ReviewSummary | None = None
    suppressed: list[SuppressedFinding] = Field(default_factory=list)

    def ensure_review_summary(self) -> ReviewSummary:
        """Freeze once at first presentation/export, after scan and policy evaluation."""
        if self.review_summary is None:
            from mcp_audit.ux_summary import compute_summary

            self.review_summary = compute_summary(self)
        return self.review_summary

    @model_serializer(mode="wrap")
    def _serialize(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        self.ensure_review_summary()
        result: dict[str, Any] = handler(self)
        return result

    @computed_field(repr=False)  # type: ignore[prop-decorator]
    @property
    def ux_summary(self) -> UxSummary:
        """Main's JSON compatibility view; all decisions come from ReviewSummary."""
        return UxSummary(grade=self.ensure_review_summary().grade)

    def redacted(self, *, identifiers: bool = False) -> "AuditReport":
        """Return a credential-redacted copy, optionally scrubbing field-report identifiers."""
        from mcp_audit.redaction import redact_data, redact_identifiers

        data = redact_data(self.model_dump(mode="json"))
        if identifiers:
            names = {audit.server.name for audit in self.audits if audit.server.name}
            names.update(f.server_name for f in self.config_health_findings if f.server_name)
            width = max(2, len(str(len(names))))  # Keep alias ordering stable across repeated redaction.
            aliases = {name: f"server-{index:0{width}d}" for index, name in enumerate(sorted(names), start=1)}
            data = redact_identifiers(data, hostname=self.hostname, name_aliases=aliases)
        # Redaction may change only display text within the saved summary.
        summary = self.ensure_review_summary()
        saved = data["review_summary"]
        saved.update(summary.model_dump(exclude={"actions"}))
        for action_data, action in zip(saved["actions"], summary.actions, strict=True):
            action_data.update(
                identity=action.identity,
                owner=action.owner,
                severity=action.severity,
                card_group=action.card_group,
            )
            if action_data["terminal"] is not None:
                action_data["terminal"]["severity"] = action.severity
        return AuditReport.model_validate(data)
