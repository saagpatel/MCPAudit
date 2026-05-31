"""Stable finding metadata and remediation guidance."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_audit.models import (
    InjectionSeverity,
    PermissionCategory,
    ShadowingKind,
    SsrfSeverity,
    TrifectaSeverity,
)


@dataclass(frozen=True)
class FindingMetadata:
    """Stable, user-facing metadata for one finding rule."""

    rule_id: str
    title: str
    severity: str
    description: str
    remediation: str


PERMISSION_FINDINGS: dict[PermissionCategory, FindingMetadata] = {
    PermissionCategory.FILE_READ: FindingMetadata(
        rule_id="MCP001",
        title="File read capability",
        severity="low",
        description="Tool metadata indicates the server may read local files or file-like inputs.",
        remediation="Review the configured paths and only keep this server enabled for trusted projects.",
    ),
    PermissionCategory.FILE_WRITE: FindingMetadata(
        rule_id="MCP002",
        title="File write capability",
        severity="medium",
        description="Tool metadata indicates the server may create or modify local files.",
        remediation=(
            "Confirm the server is trusted before allowing it to run in writable project directories."
        ),
    ),
    PermissionCategory.NETWORK: FindingMetadata(
        rule_id="MCP003",
        title="Network access capability",
        severity="medium",
        description="Tool metadata or config hints indicate the server may contact external services.",
        remediation="Check the server source and destination service before exposing private workspace data.",
    ),
    PermissionCategory.SHELL_EXEC: FindingMetadata(
        rule_id="MCP004",
        title="Shell execution capability",
        severity="high",
        description="Tool metadata indicates the server may run shell commands or local processes.",
        remediation="Disable or isolate this server until you have reviewed the command surface and source.",
    ),
    PermissionCategory.DESTRUCTIVE: FindingMetadata(
        rule_id="MCP005",
        title="Destructive operation capability",
        severity="high",
        description="Tool annotations or metadata indicate the server may perform destructive actions.",
        remediation="Require explicit human review before using this server for write or delete workflows.",
    ),
    PermissionCategory.EXFILTRATION: FindingMetadata(
        rule_id="MCP006",
        title="Data exfiltration capability",
        severity="high",
        description=(
            "Tool metadata indicates the server may combine local data access with outbound transfer."
        ),
        remediation="Treat this as sensitive: verify the server owner, destination, and data handling path.",
    ),
}


INJECTION_FINDINGS: dict[InjectionSeverity, FindingMetadata] = {
    InjectionSeverity.HIGH: FindingMetadata(
        rule_id="MCP007",
        title="High-severity prompt injection",
        severity="high",
        description="Tool text appears to contain direct instruction override or prompt-leak behavior.",
        remediation=(
            "Do not pipe this output into an AI assistant as trusted text; review or disable the server."
        ),
    ),
    InjectionSeverity.MEDIUM: FindingMetadata(
        rule_id="MCP008",
        title="Suspicious prompt content",
        severity="medium",
        description="Tool text contains hidden, role-like, or suspicious prompt-shaping content.",
        remediation=(
            "Inspect the tool description and server source before granting this server broad access."
        ),
    ),
    InjectionSeverity.LOW: FindingMetadata(
        rule_id="MCP008",
        title="Suspicious prompt content",
        severity="low",
        description="Tool text contains weak prompt-injection signals that may still deserve review.",
        remediation="Review the matched text and confirm it is expected for this server.",
    ),
}


SSRF_FINDINGS: dict[SsrfSeverity, FindingMetadata] = {
    SsrfSeverity.HIGH: FindingMetadata(
        rule_id="MCP011",
        title="Server-side request forgery (SSRF) capability",
        severity="high",
        description=(
            "A tool accepts a caller-controllable URL or host and appears to fetch it "
            "server-side, which can reach internal services or cloud metadata endpoints."
        ),
        remediation=(
            "Confirm the server validates and allowlists outbound targets and blocks "
            "link-local, loopback, and metadata addresses before enabling it for untrusted input."
        ),
    ),
    SsrfSeverity.MEDIUM: FindingMetadata(
        rule_id="MCP012",
        title="Possible SSRF-prone request capability",
        severity="medium",
        description=(
            "A tool or resource exposes a URL-shaped input or a caller-templated remote host, "
            "which may let a caller steer where the server connects."
        ),
        remediation=(
            "Review how the server resolves and fetches this target; restrict it to known, "
            "trusted destinations before exposing private workspace data."
        ),
    ),
    SsrfSeverity.LOW: FindingMetadata(
        rule_id="MCP012",
        title="Possible SSRF-prone request capability",
        severity="low",
        description=(
            "A tool or resource exposes a weak SSRF signal such as a host/address input or a "
            "path-only templated remote URI that may still deserve review."
        ),
        remediation="Confirm the destination is expected and not caller-controllable for this server.",
    ),
}


TRIFECTA_FINDINGS: dict[TrifectaSeverity, FindingMetadata] = {
    TrifectaSeverity.HIGH: FindingMetadata(
        rule_id="MCP013",
        title="Lethal trifecta: single-server toxic flow",
        severity="high",
        description=(
            "A single MCP server covers all three exfiltration legs: sensitive data access "
            "(file_read), untrusted-content ingestion (SSRF-flagged or fetch-verb tool/resource), and "
            "an outbound exfiltration capability (exfiltration). This is the canonical agent-exfiltration "
            "attack surface — a malicious or compromised tool description could instruct an AI agent "
            "to read sensitive files, fetch attacker-controlled content, and transmit the data out."
        ),
        remediation=(
            "Audit this server's tools individually. Consider whether all three capability legs are "
            "strictly necessary. If any leg is optional, disable it or move it to a separate, "
            "isolated server. Apply a strict allowlist for outbound destinations and validate all "
            "file-read paths. Never expose this server to untrusted prompts or tool outputs."
        ),
    ),
    TrifectaSeverity.MEDIUM: FindingMetadata(
        rule_id="MCP014",
        title="Lethal trifecta: fleet-level toxic flow (advisory)",
        severity="medium",
        description=(
            "Across the audited fleet, all three exfiltration legs are covered: sensitive data access "
            "(file_read), untrusted-content ingestion (SSRF-flagged or fetch-verb tool/resource), and "
            "an outbound exfiltration capability (exfiltration) — but no single server holds all three "
            "simultaneously. In a compromised multi-server agent session the legs could combine "
            "across server boundaries to achieve the same exfiltration outcome."
        ),
        remediation=(
            "Review which servers are active together in agent sessions. If the full trifecta can "
            "assemble across servers within the same session, apply per-server access controls or "
            "reduce the permission surface. Consider isolating high-privilege servers to separate "
            "agent contexts."
        ),
    ),
}


def permission_metadata(category: PermissionCategory) -> FindingMetadata:
    """Return stable metadata for a permission category."""
    return PERMISSION_FINDINGS[category]


def injection_metadata(severity: InjectionSeverity) -> FindingMetadata:
    """Return stable metadata for an injection severity."""
    return INJECTION_FINDINGS[severity]


def ssrf_metadata(severity: SsrfSeverity) -> FindingMetadata:
    """Return stable metadata for an SSRF severity."""
    return SSRF_FINDINGS[severity]


def trifecta_metadata(severity: TrifectaSeverity) -> FindingMetadata:
    """Return stable metadata for a trifecta severity."""
    return TRIFECTA_FINDINGS[severity]


SHADOWING_FINDINGS: dict[ShadowingKind, FindingMetadata] = {
    ShadowingKind.EXACT: FindingMetadata(
        rule_id="MCP015",
        title="Exact tool-name collision across servers",
        severity="high",
        description=(
            "Two or more MCP servers expose a tool with the identical name.  An AI agent "
            "routing by tool name could be tricked into calling the wrong (possibly malicious) "
            "server.  The first-configured server is presumed legitimate; later ones are suspect."
        ),
        remediation=(
            "Ensure each server namespaces its tools uniquely (e.g. github_search, slack_search). "
            "Remove or rename the duplicate tool on the secondary server."
        ),
    ),
    ShadowingKind.NORMALIZED: FindingMetadata(
        rule_id="MCP016",
        title="Normalised tool-name collision across servers",
        severity="medium",
        description=(
            "Two or more MCP servers expose tools whose names are identical after case-folding "
            "and separator removal (e.g. read_file vs readFile vs read-file).  An AI agent "
            "may route ambiguously between them."
        ),
        remediation=(
            "Adopt a consistent namespace prefix for each server's tools so normalised forms "
            "remain distinct (e.g. fs_read_file vs db_read_file)."
        ),
    ),
    ShadowingKind.HOMOGLYPH: FindingMetadata(
        rule_id="MCP017",
        title="Homoglyph tool-name collision across servers",
        severity="high",
        description=(
            "A tool name on one server contains non-ASCII confusable characters whose ASCII "
            "skeleton matches a tool name on another server (e.g. Cyrillic 'е' mimicking 'e'). "
            "This is a deliberate spoofing signal — the malicious server shadows the legitimate "
            "one by registering a visually identical but byte-distinct tool name."
        ),
        remediation=(
            "Remove the server with the non-ASCII tool name unless it is explicitly trusted. "
            "Report the finding to the server author if the homoglyph appears accidental."
        ),
    ),
}


def shadowing_metadata(kind: ShadowingKind) -> FindingMetadata:
    """Return stable metadata for a shadowing kind."""
    return SHADOWING_FINDINGS[kind]
