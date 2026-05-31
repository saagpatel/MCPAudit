"""Stable finding metadata and remediation guidance."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_audit.models import (
    EscalationKind,
    InjectionSeverity,
    IntegrityKind,
    PackageVerifyKind,
    PermissionCategory,
    ProvenanceKind,
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


ESCALATION_FINDINGS: dict[EscalationKind, FindingMetadata] = {
    EscalationKind.CAPABILITY: FindingMetadata(
        rule_id="MCP018",
        title="Capability escalation since pin baseline",
        severity="high",
        description=(
            "A pinned tool has GAINED a dangerous permission category it did not hold when "
            "the operator approved its baseline (e.g. a read-only tool that now infers "
            "file_write, exfiltration, shell_execution, or destructive capability). This is the "
            "MCP supply-chain 'rug pull': a previously-trusted server ships an update that "
            "quietly broadens its capability surface. Severity is HIGH when the gained category "
            "is exfiltration/shell_execution/destructive, MEDIUM for file_write/network."
        ),
        remediation=(
            "Do NOT refresh the pin until you have reviewed why this tool's capability surface "
            "grew. Inspect the changed tool metadata, confirm the new capability is intended and "
            "from a trusted source, and only then run `mcp-audit pin --refresh <server>`. If the "
            "change is unexpected, disable the server and report it to the author."
        ),
    ),
    EscalationKind.DESCRIPTION_INJECTION: FindingMetadata(
        rule_id="MCP019",
        title="Tool description gained injection patterns since pin baseline",
        severity="high",
        description=(
            "A pinned tool's description has GAINED prompt-injection pattern(s) that were absent "
            "from the operator-approved baseline (e.g. 'ignore previous instructions', hidden "
            "directives, or system-prompt override framing). A benign tool description mutating "
            "to carry agent-targeting instructions is a strong rug-pull / compromise signal."
        ),
        remediation=(
            "Treat the server as untrusted until reviewed. Read the full updated description, "
            "compare it against the pinned baseline, and confirm the injected text with the "
            "server author. Do not refresh the pin while the injection pattern is present."
        ),
    ),
}


def escalation_metadata(kind: EscalationKind) -> FindingMetadata:
    """Return stable metadata for a capability-escalation kind."""
    return ESCALATION_FINDINGS[kind]


PROVENANCE_FINDINGS: dict[ProvenanceKind, FindingMetadata] = {
    ProvenanceKind.COMMAND: FindingMetadata(
        rule_id="MCP020",
        title="Launch command/transport changed since pin baseline",
        severity="high",
        description=(
            "The server's launch command/binary or transport changed since it was pinned. The "
            "command is the supply-chain trust anchor — swapping the executable (or switching "
            "transport, e.g. stdio→http) can redirect the agent to an entirely different program "
            "while the tool schemas stay identical. This is a classic rug-pull vector."
        ),
        remediation=(
            "Confirm the new command/transport is intended and from a trusted source before "
            "refreshing the pin. If unexpected, disable the server and inspect the config file that "
            "defines it. Run `mcp-audit pin --refresh <server>` only after review."
        ),
    ),
    ProvenanceKind.ARGS: FindingMetadata(
        rule_id="MCP021",
        title="Launch arguments changed since pin baseline",
        severity="medium",
        description=(
            "The server's launch arguments changed since it was pinned — a pinned package version "
            "floating to a different version or `@latest`, a swapped package name (possible "
            "typosquat), or a newly added flag. HIGH when a known-dangerous flag "
            "(e.g. --no-sandbox, --dangerously-*, --allow-all) was gained; MEDIUM otherwise."
        ),
        remediation=(
            "Review the argument diff. Re-pin to an explicit, trusted package version rather than a "
            "floating tag. Reject any newly added permission-broadening flag unless it is "
            "deliberate. Refresh the pin only after the change is understood."
        ),
    ),
    ProvenanceKind.URL: FindingMetadata(
        rule_id="MCP022",
        title="HTTP endpoint/URL changed since pin baseline",
        severity="high",
        description=(
            "The server's HTTP endpoint/URL changed since it was pinned. A changed host or path can "
            "silently repoint the agent at an attacker-controlled endpoint that proxies or replaces "
            "the legitimate service while presenting the same tool schemas."
        ),
        remediation=(
            "Verify the new endpoint is the legitimate service over TLS and was changed "
            "intentionally. Treat an unexpected host change as a compromise until proven otherwise. "
            "Refresh the pin only after confirming the endpoint."
        ),
    ),
    ProvenanceKind.CREDENTIALS: FindingMetadata(
        rule_id="MCP023",
        title="Declared credential key-name set changed since pin baseline",
        severity="medium",
        description=(
            "The set of declared environment-variable / header KEY NAMES the server is wired to "
            "read changed since it was pinned (only key names are ever inspected — values are never "
            "captured). A server newly demanding a credential key it did not previously reference "
            "may be attempting to harvest secrets it was not originally trusted with."
        ),
        remediation=(
            "Confirm any newly demanded credential key is required and appropriate for this server. "
            "Investigate keys that map to unrelated services. Refresh the pin only after the new "
            "credential surface is reviewed."
        ),
    ),
}


def provenance_metadata(kind: ProvenanceKind) -> FindingMetadata:
    """Return stable metadata for a provenance / launch-config change kind."""
    return PROVENANCE_FINDINGS[kind]


INTEGRITY_FINDINGS: dict[IntegrityKind, FindingMetadata] = {
    IntegrityKind.ARTIFACT_DRIFT: FindingMetadata(
        rule_id="MCP024",
        # Rule-level metadata severity is the dominant case (changed bytes); the
        # authoritative per-finding severity lives on IntegrityFinding.severity
        # (HIGH on byte change, MEDIUM when the pinned file is missing).
        title="Launch artifact bytes changed since pin baseline",
        severity="high",
        description=(
            "The on-disk artifact this server launches — the resolved command binary, or a local "
            "script passed as an argument — has a different SHA-256 than when it was pinned, or is "
            "no longer present at its path. The launch command string can stay byte-identical while "
            "the file it points at is swapped underneath you, so this catches a supply-chain "
            "substitution that the schema and provenance (config-string) checks cannot see. HIGH "
            "when the bytes changed; MEDIUM when the pinned file is missing (often a relocation)."
        ),
        remediation=(
            "Confirm the artifact was updated intentionally and from a trusted source (a legitimate "
            "package upgrade or rebuild). Treat an unexpected change as a potential compromise: "
            "disable the server and inspect the file before use. Refresh the pin with "
            "`mcp-audit pin --refresh <server>` only after the new artifact is reviewed."
        ),
    ),
}


def integrity_metadata(kind: IntegrityKind) -> FindingMetadata:
    """Return stable metadata for a launch-artifact integrity change kind."""
    return INTEGRITY_FINDINGS[kind]


PACKAGE_VERIFY_FINDINGS: dict[PackageVerifyKind, FindingMetadata] = {
    PackageVerifyKind.REGISTRY_DRIFT: FindingMetadata(
        rule_id="MCP025",
        # Per-finding severity is authoritative (HIGH on hash change, MEDIUM when
        # the registry could not be re-fetched to verify).
        title="Registry-published package hash changed since pin baseline",
        severity="high",
        description=(
            "The registry-published hash for a pinned package@version (npm or PyPI) differs from "
            "the hash captured when it was pinned — a republish-in-place / tampering signal that the "
            "on-disk and config-string checks cannot see, since for npx/uvx launches the meaningful "
            "artifact is the remote package, not the runner binary. MEDIUM when the package could not "
            "be re-fetched (registry unreachable or version withdrawn) and so could not be verified."
        ),
        remediation=(
            "Treat a changed published hash for a fixed version as a strong supply-chain compromise "
            "signal: a registry should never serve different bytes for the same version. Pin an "
            "explicit version, verify the maintainer/release, and refresh the pin with "
            "`mcp-audit pin --verify-artifacts` only after confirming the change is legitimate."
        ),
    ),
}


def package_verify_metadata(kind: PackageVerifyKind) -> FindingMetadata:
    """Return stable metadata for a registry package-verification change kind."""
    return PACKAGE_VERIFY_FINDINGS[kind]
