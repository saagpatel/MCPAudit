"""Stable finding metadata and remediation guidance."""

from __future__ import annotations

from dataclasses import dataclass

from mcp_audit.models import (
    ArtifactVerifyKind,
    EgressKind,
    EscalationKind,
    InjectionSeverity,
    IntegrityKind,
    PackageVerifyKind,
    PermissionCategory,
    ProvenanceKind,
    RuleOfTwoPosture,
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


ANNOTATION_CONTRADICTION = FindingMetadata(
    rule_id="MCP043",
    title="Annotation contradiction",
    severity="medium",
    description="An explicit served annotation contradicts keyword capability evidence at MEDIUM or better.",
    remediation=(
        "Review the tool metadata and implementation; correct the hint before trusting its declaration."
    ),
)


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
        title="This tool's text may give your AI hidden instructions.",
        severity="high",
        description="Tool text appears to contain direct instruction override or prompt-leak behavior.",
        remediation=(
            "Your AI may read this text as part of using the server. Remove the server from your config, "
            "or remove the matched instruction if you own it; restart the client before using it again."
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


EGRESS_FINDINGS: dict[EgressKind, FindingMetadata] = {
    EgressKind.DESTINATION_OUTSIDE_ALLOWLIST: FindingMetadata(
        rule_id="MCP040",
        title="Outbound destination outside the allowlist",
        severity="medium",
        description=(
            "A tool or resource sends data to a fixed network destination that is not on the "
            "configured egress allowlist. Even a non-caller-controlled destination is a data-egress "
            "path: the server can transmit workspace data to a host you have not explicitly trusted."
        ),
        remediation=(
            "Confirm the destination is expected. If it is trusted, add it to the egress allowlist "
            "(--egress-allowlist); otherwise disable the capability or isolate the server so it "
            "cannot reach unreviewed destinations with private workspace data."
        ),
    ),
    EgressKind.UNBOUNDED_EGRESS: FindingMetadata(
        rule_id="MCP041",
        title="Unbounded outbound destination (caller-controlled)",
        severity="high",
        description=(
            "A tool or resource lets the caller steer the outbound destination (a URL/host parameter "
            "or a templated host authority). The egress target is not allowlistable because it is "
            "chosen at call time, so data can be sent to an arbitrary, attacker-influenceable host."
        ),
        remediation=(
            "Treat this as the highest-priority egress risk: restrict the server to a fixed, "
            "validated set of destinations, reject caller-supplied hosts, and never expose it to "
            "untrusted prompts or tool outputs that could choose the destination."
        ),
    ),
    EgressKind.TRUSTED_DESTINATION_RESIDUAL: FindingMetadata(
        rule_id="MCP042",
        title="Trusted destination with residual egress risk",
        severity="medium",
        description=(
            "An allowlisted destination still carries residual egress risk because it is a "
            "multi-tenant data-bearing API or the tool can attach caller-controlled credentials. "
            "A trusted host is not automatically a safe destination — data sent there may land in a "
            "different tenant or be redirected by an attacker-supplied credential (the Cowork lesson)."
        ),
        remediation=(
            "Verify the tenant/account boundary on this destination and confirm credentials are not "
            "caller-controllable. Scope the allowlist to a specific account/path where possible, and "
            "review what workspace data is permitted to flow to this multi-tenant endpoint."
        ),
    ),
}


TRIFECTA_FINDINGS: dict[TrifectaSeverity, FindingMetadata] = {
    TrifectaSeverity.HIGH: FindingMetadata(
        rule_id="MCP013",
        title="Your AI could read private data and send it out through one server.",
        severity="high",
        description=(
            "A single MCP server covers all three exfiltration legs: sensitive data access "
            "(file_read), untrusted-content ingestion (SSRF-flagged or fetch-verb tool/resource), and "
            "an outbound exfiltration capability (exfiltration). This is the canonical agent-exfiltration "
            "attack surface — a malicious or compromised tool description could instruct an AI agent "
            "to read sensitive files, fetch attacker-controlled content, and transmit the data out."
        ),
        remediation=(
            "Cut one link: remove file access, untrusted-content ingestion, or outbound transfer. "
            "Use the named contributing tools to choose an optional capability to disable; "
            "otherwise isolate the server and restrict its file paths and destinations."
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


def egress_metadata(kind: EgressKind) -> FindingMetadata:
    """Return stable metadata for an egress finding kind."""
    return EGRESS_FINDINGS[kind]


def trifecta_metadata(severity: TrifectaSeverity) -> FindingMetadata:
    """Return stable metadata for a trifecta severity."""
    return TRIFECTA_FINDINGS[severity]


# Rule-of-Two posture (Meta, Oct 2025): drop one leg to break the trifecta.
RULE_OF_TWO_DESCRIPTION = (
    "Rule of Two: an agent should hold at most two of {untrusted input, sensitive data "
    "access, external communication}. Dropping any one leg breaks the trifecta."
)

# Per-leg remediation templates. {targets} is filled with the affected tool name(s).
_RULE_OF_TWO_LEG_ACTIONS: dict[int, str] = {
    1: "remove file-read access ({targets})",
    2: "remove/disable the ingestion {targets}",
    3: "restrict outbound destinations via --egress-check allowlist, or remove {targets}",
}


def rule_of_two_action(leg: int, tools: list[str]) -> str:
    """Return the concrete remediation action for dropping ``leg``, naming ``tools``.

    Example: ``rule_of_two_action(3, ["upload_file"])`` ->
    "restrict outbound destinations via --egress-check allowlist, or remove tool 'upload_file'".
    """
    label = "tool" if len(tools) == 1 else "tools"
    quoted = ", ".join(f"'{tool}'" for tool in tools)
    targets = f"{label} {quoted}" if tools else "the affected tool(s)"
    return _RULE_OF_TWO_LEG_ACTIONS[leg].format(targets=targets)


def format_rule_of_two(posture: RuleOfTwoPosture) -> str:
    """Render a posture as one compact line, shared by the text/HTML/SARIF renderers."""
    legs = ", ".join(str(n) for n in posture.legs_present)
    line = (
        f"Rule of Two — legs present: {legs}; recommended: drop Leg "
        f"{posture.recommended_drop}: {posture.action}"
    )
    alternatives = "; ".join(f"Leg {leg}: {action}" for leg, action in posture.alternatives)
    if alternatives:
        line += f"; alternatives: {alternatives}"
    return line


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


ESCALATION_FINDINGS[EscalationKind.ANNOTATION_DELTA] = ESCALATION_FINDINGS[EscalationKind.CAPABILITY]


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


ARTIFACT_VERIFY_FINDINGS: dict[ArtifactVerifyKind, FindingMetadata] = {
    ArtifactVerifyKind.PUBLISHED_MISMATCH: FindingMetadata(
        rule_id="MCP026",
        title="Downloaded artifact bytes do not match the registry-published hash",
        severity="high",
        description=(
            "Under --download-artifacts the actual bytes the registry served for a pinned "
            "package@version (npm or PyPI) were downloaded and hashed, and the hash did not match "
            "the registry's own published hash for that version. This is a content-level signal a "
            "metadata-to-metadata compare (MCP025) cannot see: a CDN, mirror, or man-in-the-middle "
            "is serving bytes inconsistent with the registry's published integrity. The same "
            "consistency check also runs at pin time, where inconsistent bytes are refused from the "
            "baseline (with a warning) rather than silently trusted; this finding is its scan-time "
            "form, raised when a version that was consistent at pin later begins serving divergent bytes."
        ),
        remediation=(
            "Treat served bytes that disagree with the registry's published hash as a strong "
            "supply-chain compromise signal. Do not install from the affected source. Re-fetch over a "
            "trusted network/mirror, verify the maintainer release, and only refresh the pin with "
            "`mcp-audit pin --download-artifacts` once consistent bytes are confirmed."
        ),
    ),
    ArtifactVerifyKind.BASELINE_MISMATCH: FindingMetadata(
        rule_id="MCP026",
        title="Downloaded artifact bytes changed since the pin baseline",
        severity="high",
        description=(
            "The bytes the registry served for a pinned package@version differ, per distribution file, "
            "from the byte-hashes captured when it was pinned with --download-artifacts. HIGH when a "
            "file present at pin time now serves different bytes or has vanished — republish-in-place "
            "proven at the byte level, which a published-hash compare can be fooled on if the registry "
            "updates its metadata to match the tampered bytes. MEDIUM (advisory) when no pinned file "
            "changed but a NEW distribution file appeared on the frozen version (e.g. a late wheel "
            "upload) — legitimate but still worth confirming, and not silently ignored."
        ),
        remediation=(
            "Investigate the version as a republish/tampering event before trusting it. Confirm the "
            "change is a legitimate maintainer action, then refresh the pin with "
            "`mcp-audit pin --download-artifacts`; otherwise pin a known-good version and report it."
        ),
    ),
    ArtifactVerifyKind.UNVERIFIED: FindingMetadata(
        rule_id="MCP026",
        title="Artifact bytes could not be downloaded or hashed to verify",
        severity="medium",
        description=(
            "Under --download-artifacts the bytes for a pinned package@version could not be retrieved "
            "or hashed — the registry/CDN was unreachable, the version was withdrawn, the artifact "
            "exceeded the download size cap, or the resolved download host was not on the registry-CDN "
            "allowlist (an SSRF guard against poisoned metadata redirecting the download)."
        ),
        remediation=(
            "Re-run when the registry is reachable. A persistent failure for a previously verifiable "
            "version warrants investigation (withdrawn release, redirected download host). The pinned "
            "byte-hash baseline is retained so verification resumes automatically once bytes are "
            "fetchable again."
        ),
    ),
}


def artifact_verify_metadata(kind: ArtifactVerifyKind) -> FindingMetadata:
    """Return stable metadata for a byte-level artifact-verification kind."""
    return ARTIFACT_VERIFY_FINDINGS[kind]


@dataclass(frozen=True)
class FindingCopy:
    """Teaching copy shared by the offline reference and finding renderers."""

    title: str
    what_we_saw: str
    why_it_matters: tuple[str, str, str]
    how_to_fix: str
    time_to_fix: str
    how_sure: str


_CAPABILITY_LIMIT = (
    "A capability inference from config or served metadata, not an observed operation. "
    "Use the finding's confidence and evidence; descriptions and annotations can be inaccurate."
)
_PATTERN_LIMIT = (
    "A deterministic text or structural heuristic, not AI judgment or proof of an attack. "
    "Quoted examples and legitimate instructions can match. Static checks do not cover every attack."
)
_BASELINE_LIMIT = (
    "A comparison with the saved baseline, not proof of compromise. Confirm the baseline's scope "
    "and review the specific delta; an intentional update can also trigger this finding."
)


# One entry per stable rule, including rules with multiple severities or kinds.
# These examples describe possible consequences; none asserts an incident occurred.
FINDING_COPY: dict[str, FindingCopy] = {
    "MCP001": FindingCopy(
        "Your AI may be able to read files through this server.",
        "Config or tool metadata suggests file-reading access.",
        (
            "You enable a file-reading tool.",
            "The tool may reach private paths.",
            "Those files can enter the AI's context.",
        ),
        "Limit allowed paths to the project files you need; remove the server if its access is unnecessary.",
        "About 5 minutes to review scope",
        _CAPABILITY_LIMIT,
    ),
    "MCP002": FindingCopy(
        "Your AI may be able to change files through this server.",
        "Config or tool metadata suggests file-writing access.",
        (
            "You enable a writing tool.",
            "It may change files outside the intended task.",
            "Your work could be overwritten.",
        ),
        "Restrict writable paths and review the implementation; disable unnecessary write tools.",
        "About 5 minutes to restrict scope",
        _CAPABILITY_LIMIT,
    ),
    "MCP003": FindingCopy(
        "Your AI may be able to reach the internet through this server.",
        "Config or tool metadata suggests network access; an absent hint alone is not evidence.",
        (
            "You enable a networked tool.",
            "It contacts an external service.",
            "Workspace data may leave your machine.",
        ),
        "Review destinations and the data each tool sends; restrict network access where possible.",
        "About 5 minutes to review destinations",
        _CAPABILITY_LIMIT,
    ),
    "MCP004": FindingCopy(
        "Your AI may be able to run commands through this server.",
        "Config or tool metadata suggests shell or process execution.",
        (
            "You enable a command-running tool.",
            "It can use the server process's permissions.",
            "Files or other local programs could be affected.",
        ),
        "Disable or isolate command execution until you have reviewed its arguments and allowed operations.",
        "About 1 minute to disable; review time varies",
        _CAPABILITY_LIMIT,
    ),
    "MCP005": FindingCopy(
        "Your AI may be able to delete or replace data through this server.",
        "Metadata or an explicit annotation suggests a destructive operation.",
        (
            "You enable a destructive tool.",
            "A mistaken call could remove data.",
            "Recovery may require a backup.",
        ),
        "Disable unnecessary destructive tools and restrict their scope; review calls before using them.",
        "About 1 minute to disable",
        _CAPABILITY_LIMIT,
    ),
    "MCP006": FindingCopy(
        "Your AI may be able to send private data out through this server.",
        "Metadata suggests access to local data combined with an outbound transfer capability.",
        (
            "A tool can access data.",
            "It also has a way to transmit data.",
            "Private content could reach an external recipient.",
        ),
        "Restrict data sources, recipients and destinations, or disable the transfer tool.",
        "About 5 minutes to review scope",
        _CAPABILITY_LIMIT,
    ),
    "MCP007": FindingCopy(
        "This tool's text may give your AI hidden instructions.",
        "Agent-facing text matched a high-severity instruction pattern; see the matched excerpt and field.",
        (
            "Your AI may read the server's text when using it.",
            "It could follow the embedded instruction instead of your task.",
            "Depending on its access, it could reveal private data or take an unwanted action.",
        ),
        "Remove the server from the named config entry, or remove the matched instruction if you own it. "
        "Restart the client. Never treat allowing a finding as removing the instruction the AI reads.",
        "About 1 minute to disable; source review varies",
        _PATTERN_LIMIT,
    ),
    "MCP008": FindingCopy(
        "Your AI may read suspicious instructions or hidden text from this server.",
        "Metadata or returned content matched an instruction, hidden-character or encoded-content heuristic.",
        (
            "Server text enters the AI's context.",
            "Instruction-shaped or hidden text may influence its next action.",
            "That action could depart from your intended task.",
        ),
        "Review the marked text and its field. Remove unexpected instructions if you own the server; "
        "otherwise disable it pending review.",
        "About 5 minutes for an initial review",
        _PATTERN_LIMIT,
    ),
    "MCP009": FindingCopy(
        "Your AI's available tools changed since the comparison baseline.",
        "A pin or controlled session comparison found a changed, added, removed or "
        "identity-conditioned surface.",
        (
            "You reviewed an earlier surface.",
            "The current surface differs.",
            "Your earlier trust decision may no longer cover it.",
        ),
        "Review the recorded changes before refreshing any pin. Disable an unexpected surface "
        "pending review.",
        "About 5 minutes for an initial comparison",
        _BASELINE_LIMIT,
    ),
    "MCP010": FindingCopy(
        "Your audit did not meet your local policy.",
        "A reported result or missing coverage violated an explicitly selected policy rule.",
        (
            "You set a local requirement.",
            "This scan did not satisfy it.",
            "Accepting the result would bypass that requirement.",
        ),
        "Read the named policy violation; repair the configuration or deliberately review the policy "
        "before rechecking.",
        "Review time depends on the violated rule",
        "A deterministic policy evaluation, not a universal security verdict.",
    ),
    "MCP011": FindingCopy(
        "Your server may fetch a destination chosen by someone else.",
        "A caller-controlled URL or host is paired with evidence of server-side fetching.",
        (
            "A caller supplies a destination.",
            "The server may fetch it using its own network access.",
            "Internal services or metadata endpoints could become reachable.",
        ),
        "Restrict destinations to validated hosts; block loopback, link-local and private targets in "
        "the server's fetch implementation.",
        "About 5 minutes to disable; implementation work varies",
        _CAPABILITY_LIMIT,
    ),
    "MCP012": FindingCopy(
        "Your server may accept a caller-chosen network destination.",
        "A URL-shaped input, host input or remote resource template matched a possible "
        "request-routing pattern.",
        (
            "A caller controls part of a request.",
            "That input may select a network destination.",
            "The server could reach an unintended service.",
        ),
        "Check how the named parameter or URI is resolved; restrict it to known destinations if it "
        "controls a fetch.",
        "About 5 minutes for an initial review",
        _CAPABILITY_LIMIT,
    ),
    "MCP013": FindingCopy(
        "Your AI could read private data and send it out through one server.",
        "One server has evidence for file access, untrusted-content ingestion and outbound transfer. "
        "The finding names the tools or resources contributing each link.",
        (
            "A tool may read private files.",
            "Untrusted content could influence the AI using those files.",
            "An outbound tool could send the data to another party.",
        ),
        "Cut one link: disable optional file access, ingestion or outbound transfer using the named "
        "contributors. "
        "If none is optional, isolate the server and restrict file paths and destinations.",
        "About 5 minutes to choose and disable an optional link",
        _CAPABILITY_LIMIT + " No successful attack or transfer was observed by this check.",
    ),
    "MCP014": FindingCopy(
        "Your AI could combine private reads and outbound transfers across servers.",
        "The audited fleet covers all three links, but no single server covers them all.",
        (
            "One server may read private files.",
            "Another may ingest untrusted content in the same AI session.",
            "An outbound capability could complete a transfer path.",
        ),
        "Review which servers share an AI session. Remove an optional link or separate them into "
        "isolated contexts.",
        "About 10 minutes to review session scope",
        _CAPABILITY_LIMIT + " This is a fleet advisory; shared session use is not established.",
    ),
    "MCP015": FindingCopy(
        "Your AI may see the same tool name from different servers.",
        "Multiple servers expose an identical tool name.",
        (
            "The AI chooses a tool by name.",
            "More than one server offers that name.",
            "Routing could reach a server you did not intend.",
        ),
        "Give tools unique server-specific prefixes, or disable the unintended duplicate after "
        "reviewing both sources.",
        "About 5 minutes to review duplicates",
        "An exact name comparison; ordering does not establish which server is legitimate.",
    ),
    "MCP016": FindingCopy(
        "Your AI may confuse tool names that differ only in formatting.",
        "Tool names match after case-folding and separator removal.",
        (
            "Two tools look similar.",
            "An agent may treat their names as interchangeable.",
            "It could choose the wrong server.",
        ),
        "Use distinct server-specific prefixes that remain different after normalization.",
        "About 5 minutes to rename or disable a duplicate",
        "A deterministic normalized comparison, not observed misrouting.",
    ),
    "MCP017": FindingCopy(
        "Your AI may see lookalike tool names from different servers.",
        "Non-ASCII confusable characters produce a name skeleton matching another server's tool.",
        (
            "A name looks familiar.",
            "Its characters differ from the expected name.",
            "A tool choice could reach a different server.",
        ),
        "Review both tool sources and remove or rename the unexpected lookalike; do not infer intent "
        "from spelling alone.",
        "About 5 minutes for an initial review",
        "A confusable-character comparison; it does not establish deliberate spoofing.",
    ),
    "MCP018": FindingCopy(
        "Your pinned tool may have gained broader access.",
        "Permission evidence or served annotations changed relative to the saved pin.",
        (
            "You pinned an earlier tool surface.",
            "New metadata suggests broader access or changed hints.",
            "The old review may no longer cover its behavior.",
        ),
        "Review the gained categories and annotation changes. Keep the old pin until you understand "
        "and accept the change.",
        "About 5 minutes for an initial comparison",
        _BASELINE_LIMIT,
    ),
    "MCP019": FindingCopy(
        "Your pinned tool now contains new instruction-shaped text.",
        "The current description contains injection patterns absent from the saved tool description.",
        (
            "You trusted an earlier description.",
            "The updated description adds agent-directed text.",
            "Your AI could act on instructions you did not approve.",
        ),
        "Disable the server pending review of the changed description; do not refresh the pin to "
        "erase an unexplained delta.",
        "About 1 minute to disable; review time varies",
        _BASELINE_LIMIT + " Pattern matches can be false positives.",
    ),
    "MCP020": FindingCopy(
        "Your pinned server now launches a different command or transport.",
        "The launch command or transport differs from the pinned configuration.",
        (
            "You reviewed one launch target.",
            "The config now selects another target or transport.",
            "Unchanged tool schemas do not establish the same program.",
        ),
        "Review the current command and transport against the pin; disable an unexpected target "
        "before reconnecting.",
        "About 5 minutes for an initial comparison",
        _BASELINE_LIMIT,
    ),
    "MCP021": FindingCopy(
        "Your pinned server now launches with different arguments.",
        "The launch argument list differs from the pin.",
        (
            "Arguments select packages, paths or options.",
            "An update changes those selections.",
            "The process could run with different access or code.",
        ),
        "Review the redacted argument delta and package or path selections before refreshing the pin.",
        "About 5 minutes for an initial comparison",
        _BASELINE_LIMIT,
    ),
    "MCP023": FindingCopy(
        "Your pinned server's credential key names changed.",
        "Environment or header key names differ from the pin; values are not captured.",
        (
            "Key names describe credential or configuration inputs.",
            "The set of inputs changed.",
            "The server's access may need a fresh review.",
        ),
        "Review which key names were added or removed and whether their scope is needed. Do not "
        "paste their values into reports.",
        "About 5 minutes to review key names",
        _BASELINE_LIMIT + " Key-name equality cannot verify unchanged secret values.",
    ),
    "MCP022": FindingCopy(
        "Your pinned server's remote endpoint changed.",
        "The configured remote URL differs from the pin.",
        (
            "You trusted one endpoint.",
            "The config now routes to another URL.",
            "A different service may receive future requests.",
        ),
        "Confirm the intended endpoint and its owner; restore the reviewed URL or disable the server "
        "pending review.",
        "About 5 minutes for an initial comparison",
        _BASELINE_LIMIT,
    ),
    "MCP024": FindingCopy(
        "Your pinned launch file changed or could not be verified.",
        "The local launch artifact's hash differs from its pin, or the configured artifact cannot be hashed.",
        (
            "You pinned a local file's bytes.",
            "The file changed or is unavailable to the verifier.",
            "The earlier artifact review cannot establish its current identity.",
        ),
        "Review the specific changed or unverified artifact. Retain the baseline until a legitimate "
        "change is confirmed.",
        "About 5 minutes for an initial review",
        _BASELINE_LIMIT + " An unavailable hash is missing evidence, not a proven change.",
    ),
    "MCP025": FindingCopy(
        "Your pinned package's published hash changed or could not be verified.",
        "Registry metadata differs from the saved hash for a package version, or metadata could not "
        "be retrieved.",
        (
            "You pinned a package version's published hash.",
            "The current registry hash differs or is unavailable.",
            "Metadata alone cannot establish the expected package bytes.",
        ),
        "Review the version and published hash delta before trusting it. Keep the pin on an "
        "unavailable check; retry verification only deliberately.",
        "Review time varies; disabling takes about 1 minute",
        _BASELINE_LIMIT + " Registry metadata is not a byte-level verification.",
    ),
    "MCP026": FindingCopy(
        "Your package bytes differ from expectations or could not be verified.",
        "Downloaded hashes disagree with published or pinned hashes, a distribution changed, or "
        "bytes could not be fetched or hashed.",
        (
            "You expect particular bytes for a version.",
            "The downloaded bytes differ, or verification is incomplete.",
            "Installation would rely on changed or unverified content.",
        ),
        "Avoid installing an unexplained mismatch. Review per-file evidence and legitimate release "
        "changes before refreshing; retain the pin when retrieval fails.",
        "Review time varies; disabling takes about 1 minute",
        "Byte comparisons establish only the recorded mismatch. New files can be legitimate; "
        "unverified downloads establish no mismatch.",
    ),
    "MCP040": FindingCopy(
        "Your server may send data to a destination you did not allow.",
        "A fixed outbound destination is outside the configured allowlist.",
        (
            "A tool can send data.",
            "Its destination is outside your selected allowlist.",
            "Workspace content could reach an unreviewed host.",
        ),
        "Review the destination; deliberately add it to --egress-allowlist if trusted, or disable "
        "the outbound capability.",
        "About 5 minutes to review the destination",
        _CAPABILITY_LIMIT,
    ),
    "MCP041": FindingCopy(
        "Your server may send data to a caller-chosen destination.",
        "A URL or host parameter, or a templated host authority, lets callers choose the outbound target.",
        (
            "The caller supplies a destination.",
            "The tool may send data there.",
            "An attacker-influenced request could choose the recipient.",
        ),
        "Replace caller-selected hosts with a validated fixed destination set, or disable the capability.",
        "About 1 minute to disable; implementation work varies",
        _CAPABILITY_LIMIT,
    ),
    "MCP042": FindingCopy(
        "Your trusted host may still send data to the wrong account.",
        "An allowlisted host has a multi-tenant API or caller-controlled credential input.",
        (
            "The hostname passes the allowlist.",
            "An account or credential can still select another recipient.",
            "Data could leave your intended tenant boundary.",
        ),
        "Review tenant, path and account scope; prevent callers from substituting credentials and "
        "limit allowed data.",
        "About 10 minutes for an initial account-boundary review",
        _CAPABILITY_LIMIT,
    ),
    "MCP043": FindingCopy(
        "Your tool's declared safety hint conflicts with its metadata.",
        "An explicit annotation contradicts capability keyword evidence at medium confidence or better.",
        (
            "A safety hint describes a restricted tool.",
            "Other metadata suggests broader behavior.",
            "Trusting the hint alone could grant unintended access.",
        ),
        "Review the actual implementation and correct the hint or description; disable the disputed "
        "capability until resolved.",
        "About 5 minutes for an initial review",
        "A metadata contradiction, not an executed behavior check. Keyword evidence and hints can "
        "both be inaccurate.",
    ),
}


CONFIG_HEALTH_COPY = FindingCopy(
    "Your server configuration needs review before you connect.",
    "A static configuration check found a launch, source, credential-scope or parsing concern.",
    (
        "Your client uses the configured entry.",
        "The reported concern can change its reach or reduce audit coverage.",
        "Connecting before review may run unintended code or leave part of the config unchecked.",
    ),
    "Follow the finding's manual remediation at the named config entry. If intent is unclear, remove "
    "that entry temporarily, restart the client, and review the command and source before restoring it.",
    "About 5 minutes for an initial review",
    "A static config check; it does not establish malicious code or an observed incident.",
)


def finding_url(rule_id: str) -> str:
    """Return the stable reference anchor, including config-health findings."""
    anchor = rule_id.lower() if rule_id in FINDING_COPY else "configuration-health"
    return f"https://github.com/saagpatel/MCPAudit/blob/main/docs/findings/index.md#{anchor}"


def finding_copy(rule_id: str) -> FindingCopy:
    """Look up teaching copy without performing a scan or reading a config."""
    if rule_id.startswith("MCP-CH-"):
        return CONFIG_HEALTH_COPY
    return FINDING_COPY[rule_id]


def config_health_rule_id(finding_type: str) -> str:
    """Match the existing stable SARIF config-health identifier."""
    token = "".join(char.upper() if char.isalnum() else "-" for char in finding_type)
    return f"MCP-CH-{token.strip('-')}"


def render_finding_reference(rule_id: str) -> str:
    """Render exactly the Markdown entry printed by the offline explain command."""
    copy = finding_copy(rule_id)
    heading = "Configuration health" if rule_id.startswith("MCP-CH-") else rule_id
    steps = "\n".join(f"{index}. {step}" for index, step in enumerate(copy.why_it_matters, 1))
    return (
        f"## {heading}\n\n{copy.title}\n\n"
        f"What we saw: {copy.what_we_saw}\n\nWhy it matters:\n\n{steps}\n\n"
        f"How to fix ({copy.time_to_fix}): {copy.how_to_fix}\n\n"
        f"How sure: {copy.how_sure}\n\nsee: {finding_url(rule_id)}\n"
    )


def render_findings_index() -> str:
    """Generate the checked-in reference; its equality test prevents copy drift."""
    return (
        "# Finding reference\n\n"
        "<!-- Generated from mcp_audit.taxonomy; run scripts/generate_findings.py. -->\n\n"
        "Read any entry offline with `mcp-audit explain MCP007`. No configs are read and no servers "
        "are contacted. Time estimates describe initial containment or review, not a guaranteed repair. "
        "Check recorded coverage before interpreting an absence of findings.\n\n"
        "Suppressions are not implemented by this reference. Permission-category overrides do not "
        "remove hidden instructions or suppress individual finding IDs.\n\n"
        + "\n".join(render_finding_reference(rule_id) for rule_id in sorted(FINDING_COPY))
        + "\n"
        + render_finding_reference("MCP-CH-CONFIGURATION-HEALTH")
    )
