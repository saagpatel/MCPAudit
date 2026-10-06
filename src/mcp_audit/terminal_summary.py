"""Summary-first presentation of recorded findings and execution coverage."""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, replace
from typing import Literal

from pydantic import BaseModel
from rich.console import Console

from mcp_audit.coverage import missing_checks
from mcp_audit.models import AuditReport, ConnectionMode, ServerAudit
from mcp_audit.terminal_text import terminal_safe

LABELS = {"high": "▲ Fix now", "medium": "◆ Worth a look", "low": "● FYI"}
STYLES = {"high": "bold red", "medium": "yellow", "low": "dim"}
_CORE = ("config_health", "metadata", "permissions", "capabilities")
_FINDING_FLAGS = {
    "InjectionFinding": "--inject-check",
    "SsrfFinding": "--ssrf-check",
    "EgressFinding": "--egress-check",
    "TrifectaFinding": "--trifecta-check",
    "ShadowingFinding": "--shadow-check",
    "EscalationFinding": "--escalation-check",
    "ProvenanceFinding": "--provenance-check",
    "IntegrityFinding": "--integrity-check",
    "PackageVerifyFinding": "--verify-artifacts",
    "ArtifactVerifyFinding": "--download-artifacts",
    "DriftFinding": "--pin-check",
}
_STATIC_FLAGS = {"--provenance-check", "--integrity-check", "--verify-artifacts", "--download-artifacts"}


def summary_console(*, color: str = "auto", stderr: bool = False) -> Console:
    disabled = color == "never" or "NO_COLOR" in os.environ
    force = False if disabled else True if color == "always" else None
    return Console(stderr=stderr, force_terminal=force, no_color=disabled)


@dataclass(frozen=True)
class Action:
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


def _text(data: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _identity(audit: ServerAudit, *, explicit_config: bool = False) -> str:
    server = audit.server
    client = "client not asserted" if explicit_config else server.client.value
    return f"{server.name} / {client} ({server.scope})"


def _action(finding: BaseModel, audits: list[ServerAudit], sources: tuple[str, ...] = ()) -> Action:
    data: dict[str, object] = finding.model_dump(mode="json")
    kind = _text(data, "finding_type")
    title = _text(data, "title", "summary", "description") or kind.replace("_", " ")
    consequence = _text(data, "description", "summary") or "Review the recorded capability before use."
    step = _text(data, "remediation") or "Review this finding in --details before enabling the entry."
    if kind == "shell_wrapper_launch":
        title = "Replace the shell wrapper"
        consequence = "A shell wrapper can run more than a single server command."
        step = "In this source, replace the wrapper with a reviewed executable and separate args."
    elif kind == "credential_heavy_config":
        title = "Review the credential access"
        consequence = "This entry references several credential keys; no credential values were used."
        step = "Disable this entry in the client while reviewing access; remove unused credential keys."
    elif kind == "package_runner_source_review":
        title = "Review and pin the package source"
        consequence = "A package runner can fetch code that changes between launches."
        step = (
            "In this source, pin a version or digest you have reviewed; do not choose an unreviewed latest."
        )
    target = _text(data, "target_name", "tool_name", "name")
    if target:
        consequence = f"{target}: {consequence}"
    paths = sources or tuple(dict.fromkeys(a.server.config_path for a in audits))
    flag = _FINDING_FLAGS.get(type(finding).__name__)
    if data.get("source") == "session" or data.get("after_call") is not None:
        flag = "--canary-check"
    flags: tuple[str, ...] = (flag,) if flag else ()
    if flag == "--canary-check":
        budgets = {a.canary.requested_calls for a in audits if a.canary is not None}
        if len(budgets) == 1:
            flags += (f"--canary-calls {next(iter(budgets))}",)
    connected = (
        not kind and (flag not in _STATIC_FLAGS) and any(a.connection_status != "skipped" for a in audits)
    )
    return Action(
        severity=_text(data, "severity") or "medium",
        title=title,
        consequence=consequence,
        step=step,
        sources=paths,
        identities=tuple(_identity(a) for a in audits),
        rule=_text(data, "rule_id") or kind or "metadata drift",
        flags=flags,
        connected=connected,
    )


def findings(report: AuditReport) -> list[Action]:
    """Keep all findings in the denominator, even when only three cards fit."""
    actions: list[Action] = []
    by_name: dict[str, list[ServerAudit]] = {}
    by_path: dict[str, list[ServerAudit]] = {}
    for audit in report.audits:
        by_name.setdefault(audit.server.name, []).append(audit)
        by_path.setdefault(audit.server.config_path, []).append(audit)
    for finding in report.config_health_findings:
        candidates = report.audits
        if finding.server_name is not None:
            candidates = by_name.get(finding.server_name, [])
        elif finding.config_paths:
            candidates = [a for path in dict.fromkeys(finding.config_paths) for a in by_path.get(path, [])]
        audits = [
            a for a in candidates if not finding.config_paths or a.server.config_path in finding.config_paths
        ]
        actions.append(_action(finding, audits, tuple(finding.config_paths)))
    for audit in report.audits:
        for group in (
            audit.permissions,
            audit.annotation_findings,
            audit.capability_findings,
            audit.injection_findings,
            audit.ssrf_findings,
            audit.egress_findings,
            audit.trifecta_findings,
            audit.escalation_findings,
            audit.provenance_findings,
            audit.integrity_findings,
            audit.package_verify_findings,
            audit.artifact_verify_findings,
        ):
            for item in group:
                actions.append(_action(item, [audit]))
        for drift in audit.drift_findings:
            actions.append(_action(drift, [audit]))
    for fleet in report.fleet_trifecta_findings:
        names = {
            n
            for leg in (fleet.leg1_contributors, fleet.leg2_contributors, fleet.leg3_contributors)
            for n, _ in leg
        }
        actions.append(_action(fleet, [a for a in report.audits if a.server.name in names]))
    for shadow in report.shadowing_findings:
        names = {n for n, _ in shadow.collisions}
        actions.append(_action(shadow, [a for a in report.audits if a.server.name in names]))
    return actions


def grade(report: AuditReport) -> Literal["A", "B", "C", "D", "F"] | None:
    """D6 rubric; incomplete/legacy/config-only evidence cannot earn a letter."""
    if report.connection_mode != ConnectionMode.ATTEMPTED or not report.audits:
        return None
    if any(report.coverage.get(key) is None or report.coverage[key].state != "complete" for key in _CORE):
        return None
    if any(a.connection_status != "connected" for a in report.audits):
        return None
    if missing_checks(report.coverage) or any(
        entry.state in {"partial", "not_run"} for entry in report.coverage.values()
    ):
        return None
    if report.warnings:
        return None
    if any(f.finding_type == "shell_wrapper_launch" for f in report.config_health_findings):
        return "F"
    if any(
        f.pattern_name in {"hidden_directive", "unicode_direction", "OBFUSCATED_METADATA"}
        for a in report.audits
        for f in a.injection_findings
    ):
        return "F"
    actions = findings(report)
    high = sum(a.severity == "high" for a in actions)
    chain = bool(report.fleet_trifecta_findings) or any(a.trifecta_findings for a in report.audits)
    shell = any(f.category.value == "shell_execution" for a in report.audits for f in a.permissions)
    if high >= 2 or (chain and shell):
        return "D"
    if high:
        return "C"
    if any(a.severity == "medium" for a in actions):
        return "B"
    return "A"


def _coverage(report: AuditReport) -> str:
    parts: list[str] = []
    for name, entry in report.coverage.items():
        if entry.state == "not_requested" and name != "runtime_security":
            continue
        state = entry.state.replace("_", " ").upper()
        if name == "runtime_security" and entry.state in {"not_run", "not_requested"}:
            parts.append("Runtime security: NOT CHECKED")
        else:
            parts.append(f"{name.replace('_', ' ')}: {state} ({entry.reason})")
    missing = missing_checks(report.coverage)
    if missing:
        parts.append("UNKNOWN (not recorded): " + ", ".join(missing))
    return "Coverage: " + " | ".join(parts)


def what_happened(report: AuditReport, *, explicit_config: bool = False) -> str:
    """Describe auditor reach using execution state, never empty findings."""
    config = report.coverage.get("config_health")
    read = (
        "Reviewed configuration evidence"
        if config and config.state == "complete"
        else "Configuration review was incomplete or unrecorded"
    )
    if report.connection_mode == ConnectionMode.SKIPPED:
        first = f"{read}; started no servers and contacted no MCP endpoints"
    elif report.connection_mode == ConnectionMode.ATTEMPTED:
        attempted = [a for a in report.audits if a.connection_status != "skipped"]
        contacted = (
            ", ".join(
                f"{a.server.name} (client not asserted)" if explicit_config else _identity(a)
                for a in attempted[:3]
            )
            or "no selected servers"
        )
        if len(attempted) > 3:
            contacted += f" (+{len(attempted) - 3} more; full identities in JSON)"
        first = (
            f"Attempted MCP connections to {contacted}; "
            f"{report.servers_connected} connected, {report.servers_failed} failed"
        )
    else:
        first = f"{read}; connection reach was not recorded"
    metadata = report.coverage.get("metadata")
    tools = (
        "metadata listing completed"
        if metadata and metadata.state == "complete"
        else "tools were not fully inspected"
    )
    canaries = [a.canary for a in report.audits if a.canary is not None]
    calls = str(sum(c.completed_calls for c in canaries)) if canaries else "not recorded"
    extra = []
    for key, label in (
        ("verify_artifacts", "registry verification"),
        ("download_artifacts", "artifact downloads"),
        ("llm_analysis", "LLM analysis"),
    ):
        entry = report.coverage.get(key)
        if entry is None:
            extra.append(f"{label} reach unknown")
        elif entry.state != "not_requested":
            extra.append(f"{label}: {entry.state.replace('_', ' ')} ({entry.reason})")
    runtime = report.coverage.get("runtime_security")
    if not canaries and runtime and runtime.state == "not_requested":
        calls = "0"
    second = f"{tools}; canary tool calls: {calls}; auditor changed no settings"
    if extra:
        second += "; " + "; ".join(extra)
    return f"What happened: {first}. {second[0].upper() + second[1:]}."


def _recheck(action: Action) -> str:
    paths = [p for p in action.sources if p and "://" not in p]
    if action.flags or action.connected:
        source = (
            "./reviewed-mcp-config.json"
            if action.connected
            else (paths[0] if paths else "./reviewed-mcp-config.json")
        )
        parts = [
            "mcp-audit scan --config",
            shlex.quote(source),
            "--config-only",
            "--override-config /dev/null",
        ]
        if not action.connected:
            parts.append("--skip-connect")
        parts.extend(action.flags)
        return " \\\n     ".join(parts)
    if paths:
        return "\n     ".join(
            f"mcp-audit check --config \\\n     {shlex.quote(p)}" for p in dict.fromkeys(paths)
        )
    return "mcp-audit inspect --details (select the source, then check --config FILE)"


def render_summary(out: Console, report: AuditReport, *, explicit_config: bool = False) -> None:
    """Responsive text cards; no tables or color-dependent meaning."""
    actions = findings(report)
    if explicit_config:
        identities = {_identity(a): _identity(a, explicit_config=True) for a in report.audits}
        actions = [replace(a, identities=tuple(identities.get(i, i) for i in a.identities)) for a in actions]
    if not report.audits:
        out.print("No MCP servers found. No security result or score is available.")
        if report.config_health_findings or report.warnings:
            out.print("Configuration diagnostics leave incomplete coverage.")
        elif explicit_config:
            out.print("Configured server maps are empty.")
        out.print("Try: mcp-audit demo")
        out.print("Or: mcp-audit check --config ./mcp.json")
        out.print("See locations: mcp-audit inspect --details")
    else:
        letter = report.ux_summary.grade
        out.print(f"MCPAudit · {'Grade ' + letter if letter else 'Preview'}", style="bold")
        if actions:
            out.print("Your MCP setup has findings to review before you enable these entries.")
        elif letter == "A":
            out.print("✓ Looks fine in the checks completed; no findings need attention.")
        else:
            out.print("No findings were reported in the available evidence; checks remain limited.")
        out.print(report.ux_summary.caveat)
    mode = (
        "CONFIG REVIEW ONLY"
        if report.connection_mode == ConnectionMode.SKIPPED
        else "CONNECTED REVIEW"
        if report.connection_mode == ConnectionMode.ATTEMPTED
        else "REVIEW MODE UNKNOWN"
    )
    clients = len({a.server.client for a in report.audits})
    entry_label = "entry" if report.servers_discovered == 1 else "entries"
    client_label = "client" if clients == 1 else "clients"
    scope = f"{report.servers_discovered} {entry_label}, {clients} {client_label}"
    if explicit_config:
        scope = f"{report.servers_discovered} {entry_label} in 1 explicit file; client not asserted"
    out.print(f"{mode} | {scope} | {len(report.config_health_findings)} config warnings")
    counts = {s: sum(a.severity == s for a in actions) for s in LABELS}
    out.print(
        f"Totals: {len(actions)} findings ({counts['high']} Fix now, "
        f"{counts['medium']} Worth a look, {counts['low']} FYI); "
        f"{len(report.warnings)} scan warnings; {report.total_tools} tools; "
        f"{report.high_risk_servers} high-risk servers (capability exposure)"
    )
    out.print(terminal_safe(_coverage(report)))
    candidates: list[Action] = []
    for warning in report.warnings:
        affected = [a for a in report.audits if not warning.servers or a.server.name in warning.servers]
        flag = (
            "--canary-check"
            if warning.check == "runtime_security"
            else "--" + warning.check.replace("_", "-")
            if warning.check
            else ""
        )
        flags = (flag,) if flag in set(_FINDING_FLAGS.values()) | {"--canary-check", "--llm-analysis"} else ()
        candidates.append(
            Action(
                "medium",
                "Restore check coverage",
                warning.message,
                "Use --details to review this check's reason and prerequisites before rechecking.",
                tuple(a.server.config_path for a in affected),
                tuple(_identity(a, explicit_config=explicit_config) for a in affected),
                warning.code,
                flags=flags,
                connected=report.connection_mode == ConnectionMode.ATTEMPTED and flag not in _STATIC_FLAGS,
            )
        )
    groups: dict[tuple[tuple[str, ...], tuple[str, ...]], list[Action]] = {}
    for action in actions:
        groups.setdefault((action.identities, action.sources), []).append(action)
    for group in groups.values():
        ordered = sorted(
            group,
            key=lambda a: (
                {"shell_wrapper_launch": 0, "credential_heavy_config": 1}.get(a.rule, 2),
                {"high": 0, "medium": 1, "low": 2}.get(a.severity, 1),
            ),
        )
        severity = min(
            (a.severity for a in group), key=lambda s: {"high": 0, "medium": 1, "low": 2}.get(s, 1)
        )
        candidates.append(
            replace(
                ordered[0],
                severity=severity,
                related=len(group) - 1,
                flags=tuple(dict.fromkeys(flag for a in group for flag in a.flags)),
                connected=any(a.connected for a in group),
            )
        )
    warning_count = len(report.warnings)
    candidates[warning_count:] = sorted(
        candidates[warning_count:],
        key=lambda a: (
            {"high": 0, "medium": 1, "low": 2}.get(a.severity, 1),
            {"shell_wrapper_launch": 0, "package_runner_source_review": 1, "credential_heavy_config": 2}.get(
                a.rule, 3
            ),
        ),
    )
    seen: set[tuple[tuple[str, ...], str]] = set()
    shown = 0
    for action in candidates:
        card_key = (action.identities, action.rule)
        if card_key in seen:
            continue
        seen.add(card_key)
        shown += 1
        out.print()
        out.print(
            terminal_safe(f"{shown}. {LABELS.get(action.severity, LABELS['medium'])} · {action.title}"),
            style=STYLES.get(action.severity, "yellow"),
        )
        out.print(terminal_safe("   " + ("; ".join(action.identities) or "Scan scope")))
        out.print(
            terminal_safe(
                "   Source: " + ("; ".join(action.sources) or "not recorded; see inspect --details")
            )
        )
        out.print(terminal_safe("   Why: " + action.consequence))
        out.print(terminal_safe("   Manual step: " + action.step))
        if action.connected:
            out.print("   Connected recheck may execute code and access the network; review first.")
            out.print("   Copy only the listed entries into ./reviewed-mcp-config.json before rechecking.")
        out.print(terminal_safe("   Recheck:\n     " + _recheck(action)))
        if action.related:
            out.print(f"   +{action.related} related findings in --details (included in totals).")
        if shown == 3:
            break
    out.print()
    out.print(terminal_safe(what_happened(report, explicit_config=explicit_config)))
    if report.policy_result is not None:
        result = report.policy_result
        out.print(
            f"Policy Gate: {'passed' if result.passed else 'FAILED'} ({len(result.violations)} violations)"
        )
    out.print("All findings, evidence and capability exposure: --details")
