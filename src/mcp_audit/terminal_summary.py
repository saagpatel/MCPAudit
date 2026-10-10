"""Summary-first presentation of recorded findings and execution coverage."""

from __future__ import annotations

import os
import shlex
from typing import TYPE_CHECKING

from pydantic import BaseModel
from rich.console import Console

from mcp_audit.coverage import missing_checks
from mcp_audit.finding_display import _view
from mcp_audit.models import AuditReport, ConnectionMode, ReviewActionDisplay, ServerAudit
from mcp_audit.taxonomy import FINDING_COPY, config_health_rule_id, finding_copy, finding_url
from mcp_audit.terminal_text import terminal_safe

LABELS = {"high": "▲ Fix now", "medium": "◆ Worth a look", "low": "● FYI"}
STYLES = {"high": "bold red", "medium": "yellow", "low": "dim"}
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
    "PinIntegrityFinding": "--pin-check",
    "DriftFinding": "--pin-check",
}
_STATIC_FLAGS = {
    "--provenance-check",
    "--integrity-check",
    "--verify-artifacts",
    "--download-artifacts",
}


def summary_console(*, color: str = "auto", stderr: bool = False) -> Console:
    disabled = color == "never" or "NO_COLOR" in os.environ
    force = False if disabled else True if color == "always" else None
    return Console(stderr=stderr, force_terminal=force, no_color=disabled)


if TYPE_CHECKING:
    from mcp_audit.models import ReviewGrade

Action = ReviewActionDisplay


def replace(action: Action, **changes: object) -> Action:
    return action.model_copy(update=changes)


def _text(data: dict[str, object], *keys: str) -> str:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _identity(audit: ServerAudit, *, explicit_config: bool = False) -> str:
    server = audit.server
    client = "client not asserted" if explicit_config else server.client.value
    identity = f"{server.name} / {client} ({server.scope})"
    source = "explicit file; parsed as Claude-style config" if explicit_config else server.config_source
    return f"{identity} | {source}" if source else identity


def _action(finding: BaseModel, audits: list[ServerAudit], sources: tuple[str, ...] = ()) -> Action:
    data: dict[str, object] = finding.model_dump(mode="json")
    kind = _text(data, "finding_type")
    title = _text(data, "title", "summary", "description") or kind.replace("_", " ")
    consequence = _text(data, "description", "summary") or "Review the recorded capability before use."
    step = _text(data, "remediation") or "Review this finding in --details before enabling the entry."
    rule = _text(data, "rule_id") or (config_health_rule_id(kind) if kind else "MCP009")
    copy = finding_copy(rule) if rule in FINDING_COPY or rule.startswith("MCP-CH-") else None
    if copy is not None:
        title = copy.title
        consequence = " ".join(copy.why_it_matters)
        step = copy.how_to_fix
    observed = _view(finding, rule_id=rule).evidence or (copy.what_we_saw if copy else consequence)
    manual_step = _text(data, "remediation")
    if kind == "shell_wrapper_launch":
        manual_step = (
            "Inspect this entry's shell arguments. If a direct executable and argument list can express "
            "the intended launch, use those instead of a shell wrapper. Otherwise remove this entry "
            "temporarily and restart the client while you review the script."
        )
    target = _text(data, "target_name", "tool_name", "name")
    if target:
        observed = f"{target}: {observed}"
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
        not kind
        and rule != "MCP027"
        and (flag not in _STATIC_FLAGS)
        and any(a.connection_status != "skipped" for a in audits)
    )
    return Action(
        severity=_text(data, "severity") or "medium",
        title=title,
        consequence=consequence,
        step=step,
        sources=paths,
        identities=tuple(_identity(a) for a in audits),
        rule=rule,
        flags=flags,
        connected=connected,
        observed=observed,
        confidence=copy.how_sure if copy else "",
        time_to_fix=copy.time_to_fix if copy else "",
        manual_step=manual_step,
        reference=finding_url(rule) if copy else "",
    )


def findings(report: AuditReport) -> list[Action]:
    """Present the saved action groups; never regroup redacted finding rows."""
    result = []
    for action in report.ensure_review_summary().actions:
        display = action.terminal
        if display is None:
            # Older saved summaries have no terminal copy. Preserve their decisions.
            display = Action(
                severity=action.severity,
                title=action.title,
                consequence="Review the recorded capability before use.",
                step=" ".join(action.steps),
                sources=(),
                identities=(),
                rule=action.sources[0].split(":", 1)[0] if action.sources else "MCP009",
            )
        result.append(
            replace(
                display,
                severity=action.severity,
                # A public taxonomy link can be rebuilt after URL-fragment redaction.
                reference=finding_url(display.rule) if display.reference else "",
            )
        )
    return result


def grade(report: AuditReport) -> ReviewGrade | None:
    """Compatibility entry point for the one precomputed presentation grade."""
    return report.ensure_review_summary().grade


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
    if report.suppressed:
        from mcp_audit.suppressions import suppression_summary

        parts.append(suppression_summary(report))
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
            ", ".join(_identity(a, explicit_config=explicit_config) for a in attempted[:3])
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
    summary = report.ensure_review_summary()
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
        letter = summary.grade
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
    out.print(f"{mode}: {scope}; {len(report.config_health_findings)} config warnings")
    counts = summary.action_counts
    out.print(
        f"Totals: {summary.action_count} findings ({counts['high']} Fix now, "
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
                severity="medium",
                title="Restore check coverage",
                consequence=warning.message,
                step="Use --details to review this check's reason and prerequisites before rechecking.",
                sources=tuple(a.server.config_path for a in affected),
                identities=tuple(_identity(a, explicit_config=explicit_config) for a in affected),
                rule=warning.code,
                flags=flags,
                connected=report.connection_mode == ConnectionMode.ATTEMPTED and flag not in _STATIC_FLAGS,
            )
        )
    groups: dict[str, list[Action]] = {}
    for saved, action in zip(summary.actions, actions, strict=True):
        groups.setdefault(saved.card_group or saved.owner, []).append(action)
    for group in groups.values():
        ordered = sorted(
            group,
            key=lambda a: (
                {
                    config_health_rule_id("shell_wrapper_launch"): 0,
                    config_health_rule_id("credential_heavy_config"): 1,
                }.get(a.rule, 2),
                {"high": 0, "medium": 1, "low": 2}.get(a.severity, 1),
                0 if a.rule.startswith("MCP-CH-") else 1,
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
            {
                config_health_rule_id("shell_wrapper_launch"): 0,
                config_health_rule_id("package_runner_source_review"): 1,
                config_health_rule_id("credential_heavy_config"): 2,
            }.get(a.rule, 3),
        ),
    )
    shown = 0
    for action in candidates:
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
        out.print(terminal_safe("   What we saw: " + (action.observed or action.consequence)))
        out.print(terminal_safe("   Why it matters: " + action.consequence))
        estimate = f" ({action.time_to_fix})" if action.time_to_fix else ""
        out.print(terminal_safe(f"   How to fix{estimate}: " + action.step))
        if action.manual_step:
            out.print(terminal_safe("   Manual step: " + action.manual_step))
        if action.confidence:
            out.print(terminal_safe("   How sure: " + action.confidence))
        if action.reference:
            out.print(terminal_safe("   see: " + action.reference))
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
    out.print(f"Estimated initial review: {summary.review_minutes} minutes")
    out.print("All findings, evidence and capability exposure: --details")
