"""Aggregate bounded check completion without inferring safety from findings."""

from mcp_audit.models import CheckCoverage, CoverageState, LLMAnalysisStatus, ScanWarning, ServerAudit

OPTIONAL_CHECKS = (
    "inject_check",
    "ssrf_check",
    "egress_check",
    "pin_check",
    "trifecta_check",
    "shadow_check",
    "escalation_check",
    "provenance_check",
    "integrity_check",
    "verify_artifacts",
    "download_artifacts",
    "llm_analysis",
    "runtime_security",
)
_CONFIG_CHECKS = {"provenance_check", "integrity_check", "verify_artifacts", "download_artifacts"}
_BASELINE_CHECKS = _CONFIG_CHECKS | {"pin_check", "escalation_check"}
_AGENT_TEXT_CHECKS = {"permissions", "inject_check", "trifecta_check", "escalation_check"}
_BOUNDED_TEXT_CHECKS = {
    "permissions",
    "capabilities",
    "ssrf_check",
    "egress_check",
    "trifecta_check",
    "escalation_check",
}


def _warning_reasons(check: str, audit: ServerAudit, warnings: list[ScanWarning]) -> list[str]:
    return [
        warning.code
        for warning in warnings
        if (
            warning.check == check
            or (
                warning.code == "permission_schema_incomplete"
                and warning.check == "permission_analysis"
                and check in {"permissions", "trifecta_check", "escalation_check"}
            )
            or (warning.code == "agent_text_incomplete" and check in _AGENT_TEXT_CHECKS)
            or (warning.code == "description_truncated" and check in _BOUNDED_TEXT_CHECKS)
        )
        and warning.code != "option_ignored"
        and (not warning.servers or audit.server.name in warning.servers)
    ]


def missing_checks(coverage: dict[str, CheckCoverage]) -> list[str]:
    """Missing known entries have unknown completion, including sparse old maps."""
    return [
        check
        for check in ("config_health", "permissions", "capabilities", "metadata", *OPTIONAL_CHECKS)
        if check not in coverage
    ]


def _aggregate(entries: list[CheckCoverage]) -> CheckCoverage:
    if not entries:
        return CheckCoverage(state="not_run", reason="no configured servers")
    states = {entry.state for entry in entries}
    state: CoverageState = next(iter(states)) if len(states) == 1 else "partial"
    reasons = dict.fromkeys(entry.reason for entry in entries if entry.state != "complete")
    return CheckCoverage(state=state, reason="; ".join(reasons) or "completed for all configured servers")


def build_coverage(
    audits: list[ServerAudit],
    *,
    requested: set[str],
    skip_connect: bool,
    warnings: list[ScanWarning],
    baselines: dict[str, list[bool]],
    completed: list[set[str]],
    package_coverage: dict[str, list[CheckCoverage]],
    discovery_incomplete: bool,
    config_health_inspected: bool,
) -> dict[str, CheckCoverage]:
    """Require execution evidence and all prerequisites before claiming completion.

    An empty listing that completed is admissible metadata. Empty inventories
    cannot substitute for an absent baseline or an unexecuted check.
    """
    coverage = {
        "config_health": CheckCoverage(state="complete", reason="configuration inspected")
        if config_health_inspected
        else CheckCoverage(state="not_run", reason="configuration inspection unavailable")
    }
    for check in ("metadata", "permissions", "capabilities", *OPTIONAL_CHECKS):
        if check in OPTIONAL_CHECKS and check not in requested:
            coverage[check] = CheckCoverage(state="not_requested", reason="check not requested")
            continue
        entries: list[CheckCoverage] = []
        for index, audit in enumerate(audits):
            if check not in completed[index]:
                entry = CheckCoverage(state="not_run", reason="check execution unavailable")
            elif check in _CONFIG_CHECKS:
                entry = CheckCoverage(state="complete", reason="configuration baseline compared")
            elif not skip_connect and audit.connection_status == "connected":
                entry = CheckCoverage(state="complete", reason="metadata listed and check executed")
            elif audit.connection_status == "partial":
                entry = CheckCoverage(state="partial", reason="metadata listing incomplete")
            else:
                state: CoverageState = (
                    "partial" if audit.tools or audit.prompts or audit.resources else "not_run"
                )
                entry = CheckCoverage(state=state, reason="connection or analysis did not complete")
            if skip_connect and check not in _CONFIG_CHECKS:
                entry = CheckCoverage(state="not_run", reason="connections disabled")
            if check == "permissions" and (skip_connect or audit.connection_status == "skipped"):
                entry = CheckCoverage(
                    state="partial", reason="configuration-derived permissions only; metadata not checked"
                )
            if check in _BASELINE_CHECKS and (check not in baselines or not baselines[check][index]):
                entry = CheckCoverage(state="not_run", reason="required per-server baseline unavailable")
            if check in package_coverage:
                entry = package_coverage[check][index].model_copy()
            if check == "integrity_check" and any(f.current_hash is None for f in audit.integrity_findings):
                entry = CheckCoverage(state="partial", reason="launch artifact hashing unavailable")
            if check == "runtime_security":
                summary = audit.canary
                if summary is None:
                    entry = CheckCoverage(state="not_run", reason="runtime exercise unavailable")
                elif (
                    summary.status != "complete"
                    or summary.warnings
                    or summary.completed_calls < summary.call_budget
                ):
                    state = "not_run" if summary.status == "no_safe_tools" else "partial"
                    if audit.connection_status == "partial":
                        state = "partial"
                    entry = CheckCoverage(
                        state=state, reason="; ".join(summary.warnings) or "runtime exercise incomplete"
                    )
            if check == "llm_analysis":
                summary_llm = audit.llm_analysis
                if summary_llm is None:
                    entry = CheckCoverage(state="not_run", reason="LLM execution unavailable")
                elif summary_llm.status == LLMAnalysisStatus.UNKNOWN:
                    entry = CheckCoverage(state="not_run", reason=summary_llm.reason_code.value)
                elif summary_llm.analyzed_tools < summary_llm.candidate_tools:
                    entry = CheckCoverage(state="partial", reason="LLM candidates not fully analyzed")
            reasons = _warning_reasons(check, audit, warnings)
            if reasons and entry.state == "complete":
                entry = CheckCoverage(state="partial", reason="; ".join(reasons))
            if check not in completed[index]:
                entry = CheckCoverage(state="not_run", reason="check execution unavailable")
            entries.append(entry)
        coverage[check] = _aggregate(entries)
        if skip_connect and check == "metadata":
            coverage[check] = CheckCoverage(state="not_run", reason="connections disabled")
    if discovery_incomplete:
        for check, entry in coverage.items():
            if entry.state != "not_requested":
                reason = "configuration discovery incomplete: config_parse_failure"
                if entry.state != "complete":
                    reason += "; " + entry.reason
                coverage[check] = CheckCoverage(state="partial", reason=reason)
    return coverage
