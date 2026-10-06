"""Aggregate bounded check completion without inferring safety from findings."""

from mcp_audit.models import (
    ArtifactVerifyKind,
    CheckCoverage,
    CoverageState,
    LLMAnalysisStatus,
    ScanWarning,
    ServerAudit,
)

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
_AGENT_TEXT_CHECKS = {"permissions", "inject_check", "trifecta_check", "escalation_check"}


def _warning_reasons(check: str, audit: ServerAudit, warnings: list[ScanWarning]) -> list[str]:
    return [
        warning.code
        for warning in warnings
        if (
            warning.check == check
            or (warning.code == "agent_text_incomplete" and check in _AGENT_TEXT_CHECKS)
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
) -> dict[str, CheckCoverage]:
    """Record requested checks, skipped prerequisites, and incomplete inventories.

    An empty listing that completed is admissible metadata. Failed listings and
    absent exercise candidates are coverage loss even when findings are empty.
    """
    coverage = {"config_health": CheckCoverage(state="complete", reason="configuration inspected")}
    metadata_entries: list[CheckCoverage] = []
    for audit in audits:
        if skip_connect:
            metadata_entries.append(CheckCoverage(state="not_run", reason="connections disabled"))
        elif audit.connection_status == "connected":
            metadata_entries.append(CheckCoverage(state="complete", reason="metadata listed"))
        elif audit.connection_status == "partial":
            metadata_entries.append(CheckCoverage(state="partial", reason="metadata listing incomplete"))
        else:
            state: CoverageState = "partial" if audit.tools or audit.prompts or audit.resources else "not_run"
            metadata_entries.append(
                CheckCoverage(state=state, reason="connection or analysis did not complete")
            )
    metadata = _aggregate(metadata_entries)
    if skip_connect:
        metadata = CheckCoverage(state="not_run", reason="connections disabled")
    coverage["metadata"] = metadata
    coverage["permissions"] = (
        CheckCoverage(state="partial", reason="configuration-derived permissions only; metadata not checked")
        if skip_connect and audits
        else metadata.model_copy()
    )
    coverage["capabilities"] = metadata.model_copy()
    permission_entries = []
    for index, audit in enumerate(audits):
        entry = metadata_entries[index].model_copy()
        reasons = _warning_reasons("permissions", audit, warnings)
        if reasons and entry.state == "complete":
            entry = CheckCoverage(state="partial", reason="; ".join(reasons))
        permission_entries.append(entry)
    if not skip_connect:
        coverage["permissions"] = _aggregate(permission_entries)

    for check in OPTIONAL_CHECKS:
        if check not in requested:
            coverage[check] = CheckCoverage(state="not_requested", reason="check not requested")
            continue
        entries: list[CheckCoverage] = []
        for index, audit in enumerate(audits):
            entry = metadata_entries[index].model_copy()
            if check in _CONFIG_CHECKS:
                entry = CheckCoverage(state="complete", reason="configuration baseline compared")
                if audit.connection_error and audit.connection_error.startswith("analysis error:"):
                    entry = CheckCoverage(state="not_run", reason="analysis did not complete")
            if check in baselines and not baselines[check][index]:
                entry = CheckCoverage(state="not_run", reason="required per-server baseline unavailable")
            if check == "runtime_security":
                summary = audit.canary
                if summary is None:
                    entry = CheckCoverage(state="not_run", reason="runtime exercise unavailable")
                elif summary.status == "complete":
                    entry = CheckCoverage(state="complete", reason="bounded canary exercise completed")
                else:
                    state = "not_run" if summary.status == "no_safe_tools" else "partial"
                    if metadata_entries[index].state == "partial":
                        state = "partial"
                    entry = CheckCoverage(
                        state=state, reason="; ".join(summary.warnings) or "runtime exercise incomplete"
                    )
            if check == "llm_analysis" and audit.llm_analysis is not None:
                summary_llm = audit.llm_analysis
                if summary_llm.status == LLMAnalysisStatus.UNKNOWN:
                    entry = CheckCoverage(state="not_run", reason=summary_llm.reason_code.value)
            if check == "verify_artifacts" and any(
                finding.current_hash is None for finding in audit.package_verify_findings
            ):
                entry = CheckCoverage(state="partial", reason="registry verification unavailable")
            if check == "download_artifacts" and any(
                finding.kind == ArtifactVerifyKind.UNVERIFIED for finding in audit.artifact_verify_findings
            ):
                entry = CheckCoverage(state="partial", reason="artifact verification unavailable")
            reasons = _warning_reasons(check, audit, warnings)
            if reasons and entry.state == "complete":
                entry = CheckCoverage(state="partial", reason="; ".join(reasons))
            entries.append(entry)
        coverage[check] = _aggregate(entries)
    return coverage
