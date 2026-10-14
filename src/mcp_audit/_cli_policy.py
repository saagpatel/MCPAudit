"""One-shot CLI policy gates, separate from library policy evaluation."""

from __future__ import annotations

from dataclasses import replace

from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, PolicyResult, PolicyViolation
from mcp_audit.policy import PolicyConfig, evaluate_policy

_PIN_CHECKS = (
    "pin_check",
    "canary_check",
    "escalation_check",
    "provenance_check",
    "integrity_check",
    "verify_artifacts",
    "download_artifacts",
)


def apply_cli_policy(
    report: AuditReport,
    options: ScanOptions,
    policy: PolicyConfig | None,
    *,
    pin_store: object | None = None,
) -> None:
    """Evaluate configured policy and fail requested withheld-baseline checks."""
    result = (
        evaluate_policy(report, replace(policy, fail_on_pin_baseline_withheld=False), pin_store=pin_store)
        if policy is not None
        else None
    )
    violations = list(result.violations) if result is not None else []
    requested = {check for check in _PIN_CHECKS if getattr(options, check)}
    for audit_index, audit in enumerate(report.audits):
        checks = sorted(
            {
                warning.check
                for warning in report.warnings
                if warning.code == "pin_baseline_withheld"
                and warning.check in requested
                and warning.check is not None
                and (not warning.servers or audit.server.name in warning.servers)
            }
        )
        if checks:
            violations.append(
                PolicyViolation(
                    rule="fail_on.pin_baseline_withheld",
                    server_name=audit.server.name,
                    audit_index=audit_index,
                    severity="high",
                    message=(
                        f"Requested checks ({', '.join(checks)}) for server '{audit.server.name}' "
                        "could not compare its withheld baseline. Restore a trusted baseline, "
                        f"or review with `mcp-audit pin --refresh {audit.server.name}` before applying."
                    ),
                )
            )
    if result is not None or violations:
        report.policy_result = PolicyResult(passed=not violations, violations=violations)
