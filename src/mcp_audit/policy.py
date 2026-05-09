"""Local policy gates for CI-friendly MCP audit enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models import AuditReport, PermissionCategory, PolicyResult, PolicyViolation

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class PolicyConfig:
    """Parsed local policy gate configuration."""

    fail_on_severity: str | None = None
    fail_on_drift: bool = False
    denied_permissions: list[PermissionCategory] = field(default_factory=list)
    max_risk: float | None = None


def load_policy(path: Path) -> PolicyConfig:
    """Load a policy YAML file from disk."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Policy file must contain a YAML mapping.")

    fail_on = _mapping(raw.get("fail_on"), "fail_on")
    deny = _mapping(raw.get("deny"), "deny")

    severity = fail_on.get("severity")
    if severity is not None:
        severity = str(severity).lower()
        if severity not in _SEVERITY_RANK:
            valid = ", ".join(_SEVERITY_RANK)
            raise ValueError(f"Unknown policy severity '{severity}'. Valid values: {valid}.")

    permissions = [_permission(value) for value in _sequence(deny.get("permissions"), "deny.permissions")]

    max_risk = raw.get("max_risk")
    if max_risk is not None:
        max_risk = float(max_risk)
        if max_risk < 0 or max_risk > 10:
            raise ValueError("max_risk must be between 0 and 10.")

    return PolicyConfig(
        fail_on_severity=severity,
        fail_on_drift=bool(fail_on.get("drift", False)),
        denied_permissions=permissions,
        max_risk=max_risk,
    )


def evaluate_policy(report: AuditReport, policy: PolicyConfig) -> PolicyResult:
    """Evaluate a completed audit report against a local policy."""
    violations: list[PolicyViolation] = []

    for audit in report.audits:
        server_name = audit.server.name

        if policy.max_risk is not None and audit.risk_score is not None:
            score = audit.risk_score.composite
            if score >= policy.max_risk:
                violations.append(
                    PolicyViolation(
                        rule="max_risk",
                        server_name=server_name,
                        severity="high",
                        message=(
                            f"Server risk score {score:.1f} meets or exceeds policy limit "
                            f"{policy.max_risk:.1f}."
                        ),
                    )
                )

        if policy.fail_on_severity is not None:
            threshold = _SEVERITY_RANK[policy.fail_on_severity]
            for permission_finding in audit.permissions:
                if _SEVERITY_RANK[permission_finding.severity] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule="fail_on.severity",
                            server_name=server_name,
                            tool_name=permission_finding.tool_name,
                            severity=permission_finding.severity,
                            message=(
                                f"{permission_finding.rule_id} "
                                f"{permission_finding.category.value} finding is "
                                f"{permission_finding.severity} severity."
                            ),
                        )
                    )
            for injection_finding in audit.injection_findings:
                if _SEVERITY_RANK[injection_finding.severity.value] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule="fail_on.severity",
                            server_name=server_name,
                            tool_name=injection_finding.tool_name,
                            severity=injection_finding.severity.value,
                            message=(
                                f"{injection_finding.rule_id} prompt-injection finding is "
                                f"{injection_finding.severity.value} severity."
                            ),
                        )
                    )

        for permission_finding in audit.permissions:
            if permission_finding.category in policy.denied_permissions:
                violations.append(
                    PolicyViolation(
                        rule="deny.permissions",
                        server_name=server_name,
                        tool_name=permission_finding.tool_name,
                        severity=permission_finding.severity,
                        message=f"{permission_finding.category.value} is denied by local policy.",
                    )
                )

        if policy.fail_on_drift:
            for drift_finding in audit.drift_findings:
                violations.append(
                    PolicyViolation(
                        rule="fail_on.drift",
                        server_name=server_name,
                        tool_name=drift_finding.tool_name,
                        severity="medium",
                        message=f"Tool schema drift detected: {drift_finding.status.value}.",
                    )
                )

    return PolicyResult(passed=not violations, violations=violations)


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a YAML mapping.")
    return value


def _sequence(value: Any, name: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a YAML list.")
    return value


def _permission(value: Any) -> PermissionCategory:
    try:
        return PermissionCategory(str(value))
    except ValueError as exc:
        valid = ", ".join(category.value for category in PermissionCategory)
        raise ValueError(f"Unknown permission category '{value}'. Valid values: {valid}.") from exc
