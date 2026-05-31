"""Local policy gates for CI-friendly MCP audit enforcement."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models import (
    AuditReport,
    ConfigHealthFinding,
    PermissionCategory,
    PolicyResult,
    PolicyViolation,
)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class PolicyConfig:
    """Parsed local policy gate configuration."""

    fail_on_severity: str | None = None
    fail_on_permission_severity: str | None = None
    fail_on_injection_severity: str | None = None
    fail_on_ssrf_severity: str | None = None
    fail_on_capability_severity: str | None = None
    fail_on_config_health_severity: str | None = None
    fail_on_drift: bool = False
    fail_on_trifecta: bool = False
    required_pin_servers: list[str] = field(default_factory=list)
    denied_permissions: list[PermissionCategory] = field(default_factory=list)
    max_risk: float | None = None
    allow_servers: list[str] = field(default_factory=list)
    server_rules: dict[str, ServerPolicyConfig] = field(default_factory=dict)


@dataclass(frozen=True)
class ServerPolicyConfig:
    """Policy overrides scoped to one server name."""

    denied_permissions: list[PermissionCategory] = field(default_factory=list)
    max_risk: float | None = None
    fail_on_permission_severity: str | None = None
    fail_on_injection_severity: str | None = None
    fail_on_ssrf_severity: str | None = None
    fail_on_capability_severity: str | None = None
    fail_on_config_health_severity: str | None = None
    fail_on_drift: bool | None = None
    require_pin: bool = False


def load_policy(path: Path) -> PolicyConfig:
    """Load a policy YAML file from disk."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError("Policy file must contain a YAML mapping.")

    fail_on = _mapping(raw.get("fail_on"), "fail_on")
    deny = _mapping(raw.get("deny"), "deny")
    require = _mapping(raw.get("require"), "require")
    pins = _mapping(require.get("pins"), "require.pins")
    server_rules = _server_rules(raw.get("servers"))

    severity = _severity(fail_on.get("severity"), "fail_on.severity")
    permission_severity = _severity(fail_on.get("permissions"), "fail_on.permissions")
    injection_severity = _severity(fail_on.get("injection"), "fail_on.injection")
    ssrf_severity = _severity(fail_on.get("ssrf"), "fail_on.ssrf")
    capability_severity = _severity(fail_on.get("capabilities"), "fail_on.capabilities")
    config_health_severity = _severity(fail_on.get("config_health"), "fail_on.config_health")
    trifecta = bool(fail_on.get("trifecta", False))

    permissions = [_permission(value) for value in _sequence(deny.get("permissions"), "deny.permissions")]

    max_risk = raw.get("max_risk")
    if max_risk is not None:
        max_risk = float(max_risk)
        if max_risk < 0 or max_risk > 10:
            raise ValueError("max_risk must be between 0 and 10.")

    return PolicyConfig(
        fail_on_severity=severity,
        fail_on_permission_severity=permission_severity,
        fail_on_injection_severity=injection_severity,
        fail_on_ssrf_severity=ssrf_severity,
        fail_on_capability_severity=capability_severity,
        fail_on_config_health_severity=config_health_severity,
        fail_on_drift=bool(fail_on.get("drift", False)),
        fail_on_trifecta=trifecta,
        required_pin_servers=[str(value) for value in _sequence(pins.get("servers"), "require.pins.servers")],
        denied_permissions=permissions,
        max_risk=max_risk,
        allow_servers=[str(value) for value in _sequence(raw.get("allow_servers"), "allow_servers")],
        server_rules=server_rules,
    )


def evaluate_policy(
    report: AuditReport,
    policy: PolicyConfig,
    pin_store: object | None = None,
) -> PolicyResult:
    """Evaluate a completed audit report against a local policy."""
    violations: list[PolicyViolation] = []
    resolved_pin_store = pin_store
    if (
        policy.required_pin_servers or any(rule.require_pin for rule in policy.server_rules.values())
    ) and resolved_pin_store is None:
        from mcp_audit.pinning import PinStore

        resolved_pin_store = PinStore()

    for audit in report.audits:
        server_name = audit.server.name
        server_rule = policy.server_rules.get(server_name, ServerPolicyConfig())

        if policy.allow_servers and server_name not in policy.allow_servers:
            violations.append(
                PolicyViolation(
                    rule="allow_servers",
                    server_name=server_name,
                    severity="medium",
                    message=f"Server '{server_name}' is not listed in allow_servers.",
                )
            )

        require_pin = server_name in policy.required_pin_servers or server_rule.require_pin
        if require_pin:
            tool_count = _pin_tool_count(resolved_pin_store, server_name)
            if tool_count == 0:
                violations.append(
                    PolicyViolation(
                        rule="require.pins",
                        server_name=server_name,
                        severity="medium",
                        message=f"Server '{server_name}' is required to have a pin baseline.",
                    )
                )

        max_risk = server_rule.max_risk if server_rule.max_risk is not None else policy.max_risk
        if max_risk is not None and audit.risk_score is not None:
            score = audit.risk_score.composite
            if score >= max_risk:
                violations.append(
                    PolicyViolation(
                        rule="max_risk",
                        server_name=server_name,
                        severity="high",
                        message=(
                            f"Server risk score {score:.1f} meets or exceeds policy limit {max_risk:.1f}."
                        ),
                    )
                )

        permission_threshold = _effective_threshold(
            server_rule.fail_on_permission_severity,
            policy.fail_on_permission_severity,
            policy.fail_on_severity,
        )
        if permission_threshold is not None:
            threshold = _SEVERITY_RANK[permission_threshold]
            for permission_finding in audit.permissions:
                if _SEVERITY_RANK[permission_finding.severity] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule=_threshold_rule(
                                "permissions",
                                policy.fail_on_severity,
                                permission_threshold,
                            ),
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

        injection_threshold = _effective_threshold(
            server_rule.fail_on_injection_severity,
            policy.fail_on_injection_severity,
            policy.fail_on_severity,
        )
        if injection_threshold is not None:
            threshold = _SEVERITY_RANK[injection_threshold]
            for injection_finding in audit.injection_findings:
                if _SEVERITY_RANK[injection_finding.severity.value] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule=_threshold_rule("injection", policy.fail_on_severity, injection_threshold),
                            server_name=server_name,
                            tool_name=injection_finding.target_name or injection_finding.tool_name,
                            severity=injection_finding.severity.value,
                            message=(
                                f"{injection_finding.rule_id} prompt-injection finding is "
                                f"{injection_finding.severity.value} severity."
                            ),
                        )
                    )

        ssrf_threshold = _effective_threshold(
            server_rule.fail_on_ssrf_severity,
            policy.fail_on_ssrf_severity,
        )
        if ssrf_threshold is not None:
            threshold = _SEVERITY_RANK[ssrf_threshold]
            for ssrf_finding in audit.ssrf_findings:
                if _SEVERITY_RANK[ssrf_finding.severity.value] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule="fail_on.ssrf",
                            server_name=server_name,
                            tool_name=ssrf_finding.target_name,
                            severity=ssrf_finding.severity.value,
                            message=(
                                f"{ssrf_finding.rule_id} SSRF finding is "
                                f"{ssrf_finding.severity.value} severity."
                            ),
                        )
                    )

        capability_threshold = _effective_threshold(
            server_rule.fail_on_capability_severity,
            policy.fail_on_capability_severity,
            policy.fail_on_severity,
        )
        if capability_threshold is not None:
            threshold = _SEVERITY_RANK[capability_threshold]
            for capability_finding in audit.capability_findings:
                if _SEVERITY_RANK[capability_finding.severity] >= threshold:
                    violations.append(
                        PolicyViolation(
                            rule=_threshold_rule(
                                "capabilities",
                                policy.fail_on_severity,
                                capability_threshold,
                            ),
                            server_name=server_name,
                            tool_name=capability_finding.target_name,
                            severity=capability_finding.severity,
                            message=(
                                f"{capability_finding.rule_id} "
                                f"{capability_finding.target_type.value} "
                                f"{capability_finding.category.value} finding is "
                                f"{capability_finding.severity} severity."
                            ),
                        )
                    )

        denied_permissions = [*policy.denied_permissions, *server_rule.denied_permissions]

        for permission_finding in audit.permissions:
            if permission_finding.category in denied_permissions:
                violations.append(
                    PolicyViolation(
                        rule="deny.permissions",
                        server_name=server_name,
                        tool_name=permission_finding.tool_name,
                        severity=permission_finding.severity,
                        message=f"{permission_finding.category.value} is denied by local policy.",
                    )
                )
        for capability_finding in audit.capability_findings:
            if capability_finding.category in denied_permissions:
                violations.append(
                    PolicyViolation(
                        rule="deny.permissions",
                        server_name=server_name,
                        tool_name=capability_finding.target_name,
                        severity=capability_finding.severity,
                        message=(
                            f"{capability_finding.target_type.value} "
                            f"{capability_finding.category.value} is denied by local policy."
                        ),
                    )
                )

        fail_on_drift = (
            server_rule.fail_on_drift if server_rule.fail_on_drift is not None else policy.fail_on_drift
        )
        if fail_on_drift:
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

        if policy.fail_on_trifecta:
            for trifecta_finding in audit.trifecta_findings:
                violations.append(
                    PolicyViolation(
                        rule="fail_on.trifecta",
                        server_name=server_name,
                        severity=trifecta_finding.severity.value,
                        message=(
                            f"{trifecta_finding.rule_id} lethal-trifecta finding is "
                            f"{trifecta_finding.severity.value} severity on server '{server_name}'."
                        ),
                    )
                )

    # Fleet-level trifecta gate
    if policy.fail_on_trifecta:
        for fleet_finding in report.fleet_trifecta_findings:
            violations.append(
                PolicyViolation(
                    rule="fail_on.trifecta",
                    server_name=None,
                    severity=fleet_finding.severity.value,
                    message=(
                        f"{fleet_finding.rule_id} fleet-level lethal-trifecta finding is "
                        f"{fleet_finding.severity.value} severity (advisory)."
                    ),
                )
            )

    violations.extend(_config_health_violations(report.config_health_findings, policy))

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


def _severity(value: Any, name: str) -> str | None:
    if value is None:
        return None
    severity = str(value).lower()
    if severity not in _SEVERITY_RANK:
        valid = ", ".join(_SEVERITY_RANK)
        raise ValueError(f"Unknown policy severity '{severity}'. Valid values: {valid}.")
    return severity


def _effective_threshold(*values: str | None) -> str | None:
    return next((value for value in values if value is not None), None)


def _threshold_rule(name: str, broad_threshold: str | None, effective_threshold: str) -> str:
    return "fail_on.severity" if broad_threshold == effective_threshold else f"fail_on.{name}"


def _pin_tool_count(pin_store: object | None, server_name: str) -> int:
    if pin_store is None:
        return 0
    tool_count = getattr(pin_store, "tool_count", None)
    if not callable(tool_count):
        return 0
    return int(tool_count(server_name))


def _config_health_violations(
    findings: list[ConfigHealthFinding],
    policy: PolicyConfig,
) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []
    for finding in findings:
        server_rule = (
            policy.server_rules.get(finding.server_name, ServerPolicyConfig())
            if finding.server_name is not None
            else ServerPolicyConfig()
        )
        threshold_name = _effective_threshold(
            server_rule.fail_on_config_health_severity,
            policy.fail_on_config_health_severity,
        )
        if threshold_name is None:
            continue
        if _SEVERITY_RANK[finding.severity.value] < _SEVERITY_RANK[threshold_name]:
            continue
        violations.append(
            PolicyViolation(
                rule="fail_on.config_health",
                server_name=finding.server_name,
                severity=finding.severity.value,
                message=(
                    f"Config health finding '{finding.finding_type}' is "
                    f"{finding.severity.value} severity: {finding.summary}"
                ),
            )
        )
    return violations


def _server_rules(value: Any) -> dict[str, ServerPolicyConfig]:
    raw_rules = _mapping(value, "servers")
    rules: dict[str, ServerPolicyConfig] = {}
    for server_name, rule_value in raw_rules.items():
        rule = _mapping(rule_value, f"servers.{server_name}")
        deny = _mapping(rule.get("deny"), f"servers.{server_name}.deny")
        fail_on = _mapping(rule.get("fail_on"), f"servers.{server_name}.fail_on")
        max_risk = rule.get("max_risk")
        if max_risk is not None:
            max_risk = float(max_risk)
            if max_risk < 0 or max_risk > 10:
                raise ValueError(f"servers.{server_name}.max_risk must be between 0 and 10.")
        rules[str(server_name)] = ServerPolicyConfig(
            denied_permissions=[
                _permission(permission)
                for permission in _sequence(
                    deny.get("permissions"),
                    f"servers.{server_name}.deny.permissions",
                )
            ],
            max_risk=max_risk,
            fail_on_permission_severity=_severity(
                fail_on.get("permissions"), f"servers.{server_name}.fail_on.permissions"
            ),
            fail_on_injection_severity=_severity(
                fail_on.get("injection"), f"servers.{server_name}.fail_on.injection"
            ),
            fail_on_ssrf_severity=_severity(fail_on.get("ssrf"), f"servers.{server_name}.fail_on.ssrf"),
            fail_on_capability_severity=_severity(
                fail_on.get("capabilities"), f"servers.{server_name}.fail_on.capabilities"
            ),
            fail_on_config_health_severity=_severity(
                fail_on.get("config_health"), f"servers.{server_name}.fail_on.config_health"
            ),
            fail_on_drift=bool(fail_on["drift"]) if "drift" in fail_on else None,
            require_pin=bool(rule.get("require_pin", False)),
        )
    return rules
