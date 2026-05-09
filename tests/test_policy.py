"""Tests for local policy gate evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_audit import cli
from mcp_audit.models import (
    AuditReport,
    Confidence,
    DriftFinding,
    DriftStatus,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
)
from mcp_audit.policy import evaluate_policy, load_policy
from tests.conftest import make_server_config, make_tool


def _audit_report(audit: ServerAudit) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="test-host",
        os_platform="test-os",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=len(audit.tools),
        high_risk_servers=1 if audit.risk_score and audit.risk_score.composite >= 7.0 else 0,
        audits=[audit],
        scan_duration_seconds=0.01,
    )


def _audit_with_shell_finding() -> ServerAudit:
    return ServerAudit(
        server=make_server_config(name="srv"),
        connection_status="connected",
        tools=[make_tool("run_shell")],
        permissions=[
            PermissionFinding(
                category=PermissionCategory.SHELL_EXEC,
                confidence=Confidence.HIGH,
                evidence=["run_shell"],
                tool_name="run_shell",
            )
        ],
        risk_score=RiskScore(
            composite=8.0,
            file_access=0.0,
            network_access=0.0,
            shell_execution=8.0,
            destructive=0.0,
            exfiltration=0.0,
        ),
    )


def test_policy_fails_on_denied_permission(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  permissions:
    - shell_execution
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "deny.permissions"
    assert result.violations[0].tool_name == "run_shell"


def test_policy_fails_on_high_severity_threshold(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  severity: high
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert not result.passed
    assert {violation.rule for violation in result.violations} == {"fail_on.severity"}


def test_policy_fails_on_drift_when_enabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  drift: true
"""
    )
    audit = _audit_with_shell_finding()
    audit.drift_findings = [
        DriftFinding(server_name="srv", tool_name="run_shell", status=DriftStatus.CHANGED)
    ]
    result = evaluate_policy(_audit_report(audit), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.drift"


def test_policy_passes_when_no_rules_match(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  permissions:
    - destructive
max_risk: 9
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert result.passed
    assert result.violations == []


def test_scan_policy_writes_json_then_exits_two(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  permissions:
    - shell_execution
"""
    )
    json_path = tmp_path / "report.json"
    audit = _audit_with_shell_finding()

    monkeypatch.setattr(cli, "discover_all_configs", lambda clients: [audit.server])

    async def fake_run_scan_core(*args: object, **kwargs: object) -> AuditReport:
        return _audit_report(audit)

    monkeypatch.setattr(cli, "_run_scan_core", fake_run_scan_core)

    with pytest.raises(SystemExit) as exc:
        anyio.run(
            cli._run_scan,
            str(json_path),
            None,
            True,
            None,
            10,
            False,
            None,
            None,
            str(policy_path),
        )

    assert exc.value.code == 2
    assert json_path.exists()
    assert '"policy_result"' in json_path.read_text()
