"""Tests for local policy gate evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_audit import cli
from mcp_audit.models import (
    AuditReport,
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    DriftFinding,
    DriftStatus,
    EgressFinding,
    EgressKind,
    EgressSeverity,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
    SsrfFinding,
    SsrfSeverity,
)
from mcp_audit.policy import evaluate_policy, load_policy
from tests.conftest import make_server_config, make_tool

EXAMPLE_POLICIES = sorted(Path("examples/policies").glob("*.yaml"))


class _FakePinStore:
    def __init__(self, counts: dict[str, int]) -> None:
        self._counts = counts

    def tool_count(self, server_name: str) -> int:
        return self._counts.get(server_name, 0)


def test_example_policies_load() -> None:
    assert EXAMPLE_POLICIES
    for policy_path in EXAMPLE_POLICIES:
        load_policy(policy_path)


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


def test_policy_fails_on_denied_capability_permission(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
deny:
  permissions:
    - network
"""
    )
    audit = _audit_with_shell_finding()
    audit.capability_findings = [
        CapabilityFinding(
            target_type=CapabilityTarget.RESOURCE,
            target_name="https://example.com/data.json",
            category=PermissionCategory.NETWORK,
            confidence=Confidence.HIGH,
            evidence=["resource URI scheme 'https'"],
        )
    ]
    result = evaluate_policy(_audit_report(audit), load_policy(policy_path))
    assert not result.passed
    assert any(violation.tool_name == "https://example.com/data.json" for violation in result.violations)


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


def test_policy_fails_on_required_pin_coverage(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
require:
  pins:
    servers:
      - srv
"""
    )
    result = evaluate_policy(
        _audit_report(_audit_with_shell_finding()),
        load_policy(policy_path),
        pin_store=_FakePinStore({}),
    )
    assert not result.passed
    assert result.violations[0].rule == "require.pins"


def test_policy_passes_required_pin_coverage_when_pinned(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
require:
  pins:
    servers:
      - srv
"""
    )
    result = evaluate_policy(
        _audit_report(_audit_with_shell_finding()),
        load_policy(policy_path),
        pin_store=_FakePinStore({"srv": 2}),
    )
    assert result.passed


def test_server_policy_can_require_pin_coverage(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
servers:
  srv:
    require_pin: true
"""
    )
    result = evaluate_policy(
        _audit_report(_audit_with_shell_finding()),
        load_policy(policy_path),
        pin_store=_FakePinStore({}),
    )
    assert not result.passed
    assert result.violations[0].rule == "require.pins"


def test_policy_can_threshold_injection_separately(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  injection: medium
"""
    )
    audit = _audit_with_shell_finding()
    audit.permissions = []
    audit.injection_findings = [
        InjectionFinding(
            tool_name="prompt://review",
            severity=InjectionSeverity.MEDIUM,
            pattern_name="role_injection",
            matched_text="assistant:",
            description="fake role",
        )
    ]
    result = evaluate_policy(_audit_report(audit), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.injection"


def _audit_with_ssrf_finding(severity: SsrfSeverity = SsrfSeverity.HIGH) -> ServerAudit:
    audit = _audit_with_shell_finding()
    audit.permissions = []
    audit.ssrf_findings = [
        SsrfFinding(
            target_name="fetch_url",
            severity=severity,
            pattern_name="url_param_with_fetch_verb",
            evidence=["URL-shaped parameter 'url'"],
            description="SSRF-prone fetch capability.",
        )
    ]
    return audit


def test_policy_can_threshold_ssrf_separately(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  ssrf: high
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_ssrf_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.ssrf"


def test_broad_severity_does_not_gate_ssrf(tmp_path: Path) -> None:
    # SSRF is opt-in: the broad fail_on.severity shortcut must not gate it.
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  severity: low
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_ssrf_finding()), load_policy(policy_path))
    assert not any(v.rule == "fail_on.ssrf" for v in result.violations)


def test_ssrf_aware_example_policy_gates_high_ssrf(tmp_path: Path) -> None:
    result = evaluate_policy(
        _audit_report(_audit_with_ssrf_finding()),
        load_policy(Path("examples/policies/ssrf-aware-ci.yaml")),
    )
    assert not result.passed
    assert any(v.rule == "fail_on.ssrf" for v in result.violations)


def _audit_with_egress_finding(
    severity: EgressSeverity = EgressSeverity.MEDIUM,
    kind: EgressKind = EgressKind.DESTINATION_OUTSIDE_ALLOWLIST,
) -> ServerAudit:
    audit = _audit_with_shell_finding()
    audit.permissions = []
    audit.egress_findings = [
        EgressFinding(
            target_type=CapabilityTarget.RESOURCE,
            target_name="https://evil.example/x",
            severity=severity,
            kind=kind,
            destination_host="evil.example",
            evidence=["fixed destination host 'evil.example'"],
        )
    ]
    return audit


def test_policy_can_threshold_egress_separately(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  egress: medium
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_egress_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.egress"


def test_broad_severity_does_not_gate_egress(tmp_path: Path) -> None:
    # Egress is opt-in: the broad fail_on.severity shortcut must not gate it.
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  severity: low
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_egress_finding()), load_policy(policy_path))
    assert not any(v.rule == "fail_on.egress" for v in result.violations)


def test_egress_below_threshold_does_not_gate(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  egress: high
"""
    )
    # A MEDIUM egress finding is below the HIGH gate, so it must not fail the build.
    result = evaluate_policy(_audit_report(_audit_with_egress_finding()), load_policy(policy_path))
    assert result.passed


def test_keyless_policy_does_not_gate_egress(tmp_path: Path) -> None:
    # Backward compat: a policy without any egress keys still parses and never gates egress.
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  permissions: high
"""
    )
    policy = load_policy(policy_path)
    assert policy.fail_on_egress_severity is None
    assert policy.egress_allowlist == []
    assert policy.multi_tenant_hosts == []
    result = evaluate_policy(_audit_report(_audit_with_egress_finding()), policy)
    assert not any(v.rule == "fail_on.egress" for v in result.violations)


def test_policy_parses_egress_config_keys(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  egress: medium
egress_allowlist:
  - api.anthropic.com
multi_tenant_hosts:
  - storage.partner.example
servers:
  srv:
    fail_on:
      egress: low
    egress_allowlist:
      - logs.internal.example
"""
    )
    policy = load_policy(policy_path)
    assert policy.fail_on_egress_severity == "medium"
    assert policy.egress_allowlist == ["api.anthropic.com"]
    assert policy.multi_tenant_hosts == ["storage.partner.example"]
    assert policy.server_rules["srv"].fail_on_egress_severity == "low"
    assert policy.server_rules["srv"].egress_allowlist == ["logs.internal.example"]


def test_per_server_egress_threshold_override(tmp_path: Path) -> None:
    # Global gate is HIGH, but the per-server override lowers it to LOW for 'srv'.
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  egress: high
servers:
  srv:
    fail_on:
      egress: low
"""
    )
    audit = _audit_with_egress_finding(EgressSeverity.LOW, EgressKind.TRUSTED_DESTINATION_RESIDUAL)
    result = evaluate_policy(_audit_report(audit), load_policy(policy_path))
    assert not result.passed
    assert any(v.rule == "fail_on.egress" for v in result.violations)


def test_egress_example_policy_gates_medium_egress() -> None:
    result = evaluate_policy(
        _audit_report(_audit_with_egress_finding()),
        load_policy(Path("examples/policies/egress.yaml")),
    )
    assert not result.passed
    assert any(v.rule == "fail_on.egress" for v in result.violations)


def test_policy_can_threshold_capabilities_separately(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  capabilities: medium
"""
    )
    audit = _audit_with_shell_finding()
    audit.permissions = []
    audit.capability_findings = [
        CapabilityFinding(
            target_type=CapabilityTarget.RESOURCE,
            target_name="https://example.com/data.json",
            category=PermissionCategory.NETWORK,
            confidence=Confidence.HIGH,
            evidence=["resource host 'example.com'"],
        )
    ]
    result = evaluate_policy(_audit_report(audit), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.capabilities"


def test_policy_can_threshold_config_health_separately(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  config_health: medium
"""
    )
    report = _audit_report(_audit_with_shell_finding())
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="remote_endpoint",
            severity=ConfigHealthSeverity.MEDIUM,
            server_name="srv",
            summary="Server uses a remote MCP endpoint.",
            details=["https://api.example.com/mcp"],
            remediation="Review remote endpoint trust before CI approval.",
        )
    ]
    result = evaluate_policy(report, load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.config_health"
    assert result.violations[0].server_name == "srv"
    assert result.violations[0].severity == "medium"
    assert "remote_endpoint" in result.violations[0].message


def test_policy_does_not_apply_broad_severity_to_config_health(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
fail_on:
  severity: medium
"""
    )
    audit = _audit_with_shell_finding()
    audit.permissions = []
    report = _audit_report(audit)
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="shell_wrapper",
            severity=ConfigHealthSeverity.HIGH,
            server_name="srv",
            summary="Server command launches through a shell wrapper.",
            remediation="Review the wrapper and call the underlying command directly when possible.",
        )
    ]
    result = evaluate_policy(report, load_policy(policy_path))
    assert result.passed


def test_server_policy_can_threshold_config_health(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
servers:
  srv:
    fail_on:
      config_health: low
"""
    )
    report = _audit_report(_audit_with_shell_finding())
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type="credential_env_surface",
            severity=ConfigHealthSeverity.LOW,
            server_name="srv",
            summary="Server references credential-like environment variable names.",
            remediation="Confirm only environment variable names are stored in config.",
        )
    ]
    result = evaluate_policy(report, load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.config_health"
    assert result.violations[0].severity == "low"


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


def test_policy_fails_for_unlisted_server_when_allow_servers_set(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
allow_servers:
  - approved
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "allow_servers"


def test_server_policy_can_set_stricter_max_risk(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
max_risk: 9
servers:
  srv:
    max_risk: 7
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "max_risk"


def test_server_policy_can_deny_specific_permissions(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
servers:
  srv:
    deny:
      permissions:
        - shell_execution
"""
    )
    result = evaluate_policy(_audit_report(_audit_with_shell_finding()), load_policy(policy_path))
    assert not result.passed
    assert result.violations[0].rule == "deny.permissions"


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
            None,  # sarif_output
            None,  # html_output
            True,  # skip_connect
            None,  # clients
            10,  # timeout
            False,  # verbose
            None,  # extra_config
            None,  # override_config_path
            str(policy_path),
        )

    assert exc.value.code == 2
    assert json_path.exists()
    assert '"policy_result"' in json_path.read_text()
