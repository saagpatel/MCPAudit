"""Tests for local policy gate evaluation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_audit import _core_cli as core_cli
from mcp_audit import cli, scan_cli
from mcp_audit.models import (
    ArtifactVerifyFinding,
    ArtifactVerifyKind,
    ArtifactVerifySeverity,
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
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    InjectionFinding,
    InjectionSeverity,
    IntegrityFinding,
    IntegrityKind,
    IntegritySeverity,
    PackageVerifyFinding,
    PackageVerifyKind,
    PackageVerifySeverity,
    PermissionCategory,
    PermissionFinding,
    ProvenanceFinding,
    ProvenanceKind,
    ProvenanceSeverity,
    RiskScore,
    ServerAudit,
    ShadowingFinding,
    ShadowingKind,
    ShadowingSeverity,
    SsrfFinding,
    SsrfSeverity,
    TrifectaFinding,
    TrifectaSeverity,
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


def _policy_gate_report() -> AuditReport:
    audit = _audit_with_shell_finding()
    audit.permissions = [
        PermissionFinding(
            category=PermissionCategory.SHELL_EXEC,
            confidence=Confidence.HIGH,
            evidence=["execute command"],
            tool_name="run_shell",
        )
    ]
    audit.escalation_findings = [
        EscalationFinding(
            kind=EscalationKind.CAPABILITY,
            severity=EscalationSeverity.HIGH,
            server_name="srv",
            tool_name="run_shell",
            description="Capability was added.",
        )
    ]
    audit.provenance_findings = [
        ProvenanceFinding(
            kind=ProvenanceKind.COMMAND,
            severity=ProvenanceSeverity.HIGH,
            server_name="srv",
            summary="Launch command changed.",
            baseline="python",
            current="python3",
        )
    ]
    audit.integrity_findings = [
        IntegrityFinding(
            kind=IntegrityKind.ARTIFACT_DRIFT,
            severity=IntegritySeverity.HIGH,
            server_name="srv",
            artifact_path="/synthetic/server",
            baseline_hash="before",
            current_hash="after",
            summary="Artifact bytes changed.",
        )
    ]
    audit.package_verify_findings = [
        PackageVerifyFinding(
            kind=PackageVerifyKind.REGISTRY_DRIFT,
            severity=PackageVerifySeverity.HIGH,
            server_name="srv",
            ecosystem="npm",
            package="synthetic-package",
            version="1.0.0",
            baseline_hash="before",
            current_hash="after",
            summary="Registry hash changed.",
        )
    ]
    audit.artifact_verify_findings = [
        ArtifactVerifyFinding(
            kind=ArtifactVerifyKind.BASELINE_MISMATCH,
            severity=ArtifactVerifySeverity.HIGH,
            server_name="srv",
            ecosystem="npm",
            package="synthetic-package",
            version="1.0.0",
            baseline_hash="before",
            current_hash="after",
            summary="Artifact bytes differ from baseline.",
        )
    ]
    audit.trifecta_findings = [
        TrifectaFinding(
            severity=TrifectaSeverity.HIGH,
            leg1_contributors=[("srv", "read_file")],
            leg2_contributors=[("srv", "fetch_url")],
            leg3_contributors=[("srv", "send_data")],
            description="Synthetic trifecta finding.",
        )
    ]
    audit.drift_findings = [
        DriftFinding(server_name="srv", tool_name="run_shell", status=DriftStatus.CHANGED),
        DriftFinding(
            server_name="srv",
            tool_name="run_shell",
            status=DriftStatus.CHANGED,
            source="session",
            severity="high",
        ),
    ]
    report = _audit_report(audit)
    report.shadowing_findings = [
        ShadowingFinding(
            kind=ShadowingKind.EXACT,
            severity=ShadowingSeverity.HIGH,
            name="search",
            collisions=[("srv", "search"), ("other", "search")],
            description="Synthetic shadowing finding.",
        )
    ]
    return report


@pytest.mark.parametrize(
    ("policy_yaml", "rule"),
    [
        ("fail_on:\n  escalation: true\n", "fail_on.escalation"),
        ("fail_on:\n  provenance: true\n", "fail_on.provenance"),
        ("fail_on:\n  integrity: true\n", "fail_on.integrity"),
        ("fail_on:\n  package_verify: true\n", "fail_on.package_verify"),
        ("fail_on:\n  artifact_verify: true\n", "fail_on.artifact_verify"),
        ("fail_on:\n  severity: high\n", "fail_on.severity"),
        ("fail_on:\n  trifecta: true\n", "fail_on.trifecta"),
        ("fail_on:\n  shadowing: true\n", "fail_on.shadowing"),
        ("fail_on:\n  drift: true\n", "fail_on.drift"),
    ],
)
def test_opt_in_gates_fail_only_when_enabled(tmp_path: Path, policy_yaml: str, rule: str) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_yaml)
    enabled = evaluate_policy(_policy_gate_report(), load_policy(policy_path))
    assert enabled.passed is False
    assert {violation.rule for violation in enabled.violations} == {rule}

    key = policy_yaml.splitlines()[1].strip().split(":", maxsplit=1)[0]
    disabled_value = "null" if key == "severity" else "false"
    policy_path.write_text(f"fail_on:\n  {key}: {disabled_value}\n")
    disabled = evaluate_policy(_policy_gate_report(), load_policy(policy_path))
    assert disabled.passed is True

    policy_path.write_text("{}\n")
    empty = evaluate_policy(_policy_gate_report(), load_policy(policy_path))
    assert empty.passed is True


def test_policy_file_gate_defaults_are_disabled(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("fail_on: {}\n")
    policy = load_policy(policy_path)

    assert policy.fail_on_severity is None
    assert policy.fail_on_permission_severity is None
    assert policy.fail_on_injection_severity is None
    assert policy.fail_on_ssrf_severity is None
    assert policy.fail_on_egress_severity is None
    assert policy.fail_on_capability_severity is None
    assert policy.fail_on_config_health_severity is None
    assert policy.fail_on_drift is False
    assert policy.fail_on_trifecta is False
    assert policy.fail_on_shadowing is False
    assert policy.fail_on_escalation is False
    assert policy.fail_on_provenance is False
    assert policy.fail_on_integrity is False
    assert policy.fail_on_package_verify is False
    assert policy.fail_on_artifact_verify is False


def test_max_risk_equal_to_score_fails(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("max_risk: 8.0\n")
    result = evaluate_policy(_policy_gate_report(), load_policy(policy_path))

    assert result.passed is False
    assert [violation.rule for violation in result.violations] == ["max_risk"]


def test_broad_severity_gates_session_drift_but_not_pin_drift(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("fail_on:\n  severity: high\n")
    report = _policy_gate_report()
    report.audits[0].permissions = []
    report.audits[0].drift_findings = [
        finding for finding in report.audits[0].drift_findings if finding.source == "pin"
    ]
    pin_result = evaluate_policy(report, load_policy(policy_path))
    assert pin_result.passed is True

    report.audits[0].drift_findings = [
        finding.model_copy(update={"source": "session", "severity": "high"})
        for finding in report.audits[0].drift_findings
    ]
    session_result = evaluate_policy(report, load_policy(policy_path))
    assert session_result.passed is False
    assert {violation.rule for violation in session_result.violations} == {"fail_on.severity"}


@pytest.mark.parametrize(
    ("policy_yaml", "message"),
    [
        ("[]\n", "Policy file must contain a YAML mapping."),
        ("max_risk: 11\n", "max_risk must be between 0 and 10."),
        ("deny:\n  permissions: shell\n", "deny.permissions must be a YAML list."),
        (
            "fail_on:\n  severity: critical\n",
            "Unknown policy severity 'critical'. Valid values: low, medium, high.",
        ),
    ],
)
def test_invalid_policy_files_raise_documented_errors(tmp_path: Path, policy_yaml: str, message: str) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_yaml)

    with pytest.raises(ValueError, match=message.replace(".", r"\.")):
        load_policy(policy_path)


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


def test_scan_threads_per_server_egress_allowlist_from_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``_run_scan`` derives the per-server egress allowlist map from ``policy.server_rules``
    and threads it into the engine's ``run_scan`` options. Regression guard for the map-building
    half of the wiring; the apply half (map → detector) is covered in test_egress_integration."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
egress_allowlist:
  - api.anthropic.com
servers:
  trusted:
    egress_allowlist:
      - logs.internal.example
  no_egress_rule:
    fail_on:
      egress: low
"""
    )
    captured: dict[str, object] = {}

    async def fake_run_scan(*args: object, **kwargs: object) -> AuditReport:
        captured["options"] = args[0]
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="h",
            os_platform="t",
            servers_discovered=0,
            servers_connected=0,
            servers_failed=0,
            total_tools=0,
            high_risk_servers=0,
            audits=[],
            scan_duration_seconds=0.0,
        )

    monkeypatch.setattr(scan_cli, "run_scan", fake_run_scan)
    monkeypatch.setattr(core_cli, "discover_all_configs", lambda clients, parse_errors=None: [])

    anyio.run(
        cli._run_scan,
        None,  # json_output
        None,  # sarif_output
        None,  # html_output
        True,  # skip_connect
        None,  # clients
        10,  # timeout
        False,  # verbose
        None,  # extra_config
        None,  # override_config_path
        str(policy_path),  # policy_path
    )

    # Only servers with a non-empty per-server egress_allowlist appear in the map.
    options = captured["options"]
    assert options.egress_server_allowlists == {"trusted": ["logs.internal.example"]}  # type: ignore[attr-defined]


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

    async def fake_run_scan(*args: object, **kwargs: object) -> AuditReport:
        return _audit_report(audit)

    monkeypatch.setattr(scan_cli, "run_scan", fake_run_scan)

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
