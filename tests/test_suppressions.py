"""Fixture-backed suppression and policy contracts; no workstation discovery."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mcp_audit import check_cli, scan_cli
from mcp_audit.cli import main
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, CheckCoverage, InjectionFinding, InjectionSeverity
from mcp_audit.overrides import OverrideApplier, OverrideConfig, load_override_config
from mcp_audit.policy import PolicyConfig, evaluate_policy, load_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.suppressions import IgnoreEntry, apply_suppressions

REPORTS = Path(__file__).parent / "fixtures/reports"
SYNTHETIC = Path(__file__).resolve().parents[1] / "examples/sandbox/fixtures/synthetic-mcp-config.json"


def _shadow_report() -> AuditReport:
    return AuditReport.model_validate_json((REPORTS / "shadowing_report.json").read_text())


def _entry(**updates: object) -> IgnoreEntry:
    return IgnoreEntry.model_validate(
        {"rule": "MCP015", "server": "*", "tool": "*", "reason": "Reviewed intentional collision", **updates}
    )


def test_saved_shadow_ignore_retains_evidence_and_does_not_gate(tmp_path: Path) -> None:
    config = tmp_path / "ignores.yaml"
    config.write_text(
        "ignore:\n  - rule: MCP015\n    server: '*'\n    tool: '*'\n"
        "    reason: Reviewed intentional collision\n"
    )
    report = _shadow_report()
    original = report.model_dump(mode="json")
    assert not evaluate_policy(report, PolicyConfig(fail_on_shadowing=True)).passed
    OverrideApplier(load_override_config(config)).suppress(report)
    result = evaluate_policy(report, PolicyConfig(fail_on_shadowing=True))
    assert result.passed
    dumped = report.model_dump(mode="json")
    assert dumped["schema_version"] == original["schema_version"]
    assert dumped["shadowing_findings"] == original["shadowing_findings"]
    assert dumped["audits"] == original["audits"]
    assert dumped["suppressed"] == [
        {
            "finding_path": "/shadowing_findings/0",
            "rule_id": "MCP015",
            "reason": "Reviewed intentional collision",
            "source": "config",
            "expires": None,
        }
    ]
    assert AuditReport.model_validate_json(report.model_dump_json()).suppressed == report.suppressed
    for details in (None, False, True):
        text = ReportGenerator().capture_terminal(report, details=details)
        assert "Suppressed: 1" in text
        assert "Reviewed intentional collision" in text
        assert "MCP015" in text


def test_policy_refuses_suppressions_and_still_gates_original(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("allow_ignores: false\nfail_on:\n  shadowing: true\n")
    report = _shadow_report()
    apply_suppressions(report, [_entry()])
    result = evaluate_policy(report, load_policy(policy_path))
    assert not result.passed
    assert {v.rule for v in result.violations} == {"allow_ignores", "fail_on.shadowing"}
    assert not evaluate_policy(report, PolicyConfig(allow_ignores=False)).passed
    policy_path.write_text("allow_ignores: 'false'\n")
    with pytest.raises(ValueError, match="allow_ignores"):
        load_policy(policy_path)


def test_ignore_never_hides_coverage_or_warnings() -> None:
    report = _shadow_report()
    report.coverage = {"metadata": CheckCoverage(state="partial", reason="fixture listing incomplete")}
    before = report.coverage.copy()
    apply_suppressions(report, [_entry()])
    result = evaluate_policy(report, PolicyConfig(fail_on_coverage=True, fail_on_shadowing=True))
    assert not result.passed
    assert all(v.rule == "fail_on.coverage" for v in result.violations)
    assert report.coverage == before
    for rule in ("coverage", "fail_on.coverage", "MCP010", "MCP999"):
        with pytest.raises(ValueError):
            apply_suppressions(report, cli_rules=[rule])


@pytest.mark.parametrize("reason", [None, "", "   "])
def test_cli_high_requires_explicit_reason(reason: str | None) -> None:
    report = _shadow_report()
    apply_suppressions(report, cli_rules=["MCP015"], cli_reason=reason)
    assert not report.suppressed
    assert evaluate_policy(report, PolicyConfig(fail_on_shadowing=True)).passed is False
    assert report.warnings[-1].code == "ignore_reason_required"


def test_cli_high_with_reason_and_duplicate_requests() -> None:
    report = _shadow_report()
    apply_suppressions(report, cli_rules=["MCP015", "MCP015"], cli_reason="Reviewed for this run")
    apply_suppressions(report, [_entry()])
    assert len(report.suppressed) == 1
    assert report.suppressed[0].source == "cli"
    assert report.suppressed[0].reason == "Reviewed for this run"
    assert evaluate_policy(report, PolicyConfig(fail_on_shadowing=True)).passed


@pytest.mark.parametrize(
    "changes",
    [
        {"reason": ""},
        {"reason": "  "},
        {"reason": None},
        {"reason": 2},
        {"server": ""},
        {"tool": ""},
        {"expires": "tomorrow"},
        {"expires": 1},
        {"unexpected": True},
    ],
)
def test_invalid_saved_ignores_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _entry(**changes)


def test_saved_ignore_requires_reason(tmp_path: Path) -> None:
    path = tmp_path / "ignore.yaml"
    path.write_text("ignore:\n  - rule: MCP015\n    server: '*'\n    tool: '*'\n")
    with pytest.raises(ValidationError):
        load_override_config(path)


@pytest.mark.parametrize("offset,expected", [(-1, 0), (0, 1), (1, 1)])
def test_expiration_uses_scan_date(offset: int, expected: int) -> None:
    report = _shadow_report()
    expires = report.scan_timestamp.date() + timedelta(days=offset)
    apply_suppressions(report, [_entry(expires=expires)])
    assert len(report.suppressed) == expected
    assert evaluate_policy(report, PolicyConfig(fail_on_shadowing=True)).passed == bool(expected)


def test_fleet_server_and_tool_must_match_same_contributor() -> None:
    report = _shadow_report()
    finding = report.shadowing_findings[0]
    finding.collisions = [("one", "alpha"), ("two", "beta")]
    apply_suppressions(report, [_entry(server="one", tool="beta")])
    assert not report.suppressed
    apply_suppressions(report, [_entry(server="two", tool="beta")])
    assert len(report.suppressed) == 1


@pytest.mark.parametrize("target_name", [None, "", "search-prompt"])
def test_exact_injection_ignore_uses_target_name_or_tool_name(target_name: str | None) -> None:
    report = _shadow_report()
    audit = report.audits[0]
    finding = InjectionFinding(
        tool_name="search",
        severity=InjectionSeverity.HIGH,
        pattern_name="ignore_instructions",
        matched_text="Ignore previous instructions",
        description="Synthetic injection finding",
    )
    assert finding.target_name is None
    if target_name is not None:
        finding.target_name = target_name
    audit.injection_findings = [finding]
    original = audit.model_dump(mode="json")
    policy = PolicyConfig(fail_on_injection_severity="high")
    assert not evaluate_policy(report, policy).passed

    wrong_tool = "search" if target_name else "other"
    apply_suppressions(report, [_entry(rule=finding.rule_id, server=audit.server.name, tool=wrong_tool)])
    assert not report.suppressed
    assert not evaluate_policy(report, policy).passed

    apply_suppressions(
        report, [_entry(rule=finding.rule_id, server=audit.server.name, tool=target_name or "search")]
    )
    assert len(report.suppressed) == 1
    assert report.suppressed[0].finding_path == "/audits/0/injection_findings/0"
    assert report.suppressed[0].rule_id == finding.rule_id
    assert evaluate_policy(report, policy).passed
    assert audit.model_dump(mode="json") == original


def test_ignore_reason_redacts_before_truncation() -> None:
    report = _shadow_report()
    apply_suppressions(report, [_entry(reason="Reviewed token=" + "SYNTHETIC_VALUE" * 100)])
    reason = report.suppressed[0].reason
    assert "SYNTHETIC_VALUE" not in reason
    assert len(reason) <= 512


@pytest.mark.parametrize("command", ["scan", "check"])
def test_cli_synthetic_permission_ignore(command: str, tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    args = [command, "--config", str(SYNTHETIC), "--override-config", "/dev/null", "--ignore", "MCP001"]
    args += (
        ["--config-only", "--skip-connect", "--json", str(output)]
        if command == "scan"
        else ["--output-json", str(output)]
    )
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(output.read_text())
    assert report.suppressed
    assert all(s.rule_id == "MCP001" and s.source == "cli" for s in report.suppressed)
    assert "Suppressed:" in result.output
    assert report.connection_mode == "skipped"


@pytest.mark.parametrize("command", ["scan", "check"])
def test_invalid_ignore_fails_before_scan(command: str, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main, [command, "--config", str(tmp_path / "absent.json"), "--ignore", "coverage"]
    )
    assert result.exit_code != 0
    assert "absent.json" not in result.output


@pytest.mark.anyio
async def test_engine_applies_saved_ignores_to_fixture() -> None:
    report = await run_scan(
        ScanOptions(extra_config=str(SYNTHETIC), config_only=True, skip_connect=True),
        override_applier=OverrideApplier(OverrideConfig(ignore=[_entry(rule="MCP001")])),
    )
    assert report.suppressed
    assert report.suppressed[0].source == "config"


def test_legacy_json_defaults_to_no_suppressions() -> None:
    raw = json.loads((REPORTS / "shadowing_report.json").read_text())
    assert "suppressed" not in raw
    assert AuditReport.model_validate(raw).suppressed == []


@pytest.mark.parametrize("command", ["scan", "check"])
@pytest.mark.parametrize(
    "reason,allow,exit_code",
    [(None, True, 2), ("Reviewed collision", True, 0), ("Reviewed collision", False, 2)],
)
def test_cli_shadow_policy_contract(
    command: str,
    reason: str | None,
    allow: bool,
    exit_code: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fixture_scan(*args: object, **kwargs: object) -> AuditReport:
        return _shadow_report()

    monkeypatch.setattr(scan_cli if command == "scan" else check_cli, "run_scan", fixture_scan)
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"allow_ignores: {str(allow).lower()}\nfail_on:\n  shadowing: true\n")
    output = tmp_path / "report.json"
    args = [
        command,
        "--config",
        str(SYNTHETIC),
        "--override-config",
        "/dev/null",
        "--policy",
        str(policy),
        "--ignore",
        "MCP015",
    ]
    args += (
        ["--config-only", "--skip-connect", "--json", str(output)]
        if command == "scan"
        else ["--output-json", str(output)]
    )
    if reason is not None:
        args += ["--ignore-reason", reason]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == exit_code, result.output
    report = AuditReport.model_validate_json(output.read_text())
    assert report.shadowing_findings
    assert bool(report.suppressed) == (reason is not None)
    assert report.policy_result is not None
    assert report.policy_result.passed == (exit_code == 0)
    if reason:
        assert report.suppressed[0].reason == reason
        assert "Suppressed: 1" in result.output


def test_suppressed_permission_does_not_change_risk_gate() -> None:
    report = AuditReport.model_validate_json((REPORTS / "sample_audit_report.json").read_text())
    audit = report.audits[0]
    permission = audit.permissions[0]
    apply_suppressions(
        report, [_entry(rule=permission.rule_id, server=audit.server.name, tool=permission.tool_name)]
    )
    assert report.suppressed
    assert audit.risk_score is not None
    result = evaluate_policy(report, PolicyConfig(max_risk=audit.risk_score.composite))
    assert not result.passed
    assert any(v.rule == "max_risk" for v in result.violations)


@pytest.mark.parametrize("command", ["scan", "check"])
def test_cli_loads_explicit_saved_ignores(command: str, tmp_path: Path) -> None:
    ignore_path = tmp_path / "ignores.yaml"
    ignore_path.write_text(
        "ignore:\n  - rule: MCP001\n    server: '*'\n    tool: '*'\n    reason: Reviewed fixture access\n"
    )
    output = tmp_path / "report.json"
    args = [command, "--config", str(SYNTHETIC), "--override-config", str(ignore_path)]
    args += (
        ["--config-only", "--skip-connect", "--json", str(output)]
        if command == "scan"
        else ["--output-json", str(output)]
    )
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(output.read_text())
    assert report.suppressed
    assert all(s.source == "config" and s.reason == "Reviewed fixture access" for s in report.suppressed)
