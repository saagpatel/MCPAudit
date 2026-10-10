"""Synthetic summary acceptance: widths, grades, reach and safe presentation."""

from __future__ import annotations

import io
import json
import re
import shlex
import sys
from functools import partial
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_audit.cli import main
from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import (
    AuditReport,
    CanarySummary,
    CheckCoverage,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    ConnectionMode,
    InjectionFinding,
    InjectionSeverity,
    ScanWarning,
)
from mcp_audit.report import ReportGenerator
from mcp_audit.taxonomy import config_health_rule_id, finding_copy
from mcp_audit.terminal_summary import _recheck, findings, what_happened
from tests.test_report import _base_report, _make_audit

FIXTURE = Path("examples/sandbox/fixtures/synthetic-mcp-config.json")
GOLDENS = Path(__file__).parent / "fixtures" / "terminal"


@pytest.fixture
def synthetic_report() -> AuditReport:
    return anyio.run(
        partial(
            run_scan,
            ScanOptions(
                skip_connect=True,
                config_only=True,
                extra_config=str(FIXTURE),
            ),
        )
    )


def _render(
    report: AuditReport, width: int = 80, *, details: bool = False, explicit_config: bool = False
) -> str:
    buf = io.StringIO()
    ReportGenerator(Console(file=buf, width=width, force_terminal=False)).render_terminal(
        report,
        details=details,
        explicit_config=explicit_config,
    )
    return "\n".join(line.rstrip() for line in buf.getvalue().splitlines()) + "\n"


def _connected() -> AuditReport:
    report = _base_report([_make_audit("synthetic-server", risk=9.8)])
    report.audits[0].server.config_path = "synthetic.json"
    report.coverage = {
        key: CheckCoverage(state="complete", reason="fixture execution completed")
        for key in ("config_health", "metadata", "permissions", "capabilities", *OPTIONAL_CHECKS)
    }
    for key in OPTIONAL_CHECKS:
        report.coverage[key] = CheckCoverage(state="not_requested", reason="check not requested")
    return report


def _finding(
    severity: ConfigHealthSeverity = ConfigHealthSeverity.MEDIUM, kind: str = "package_runner_source_review"
) -> ConfigHealthFinding:
    return ConfigHealthFinding(
        finding_type=kind,
        severity=severity,
        server_name="synthetic-server",
        summary="Review this launch.",
        remediation="Pin a reviewed version.",
        config_paths=["synthetic.json"],
    )


@pytest.mark.parametrize("width", [60, 80, 120])
def test_synthetic_summary_golden(synthetic_report: AuditReport, width: int) -> None:
    output = _render(synthetic_report, width, explicit_config=True)
    assert output == (GOLDENS / f"summary-{width}.txt").read_text()
    assert max(len(line) for line in output.splitlines()) <= width
    assert output.startswith("MCPAudit · Preview")
    assert "CONFIG REVIEW ONLY |" not in output
    assert "reach and hygiene, not a safety certificate" in output
    assert len(re.findall(r"^\d\. [▲◆●]", output, re.MULTILINE)) == 3
    assert "7 config warnings" in " ".join(output.split())
    assert "Source:" in output and "Manual step:" in output and "Recheck:" in output
    assert "┏" not in output
    assert "Tools were not fully inspected" in " ".join(output.split())
    assert "Runtime security: NOT CHECKED" in output


def test_legacy_tables_available_only_with_details(synthetic_report: AuditReport) -> None:
    assert "Top Permissions" not in _render(synthetic_report, 120)
    detailed = _render(synthetic_report, 120, details=True)
    assert "Top Permissions" in detailed
    assert "Capability exposure" in detailed
    normalized = " ".join(detailed.split())
    for finding in synthetic_report.config_health_findings:
        assert " ".join(finding.summary.split()) in normalized
        assert " ".join(finding.remediation.split()) in normalized


@pytest.mark.parametrize(
    "severities, expected",
    [
        ([], "A"),
        ([ConfigHealthSeverity.LOW], "A"),
        ([ConfigHealthSeverity.MEDIUM], "B"),
        ([ConfigHealthSeverity.HIGH], "C"),
        ([ConfigHealthSeverity.HIGH, ConfigHealthSeverity.HIGH], "D"),
    ],
)
def test_grade_uses_finding_classes_not_numeric_score(
    severities: list[ConfigHealthSeverity], expected: str
) -> None:
    report = _connected()
    report.config_health_findings = [
        _finding(severity, f"synthetic-{i}") for i, severity in enumerate(severities)
    ]
    assert report.ux_summary.grade == expected
    assert report.audits[0].risk_score is not None
    assert report.audits[0].risk_score.composite == 9.8
    assert json.loads(report.model_dump_json())["ux_summary"]["grade"] == expected
    report = report.model_copy(update={"connection_mode": ConnectionMode.SKIPPED, "review_summary": None})
    assert report.ux_summary.grade is None


def test_shell_launch_is_f_and_has_plain_manual_action() -> None:
    report = _connected()
    report.config_health_findings = [_finding(kind="shell_wrapper_launch")]
    assert report.ux_summary.grade == "F"
    output = " ".join(_render(report).split())
    copy = finding_copy(config_health_rule_id("shell_wrapper_launch"))
    assert copy.title in output and copy.how_to_fix in output
    assert "direct executable and argument list" in output
    assert "restart the client" in output
    assert "tidy" not in output and "confetti" not in output


def test_hidden_text_grade_and_connected_recheck_preserve_check() -> None:
    report = _connected()
    report.coverage["inject_check"] = CheckCoverage(state="complete", reason="fixture text inspected")
    report.audits[0].injection_findings = [
        InjectionFinding(
            tool_name="synthetic-tool",
            severity=InjectionSeverity.MEDIUM,
            pattern_name="hidden_directive",
            matched_text="synthetic hidden text",
            description="Hidden text in the tool metadata.",
        )
    ]
    assert report.ux_summary.grade == "F"
    output = " ".join(_render(report, explicit_config=True).split())
    assert "--inject-check" in output
    assert "./reviewed-mcp-config.json" in output
    assert "Copy only the listed entries" in output
    assert "may execute code and access the network" in output
    assert "claude_code" not in output
    assert "client not asserted" in output


def test_credential_keys_are_not_treated_as_a_confirmed_config_secret() -> None:
    report = _connected()
    report.config_health_findings = [_finding(kind="credential_heavy_config")]
    assert report.ux_summary.grade == "B"


def test_generated_connected_recheck_runs_only_the_reviewed_local_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp_audit import engine

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("recheck must not discover workstation configurations")

    monkeypatch.setattr(engine, "discover_all_configs", forbidden)
    fixture = Path(__file__).parent / "fixtures" / "mock_server.py"
    config = tmp_path / "reviewed-mcp-config.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "synthetic-server": {
                        "command": sys.executable,
                        "args": ["-I", str(fixture)],
                    }
                }
            }
        )
    )
    report = _connected()
    report.audits[0].injection_findings = [
        InjectionFinding(
            tool_name="synthetic-tool",
            severity=InjectionSeverity.MEDIUM,
            pattern_name="hidden_directive",
            matched_text="synthetic hidden text",
            description="Hidden text in the tool metadata.",
        )
    ]
    command = _recheck(findings(report)[0])
    args = shlex.split(command.replace("\\\n", ""))[1:]
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "rechecked.json"
    result = CliRunner().invoke(main, [*args, "--json", str(output)])
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text())
    assert payload["servers_discovered"] == payload["servers_connected"] == 1
    assert payload["coverage"]["inject_check"]["state"] == "complete"


@pytest.mark.parametrize("state", ["partial", "not_run"])
def test_reduced_requested_coverage_cannot_earn_a(state: str) -> None:
    report = _connected()
    report.coverage["inject_check"] = CheckCoverage.model_validate(
        {"state": state, "reason": "fixture unavailable"}
    )
    assert report.ux_summary.grade is None
    assert "Looks fine" not in _render(report)


def test_empty_legacy_and_sparse_coverage_do_not_claim_checked() -> None:
    report = _base_report([])
    output = _render(report)
    assert output.startswith("No MCP servers found.")
    assert "Grade" not in output and "Checked:" not in output
    report = _connected()
    report.coverage = {"config_health": report.coverage["config_health"]}
    output = _render(report)
    assert "UNKNOWN (not recorded)" in " ".join(output.split())
    assert "Preview" in output and "Looks fine" not in output


def test_action_cap_never_hides_totals_and_groups_related_findings() -> None:
    report = _connected()
    report.config_health_findings = [_finding(ConfigHealthSeverity.HIGH, f"synthetic-{i}") for i in range(6)]
    output = _render(report)
    assert "Totals: 6 findings (6 Fix now" in output
    assert len(re.findall(r"^\d\. ▲ Fix now", output, re.MULTILINE)) == 1
    assert "+5 related findings" in output
    report = report.model_copy(update={"review_summary": None}, deep=True)
    report.audits = [_make_audit(f"server-{i}") for i in range(6)]
    for i, (audit, finding) in enumerate(zip(report.audits, report.config_health_findings, strict=True)):
        audit.server.config_path = f"synthetic-{i}.json"
        finding.server_name = audit.server.name
        finding.config_paths = [audit.server.config_path]
    output = _render(report)
    assert "Totals: 6 findings (6 Fix now" in output
    assert len(re.findall(r"^\d\. ▲ Fix now", output, re.MULTILINE)) == 3


@pytest.mark.parametrize("width", [60, 80, 120])
@pytest.mark.parametrize("explicit_config", [False, True])
def test_warnings_reduce_coverage_without_turning_empty_findings_into_a_pass(
    width: int, explicit_config: bool
) -> None:
    report = _connected()
    report.coverage["permissions"] = CheckCoverage(state="partial", reason="schema incomplete")
    report.warnings = [
        ScanWarning(code="permission_schema_incomplete", message="Schema not fully inspected.")
    ]
    output = _render(report, width, explicit_config=explicit_config)
    flat = " ".join(output.split())
    assert "Restore check coverage" in flat and "1 scan warnings" in flat
    assert "Looks fine" not in flat
    identity = "client not asserted" if explicit_config else "claude_code"
    assert f"synthetic-server / {identity} (workstation)" in flat
    if explicit_config:
        assert "claude_code" not in output
        assert "explicit file; parsed as Claude-style config" in flat


def test_execution_disclosure_connected_and_canary() -> None:
    report = _connected()
    report.audits[0].canary = CanarySummary(requested_calls=3, completed_calls=2, status="partial")
    report.coverage["runtime_security"] = CheckCoverage(state="partial", reason="call budget incomplete")
    report.coverage["llm_analysis"] = CheckCoverage(state="not_run", reason="fixture unavailable")
    text = what_happened(report)
    assert "Attempted MCP connections to synthetic-server" in text
    assert "canary tool calls: 2" in text and "LLM analysis: not run" in text
    assert "started no servers" not in text


def test_terminal_and_json_scrub_hostile_finding_text() -> None:
    report = _connected()
    finding = _finding(kind="synthetic-review")
    finding.summary = "[bold]literal[/bold] token=synthetic-secret-value\x1b[31m"
    report.config_health_findings = [finding]
    output = _render(report)
    assert "[bold]literal[/bold]" in output
    assert "synthetic-secret-value" not in output and "\x1b" not in output
    assert "synthetic-secret-value" not in report.redacted().model_dump_json()


@pytest.mark.parametrize(
    "color, env, ansi",
    [
        ("auto", {}, False),
        ("never", {}, False),
        ("always", {}, True),
        ("always", {"NO_COLOR": "1"}, False),
    ],
)
def test_color_and_non_tty(
    color: str, env: dict[str, str], ansi: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    result = CliRunner().invoke(main, ["check", "--config", str(FIXTURE), "--color", color], env=env)
    assert result.exit_code == 0, result.output
    assert ("\x1b[" in result.stdout) is ansi
    assert "Worth a look" in result.stdout


def test_scan_details_and_json_stdout_are_compatible() -> None:
    args = [
        "scan",
        "--config",
        str(FIXTURE),
        "--config-only",
        "--skip-connect",
        "--override-config",
        "/dev/null",
    ]
    summary = CliRunner().invoke(main, args)
    detailed = CliRunner().invoke(main, [*args, "--details"])
    assert summary.exit_code == detailed.exit_code == 0
    assert summary.output.startswith("MCPAudit · Preview")
    assert "Top Permissions" not in summary.output
    assert "Top" in detailed.output and "Permissions" in detailed.output
    result = CliRunner().invoke(main, ["check", "--config", str(FIXTURE), "--json", "--color", "always"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["schema_version"] == 1 and data["ux_summary"]["grade"] is None
    assert "\x1b" not in result.stdout


def test_grade_requires_core_coverage_and_connected_audits() -> None:
    sparse = _connected()
    sparse.coverage = {"metadata": CheckCoverage(state="complete", reason="fixture execution completed")}
    assert sparse.ux_summary.grade is None
    failed = _connected()
    failed.audits[0].connection_status = "failed"
    assert failed.ux_summary.grade is None


def test_fleet_chain_with_shell_grades_d() -> None:
    from mcp_audit.models import PermissionCategory, TrifectaSeverity
    from tests.test_trifecta_integration import _pf, _trifecta_finding

    report = _connected()
    report.audits[0].permissions = [_pf(PermissionCategory.SHELL_EXEC, "run")]
    report.fleet_trifecta_findings = [_trifecta_finding(TrifectaSeverity.MEDIUM, is_fleet=True)]
    assert report.ux_summary.grade == "D"
    assert json.loads(report.model_dump_json())["ux_summary"]["grade"] == "D"
