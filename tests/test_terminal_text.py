"""Untrusted terminal/HTML fields stay literal and control-free."""

from __future__ import annotations

import io
import json
import logging
import re
import time
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_audit import _core_cli as core_cli
from mcp_audit import pin_cli, watcher
from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    ArtifactVerifyFinding,
    AuditReport,
    EgressFinding,
    EscalationFinding,
    InjectionFinding,
    IntegrityFinding,
    PackageVerifyFinding,
    PolicyResult,
    ProvenanceFinding,
    ScanWarning,
    ServerAudit,
    ServerConfig,
    ShadowingFinding,
    SsrfFinding,
    TrifectaFinding,
)
from mcp_audit.report import ReportGenerator
from mcp_audit.terminal_text import TerminalSafeLogFilter, strip_controls, terminal_safe
from tests.test_htmlreport import _report_with_findings

PAYLOADS = [
    "\x1b]8;;http://evil.example\x1b\\click\x1b]8;;\x1b\\",
    "\x1b[2J",
    "\x1b]0;pwned\x07",
    "\x9b31m",
    "[/bold]",
    "[link=http://evil.example]x[/link]",
    "[red]",
]
_FORBIDDEN = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_SGR = re.compile(r"\x1b\[[0-9;]*m")


def _console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, force_terminal=True, width=600, highlight=False), buffer


def _hostile_report(payload: str) -> AuditReport:
    report = AuditReport.model_validate_json(
        Path("tests/fixtures/reports/sample_audit_report.json").read_text()
    )
    audit = report.audits[0]
    audit.server.name = payload
    audit.server.config_path = payload
    audit.connection_error = payload
    audit.tools[0].name = payload
    audit.tools[0].description = payload
    audit.permissions[0].tool_name = payload
    audit.permissions[0].evidence = [payload]
    audit.prompts[0].name = payload
    audit.prompts[0].description = payload
    audit.resources[0].name = payload
    audit.resources[0].uri = payload
    audit.resources[0].description = payload
    audit.capability_findings[0].target_name = payload
    audit.drift_findings[0].tool_name = payload
    audit.drift_findings[0].summary = payload
    audit.drift_findings[0].details = [payload]
    audit.injection_findings = [
        InjectionFinding.model_validate(
            dict(
                tool_name=payload,
                severity="high",
                pattern_name=payload,
                matched_text=payload,
                description=payload,
            )
        )
    ]
    audit.ssrf_findings = [
        SsrfFinding.model_validate(
            dict(
                target_name=payload,
                severity="medium",
                pattern_name=payload,
                evidence=[payload],
                description=payload,
            )
        )
    ]
    audit.egress_findings = [
        EgressFinding.model_validate(
            dict(
                target_name=payload,
                severity="high",
                kind="destination_outside_allowlist",
                destination_host=payload,
                evidence=[payload],
            )
        )
    ]
    audit.provenance_findings = [
        ProvenanceFinding.model_validate(
            dict(
                server_name=payload,
                kind="command",
                severity="high",
                summary=payload,
                baseline=payload,
                current=payload,
            )
        )
    ]
    audit.escalation_findings = [
        EscalationFinding.model_validate(
            dict(
                server_name=payload,
                tool_name=payload,
                kind="description_injection",
                severity="high",
                gained_patterns=[payload],
                description=payload,
            )
        )
    ]
    hash_finding = dict(
        server_name=payload,
        severity="high",
        summary=payload,
        baseline_hash="sha256:fixture-before",
        current_hash="sha256:fixture-after",
    )
    audit.integrity_findings = [
        IntegrityFinding.model_validate(dict(hash_finding, kind="artifact_drift", artifact_path=payload))
    ]
    package_finding = dict(hash_finding, ecosystem=payload, package=payload, version=payload)
    audit.package_verify_findings = [
        PackageVerifyFinding.model_validate(dict(package_finding, kind="registry_drift"))
    ]
    audit.artifact_verify_findings = [
        ArtifactVerifyFinding.model_validate(dict(package_finding, kind="published_mismatch"))
    ]
    trifecta = TrifectaFinding.model_validate(
        dict(
            severity="high",
            leg1_contributors=[(payload, payload)],
            leg2_contributors=[(payload, payload)],
            leg3_contributors=[(payload, payload)],
            description=payload,
        )
    )
    audit.trifecta_findings = [trifecta]
    report.fleet_trifecta_findings = [trifecta.model_copy(update={"is_fleet": True})]
    report.shadowing_findings = [
        ShadowingFinding.model_validate(
            dict(
                kind="exact",
                severity="high",
                name=payload,
                collisions=[(payload, payload)],
                description=payload,
            )
        )
    ]
    report.policy_result = PolicyResult.model_validate(
        dict(
            passed=False,
            violations=[
                dict(rule=payload, server_name=payload, tool_name=payload, severity="high", message=payload)
            ],
        )
    )
    report.warnings = [ScanWarning(code="fixture", message=payload, servers=[payload])]
    return report


@pytest.mark.parametrize("payload", PAYLOADS)
def test_terminal_and_html_fields_are_safe(payload: str) -> None:
    report = _hostile_report(payload)
    console, buffer = _console()
    ReportGenerator(console).render_terminal(report, verbose=True)
    output = _SGR.sub("", buffer.getvalue())  # Rich's own styling is allowed.
    assert not _FORBIDDEN.search(output)
    if payload.startswith("["):
        assert payload in output
        assert "\\[" not in output
    html = HtmlReportGenerator().generate(report)
    assert not _FORBIDDEN.search(html)
    # Rendering must not mutate the data contract.
    assert report.audits[0].server.name == payload


@pytest.mark.parametrize("payload", PAYLOADS)
def test_discovery_pin_and_watch_sinks_are_safe(payload: str, monkeypatch: pytest.MonkeyPatch) -> None:
    report = _hostile_report(payload)
    console, buffer = _console()
    monkeypatch.setattr(core_cli, "console", console)
    monkeypatch.setattr(pin_cli, "console", console)
    monkeypatch.setattr(watcher, "_console", console)
    monkeypatch.setattr(core_cli, "discover_all_configs", lambda *_args, **_kwargs: [report.audits[0].server])
    result = CliRunner().invoke(main, ["discover", "--verbose"])
    assert result.exit_code == 0, result.output
    pin_cli._render_pin_refresh_review(payload, 1, report.audits[0].drift_findings)
    pin_cli._render_refresh_security_section(payload, [(payload, "high", payload, payload)])
    watcher._render_diff(report.model_copy(update={"audits": []}), report)
    output = _SGR.sub("", buffer.getvalue())
    assert not _FORBIDDEN.search(output)
    if payload.startswith("["):
        assert payload in output


@pytest.mark.anyio
@pytest.mark.parametrize("payload", PAYLOADS)
async def test_engine_warning_is_safe(payload: str, monkeypatch: pytest.MonkeyPatch) -> None:
    report = _hostile_report(payload)
    console, buffer = _console()

    async def connect(self: ServerConnector, config: ServerConfig) -> ServerAudit:
        assert self.scan_warnings is not None
        self.scan_warnings.extend(report.warnings)
        return report.audits[0]

    monkeypatch.setattr("mcp_audit.connector.ServerConnector.connect", connect)

    await run_scan(ScanOptions(), servers=[report.audits[0].server], console=console)
    # Live emits its own cursor/repaint controls before the warning line.
    output = _SGR.sub("", buffer.getvalue()).rsplit("\x1b[2K", 1)[-1]
    assert not _FORBIDDEN.search(output)
    if payload.startswith("["):
        assert payload in output


def test_cli_markup_name_still_writes_json(tmp_path: Path) -> None:
    config = tmp_path / "synthetic.json"
    config.write_text(json.dumps({"mcpServers": {"evil[/bold]name": {"command": "fixture"}}}))
    output = tmp_path / "out.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--config",
            str(config),
            "--config-only",
            "--skip-connect",
            "--json",
            str(output),
            "--override-config",
            "/dev/null",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["audits"][0]["server"]["name"] == "evil[/bold]name"


@pytest.mark.parametrize("payload", PAYLOADS)
def test_cli_config_path_errors_are_safe(payload: str, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--config",
            str(tmp_path / payload),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
        ],
    )
    assert result.exit_code == 1
    assert not _FORBIDDEN.search(result.output)
    assert strip_controls(str(tmp_path / payload)) in result.output


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a\t\nb\r\x00\x7f\x80\x9f", "a\t\nb"),
        ("a\x1b[31mb\x1b[0m", "ab"),
        ("a\x1b]title\x07b", "ab"),
        ("a\x1b]title\x1b\\b", "ab"),
        ("a\x1bXb", "ab"),
        ("a\x1b[", "a"),
        ("a\x1b]unterminated", "a"),
        ("a\x1b", "a"),
    ],
)
def test_strip_controls(value: str, expected: str) -> None:
    assert strip_controls(value) == expected
    assert terminal_safe(value).plain == expected


def test_strip_controls_megabyte_is_linear() -> None:
    def elapsed(size: int) -> float:
        value = "\x1b[" * (size // 2)
        start = time.perf_counter()
        assert strip_controls(value) == ""
        return time.perf_counter() - start

    small, large = elapsed(256 * 1024), elapsed(1024 * 1024)
    assert large < 10 * small + 0.05


def test_diagnostic_log_controls_and_traceback_are_safe() -> None:
    record = logging.LogRecord("fixture", logging.DEBUG, "fixture", 1, "%s", ("\x1b[2J[/bold]",), None)
    assert TerminalSafeLogFilter().filter(record)
    assert record.getMessage() == "[/bold]"
    try:
        raise ValueError("\x1b]0;pwned\x07")
    except ValueError:
        import sys

        record.exc_info = sys.exc_info()
    assert TerminalSafeLogFilter().filter(record)
    assert not _FORBIDDEN.search(logging.Formatter().format(record))


@pytest.mark.parametrize("no_color", [False, True])
def test_benign_non_tty_output_is_unchanged(no_color: bool) -> None:
    report = _report_with_findings()
    # Use benign fixture data for the baseline contract.
    audit = report.audits[0]
    audit.server.name = "fixture-server"
    audit.connection_error = None
    audit.permissions[0].evidence = ["fixture-evidence"]
    audit.injection_findings[0].matched_text = "fixture-text"
    console = Console(file=io.StringIO(), force_terminal=False, no_color=no_color, width=120, highlight=False)
    ReportGenerator(console).render_terminal(report, verbose=True)
    assert isinstance(console.file, io.StringIO)
    output = console.file.getvalue()
    assert output.count("Policy Gate Failed") == 1
    assert output == Path("tests/fixtures/reports/benign_terminal.txt").read_text()
