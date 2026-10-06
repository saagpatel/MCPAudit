"""Regression coverage for credential redaction at user-facing output surfaces."""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_audit import cli
from mcp_audit.engine import ScanOptions
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    InjectionFinding,
    InjectionSeverity,
    ServerAudit,
    ServerConfig,
)
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.server import _build_mcp_server
from tests.conftest import make_server_config

FIXTURE = Path(__file__).parent / "fixtures" / "configs" / "cfg_secrets.json"


def _fixture_secrets() -> list[str]:
    """Return the deliberate synthetic credentials planted in the fixture."""
    return [
        "ghp_SECRETVALUE1234567890abcdefABCDEF12",
        "sk-proj-SECRETabcdefghijklmnop",
        "hunter2-SECRET",
        "ENVSTYLESECRET",
        "xoxb-SLACKSECRET-123456",
        "AKIAABCDEFGHIJKLMNOP",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature12345678",
        "QUERYSECRET789",
        "SIGSECRET",
        "first second&third",
        "first,second",
        "first&second",
        "first\"second'third",
        "DBSECRET",
    ]


@pytest.mark.parametrize("field_report", [False, True], ids=["default", "redact-identifiers"])
def test_cli_all_report_surfaces_redact_fixture_credentials(tmp_path: Path, field_report: bool) -> None:
    outputs = {suffix: tmp_path / f"report.{suffix}" for suffix in ("json", "sarif", "html")}
    args = [
        "scan",
        "--config",
        str(FIXTURE),
        "--config-only",
        "--skip-connect",
        "--override-config",
        "/dev/null",
        "--json",
        str(outputs["json"]),
        "--sarif",
        str(outputs["sarif"]),
        "--html",
        str(outputs["html"]),
    ]
    if field_report:
        args.append("--redact")

    result = CliRunner().invoke(cli.main, args)

    assert result.exit_code == 0, result.output
    for surface, path in outputs.items():
        rendered = path.read_text()
        for secret in _fixture_secrets():
            assert secret not in rendered, f"{surface} leaked fixture credential"
    for secret in _fixture_secrets():
        assert secret not in result.output, "terminal output leaked fixture credential"


def _report_with_secret_finding(
    server: ServerConfig | None = None, *, include_finding: bool = True
) -> AuditReport:
    config = server or make_server_config(name="fixture-server", args=["--token", "fixture-token-secret"])
    finding = InjectionFinding(
        tool_name="fixture-tool",
        severity=InjectionSeverity.HIGH,
        pattern_name="fixture_pattern",
        matched_text="token=abc123secret",
        description="Description contains token=abc123secret",
    )
    audit = ServerAudit(
        server=config,
        connection_status="connected",
        injection_findings=[finding] if include_finding else [],
    )
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="synthetic-host",
        os_platform="synthetic-os",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.01,
    )


@pytest.mark.parametrize("delimiter", ["=", ":"])
@pytest.mark.parametrize(
    "value", ["first second&third", "first,second", "first&second", "first\"second'third"]
)
def test_report_redacts_whole_inline_argv_value(delimiter: str, value: str) -> None:
    config = make_server_config(args=[f"--password{delimiter}{value}", "--port", "8080"])
    report = _report_with_secret_finding(config, include_finding=False)
    redacted = report.redacted()
    assert redacted.audits[0].server.args == [f"--password{delimiter}<redacted>", "--port", "8080"]
    assert value not in redacted.model_dump_json()
    assert report.audits[0].server.args == config.args


def _tool_payload(result: object) -> Any:
    structured = getattr(result, "structured_content", None)
    assert isinstance(structured, dict)
    raw = structured["result"]
    assert isinstance(raw, str)
    return json.loads(raw)


@pytest.mark.anyio
async def test_serve_report_and_finding_tools_redact_synthetic_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_audit.server as server_module

    config = make_server_config(name="fixture-server", args=["--token", "fixture-token-secret"])
    report = _report_with_secret_finding(config)

    async def fake_scan(options: ScanOptions, *, servers: list[ServerConfig] | None = None) -> AuditReport:
        return report

    monkeypatch.setattr(server_module, "_scan", fake_scan)
    monkeypatch.setattr(server_module, "discover_all_configs", lambda clients, parse_errors: [config])
    app = _build_mcp_server()

    for tool, params in (
        ("scan_mcp_servers", {"skip_connect": True}),
        ("check_server", {"name": "fixture-server"}),
    ):
        payload = _tool_payload(await app.call_tool(tool, params))
        encoded = json.dumps(payload)
        assert "fixture-token-secret" not in encoded
        assert "abc123secret" not in encoded
        assert "token=<redacted>" in encoded

    findings = _tool_payload(await app.call_tool("get_injection_findings", {}))
    encoded_findings = json.dumps(findings)
    assert "abc123secret" not in encoded_findings
    assert "token=<redacted>" in encoded_findings


def test_each_report_renderer_calls_redaction_entry_point(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = _report_with_secret_finding()
    calls: list[AuditReport] = []

    def redacted(self: AuditReport, *, identifiers: bool = False) -> AuditReport:
        del identifiers
        calls.append(self)
        return self

    monkeypatch.setattr(AuditReport, "redacted", redacted)

    generator = ReportGenerator(console=Console(file=StringIO()))
    generator.render_terminal(report)
    generator.render_json(report, tmp_path / "report.json")
    SarifGenerator().generate(report)
    HtmlReportGenerator().generate(report)

    assert calls == [report, report, report, report]


def test_renderers_and_serve_module_do_not_call_redact_data_directly() -> None:
    import mcp_audit.htmlreport as htmlreport_module
    import mcp_audit.report as report_module
    import mcp_audit.sarif as sarif_module
    import mcp_audit.server as server_module

    modules = (report_module, sarif_module, htmlreport_module, server_module)
    for module in modules:
        assert module.__file__ is not None
        syntax_tree = ast.parse(Path(module.__file__).read_text())
        assert not any(
            isinstance(node, ast.Name) and node.id == "redact_data" for node in ast.walk(syntax_tree)
        ), f"{module.__name__} calls redact_data directly"


@pytest.mark.anyio
async def test_serve_report_and_finding_tools_call_report_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mcp_audit.server as server_module

    config = make_server_config(name="fixture-server")
    named_config = make_server_config(name="token=abc123secret")
    report = _report_with_secret_finding(config, include_finding=False).model_copy(
        update={
            "servers_discovered": 2,
            "audits": [
                ServerAudit(server=config, connection_status="connected"),
                ServerAudit(server=named_config, connection_status="skipped"),
            ],
        }
    )
    calls: list[AuditReport] = []

    async def fake_scan(*args: object, **kwargs: object) -> AuditReport:
        return report

    original_redacted = AuditReport.redacted

    def redacted(self: AuditReport, *, identifiers: bool = False) -> AuditReport:
        calls.append(self)
        return original_redacted(self, identifiers=identifiers)

    monkeypatch.setattr(server_module, "_scan", fake_scan)
    monkeypatch.setattr(server_module, "run_scan", fake_scan)
    monkeypatch.setattr(
        server_module,
        "discover_all_configs",
        lambda clients, parse_errors=None: [config, named_config],
    )
    monkeypatch.setattr(AuditReport, "redacted", redacted)
    app = _build_mcp_server()

    tool_cases: tuple[tuple[str, dict[str, object]], ...] = (
        ("scan_mcp_servers", {"skip_connect": True}),
        ("get_high_risk_servers", {}),
        ("check_server", {"name": "fixture-server"}),
        ("get_injection_findings", {}),
        ("get_ssrf_findings", {}),
        ("get_trifecta_findings", {}),
        ("get_shadowing_findings", {}),
        ("get_escalation_findings", {}),
        ("get_provenance_findings", {}),
        ("get_integrity_findings", {}),
        ("get_package_verify_findings", {}),
        ("get_artifact_verify_findings", {}),
        ("list_discovered_servers", {}),
    )
    for tool, params in tool_cases:
        result = await app.call_tool(tool, params)
        if tool == "list_discovered_servers":
            payload = _tool_payload(result)
            assert {server["name"] for server in payload} == {
                "fixture-server",
                "token=<redacted>",
            }
        else:
            _tool_payload(result)

    assert len(calls) == len(tool_cases)
