"""Coverage contracts exercised through isolated repository-owned servers."""

import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, CheckCoverage, ServerAudit, ServerConfig
from mcp_audit.policy import PolicyConfig, evaluate_policy, load_policy
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.anyio
async def test_config_only_reports_unchecked_metadata_and_gate() -> None:
    report = await run_scan(ScanOptions(skip_connect=True, inject_check=True), servers=[make_server_config()])
    assert report.schema_version == 1
    assert report.coverage["config_health"].state == "complete"
    assert report.coverage["metadata"] == CheckCoverage(state="not_run", reason="connections disabled")
    assert report.coverage["inject_check"].state == "not_run"
    assert report.coverage["runtime_security"].state == "not_requested"
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed
    assert evaluate_policy(report, PolicyConfig()).passed


@pytest.mark.anyio
async def test_no_eligible_tools_is_incomplete_in_html_sarif_and_policy() -> None:
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "deadbugz_server.py"), "unsafe"])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    assert report.coverage["metadata"].state == "complete"
    assert report.coverage["runtime_security"].state == "not_run"
    assert "No eligible" in report.coverage["runtime_security"].reason
    assert "Audit coverage is incomplete" in HtmlReportGenerator().generate(report)
    run = SarifGenerator().generate(report)["runs"][0]
    assert run["properties"]["mcpAuditCoverage"]["runtime_security"]["state"] == "not_run"
    assert run["invocations"][0]["toolExecutionNotifications"]
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
@pytest.mark.parametrize("canary", [False, True])
async def test_pagination_flood_is_partial_and_gateable(canary: bool) -> None:
    config = make_server_config(
        command=sys.executable, args=[str(FIXTURES / "evasion_server.py"), "page_flood", "current"]
    )
    report = await run_scan(ScanOptions(canary_check=canary, timeout=15), servers=[config])
    assert report.audits[0].connection_status == "partial"
    assert not report.audits[0].tools
    assert report.servers_connected == 1 and report.servers_failed == 0
    assert report.coverage["metadata"].state == "partial"
    if canary:
        assert report.coverage["runtime_security"].state == "partial"
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
async def test_bounded_clean_canary_and_unrequested_checks_pass_coverage_gate() -> None:
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "deadbugz_server.py"), "clean"])
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    assert report.coverage["runtime_security"].state == "complete"
    assert report.coverage["inject_check"].state == "not_requested"
    assert evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


@pytest.mark.anyio
async def test_advertised_metadata_failure_is_partial_without_pagination_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mcp import Client

    async def fail(self: Client, *args: object, **kwargs: object) -> None:
        raise ValueError("fixture failure")

    monkeypatch.setattr(Client, "list_prompts", fail)
    config = make_server_config(command=sys.executable, args=[str(FIXTURES / "mock_server.py")])
    report = await run_scan(ScanOptions(timeout=15), servers=[config])
    assert report.audits[0].connection_status == "partial"
    assert report.coverage["metadata"].state == "partial"
    warning = next(warning for warning in report.warnings if warning.code == "surface_listing_incomplete")
    assert "Advertised metadata could not be listed" in warning.message
    assert "large" not in warning.message


@pytest.mark.anyio
async def test_mixed_fleet_and_missing_per_server_baseline_are_partial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from mcp_audit import pinning

    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    servers = [make_server_config(name=name) for name in ("pinned", "unpinned")]
    store.pin_server("pinned", [], server_config=servers[0])
    monkeypatch.setattr(pinning, "PinStore", lambda: store)
    report = await run_scan(ScanOptions(skip_connect=True, provenance_check=True), servers=servers)
    assert report.coverage["provenance_check"].state == "partial"
    assert "baseline unavailable" in report.coverage["provenance_check"].reason


@pytest.mark.anyio
@pytest.mark.parametrize("pinned", [False, True])
async def test_empty_tool_pin_baseline_presence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pinned: bool
) -> None:
    from mcp_audit import pinning
    from mcp_audit.connector import ServerConnector

    store = pinning.PinStore(path=tmp_path / "pins.yaml")
    config = make_server_config()
    if pinned:
        store.pin_server(config.name, [])
    monkeypatch.setattr(pinning, "PinStore", lambda: store)

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="connected")

    monkeypatch.setattr(ServerConnector, "connect", connect)
    report = await run_scan(ScanOptions(pin_check=True), servers=[config])
    assert report.audits[0].drift_findings == []
    assert report.coverage["pin_check"].state == ("complete" if pinned else "not_run")
    assert evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed is pinned


def test_legacy_unknown_coverage_is_gateable() -> None:
    report = AuditReport.model_validate_json((FIXTURES / "reports/config_only_report.json").read_text())
    result = evaluate_policy(report, PolicyConfig(fail_on_coverage=True))
    assert not result.passed
    assert result.violations[0].rule == "fail_on.coverage"
    assert "unknown" in result.violations[0].message


def test_sparse_coverage_does_not_pass_gate() -> None:
    report = AuditReport.model_validate_json((FIXTURES / "reports/config_only_report.json").read_text())
    report.coverage = {"metadata": CheckCoverage(state="complete", reason="metadata listed")}
    assert not evaluate_policy(report, PolicyConfig(fail_on_coverage=True)).passed


def test_coverage_policy_and_extended_sarif_cli(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("fail_on:\n  coverage: true\n")
    assert load_policy(policy_path).fail_on_coverage
    output = tmp_path / "audit.sarif"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--config",
            "examples/sandbox/fixtures/synthetic-mcp-config.json",
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--policy",
            str(policy_path),
            "--sarif",
            str(output),
            "--sarif-profile",
            "extended",
        ],
    )
    assert result.exit_code == 2, result.output
    assert output.exists()
    assert "MCP-CH-" in output.read_text()


@pytest.mark.parametrize("value", ["partial", "yes please", 1, None])
def test_coverage_policy_rejects_ambiguous_values(tmp_path: Path, value: object) -> None:
    import yaml

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump({"fail_on": {"coverage": value}}))
    with pytest.raises(ValueError, match="must be a boolean"):
        load_policy(policy_path)
