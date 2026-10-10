"""Golden parity coverage for the bounded engine and CLI adapter extraction."""

from __future__ import annotations

import hashlib
import inspect
import json
import platform
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import cast

import anyio
import pytest
from pydantic import ValidationError

from mcp_audit import engine, scan_cli
from mcp_audit.api import parse_config
from mcp_audit.engine import ScanOptions
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ClientType, ScanWarning, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.sarif import SarifGenerator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE: dict[str, object] = json.loads((ROOT / "tests/fixtures/engine_parity.json").read_text())


def _stable_report(report: AuditReport) -> AuditReport:
    """Replace only timestamp, hostname, and duration before comparing bytes."""
    return report.model_copy(
        update={
            "scan_timestamp": datetime(2000, 1, 1, tzinfo=UTC),
            "hostname": "parity-host",
            "scan_duration_seconds": 0.0,
        },
        deep=True,
    )


def _report_hashes(report: AuditReport) -> dict[str, str]:
    stable = _stable_report(report)
    outputs = {
        "json": json.dumps(stable.model_dump(mode="json"), indent=2).encode("utf-8"),
        "sarif": json.dumps(SarifGenerator().generate(stable), indent=2).encode("utf-8"),
        "html": HtmlReportGenerator().generate(stable).encode("utf-8"),
    }
    return {name: hashlib.sha256(output).hexdigest() for name, output in outputs.items()}


def _engine_hashes() -> dict[str, dict[str, str]]:
    baseline = cast(dict[str, object], FIXTURE["baseline_output_sha256"])
    return cast(dict[str, dict[str, str]], baseline["engine_reports"])


def _report_inputs() -> list[str]:
    return cast(list[str], FIXTURE["audit_report_inputs"])


def _scan_config(relative_path: str, monkeypatch: pytest.MonkeyPatch) -> AuditReport:
    monkeypatch.setattr(platform, "system", lambda: "FixtureOS")
    options = ScanOptions(config_only=True, skip_connect=True, extra_config=relative_path)
    return anyio.run(partial(engine.run_scan, options))


@pytest.mark.parametrize("relative_path", cast(list[str], FIXTURE["example_config_inputs"]))
def test_example_config_scan_matches_immutable_baseline_output_hashes(
    relative_path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = _scan_config(relative_path, monkeypatch)
    assert _report_hashes(report) == _engine_hashes()[f"config:{relative_path}"]


class _FixtureConnector:
    """Return deterministic connected-shaped results without starting a server."""

    def __init__(self, *, tools_by_name: dict[str, list[ToolInfo]], fail_first: bool = False) -> None:
        self.tools_by_name = tools_by_name
        self.fail_first = fail_first
        warning = cast(dict[str, object], FIXTURE["connector_warning"])
        self.fixture_warnings = [
            ScanWarning(
                code=cast(str, warning["code"]),
                message=cast(str, warning["message"]),
                check=cast(str, warning["check"]),
                servers=cast(list[str], warning["servers"]),
            )
        ]
        self._scan_warnings: list[ScanWarning] = []

    @property
    def scan_warnings(self) -> list[ScanWarning]:
        return [*self.fixture_warnings, *self._scan_warnings]

    @scan_warnings.setter
    def scan_warnings(self, warnings: list[ScanWarning]) -> None:
        self._scan_warnings = warnings

    def skip_connect_audit(self, server: ServerConfig) -> ServerAudit:
        return ServerAudit(server=server, connection_status="skipped")

    async def connect(self, server: ServerConfig, **_: object) -> ServerAudit:
        if self.fail_first and server.name == "fixture-alpha":
            raise RuntimeError("fixture analysis error")
        return ServerAudit(
            server=server,
            connection_status="connected",
            tools=self.tools_by_name[server.name],
        )


def _connected_report(monkeypatch: pytest.MonkeyPatch, *, fail_first: bool = False) -> AuditReport:
    monkeypatch.setattr(platform, "system", lambda: "FixtureOS")
    connected_servers = cast(list[dict[str, object]], FIXTURE["connected_servers"])
    servers: list[ServerConfig] = []
    tools_by_name: dict[str, list[ToolInfo]] = {}
    for entry in connected_servers:
        name = cast(str, entry["name"])
        servers.append(
            ServerConfig(
                name=name,
                client=ClientType.CLAUDE_CODE,
                config_path=f"fixture://{name}",
                command=cast(str, entry["command"]),
            )
        )
        tools_by_name[name] = [
            ToolInfo.model_validate(tool) for tool in cast(list[dict[str, object]], entry["tools"])
        ]

    def connector(**_: object) -> _FixtureConnector:
        return _FixtureConnector(tools_by_name=tools_by_name, fail_first=fail_first)

    monkeypatch.setattr(engine, "ServerConnector", connector)
    connected_options = cast(dict[str, bool], FIXTURE["connected_options"])
    options = ScanOptions(
        inject_check=connected_options["inject_check"],
        ssrf_check=connected_options["ssrf_check"],
        egress_check=connected_options["egress_check"],
        trifecta_check=connected_options["trifecta_check"],
        shadow_check=connected_options["shadow_check"],
    )
    return anyio.run(partial(engine.run_scan, options, servers=servers))


def test_connected_scan_matches_immutable_baseline_output_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _report_hashes(_connected_report(monkeypatch)) == _engine_hashes()["connected"]


def test_one_server_analysis_error_does_not_cancel_sibling_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _connected_report(monkeypatch, fail_first=True)

    assert _report_hashes(report) == _engine_hashes()["connected_error_isolation"]
    assert [audit.connection_status for audit in report.audits] == ["failed", "connected"]
    assert report.servers_failed == 1
    assert report.servers_connected == 1
    assert [warning.code for warning in report.warnings] == ["fixture_warning"]


@pytest.mark.parametrize("relative_path", _report_inputs())
def test_cli_adapter_files_match_pre_extraction_sha256(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, relative_path: str
) -> None:
    report = _stable_report(AuditReport.model_validate_json((ROOT / relative_path).read_text()))

    async def fixture_scan(*_: object, **__: object) -> AuditReport:
        return report.model_copy(deep=True)

    monkeypatch.setattr(scan_cli, "run_scan", fixture_scan)
    override_path = tmp_path / "empty-overrides.yaml"
    override_path.write_text("{}\n")
    output_paths = {
        "report.json": tmp_path / "report.json",
        "report.sarif": tmp_path / "report.sarif",
        "report.html": tmp_path / "report.html",
    }
    try:
        anyio.run(
            partial(
                scan_cli._run_scan,
                json_output=str(output_paths["report.json"]),
                sarif_output=str(output_paths["report.sarif"]),
                html_output=str(output_paths["report.html"]),
                skip_connect=True,
                clients=None,
                timeout=10,
                verbose=False,
                extra_config=str(ROOT / cast(list[str], FIXTURE["example_config_inputs"])[0]),
                override_config_path=str(override_path),
                policy_path=None,
                config_only=True,
                color="never",
            )
        )
        exit_code = 0
    except SystemExit as exc:
        exit_code = int(exc.code or 0)

    baseline = cast(dict[str, object], FIXTURE["baseline_output_sha256"])
    cli_files = cast(dict[str, object], baseline["cli_files"])
    expected = cast(dict[str, object], cli_files[relative_path])
    observed = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in output_paths.values()}
    assert observed == {name: expected[name] for name in output_paths}
    assert exit_code == expected["exit_code"]


def test_run_scan_remains_under_150_lines() -> None:
    source_lines, _ = inspect.getsourcelines(engine.run_scan)
    assert len(source_lines) < 150


def test_report_inventory_excludes_non_report_json_inputs() -> None:
    selected_reports = set(_report_inputs())
    exclusions = cast(dict[str, str], FIXTURE["non_audit_report_json"])
    all_inputs = {
        path.as_posix()
        for base in (ROOT / "examples", ROOT / "tests/fixtures/reports")
        for path in base.rglob("*.json")
    }
    detected_reports: set[str] = set()
    for relative_path in all_inputs:
        try:
            AuditReport.model_validate_json((ROOT / relative_path).read_text())
        except ValidationError:
            continue
        detected_reports.add(Path(relative_path).relative_to(ROOT).as_posix())

    selected_configs = set(cast(list[str], FIXTURE["example_config_inputs"]))
    detected_configs: set[str] = set()
    for path in (ROOT / "examples").rglob("*.json"):
        payload = json.loads(path.read_text())
        if isinstance(payload, dict) and isinstance(payload.get("mcpServers"), dict):
            parse_config(payload)
            detected_configs.add(path.relative_to(ROOT).as_posix())

    assert selected_reports == detected_reports
    assert selected_configs == detected_configs
    relative_inputs = {Path(path).relative_to(ROOT).as_posix() for path in all_inputs}
    assert selected_reports.isdisjoint(exclusions)
    assert selected_reports | set(exclusions) == relative_inputs
    assert all(reason for reason in exclusions.values())


def test_cli_policy_evaluation_and_load_error_exit_codes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = AuditReport.model_validate_json(
        (ROOT / "tests/fixtures/reports/policy_failure_report.json").read_text()
    )
    override_path = tmp_path / "empty-overrides.yaml"
    override_path.write_text("{}\n")

    async def fixture_scan(*_: object, **__: object) -> AuditReport:
        return report.model_copy(deep=True)

    monkeypatch.setattr(scan_cli, "run_scan", fixture_scan)
    policy_path = ROOT / "examples/policies/ci-strict.yaml"
    try:
        anyio.run(
            partial(
                scan_cli._run_scan,
                None,
                None,
                None,
                True,
                None,
                10,
                False,
                str(ROOT / "examples/configs/popular-public-servers.json"),
                str(override_path),
                str(policy_path),
                config_only=True,
                color="never",
            )
        )
        policy_exit_code = 0
    except SystemExit as exc:
        policy_exit_code = int(exc.code or 0)
    assert policy_exit_code == 2

    invalid_policy = tmp_path / "invalid-policy.yaml"
    invalid_policy.write_text("fail_on: [\n")
    try:
        anyio.run(
            partial(
                scan_cli._run_scan,
                None,
                None,
                None,
                True,
                None,
                10,
                False,
                str(ROOT / "examples/configs/popular-public-servers.json"),
                str(override_path),
                str(invalid_policy),
                config_only=True,
                color="never",
            )
        )
        load_error_exit_code = 0
    except SystemExit as exc:
        load_error_exit_code = int(exc.code or 0)
    assert load_error_exit_code == 1
