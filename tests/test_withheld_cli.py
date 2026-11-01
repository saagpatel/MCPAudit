"""One-shot failure and watch continuation on synthetic withheld pin baselines."""

from __future__ import annotations

import io
import json
import sys
import types
from collections.abc import AsyncIterator
from dataclasses import replace
from functools import partial
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner
from rich.console import Console

from mcp_audit import check_cli, engine, watcher
from mcp_audit.cli import main
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, CanarySummary, ScanWarning, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.pinning import PinStore
from mcp_audit.pkgverify import RegistryClient
from mcp_audit.policy import PolicyConfig, evaluate_policy
from tests.conftest import make_server_config

CHECKS = (
    "pin_check",
    "canary_check",
    "escalation_check",
    "provenance_check",
    "integrity_check",
    "verify_artifacts",
    "download_artifacts",
)


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "synthetic"}}}')
    pins = tmp_path / "pins.yaml"
    pins.write_bytes((Path(__file__).parent / "fixtures/pinning/legacy-v1.yaml").read_bytes())

    async def connect(self: ServerConnector, server: ServerConfig, **kwargs: object) -> ServerAudit:
        calls = kwargs.get("canary_calls")
        canary = (
            CanarySummary(requested_calls=calls, completed_calls=calls, status="complete")
            if isinstance(calls, int)
            else None
        )
        return ServerAudit(
            server=server, connection_status="connected", tools=[ToolInfo(name="status")], canary=canary
        )

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("withheld-baseline tests must not discover or fetch external input")

    monkeypatch.setattr(ServerConnector, "connect", connect)
    monkeypatch.setattr(engine, "discover_all_configs", forbidden)
    monkeypatch.setattr(RegistryClient, "fetch_hash", forbidden)
    monkeypatch.setattr(RegistryClient, "fetch_artifact", forbidden)
    return config, pins


def _args(inputs: tuple[Path, Path], check: str | None = "pin_check") -> list[str]:
    config, pins = inputs
    args = [
        "check",
        "--config",
        str(config),
        "--config-only",
        "--override-config",
        "/dev/null",
        "--pin-file",
        str(pins),
        "--json",
    ]
    if check == "canary_check":
        args.extend(["--connect", "--server", "claude_code:workstation:fixture"])
    else:
        args.append("--skip-connect")
    if check is not None:
        args.append("--" + check.replace("_", "-"))
    return args


@pytest.mark.parametrize("check", CHECKS)
def test_all_requested_checks_fail_after_all_artifacts_without_policy(
    inputs: tuple[Path, Path], tmp_path: Path, check: str
) -> None:
    original = {path: path.read_bytes() for path in inputs}
    outputs = {
        flag: tmp_path / name
        for flag, name in (
            ("--output-json", "report.json"),
            ("--sarif", "report.sarif"),
            ("--html", "report.html"),
            ("--card", "card.html"),
        )
    }
    args = _args(inputs, check)
    for flag, path in outputs.items():
        args.extend([flag, str(path)])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.schema_version == 1
    assert report.policy_result is not None and not report.policy_result.passed
    (violation,) = report.policy_result.violations
    assert violation.rule == "fail_on.pin_baseline_withheld"
    assert violation.server_name == "fixture" and violation.audit_index == 0
    assert violation.severity == "high" and check in violation.message
    coverage_key = "runtime_security" if check == "canary_check" else check
    assert report.coverage[coverage_key].state == (
        "partial" if check in {"pin_check", "canary_check"} else "not_run"
    )
    assert any(w.code == "pin_baseline_withheld" and w.check == check for w in report.warnings)
    assert json.loads(outputs["--output-json"].read_text()) == json.loads(result.stdout)
    sarif = json.loads(outputs["--sarif"].read_text())
    assert any(r["ruleId"] == "MCP010" for r in sarif["runs"][0]["results"])
    assert all(path.stat().st_size for path in outputs.values())
    assert "fail_on.pin_baseline_withheld" in outputs["--html"].read_text()
    assert {path: path.read_bytes() for path in inputs} == original


@pytest.mark.parametrize("value", [None, "false", "true"])
@pytest.mark.parametrize("command", ["check", "shadow"])
def test_policy_cannot_disable_gate_and_false_warns(
    inputs: tuple[Path, Path],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    command: str,
    value: str | None,
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("{}" if value is None else f"fail_on:\n  pin_baseline_withheld: {value}\n")
    args = (
        _args(inputs)
        if command == "check"
        else [
            "shadow",
            "--config",
            str(inputs[0]),
            "--pin-file",
            str(inputs[1]),
            "--json",
        ]
    )
    result = CliRunner().invoke(main, [*args, "--policy", str(policy)])
    assert result.exit_code == 2, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.policy_result is not None and not report.policy_result.passed
    assert [v.rule for v in report.policy_result.violations] == ["fail_on.pin_baseline_withheld"]
    assert ("false is ignored by check and shadow" in caplog.text) is (value == "false")


def test_gate_merges_existing_policy_violations(inputs: tuple[Path, Path], tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("allow_servers: [other]\nfail_on:\n  pin_baseline_withheld: true\n")
    result = CliRunner().invoke(main, [*_args(inputs), "--policy", str(policy)])
    assert result.exit_code == 2, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.policy_result is not None
    assert [v.rule for v in report.policy_result.violations] == [
        "allow_servers",
        "fail_on.pin_baseline_withheld",
    ]


@pytest.mark.parametrize("json_stdout", [False, True])
def test_shadow_without_policy_fails_after_rendering(inputs: tuple[Path, Path], json_stdout: bool) -> None:
    args = ["shadow", "--config", str(inputs[0]), "--pin-file", str(inputs[1])]
    if json_stdout:
        args.append("--json")
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2, result.output
    if json_stdout:
        report = AuditReport.model_validate_json(result.stdout)
        assert report.policy_result is not None and not report.policy_result.passed
    else:
        assert "pin baselines that cannot be trusted" in result.stdout


@pytest.mark.parametrize("state", ["unrequested", "missing", "usable"])
def test_gate_does_not_fail_other_baseline_states(inputs: tuple[Path, Path], state: str) -> None:
    check = None if state == "unrequested" else "pin_check"
    if state == "missing":
        inputs[1].unlink()
    elif state == "usable":
        inputs[1].unlink()
        PinStore(inputs[1]).pin_server("fixture", [ToolInfo(name="status")])
    result = CliRunner().invoke(main, _args(inputs, check))
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.policy_result is None


@pytest.mark.parametrize(
    "warning_check,servers,expected",
    [
        ("provenance_check", ["fixture"], 0),
        ("pin_check", ["peer"], 0),
        ("pin_check", [], 2),
    ],
)
def test_gate_filters_warning_by_request_and_server(
    inputs: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    warning_check: str,
    servers: list[str],
    expected: int,
) -> None:
    real_scan = engine.run_scan

    async def scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        report = await real_scan(
            replace(options, pin_check=False), servers=[make_server_config(name="fixture")]
        )
        report.warnings.append(
            ScanWarning(
                code="pin_baseline_withheld",
                check=warning_check,
                servers=servers,
                message="Synthetic withheld baseline.",
            )
        )
        return report

    monkeypatch.setattr(check_cli, "run_scan", scan)
    result = CliRunner().invoke(main, _args(inputs))
    assert result.exit_code == expected, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert (report.policy_result is not None) is (expected == 2)


@pytest.mark.parametrize("check", CHECKS)
def test_library_run_scan_remains_ungated(inputs: tuple[Path, Path], check: str) -> None:
    options = ScanOptions(
        pin_file=inputs[1],
        skip_connect=check != "canary_check",
        pin_check=check == "pin_check",
        canary_check=check == "canary_check",
        escalation_check=check == "escalation_check",
        provenance_check=check == "provenance_check",
        integrity_check=check == "integrity_check",
        verify_artifacts=check == "verify_artifacts",
        download_artifacts=check == "download_artifacts",
    )
    report = anyio.run(partial(engine.run_scan, options, servers=[make_server_config(name="fixture")]))
    assert any(w.code == "pin_baseline_withheld" and w.check == check for w in report.warnings)
    assert report.policy_result is None
    assert evaluate_policy(report, PolicyConfig()).passed
    assert evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=False)).passed


@pytest.mark.anyio
async def test_watch_writes_partial_reports_and_warns_on_every_rescan(
    inputs: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = io.StringIO()
    monkeypatch.setattr(watcher, "_console", Console(file=buffer, width=240, highlight=False))
    monkeypatch.setattr(watcher, "discover_all_configs", lambda *args, **kwargs: [])

    async def changes(*paths: str) -> AsyncIterator[set[tuple[int, str]]]:
        yield {(2, str(inputs[0]))}
        yield {(2, str(inputs[0]))}

    monkeypatch.setitem(sys.modules, "watchfiles", types.SimpleNamespace(awatch=changes))
    real_scan = engine.run_scan

    async def scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        assert options.pin_check and options.skip_connect
        return await real_scan(
            options,
            servers=[make_server_config(name="fixture")],
            pin_store=PinStore(inputs[1]),
        )

    monkeypatch.setattr(engine, "run_scan", scan)
    real_write = watcher._write_outputs
    reports: list[AuditReport] = []

    def write(report: AuditReport, json_output: str | None, sarif_output: str | None) -> None:
        real_write(report, json_output, sarif_output)
        assert json_output is not None and sarif_output is not None
        saved = AuditReport.model_validate_json(Path(json_output).read_text())
        assert saved.coverage["pin_check"].state == "partial"
        assert saved.policy_result is None
        assert json.loads(Path(sarif_output).read_text())["version"] == "2.1.0"
        reports.append(saved)

    monkeypatch.setattr(watcher, "_write_outputs", write)
    await watcher._watch_loop(
        str(tmp_path / "watch.json"),
        str(tmp_path / "watch.sarif"),
        True,
        None,
        10,
        False,
        str(inputs[0]),
        "/dev/null",
    )
    assert len(reports) == 3
    assert buffer.getvalue().count("pin baselines that cannot be trusted") == 3
