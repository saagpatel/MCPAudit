"""Shadow fold acceptance against synthetic pins and local metadata fixtures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import cli, engine, pin_signing
from mcp_audit.connector import ServerConnector
from mcp_audit.models import AuditReport, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.pin_signing import generate_keypair
from mcp_audit.pinning import PinStore
from tests.conftest import make_server_config


@pytest.fixture
def shadow_inputs(tmp_path: Path) -> tuple[Path, Path, Path, ToolInfo]:
    config = tmp_path / "synthetic.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    name: {
                        "command": sys.executable,
                        "args": [str(Path("tests/fixtures/mock_server.py").resolve())],
                    }
                    for name in ("fixture-a", "fixture-b")
                }
            }
        )
    )
    trust = tmp_path / "trusted-pin-keys.json"
    key = generate_keypair(tmp_path / "keys", trust)
    tool = ToolInfo.model_validate_json(Path("tests/fixtures/pinning/tool-v2.json").read_text())
    store = PinStore(tmp_path / "pins.yaml", signing_key=key.private_key_path, trusted_keys_path=trust)
    for name in ("fixture-a", "fixture-b"):
        store.pin_server(name, [tool], make_server_config(name=name))
    return config, store.path, trust, tool


def _args(inputs: tuple[Path, Path, Path, ToolInfo]) -> list[str]:
    config, pins, trust, _ = inputs
    return [
        "shadow",
        "--config",
        str(config),
        "--pin-file",
        str(pins),
        "--trusted-keys",
        str(trust),
        "--json",
    ]


@pytest.fixture
def metadata_only(
    monkeypatch: pytest.MonkeyPatch, shadow_inputs: tuple[Path, Path, Path, ToolInfo]
) -> list[str]:
    calls: list[str] = []
    tool = shadow_inputs[3]

    def no_discovery(*args: object, **kwargs: object) -> None:
        raise AssertionError("shadow must not discover workstation configs")

    async def connect(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        calls.append(server.name)
        return ServerAudit(server=server, connection_status="connected", tools=[tool])

    monkeypatch.setattr(engine, "discover_all_configs", no_discovery)
    monkeypatch.setattr(ServerConnector, "connect", connect)

    def no_trust_write(*args: object, **kwargs: object) -> None:
        raise AssertionError("shadow must not update trust history")

    monkeypatch.setattr(pin_signing, "record_signed_pin", no_trust_write)
    return calls


@pytest.mark.parametrize("drift_policy", [False, True])
def test_shadow_static_default_uses_engine_without_connecting_or_writing(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo],
    metadata_only: list[str],
    tmp_path: Path,
    drift_policy: bool,
) -> None:
    paths = shadow_inputs[:3]
    original = {path: path.read_bytes() for path in paths}
    args = _args(shadow_inputs)
    if drift_policy:
        policy = tmp_path / "policy.yaml"
        policy.write_text("fail_on:\n  drift: true\n")
        args.extend(["--policy", str(policy)])
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.schema_version == 1
    assert report.servers_discovered == 2
    assert metadata_only == []
    assert {audit.connection_status for audit in report.audits} == {"skipped"}
    assert {audit.pin_verification.state.value for audit in report.audits if audit.pin_verification} == {
        "verified"
    }
    assert report.coverage["pin_check"].state == "not_run"
    assert report.coverage["shadow_check"].state == "not_run"
    assert all(not audit.drift_findings for audit in report.audits)
    if drift_policy:
        assert report.policy_result is not None and report.policy_result.passed
    assert {path: path.read_bytes() for path in paths} == original


@pytest.mark.parametrize("state", ["failed", "timeout", "partial"])
def test_shadow_unavailable_listing_does_not_report_removed_tools(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo],
    metadata_only: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
) -> None:
    async def unavailable(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        metadata_only.append(server.name)
        return ServerAudit(server=server, connection_status=state)

    monkeypatch.setattr(ServerConnector, "connect", unavailable)
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on:\n  drift: true\n")
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect", "--policy", str(policy)])
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert sorted(metadata_only) == ["fixture-a", "fixture-b"]
    assert {audit.connection_status for audit in report.audits} == {state}
    assert all(not audit.drift_findings for audit in report.audits)
    assert report.coverage["pin_check"].state == "not_run"
    assert report.policy_result is not None and report.policy_result.passed


@pytest.mark.parametrize("empty_listing", [False, True])
def test_shadow_completed_listing_distinguishes_removal_from_matching_tools(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo],
    metadata_only: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    empty_listing: bool,
) -> None:
    async def connected(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        metadata_only.append(server.name)
        return ServerAudit(
            server=server,
            connection_status="connected",
            tools=[] if empty_listing else [shadow_inputs[3]],
        )

    monkeypatch.setattr(ServerConnector, "connect", connected)
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on:\n  drift: true\n")
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect", "--policy", str(policy)])
    assert result.exit_code == (2 if empty_listing else 0), result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert sorted(metadata_only) == ["fixture-a", "fixture-b"]
    assert report.coverage["pin_check"].state == "complete"
    for audit in report.audits:
        assert [(finding.tool_name, finding.status.value) for finding in audit.drift_findings] == (
            [(shadow_inputs[3].name, "removed")] if empty_listing else []
        )
    assert report.policy_result is not None
    assert report.policy_result.passed is not empty_listing


def test_shadow_connected_review_joins_pin_drift_and_fleet_findings(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str]
) -> None:
    paths = shadow_inputs[:3]
    original = {path: path.read_bytes() for path in paths}
    shadow_inputs[3].description = "Changed synthetic status description."
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect"])
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert sorted(metadata_only) == ["fixture-a", "fixture-b"]
    assert {finding.kind.value for finding in report.shadowing_findings} == {"exact"}
    assert {finding.status.value for audit in report.audits for finding in audit.drift_findings} == {
        "changed"
    }
    assert report.coverage["pin_check"].state == "complete"
    assert report.coverage["shadow_check"].state == "complete"
    assert {path: path.read_bytes() for path in paths} == original


@pytest.mark.parametrize("state", ["missing", "corrupt", "tampered", "missing-trust"])
def test_shadow_reports_unavailable_or_untrusted_baseline(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str], state: str, tmp_path: Path
) -> None:
    _, pins, trust, _ = shadow_inputs
    if state == "missing":
        pins.unlink()
    elif state == "corrupt":
        pins.write_text("servers: [")
    elif state == "missing-trust":
        trust.unlink()
    else:
        data = yaml.safe_load(pins.read_text())
        data["servers"]["fixture-a"]["tools"]["status"]["description"] = "tampered"
        pins.write_text(yaml.safe_dump(data))
    original = {path: path.read_bytes() for path in shadow_inputs[:3] if path.exists()}
    policy = tmp_path / "policy.yaml"
    policy.write_text("fail_on:\n  pin_integrity: true\n")
    result = CliRunner().invoke(
        cli.main, [*_args(shadow_inputs), "--connect", "--pin-min-sequence", "1", "--policy", str(policy)]
    )
    assert result.exit_code == 2, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.coverage["pin_check"].state in {"partial", "not_run"}
    assert any(warning.code == "pin_baseline_withheld" for warning in report.warnings)
    assert any(audit.pin_integrity_findings for audit in report.audits)
    assert report.policy_result is not None and not report.policy_result.passed
    assert {path: path.read_bytes() for path in shadow_inputs[:3] if path.exists()} == original


@pytest.mark.parametrize("minimum,exit_code", [(1, 0), (2, 0), (3, 2)])
def test_shadow_signed_sequence_gate(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str], minimum: int, exit_code: int
) -> None:
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--pin-min-sequence", str(minimum)])
    assert result.exit_code == exit_code, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.policy_result is not None
    assert report.policy_result.passed == (exit_code == 0)


def test_shadow_cli_minimum_cannot_lower_policy_minimum(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], tmp_path: Path
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("require:\n  pin_min_sequence: 3\n")
    result = CliRunner().invoke(
        cli.main, [*_args(shadow_inputs), "--pin-min-sequence", "1", "--policy", str(policy)]
    )
    assert result.exit_code == 2, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.policy_result is not None and not report.policy_result.passed


def test_shadow_local_fixture_lists_metadata_without_proxying(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp import ClientSession

    async def no_tool_calls(*args: object, **kwargs: object) -> None:
        raise AssertionError("shadow must only list metadata, never call tools")

    monkeypatch.setattr(ClientSession, "call_tool", no_tool_calls)
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect"])
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert report.servers_connected == 2
    assert report.servers_failed == 0
    assert {tool.name for audit in report.audits for tool in audit.tools} == {
        "read_file",
        "write_file",
        "execute_command",
    }
    assert report.shadowing_findings
    assert report.coverage["pin_check"].state == "complete"


@pytest.mark.parametrize("args", [[], ["--config", "missing.json"]])
def test_shadow_requires_explicit_inputs(args: list[str]) -> None:
    result = CliRunner().invoke(cli.main, ["shadow", *args])
    assert result.exit_code == 2


@pytest.mark.parametrize("option", ["--enforce", "--write"])
def test_shadow_has_no_enforcing_or_write_mode(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], option: str
) -> None:
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), option])
    assert result.exit_code == 2
    assert f"No such option '{option}'" in result.output


def test_shadow_invalid_config_stops_before_connection(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str]
) -> None:
    shadow_inputs[0].write_text("{")
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect"])
    assert result.exit_code == 1
    assert "Cannot complete shadow review (ValueError)" in result.output
    assert metadata_only == []


def test_shadow_read_only_verification_still_detects_recorded_rollback(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str]
) -> None:
    trust = shadow_inputs[2]
    data = json.loads(trust.read_text())
    data["servers"]["fixture-a"]["last_seen_pinned_at"] = "2099-01-01T00:00:00Z"
    trust.write_text(json.dumps(data))
    original = trust.read_bytes()
    result = CliRunner().invoke(cli.main, _args(shadow_inputs))
    assert result.exit_code == 0, result.output
    report = AuditReport.model_validate_json(result.stdout)
    assert any(warning.code == "pin_rolled_back" for warning in report.warnings)
    assert trust.read_bytes() == original


def test_shadow_terminal_surfaces_pin_warnings(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo], metadata_only: list[str]
) -> None:
    shadow_inputs[1].unlink()
    result = CliRunner().invoke(cli.main, _args(shadow_inputs)[:-1])
    assert result.exit_code == 2, result.output
    assert "pin baselines that cannot be trusted" in result.output


@pytest.mark.parametrize(
    ("policy_yaml", "error_type"),
    [
        ("require:\n  pin_min_sequence: 0\n", "ValueError"),
        ("max_risk: []\n", "TypeError"),
        ("max_risk: {synthetic-policy-value: []}\n", "TypeError"),
        ("max_risk: synthetic-policy-value\n", "ValueError"),
    ],
)
def test_shadow_invalid_policy_stops_before_connection(
    shadow_inputs: tuple[Path, Path, Path, ToolInfo],
    metadata_only: list[str],
    tmp_path: Path,
    policy_yaml: str,
    error_type: str,
) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_yaml)
    result = CliRunner().invoke(cli.main, [*_args(shadow_inputs), "--connect", "--policy", str(policy)])
    assert result.exit_code == 1
    assert result.output == f"Error: Cannot complete shadow review ({error_type}).\n"
    assert metadata_only == []
