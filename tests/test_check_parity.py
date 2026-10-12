"""Acceptance contracts for check/scan parity, using synthetic input only."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit import check_cli, cli, engine, pinning
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, ResourceInfo, ServerAudit, ServerConfig
from mcp_audit.overrides import OverrideApplier
from mcp_audit.taxonomy import config_health_rule_id

ROOT = Path(__file__).resolve().parents[1]
SANDBOX = ROOT / "examples/sandbox/fixtures/synthetic-mcp-config.json"
DETECTORS = (
    "inject-check",
    "ssrf-check",
    "egress-check",
    "pin-check",
    "trifecta-check",
    "shadow-check",
    "escalation-check",
    "provenance-check",
    "integrity-check",
)


@pytest.fixture(autouse=True)
def isolated_review(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)


def _config(path: Path, *, args: list[str] | None = None) -> Path:
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": "never-launch-this-fixture",
                        "args": args or [],
                    }
                }
            }
        )
    )
    return path


@pytest.mark.parametrize("explicit_baseline", [False, True])
@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
@pytest.mark.parametrize("artifact", ["--output-json", "--sarif", "--html", "--card"])
@pytest.mark.parametrize(
    "consumer",
    [
        "pin-check",
        "escalation-check",
        "provenance-check",
        "integrity-check",
        "canary-check",
        "verify-artifacts",
        "download-artifacts",
        "policy-pins",
        "policy-sequence",
        "policy-integrity",
        "policy-server",
        "pin-min-sequence",
    ],
)
def test_baseline_consumers_reject_artifact_aliases_before_scan_or_write(
    explicit_baseline: bool,
    alias: str,
    artifact: str,
    consumer: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = Path.home() / ".mcp-audit-pins.yaml"
    monkeypatch.setattr(pinning, "DEFAULT_PIN_PATH", baseline)
    before = b"pins: {}\n"
    baseline.write_bytes(before)
    destination = baseline
    if alias != "direct":
        destination = tmp_path / "baseline-alias"
        if alias == "symlink":
            destination.symlink_to(baseline)
        else:
            destination.hardlink_to(baseline)
    config = _config(tmp_path / "fixture.json")
    args = ["check", "--config", str(config), "--json", artifact, str(destination)]
    other_output = tmp_path / "other-report"
    args.extend(["--sarif" if artifact == "--output-json" else "--output-json", str(other_output)])
    if explicit_baseline:
        args.extend(["--pin-file", str(baseline)])
    if consumer.startswith("policy-"):
        policy = tmp_path / "policy.yaml"
        policy.write_text(
            {
                "policy-pins": "require:\n  pins:\n    servers: [fixture]\n",
                "policy-sequence": "require:\n  pin_min_sequence: 1\n",
                "policy-integrity": "fail_on:\n  pin_integrity: true\n",
                "policy-server": "servers:\n  fixture:\n    require_pin: true\n",
            }[consumer]
        )
        args.extend(["--policy", str(policy)])
    elif consumer == "pin-min-sequence":
        args.extend(["--pin-min-sequence", "1"])
    else:
        args.append(f"--{consumer}")
    if consumer == "canary-check":
        args.extend(["--connect", "--server", "claude_code:workstation:fixture"])

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("baseline aliases must be rejected before scanning or writing")

    monkeypatch.setattr(check_cli, "run_scan", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == 2, result.output
    assert "aliases an input file" in result.stderr
    assert artifact in result.stderr
    assert "Scanned: no" in result.stderr
    assert "Written: none" in result.stderr
    assert baseline.read_bytes() == before
    assert destination.read_bytes() == before
    assert not other_output.exists()


@pytest.mark.parametrize("skip_connect", [False, True])
def test_static_project_connection_opt_in_is_rejected_before_discovery(
    skip_connect: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid connection scope must fail before discovery")

    monkeypatch.setattr(check_cli, "review_sources", forbidden)
    result = CliRunner().invoke(
        cli.main,
        ["check", "--connect-project-configs", "--json", *(["--skip-connect"] if skip_connect else [])],
    )
    assert result.exit_code == 2, result.output
    assert "--connect-project-configs requires --connect" in result.stderr


def test_static_project_config_retains_warning_and_sarif(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config(tmp_path / ".mcp.json")
    output = tmp_path / "report.sarif"

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static project checks must not launch or connect")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--client",
            "claude-code",
            "--override-config",
            "/dev/null",
            "--json",
            "--sarif",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["connection_mode"] == "skipped"
    assert report["audits"][0]["server"]["scope"] == "project"
    assert any(w["code"] == "project_config_not_connected" for w in report["warnings"])
    sarif = json.loads(output.read_text())
    assert any(
        notification["descriptor"]["id"] == "MCP-PROJECT-CONFIG-NOT-CONNECTED"
        for notification in sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    )


@pytest.mark.parametrize("detector", DETECTORS)
def test_detector_matches_scan_without_enabling_connections(
    detector: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("static detector flags must not launch or connect")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    baseline = tmp_path / "empty-pins.yaml"
    baseline.write_text("pins: {}\n")
    output = tmp_path / "scan.json"
    shared = [
        "--config",
        str(SANDBOX),
        "--override-config",
        "/dev/null",
        "--pin-file",
        str(baseline),
        f"--{detector}",
    ]
    scan = CliRunner().invoke(
        cli.main, ["scan", *shared, "--config-only", "--skip-connect", "--json", str(output)]
    )
    check = CliRunner().invoke(cli.main, ["check", *shared, "--json"])
    assert scan.exit_code == check.exit_code == 0, scan.output + check.output
    actual = json.loads(check.stdout)
    expected = json.loads(output.read_text())
    for payload in (actual, expected):
        payload.pop("scan_timestamp")
        payload.pop("scan_duration_seconds")
    assert actual == expected
    assert actual["connection_mode"] == "skipped"
    assert actual["coverage"][detector.replace("-", "_")]["state"] != "skipped"


@pytest.mark.parametrize("mode", ["verify_artifacts", "download_artifacts", "llm_analysis"])
def test_higher_reach_mode_is_forwarded_only_when_requested(
    mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[ScanOptions] = []

    async def bounded_scan(
        options: ScanOptions,
        *,
        servers: list[ServerConfig],
        override_applier: OverrideApplier,
        _allow_sharding: bool,
        **kwargs: object,
    ) -> AuditReport:
        captured.append(options)
        assert _allow_sharding
        # Verify CLI dispatch without making any live registry or LLM request.
        return await engine.run_scan(
            replace(options, verify_artifacts=False, download_artifacts=False, llm_analysis=False),
            servers=servers,
            override_applier=override_applier,
        )

    monkeypatch.setattr(check_cli, "run_scan", bounded_scan)
    config = _config(tmp_path / "fixture.json")
    for flags in ([], ["--" + mode.replace("_", "-")]):
        result = CliRunner().invoke(cli.main, ["check", "--config", str(config), "--json", *flags])
        assert result.exit_code == 0, result.output
        assert captured[-1].skip_connect
        assert getattr(captured[-1], mode) is bool(flags)
        for other in {"verify_artifacts", "download_artifacts", "llm_analysis"} - {mode}:
            assert not getattr(captured[-1], other)


def test_permission_overrides_and_ignores_match_scan(tmp_path: Path) -> None:
    override = tmp_path / "overrides.yaml"
    override.write_text(
        "overrides:\n  - server: '*'\n    tool: '*'\n    permissions:\n      shell_execution: true\n"
        "ignore:\n  - rule: MCP004\n    server: '*'\n    tool: '*'\n    reason: synthetic exception\n"
    )
    scan_path = tmp_path / "scan.json"
    shared = ["--config", str(SANDBOX), "--override-config", str(override)]
    scan = CliRunner().invoke(
        cli.main, ["scan", *shared, "--config-only", "--skip-connect", "--json", str(scan_path)]
    )
    check = CliRunner().invoke(cli.main, ["check", *shared, "--json"])
    assert scan.exit_code == check.exit_code == 0, scan.output + check.output
    actual = json.loads(check.stdout)
    expected = json.loads(scan_path.read_text())
    for payload in (actual, expected):
        payload.pop("scan_timestamp")
        payload.pop("scan_duration_seconds")
    assert actual == expected
    assert any(p["confidence"] == "manual" for a in actual["audits"] for p in a["permissions"])
    assert actual["suppressed"]


def test_discovery_loads_saved_permission_overrides(tmp_path: Path) -> None:
    config_dir = Path.home() / ".cursor"
    config_dir.mkdir()
    _config(config_dir / "mcp.json")
    (Path.home() / ".mcp-audit.yaml").write_text(
        "overrides:\n  - server: fixture\n    tool: '*'\n    permissions:\n      network: true\n"
    )
    result = CliRunner().invoke(cli.main, ["check", "--project", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    permissions = json.loads(result.stdout)["audits"][0]["permissions"]
    assert any(p["category"] == "network" and p["confidence"] == "manual" for p in permissions)


def test_policy_and_cli_allowlists_merge_per_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def connected(self: ServerConnector, server: ServerConfig) -> ServerAudit:
        return ServerAudit(
            server=server,
            connection_status="connected",
            resources=[
                ResourceInfo(uri=f"https://{host}/data")
                for host in ("cli.example", "policy.example", "server.example", "outside.example")
            ],
        )

    monkeypatch.setattr(ServerConnector, "connect", connected)
    config = _config(tmp_path / "fixture.json")
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "egress_allowlist: [policy.example]\nmulti_tenant_hosts: [policy.example]\n"
        "servers:\n  fixture:\n    egress_allowlist: [server.example]\n"
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect",
            "--server",
            "claude_code:workstation:fixture",
            "--connect-project-configs",
            "--egress-check",
            "--egress-allowlist",
            "cli.example",
            "--multi-tenant-hosts",
            "cli.example",
            "--policy",
            str(policy),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    findings = json.loads(result.stdout)["audits"][0]["egress_findings"]
    assert {(f["destination_host"], f["kind"]) for f in findings} == {
        ("cli.example", "trusted_destination_residual"),
        ("policy.example", "trusted_destination_residual"),
        ("outside.example", "destination_outside_allowlist"),
    }


@pytest.mark.parametrize("redact", [False, True])
def test_identifier_redaction_applies_to_all_artifacts_and_json_stdout(
    redact: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: "synthetic-host")
    config_path = tmp_path / "Users/example-user/synthetic-host/fixture.json"
    config_path.parent.mkdir(parents=True)
    config = _config(config_path, args=["/Users/example-user/synthetic-host"])
    override = tmp_path / "override.yaml"
    override.write_text(
        "overrides:\n  - server: fixture\n    tool: '*'\n    permissions:\n      network: true\n"
        "    notes: synthetic-host /Users/example-user/fixture\n"
    )
    outputs = {ext: tmp_path / f"report.{ext}" for ext in ("json", "sarif", "html")}
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--override-config",
            str(override),
            "--json",
            "--output-json",
            str(outputs["json"]),
            "--sarif",
            str(outputs["sarif"]),
            "--html",
            str(outputs["html"]),
            "--show-host",
            *(["--redact"] if redact else []),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == json.loads(outputs["json"].read_text())
    for content in (result.stdout, *(path.read_text() for path in outputs.values())):
        assert ("synthetic-host" in content) is not redact
        assert ("example-user" in content) is not redact


@pytest.mark.parametrize("profile", ["compatibility", "extended"])
def test_sarif_profile_emits_configuration_health_only_when_extended(
    profile: str,
    tmp_path: Path,
) -> None:
    config = ROOT / "tests/fixtures/config_health/shell_remote_arg_config.json"
    output = tmp_path / "report.sarif"
    result = CliRunner().invoke(
        cli.main,
        ["check", "--config", str(config), "--sarif", str(output), "--sarif-profile", profile, "--json"],
    )
    assert result.exit_code == 0, result.output
    findings = json.loads(result.stdout)["config_health_findings"]
    assert findings
    rules = {config_health_rule_id(f["finding_type"]) for f in findings}
    emitted = {row["ruleId"] for row in json.loads(output.read_text())["runs"][0]["results"]}
    assert bool(rules & emitted) is (profile == "extended")


def test_verbose_renders_per_tool_detail_without_source_listing() -> None:
    base = CliRunner().invoke(cli.main, ["check", "--config", str(SANDBOX)])
    verbose = CliRunner().invoke(cli.main, ["check", "--config", str(SANDBOX), "--verbose"])
    assert base.exit_code == verbose.exit_code == 0
    assert "Capability exposure (legacy" not in base.output
    assert "Capability exposure (legacy" in verbose.output
    assert "Unsupported source: Codex" not in verbose.output


def test_tuning_and_selected_pin_file_reach_the_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[ScanOptions] = []

    async def bounded_scan(
        options: ScanOptions,
        *,
        servers: list[ServerConfig],
        override_applier: OverrideApplier,
        _allow_sharding: bool,
        **kwargs: object,
    ) -> AuditReport:
        captured.append(options)
        assert _allow_sharding
        return await engine.run_scan(options, servers=servers, override_applier=override_applier)

    monkeypatch.setattr(check_cli, "run_scan", bounded_scan)
    pin_file = tmp_path / "empty-pins.yaml"
    pin_file.write_text("servers: {}\n")
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(SANDBOX),
            "--pin-file",
            str(pin_file),
            "--pin-check",
            "--timeout",
            "7",
            "--max-concurrency",
            "3",
            "--ssrf-check",
            "--ssrf-allowlist",
            "trusted.example",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert captured[0].timeout == 7
    assert captured[0].max_concurrency == 3
    assert captured[0].pin_file == pin_file
    assert captured[0].ssrf_allowlist == "trusted.example"
    assert not captured[0].connect_project_configs
    assert captured[0].skip_connect


@pytest.mark.parametrize(
    "args",
    [
        ["--skip-connect", "--connect", "--server", "claude_code:workstation:fixture"],
        ["--config-only"],
        ["--config-only", "--config", str(SANDBOX), "--include-discovered"],
        ["--canary-check", "--config", str(SANDBOX)],
        ["--canary-check", "--connect", "--server", "claude_code:workstation:fixture"],
        [
            "--canary-check",
            "--config",
            str(SANDBOX),
            "--include-discovered",
            "--connect",
            "--server",
            "claude_code:workstation:fixture",
        ],
        ["--canary-calls", "0"],
        ["--canary-calls", "101"],
        ["--canary-identities", "0"],
        ["--canary-identities", "3"],
        ["--max-concurrency", "0"],
        ["--sarif-profile", "unknown"],
    ],
)
def test_invalid_scope_or_limits_reject_before_discovery(
    args: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid options must fail before discovery")

    monkeypatch.setattr(check_cli, "review_sources", forbidden)
    result = CliRunner().invoke(cli.main, ["check", *args])
    assert result.exit_code == 2, result.output


def test_hidden_flags_are_noops_and_keep_explicit_file_static() -> None:
    base = CliRunner().invoke(cli.main, ["check", "--config", str(SANDBOX), "--json"])
    compat = CliRunner().invoke(
        cli.main, ["check", "--config", str(SANDBOX), "--json", "--skip-connect", "--config-only"]
    )
    assert base.exit_code == compat.exit_code == 0
    actual = json.loads(compat.stdout)
    expected = json.loads(base.stdout)
    for payload in (actual, expected):
        payload.pop("scan_timestamp")
        payload.pop("scan_duration_seconds")
    assert actual == expected
    help_result = CliRunner().invoke(cli.main, ["check", "--help"])
    assert "--skip-connect" not in help_result.output
    assert "--config-only" not in help_result.output


def test_canary_controls_use_only_selected_local_fixture(tmp_path: Path) -> None:
    config = tmp_path / "fixture.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fixture": {
                        "command": sys.executable,
                        "args": [
                            str(ROOT / "tests/fixtures/deadbugz_server.py"),
                            "flip",
                        ],
                    },
                    "unselected": {"command": "never-launch-this-fixture"},
                }
            }
        )
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--connect",
            "--server",
            "claude_code:workstation:fixture",
            "--canary-check",
            "--canary-calls",
            "4",
            "--canary-identities",
            "1",
            "--canary-safe-tool",
            "fixture/status",
            "--canary-safe-tool",
            "unselected/status",
            "--timeout",
            "15",
            "--max-concurrency",
            "1",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["servers_discovered"] == report["servers_connected"] == 1
    canary = report["audits"][0]["canary"]
    assert canary["completed_calls"] == 4
    assert report["audits"][0]["drift_findings"][0]["severity"] == "high"
