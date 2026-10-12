"""Fixture-backed config-health coverage for 1.5 evidence intake."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit import confighealth
from mcp_audit.confighealth import config_health_findings
from mcp_audit.discovery import ConfigParseError
from mcp_audit.discovery.claude_code import ClaudeCodeDiscoverer
from mcp_audit.models import ClientType, ConfigHealthSeverity
from tests.conftest import make_server_config

CONFIG_HEALTH_FIXTURES = Path("tests/fixtures/config_health")


def test_command_path_reuse_keeps_each_existence_check_live(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "synthetic-binary"
    binary.write_text("")
    original_path, original_exists = Path, Path.exists
    parsed: list[str] = []

    def counted_path(value: str) -> Path:
        parsed.append(value)
        return original_path(value)

    def exists(path: Path) -> bool:
        result = original_exists(path)
        if path == binary and result:
            binary.unlink()
        return result

    monkeypatch.setattr(confighealth, "Path", counted_path)
    monkeypatch.setattr(Path, "exists", exists)
    servers = [make_server_config(name=name, command=str(binary)) for name in ("first", "second")]
    findings = config_health_findings(servers)
    assert parsed == [str(binary)]
    assert [(finding.finding_type, finding.server_name) for finding in findings] == [
        ("missing_local_binary", "second")
    ]


def test_unique_names_need_no_conflict_definition_summaries(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_summary(*args: object) -> str:
        pytest.fail("A unique name cannot have conflicting definitions")

    monkeypatch.setattr(confighealth, "_server_definition_summary", unexpected_summary)
    servers = [make_server_config(name=f"fixture-{i}", command="fixture") for i in range(100)]
    assert config_health_findings(servers) == []


def _finding_types(fixture_name: str) -> set[str]:
    servers = ClaudeCodeDiscoverer().parse(CONFIG_HEALTH_FIXTURES / fixture_name)
    return {finding.finding_type for finding in config_health_findings(servers)}


def test_local_shadowing_fixture_covers_current_config_health_signals() -> None:
    assert _finding_types("local_shadowing_config.json") == {
        "conflicting_scope_server_name",
        "conflicting_server_definition",
        "duplicate_server_name",
        "package_runner_source_review",
    }


def test_remote_credentials_fixture_covers_current_config_health_signals() -> None:
    assert _finding_types("remote_credentials_config.json") == {
        "credential_heavy_config",
        "remote_endpoint",
    }


def test_shell_remote_arg_fixture_covers_current_config_health_signals() -> None:
    assert _finding_types("shell_remote_arg_config.json") == {
        "remote_url_argument",
        "shell_wrapper_launch",
    }


def test_config_health_fixtures_do_not_expose_credential_values() -> None:
    secret_markers = {
        "Bearer redacted",
        "ghp_redacted_global",
        "ghp_redacted_project",
        "redacted",
    }

    for fixture_path in CONFIG_HEALTH_FIXTURES.glob("*.json"):
        servers = ClaudeCodeDiscoverer().parse(fixture_path)
        findings = config_health_findings(servers)
        rendered = " ".join(
            [
                *(str(server.model_dump()) for server in servers),
                *(finding.model_dump_json() for finding in findings),
            ]
        )
        for marker in secret_markers:
            assert marker not in rendered


def test_parse_errors_surface_as_high_findings() -> None:
    errors = [
        ConfigParseError(
            path="/home/user/.cursor/mcp.json",
            client=ClientType.CURSOR,
            reason="Expecting value: line 1 column 1 (char 0)",
        )
    ]
    findings = config_health_findings([], parse_errors=errors)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "config_parse_failure"
    assert finding.severity is ConfigHealthSeverity.HIGH
    assert "/home/user/.cursor/mcp.json" in finding.summary
    assert "cursor" in finding.summary
