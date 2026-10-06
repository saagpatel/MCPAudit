"""Synthetic P1-8 regressions for every explicit-config failure path."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from mcp_audit.api import parse_config, scan_config_only
from mcp_audit.cli import main
from mcp_audit.confighealth import config_health_findings
from mcp_audit.discovery import ConfigDiscoverer, ConfigParseError
from mcp_audit.discovery.claude_code import ClaudeCodeDiscoverer
from mcp_audit.discovery.claude_desktop import ClaudeDesktopDiscoverer
from mcp_audit.discovery.cursor import CursorDiscoverer
from mcp_audit.discovery.vscode import VSCodeDiscoverer
from mcp_audit.discovery.windsurf import WindsurfDiscoverer
from mcp_audit.engine import ScanOptions, _parse_extra_config, run_scan
from mcp_audit.models import ClientType

FIXTURES = Path(__file__).parent / "fixtures" / "config_paths"
DISCOVERERS = [
    ClaudeCodeDiscoverer,
    ClaudeDesktopDiscoverer,
    CursorDiscoverer,
    VSCodeDiscoverer,
    WindsurfDiscoverer,
]


@pytest.mark.parametrize(
    ("fixture", "name"),
    [("bad_vscode_format.json", "standalone"), ("bad_nested_servers_key.json", "embedded")],
)
def test_explicit_config_sniffs_vscode_maps(fixture: str, name: str) -> None:
    assert [server.name for server in _parse_extra_config(FIXTURES / fixture)] == [name]


@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
def test_malformed_entries_are_findings_with_healthy_sibling(
    discoverer_cls: type[ConfigDiscoverer],
) -> None:
    issues: list[ConfigParseError] = []
    servers = discoverer_cls().parse(FIXTURES / "bad_weird_types.json", issues)
    assert [server.name for server in servers] == ["healthy"]
    findings = config_health_findings(servers, issues)
    assert [(f.finding_type, f.server_name) for f in findings] == [
        ("malformed_server_entry", "broken"),
        ("malformed_server_entry", "scalar"),
    ]
    assert findings[0].details == ["command must be a string"]


@pytest.mark.anyio
async def test_explicit_config_carries_malformed_entry_findings() -> None:
    report = await run_scan(
        ScanOptions(skip_connect=True, config_only=True, extra_config=str(FIXTURES / "bad_weird_types.json"))
    )
    assert report.servers_discovered == 1
    assert {f.finding_type for f in report.config_health_findings} == {"malformed_server_entry"}


@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
def test_duplicate_keys_are_recorded_at_all_object_depths(
    discoverer_cls: type[ConfigDiscoverer],
) -> None:
    issues: list[ConfigParseError] = []
    servers = discoverer_cls().parse(FIXTURES / "bad_dupkeys.json", issues)
    assert len(servers) == 1
    assert servers[0].command == "echo"
    finding = config_health_findings(servers, issues)[0]
    assert finding.finding_type == "duplicate_config_key"
    assert "2 duplicate object key(s)" in finding.details[0]


@pytest.mark.anyio
async def test_explicit_config_carries_duplicate_key_finding() -> None:
    report = await run_scan(
        ScanOptions(skip_connect=True, config_only=True, extra_config=str(FIXTURES / "bad_dupkeys.json"))
    )
    assert report.config_health_findings[0].finding_type == "duplicate_config_key"


@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
def test_bomhome_configs_are_readable(tmp_path: Path, discoverer_cls: type[ConfigDiscoverer]) -> None:
    config = tmp_path / "bomhome.json"
    config.write_text('{"mcpServers": {"bom": {"command": "echo"}}}', encoding="utf-8-sig")
    assert discoverer_cls().parse(config)[0].name == "bom"
    assert _parse_extra_config(config)[0].name == "bom"


@pytest.mark.parametrize("layout", ["standalone", "settings"])
def test_vscode_jsonc_for_both_files(tmp_path: Path, layout: str) -> None:
    text = (FIXTURES / "vscode_jsonc.json").read_text()
    if layout == "settings":
        text = '{"mcp": ' + text + "}"
    config = tmp_path / ("settings.json" if layout == "settings" else "mcp.json")
    config.write_text(text)
    assert VSCodeDiscoverer().parse(config)[0].name == "jsonc"
    assert _parse_extra_config(config)[0].name == "jsonc"


def test_fakehome_discovers_fifty_vscode_servers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "fakehome"
    config = home / ".vscode" / "mcp.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps({"servers": {f"srv{i}": {"command": "echo"} for i in range(50)}}))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    issues: list[ConfigParseError] = []
    servers = VSCodeDiscoverer().discover(issues)
    assert len(servers) == 50
    assert all(server.client == ClientType.VSCODE and server.scope == "workstation" for server in servers)
    assert issues == []


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires os.mkfifo")
@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
def test_fifo_rejected_before_reading(tmp_path: Path, discoverer_cls: type[ConfigDiscoverer]) -> None:
    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    with patch.object(Path, "read_text", side_effect=AssertionError("must never read a FIFO")):
        with pytest.raises(ValueError, match="not a regular file"):
            _parse_extra_config(fifo)
        issues: list[ConfigParseError] = []
        with patch.object(discoverer_cls, "config_paths", return_value=[fifo]):
            assert discoverer_cls().discover(issues) == []
    assert config_health_findings([], issues)[0].finding_type == "config_parse_failure"
    assert issues[0].reason == "config path is not a regular file"


@pytest.mark.anyio
@pytest.mark.parametrize("fixture", ["bad_dupkeys.json", "bad_weird_types.json"])
async def test_in_memory_scan_preserves_same_config_diagnostics(fixture: str) -> None:
    path = FIXTURES / fixture
    memory = await scan_config_only(path.read_text(), source=str(path))
    file = await run_scan(ScanOptions(skip_connect=True, config_only=True, extra_config=str(path)))
    assert memory.config_health_findings == file.config_health_findings
    assert memory.servers_discovered == file.servers_discovered
    assert memory.coverage == file.coverage
    assert memory.coverage["config_health"].state == "partial"


@pytest.mark.parametrize(
    "text",
    [
        '{"projects": {}}',
        '{"projects": {"demo": {}}}',
        '{"projects": {"demo": {"servers": {"missed": {"command": "echo"}}}}}',
        '{"projects": {"demo": {"mcpServer": {"missed": {"command": "echo"}}}}}',
        '{"projects": {"demo": {"mcp": {"servers": {"missed": {"command": "echo"}}}}}}',
    ],
)
def test_projects_without_supported_server_maps_are_rejected(tmp_path: Path, text: str) -> None:
    config = tmp_path / "unsupported-project.json"
    config.write_text(text)
    with pytest.raises(ValueError, match="unsupported client config format"):
        _parse_extra_config(config)
    for data in (text, json.loads(text)):
        with pytest.raises(ValueError, match="unsupported client config format"):
            parse_config(data, parse_errors=[])


@pytest.mark.anyio
async def test_explicit_empty_project_server_map_is_valid(tmp_path: Path) -> None:
    config = tmp_path / "empty-project.json"
    text = '{"projects": {"demo": {"mcpServers": {}}}}'
    config.write_text(text)
    memory = await scan_config_only(text, source=str(config))
    file = await run_scan(ScanOptions(skip_connect=True, config_only=True, extra_config=str(config)))
    assert memory.servers_discovered == file.servers_discovered == 0
    assert memory.config_health_findings == file.config_health_findings == []
    assert memory.coverage == file.coverage
    assert memory.coverage["config_health"].state == "complete"


@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
@pytest.mark.parametrize(
    "entry",
    [{"url": []}, {"args": "wrong"}, {"args": [42]}, {"env": []}, {"headers": False}, {"type": {}}],
)
def test_wrong_field_types_never_disappear_silently(
    tmp_path: Path, discoverer_cls: type[ConfigDiscoverer], entry: dict[str, object]
) -> None:
    config = tmp_path / "wrong-type.json"
    config.write_text(json.dumps({"mcpServers": {"broken": entry}}))
    issues: list[ConfigParseError] = []
    assert discoverer_cls().parse(config, issues) == []
    assert config_health_findings([], issues)[0].finding_type == "malformed_server_entry"


@pytest.mark.parametrize("discoverer_cls", DISCOVERERS)
def test_parser_errors_do_not_echo_input(tmp_path: Path, discoverer_cls: type[ConfigDiscoverer]) -> None:
    config = tmp_path / "invalid.json"
    config.write_text('{"unexpected-literal-canary"')
    issues: list[ConfigParseError] = []
    with patch.object(discoverer_cls, "config_paths", return_value=[config]):
        assert discoverer_cls().discover(issues) == []
    assert "unexpected-literal-canary" not in str(config_health_findings([], issues))


@pytest.mark.parametrize(
    ("text", "error"),
    [
        ("", "empty config file"),
        ("{}", "no server map found in"),
        ('{"unsupported": {}}', "unsupported client config format"),
        ('{"mcpServers": []}', "server map is not an object"),
        ('{"mcp": {"servers": false}}', "server map is not an object"),
        ('{"mcp": false}', "mcp section is not an object"),
        ('{"projects": []}', "projects map is not an object"),
        ("null", "not an object"),
        ("{", "invalid JSON"),
        ("[" * 2000, "invalid JSON"),
    ],
)
def test_explicit_config_failure_paths(tmp_path: Path, text: str, error: str) -> None:
    config = tmp_path / "bad.json"
    config.write_text(text)
    with pytest.raises(ValueError, match=error):
        _parse_extra_config(config)


def test_explicit_config_missing_directory_unreadable_and_encoding(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not found"):
        _parse_extra_config(tmp_path / "missing.json")
    with pytest.raises(ValueError, match="not a regular file"):
        _parse_extra_config(tmp_path)
    config = tmp_path / "unreadable.json"
    config.touch()
    with patch.object(Path, "read_text", side_effect=PermissionError("synthetic permission denial")):
        with pytest.raises(ValueError, match="Failed to read"):
            _parse_extra_config(config)
    config.write_bytes(b"\xff")
    with pytest.raises(ValueError, match="invalid UTF-8 encoding"):
        _parse_extra_config(config)


@pytest.mark.parametrize(
    ("text", "message", "exit_code"),
    [
        ("", "empty config file", 1),
        ("{}", "unsupported client config format", 1),
        ('{"mcpServers": {}}', "Configured server maps are empty", 0),
        ('{"mcpServers": {"broken": false}}', "incomplete coverage", 0),
    ],
)
def test_cli_empty_states(tmp_path: Path, text: str, message: str, exit_code: int) -> None:
    config = tmp_path / "empty.json"
    config.write_text(text)
    result = CliRunner().invoke(
        main,
        ["scan", "--config", str(config), "--config-only", "--skip-connect", "--override-config", os.devnull],
    )
    assert result.exit_code == exit_code, result.output
    assert message in result.output


def test_cli_unreadable_empty_state(tmp_path: Path) -> None:
    config = tmp_path / "unreadable.json"
    config.touch()
    read_text = Path.read_text

    def read(path: Path, encoding: str | None = None, errors: str | None = None) -> str:
        if path == config:
            raise PermissionError("synthetic permission denial")
        return read_text(path, encoding=encoding, errors=errors)

    with patch.object(Path, "read_text", read):
        result = CliRunner().invoke(
            main,
            [
                "scan",
                "--config",
                str(config),
                "--config-only",
                "--skip-connect",
                "--override-config",
                os.devnull,
            ],
        )
    assert result.exit_code == 1
    assert "Failed to read" in result.output
