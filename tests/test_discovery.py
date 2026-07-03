"""Unit tests for config discoverers."""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.discovery import ConfigDiscoverer, ConfigParseError, discover_all_configs
from mcp_audit.discovery.claude_code import ClaudeCodeDiscoverer
from mcp_audit.discovery.claude_desktop import ClaudeDesktopDiscoverer
from mcp_audit.discovery.cursor import CursorDiscoverer
from mcp_audit.discovery.vscode import VSCodeDiscoverer
from mcp_audit.discovery.windsurf import WindsurfDiscoverer
from mcp_audit.models import ClientType, TransportType

# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


class TestClaudeCodeDiscoverer:
    def test_parses_global_stdio_server(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)

        names = {s.name for s in servers}
        assert "filesystem" in names

        fs = next(s for s in servers if s.name == "filesystem")
        assert fs.client == ClientType.CLAUDE_CODE
        assert fs.transport == TransportType.STDIO
        assert fs.command == "npx"
        assert fs.args == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        assert fs.project_path is None

    def test_parses_global_http_server(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)

        http_srv = next(s for s in servers if s.name == "github-http")
        assert http_srv.transport == TransportType.HTTP
        assert http_srv.url == "https://api.example.com/mcp"
        # Header KEY names captured — never values
        assert set(http_srv.headers_keys) == {"Authorization", "X-Custom-Header"}
        # No credential values in the model
        assert "Bearer REDACTED" not in str(http_srv.model_dump())

    def test_env_keys_captured_never_values(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)

        fs = next(s for s in servers if s.name == "filesystem")
        assert "NODE_ENV" in fs.env_keys

        # Ensure no values leaked
        dumped = str(fs.model_dump())
        assert "production" not in dumped

    def test_parses_project_scoped_server(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)

        project_srv = next(s for s in servers if s.name == "project-db")
        assert project_srv.project_path == "/Users/dev/my-project"
        assert set(project_srv.env_keys) == {"DATABASE_URL", "SECRET_KEY"}
        assert project_srv.command == "python"

    def test_empty_project_mcp_servers_skipped(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)

        # /Users/dev/another-project has empty mcpServers — should not appear
        project_paths = {s.project_path for s in servers}
        assert "/Users/dev/another-project" not in project_paths

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        discoverer = ClaudeCodeDiscoverer()
        with patch.object(ClaudeCodeDiscoverer, "config_paths", return_value=[tmp_path / "nonexistent.json"]):
            assert discoverer.discover() == []

    def test_total_server_count(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_code_config.json"
        discoverer = ClaudeCodeDiscoverer()
        servers = discoverer.parse(config)
        # 2 global + 1 project-scoped
        assert len(servers) == 3

    def test_config_paths_includes_repo_local_mcp_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        paths = ClaudeCodeDiscoverer().config_paths()
        assert tmp_path / ".mcp.json" in paths

    def test_parses_repo_local_mcp_json(self, tmp_path: Path) -> None:
        # Claude Code's project-shared `.mcp.json` is a top-level mcpServers map.
        config = tmp_path / ".mcp.json"
        config.write_text(
            json.dumps({"mcpServers": {"repo-fs": {"command": "npx", "args": ["-y", "srv", "."]}}}),
            encoding="utf-8",
        )
        servers = ClaudeCodeDiscoverer().parse(config)
        assert {s.name for s in servers} == {"repo-fs"}
        repo_fs = servers[0]
        assert repo_fs.client == ClientType.CLAUDE_CODE
        assert repo_fs.command == "npx"
        assert repo_fs.project_path is None


# ---------------------------------------------------------------------------
# Claude Desktop
# ---------------------------------------------------------------------------


class TestClaudeDesktopDiscoverer:
    def test_parses_stdio_servers(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_desktop_config.json"
        discoverer = ClaudeDesktopDiscoverer()
        servers = discoverer.parse(config)

        assert len(servers) == 2
        names = {s.name for s in servers}
        assert names == {"sequential-thinking", "brave-search"}

    def test_all_servers_are_stdio(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_desktop_config.json"
        discoverer = ClaudeDesktopDiscoverer()
        servers = discoverer.parse(config)

        for s in servers:
            assert s.transport == TransportType.STDIO
            assert s.client == ClientType.CLAUDE_DESKTOP
            assert s.project_path is None

    def test_env_keys_captured(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "claude_desktop_config.json"
        discoverer = ClaudeDesktopDiscoverer()
        servers = discoverer.parse(config)

        brave = next(s for s in servers if s.name == "brave-search")
        assert brave.env_keys == ["BRAVE_API_KEY"]
        assert "REDACTED" not in str(brave.model_dump())

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        discoverer = ClaudeDesktopDiscoverer()
        with patch.object(ClaudeDesktopDiscoverer, "config_paths", return_value=[tmp_path / "missing.json"]):
            assert discoverer.discover() == []


# ---------------------------------------------------------------------------
# Cursor
# ---------------------------------------------------------------------------


class TestCursorDiscoverer:
    def test_parses_jsonc_with_comments_and_trailing_commas(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "cursor_mcp.json"
        discoverer = CursorDiscoverer()
        servers = discoverer.parse(config)

        assert len(servers) == 1
        srv = servers[0]
        assert srv.name == "shell-runner"
        assert srv.client == ClientType.CURSOR
        assert srv.transport == TransportType.STDIO
        assert srv.command == "node"
        assert srv.env_keys == ["SHELL_ALLOWED_DIRS"]

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        discoverer = CursorDiscoverer()
        with patch.object(CursorDiscoverer, "config_paths", return_value=[tmp_path / "missing.json"]):
            assert discoverer.discover() == []


# ---------------------------------------------------------------------------
# VS Code
# ---------------------------------------------------------------------------


class TestVSCodeDiscoverer:
    def test_parses_standalone_mcp_json(self, fixtures_dir: Path) -> None:
        config = fixtures_dir / "vscode_mcp.json"
        discoverer = VSCodeDiscoverer()
        servers = discoverer.parse(config)

        assert len(servers) == 1
        srv = servers[0]
        assert srv.name == "memory"
        assert srv.client == ClientType.VSCODE
        assert srv.transport == TransportType.STDIO
        assert srv.command == "npx"

    def test_parses_settings_json_mcp_section(self, tmp_path: Path) -> None:
        settings = tmp_path / "settings.json"
        settings.write_text(
            '{"mcp": {"servers": {"my-server": {"command": "python", "args": ["-m", "server"]}}}}'
        )
        discoverer = VSCodeDiscoverer()
        servers = discoverer.parse(settings)

        assert len(servers) == 1
        assert servers[0].name == "my-server"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        discoverer = VSCodeDiscoverer()
        with patch.object(VSCodeDiscoverer, "config_paths", return_value=[tmp_path / "missing.json"]):
            assert discoverer.discover() == []


# ---------------------------------------------------------------------------
# Windsurf
# ---------------------------------------------------------------------------


class TestWindsurfDiscoverer:
    def test_parses_windsurf_config(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp_config.json"
        config.write_text('{"mcpServers": {"ws-tool": {"command": "node", "args": ["server.js"]}}}')
        discoverer = WindsurfDiscoverer()
        servers = discoverer.parse(config)

        assert len(servers) == 1
        assert servers[0].name == "ws-tool"
        assert servers[0].client == ClientType.WINDSURF

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        discoverer = WindsurfDiscoverer()
        with patch.object(WindsurfDiscoverer, "config_paths", return_value=[tmp_path / "missing.json"]):
            assert discoverer.discover() == []


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


class TestDiscoverAllConfigs:
    def test_client_filter_runs_only_matching_discoverer(self, fixtures_dir: Path, tmp_path: Path) -> None:
        """Only ClaudeCodeDiscoverer should run when filtering to claude_code."""
        with (
            patch.object(
                ClaudeCodeDiscoverer,
                "config_paths",
                return_value=[fixtures_dir / "claude_code_config.json"],
            ),
            patch.object(
                ClaudeDesktopDiscoverer,
                "config_paths",
                return_value=[tmp_path / "nonexistent.json"],
            ),
        ):
            servers = discover_all_configs([ClientType.CLAUDE_CODE])

        assert all(s.client == ClientType.CLAUDE_CODE for s in servers)
        assert len(servers) == 3

    def test_deduplication(self, fixtures_dir: Path) -> None:
        """Running the same discoverer twice should not produce duplicates."""
        with patch.object(
            ClaudeDesktopDiscoverer,
            "config_paths",
            return_value=[fixtures_dir / "claude_desktop_config.json"],
        ):
            # Simulate two desktop discoverers by running twice
            from mcp_audit.discovery.claude_desktop import ClaudeDesktopDiscoverer as D

            d = D()
            first = d.discover()
            second = d.discover()
            combined_names = [s.name for s in first + second]

        # Raw combination has duplicates — aggregator deduplicates
        assert len(combined_names) > len(set(combined_names))

        # But discover_all_configs deduplicates
        with patch.object(
            ClaudeDesktopDiscoverer,
            "config_paths",
            return_value=[fixtures_dir / "claude_desktop_config.json"],
        ):
            result = discover_all_configs([ClientType.CLAUDE_DESKTOP])

        result_names = [s.name for s in result]
        assert len(result_names) == len(set(result_names))

    def test_returns_empty_when_no_configs_found(self, tmp_path: Path) -> None:
        missing = tmp_path / "nothing.json"
        with (
            patch.object(ClaudeCodeDiscoverer, "config_paths", return_value=[missing]),
            patch.object(ClaudeDesktopDiscoverer, "config_paths", return_value=[missing]),
            patch.object(CursorDiscoverer, "config_paths", return_value=[missing]),
            patch.object(VSCodeDiscoverer, "config_paths", return_value=[missing]),
            patch.object(WindsurfDiscoverer, "config_paths", return_value=[missing]),
        ):
            assert discover_all_configs() == []


# ---------------------------------------------------------------------------
# Parse-failure surfacing
# ---------------------------------------------------------------------------

_ALL_DISCOVERERS = [
    ClaudeCodeDiscoverer,
    ClaudeDesktopDiscoverer,
    CursorDiscoverer,
    VSCodeDiscoverer,
    WindsurfDiscoverer,
]


class TestParseFailureSurfacing:
    @pytest.mark.parametrize("discoverer_cls", _ALL_DISCOVERERS)
    def test_unparseable_config_raises_config_parse_error(
        self, tmp_path: Path, discoverer_cls: type[ConfigDiscoverer]
    ) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text('{"mcpServers": {')  # truncated mid-save
        with pytest.raises(ConfigParseError) as excinfo:
            discoverer_cls().parse(broken)
        assert excinfo.value.path == str(broken)
        assert excinfo.value.reason

    @pytest.mark.parametrize("discoverer_cls", _ALL_DISCOVERERS)
    def test_non_object_top_level_raises_config_parse_error(
        self, tmp_path: Path, discoverer_cls: type[ConfigDiscoverer]
    ) -> None:
        broken = tmp_path / "list.json"
        broken.write_text('["not", "a", "config"]')
        with pytest.raises(ConfigParseError):
            discoverer_cls().parse(broken)

    def test_discover_collects_errors_and_keeps_scanning(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{")
        good = tmp_path / "good.json"
        good.write_text(json.dumps({"mcpServers": {"ok": {"command": "echo"}}}))
        errors: list[ConfigParseError] = []
        with patch.object(CursorDiscoverer, "config_paths", return_value=[broken, good]):
            servers = CursorDiscoverer().discover(parse_errors=errors)
        assert [server.name for server in servers] == ["ok"]
        assert [error.path for error in errors] == [str(broken)]

    def test_discover_without_accumulator_warns(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("{")
        with (
            patch.object(CursorDiscoverer, "config_paths", return_value=[broken]),
            caplog.at_level(logging.WARNING, logger="mcp_audit.discovery.base"),
        ):
            assert CursorDiscoverer().discover() == []
        assert any("broken.json" in record.getMessage() for record in caplog.records)

    def test_unresolvable_config_paths_skip_discoverer_not_sweep(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # Path.cwd() raises OSError when the working directory was deleted;
        # one client's path resolution failing must not crash the whole sweep.
        with (
            patch.object(CursorDiscoverer, "config_paths", side_effect=OSError("cwd was deleted")),
            caplog.at_level(logging.WARNING, logger="mcp_audit.discovery.base"),
        ):
            assert CursorDiscoverer().discover() == []
        assert any("cannot resolve config paths" in r.getMessage() for r in caplog.records)

    def test_discover_all_configs_threads_parse_errors(self, tmp_path: Path) -> None:
        broken = tmp_path / "broken.json"
        broken.write_text("definitely not json")
        errors: list[ConfigParseError] = []
        with patch.object(CursorDiscoverer, "config_paths", return_value=[broken]):
            servers = discover_all_configs([ClientType.CURSOR], parse_errors=errors)
        assert servers == []
        assert len(errors) == 1
        assert errors[0].client is ClientType.CURSOR
