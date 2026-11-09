from __future__ import annotations

import sys
from types import ModuleType

import pytest

from redteam.chains.__main__ import main
from redteam.chains.discovery import DEFAULT_COLLECTORS, discover_servers


class _ShadowModule(ModuleType):
    discover_all: object


def _shadow(monkeypatch: pytest.MonkeyPatch, discover_all: object) -> list[str]:
    facade = _ShadowModule("shadow_mcp")
    facade.discover_all = discover_all
    collectors = ModuleType("shadow_mcp.collectors")
    constructed: list[str] = []
    for name in (*DEFAULT_COLLECTORS, "ClaudeCode"):

        def factory(collector_name: str = name) -> str:
            constructed.append(collector_name)
            return collector_name

        setattr(collectors, name, factory)
    monkeypatch.setitem(sys.modules, "shadow_mcp", facade)
    monkeypatch.setitem(sys.modules, "shadow_mcp.collectors", collectors)
    return constructed


def test_discovery_only_uses_allowlisted_collectors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[object]] = []

    def discover_all(*, collectors: list[object]) -> list[dict[str, object]]:
        calls.append(collectors)
        return [
            {
                "name": "filesystem",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                "env": {"TOKEN": "private-value"},
            }
        ]

    constructed = _shadow(monkeypatch, discover_all)
    servers = discover_servers()
    assert constructed == list(DEFAULT_COLLECTORS)
    assert calls == [list(DEFAULT_COLLECTORS)]
    assert servers[0].source == "catalog"
    assert servers[0].env_keys == ("TOKEN",)
    assert "private-value" not in repr(servers)


def test_claude_code_requires_explicit_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[object]] = []

    async def discover_all(*, collectors: list[object]) -> list[object]:
        calls.append(collectors)
        return []

    constructed = _shadow(monkeypatch, discover_all)
    assert discover_servers(include_claude_code=True) == []
    assert constructed == [*DEFAULT_COLLECTORS, "ClaudeCode"]
    assert calls == [[*DEFAULT_COLLECTORS, "ClaudeCode"]]


def test_incompatible_discovery_fails_before_calling_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def discover_all() -> list[object]:
        calls.append(True)
        return []

    constructed = _shadow(monkeypatch, discover_all)
    with pytest.raises(ValueError, match="explicit collectors"):
        discover_servers()
    assert calls == []
    assert constructed == []


def test_missing_collector_never_runs_partial_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def discover_all(*, collectors: list[object]) -> list[object]:
        calls.append(True)
        return []

    _shadow(monkeypatch, discover_all)
    delattr(sys.modules["shadow_mcp.collectors"], "ProjectMcpJson")
    with pytest.raises(ValueError, match="ProjectMcpJson"):
        discover_servers()
    assert calls == []


def test_discovered_duplicate_names_are_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    def discover_all(*, collectors: list[object]) -> dict[str, object]:
        return {"servers": [{"name": "same", "command": "one"}, {"name": "same", "command": "two"}]}

    _shadow(monkeypatch, discover_all)
    servers = discover_servers()
    assert [server.name for server in servers] == ["same [discovered entry 1]", "same [discovered entry 2]"]


def test_missing_shadow_cli_message(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "shadow_mcp", None)
    assert main(["run", "--discover"]) == 2
    assert capsys.readouterr().err.strip() == "install shadow-mcp: uv run --with <path-to-shadow-mcp> ..."


def test_cli_rejects_claude_code_opt_in_with_explicit_config() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["run", "--config", "synthetic.json", "--include-claude-code"])
    assert exc.value.code == 2
