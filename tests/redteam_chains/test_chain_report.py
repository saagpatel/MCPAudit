from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from redteam.catalog import load_catalog
from redteam.chains.__main__ import main
from redteam.chains.pairs import ConfiguredServer, load_config, pair_servers
from redteam.chains.report import build_report, to_json, to_markdown
from redteam.chains.reproduce import ReproductionResult
from redteam.surface import ServerSurface, SurfaceTool

FIXTURES = Path("redteam/fixtures/servers/configs")


def test_explicit_provenance_cannot_leak_contents_or_claim_verification() -> None:
    server = ConfiguredServer(
        "synthetic",
        ServerSurface(
            server_name="synthetic",
            source="catalog",
            tools=[SurfaceTool(name="write_file")],
            provenance="synthetic-private-file-contents",
            unverified=False,
        ),
        source="explicit",
    )
    report = build_report([server])
    encoded = to_json(report)
    assert "synthetic-private-file-contents" not in encoded + to_markdown(report)
    assert json.loads(encoded)["servers"][0]["unverified"] is True


def test_report_is_stable_and_metadata_only(tmp_path: Path) -> None:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/synthetic/repo"],
                        "env": {"SYNTHETIC_TOKEN": "secret-value-never-printed"},
                    },
                    "git": {"command": "uvx", "args": ["mcp-server-git", "-r", "/synthetic/repo"]},
                    "unknown": {"command": "secret-argument-never-printed"},
                }
            }
        ),
        encoding="utf-8",
    )
    report = build_report(load_config(path))
    encoded = to_json(report)
    assert encoded == to_json(build_report(load_config(path)))
    decoded = json.loads(encoded)
    assert decoded["ranked"][0]["template"] == "git-clean-filter"
    assert decoded["unknown_surfaces"] == ["unknown"]
    assert "SYNTHETIC_TOKEN" in encoded
    for private in ("secret-value-never-printed", "secret-argument-never-printed", "/synthetic/repo"):
        assert private not in encoded
    assert "input_schema" not in encoded
    assert "description" not in encoded
    assert "git-clean-filter" in to_markdown(report)
    assert "catalog (unversioned/unverified)" in encoded


def test_cli_writes_both_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    json_path = tmp_path / "out" / "report.json"
    md_path = tmp_path / "out" / "report.md"
    assert (
        main(
            [
                "run",
                "--config",
                str(FIXTURES / "git-plus-filesystem.json"),
                "--json",
                str(json_path),
                "--md",
                str(md_path),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == md_path.read_text()
    assert json.loads(json_path.read_text())["ranked"][0]["template"] == "git-clean-filter"
    markdown = md_path.read_text()
    assert "| Steps |" in markdown
    tools = r"filesystem.edit_file\|move_file\|write_file"
    assert f"{tools} → git.git_add" in markdown
    assert f"{tools} → git.git_commit" in markdown
    rows = json.loads(json_path.read_text())["ranked"]
    assert [row["template"] for row in rows] == ["git-clean-filter", "git-hook"]
    assert rows[0]["alternative_tool_pairs"] == [
        {"writer_tool": "edit_file", "executor_tool": "git_add"},
        {"writer_tool": "move_file", "executor_tool": "git_add"},
        {"writer_tool": "write_file", "executor_tool": "git_add"},
    ]


def test_only_top_supported_chain_reproduced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def canary() -> ReproductionResult:
        calls.append(True)
        return ReproductionResult("SKIPPED", "nested sandbox unavailable", teardown_confirmed=True)

    monkeypatch.setattr("redteam.chains.report.reproduce_git_clean_filter", canary)
    report = build_report(load_config(FIXTURES / "git-plus-filesystem.json"), reproduce=True)
    assert calls == [True]
    reproduction = report["reproduction"]
    assert isinstance(reproduction, dict)
    assert reproduction["rank"] == 1
    assert reproduction["template"] == "git-clean-filter"
    assert reproduction["provenance_flag"] == "MOCKED"
    assert reproduction["status"] == "SKIPPED"
    assert "nested sandbox unavailable" in to_markdown(report)
    assert "not an exploit against a live MCP server" in to_markdown(report)


def test_reproduction_identifies_supported_chain_below_unsupported_top(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chains = pair_servers(load_config(FIXTURES / "git-plus-filesystem.json"))
    supported = next(chain for chain in chains if chain.template.name == "git-clean-filter")
    unsupported = next(chain for chain in chains if chain.template.name == "git-hook")
    supported = replace(supported, template=replace(supported.template, automaticity="user_action"))
    unsupported = replace(
        unsupported,
        template=replace(unsupported.template, name="unregistered-high-rank", automaticity="automatic"),
    )
    monkeypatch.setattr("redteam.chains.report.pair_servers", lambda _servers: [supported, unsupported])
    monkeypatch.setattr(
        "redteam.chains.report.reproduce_git_clean_filter",
        lambda: ReproductionResult("REPRODUCED", teardown_confirmed=True),
    )

    report = build_report(load_config(FIXTURES / "git-plus-filesystem.json"), reproduce=True)
    reproduction = report["reproduction"]
    assert isinstance(reproduction, dict)
    ranked = report["ranked"]
    assert isinstance(ranked, list) and ranked and isinstance(ranked[0], dict)
    assert ranked[0]["template"] == "unregistered-high-rank"
    assert reproduction["status"] == "REPRODUCED"
    assert reproduction["rank"] == 2
    assert reproduction["template"] == "git-clean-filter"
    markdown = to_markdown(report)
    assert "Selected rank 2, git-clean-filter" in markdown
    assert "highest-ranked supported chain" in markdown


def test_no_supported_chain_skips_without_running_canary(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden() -> None:
        pytest.fail("no canary should run without a supported ranked chain")

    monkeypatch.setattr("redteam.chains.report.reproduce_git_clean_filter", forbidden)
    report = build_report([ConfiguredServer("unknown", None)], reproduce=True)
    assert report["reproduction"] == {
        "status": "SKIPPED",
        "reason": "no ranked chain has a registered reproducer",
        "demonstration": (
            "Git filter activation via equivalent filesystem writes and git add operations on a canary; "
            "not an exploit against a live MCP server."
        ),
    }


@pytest.mark.parametrize("log_and_add_only", [True, False])
def test_git_only_servers_cannot_receive_a_canary_result(
    monkeypatch: pytest.MonkeyPatch, log_and_add_only: bool
) -> None:
    git = load_catalog()["pypi:mcp-server-git"]
    servers = [
        ConfiguredServer(
            name,
            git.model_copy(
                update={
                    "tools": [tool for tool in git.tools if not log_and_add_only or tool.name == tool_name]
                }
            ),
        )
        for name, tool_name in (("git-a", "git_log"), ("git-b", "git_add"))
    ]

    def forbidden() -> ReproductionResult:
        pytest.fail("Git-only surfaces cannot supply the canary's writer role")

    monkeypatch.setattr("redteam.chains.report.reproduce_git_clean_filter", forbidden)
    report = build_report(servers, reproduce=True)
    assert report["ranked"] == []
    reproduction = report["reproduction"]
    assert isinstance(reproduction, dict)
    assert reproduction["status"] == "SKIPPED"
    assert "provenance_flag" not in reproduction


def test_unknown_tool_label_is_reported_as_unranked_candidate() -> None:
    from redteam.surface import ServerSurface, SurfaceTool

    server = ConfiguredServer(
        "unknown-tool",
        ServerSurface(server_name="unknown-tool", source="fixture", tools=[SurfaceTool(name="mystery")]),
    )
    report = build_report([server])
    assert report["unknown_labels"] == [{"server": "unknown-tool", "tool": "mystery"}]
    assert "possible chains were not ranked" in to_markdown(report)


def test_cli_does_not_echo_parser_secrets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"mcpServers": "private-value" broken}', encoding="utf-8")
    assert main(["run", "--config", str(path)]) == 2
    captured = capsys.readouterr()
    assert "private-value" not in captured.out + captured.err


def test_cli_returns_failure_for_failed_canary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redteam.chains.report.reproduce_git_clean_filter",
        lambda: ReproductionResult("NOT_REPRODUCED", "synthetic failure"),
    )
    assert main(["run", "--config", str(FIXTURES / "git-plus-filesystem.json"), "--reproduce"]) == 1
    assert "NOT_REPRODUCED" in capsys.readouterr().out


def test_cli_skipped_canary_has_distinct_failure_and_allow_skip(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "redteam.chains.report.reproduce_git_clean_filter",
        lambda: ReproductionResult("SKIPPED", "nested sandbox unavailable"),
    )
    args = ["run", "--config", str(FIXTURES / "git-plus-filesystem.json"), "--reproduce"]
    assert main(args) == 3
    assert "SKIPPED" in capsys.readouterr().out
    assert main([*args, "--allow-skip"]) == 0
    assert "SKIPPED" in capsys.readouterr().out


def test_markdown_escapes_separators_and_strips_terminal_controls() -> None:
    report = build_report([ConfiguredServer("odd|<tag>\x1b[2J\nname", None)])
    markdown = to_markdown(report)
    assert "\x1b" not in markdown
    assert r"odd\|<tag> [2J name" in markdown


def test_markdown_preserves_quotes_and_markup_without_html_entities() -> None:
    report = build_report([ConfiguredServer('writer\'s "tool" & <tag> `name`|next\r\nrow', None)])
    markdown = to_markdown(report)
    assert 'writer\'s "tool" & <tag> `name`\\|next  row' in markdown
    assert "&#" not in markdown
    assert "&amp;" not in markdown
    assert "&lt;" not in markdown


def test_cli_rejects_output_overwriting_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "config.json"
    original = '{"mcpServers": {"unknown": {"command": "synthetic"}}}'
    config.write_text(original, encoding="utf-8")
    assert main(["run", "--config", str(config), "--json", str(config)]) == 2
    assert config.read_text() == original
    assert "ValueError" in capsys.readouterr().err


def test_cli_rejects_aliased_report_outputs(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    assert (
        main(
            [
                "run",
                "--config",
                str(FIXTURES / "git-plus-filesystem.json"),
                "--json",
                str(report),
                "--md",
                str(report),
            ]
        )
        == 2
    )
    assert not report.exists()


@pytest.mark.parametrize("alias", ["direct", "symlink", "hardlink"])
def test_cli_rejects_mapped_surface_output_aliases(
    tmp_path: Path, alias: str, capsys: pytest.CaptureFixture[str]
) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mcpServers": {"server": {"command": "synthetic"}}}))
    surface = tmp_path / "surface.json"
    surface.write_text(ServerSurface(server_name="server", source="fixture", tools=[]).to_json())
    original = surface.read_bytes()
    mapping = tmp_path / "mapping.json"
    mapping.write_text(json.dumps({"server": surface.name}))
    output = tmp_path / "alias.json"
    if alias == "direct":
        output = surface
    elif alias == "symlink":
        output.symlink_to(surface)
    else:
        output.hardlink_to(surface)
    assert main(["run", "--config", str(config), "--surfaces", str(mapping), "--json", str(output)]) == 2
    assert surface.read_bytes() == original
    assert "distinct from inputs" in capsys.readouterr().err


def test_cli_rejects_pin_file_hardlink_and_output_inside_pin_directory(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"mcpServers": {"server": {"command": "synthetic"}}}))
    pins = tmp_path / "pins"
    pins.mkdir()
    pin = pins / ".mcp-audit-pins.yaml"
    pin.write_text("servers: {}\n")
    alias = tmp_path / "pin-alias.json"
    alias.hardlink_to(pin)
    original = pin.read_bytes()
    for output in (alias, pins / "report.json"):
        assert main(["run", "--config", str(config), "--pins", str(pins), "--json", str(output)]) == 2
    assert pin.read_bytes() == original
    assert not (pins / "report.json").exists()
