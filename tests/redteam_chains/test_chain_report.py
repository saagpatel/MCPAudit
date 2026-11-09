from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.chains.__main__ import main
from redteam.chains.pairs import ConfiguredServer, load_config
from redteam.chains.report import build_report, to_json, to_markdown
from redteam.chains.reproduce import ReproductionResult

FIXTURES = Path("redteam/fixtures/servers/configs")


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


def test_markdown_and_terminal_names_are_inert() -> None:
    report = build_report([ConfiguredServer("odd|<tag>\x1b[2J\nname", None)])
    markdown = to_markdown(report)
    assert "\x1b" not in markdown
    assert "<tag>" not in markdown
    assert "odd&#124;&lt;tag&gt;" in markdown


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
