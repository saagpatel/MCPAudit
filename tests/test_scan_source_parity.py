"""D22 translations against unchanged library discovery, never legacy CLI execution."""

from __future__ import annotations

import json
import os
import platform
import shlex
import socket
import subprocess
from functools import partial
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner

from mcp_audit import _core_cli, check_cli, cli, engine, review_discovery
from mcp_audit.connector import ServerConnector
from mcp_audit.discovery.claude_desktop import ClaudeDesktopDiscoverer
from mcp_audit.models import AuditReport, ClientType
from mcp_audit.policy import evaluate_policy, load_policy
from mcp_audit.scan_translation import ScanTranslation, classify_scan_options


@pytest.fixture(autouse=True)
def isolated_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(socket, "gethostname", lambda: "synthetic-host")

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("parity must not launch, connect, or execute the legacy CLI")

    monkeypatch.setattr(ServerConnector, "connect", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(_core_cli, "_run_scan", forbidden, raising=False)


def _write(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def _servers(*names: str) -> dict[str, object]:
    return {name: {"command": "never-launch-fixture", "args": []} for name in names}


def _translation(args: list[str]) -> ScanTranslation:
    with _core_cli.scan.make_context("scan", list(args)) as context:
        translation = classify_scan_options(context.params)
    assert translation.coverage == "preserved", translation.notice()
    assert translation.check_argv is not None
    assert translation.check_argv[-2:] == ("--include-discovered", "--scan-compatible-sources")
    return translation


def _check(translation: ScanTranslation) -> tuple[AuditReport, int]:
    assert translation.check_argv is not None
    return _check_argv(translation.check_argv)


def _check_argv(argv: tuple[str, ...] | list[str]) -> tuple[AuditReport, int]:
    result = CliRunner().invoke(cli.main, [*argv[1:], "--json"])
    assert result.exit_code in (0, 2), result.output
    return AuditReport.model_validate_json(result.stdout), result.exit_code


def _stable(report: AuditReport) -> dict[str, object]:
    return report.model_dump(mode="json", exclude={"scan_timestamp", "scan_duration_seconds"})


def _server_set(report: AuditReport) -> set[tuple[str, str, str, str | None, str]]:
    return {
        (a.server.name, a.server.client.value, a.server.config_path, a.server.project_path, a.server.scope)
        for a in report.audits
    }


@pytest.mark.parametrize(
    "shape",
    [
        "claude-scopes",
        "cursor-global-project",
        "all-clients",
        "claude-filter",
        "cursor-filter",
        "hook-2.11",
        "malformed-sibling",
        "vscode-overlap",
        "no-server-map-policy",
        "vscode-malformed-mcp",
    ],
)
def test_translation_matches_library_discovery_report_and_exit(shape: str, tmp_path: Path) -> None:
    home = Path.home()
    claude: dict[str, object] = {
        "mcpServers": _servers("global"),
        "projects": {
            str(tmp_path): {"mcpServers": _servers("current")},
            "/synthetic/project-a": {"mcpServers": _servers("other-a")},
            "/synthetic/project-b": {"mcpServers": _servers("other-b")},
        },
    }
    claude_names = {"global", "current", "other-a", "other-b", "shared"}
    cursor_names = {"cursor-global"}
    all_names = (
        claude_names | cursor_names | {"desktop", "vscode-project", "vscode-global", "windsurf-fixture"}
    )
    args = ["--skip-connect", "--override-config", "/dev/null", "--redact"]
    clients = None
    inject = shape == "hook-2.11"
    policy = None
    if shape in {"claude-scopes", "all-clients", "claude-filter", "cursor-filter", "hook-2.11"}:
        _write(home / ".claude.json", claude)
        _write(tmp_path / ".mcp.json", {"mcpServers": _servers("shared")})
        expected_names = claude_names
    if shape in {"cursor-global-project", "all-clients", "claude-filter", "cursor-filter", "hook-2.11"}:
        _write(home / ".cursor/mcp.json", {"mcpServers": _servers("cursor-global")})
        _write(tmp_path / ".cursor/mcp.json", {"mcpServers": _servers("cursor-project")})
        expected_names = cursor_names if shape == "cursor-global-project" else claude_names | cursor_names
    if shape in {"all-clients", "claude-filter", "cursor-filter", "hook-2.11"}:
        _write(ClaudeDesktopDiscoverer().config_paths()[0], {"mcpServers": _servers("desktop")})
        _write(tmp_path / ".vscode/mcp.json", {"servers": _servers("vscode-project")})
        _write(home / ".vscode/mcp.json", {"mcpServers": _servers("vscode-global")})
        _write(home / ".codeium/windsurf/mcp_config.json", {"mcpServers": _servers("windsurf-fixture")})
        expected_names = all_names
    if shape in {"claude-filter", "cursor-filter"}:
        client = ClientType.CLAUDE_CODE if shape == "claude-filter" else ClientType.CURSOR
        clients = [client]
        args.extend(("--clients", client.value))
        expected_names = claude_names if shape == "claude-filter" else cursor_names
    if inject:
        args.append("--inject-check")
    if shape == "malformed-sibling":
        claude["projects"] = {
            str(tmp_path): {"mcpServers": _servers("current")},
            "/synthetic/broken": None,
        }
        _write(home / ".claude.json", claude)
        _write(tmp_path / ".mcp.json", {"mcpServers": _servers("survivor")})
        expected_names = {"survivor"}
    if shape == "vscode-overlap":
        _write(
            tmp_path / ".vscode/mcp.json",
            {
                "mcpServers": _servers("twice"),
                "servers": _servers("twice", "once"),
                "mcp": {"servers": _servers("twice", "nested")},
            },
        )
        expected_names = {"twice", "once", "nested"}
    if shape in {"no-server-map-policy", "vscode-malformed-mcp"}:
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("fail_on:\n  config_health: low\n")
        policy = load_policy(policy_path)
        args.extend(("--policy", str(policy_path)))
        expected_names = set()
        if shape == "no-server-map-policy":
            _write(tmp_path / ".mcp.json", {"theme": "dark"})
        else:
            _write(tmp_path / ".mcp.json", {"mcpServers": {}})
            _write(
                tmp_path / ".vscode/mcp.json",
                {"mcpServers": {**_servers("discarded"), "broken": None}, "mcp": False},
            )

    # No pre-parsed servers: the unchanged library path performs discovery itself.
    oracle = anyio.run(
        partial(engine.run_scan, engine.ScanOptions(skip_connect=True, clients=clients, inject_check=inject))
    )
    assert {a.server.name for a in oracle.audits} == expected_names
    if policy is not None:
        oracle.policy_result = evaluate_policy(oracle, policy)
    expected_exit = 2 if oracle.policy_result is not None and not oracle.policy_result.passed else 0
    expected = oracle.redacted(identifiers=True)
    actual, exit_code = _check(_translation(args))
    assert _server_set(actual) == _server_set(expected)
    assert actual.servers_discovered == expected.servers_discovered == len(expected_names)
    assert _stable(actual) == _stable(expected)
    assert exit_code == expected_exit == (2 if shape == "vscode-malformed-mcp" else 0)
    if shape == "vscode-malformed-mcp":
        assert len(actual.config_health_findings) == 2
        plain = CliRunner().invoke(cli.main, ["check", "--include-discovered", *args, "--json"])
        assert plain.exit_code == 2, plain.output
        assert len(AuditReport.model_validate_json(plain.stdout).config_health_findings) == 1
    assert "synthetic-host" not in json.dumps(_stable(actual))
    # --redact aliases names, so compare real names through an unredacted run.
    unredacted = _check_argv([a for a in _translation(args).check_argv or () if a != "--redact"])[0]
    assert {a.server.name for a in unredacted.audits} == expected_names


@pytest.mark.parametrize("policy", [False, True], ids=["no-policy", "config-health-policy"])
@pytest.mark.parametrize("limit", ["symlink", "bytes", "depth"])
def test_translation_documents_sources_skipped_by_review_limits(
    limit: str, policy: bool, tmp_path: Path
) -> None:
    data: dict[str, object] = {"mcpServers": _servers("beyond-review-limit")}
    source = Path.home() / ".claude.json"
    if limit == "symlink":
        target = tmp_path / "symlink-target.json"
        _write(target, data)
        source.symlink_to(target)
        statement = "symlink refusal for discovered sources"
        reason = "symlink skipped"
    else:
        if limit == "bytes":
            data["padding"] = "x" * review_discovery.MAX_CONFIG_BYTES
            statement = f"{review_discovery.MAX_CONFIG_BYTES}-byte source limit"
            reason = f"exceeds {review_discovery.MAX_CONFIG_BYTES}-byte limit"
        else:
            nested: object = {}
            for _ in range(review_discovery.MAX_DEPTH):
                nested = {"nested": nested}
            data["padding"] = nested
            statement = f"nesting depth {review_discovery.MAX_DEPTH}"
            reason = "nesting or container limit"
        _write(source, data)
    # Keep one accepted source so the comparison isolates the documented limit.
    _write(tmp_path / ".mcp.json", {"mcpServers": _servers("accepted")})
    oracle = anyio.run(partial(engine.run_scan, engine.ScanOptions(skip_connect=True)))
    assert {a.server.name for a in oracle.audits} == {"beyond-review-limit", "accepted"}
    args = ["--skip-connect", "--override-config", "/dev/null", "--redact"]
    if policy:
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text("fail_on:\n  config_health: low\n")
        oracle.policy_result = evaluate_policy(oracle, load_policy(policy_path))
        args.extend(("--policy", str(policy_path)))
    translation = _translation(args)
    assert statement in translation.notice()
    assert "a skipped source is reported as a config-health finding" in translation.notice()
    actual, exit_code = _check(translation)
    expected = oracle.redacted(identifiers=True)
    assert actual.servers_discovered == 1 and expected.servers_discovered == 2
    assert _server_set(actual) != _server_set(expected)
    assert _stable(actual) != _stable(expected)
    warning = next(w for w in actual.warnings if w.code == "review_source_skipped")
    assert warning.check == "config_health" and reason in warning.message
    assert actual.coverage["config_health"].state == "partial"
    # The skipped source is loud, never silent: a HIGH config-health finding
    # that scan (which read the file) does not report.
    finding = next(f for f in actual.config_health_findings if reason in f.model_dump_json())
    assert finding.finding_type == "config_parse_failure" and finding.severity.value == "high"
    assert expected.config_health_findings == []
    oracle_exit = 2 if oracle.policy_result is not None and not oracle.policy_result.passed else 0
    assert oracle_exit == 0
    assert exit_code == (2 if policy else 0)


def test_zero_source_hook_translation_differs_only_by_no_sources_warning() -> None:
    # Empty HOME and cwd: the usual CI runner for the 2.11 hook form.
    oracle = anyio.run(partial(engine.run_scan, engine.ScanOptions(skip_connect=True, inject_check=True)))
    expected = oracle.redacted(identifiers=True)
    args = ["--skip-connect", "--override-config", "/dev/null", "--redact", "--inject-check"]
    actual, exit_code = _check(_translation(args))
    assert _server_set(actual) == _server_set(expected) == set()
    assert actual.servers_discovered == expected.servers_discovered == 0
    assert exit_code == 0 and oracle.policy_result is None
    # Owner decision O-1 keeps the non-fatal warning; it is the only difference.
    assert [w.code for w in actual.warnings if w not in expected.warnings] == ["no_sources_reviewed"]
    actual.warnings = [w for w in actual.warnings if w.code != "no_sources_reviewed"]
    assert _stable(actual) == _stable(expected)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads files regardless of mode bits")
def test_unreadable_source_uses_scan_wording_only_under_the_selector(tmp_path: Path) -> None:
    source = tmp_path / ".mcp.json"
    _write(source, {"mcpServers": _servers("unreadable")})
    # One accepted source keeps the comparison free of no_sources_reviewed.
    _write(Path.home() / ".cursor/mcp.json", {"mcpServers": _servers("accepted")})
    source.chmod(0)
    try:
        oracle = anyio.run(partial(engine.run_scan, engine.ScanOptions(skip_connect=True)))
        expected = oracle.redacted(identifiers=True)
        args = ["--skip-connect", "--override-config", "/dev/null", "--redact"]
        actual, exit_code = _check(_translation(args))
        plain, plain_exit = _check_argv(["mcp-audit", "check", "--include-discovered", *args])
    finally:
        source.chmod(0o600)
    assert "unreadable config file: PermissionError" in json.dumps(_stable(expected))
    assert _stable(actual) == _stable(expected)
    assert exit_code == plain_exit == 0
    plain_text = json.dumps(_stable(plain))
    assert "unreadable config: PermissionError" in plain_text
    assert "unreadable config file:" not in plain_text


@pytest.mark.parametrize(
    "scope", [[], ["--clients", "claude_code"], ["--clients", "cursor"], ["--inject-check"]]
)
def test_printed_notice_round_trips_to_identical_check_options(
    scope: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_execution(*args: object, **kwargs: object) -> None:
        pass

    # raising=False is deliberate: X-1 removes this re-export and X-2 replaces
    # scan with the interceptor, which must not fail this round trip. The
    # autouse fixture still forbids connections and subprocesses.
    monkeypatch.setattr(_core_cli, "_run_scan", no_execution, raising=False)
    args = ["--skip-connect", "--override-config", "/dev/null", *scope]
    expected = _translation(args)
    result = CliRunner().invoke(cli.main, ["scan", *args])
    assert result.exit_code == 0, result.output
    assert result.stderr == expected.notice() + "\n"
    printed = shlex.split(result.stderr.strip().split(": ", 2)[2])
    assert printed == list(expected.check_argv or ())
    with check_cli.check.make_context("check", printed[2:]) as context:
        actual_options = context.params
    assert expected.check_argv is not None
    with check_cli.check.make_context("check", list(expected.check_argv[2:])) as context:
        assert actual_options == context.params
    assert actual_options["include_discovered"] is True
    assert actual_options["scan_compatible_sources"] is True
    assert actual_options["skip_connect"] is True
    assert actual_options["override_config"] == Path("/dev/null")
    assert actual_options["inject_check"] is ("--inject-check" in scope)
    expected_clients = {
        "claude_code": (ClientType.CLAUDE_CODE,),
        "cursor": (ClientType.CURSOR,),
    }.get(scope[1] if scope[:1] == ["--clients"] else "", ())
    assert actual_options["clients"] == expected_clients
