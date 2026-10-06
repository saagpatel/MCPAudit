"""Local checks for the hostile fixture and fail-closed gate accounting."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_hostile_perf import CASES, FIXTURES, Case, assert_limits, isolated_env, run_case


@pytest.mark.parametrize(
    "mode",
    [
        "normal",
        "notifications",
        "infinite-pages",
        "malformed-list",
        "banner",
        "ansi",
        "crash",
        "huge",
        "oversized",
        "hugeline",
    ],
)
def test_hostile_wire_payloads(mode: str, tmp_path: Path) -> None:
    env = isolated_env(tmp_path)
    methods = ("initialize", "tools/list", "prompts/list", "resources/list", "tools/call")
    requests = "".join(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": i,
                "method": method,
                "params": {"protocolVersion": "2025-06-18"} if i == 0 else {},
            }
        )
        + "\n"
        for i, method in enumerate(methods)
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            str(FIXTURES / "hostile_server.py"),
            mode,
            "--work-dir",
            str(tmp_path),
            "--tools",
            "2",
            "--frame-bytes",
            "64",
            "--size-mib",
            "1",
        ],
        input=requests,
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        timeout=10,
        check=True,
    )
    responses = []
    for line in result.stdout.splitlines():
        if line.strip().startswith('{"jsonrpc"'):
            value = json.loads(line)
            if "id" in value:
                responses.append(value)
    assert len(responses) == 5
    assert responses[0]["result"]["protocolVersion"] == "2025-06-18"
    tools = responses[1]["result"]["tools"]
    if mode == "ansi":
        assert "\x1b]8;;https://evil.example.test/" in tools[0]["name"]
        assert "<script>" in tools[1]["description"]
        assert "\x1b[2J" in responses[4]["result"]["content"][0]["text"]
    elif mode == "crash":
        assert tools[0]["name"] == "status[/bold]"
    elif mode in {"huge", "oversized"}:
        assert len(tools[0]["description"]) == (1024 * 1024 if mode == "huge" else 64)
    elif mode == "infinite-pages":
        assert responses[1]["result"]["nextCursor"] == "1"
    else:
        assert len(tools) == 2
    assert len(list((tmp_path / "pids").glob("*.json"))) == 1


@pytest.mark.parametrize("attempt", ["home", "network"])
def test_fixture_guard_denies_home_and_sockets(attempt: str, tmp_path: Path) -> None:
    env = isolated_env(tmp_path)
    program = """
import importlib.util, os, pathlib, socket, sys
spec = importlib.util.spec_from_file_location('hostile', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.restrict_io(pathlib.Path.cwd())
try:
    if sys.argv[2] == 'home':
        open(pathlib.Path(sys.prefix) / 'forbidden-fixture-file', 'w')
    else:
        socket.socket()
except PermissionError:
    print('denied')
else:
    raise AssertionError('Fixture boundary was bypassed')
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            program,
            str(FIXTURES / "hostile_server.py"),
            attempt,
        ],
        text=True,
        capture_output=True,
        cwd=tmp_path,
        env=env,
        timeout=10,
        check=True,
    )
    assert result.stdout == "denied\n"


def test_scanner_runner_measures_and_cleans_fixture(tmp_path: Path) -> None:
    metrics = run_case(tmp_path, Case("smoke", ("normal", "--tools", "1"), 10))
    assert metrics["exit_code"] == 0
    assert metrics["connected"] == metrics["total_tools"] == 1
    assert metrics["recorded_processes"] == 1
    assert metrics["leftover_processes"] == metrics["leftover_groups"] == 0
    assert isinstance(metrics["peak_rss_bytes"], int) and metrics["peak_rss_bytes"] > 0
    assert isinstance(metrics["analysis_seconds"], float) and metrics["analysis_seconds"] > 0


@pytest.mark.parametrize("regression", ["wall_seconds", "peak_rss_bytes", "leftover_processes"])
def test_gate_rejects_baseline_regressions(regression: str) -> None:
    case = CASES[0]
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": 1.0,
        "peak_rss_bytes": 1,
        "connected": 500,
        "total_tools": 5000,
        "recorded_processes": 500,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    metrics[regression] = 10**12
    with pytest.raises(AssertionError):
        assert_limits(metrics, case, "baseline")


def test_frame_target_requires_failure_reason() -> None:
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": 0.1,
        "peak_rss_bytes": 1,
        "statuses": ["failed"],
        "errors": ["unrelated failure"],
        "recorded_processes": 1,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    with pytest.raises(AssertionError):
        assert_limits(metrics, CASES[3], "p3-7")
