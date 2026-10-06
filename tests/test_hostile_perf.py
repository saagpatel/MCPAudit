"""Opt-in, process-isolated regression gate for the approved hostile baselines."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PROFILES = ("baseline", "p1-9", "p3-7", "p3-8")
MIB = 1024 * 1024


@dataclass(frozen=True)
class Case:
    name: str
    args: tuple[str, ...]
    wall: float
    rss_mib: int | None = None
    analysis: float | None = None
    servers: int = 1
    tools: int = 1
    timeout: int = 10
    leftovers: int = 0


# Exact published measurements (RSS was reported in MiB by the stress runner).
# Do not increase these to accommodate a failed run: record the regression.
CASES = (
    Case("scale_500", ("normal", "--tools", "10"), 5.8, 213, servers=500, tools=5000),
    Case("desc_5mb_x1", ("normal", "--tools", "1", "--desc-bytes", "5000000"), 18.8, analysis=18),
    Case("desc_1mb_x20", ("normal", "--tools", "20", "--desc-bytes", "1000000"), 75, 1282, tools=20),
    Case("oversized_50mb", ("oversized", "--frame-bytes", "50000000"), 191.7, 3217),
    Case("spawn_child_exit", ("spawn-child-exit",), 6.5, timeout=2, leftovers=1),
)


def isolated_env(root: Path) -> dict[str, str]:
    """Never inherit credentials or a real home into the scanner/fixture."""
    for directory in ("home", "pids", "tmp"):
        (root / directory).mkdir(exist_ok=True)
    return {
        "HOME": str(root / "home"),
        "PATH": os.defpath,
        "TMPDIR": str(root / "tmp"),
        "XDG_CONFIG_HOME": str(root / "home"),
        "XDG_CACHE_HOME": str(root / "home"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "NO_COLOR": "1",
    }


def process_exists(pid: int, *, group: bool = False) -> bool:
    if pid <= 1 or (group and pid == os.getpgrp()):
        raise ValueError("Refusing to inspect or signal a non-fixture process group.")
    try:
        if group:
            os.killpg(pid, 0)
        else:
            os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # Permission errors are a failed measurement, never a false zero.
    return True


def read_ledger(root: Path) -> tuple[list[int], list[int], list[str]]:
    pids: list[int] = []
    groups: set[int] = set()
    roles: list[str] = []
    for path in (root / "pids").glob("*.json"):
        value = json.loads(path.read_text())
        pid, pgid = value["pid"], value["pgid"]
        assert isinstance(pid, int) and isinstance(pgid, int)
        assert path.stem == str(pid)
        role = value["role"]
        assert role in {"server", "child"}
        pids.append(pid)
        groups.add(pgid)
        roles.append(role)
    return pids, sorted(groups), roles


def cleanup_groups(groups: list[int]) -> None:
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for group in groups:
            if process_exists(group, group=True):
                try:
                    os.killpg(group, sig)
                except ProcessLookupError:
                    pass  # The fixture exited between the probe and signal.
        if sig == signal.SIGTERM:
            time.sleep(0.1)


def run_case(root: Path, case: Case, *, timeout: int | None = None) -> dict[str, object]:
    assert not any(root.iterdir()), "Use a fresh performance case directory."
    env = isolated_env(root)
    fixture = str(FIXTURES / "hostile_server.py")
    configs: dict[str, object] = {
        f"srv{i:04d}": {
            "command": sys.executable,
            "args": ["-I", "-S", fixture, *case.args, "--work-dir", str(root)],
        }
        for i in range(case.servers)
    }
    if case.name == "spawn_child_exit":
        configs["healthy"] = {
            "command": sys.executable,
            "args": [
                "-I",
                "-S",
                fixture,
                "normal",
                "--tools",
                "1",
                "--work-dir",
                str(root),
            ],
        }
    config = root / "config.json"
    config.write_text(json.dumps({"mcpServers": configs}))
    override = root / "empty.yaml"
    override.write_text("")
    report_path = root / "report.json"
    timing_path = root / "timing.json"
    command = [
        sys.executable,
        str(FIXTURES / "perf_scan.py"),
        str(timing_path),
        "scan",
        "--config",
        str(config),
        "--config-only",
        "--override-config",
        str(override),
        "--timeout",
        str(case.timeout if timeout is None else timeout),
        "--json",
        str(report_path),
    ]
    start = time.perf_counter()
    measured: dict[str, object] = {"case": case.name, "timeout": case.timeout if timeout is None else timeout}
    process = subprocess.Popen(
        command, cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True
    )
    groups: list[int] = []
    try:
        try:
            _, stderr = process.communicate(timeout=case.wall + 10)
            measured["deadline_exceeded"] = False
        except subprocess.TimeoutExpired:
            measured["deadline_exceeded"] = True
            os.killpg(process.pid, signal.SIGKILL)
            _, stderr = process.communicate(timeout=5)
        measured["wall_seconds"] = time.perf_counter() - start
        measured["exit_code"] = process.returncode
        measured["stderr_bytes"] = len(stderr)
        if timing_path.exists():
            measured.update(json.loads(timing_path.read_text()))
        if report_path.exists():
            report = json.loads(report_path.read_text())
            measured["connected"] = report["servers_connected"]
            measured["total_tools"] = report["total_tools"]
            measured["statuses"] = [a["connection_status"] for a in report["audits"]]
            measured["errors"] = [a["connection_error"] for a in report["audits"]]
            measured["file_read_tools"] = [
                [f["tool_name"] for f in a["permissions"] if f["category"] == "file_read"]
                for a in report["audits"]
            ]
        pids, groups, roles = read_ledger(root)
        # Same post-scan observation grace as the original stress runner.
        time.sleep(0.5)
        measured["recorded_processes"] = len(pids)
        measured["process_roles"] = roles
        measured["leftover_processes"] = sum(process_exists(pid) for pid in pids)
        measured["leftover_groups"] = sum(process_exists(group, group=True) for group in groups)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        if not groups:
            _, groups, _ = read_ledger(root)
        try:
            cleanup_groups(groups)
        finally:
            (root / "metrics.json").write_text(json.dumps(measured, indent=2) + "\n")
    return measured


def number(metrics: dict[str, object], key: str) -> float:
    value = metrics[key]
    assert isinstance(value, (int, float)), f"Missing numeric measurement: {key}"
    return float(value)


def print_metrics(metrics: dict[str, object]) -> None:
    # Full coverage/status/error arrays remain in the artifact, not the console log.
    arrays = {"statuses", "errors", "analysis_tool_counts", "process_roles", "file_read_tools"}
    summary = {key: value for key, value in metrics.items() if key not in arrays}
    print(json.dumps(summary, sort_keys=True))


def assert_limits(metrics: dict[str, object], case: Case, profile: str) -> None:
    stage = PROFILES.index(profile)
    assert metrics["deadline_exceeded"] is False, metrics
    assert metrics["exit_code"] == 0, metrics
    wall = case.wall
    rss = case.rss_mib
    analysis = case.analysis
    leftovers = case.leftovers if stage < 3 else 0
    if stage >= 1:
        if case.name == "scale_500":
            wall = 4
        elif case.name == "desc_5mb_x1":
            analysis = 1
        elif case.name == "desc_1mb_x20":
            wall, rss = 3, None
            assert number(metrics, "peak_rss_bytes") < 400_000_000, metrics
    if stage >= 2 and case.name == "oversized_50mb":
        assert number(metrics, "wall_seconds") < 1, metrics
        assert number(metrics, "peak_rss_bytes") < 300_000_000, metrics
        assert metrics["statuses"] == ["failed"], metrics
        errors = cast(list[str | None], metrics["errors"])
        assert (
            errors[0]
            and "frame" in errors[0].lower()
            and any(word in errors[0].lower() for word in ("size", "exceed", "limit", "large"))
        ), metrics
        assert metrics["total_tools"] == 0, metrics
        rss = None
    elif case.name == "spawn_child_exit":
        assert metrics["connected"] == 1 and metrics["total_tools"] == 1, metrics
        assert metrics["statuses"] in (["timeout", "connected"], ["failed", "connected"]), metrics
        roles = metrics["process_roles"]
        assert isinstance(roles, list) and sorted(roles) == ["child", "server", "server"], metrics
        assert number(metrics, "recorded_processes") == 3, metrics
    else:
        assert metrics["connected"] == case.servers and metrics["total_tools"] == case.tools, metrics
    if case.name in {"desc_5mb_x1", "desc_1mb_x20"}:
        assert number(metrics, "analysis_invocations") == case.servers, metrics
        assert metrics["analysis_tool_counts"] == [case.tools], metrics
        assert metrics["file_read_tools"] == [[f"tool_{i}" for i in range(case.tools)]], metrics
    assert number(metrics, "wall_seconds") <= wall, metrics
    if analysis is not None:
        assert number(metrics, "analysis_seconds") <= analysis, metrics
    if rss is not None:
        assert number(metrics, "peak_rss_bytes") <= rss * MIB, metrics
    assert number(metrics, "recorded_processes") >= case.servers, metrics
    assert number(metrics, "leftover_processes") <= leftovers, metrics
    assert number(metrics, "leftover_groups") <= leftovers, metrics


@pytest.mark.perf
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_hostile_performance(case: Case, tmp_path: Path, pytestconfig: pytest.Config) -> None:
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        pytest.fail("Performance gate requires Linux or macOS process groups and peak-RSS accounting.")
    output: Path | None = pytestconfig.getoption("--perf-output")
    root = tmp_path if output is None else output.resolve() / case.name
    root.mkdir(parents=True, exist_ok=True)
    profile: str = pytestconfig.getoption("--perf-profile")
    metrics = run_case(root, case)
    metrics["profile"] = profile
    (root / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print_metrics(metrics)
    short: dict[str, object] | None = None
    if case.name == "scale_500":
        short_root = root / "timeout2"
        short_root.mkdir()
        short = run_case(short_root, case, timeout=2)
        print_metrics(short)
    assert_limits(metrics, case, profile)
    if short is not None:
        assert short["deadline_exceeded"] is False and short["exit_code"] == 0, short
        assert number(short, "leftover_processes") == number(short, "leftover_groups") == 0, short
        assert number(short, "wall_seconds") <= case.wall, short
        assert number(short, "recorded_processes") == 500, short
        assert number(short, "peak_rss_bytes") <= 213 * MIB, short
        if profile != "baseline":
            assert short["connected"] == 500 and short["total_tools"] == 5000, short
        else:
            assert set(cast(list[str], short["statuses"])) <= {"connected", "timeout"}, short
