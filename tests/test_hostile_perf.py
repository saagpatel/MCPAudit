"""Opt-in, process-isolated regression gate for the approved hostile baselines."""

from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from statistics import median
from typing import cast

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PROFILES = ("baseline", "p1-9", "p3-7", "p3-8")
MIB = 1024 * 1024
# The SSRF fixture consumes 65 bytes of the 256 KiB item budget for its
# identifiers and schema keys/values before retaining description text.
SSRF_RETAINED_BYTES = 256 * 1024 - 65

# Median of five isolated calibration runs on Apple Silicon, Python 3.11,
# with no concurrent test/lint workloads. Component seconds, not total time.
REFERENCE = {"process": 1.6466256250278093, "cpu": 1.2312097090180032}


@dataclass(frozen=True)
class Calibration:
    runs: tuple[dict[str, float], ...] = ()

    @property
    def seconds(self) -> dict[str, float]:
        return {key: median(run[key] for run in self.runs) for key in REFERENCE} if self.runs else {}

    @property
    def factor(self) -> float:
        # Max avoids weights that could dilute a slow process or CPU component.
        return max([1.0, *(value / REFERENCE[key] for key, value in self.seconds.items())])

    def metrics(self) -> dict[str, object]:
        return {
            "enabled": bool(self.runs),
            "runs_seconds": list(self.runs),
            "seconds": self.seconds,
            "reference_seconds": dict(REFERENCE),
            "factor": self.factor,
        }


RAW_CALIBRATION = Calibration()


def calibration_run(root: Path) -> dict[str, float]:
    root = root.resolve()
    root.mkdir(parents=True)
    process = subprocess.Popen(
        [sys.executable, str(FIXTURES / "perf_calibrate.py"), str(root)],
        cwd=root,
        env=isolated_env(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, _ = process.communicate(timeout=120)
        assert process.returncode == 0, "Calibration process failed."
    finally:
        # Also stop fixture children if calibration aborts during a handshake.
        if process_exists(process.pid, group=True):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    values: object = json.loads(stdout)
    assert isinstance(values, dict) and set(values) == set(REFERENCE), "Incomplete calibration."
    measured: dict[str, float] = {}
    for key in REFERENCE:
        value = values[key]
        assert isinstance(value, (int, float)) and math.isfinite(value) and value > 0
        measured[key] = float(value)
    return measured


def calibrate(root: Path | None) -> Calibration:
    return (
        RAW_CALIBRATION
        if root is None
        else Calibration(tuple(calibration_run(root / str(i)) for i in range(3)))
    )


@pytest.fixture(scope="session")
def perf_calibration(pytestconfig: pytest.Config, tmp_path_factory: pytest.TempPathFactory) -> Calibration:
    root = (
        None
        if pytestconfig.getoption("--perf-no-calibration")
        else tmp_path_factory.mktemp("perf-calibration")
    )
    calibration = calibrate(root)
    print(json.dumps({"calibration": calibration.metrics()}, sort_keys=True))
    return calibration


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
    cli_args: tuple[str, ...] = ()
    hostile: bool = False


# Exact published measurements (RSS was reported in MiB by the stress runner).
# Do not increase these to accommodate a failed run: record the regression.
# REFERENCE must not be changed to absorb a regression either.
CASES = (
    Case("scale_500", ("normal", "--tools", "10"), 5.8, 213, servers=500, tools=5000),
    Case("desc_5mb_x1", ("normal", "--tools", "1", "--desc-bytes", "5000000"), 18.8, analysis=18),
    Case("desc_1mb_x20", ("normal", "--tools", "20", "--desc-bytes", "1000000"), 75, 1282, tools=20),
    Case("oversized_50mb", ("oversized", "--frame-bytes", "50000000"), 191.7, 3217),
    Case("spawn_child_exit", ("spawn-child-exit",), 6.5, timeout=2, hostile=True),
    Case("scale_2000", ("normal", "--tools", "10"), 16, servers=2000, tools=20000),
    Case("pages_20k", ("normal", "--tools", "20000", "--pages", "20"), 9, tools=20000),
    Case("scale_100k_skip", ("normal",), 10, servers=100_000, tools=0, cli_args=("--skip-connect",)),
    Case(
        "ssrf_1mib",
        ("ssrf-description", "--desc-bytes", str(MIB)),
        1,
        cli_args=("--ssrf-check",),
    ),
    *(
        Case(f"hostile_{mode}", (mode, "--ignore-sigterm"), 6.5, timeout=2, hostile=True)
        for mode in (
            "silent",
            "slow-bytes",
            "wrong-id",
            "wrong-id-list",
            "notification-flood",
            "stderr-flood",
            "hang-after-handshake",
            "silent-after-eof",
        )
    ),
    # New full-field redaction ceiling, separate from historical scan measurements.
    Case("escape_dense", (), 10, 512, servers=0, tools=0),
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
    return _live_on_linux(pid, group=group)


def _proc_stat(path: Path) -> tuple[str, int] | None:
    """State and process group from /proc/<pid>/stat, or None if it vanished."""
    try:
        fields = path.read_text().rpartition(")")[2].split()
    except (FileNotFoundError, ProcessLookupError):
        return None
    return fields[0], int(fields[2])


def _live_on_linux(pid: int, *, group: bool, proc: Path = Path("/proc")) -> bool:
    # A zombie is dead: it keeps kill(pid, 0) succeeding only until an init
    # that does not reap promptly collects it. Count live processes only.
    if not (proc / "self" / "stat").exists():
        return True  # No procfs: the signal probe is the measurement.
    if not group:
        stat = _proc_stat(proc / str(pid) / "stat")
        return stat is not None and stat[0] not in {"Z", "X"}
    for entry in proc.iterdir():
        if entry.name.isdigit() and (stat := _proc_stat(entry / "stat")) is not None:
            if stat[1] == pid and stat[0] not in {"Z", "X"}:
                return True
    return False


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


def run_case(
    root: Path, case: Case, *, calibration: Calibration = RAW_CALIBRATION, timeout: int | None = None
) -> dict[str, object]:
    assert not any(root.iterdir()), "Use a fresh performance case directory."
    env = isolated_env(root)
    if case.name == "escape_dense":
        return run_escape_dense(root, case, env, calibration)
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
    # The scanner CLI accepts whole seconds; round up its calibrated deadline.
    session_timeout = math.ceil((case.timeout if timeout is None else timeout) * calibration.factor)
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
        str(session_timeout),
        "--json",
        str(report_path),
        *case.cli_args,
    ]
    if case.name == "desc_1mb_x20":
        # This 20 MB frame exercises retained item text and analysis, rather
        # than the default 16 MiB frame rejection covered by oversized_50mb.
        command.extend(["--max-frame-bytes", "32000000"])
    start = time.perf_counter()
    measured: dict[str, object] = {
        "case": case.name,
        "timeout": session_timeout,
        "calibration": calibration.metrics(),
        "deadline_seconds": (case.wall + 10) * calibration.factor,
    }
    process = subprocess.Popen(
        command, cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True
    )
    groups: list[int] = []
    try:
        try:
            _, stderr = process.communicate(timeout=(case.wall + 10) * calibration.factor)
            measured["deadline_exceeded"] = False
        except subprocess.TimeoutExpired:
            measured["deadline_exceeded"] = True
            os.killpg(process.pid, signal.SIGKILL)
            _, stderr = process.communicate(timeout=5 * calibration.factor)
        measured["wall_seconds"] = time.perf_counter() - start
        measured["exit_code"] = process.returncode
        measured["stderr_bytes"] = len(stderr)
        if timing_path.exists():
            measured.update(json.loads(timing_path.read_text()))
        if report_path.exists():
            report = json.loads(report_path.read_text())
            measured["discovered"] = report["servers_discovered"]
            measured["connected"] = report["servers_connected"]
            measured["total_tools"] = report["total_tools"]
            measured["statuses"] = [a["connection_status"] for a in report["audits"]]
            measured["errors"] = [a["connection_error"] for a in report["audits"]]
            measured["warning_codes"] = [warning["code"] for warning in report["warnings"]]
            measured["ssrf_patterns"] = [
                [finding["pattern_name"] for finding in audit["ssrf_findings"]] for audit in report["audits"]
            ]
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
            process.wait(timeout=5 * calibration.factor)
        if not groups:
            _, groups, _ = read_ledger(root)
        try:
            cleanup_groups(groups)
        finally:
            (root / "metrics.json").write_text(json.dumps(measured, indent=2) + "\n")
    return measured


def run_escape_dense(
    root: Path, case: Case, env: dict[str, str], calibration: Calibration
) -> dict[str, object]:
    # Connected listings cap item text below 1 MiB; exercise the complete field
    # directly, in an isolated process with the same allowlisted environment.
    timing_path = root / "timing.json"
    deadline = (case.wall + 10) * calibration.factor
    measured: dict[str, object] = {
        "case": case.name,
        "calibration": calibration.metrics(),
        "deadline_seconds": deadline,
    }
    start = time.perf_counter()
    process = subprocess.Popen(
        [sys.executable, str(FIXTURES / "perf_redact.py"), str(timing_path)],
        cwd=root,
        env={**env, "PYTHONPATH": str(FIXTURES.parent.parent)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        try:
            _, stderr = process.communicate(timeout=deadline)
            measured["deadline_exceeded"] = False
        except subprocess.TimeoutExpired:
            measured["deadline_exceeded"] = True
            os.killpg(process.pid, signal.SIGKILL)
            _, stderr = process.communicate(timeout=5 * calibration.factor)
        measured["wall_seconds"] = time.perf_counter() - start
        measured["exit_code"] = process.returncode
        measured["stderr_bytes"] = len(stderr)
        if timing_path.exists():
            measured.update(json.loads(timing_path.read_text()))
    finally:
        if process_exists(process.pid, group=True):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5 * calibration.factor)
        (root / "metrics.json").write_text(json.dumps(measured, indent=2) + "\n")
    return measured


def number(metrics: dict[str, object], key: str) -> float:
    value = metrics[key]
    assert isinstance(value, (int, float)), f"Missing numeric measurement: {key}"
    return float(value)


def print_metrics(metrics: dict[str, object]) -> None:
    # Full coverage/status/error arrays remain in the artifact, not the console log.
    arrays = {
        "statuses",
        "errors",
        "analysis_tool_counts",
        "process_roles",
        "file_read_tools",
        "ssrf_patterns",
    }
    summary = {key: value for key, value in metrics.items() if key not in arrays}
    print(json.dumps(summary, sort_keys=True))


def assert_oversized_rejected(metrics: dict[str, object]) -> None:
    assert metrics["deadline_exceeded"] is False and metrics["exit_code"] == 0, metrics
    assert number(metrics, "peak_rss_bytes") < 300_000_000, metrics
    assert metrics["statuses"] == ["failed"], metrics
    errors = cast(list[str | None], metrics["errors"])
    assert (
        errors[0]
        and "frame" in errors[0].lower()
        and any(word in errors[0].lower() for word in ("size", "exceed", "limit", "large"))
    ), metrics
    assert metrics["total_tools"] == 0, metrics


def assert_frame_rejection_bounded(large_seconds: float, small_seconds: float, factor: float = 1.0) -> None:
    # Both frames exceed the 16 MiB limit, so rejection reads the same prefix:
    # 2.5x the bytes may cost at most 2x the time (linear would be 2.5x).
    assert large_seconds <= 2 * small_seconds + 0.1 * factor, (large_seconds, small_seconds)


def assert_limits(
    metrics: dict[str, object], case: Case, profile: str, calibration: Calibration = RAW_CALIBRATION
) -> None:
    stage = PROFILES.index(profile)
    assert metrics["deadline_exceeded"] is False, metrics
    assert metrics["exit_code"] == 0, metrics
    if case.name == "escape_dense":
        assert number(metrics, "redaction_input_bytes") == MIB, metrics
        assert 0 < number(metrics, "redaction_output_bytes") < MIB, metrics
        assert metrics["credential_withheld"] is True and metrics["stable"] is True, metrics
        assert 0 < number(metrics, "redaction_seconds") <= case.wall * calibration.factor, metrics
        assert number(metrics, "wall_seconds") <= case.wall * calibration.factor, metrics
        assert case.rss_mib is not None
        assert number(metrics, "peak_rss_bytes") <= case.rss_mib * MIB, metrics
        return
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
    if case.name == "oversized_50mb":
        assert_oversized_rejected(metrics)
        rss = None
    elif case.name == "spawn_child_exit":
        assert metrics["connected"] == 1 and metrics["total_tools"] == 1, metrics
        assert metrics["statuses"] in (["timeout", "connected"], ["failed", "connected"]), metrics
        roles = metrics["process_roles"]
        assert isinstance(roles, list) and sorted(roles) == ["child", "server", "server"], metrics
        assert number(metrics, "recorded_processes") == 3, metrics
    elif case.hostile:
        statuses = metrics["statuses"]
        assert isinstance(statuses, list) and len(statuses) == 1, metrics
        assert statuses[0] in {"connected", "timeout", "failed"}, metrics
        assert metrics["process_roles"] == ["server"], metrics
    elif "--skip-connect" in case.cli_args:
        assert metrics["discovered"] == case.servers, metrics
        assert metrics["connected"] == metrics["total_tools"] == 0, metrics
        statuses = metrics["statuses"]
        assert isinstance(statuses, list) and len(statuses) == case.servers, metrics
        assert set(statuses) == {"skipped"}, metrics
        assert number(metrics, "recorded_processes") == 0, metrics
    else:
        assert metrics["connected"] == case.servers and metrics["total_tools"] == case.tools, metrics
    if case.name in {"desc_5mb_x1", "desc_1mb_x20"}:
        assert number(metrics, "analysis_invocations") == case.servers, metrics
        assert metrics["analysis_tool_counts"] == [case.tools], metrics
        assert metrics["file_read_tools"] == [[f"tool_{i}" for i in range(case.tools)]], metrics
    if case.name == "pages_20k":
        assert metrics["statuses"] == ["connected"] and metrics["warning_codes"] == [], metrics
        assert number(metrics, "peak_rss_bytes") < 500_000_000, metrics
    if case.name == "ssrf_1mib":
        assert metrics["statuses"] == ["partial"], metrics
        assert metrics["ssrf_tool_counts"] == [1], metrics
        assert metrics["ssrf_description_bytes"] == [SSRF_RETAINED_BYTES], metrics
        assert metrics["ssrf_patterns"] == [["url_param_with_fetch_verb"]], metrics
        assert "surface_truncated" in cast(list[str], metrics["warning_codes"]), metrics
        assert number(metrics, "wall_seconds") < wall * calibration.factor, metrics
    else:
        if case.hostile:
            wall = number(metrics, "timeout") + 4.5 * calibration.factor
        else:
            wall *= calibration.factor
        assert number(metrics, "wall_seconds") <= wall, metrics
    if analysis is not None:
        assert number(metrics, "analysis_seconds") <= analysis * calibration.factor, metrics
    if rss is not None:
        assert number(metrics, "peak_rss_bytes") <= rss * MIB, metrics
    if "--skip-connect" not in case.cli_args:
        assert number(metrics, "recorded_processes") >= case.servers, metrics
    assert number(metrics, "leftover_processes") <= leftovers, metrics
    assert number(metrics, "leftover_groups") <= leftovers, metrics


@pytest.mark.perf
@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_hostile_performance(
    case: Case, tmp_path: Path, pytestconfig: pytest.Config, perf_calibration: Calibration
) -> None:
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        pytest.fail("Performance gate requires Linux or macOS process groups and peak-RSS accounting.")
    output: Path | None = pytestconfig.getoption("--perf-output")
    root = tmp_path if output is None else output.resolve() / case.name
    root.mkdir(parents=True, exist_ok=True)
    profile: str = pytestconfig.getoption("--perf-profile")
    metrics = run_case(root, case, calibration=perf_calibration)
    metrics["profile"] = profile
    (root / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print_metrics(metrics)
    if case.name == "oversized_50mb":
        smaller_root = root / "frame20"
        smaller_root.mkdir()
        smaller_case = replace(case, name="oversized_20mb", args=("oversized", "--frame-bytes", "20000000"))
        smaller_metrics = run_case(smaller_root, smaller_case, calibration=perf_calibration)
        print_metrics(smaller_metrics)
        assert_oversized_rejected(smaller_metrics)
        assert_frame_rejection_bounded(
            number(metrics, "wall_seconds"), number(smaller_metrics, "wall_seconds"), perf_calibration.factor
        )
    short: dict[str, object] | None = None
    if case.name == "scale_500":
        short_root = root / "timeout2"
        short_root.mkdir()
        short = run_case(short_root, case, calibration=perf_calibration, timeout=2)
        print_metrics(short)
    assert_limits(metrics, case, profile, perf_calibration)
    if short is not None:
        assert short["deadline_exceeded"] is False and short["exit_code"] == 0, short
        assert number(short, "leftover_processes") == number(short, "leftover_groups") == 0, short
        assert number(short, "wall_seconds") <= case.wall * perf_calibration.factor, short
        assert number(short, "recorded_processes") == 500, short
        assert number(short, "peak_rss_bytes") <= 213 * MIB, short
        if profile != "baseline":
            assert short["connected"] == 500 and short["total_tools"] == 5000, short
        else:
            assert set(cast(list[str], short["statuses"])) <= {"connected", "timeout"}, short


def test_frame_rejection_bound_rejects_size_dependent_timing() -> None:
    assert_frame_rejection_bounded(1.1, 1.0)
    for large in (2.5, 6.25):  # linear and quadratic growth from 20 MB to 50 MB
        with pytest.raises(AssertionError):
            assert_frame_rejection_bounded(large, 1.0)


def test_zombies_do_not_count_as_leftovers(tmp_path: Path) -> None:
    def stat(pid: int, state: str, pgrp: int) -> None:
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "stat").write_text(f"{pid} (fixture (x)) {state} 1 {pgrp} {pgrp} 0\n")

    (tmp_path / "self").mkdir()
    (tmp_path / "self" / "stat").write_text("1 (self) S 0 1 1 0\n")
    stat(4100, "Z", 4100)
    stat(4101, "S", 4200)
    stat(4102, "Z", 4200)
    assert not _live_on_linux(4100, group=False, proc=tmp_path)
    assert _live_on_linux(4101, group=False, proc=tmp_path)
    assert not _live_on_linux(4999, group=False, proc=tmp_path)
    assert not _live_on_linux(4100, group=True, proc=tmp_path)
    assert _live_on_linux(4200, group=True, proc=tmp_path)
    assert _live_on_linux(4100, group=False, proc=tmp_path / "missing")
