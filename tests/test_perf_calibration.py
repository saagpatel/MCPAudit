"""Synthetic calibration arithmetic and harness wiring; no timed workloads."""

from __future__ import annotations

import json
import math
import subprocess
import time
from pathlib import Path

import pytest

from tests import test_hostile_perf as perf


def calibration(process_ratio: float, cpu_ratio: float) -> perf.Calibration:
    sample = {
        "process": perf.REFERENCE["process"] * process_ratio,
        "cpu": perf.REFERENCE["cpu"] * cpu_ratio,
    }
    return perf.Calibration((sample, sample, sample))


@pytest.mark.parametrize("ratios,expected", [((0.5, 0.8), 1), ((3, 2), 3), ((2, 4), 4)])
def test_factor_uses_conservative_component_with_floor(ratios: tuple[float, float], expected: float) -> None:
    assert calibration(*ratios).factor == expected
    assert perf.Calibration().factor == 1


def test_calibration_records_component_medians_and_reference(capsys: pytest.CaptureFixture[str]) -> None:
    runs = tuple({key: value * ratio for key, value in perf.REFERENCE.items()} for ratio in (1, 9, 2))
    result = perf.Calibration(runs)
    assert result.seconds == {key: value * 2 for key, value in perf.REFERENCE.items()}
    assert result.metrics() == {
        "enabled": True,
        "runs_seconds": list(runs),
        "seconds": result.seconds,
        "reference_seconds": perf.REFERENCE,
        "factor": 2,
    }
    assert perf.Calibration().metrics()["enabled"] is False
    perf.print_metrics({"calibration": result.metrics(), "statuses": ["connected"]})
    assert json.loads(capsys.readouterr().out) == {"calibration": result.metrics()}


def test_scaling_changes_only_time_acceptance() -> None:
    case = perf.Case("synthetic", (), wall=10, analysis=2, rss_mib=100, servers=2, tools=3, leftovers=1)
    result = calibration(2, 1)
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": 20,
        "analysis_seconds": 4,
        "peak_rss_bytes": 100 * perf.MIB,
        "connected": 2,
        "total_tools": 3,
        "recorded_processes": 2,
        "leftover_processes": 1,
        "leftover_groups": 1,
    }
    perf.assert_limits(metrics, case, "baseline", result)
    with pytest.raises(AssertionError):
        perf.assert_limits(metrics, case, "baseline", perf.Calibration())
    for key, value in (
        ("wall_seconds", 21),
        ("analysis_seconds", 5),
        ("peak_rss_bytes", 101 * perf.MIB),
        ("connected", 1),
        ("total_tools", 4),
        ("recorded_processes", 1),
        ("leftover_processes", 2),
        ("leftover_groups", 2),
        ("exit_code", 1),
        ("deadline_exceeded", True),
    ):
        with pytest.raises(AssertionError):
            perf.assert_limits({**metrics, key: value}, case, "baseline", result)
    assert case == perf.Case(
        "synthetic", (), wall=10, analysis=2, rss_mib=100, servers=2, tools=3, leftovers=1
    )


def test_scaled_run_records_calibration_and_deadlines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[float] = []
    commands: list[list[str]] = []

    class Scanner:
        pid = 12345
        returncode = 0

        def __init__(self, command: list[str], **kwargs: object) -> None:
            commands.append(command)

        def communicate(self, *, timeout: float) -> tuple[bytes, bytes]:
            calls.append(timeout)
            return b"", b""

        def poll(self) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", Scanner)
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr(time, "perf_counter", lambda: 0)
    case = perf.CASES[0]
    result = calibration(2, 1)
    measured = perf.run_case(tmp_path, case, calibration=result, timeout=2)
    assert calls == [(case.wall + 10) * 2]
    assert commands[0][commands[0].index("--timeout") + 1] == "4"
    assert measured["calibration"] == result.metrics()
    assert measured["timeout"] == 4
    assert measured["deadline_seconds"] == calls[0]
    assert json.loads((tmp_path / "metrics.json").read_text()) == measured


@pytest.mark.parametrize("profile", perf.PROFILES)
def test_profile_time_targets_scale_but_status_and_memory_do_not(profile: str) -> None:
    case = perf.CASES[0]
    result = calibration(2, 1)
    target = case.wall if profile == "baseline" else 4
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": target * 2,
        "peak_rss_bytes": 213 * perf.MIB,
        "connected": 500,
        "total_tools": 5000,
        "recorded_processes": 500,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    perf.assert_limits(metrics, case, profile, result)
    with pytest.raises(AssertionError):
        perf.assert_limits({**metrics, "wall_seconds": target * 2 + 1}, case, profile, result)
    with pytest.raises(AssertionError):
        perf.assert_limits({**metrics, "peak_rss_bytes": 214 * perf.MIB}, case, profile, result)
    pages: dict[str, object] = {
        **metrics,
        "connected": 1,
        "total_tools": 20000,
        "recorded_processes": 1,
        "wall_seconds": 9,
        "statuses": ["connected"],
        "warning_codes": [],
    }
    perf.assert_limits(pages, perf.CASES[6], profile, result)
    with pytest.raises(AssertionError):
        perf.assert_limits({**pages, "statuses": ["timeout"]}, perf.CASES[6], profile, result)


def test_no_calibration_skips_workload(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected(root: Path) -> dict[str, float]:
        pytest.fail("Disabled calibration must not run its workload.")

    monkeypatch.setattr(perf, "calibration_run", unexpected)
    result = perf.calibrate(None)
    assert result.factor == 1 and result.runs == ()


def test_session_calibration_runs_three_samples(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Path] = []

    def sample(root: Path) -> dict[str, float]:
        calls.append(root)
        return {key: value * len(calls) for key, value in perf.REFERENCE.items()}

    monkeypatch.setattr(perf, "calibration_run", sample)
    result = perf.calibrate(tmp_path)
    assert calls == [tmp_path / str(i) for i in range(3)]
    assert result.factor == 2


@pytest.mark.parametrize("profile", perf.PROFILES)
@pytest.mark.parametrize("factor", [1.0, 1.25, 2.0])
def test_skip_connect_gate_requires_full_fleet_without_processes(profile: str, factor: float) -> None:
    case = next(case for case in perf.CASES if case.name == "scale_100k_skip")
    result = calibration(factor, factor)
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": 10 * factor,
        "discovered": 100_000,
        "connected": 0,
        "total_tools": 0,
        "statuses": ["skipped"] * 100_000,
        "recorded_processes": 0,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    perf.assert_limits(metrics, case, profile, result)
    for key, value in (
        ("wall_seconds", 10 * factor + 0.01),
        ("discovered", 99_999),
        ("connected", 1),
        ("total_tools", 1),
        ("statuses", ["skipped"] * 99_999),
        ("statuses", ["connected"] + ["skipped"] * 99_999),
        ("recorded_processes", 1),
        ("leftover_groups", 1),
    ):
        with pytest.raises(AssertionError):
            perf.assert_limits({**metrics, key: value}, case, profile, result)


@pytest.mark.parametrize("profile", perf.PROFILES)
@pytest.mark.parametrize("factor", [1.0, 1.25, 2.0])
def test_ssrf_gate_is_strict_and_requires_executed_analysis(profile: str, factor: float) -> None:
    case = next(case for case in perf.CASES if case.name == "ssrf_1mib")
    result = calibration(factor, factor)
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "wall_seconds": 0.99 * factor,
        "connected": 1,
        "total_tools": 1,
        "statuses": ["partial"],
        "ssrf_tool_counts": [1],
        "ssrf_description_bytes": [perf.SSRF_RETAINED_BYTES],
        "ssrf_patterns": [["url_param_with_fetch_verb"]],
        "warning_codes": ["surface_truncated"],
        "recorded_processes": 1,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    perf.assert_limits(metrics, case, profile, result)
    for key, value in (
        ("wall_seconds", factor),
        ("connected", 0),
        ("total_tools", 0),
        ("statuses", ["timeout"]),
        ("ssrf_tool_counts", []),
        ("ssrf_description_bytes", [0]),
        ("ssrf_patterns", [[]]),
        ("warning_codes", []),
        ("leftover_processes", 1),
        ("leftover_groups", 1),
    ):
        with pytest.raises(AssertionError):
            perf.assert_limits({**metrics, key: value}, case, profile, result)


@pytest.mark.parametrize("profile", perf.PROFILES)
@pytest.mark.parametrize("factor", [1.0, 1.25, 2.0])
@pytest.mark.parametrize("case", [case for case in perf.CASES if case.hostile], ids=lambda case: case.name)
def test_hostile_gate_scales_grace_and_requires_zero_leftovers(
    profile: str, factor: float, case: perf.Case
) -> None:
    result = calibration(factor, factor)
    timeout = math.ceil(case.timeout * factor)
    wall = timeout + 4.5 * factor
    orphan = case.name == "spawn_child_exit"
    metrics: dict[str, object] = {
        "deadline_exceeded": False,
        "exit_code": 0,
        "timeout": timeout,
        "wall_seconds": wall,
        "connected": 1 if orphan else 0,
        "total_tools": 1 if orphan else 0,
        "statuses": ["failed", "connected"] if orphan else ["timeout"],
        "process_roles": ["child", "server", "server"] if orphan else ["server"],
        "recorded_processes": 3 if orphan else 1,
        "leftover_processes": 0,
        "leftover_groups": 0,
    }
    perf.assert_limits(metrics, case, profile, result)
    for key, value in (
        ("wall_seconds", wall + 0.01),
        ("recorded_processes", 0),
        ("leftover_processes", 1),
        ("leftover_groups", 1),
    ):
        with pytest.raises(AssertionError):
            perf.assert_limits({**metrics, key: value}, case, profile, result)
