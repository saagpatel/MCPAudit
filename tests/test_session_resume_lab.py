from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.session_resume_lab import (
    SessionResumeInputError,
    load_builtin_scenarios,
    load_scenario_path,
    report_json_bytes,
    run_builtin_suite,
    run_scenario,
    scenario_json_bytes,
)
from mcp_audit.session_resume_models import DeliveryClassification

REQUIRED_FAULTS = {
    "disconnect-before-acceptance",
    "disconnect-after-acceptance-before-response",
    "dropped-event",
    "duplicated-event",
    "stale-last-event-id",
    "unknown-last-event-id",
    "missing-session-id",
    "invalid-session-id",
    "session-expiry",
    "session-termination",
    "server-restart",
    "session-rotation-migration",
    "concurrent-reconnects",
    "replay-gap",
    "cancellation-after-disconnect",
    "retry-bound-exceeded",
}


def test_builtin_corpus_covers_required_faults_and_negative_control() -> None:
    scenarios = load_builtin_scenarios()
    assert REQUIRED_FAULTS <= set(scenarios)
    assert "successful-resume-control" in scenarios
    assert "current-profile-resume-unsupported" in scenarios


def test_every_builtin_replays_byte_identically_with_exact_ordering() -> None:
    for scenario in load_builtin_scenarios().values():
        first = run_scenario(scenario)
        second = run_scenario(scenario)
        assert report_json_bytes(first) == report_json_bytes(second)
        assert [item.order for item in first.transcript.entries] == list(range(1, len(scenario.steps) + 1))
        assert [item.at_ms for item in first.transcript.entries] == sorted(
            item.at_ms for item in first.transcript.entries
        )
        assert first.scenario_digest_sha256 == second.scenario_digest_sha256


def test_virtual_transport_state_does_not_leak_between_runs() -> None:
    scenario = load_builtin_scenarios()["successful-resume-control"]
    original = report_json_bytes(run_scenario(scenario))
    _ = run_builtin_suite()
    after_suite = report_json_bytes(run_scenario(scenario))
    assert after_suite == original


@pytest.mark.parametrize(
    ("scenario_id", "classification", "rule_id"),
    [
        ("disconnect-before-acceptance", DeliveryClassification.UNKNOWN, "MCPSR000"),
        ("disconnect-after-acceptance-before-response", DeliveryClassification.LOST_RESULT_RISK, "MCPSR006"),
        ("dropped-event", DeliveryClassification.LOST_RESULT_RISK, "MCPSR006"),
        ("duplicated-event", DeliveryClassification.DUPLICATE_RISK, "MCPSR005"),
        ("stale-last-event-id", DeliveryClassification.LOST_RESULT_RISK, "MCPSR004"),
        ("unknown-last-event-id", DeliveryClassification.UNKNOWN, "MCPSR004"),
        ("missing-session-id", DeliveryClassification.AT_MOST_ONCE, "MCPSR002"),
        ("invalid-session-id", DeliveryClassification.AT_MOST_ONCE, "MCPSR003"),
        ("session-expiry", DeliveryClassification.UNKNOWN, "MCPSR003"),
        ("session-termination", DeliveryClassification.AT_MOST_ONCE, "MCPSR003"),
        ("server-restart", DeliveryClassification.LOST_RESULT_RISK, "MCPSR009"),
        ("session-rotation-migration", DeliveryClassification.UNKNOWN, "MCPSR009"),
        ("concurrent-reconnects", DeliveryClassification.UNKNOWN, "MCPSR007"),
        ("replay-gap", DeliveryClassification.LOST_RESULT_RISK, "MCPSR004"),
        ("cancellation-after-disconnect", DeliveryClassification.UNKNOWN, "MCPSR008"),
        ("retry-bound-exceeded", DeliveryClassification.UNKNOWN, "MCPSR007"),
        ("current-profile-resume-unsupported", DeliveryClassification.AT_MOST_ONCE, "MCPSR001"),
    ],
)
def test_faults_have_actionable_classification(
    scenario_id: str,
    classification: DeliveryClassification,
    rule_id: str,
) -> None:
    report = run_scenario(load_builtin_scenarios()[scenario_id])
    assert classification in report.safety.classifications
    assert rule_id in {item.rule_id for item in report.findings}
    assert all(item.remediation for item in report.findings)
    assert report.claim_ceiling == "local_model_observations_only_exactly_once_unproven"


def test_negative_control_is_at_most_and_at_least_once_without_exactly_once_claim() -> None:
    report = run_scenario(load_builtin_scenarios()["successful-resume-control"])
    assert report.verdict == "pass"
    assert report.safety.classifications == [
        DeliveryClassification.AT_MOST_ONCE,
        DeliveryClassification.AT_LEAST_ONCE,
    ]
    assert "exactly_once" not in {item.value for item in report.safety.classifications}


def test_retry_bound_is_reported_and_execution_terminates() -> None:
    report = run_scenario(load_builtin_scenarios()["retry-bound-exceeded"])
    matching = [item for item in report.findings if item.rule_id == "MCPSR007"]
    assert any("bound exceeded" in item.title.lower() for item in matching)
    assert len(report.transcript.entries) == 5


def test_suite_has_no_network_path(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    report = run_builtin_suite()
    assert report.scenario_count >= len(REQUIRED_FAULTS)


def test_supplied_json_path_matches_builtin(tmp_path: Path) -> None:
    scenario = load_builtin_scenarios()["dropped-event"]
    path = tmp_path / "scenario.json"
    path.write_bytes(scenario_json_bytes(scenario))
    assert report_json_bytes(run_scenario(load_scenario_path(path))) == report_json_bytes(
        run_scenario(scenario)
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b'{"schema_version":"mcpaudit.session-resume.scenario.v1","schema_version":"duplicate"}',
        json.dumps({"unexpected": True}).encode(),
    ],
)
def test_malformed_inputs_fail_closed(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(payload)
    with pytest.raises(SessionResumeInputError):
        load_scenario_path(path)


def test_oversized_and_symlink_inputs_fail_closed(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 1_048_577)
    with pytest.raises(SessionResumeInputError, match="exceeds"):
        load_scenario_path(oversized)

    target = tmp_path / "target.json"
    target.write_bytes(scenario_json_bytes(load_builtin_scenarios()["dropped-event"]))
    symlink = tmp_path / "scenario-link.json"
    symlink.symlink_to(target)
    with pytest.raises(SessionResumeInputError, match="non-symlink"):
        load_scenario_path(symlink)


def test_excessive_json_depth_fails_closed(tmp_path: Path) -> None:
    value: object = "leaf"
    for _ in range(40):
        value = {"nested": value}
    path = tmp_path / "deep.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(SessionResumeInputError, match="JSON levels"):
        load_scenario_path(path)


def test_cli_lists_runs_builtins_supplied_json_and_schemas(tmp_path: Path) -> None:
    runner = CliRunner()
    listed = runner.invoke(main, ["session-resume", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    assert "disconnect-before-acceptance" in listed.output

    readable = runner.invoke(main, ["session-resume", "run", "dropped-event"])
    assert readable.exit_code == 0, readable.output
    assert "lost-result-risk=observed" in readable.output

    machine = runner.invoke(
        main,
        ["session-resume", "run", "successful-resume-control", "--format", "json"],
    )
    assert machine.exit_code == 0, machine.output
    assert json.loads(machine.output)["schema_version"] == "mcpaudit.session-resume.report.v1"

    scenario_path = tmp_path / "supplied.json"
    scenario_path.write_bytes(scenario_json_bytes(load_builtin_scenarios()["disconnect-before-acceptance"]))
    supplied = runner.invoke(
        main,
        ["session-resume", "run", str(scenario_path), "--format", "json"],
    )
    assert supplied.exit_code == 0, supplied.output
    assert json.loads(supplied.output)["scenario_id"] == "disconnect-before-acceptance"

    for contract in ("scenario", "transcript", "report", "suite-report"):
        schema = runner.invoke(main, ["session-resume", "schema", contract])
        assert schema.exit_code == 0, schema.output
        assert json.loads(schema.output)["type"] == "object"


def test_cli_rejects_unknown_or_conflicting_selection() -> None:
    runner = CliRunner()
    unknown = runner.invoke(main, ["session-resume", "run", "not-a-scenario"])
    assert unknown.exit_code == 2
    assert "unknown built-in scenario ID" in unknown.output
    conflict = runner.invoke(
        main,
        ["session-resume", "run", "dropped-event", "--all"],
    )
    assert conflict.exit_code == 2
