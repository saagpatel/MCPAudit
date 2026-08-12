from __future__ import annotations

import json
import os
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
from mcp_audit.session_resume_models import DeliveryClassification, SessionResumeScenario

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


def _scenario_with_steps(
    scenario_id: str,
    steps: list[dict[str, object]],
) -> SessionResumeScenario:
    payload = load_builtin_scenarios()["successful-resume-control"].model_dump(mode="json")
    payload.update(
        {
            "scenario_id": scenario_id,
            "title": scenario_id,
            "description": f"Focused regression scenario for {scenario_id}.",
            "steps": steps,
        }
    )
    return SessionResumeScenario.model_validate(payload)


def test_path_open_uses_nonblocking_flag_after_regular_file_precheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not hasattr(os, "O_NONBLOCK"):
        pytest.skip("platform does not expose O_NONBLOCK")
    path = tmp_path / "scenario.json"
    path.write_bytes(scenario_json_bytes(load_builtin_scenarios()["successful-resume-control"]))

    def reject_open(_path: Path, flags: int) -> int:
        assert flags & os.O_NONBLOCK
        raise OSError("synthetic raced replacement")

    monkeypatch.setattr(os, "open", reject_open)
    with pytest.raises(SessionResumeInputError, match="read safely"):
        load_scenario_path(path)


def test_path_revalidates_descriptor_after_in_place_read_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "scenario.json"
    path.write_bytes(scenario_json_bytes(load_builtin_scenarios()["successful-resume-control"]))
    original_read = os.read
    before = path.stat()
    raced = False

    def read_then_overwrite(descriptor: int, limit: int) -> bytes:
        nonlocal raced
        chunk = original_read(descriptor, limit)
        if chunk and not raced:
            raced = True
            with path.open("r+b") as raced_file:
                raced_file.write(b" ")
            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
        return chunk

    monkeypatch.setattr(os, "read", read_then_overwrite)

    with pytest.raises(SessionResumeInputError, match="identity changed during bounded read"):
        load_scenario_path(path)


def test_distinct_result_event_ids_are_counted_as_duplicates_per_request() -> None:
    report = run_scenario(
        _scenario_with_steps(
            "distinct-result-event-duplicates",
            [
                {"step_id": "init", "at_ms": 0, "type": "initialize", "session_id": "session-a"},
                {
                    "step_id": "send",
                    "at_ms": 1,
                    "type": "send_request",
                    "request_id": "req-a",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept",
                    "at_ms": 2,
                    "type": "accept_request",
                    "request_id": "req-a",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete",
                    "at_ms": 3,
                    "type": "complete_request",
                    "request_id": "req-a",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit-a",
                    "at_ms": 4,
                    "type": "emit_event",
                    "request_id": "req-a",
                    "event_id": "result:a",
                    "event_kind": "result",
                },
                {"step_id": "deliver-a", "at_ms": 5, "type": "deliver_event", "event_id": "result:a"},
                {
                    "step_id": "emit-b",
                    "at_ms": 6,
                    "type": "emit_event",
                    "request_id": "req-a",
                    "event_id": "result:b",
                    "event_kind": "result",
                },
                {"step_id": "deliver-b", "at_ms": 7, "type": "deliver_event", "event_id": "result:b"},
            ],
        )
    )

    assert report.safety.duplicate_risk == "observed"
    assert report.safety.at_most_once == "contradicted"
    assert DeliveryClassification.DUPLICATE_RISK in report.safety.classifications
    assert report.verdict == "risk"


def test_every_accepted_request_requires_completion_evidence() -> None:
    report = run_scenario(
        _scenario_with_steps(
            "per-request-completion-evidence",
            [
                {"step_id": "init", "at_ms": 0, "type": "initialize", "session_id": "session-a"},
                {
                    "step_id": "send-a",
                    "at_ms": 1,
                    "type": "send_request",
                    "request_id": "req-a",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept-a",
                    "at_ms": 2,
                    "type": "accept_request",
                    "request_id": "req-a",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete-a",
                    "at_ms": 3,
                    "type": "complete_request",
                    "request_id": "req-a",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit-a",
                    "at_ms": 4,
                    "type": "emit_event",
                    "request_id": "req-a",
                    "event_id": "result:a",
                    "event_kind": "result",
                },
                {"step_id": "deliver-a", "at_ms": 5, "type": "deliver_event", "event_id": "result:a"},
                {
                    "step_id": "send-b",
                    "at_ms": 6,
                    "type": "send_request",
                    "request_id": "req-b",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept-b",
                    "at_ms": 7,
                    "type": "accept_request",
                    "request_id": "req-b",
                    "server_instance": "server-a",
                },
            ],
        )
    )

    assert report.safety.at_least_once == "contradicted"
    assert report.safety.lost_result_risk == "observed"
    assert DeliveryClassification.AT_LEAST_ONCE not in report.safety.classifications
    assert DeliveryClassification.LOST_RESULT_RISK in report.safety.classifications
    assert "accepted requests without completion=1" in report.safety.rationale
    assert report.verdict == "risk"


def test_successful_replay_resolves_a_provisional_result_drop() -> None:
    report = run_scenario(
        _scenario_with_steps(
            "replay-recovers-dropped-result",
            [
                {"step_id": "init", "at_ms": 0, "type": "initialize", "session_id": "session-a"},
                {
                    "step_id": "send",
                    "at_ms": 1,
                    "type": "send_request",
                    "request_id": "req-a",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept",
                    "at_ms": 2,
                    "type": "accept_request",
                    "request_id": "req-a",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete",
                    "at_ms": 3,
                    "type": "complete_request",
                    "request_id": "req-a",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit",
                    "at_ms": 4,
                    "type": "emit_event",
                    "request_id": "req-a",
                    "event_id": "result:a",
                    "event_kind": "result",
                },
                {"step_id": "drop", "at_ms": 5, "type": "drop_event", "event_id": "result:a"},
                {
                    "step_id": "disconnect",
                    "at_ms": 6,
                    "type": "disconnect",
                    "request_id": "req-a",
                    "phase": "after_event",
                },
                {
                    "step_id": "reconnect",
                    "at_ms": 7,
                    "type": "reconnect",
                    "request_id": "req-a",
                    "attempt": 1,
                    "session_id": "session-a",
                },
                {
                    "step_id": "replay",
                    "at_ms": 8,
                    "type": "replay",
                    "request_id": "req-a",
                    "event_ids": ["result:a"],
                },
            ],
        )
    )

    assert report.safety.lost_result_risk == "not_observed"
    assert report.safety.classifications == [
        DeliveryClassification.AT_MOST_ONCE,
        DeliveryClassification.AT_LEAST_ONCE,
    ]
    assert "MCPSR006" not in {finding.rule_id for finding in report.findings}
    assert report.verdict == "pass"


def test_lost_result_risk_is_correlated_per_request() -> None:
    report = run_scenario(
        _scenario_with_steps(
            "per-request-lost-result",
            [
                {"step_id": "init", "at_ms": 0, "type": "initialize", "session_id": "session-a"},
                {
                    "step_id": "send-a",
                    "at_ms": 1,
                    "type": "send_request",
                    "request_id": "req-a",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept-a",
                    "at_ms": 2,
                    "type": "accept_request",
                    "request_id": "req-a",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete-a",
                    "at_ms": 3,
                    "type": "complete_request",
                    "request_id": "req-a",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit-a",
                    "at_ms": 4,
                    "type": "emit_event",
                    "request_id": "req-a",
                    "event_id": "result:a",
                    "event_kind": "result",
                },
                {
                    "step_id": "send-b",
                    "at_ms": 5,
                    "type": "send_request",
                    "request_id": "req-b",
                    "session_id": "session-a",
                },
                {
                    "step_id": "accept-b",
                    "at_ms": 6,
                    "type": "accept_request",
                    "request_id": "req-b",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete-b",
                    "at_ms": 7,
                    "type": "complete_request",
                    "request_id": "req-b",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit-b1",
                    "at_ms": 8,
                    "type": "emit_event",
                    "request_id": "req-b",
                    "event_id": "result:b1",
                    "event_kind": "result",
                },
                {"step_id": "deliver-b1", "at_ms": 9, "type": "deliver_event", "event_id": "result:b1"},
                {
                    "step_id": "emit-b2",
                    "at_ms": 10,
                    "type": "emit_event",
                    "request_id": "req-b",
                    "event_id": "result:b2",
                    "event_kind": "result",
                },
                {"step_id": "deliver-b2", "at_ms": 11, "type": "deliver_event", "event_id": "result:b2"},
            ],
        )
    )

    assert report.safety.lost_result_risk == "observed"
    assert DeliveryClassification.LOST_RESULT_RISK in report.safety.classifications
    assert report.safety.duplicate_risk == "observed"
    assert report.verdict == "risk"


def test_rejected_send_cannot_enable_later_acceptance_or_delivery_proof() -> None:
    report = run_scenario(
        _scenario_with_steps(
            "rejected-send-cannot-progress",
            [
                {"step_id": "init", "at_ms": 0, "type": "initialize", "session_id": "session-a"},
                {
                    "step_id": "send",
                    "at_ms": 1,
                    "type": "send_request",
                    "request_id": "req-rejected",
                    "session_id": "session-invalid",
                },
                {
                    "step_id": "accept",
                    "at_ms": 2,
                    "type": "accept_request",
                    "request_id": "req-rejected",
                    "server_instance": "server-a",
                },
                {
                    "step_id": "complete",
                    "at_ms": 3,
                    "type": "complete_request",
                    "request_id": "req-rejected",
                    "result_marker": "<synthetic-result>",
                },
                {
                    "step_id": "emit",
                    "at_ms": 4,
                    "type": "emit_event",
                    "request_id": "req-rejected",
                    "event_id": "result:rejected",
                    "event_kind": "result",
                },
                {
                    "step_id": "deliver",
                    "at_ms": 5,
                    "type": "deliver_event",
                    "event_id": "result:rejected",
                },
            ],
        )
    )

    outcomes = {entry.step_id: entry.outcome for entry in report.transcript.entries}
    assert outcomes["send"] == "rejected"
    assert outcomes["accept"] == "ambiguous"
    assert outcomes["complete"] == "ambiguous"
    assert outcomes["emit"] == "ambiguous"
    assert outcomes["deliver"] == "ambiguous"
    assert report.safety.at_least_once == "contradicted"
    assert DeliveryClassification.AT_LEAST_ONCE not in report.safety.classifications


def test_supplied_session_ids_are_report_local_pseudonyms() -> None:
    payload = load_builtin_scenarios()["session-rotation-migration"].model_dump(mode="json")
    raw_session_ids = {"session-old": "bearer-like-old-session", "session-new": "bearer-like-new-session"}
    for step in payload["steps"]:
        if "session_id" in step:
            step["session_id"] = raw_session_ids.get(step["session_id"], step["session_id"])
        if "old_session_id" in step:
            step["old_session_id"] = raw_session_ids[step["old_session_id"]]
        if "new_session_id" in step:
            step["new_session_id"] = raw_session_ids[step["new_session_id"]]
    scenario = SessionResumeScenario.model_validate(payload)

    report = run_scenario(scenario)
    serialized = report_json_bytes(report)
    rendered_ids = {entry.session_id for entry in report.transcript.entries if entry.session_id is not None}

    assert all(raw.encode() not in serialized for raw in raw_session_ids.values())
    assert rendered_ids == {"session-ref-001", "session-ref-002"}
    assert all(raw not in finding.target for raw in raw_session_ids.values() for finding in report.findings)
