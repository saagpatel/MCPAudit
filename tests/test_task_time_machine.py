from __future__ import annotations

import builtins
import json
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.task_time_machine import (
    builtin_scenarios,
    parse_scenario_bytes,
    result_json_bytes,
    scan_scenario_path,
    simulate_scenario,
)
from mcp_audit.task_time_machine_cli import render_human
from mcp_audit.task_time_machine_models import TaskScenario, TaskSimulationResult

FIXTURES = Path(__file__).parent / "fixtures" / "task_time_machine"


@pytest.mark.parametrize(
    ("name", "verdict", "status", "rule_ids"),
    [
        ("happy-path", "pass", "completed", set()),
        ("transient-retry", "pass", "completed", set()),
        ("retry-exhaustion", "pass", "failed", set()),
        ("poll-cadence", "fail", "working", {"MCPTASK003"}),
        ("cancel-before-start", "pass", "cancelled", set()),
        ("cancel-during-work", "pass", "cancelled", set()),
        ("completion-vs-cancel-race", "pass", "completed", set()),
        ("expiry", "unknown", "working", {"MCPTASK007"}),
        ("duplicate-events", "fail", "working", {"MCPTASK006"}),
        ("stale-polling", "fail", "completed", {"MCPTASK003"}),
        ("input-required", "pass", "completed", set()),
        ("forbidden-post-terminal", "fail", "completed", {"MCPTASK002"}),
    ],
)
def test_builtin_scenario_matrix(name: str, verdict: str, status: str, rule_ids: set[str]) -> None:
    result = simulate_scenario(builtin_scenarios()[name])
    assert result.verdict == verdict
    assert result.final_task is not None
    assert result.final_task.status == status
    assert {finding.rule_id for finding in result.findings} == rule_ids


def test_execution_is_byte_deterministic_and_seed_free() -> None:
    scenario = builtin_scenarios()["happy-path"]
    first = result_json_bytes(simulate_scenario(scenario))
    second = result_json_bytes(simulate_scenario(scenario))
    assert first == second
    assert json.loads(first)["seed"] is None


def test_serialization_order_does_not_change_causal_result() -> None:
    original = builtin_scenarios()["completion-vs-cancel-race"]
    payload = original.model_dump(mode="json")
    payload["events"] = list(reversed(payload["events"]))
    reordered = TaskScenario.model_validate(payload)
    assert result_json_bytes(simulate_scenario(original)) == result_json_bytes(simulate_scenario(reordered))


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
@pytest.mark.parametrize("post_event", ["complete", "fail", "input_required"])
def test_property_style_terminal_states_reject_transitions(terminal: str, post_event: str) -> None:
    events: list[dict[str, object]] = [{"event_id": "e1", "sequence": 1, "at_ms": 0, "type": "create"}]
    if terminal == "completed":
        events.append({"event_id": "e2", "sequence": 2, "at_ms": 1, "type": "complete", "result": {}})
    elif terminal == "failed":
        events.append(
            {
                "event_id": "e2",
                "sequence": 2,
                "at_ms": 1,
                "type": "fail",
                "error": {"code": -32603, "message": "fixture", "data": None},
            }
        )
    else:
        events.extend(
            [
                {"event_id": "cancel", "sequence": 2, "at_ms": 1, "type": "cancel_requested"},
                {"event_id": "e2", "sequence": 3, "at_ms": 2, "type": "cancel_applied"},
            ]
        )
    sequence = 4 if terminal == "cancelled" else 3
    if post_event == "complete":
        events.append(
            {"event_id": "post", "sequence": sequence, "at_ms": 3, "type": "complete", "result": {}}
        )
    elif post_event == "fail":
        events.append(
            {
                "event_id": "post",
                "sequence": sequence,
                "at_ms": 3,
                "type": "fail",
                "error": {"code": -32603, "message": "late", "data": None},
            }
        )
    else:
        events.append(
            {
                "event_id": "post",
                "sequence": sequence,
                "at_ms": 3,
                "type": "input_required",
                "request_key": "late",
            }
        )
    payload = builtin_scenarios()["happy-path"].model_dump(mode="json")
    payload.update({"scenario_id": f"{terminal}-{post_event}", "task_id": "task-property", "events": events})
    result = simulate_scenario(TaskScenario.model_validate(payload))
    assert result.final_task is not None
    assert result.final_task.status == terminal
    assert "MCPTASK002" in {finding.rule_id for finding in result.findings}


def test_terminal_poll_is_observation_not_transition() -> None:
    result = simulate_scenario(builtin_scenarios()["happy-path"])
    assert result.transitions[-1].event_type == "poll"
    assert result.transitions[-1].before_status == "completed"
    assert result.transitions[-1].after_status == "completed"
    assert result.transitions[-1].disposition == "observed"


def test_pure_simulator_reads_no_network_credentials_files_or_wall_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario = builtin_scenarios()["input-required"]

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("ambient access is forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr("os.getenv", forbidden)
    monkeypatch.setattr(Path, "home", forbidden)
    monkeypatch.setattr(builtins, "open", forbidden)
    result = simulate_scenario(scenario)
    assert result.verdict == "pass"


def test_arbitrary_result_payload_is_not_reflected() -> None:
    sentinel = "not-a-real-secret-but-must-not-echo"
    payload = builtin_scenarios()["happy-path"].model_dump(mode="json")
    payload["events"][3]["result"] = {"token": sentinel}
    output = result_json_bytes(simulate_scenario(TaskScenario.model_validate(payload)))
    assert sentinel.encode() not in output
    assert b'"result_present":true' in output


def test_checked_in_fixture_matches_builtin() -> None:
    fixture = scan_scenario_path(FIXTURES / "happy-path.json")
    builtin = simulate_scenario(builtin_scenarios()["happy-path"])
    assert result_json_bytes(fixture) == result_json_bytes(builtin)


def test_malformed_fixture_emits_structured_unknown() -> None:
    result = scan_scenario_path(FIXTURES / "malformed.json")
    assert result.verdict == "unknown"
    assert result.coverage.input_state == "malformed"
    assert result.findings[0].rule_id == "MCPTASK000"


def test_oversized_fixture_emits_bounded_unknown(tmp_path: Path) -> None:
    scenario = tmp_path / "oversized.json"
    scenario.write_bytes(b" " * (1_048_576 + 1))
    result = scan_scenario_path(scenario)
    assert result.verdict == "unknown"
    assert result.coverage.limitations == ["input_size_limit_exceeded"]


def test_symlink_fixture_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_bytes((FIXTURES / "happy-path.json").read_bytes())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    result = CliRunner().invoke(main, ["task-time-machine", "run", str(link), "--json"])
    assert result.exit_code == 2
    assert "scenario_input_open_failed" in result.output


def test_duplicate_json_keys_are_malformed() -> None:
    parsed = parse_scenario_bytes(b'{"schema_version":"x","schema_version":"y"}')
    assert isinstance(parsed, TaskSimulationResult)
    assert parsed.coverage.limitations == ["invalid_strict_json"]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value":NaN}',
        (b'{"value":' + b"[" * 40 + b"0" + b"]" * 40 + b"}"),
    ],
)
def test_non_finite_or_deep_json_is_structured_unknown(raw: bytes) -> None:
    parsed = parse_scenario_bytes(raw)
    assert isinstance(parsed, TaskSimulationResult)
    assert parsed.verdict == "unknown"
    assert parsed.coverage.input_state == "malformed"


def test_unknown_protocol_is_not_graded_as_current() -> None:
    payload = builtin_scenarios()["happy-path"].model_dump(mode="json")
    payload["protocol_version"] = "2025-11-25"
    result = simulate_scenario(TaskScenario.model_validate(payload))
    assert result.verdict == "unknown"
    assert result.coverage.input_state == "unsupported"
    assert result.transitions == []


def test_human_output_explains_every_transition() -> None:
    result = simulate_scenario(builtin_scenarios()["input-required"])
    output = render_human(result)
    for transition in result.transitions:
        assert f"seq={transition.sequence}" in output
        assert transition.explanation in output


def test_strict_schemas_are_versioned_and_closed() -> None:
    scenario_schema = TaskScenario.model_json_schema()
    result_schema = TaskSimulationResult.model_json_schema()
    assert scenario_schema["properties"]["schema_version"]["const"] == (
        "mcpaudit.task-time-machine.scenario.v1"
    )
    assert scenario_schema["additionalProperties"] is False
    assert result_schema["properties"]["schema_version"]["const"] == ("mcpaudit.task-time-machine.result.v1")
    assert result_schema["additionalProperties"] is False


def test_cli_builtin_human_and_json_modes() -> None:
    human = CliRunner().invoke(main, ["task-time-machine", "run", "--builtin", "happy-path"])
    machine = CliRunner().invoke(main, ["task-time-machine", "run", "--builtin", "happy-path", "--json"])
    assert human.exit_code == 0
    assert "Transitions" in human.output
    assert machine.exit_code == 0
    assert json.loads(machine.output)["verdict"] == "pass"


def test_cli_runs_user_fixture_and_returns_one_for_unknown() -> None:
    success = CliRunner().invoke(
        main, ["task-time-machine", "run", str(FIXTURES / "input-required.json"), "--json"]
    )
    malformed = CliRunner().invoke(
        main, ["task-time-machine", "run", str(FIXTURES / "malformed.json"), "--json"]
    )
    assert success.exit_code == 0
    assert json.loads(success.output)["final_task"]["status"] == "completed"
    assert malformed.exit_code == 1
    assert json.loads(malformed.output)["coverage"]["input_state"] == "malformed"


@pytest.mark.parametrize("contract", ["scenario", "result"])
def test_cli_emits_contract_schema(contract: str) -> None:
    result = CliRunner().invoke(main, ["task-time-machine", "schema", contract])
    assert result.exit_code == 0
    assert json.loads(result.output)["additionalProperties"] is False


def test_cli_requires_exactly_one_input() -> None:
    result = CliRunner().invoke(main, ["task-time-machine", "run"])
    assert result.exit_code == 2
    assert "exactly one" in result.output
