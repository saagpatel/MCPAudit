"""Focused proof for the fixture-first AG-UI interrupt integrity auditor."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from mcp_audit.agui_interrupt_models import AGUIInterruptReport, FixtureManifest
from mcp_audit.agui_interrupt_reducer import ReducerState
from mcp_audit.agui_interrupt_scanner import (
    AGUIInterruptInputError,
    render_sarif,
    report_json_bytes,
    sarif_json_bytes,
    scan_agui_interrupt_path,
)
from mcp_audit.cli import main

FIXTURE_ROOT = Path("tests/fixtures/agui_interrupt")
RULE_TRIPLETS = {
    "AGUI000": "coverage",
    "AGUI001": "binding",
    "AGUI002": "response-set",
    "AGUI003": "contract",
    "AGUI004": "snapshot",
    "AGUI005": "idempotency",
    "AGUI006": "lifecycle",
}
ADDITIONAL_VARIANTS = {
    "agui001-stale-attempt-vulnerable.jsonl": ("AGUI001", "wrong_source_run"),
    "agui002-extra-vulnerable.jsonl": ("AGUI002", "extra_response"),
    "agui002-duplicate-vulnerable.jsonl": ("AGUI002", "duplicate_response"),
    "agui003-tool-id-vulnerable.jsonl": ("AGUI003", "unbound_tool_result"),
}


def _fixture(name: str) -> Path:
    return FIXTURE_ROOT / name


@pytest.mark.parametrize(("rule_id", "family"), RULE_TRIPLETS.items())
def test_vulnerable_fixture_fires_its_stable_rule(rule_id: str, family: str) -> None:
    report = scan_agui_interrupt_path(_fixture(f"{rule_id.lower()}-{family}-vulnerable.jsonl"))
    assert rule_id in {finding.rule_id for finding in report.findings}
    assert report.verdict == ("unknown" if rule_id == "AGUI000" else "fail")


@pytest.mark.parametrize(("rule_id", "family"), RULE_TRIPLETS.items())
def test_negative_fixture_does_not_fire_family_rule(rule_id: str, family: str) -> None:
    report = scan_agui_interrupt_path(_fixture(f"{rule_id.lower()}-{family}-negative.jsonl"))
    assert rule_id not in {finding.rule_id for finding in report.findings}
    assert report.verdict == "pass"


@pytest.mark.parametrize(("rule_id", "family"), RULE_TRIPLETS.items())
def test_near_miss_fixture_does_not_fire_family_rule(rule_id: str, family: str) -> None:
    report = scan_agui_interrupt_path(_fixture(f"{rule_id.lower()}-{family}-near-miss.jsonl"))
    assert rule_id not in {finding.rule_id for finding in report.findings}
    assert report.verdict == "pass"


@pytest.mark.parametrize(("name", "expected"), ADDITIONAL_VARIANTS.items())
def test_rule_variants_are_distinguished(name: str, expected: tuple[str, str]) -> None:
    report = scan_agui_interrupt_path(_fixture(name))
    observed = {(finding.rule_id, finding.kind.value) for finding in report.findings}
    assert expected in observed


def test_parallel_interleaving_is_not_a_finding() -> None:
    report = scan_agui_interrupt_path(_fixture("agui001-binding-negative.jsonl"))
    assert report.verdict == "pass"
    assert report.findings == []
    assert report.state.resolved_count == 2


def test_parent_run_id_is_orthogonal_to_resume_binding() -> None:
    report = scan_agui_interrupt_path(_fixture("agui001-binding-near-miss.jsonl"))
    assert report.verdict == "pass"
    assert report.state.resolved_count == 1


def test_benign_same_run_delivery_retry_is_idempotent() -> None:
    report = scan_agui_interrupt_path(_fixture("agui005-idempotency-near-miss.jsonl"))
    assert report.verdict == "pass"
    assert report.state.resolved_count == 1


def test_cross_run_duplicate_can_be_explicitly_rejected() -> None:
    report = scan_agui_interrupt_path(_fixture("agui005-idempotency-negative.jsonl"))
    assert report.verdict == "pass"
    assert report.state.resolved_count == 1


def test_expired_resume_can_be_explicitly_rejected_without_reopening() -> None:
    report = scan_agui_interrupt_path(_fixture("agui006-lifecycle-negative.jsonl"))
    assert report.verdict == "pass"
    assert report.state.expired_count == 1


def test_run_error_restores_a_valid_resume_to_open_state(tmp_path: Path) -> None:
    fixture = tmp_path / "resume-error.jsonl"
    source = _fixture("agui002-response-set-negative.jsonl").read_text(encoding="utf-8")
    fixture.write_text(
        source.replace(
            '{"type":"RUN_FINISHED","threadId":"thread-a","runId":"run-2","outcome":{"type":"success"}}}',
            '{"type":"RUN_ERROR","message":"resume rejected","code":"REJECTED"}}',
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "pass"
    assert report.state.open_count == 1
    assert report.state.cancelled_count == 0


def test_retry_after_pre_application_run_error_can_apply_once(tmp_path: Path) -> None:
    fixture = tmp_path / "resume-error-retry.jsonl"
    source = _fixture("agui002-response-set-negative.jsonl").read_text(encoding="utf-8")
    source = source.replace(
        '{"type":"RUN_FINISHED","threadId":"thread-a","runId":"run-2","outcome":{"type":"success"}}}',
        '{"type":"RUN_ERROR","message":"resume rejected","code":"REJECTED"}}',
    )
    source += (
        '{"kind":"run_input","sequence":7,"timestamp":"2026-07-28T12:00:06Z",'
        '"input":{"threadId":"thread-a","runId":"run-3","resume":[{"interruptId":'
        '"interrupt-1","status":"cancelled"}]}}\n'
        '{"kind":"event","sequence":8,"timestamp":"2026-07-28T12:00:07Z",'
        '"streamId":"stream-3","event":{"type":"RUN_STARTED","threadId":"thread-a",'
        '"runId":"run-3"}}\n'
        '{"kind":"event","sequence":9,"timestamp":"2026-07-28T12:00:08Z",'
        '"streamId":"stream-3","event":{"type":"RUN_FINISHED","threadId":"thread-a",'
        '"runId":"run-3","outcome":{"type":"success"}}}\n'
    )
    fixture.write_text(source, encoding="utf-8")
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "pass"
    assert report.state.cancelled_count == 1


def test_unobserved_resume_and_silent_interrupt_supersession_are_detected(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "silent-supersession.jsonl"
    source = _fixture("agui004-snapshot-negative.jsonl").read_text(encoding="utf-8")
    fixture.write_text(
        source + '{"kind":"event","sequence":4,"timestamp":"2026-07-28T12:00:03Z",'
        '"streamId":"stream-2","event":{"type":"RUN_STARTED","threadId":"thread-a",'
        '"runId":"run-2"}}\n' + '{"kind":"event","sequence":5,"timestamp":"2026-07-28T12:00:04Z",'
        '"streamId":"stream-2","event":{"type":"RUN_FINISHED","threadId":"thread-a",'
        '"runId":"run-2","outcome":{"type":"interrupt","interrupts":[{"id":"interrupt-2",'
        '"reason":"confirmation"}]}}}\n',
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    observed = {(finding.rule_id, finding.kind.value) for finding in report.findings}
    assert ("AGUI001", "missing_resume") in observed
    assert ("AGUI006", "interrupt_set_superseded") in observed


def test_tool_call_interrupt_requires_args_before_end(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-tool-args.jsonl"
    lines = _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
    fixture.write_text(
        "\n".join(line for line in lines if '"type":"TOOL_CALL_ARGS"' not in line) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert ("AGUI003", "missing_tool_binding") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_reducer_state_is_immutable() -> None:
    state = ReducerState()
    with pytest.raises(FrozenInstanceError):
        state.interrupts = ()  # type: ignore[misc]


def test_json_and_sarif_are_byte_stable_and_do_not_echo_event_content() -> None:
    path = _fixture("agui003-tool-id-vulnerable.jsonl")
    first = scan_agui_interrupt_path(path)
    second = scan_agui_interrupt_path(path)
    assert report_json_bytes(first) == report_json_bytes(second)
    assert sarif_json_bytes(first) == sarif_json_bytes(second)
    assert b"synthetic-wrong" not in report_json_bytes(first)


def test_sarif_contains_every_stable_rule_and_only_report_findings() -> None:
    report = scan_agui_interrupt_path(_fixture("agui002-extra-vulnerable.jsonl"))
    sarif = render_sarif(report)
    rules = {item["id"] for item in sarif["runs"][0]["tool"]["driver"]["rules"]}
    results = {item["ruleId"] for item in sarif["runs"][0]["results"]}
    assert rules == {f"AGUI00{index}" for index in range(7)}
    assert results == {"AGUI002"}


@pytest.mark.parametrize(
    ("name", "exit_code", "verdict"),
    [
        ("agui001-binding-near-miss.jsonl", 0, "pass"),
        ("agui001-binding-vulnerable.jsonl", 1, "fail"),
        ("agui001-binding-negative.jsonl", 0, "pass"),
        ("agui000-malformed.jsonl", 1, "unknown"),
        ("agui000-coverage-vulnerable.jsonl", 1, "unknown"),
        ("agui000-unsupported.jsonl", 1, "unknown"),
    ],
)
def test_cli_smokes(name: str, exit_code: int, verdict: str) -> None:
    result = CliRunner().invoke(main, ["ag-ui-interrupt", "scan", str(_fixture(name))])
    assert result.exit_code == exit_code
    assert json.loads(result.output)["verdict"] == verdict


def test_cli_writes_compatible_json_and_sarif(tmp_path: Path) -> None:
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    result = CliRunner().invoke(
        main,
        [
            "ag-ui-interrupt",
            "scan",
            str(_fixture("agui002-extra-vulnerable.jsonl")),
            "--json",
            str(json_path),
            "--sarif",
            str(sarif_path),
        ],
    )
    assert result.exit_code == 1
    assert AGUIInterruptReport.model_validate_json(json_path.read_bytes()).verdict == "fail"
    assert json.loads(sarif_path.read_bytes())["version"] == "2.1.0"


def test_cli_refuses_implicit_output_replacement(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    output.write_text("owned", encoding="utf-8")
    result = CliRunner().invoke(
        main,
        [
            "ag-ui-interrupt",
            "scan",
            str(_fixture("agui001-binding-negative.jsonl")),
            "--json",
            str(output),
        ],
    )
    assert result.exit_code == 2
    assert output.read_text(encoding="utf-8") == "owned"


def test_credential_looking_fixture_is_rejected_without_echo(tmp_path: Path) -> None:
    fixture = tmp_path / "unsafe.jsonl"
    marker = "sk-examplevalue123456789"
    fixture.write_text(
        '{"fixture":{"schema_version":"mcpaudit.ag-ui-interrupt.fixture.v1",'
        '"program_owned":true,"fixture_id":"unsafe-fixture","control_kind":"vulnerable",'
        '"protocol":"ag-ui","protocol_version":"@ag-ui/core@0.0.57",'
        '"contract_revision":"34c3e0ceda257dd1366c6bdfe01c52777611e4bf",'
        '"complete":true,"required_boundary_events":[]}}\n'
        f'{{"unsafe":"{marker}"}}\n',
        encoding="utf-8",
    )
    with pytest.raises(AGUIInterruptInputError, match="credential-like"):
        scan_agui_interrupt_path(fixture)
    result = CliRunner().invoke(main, ["ag-ui-interrupt", "scan", str(fixture)])
    assert result.exit_code == 2
    assert marker not in result.output


@pytest.mark.parametrize("name", [".env", "private.log"])
def test_non_jsonl_private_paths_are_rejected_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    fixture = tmp_path / name
    fixture.write_text("must-not-be-read", encoding="utf-8")
    opened = False

    def blocked_open(*args: object, **kwargs: object) -> int:
        nonlocal opened
        opened = True
        raise AssertionError("non-JSONL input must not be opened")

    monkeypatch.setattr("mcp_audit.agui_interrupt_scanner.os.open", blocked_open)
    with pytest.raises(AGUIInterruptInputError, match="explicit .jsonl synthetic"):
        scan_agui_interrupt_path(fixture)
    assert opened is False


def test_unicode_escaped_credential_is_rejected_without_echo_or_outputs(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "escaped-unsafe.jsonl"
    json_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    decoded_marker = "sk-abcdef123456789"
    source = _fixture("agui001-binding-negative.jsonl").read_text(encoding="utf-8")
    fixture.write_text(
        source.replace("agui001-binding-negative", r"sk-\u0061bcdef123456789"),
        encoding="utf-8",
    )
    with pytest.raises(AGUIInterruptInputError, match="credential-like"):
        scan_agui_interrupt_path(fixture)
    result = CliRunner().invoke(
        main,
        [
            "ag-ui-interrupt",
            "scan",
            str(fixture),
            "--json",
            str(json_path),
            "--sarif",
            str(sarif_path),
        ],
    )
    assert result.exit_code == 2
    assert decoded_marker not in result.output
    assert not json_path.exists()
    assert not sarif_path.exists()


def test_symlink_input_is_rejected(tmp_path: Path) -> None:
    link = tmp_path / "fixture.jsonl"
    link.symlink_to(_fixture("agui001-binding-negative.jsonl").resolve())
    with pytest.raises(AGUIInterruptInputError, match="regular non-symlink"):
        scan_agui_interrupt_path(link)


def test_oversized_fixture_is_rejected(tmp_path: Path) -> None:
    fixture = tmp_path / "oversized.jsonl"
    fixture.write_bytes(b"x" * 4_194_305)
    with pytest.raises(AGUIInterruptInputError, match="exceeds"):
        scan_agui_interrupt_path(fixture)


def test_record_limit_is_rejected(tmp_path: Path) -> None:
    fixture = tmp_path / "too-many.jsonl"
    manifest = (
        '{"fixture":{"schema_version":"mcpaudit.ag-ui-interrupt.fixture.v1",'
        '"program_owned":true,"fixture_id":"too-many-records","control_kind":"vulnerable",'
        '"protocol":"ag-ui","protocol_version":"@ag-ui/core@0.0.57",'
        '"contract_revision":"34c3e0ceda257dd1366c6bdfe01c52777611e4bf",'
        '"complete":true,"required_boundary_events":[]}}'
    )
    records = [
        json.dumps(
            {
                "kind": "run_input",
                "sequence": index,
                "timestamp": "2026-07-28T12:00:00Z",
                "input": {"threadId": "thread-a", "runId": f"run-{index}"},
            },
            separators=(",", ":"),
        )
        for index in range(1, 5_002)
    ]
    fixture.write_text("\n".join([manifest, *records, ""]), encoding="utf-8")
    with pytest.raises(AGUIInterruptInputError, match="record limit"):
        scan_agui_interrupt_path(fixture)


def test_interrupt_aggregate_limit_is_rejected(tmp_path: Path) -> None:
    fixture = tmp_path / "too-many-interrupts.jsonl"
    manifest = {
        "fixture": {
            "schema_version": "mcpaudit.ag-ui-interrupt.fixture.v1",
            "program_owned": True,
            "fixture_id": "too-many-interrupts",
            "control_kind": "vulnerable",
            "protocol": "ag-ui",
            "protocol_version": "@ag-ui/core@0.0.57",
            "contract_revision": "34c3e0ceda257dd1366c6bdfe01c52777611e4bf",
            "complete": True,
            "required_boundary_events": [],
        }
    }
    records: list[dict[str, Any]] = []
    sequence = 1
    for run_index in range(33):
        run_id = f"run-{run_index}"
        stream_id = f"stream-{run_index}"
        records.append(
            {
                "kind": "event",
                "sequence": sequence,
                "timestamp": "2026-07-28T12:00:00Z",
                "streamId": stream_id,
                "event": {
                    "type": "RUN_STARTED",
                    "threadId": "thread-a",
                    "runId": run_id,
                },
            }
        )
        sequence += 1
        records.append(
            {
                "kind": "event",
                "sequence": sequence,
                "timestamp": "2026-07-28T12:00:00Z",
                "streamId": stream_id,
                "event": {
                    "type": "RUN_FINISHED",
                    "threadId": "thread-a",
                    "runId": run_id,
                    "outcome": {
                        "type": "interrupt",
                        "interrupts": [
                            {
                                "id": f"interrupt-{run_index}-{interrupt_index}",
                                "reason": "confirmation",
                            }
                            for interrupt_index in range(128)
                        ],
                    },
                },
            }
        )
        sequence += 1
    fixture.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in (manifest, *records)) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(AGUIInterruptInputError, match="interrupt aggregate limit"):
        scan_agui_interrupt_path(fixture)


def test_unsupported_schema_is_not_treated_as_safe(tmp_path: Path) -> None:
    fixture = tmp_path / "unsupported-schema.jsonl"
    base = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    fixture.write_text(
        base.replace(
            '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
            '"required":["choice"],"additionalProperties":false}',
            '{"type":"object","oneOf":[{"type":"object"}]}',
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "unknown"
    assert ("AGUI000", "unsupported_schema") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


@pytest.mark.parametrize(
    "fixture_name",
    [
        "agui004-snapshot-negative.jsonl",
        "agui002-response-set-negative.jsonl",
    ],
)
def test_unsupported_schema_is_unknown_before_resolution_or_on_cancellation(
    tmp_path: Path,
    fixture_name: str,
) -> None:
    fixture = tmp_path / "unsupported-schema-without-payload.jsonl"
    source = _fixture(fixture_name).read_text(encoding="utf-8")
    fixture.write_text(
        source.replace(
            '{"type":"boolean"}',
            '{"type":"object","oneOf":[{"type":"object"}]}',
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "unknown"
    assert report.complete is False
    assert ("AGUI000", "unsupported_schema") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        (
            {
                "type": "object",
                "properties": {
                    "optional": {
                        "type": "object",
                        "oneOf": [{"type": "object"}],
                    }
                },
                "additionalProperties": False,
            },
            {},
        ),
        (
            {
                "type": "array",
                "items": {
                    "type": "object",
                    "oneOf": [{"type": "object"}],
                },
            },
            [],
        ),
    ],
)
def test_unexercised_nested_unsupported_schema_is_unknown(
    tmp_path: Path,
    schema: dict[str, Any],
    payload: Any,
) -> None:
    fixture = tmp_path / "nested-unsupported-schema.jsonl"
    source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    original_schema = (
        '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
        '"required":["choice"],"additionalProperties":false}'
    )
    fixture.write_text(
        source.replace(
            original_schema,
            json.dumps(schema, separators=(",", ":")),
        ).replace(
            '{"choice":"maybe"}',
            json.dumps(payload, separators=(",", ":")),
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "unknown"
    assert report.complete is False
    assert ("AGUI000", "unsupported_schema") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


@pytest.mark.parametrize(
    ("schema", "payload"),
    [
        ({"type": "integer", "enum": [True]}, 1),
        ({"type": "boolean", "const": 1}, True),
        ({"type": "object", "enum": [{"value": True}]}, {"value": 1}),
    ],
)
def test_schema_equality_preserves_json_boolean_number_identity(
    tmp_path: Path,
    schema: dict[str, Any],
    payload: Any,
) -> None:
    fixture = tmp_path / "typed-schema-mismatch.jsonl"
    source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    original_schema = (
        '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
        '"required":["choice"],"additionalProperties":false}'
    )
    fixture.write_text(
        source.replace(
            original_schema,
            json.dumps(schema, separators=(",", ":")),
        ).replace(
            '{"choice":"maybe"}',
            json.dumps(payload, separators=(",", ":")),
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "fail"
    assert ("AGUI003", "schema_mismatch") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_exponent_overflow_is_unknown_and_never_serialized_as_infinity(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "overflow.jsonl"
    source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    original_schema = (
        '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
        '"required":["choice"],"additionalProperties":false}'
    )
    fixture.write_text(
        source.replace(original_schema, '{"type":"number","const":1e400}').replace(
            '{"choice":"maybe"}',
            "2e400",
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert report.complete is False
    assert "AGUI000" in {finding.rule_id for finding in report.findings}
    assert b"Infinity" not in report_json_bytes(report)


def test_inexact_json_decimal_is_unknown_instead_of_rounded_safe(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "inexact-decimal.jsonl"
    source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    original_schema = (
        '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
        '"required":["choice"],"additionalProperties":false}'
    )
    fixture.write_text(
        source.replace(
            original_schema,
            '{"type":"number","const":9007199254740992.0}',
        ).replace(
            '{"choice":"maybe"}',
            "9007199254740993.0",
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert report.complete is False
    assert "AGUI000" in {finding.rule_id for finding in report.findings}


@pytest.mark.parametrize("location", ["manifest", "record"])
def test_extreme_json_exponent_is_fail_closed_without_traceback(
    tmp_path: Path,
    location: str,
) -> None:
    fixture = tmp_path / f"extreme-exponent-{location}.jsonl"
    if location == "manifest":
        source = _fixture("agui003-contract-negative.jsonl").read_text(encoding="utf-8")
        source = source.replace(
            '"program_owned":true',
            '"program_owned":1e999999999999999999999',
        )
    else:
        source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
        source = source.replace(
            '{"choice":"maybe"}',
            "1e999999999999999999999",
        )
    fixture.write_text(source, encoding="utf-8")
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert report.complete is False
    assert "AGUI000" in {finding.rule_id for finding in report.findings}
    result = CliRunner().invoke(main, ["ag-ui-interrupt", "scan", str(fixture)])
    assert result.exit_code == 1
    assert json.loads(result.output)["verdict"] != "pass"
    assert "Traceback" not in result.output


def test_exact_binary64_decimal_remains_supported(tmp_path: Path) -> None:
    fixture = tmp_path / "exact-decimal.jsonl"
    source = _fixture("agui003-contract-vulnerable.jsonl").read_text(encoding="utf-8")
    original_schema = (
        '{"type":"object","properties":{"choice":{"type":"string","enum":["yes","no"]}},'
        '"required":["choice"],"additionalProperties":false}'
    )
    fixture.write_text(
        source.replace(original_schema, '{"type":"number","const":1.5}').replace(
            '{"choice":"maybe"}',
            "1.5",
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "pass"


def test_nonstandard_json_constant_is_unknown_not_safe(tmp_path: Path) -> None:
    fixture = tmp_path / "nan.jsonl"
    source = _fixture("agui002-response-set-near-miss.jsonl").read_text(encoding="utf-8")
    fixture.write_text(source.replace('"payload":true', '"payload":NaN', 1), encoding="utf-8")
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert "AGUI000" in {finding.rule_id for finding in report.findings}
    assert report.complete is False
    assert b"NaN" not in report_json_bytes(report)


def test_distinct_streams_cannot_claim_one_semantic_run_identity(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "duplicate-semantic-run.jsonl"
    source = _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8")
    source += (
        '{"kind":"event","sequence":11,"timestamp":"2026-07-28T12:00:10Z",'
        '"streamId":"stream-duplicate","event":{"type":"RUN_STARTED",'
        '"threadId":"thread-a","runId":"run-2"}}\n'
        '{"kind":"event","sequence":12,"timestamp":"2026-07-28T12:00:11Z",'
        '"streamId":"stream-duplicate","event":{"type":"RUN_FINISHED",'
        '"threadId":"thread-a","runId":"run-2","outcome":{"type":"success"}}}\n'
    )
    fixture.write_text(source, encoding="utf-8")
    first = scan_agui_interrupt_path(fixture)
    second = scan_agui_interrupt_path(fixture)
    assert first.verdict == "unknown"
    assert first.complete is False
    assert ("AGUI000", "malformed_transcript") in {
        (finding.rule_id, finding.kind.value) for finding in first.findings
    }
    assert report_json_bytes(first) == report_json_bytes(second)


def test_supplied_payload_cannot_collide_with_omitted_payload_fingerprint(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "payload-presence-collision.jsonl"
    rows = [
        json.loads(line)
        for line in _fixture("agui003-contract-negative.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    first_resume = rows[4]
    first_resume["input"]["resume"][0].pop("payload")
    conflicting_resume = json.loads(json.dumps(first_resume))
    conflicting_resume["sequence"] = 5
    conflicting_resume["timestamp"] = "2026-07-28T12:00:04Z"
    conflicting_resume["input"]["resume"][0]["payload"] = {"__omitted__": True}
    rows[5]["sequence"] = 6
    rows[5]["timestamp"] = "2026-07-28T12:00:05Z"
    rows[6]["sequence"] = 7
    rows[6]["timestamp"] = "2026-07-28T12:00:06Z"
    rows.insert(5, conflicting_resume)
    fixture.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert ("AGUI000", "malformed_transcript") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_late_conflicting_resume_for_terminal_run_is_unknown(tmp_path: Path) -> None:
    fixture = tmp_path / "late-conflicting-resume.jsonl"
    source = _fixture("agui002-response-set-negative.jsonl").read_text(encoding="utf-8")
    source += (
        '{"kind":"run_input","sequence":7,"timestamp":"2026-07-28T12:00:06Z",'
        '"input":{"threadId":"thread-a","runId":"run-2","resume":[{"interruptId":'
        '"interrupt-1","status":"resolved","payload":true}]}}\n'
    )
    fixture.write_text(source, encoding="utf-8")
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "unknown"
    assert report.complete is False
    assert ("AGUI000", "malformed_transcript") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_tool_call_end_before_args_is_unknown(tmp_path: Path) -> None:
    fixture = tmp_path / "tool-order.jsonl"
    rows = [
        json.loads(line)
        for line in _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    rows[4]["event"] = {"type": "TOOL_CALL_END", "toolCallId": "tool-1"}
    rows[5]["event"] = {
        "type": "TOOL_CALL_ARGS",
        "toolCallId": "tool-1",
        "delta": "{}",
    }
    fixture.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict != "pass"
    assert ("AGUI000", "invalid_tool_event_order") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_duplicate_tool_result_is_unknown(tmp_path: Path) -> None:
    fixture = tmp_path / "duplicate-result.jsonl"
    rows = [
        json.loads(line)
        for line in _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    duplicate = json.loads(json.dumps(rows[-2]))
    duplicate["sequence"] = 10
    duplicate["timestamp"] = "2026-07-28T12:00:09Z"
    rows[-1]["sequence"] = 11
    rows[-1]["timestamp"] = "2026-07-28T12:00:10Z"
    rows.insert(-1, duplicate)
    fixture.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "unknown"
    assert ("AGUI000", "duplicate_tool_event") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_successful_resume_requires_exactly_one_tool_result(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-result.jsonl"
    lines = _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
    fixture.write_text(
        "\n".join(line for line in lines if '"type":"TOOL_CALL_RESULT"' not in line) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "fail"
    assert ("AGUI003", "missing_tool_result") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_resumed_run_interrupt_still_requires_tool_result(tmp_path: Path) -> None:
    fixture = tmp_path / "missing-result-before-next-interrupt.jsonl"
    rows = [
        json.loads(line)
        for line in _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
        if '"type":"TOOL_CALL_RESULT"' not in line
    ]
    rows[-1]["event"]["outcome"] = {
        "type": "interrupt",
        "interrupts": [{"id": "interrupt-2", "reason": "confirmation"}],
    }
    fixture.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "fail"
    assert ("AGUI003", "missing_tool_result") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_tool_result_before_tool_interrupt_is_not_safe(tmp_path: Path) -> None:
    fixture = tmp_path / "result-before-interrupt.jsonl"
    rows = [
        json.loads(line)
        for line in _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    premature_result = {
        "kind": "event",
        "sequence": 6,
        "timestamp": "2026-07-28T12:00:05Z",
        "streamId": "stream-1",
        "event": {
            "type": "TOOL_CALL_RESULT",
            "messageId": "message-premature",
            "toolCallId": "tool-1",
            "content": "synthetic-premature",
            "role": "tool",
        },
    }
    for row in rows[6:]:
        row["sequence"] += 1
        row["timestamp"] = f"2026-07-28T12:00:{row['sequence'] - 1:02d}Z"
    rows.insert(6, premature_result)
    fixture.write_text(
        "\n".join(json.dumps(row, separators=(",", ":")) for row in rows) + "\n",
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "fail"
    assert ("AGUI003", "tool_result_before_interrupt") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_run_error_after_resumed_tool_result_does_not_reopen_interrupt(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "result-then-error.jsonl"
    source = _fixture("agui003-contract-near-miss.jsonl").read_text(encoding="utf-8")
    fixture.write_text(
        source.replace(
            '{"type":"RUN_FINISHED","threadId":"thread-a","runId":"run-2","outcome":{"type":"success"}}}',
            '{"type":"RUN_ERROR","message":"downstream failure","code":"FAILED_AFTER_RESULT"}}',
        ),
        encoding="utf-8",
    )
    report = scan_agui_interrupt_path(fixture)
    assert report.verdict == "fail"
    assert report.state.resolved_count == 1
    assert report.state.open_count == 0
    assert ("AGUI006", "terminal_reopened") in {
        (finding.rule_id, finding.kind.value) for finding in report.findings
    }


def test_schema_models_reject_unknown_fields() -> None:
    payload: dict[str, Any] = {
        "schema_version": "mcpaudit.ag-ui-interrupt.fixture.v1",
        "program_owned": True,
        "fixture_id": "strict-fixture",
        "control_kind": "negative",
        "protocol": "ag-ui",
        "protocol_version": "@ag-ui/core@0.0.57",
        "contract_revision": "34c3e0ceda257dd1366c6bdfe01c52777611e4bf",
        "complete": True,
        "required_boundary_events": [],
        "unexpected": True,
    }
    with pytest.raises(ValidationError):
        FixtureManifest.model_validate(payload, strict=True)


@pytest.mark.parametrize(
    "contract",
    ["fixture-manifest", "run-input", "event-record", "report"],
)
def test_cli_emits_authoritative_schemas(contract: str) -> None:
    result = CliRunner().invoke(main, ["ag-ui-interrupt", "schema", contract])
    assert result.exit_code == 0
    assert json.loads(result.output)["type"] == "object"


def test_scan_has_no_network_or_process_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("external execution is outside the scanner boundary")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)
    report = scan_agui_interrupt_path(_fixture("agui001-binding-negative.jsonl"))
    assert report.verdict == "pass"
