"""Contract, failure-path, and offline-boundary tests for Result Parcel Lab."""

from __future__ import annotations

import ast
import builtins
import json
import os
import socket
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.result_parcel_models import (
    MAX_DECLARED_PAYLOAD_BYTES,
    MAX_INPUT_BYTES,
    ParcelAnalysisReport,
    ParcelScenario,
)
from mcp_audit.result_parcel_scanner import (
    ParcelInputError,
    analyze_scenario,
    builtin_scenarios,
    generate_synthetic_scenario,
    scan_scenario_bytes,
    scan_scenario_path,
)

FIXTURES = Path(__file__).parent / "fixtures" / "result_parcel"


@pytest.mark.parametrize(
    ("name", "verdict", "evidence"),
    [
        ("small-inline.json", "pass", set()),
        ("large-inline.json", "pass", {"inline_payload_above_advisory_bound"}),
        ("ordered-stream.json", "pass", set()),
        (
            "interrupted-stream.json",
            "fail",
            {"stream_incomplete", "chunk_size_mismatch", "stream_idempotency_unbound"},
        ),
        ("expiring-reference.json", "fail", {"reference_expired"}),
        ("missing-blob.json", "fail", {"reference_missing"}),
        ("stale-reference.json", "fail", {"reference_stale"}),
        ("authorization-denial.json", "fail", {"retrieval_authorization_denied"}),
        ("redaction-before.json", "pass", set()),
        ("redaction-after.json", "fail", {"redaction_after_packaging"}),
        ("content-type-mismatch.json", "fail", {"content_type_mismatch"}),
        ("integrity-mismatch.json", "fail", {"integrity_digest_mismatch"}),
        ("partial-retrieval.json", "fail", {"reference_partial_retrieval"}),
        (
            "duplicate-chunks.json",
            "fail",
            {"duplicate_chunk_index", "stream_incomplete", "stream_idempotency_unbound"},
        ),
        ("unsupported-host.json", "fail", {"host_capability_unsupported"}),
        ("progress-status.json", "pass", set()),
        (
            "progress-payload-conflation.json",
            "fail",
            {"progress_payload_conflation", "progress_final_result_missing"},
        ),
        ("tasks-completed.json", "pass", {"retained_cleanup_unproven"}),
    ],
)
def test_deterministic_fixture_outcomes(
    name: str,
    verdict: str,
    evidence: set[str],
) -> None:
    report = scan_scenario_bytes((FIXTURES / name).read_bytes())

    assert report.verdict == verdict
    assert {finding.evidence_code for finding in report.findings} == evidence
    assert report.coverage.input_state == "valid"
    assert report.recommendation is not None


@pytest.mark.parametrize(
    "name",
    ["malformed.json", "duplicate-key.json", "unknown-field.json"],
)
def test_malformed_and_adversarial_contract_inputs_are_unknown(name: str) -> None:
    report = scan_scenario_bytes((FIXTURES / name).read_bytes())

    assert report.verdict == "unknown"
    assert report.recommendation is None
    assert [finding.evidence_code for finding in report.findings] == ["scenario_validation_failed"]


def test_input_and_declared_size_boundaries() -> None:
    oversized_input = b"{" + b" " * MAX_INPUT_BYTES + b"}"
    input_report = scan_scenario_bytes(oversized_input)
    assert input_report.verdict == "unknown"
    assert input_report.findings[0].evidence_code == "input_size_limit_exceeded"

    scenario = builtin_scenarios()["small-inline"].model_dump(mode="json")
    scenario["payload"]["size_bytes"] = MAX_DECLARED_PAYLOAD_BYTES + 1
    declared_report = scan_scenario_bytes(json.dumps(scenario).encode())
    assert declared_report.verdict == "unknown"
    assert declared_report.findings[0].evidence_code == "scenario_validation_failed"


def test_large_generator_does_not_allocate_payload_bytes() -> None:
    scenario = generate_synthetic_scenario(
        scenario_id="one-terabyte-metadata",
        size_bytes=MAX_DECLARED_PAYLOAD_BYTES,
        mode="resource_link",
        sensitivity="confidential",
    )

    assert scenario.payload.size_bytes == MAX_DECLARED_PAYLOAD_BYTES
    assert len(scenario.model_dump_json()) < 5_000
    assert analyze_scenario(scenario).verdict == "pass"


def test_adversarial_content_is_not_reflected_into_report() -> None:
    raw = (FIXTURES / "adversarial-reference.json").read_bytes()
    report = scan_scenario_bytes(raw)
    serialized = report.model_dump_json()

    assert report.verdict == "pass"
    assert "Ignore prior instructions" not in serialized
    assert "token=do-not-reflect" not in serialized


def test_analysis_performs_no_network_environment_home_or_general_file_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = (FIXTURES / "small-inline.json").read_bytes()

    def denied(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("forbidden external or credential-adjacent read")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(os, "getenv", denied)
    monkeypatch.setattr(Path, "home", denied)
    monkeypatch.setattr(builtins, "open", denied)

    report = scan_scenario_bytes(raw)
    assert report.verdict == "pass"


def test_lab_modules_import_no_network_or_credential_clients() -> None:
    forbidden_roots = {
        "http",
        "httpx",
        "keyring",
        "mcp",
        "requests",
        "socket",
        "urllib",
    }
    for name in (
        "result_parcel_models.py",
        "result_parcel_scanner.py",
        "result_parcel_cli.py",
    ):
        source = (Path(__file__).parents[1] / "src" / "mcp_audit" / name).read_text()
        tree = ast.parse(source)
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden_roots)


def test_path_loader_refuses_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "scenario.json"
    target.write_bytes((FIXTURES / "small-inline.json").read_bytes())
    link = tmp_path / "scenario-link.json"
    link.symlink_to(target)

    with pytest.raises(ParcelInputError, match="refusing symlink"):
        scan_scenario_path(link)


def test_path_loader_refuses_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "scenario.fifo"
    os.mkfifo(fifo)

    with pytest.raises(ParcelInputError, match="not a regular file"):
        scan_scenario_path(fifo)


def test_material_unknowns_prevent_a_definitive_recommendation() -> None:
    scenario = builtin_scenarios()["small-inline"].model_dump(mode="json")
    scenario["payload"]["sensitivity"] = "unknown"
    scenario["delivery"]["host_support"] = "unknown"

    report = scan_scenario_bytes(json.dumps(scenario).encode())

    assert report.verdict == "unknown"
    assert report.recommendation is not None
    assert report.recommendation.suitability == "unknown"
    assert set(report.unknowns) == {
        "payload sensitivity is unknown",
        "selected delivery mode support is unverified for the host",
    }


def test_schema_contracts_are_versioned_closed_and_machine_readable() -> None:
    scenario_schema = ParcelScenario.model_json_schema()
    report_schema = ParcelAnalysisReport.model_json_schema()

    assert scenario_schema["properties"]["schema_version"]["const"] == ("mcpaudit.result-parcel.scenario.v1")
    assert scenario_schema["additionalProperties"] is False
    assert report_schema["properties"]["schema_version"]["const"] == ("mcpaudit.result-parcel.report.v1")
    assert report_schema["additionalProperties"] is False

    runner = CliRunner()
    for contract in ("scenario", "report"):
        result = runner.invoke(main, ["result-parcel", "schema", contract])
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["additionalProperties"] is False


def test_cli_supports_builtins_supplied_json_human_and_json() -> None:
    runner = CliRunner()

    builtins_result = runner.invoke(main, ["result-parcel", "builtins"])
    assert builtins_result.exit_code == 0
    assert builtins_result.output.splitlines() == [
        "large-inline",
        "large-resource-link",
        "small-inline",
    ]

    human = runner.invoke(
        main,
        ["result-parcel", "analyze", "--builtin", "small-inline", "--format", "human"],
    )
    assert human.exit_code == 0, human.output
    assert "Recommendation: suitable — inline" in human.output
    assert "information_exposure: low" in human.output

    machine = runner.invoke(
        main,
        [
            "result-parcel",
            "analyze",
            str(FIXTURES / "integrity-mismatch.json"),
            "--format",
            "json",
        ],
    )
    assert machine.exit_code == 1, machine.output
    assert json.loads(machine.output)["findings"][0]["evidence_code"] == ("integrity_digest_mismatch")


def test_cli_generates_large_synthetic_metadata_and_rejects_ambiguous_input() -> None:
    runner = CliRunner()
    generated = runner.invoke(
        main,
        [
            "result-parcel",
            "generate-large",
            "--scenario-id",
            "generated-large",
            "--size-bytes",
            "8388608",
            "--mode",
            "resource_link",
        ],
    )
    assert generated.exit_code == 0, generated.output
    assert json.loads(generated.output)["payload"]["size_bytes"] == 8_388_608

    ambiguous = runner.invoke(
        main,
        [
            "result-parcel",
            "analyze",
            str(FIXTURES / "small-inline.json"),
            "--builtin",
            "small-inline",
        ],
    )
    assert ambiguous.exit_code == 2


def test_scenarios_bind_semantics_and_evidence_class() -> None:
    inline = json.loads((FIXTURES / "small-inline.json").read_text())
    inline["delivery"]["semantics"] = "provider_extension"
    assert scan_scenario_bytes(json.dumps(inline).encode()).verdict == "unknown"

    tasks = json.loads((FIXTURES / "tasks-completed.json").read_text())
    tasks["delivery"]["extension_id"] = "vendor/tasks"
    assert scan_scenario_bytes(json.dumps(tasks).encode()).verdict == "unknown"

    stream = json.loads((FIXTURES / "ordered-stream.json").read_text())
    stream["evidence_provenance"][0]["evidence_class"] = "local_fixture"
    assert scan_scenario_bytes(json.dumps(stream).encode()).verdict == "unknown"


def test_report_is_deterministic_and_explainable_from_named_inputs() -> None:
    raw = (FIXTURES / "redaction-after.json").read_bytes()
    first = scan_scenario_bytes(raw)
    second = scan_scenario_bytes(raw)

    assert first.model_dump_json() == second.model_dump_json()
    finding = next(item for item in first.findings if item.rule_id == "MCPPARCEL013")
    assert finding.input_fields == ["redaction.required", "redaction.stage"]
    assert first.dimensions is not None
    assert first.dimensions.information_exposure.state == "high"
