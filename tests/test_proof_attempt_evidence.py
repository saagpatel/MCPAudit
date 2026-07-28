"""Failing controls for Proof Before Action attempt-level evidence gaps."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import ValidationError

from mcp_audit.proof_capsule import build_capsule, compare_bill, export_capsule, verify_capsule
from mcp_audit.proof_cli import main
from mcp_audit.proof_models import (
    CAPSULE_INDEX_SCHEMA,
    CAPSULE_INDEX_SCHEMA_V1,
    CAPSULE_SCHEMA,
    CAPSULE_SCHEMA_V1,
    OBSERVATION_SCHEMA,
    OBSERVATION_SCHEMA_V1,
    ActionDeclaration,
    AttemptEvidence,
    AttemptEvidenceProvenance,
    EvidenceCapsule,
    NetworkEvidence,
    Observation,
    SurfaceObservation,
    canonical_json_bytes,
    sha256_bytes,
)
from mcp_audit.proof_observer import (
    _attempt_evidence_receipts,
    _network_evidence,
    observe_command,
)
from mcp_audit.proof_trust import build_release_trust_manifest

DOCKER_READY = (
    shutil.which("docker") is not None
    and subprocess.run(
        ["docker", "image", "inspect", "node:24-slim"],
        check=False,
        capture_output=True,
    ).returncode
    == 0
)
requires_docker = pytest.mark.skipif(
    not DOCKER_READY,
    reason="local node:24-slim image and Docker are required",
)

EXPECTED_ATTEMPT_RECEIPTS = {
    "PBA-FS-TRANSIENT-001": {
        "surface": "filesystem.transient_attempt",
        "operations": ["create_delete", "write_restore"],
        "provenance_kinds": {"workspace_final_state"},
    },
    "PBA-DB-NO-DELTA-001": {
        "surface": "database.no_delta_attempt",
        "operations": ["query_no_delta", "transaction_rollback"],
        "provenance_kinds": {"sqlite_final_state"},
    },
    "PBA-NET-DESTINATION-001": {
        "surface": "network.requested_destination",
        "operations": ["connect_ip", "resolve_hostname"],
        "provenance_kinds": {"network_namespace_counters"},
    },
    "PBA-UNIX-SOCKET-001": {
        "surface": "network.unix_socket",
        "operations": ["abstract_socket", "filesystem_socket"],
        "provenance_kinds": {"observer_contract"},
    },
}


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "input.txt").write_text("stable\n", encoding="utf-8")
    return root


def _node_image_id() -> str:
    return subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "node:24-slim"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _receipt(observation: Observation, rule_id: str) -> dict[str, Any]:
    payload = observation.model_dump(mode="json")
    receipts = payload.get("attempt_evidence")
    assert isinstance(receipts, list), "explicit attempt_evidence receipts are missing"
    matches = [item for item in receipts if item.get("rule_id") == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id} receipt"
    receipt = cast(dict[str, Any], matches[0])
    expected = EXPECTED_ATTEMPT_RECEIPTS[rule_id]
    assert receipt["surface"] == expected["surface"]
    assert receipt["operations"] == expected["operations"]
    assert receipt["state"] == "unknown"
    assert receipt["attribution_confidence"] == "none"
    assert receipt["platform"] == "linux"
    assert receipt["backend"] == "docker"
    assert receipt["support"] == "unsupported"
    assert receipt["unknown_reasons"]
    assert {item["kind"] for item in receipt["provenance"]} == expected["provenance_kinds"]
    return receipt


def _declaration() -> ActionDeclaration:
    return ActionDeclaration.model_validate(
        {
            "name": "attempt evidence fixture",
            "tools": ["node"],
            "permissions": [],
            "destinations": {"files": [], "databases": [], "network": []},
            "side_effects": {
                "filesystem": "none",
                "database": "none",
                "network": "none",
            },
            "limitations": [],
        }
    )


def _available_network_evidence() -> NetworkEvidence:
    return NetworkEvidence(
        surface=SurfaceObservation(
            attempted=False,
            decision="not_applicable",
            outcome="not_applicable",
            persisted="unchanged",
            mechanism="synthetic complete counter delta fixture",
            complete=False,
            limitations=["Counters do not identify requested destinations."],
        ),
        counters={"Ip.OutRequests": 0},
    )


def test_attempt_evidence_schema_is_additive_strict_and_deterministic() -> None:
    first = _attempt_evidence_receipts(_available_network_evidence())
    second = _attempt_evidence_receipts(_available_network_evidence())

    assert canonical_json_bytes([item.model_dump(mode="json") for item in first]) == (
        canonical_json_bytes([item.model_dump(mode="json") for item in second])
    )
    assert [item.rule_id for item in first] == list(EXPECTED_ATTEMPT_RECEIPTS)

    result = CliRunner().invoke(main, ["schema", "observation"])
    assert result.exit_code == 0
    schema = result.output
    assert '"attempt_evidence"' in schema
    assert "PBA-FS-TRANSIENT-001" in schema
    assert "PBA-UNIX-SOCKET-001" in schema


def test_emitted_schema_enforces_attempt_receipt_invariants() -> None:
    result = CliRunner().invoke(main, ["schema", "observation"])
    assert result.exit_code == 0
    observation_schema = cast(dict[str, Any], json.loads(result.output))
    attempt_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": observation_schema["$defs"],
        **observation_schema["properties"]["attempt_evidence"],
    }
    validator = Draft202012Validator(attempt_schema)
    receipts = [
        item.model_dump(mode="json") for item in _attempt_evidence_receipts(_available_network_evidence())
    ]
    validator.validate(receipts)

    wrong_surface = [{**receipts[0], "surface": "network.requested_destination"}]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(wrong_surface)

    claim_inflated = [
        {
            **receipts[0],
            "state": "observed",
            "attribution_confidence": "high",
            "unknown_reasons": [],
        }
    ]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(claim_inflated)

    attributed_unknown = [{**receipts[0], "attribution_confidence": "low"}]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(attributed_unknown)

    observed_with_unknown_reason = [
        {
            **receipts[0],
            "state": "observed",
            "support": "supported",
            "attribution_confidence": "high",
        }
    ]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(observed_with_unknown_reason)

    unowned_observation = [
        {
            **observed_with_unknown_reason[0],
            "unknown_reasons": [],
            "provenance": [
                {
                    **receipts[0]["provenance"][0],
                    "observer_owned": False,
                }
            ],
        }
    ]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(unowned_observation)

    missing_reason = [{**receipts[0], "unknown_reasons": []}]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(missing_reason)

    duplicate_rule = [receipts[0], {**receipts[0], "platform": "darwin"}]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(duplicate_rule)


def test_attempt_evidence_rejects_claim_inflation_and_wrong_rule_binding() -> None:
    payload = _attempt_evidence_receipts(_available_network_evidence())[0].model_dump(mode="json")
    with pytest.raises(ValidationError, match="unsupported attempt evidence must remain unknown"):
        AttemptEvidence.model_validate(
            {
                **payload,
                "state": "observed",
                "attribution_confidence": "high",
                "unknown_reasons": [],
            }
        )
    with pytest.raises(ValidationError, match="stable surface and operations"):
        AttemptEvidence.model_validate(
            {
                **payload,
                "surface": "network.requested_destination",
            }
        )
    with pytest.raises(ValidationError, match="requires an unknown reason"):
        AttemptEvidence.model_validate(
            {
                **payload,
                "unknown_reasons": [],
            }
        )
    with pytest.raises(ValidationError, match="must not retain unknown reasons"):
        AttemptEvidence.model_validate(
            {
                **payload,
                "state": "observed",
                "support": "supported",
                "attribution_confidence": "high",
            }
        )


def test_network_receipt_reflects_counter_availability(tmp_path: Path) -> None:
    available = _attempt_evidence_receipts(_available_network_evidence())[2]
    assert {item.kind for item in available.provenance} == {"network_namespace_counters"}
    assert "before/after counter deltas" in available.provenance[0].source

    missing_paths = [tmp_path / name for name in ("before", "after", "before6", "after6")]
    timed_out = _network_evidence(*missing_paths, timed_out=True)
    missing = _network_evidence(*missing_paths, timed_out=False)

    before, after, before6, after6 = [
        tmp_path / name for name in ("regress.before", "regress.after", "regress6.before", "regress6.after")
    ]
    before.write_text(
        "Ip: OutRequests\nIp: 1\n"
        "Tcp: ActiveOpens PassiveOpens AttemptFails\nTcp: 1 1 1\n"
        "Udp: OutDatagrams\nUdp: 1\n",
        encoding="utf-8",
    )
    after.write_text(
        "Ip: OutRequests\nIp: 0\n"
        "Tcp: ActiveOpens PassiveOpens AttemptFails\nTcp: 0 0 0\n"
        "Udp: OutDatagrams\nUdp: 0\n",
        encoding="utf-8",
    )
    before6.write_text("Ip6OutRequests 1\nUdp6OutDatagrams 1\n", encoding="utf-8")
    after6.write_text("Ip6OutRequests 0\nUdp6OutDatagrams 0\n", encoding="utf-8")
    regressed = _network_evidence(before, after, before6, after6, timed_out=False)

    for network, expected_reason in (
        (timed_out, "command timed out"),
        (missing, "counter snapshots were unavailable"),
        (regressed, "counter regressed or wrapped"),
    ):
        unavailable = _attempt_evidence_receipts(network)[2]
        assert network.counters == {}
        assert {item.kind for item in unavailable.provenance} == {"observer_contract"}
        assert "no usable before/after network counter deltas" in unavailable.provenance[0].source
        assert any(expected_reason in reason for reason in unavailable.unknown_reasons)


def test_unsupported_platform_receipt_stays_machine_readable_unknown() -> None:
    receipt = AttemptEvidence(
        rule_id="PBA-UNIX-SOCKET-001",
        surface="network.unix_socket",
        operations=["abstract_socket", "filesystem_socket"],
        state="unknown",
        attribution_confidence="none",
        platform="darwin",
        backend="native",
        support="unsupported",
        provenance=[
            AttemptEvidenceProvenance(
                kind="observer_contract",
                source="no supported native observer backend",
                observer_owned=True,
            )
        ],
        unknown_reasons=["native platform observation is unsupported"],
    )

    assert receipt.state == "unknown"
    assert receipt.support == "unsupported"
    assert receipt.platform == "darwin"


@requires_docker
def test_versioned_attempt_semantics_preserve_historical_v1_capsule_verification(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        ["node", "-e", "process.exit(0)"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    assert observation.schema_version == OBSERVATION_SCHEMA
    declaration = _declaration()
    trust = build_release_trust_manifest(
        repo,
        None,
        subject_snapshot=observation.subject_snapshot,
    )
    current = build_capsule(
        declaration,
        observation,
        compare_bill(declaration, observation),
        trust,
    )
    assert current.schema_version == CAPSULE_SCHEMA
    current_output = tmp_path / "current-capsule"
    export_capsule(current, current_output)
    assert (
        json.loads((current_output / "capsule-index.json").read_bytes())["schema_version"]
        == CAPSULE_INDEX_SCHEMA
    )
    legacy_observation_payload = observation.model_dump(mode="json")
    legacy_observation_payload["schema_version"] = OBSERVATION_SCHEMA_V1
    legacy_observation_payload.pop("attempt_evidence")
    legacy_observation = Observation.model_validate(legacy_observation_payload)
    with pytest.raises(
        ValidationError,
        match="observation v1 cannot contain v2 attempt-evidence semantics",
    ):
        Observation.model_validate(
            {
                **legacy_observation_payload,
                "attempt_evidence": [],
            }
        )
    legacy_payload = current.model_dump(mode="json")
    mixed_payload = current.model_dump(mode="json")
    mixed_payload["schema_version"] = CAPSULE_SCHEMA_V1
    with pytest.raises(
        ValidationError,
        match="capsule and observation schema versions must match",
    ):
        EvidenceCapsule.model_validate(mixed_payload)
    legacy_payload["schema_version"] = CAPSULE_SCHEMA_V1
    legacy_payload["payload"]["observation"] = legacy_observation_payload
    legacy_payload["payload"]["comparison"] = compare_bill(
        declaration,
        legacy_observation,
    ).model_dump(mode="json")
    legacy_payload["integrity"]["payload_sha256"] = sha256_bytes(
        canonical_json_bytes(legacy_payload["payload"])
    )
    legacy_capsule = EvidenceCapsule.model_validate(legacy_payload)
    output = tmp_path / "legacy-capsule"

    export_capsule(legacy_capsule, output)

    assert verify_capsule(output)["valid"] is True
    assert b"Attempt-level evidence" not in (output / "report.html").read_bytes()
    current_index = json.loads((current_output / "capsule-index.json").read_bytes())
    legacy_index = json.loads((output / "capsule-index.json").read_bytes())
    assert legacy_index["capsule_schema_version"] == CAPSULE_SCHEMA_V1

    emitted_schemas: dict[str, dict[str, Any]] = {}
    for contract in ("observation", "capsule", "capsule-index"):
        result = CliRunner().invoke(main, ["schema", contract])
        assert result.exit_code == 0
        emitted_schemas[contract] = cast(dict[str, Any], json.loads(result.output))
    observation_schema = emitted_schemas["observation"]
    capsule_schema = emitted_schemas["capsule"]
    index_schema = emitted_schemas["capsule-index"]
    Draft202012Validator(observation_schema).validate(observation.model_dump(mode="json"))
    Draft202012Validator(observation_schema).validate(legacy_observation_payload)
    Draft202012Validator(capsule_schema).validate(current.model_dump(mode="json"))
    Draft202012Validator(capsule_schema).validate(legacy_payload)
    Draft202012Validator(index_schema).validate(current_index)
    Draft202012Validator(index_schema).validate(legacy_index)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(observation_schema).validate(
            {
                **legacy_observation_payload,
                "attempt_evidence": [],
            }
        )
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(capsule_schema).validate(mixed_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(index_schema).validate(
            {
                **current_index,
                "schema_version": CAPSULE_INDEX_SCHEMA_V1,
            }
        )


@requires_docker
@pytest.mark.parametrize(
    "code",
    [
        ("const fs=require('fs');fs.writeFileSync('transient.txt','created');fs.unlinkSync('transient.txt')"),
        (
            "const fs=require('fs');"
            "const before=fs.readFileSync('input.txt');"
            "fs.writeFileSync('input.txt','modified\\n');"
            "fs.writeFileSync('input.txt',before)"
        ),
    ],
    ids=["create-delete", "write-restore"],
)
def test_transient_filesystem_attempt_has_explicit_unknown_receipt(
    tmp_path: Path,
    code: str,
) -> None:
    repo = _repo(tmp_path)

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.file_changes == []
    assert observation.filesystem.complete is False
    _receipt(observation, "PBA-FS-TRANSIENT-001")
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "unknown"
    assert "attempt_evidence_unresolved" in {item.code for item in comparison.findings}

    missing = observation.model_copy(update={"attempt_evidence": []})
    missing_comparison = compare_bill(_declaration(), missing)
    assert missing_comparison.verdict == "unknown"
    assert "attempt_evidence_missing" in {item.code for item in missing_comparison.findings}

    forged_receipt = observation.attempt_evidence[0].model_copy(
        update={
            "state": "observed",
            "support": "supported",
            "attribution_confidence": "high",
            "unknown_reasons": [],
        }
    )
    forged = observation.model_copy(
        update={
            "attempt_evidence": [
                forged_receipt,
                *observation.attempt_evidence[1:],
            ]
        }
    )
    forged_comparison = compare_bill(_declaration(), forged)
    assert forged_comparison.verdict == "unknown"
    assert "attempt_evidence_claim_unsupported" in {item.code for item in forged_comparison.findings}


@requires_docker
def test_no_delta_sqlite_attempt_has_explicit_unknown_receipt(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    database = sqlite3.connect(repo / "synthetic.db")
    database.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    database.execute("INSERT INTO items(value) VALUES ('before')")
    database.commit()
    database.close()
    code = (
        "const {DatabaseSync}=require('node:sqlite');"
        "const db=new DatabaseSync('synthetic.db');"
        "db.prepare('SELECT value FROM items WHERE id=?').get(1);"
        "db.exec(\"BEGIN;UPDATE items SET value='transient' WHERE id=1;ROLLBACK;\");"
        "db.close()"
    )

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.database_changes == []
    assert observation.database.complete is False
    _receipt(observation, "PBA-DB-NO-DELTA-001")


@requires_docker
@pytest.mark.parametrize(
    "code",
    [
        (
            "const net=require('net');"
            "const socket=net.connect({host:'198.51.100.7',port:443});"
            "socket.on('error',()=>process.exit(0));"
            "setTimeout(()=>process.exit(4),1000)"
        ),
        (
            "const net=require('net');"
            "const socket=net.connect({host:'pba-denied.invalid',port:443});"
            "socket.on('error',()=>process.exit(0));"
            "setTimeout(()=>process.exit(4),1000)"
        ),
    ],
    ids=["ip-destination", "hostname-destination"],
)
def test_denied_network_destination_has_explicit_unknown_receipt(
    tmp_path: Path,
    code: str,
) -> None:
    repo = _repo(tmp_path)

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.isolation.container_network_mode == "none"
    assert observation.network.external_contact_count == 0
    assert observation.network.surface.complete is False
    _receipt(observation, "PBA-NET-DESTINATION-001")


@requires_docker
@pytest.mark.parametrize(
    "code",
    [
        (
            "const fs=require('fs'),net=require('net');"
            "const path='transient.sock';"
            "const server=net.createServer(socket=>socket.end());"
            "server.listen(path,()=>{"
            "const client=net.connect(path);"
            "client.on('close',()=>server.close(()=>{"
            "try{fs.unlinkSync(path)}catch(error){if(error.code!=='ENOENT')throw error}"
            "process.exit(0)}))});"
            "setTimeout(()=>process.exit(4),1500)"
        ),
        (
            r"const net=require('net');"
            r"const path='\0pba-abstract-control';"
            r"const server=net.createServer(socket=>socket.end());"
            r"server.listen(path,()=>{"
            r"const client=net.connect(path);"
            r"client.on('close',()=>server.close(()=>process.exit(0)))});"
            r"setTimeout(()=>process.exit(4),1500)"
        ),
    ],
    ids=["filesystem-socket", "abstract-socket"],
)
def test_unix_socket_activity_has_explicit_unknown_receipt(
    tmp_path: Path,
    code: str,
) -> None:
    repo = _repo(tmp_path)

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.file_changes == []
    assert observation.network.surface.complete is False
    assert "Unix-domain socket activity" in " ".join(observation.network.surface.limitations)
    _receipt(observation, "PBA-UNIX-SOCKET-001")


@requires_docker
def test_benign_twin_and_failure_controls_keep_attempt_gaps_unknown(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    benign = observe_command(
        repo,
        ["node", "-e", "require('fs').readFileSync('input.txt')"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    failure = observe_command(
        repo,
        ["node", "-e", "setTimeout(()=>{},10000)"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
        timeout_seconds=1,
    )

    assert all(item.state == "unknown" for item in benign.attempt_evidence)
    assert compare_bill(_declaration(), benign).verdict == "unknown"
    assert all(item.state == "unknown" for item in failure.attempt_evidence)
    assert failure.command.timed_out is True
    failure_network_receipt = next(
        item for item in failure.attempt_evidence if item.rule_id == "PBA-NET-DESTINATION-001"
    )
    assert {item.kind for item in failure_network_receipt.provenance} == {"observer_contract"}
    assert any("timed out" in reason for reason in failure_network_receipt.unknown_reasons)
    assert compare_bill(_declaration(), failure).verdict == "block"
