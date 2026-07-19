"""End-to-end acceptance coverage for Proof Before Action."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_audit.proof_capsule import (
    build_capsule,
    compare_bill,
    export_capsule,
    verify_capsule,
)
from mcp_audit.proof_cli import main
from mcp_audit.proof_models import (
    CAPSULE_SCHEMA,
    ActionDeclaration,
    ReleaseTrustManifest,
    canonical_json_bytes,
)
from mcp_audit.proof_observer import ObservationBlocked, _redact_argv, observe_command
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
    not DOCKER_READY, reason="local node:24-slim image and Docker are required"
)


def _declaration(**updates: object) -> ActionDeclaration:
    payload: dict[str, object] = {
        "schema_version": "proof-before-action.declaration.v1",
        "name": "fixture",
        "tools": ["node"],
        "permissions": [],
        "destinations": {"files": [], "databases": [], "network": []},
        "side_effects": {"filesystem": "none", "database": "none", "network": "none"},
        "limitations": [],
    }
    payload.update(updates)
    return ActionDeclaration.model_validate(payload)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "input.txt").write_text("stable\n", encoding="utf-8")
    return root


def _empty_trust(repo: Path) -> ReleaseTrustManifest:
    return build_release_trust_manifest(repo, None)


@requires_docker
def test_read_only_command_passes_and_is_deterministic(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    command = ["node", "-e", "require('fs').readFileSync('input.txt')"]
    first = observe_command(repo, command, image="node:24-slim")
    second = observe_command(repo, command, image="node:24-slim")
    assert first.file_changes == []
    assert first.database_changes == []
    assert first.network.surface.attempted is False
    first_comparison = compare_bill(_declaration(), first)
    second_comparison = compare_bill(_declaration(), second)
    assert first_comparison.verdict == "pass"
    first_capsule = build_capsule(_declaration(), first, first_comparison, _empty_trust(repo))
    second_capsule = build_capsule(_declaration(), second, second_comparison, _empty_trust(repo))
    assert canonical_json_bytes(first_capsule) == canonical_json_bytes(second_capsule)


@requires_docker
def test_undeclared_file_write_is_detected_and_blocked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        ["node", "-e", "require('fs').writeFileSync('created.txt','proof')"],
        image="node:24-slim",
    )
    assert [(item.path, item.change) for item in observation.file_changes] == [("created.txt", "added")]
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "block"
    assert "undeclared_file_write" in {item.code for item in comparison.findings}
    declared_write = _declaration(
        destinations={"files": ["created.txt"], "databases": [], "network": []},
        side_effects={"filesystem": "write", "database": "none", "network": "none"},
    )
    assert compare_bill(declared_write, observation).verdict == "pass"


@requires_docker
def test_seeded_sqlite_mutation_is_semantically_detected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    database = sqlite3.connect(repo / "seeded.db")
    database.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    database.execute("INSERT INTO items(value) VALUES ('before')")
    database.commit()
    database.close()
    code = (
        "const {DatabaseSync}=require('node:sqlite');"
        "const db=new DatabaseSync('seeded.db');"
        "db.exec(\"UPDATE items SET value='after' WHERE id=1\");db.close()"
    )
    observation = observe_command(repo, ["node", "-e", code], image="node:24-slim")
    assert len(observation.database_changes) == 1
    change = observation.database_changes[0]
    assert change.path == "seeded.db"
    assert change.change == "modified"
    assert change.changed_tables == ["items"]
    comparison = compare_bill(_declaration(), observation)
    assert "undeclared_database_write" in {item.code for item in comparison.findings}


@requires_docker
def test_loopback_network_attempt_is_detected_without_external_contact(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    code = (
        "const net=require('net');const s=net.connect(9,'127.0.0.1');"
        "s.on('error',()=>process.exit(0));setTimeout(()=>process.exit(0),500)"
    )
    observation = observe_command(repo, ["node", "-e", code], image="node:24-slim")
    assert observation.network.surface.attempted is True
    assert observation.network.external_contact_count == 0
    assert observation.network.counters["Tcp.ActiveOpens"] >= 1
    comparison = compare_bill(_declaration(), observation)
    assert "undeclared_network_attempt" in {item.code for item in comparison.findings}
    declared_attempt = _declaration(
        destinations={"files": [], "databases": [], "network": ["127.0.0.1:9"]},
        side_effects={"filesystem": "none", "database": "none", "network": "attempt"},
    )
    declared_comparison = compare_bill(declared_attempt, observation)
    assert declared_comparison.verdict == "unknown"
    assert "network_destination_unknown" in {item.code for item in declared_comparison.findings}


def test_declaration_omission_is_deterministic() -> None:
    from mcp_audit.proof_models import (
        CommandEvidence,
        FileChange,
        IsolationEvidence,
        NetworkEvidence,
        Observation,
        SurfaceObservation,
    )

    unchanged = SurfaceObservation(
        attempted=None,
        decision="unknown",
        outcome="unknown",
        persisted="unchanged",
        mechanism="fixture",
        complete=True,
    )
    observation = Observation(
        isolation=IsolationEvidence(
            image_reference="fixture",
            image_id="sha256:" + "a" * 64,
            runtime_user="65534:65534",
            container_network_mode="none",
            log_driver="none",
            root_filesystem_read_only=True,
            capabilities_dropped=True,
            no_new_privileges=True,
            pids_limit=128,
            memory_bytes=536870912,
            nano_cpus=1000000000,
            tmpfs_paths=["/pba", "/tmp", "/workspace"],
            containment="partial",
        ),
        command=CommandEvidence(
            argv=["node"],
            argv_sha256="c" * 64,
            executable="node",
            exit_code=0,
            timed_out=False,
            stdout_sha256="a" * 64,
            stderr_sha256="a" * 64,
            stdout_bytes=0,
            stderr_bytes=0,
        ),
        filesystem=unchanged.model_copy(
            update={"attempted": True, "persisted": "changed", "decision": "allowed"}
        ),
        file_changes=[FileChange(path="x", change="added", after_sha256="b" * 64)],
        database=unchanged,
        network=NetworkEvidence(surface=unchanged),
    )
    first = compare_bill(_declaration(), observation)
    second = compare_bill(_declaration(), observation)
    assert first.verdict == "block"
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


def _trust_fixture(tmp_path: Path) -> Path:
    trust = tmp_path / "mcp-trust"
    (trust / "src/mcp_trust/catalog").mkdir(parents=True)
    (trust / "src/mcp_trust/core").mkdir(parents=True)
    seed = [
        {
            "slug": "known",
            "name": "Known",
            "source": {"kind": "npm", "reference": "@fixture/known-mcp"},
        },
        {
            "slug": "masked",
            "name": "Masked",
            "source": {"kind": "npm", "reference": "@fixture/masked-mcp"},
        },
    ]
    snapshot = {
        "schema_version": 2,
        "generated_at": "2026-07-18T00:00:00+00:00",
        "servers": [
            {
                "slug": "known",
                "grade": "B",
                "transparency": "high",
                "scanned_at": "2026-07-01T00:00:00+00:00",
                "engine": "mcpaudit",
                "engine_version": "2.4.0",
                "scan_mode": "mcpaudit-local-network-off",
                "sandbox": {"mode": "docker", "network": "none"},
            }
        ],
    }
    (trust / "src/mcp_trust/catalog/seed_servers.json").write_text(json.dumps(seed), encoding="utf-8")
    (trust / "src/mcp_trust/catalog_snapshot.json").write_text(json.dumps(snapshot), encoding="utf-8")
    (trust / "masked-grades.json").write_text('["masked"]', encoding="utf-8")
    (trust / "src/mcp_trust/core/spec_shift_verdicts.json").write_text(
        '{"format_version":2,"servers":{}}', encoding="utf-8"
    )
    return trust


def test_known_unmatched_and_masked_dependencies_are_all_preserved(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "known": {
                        "command": "npx",
                        "args": ["@fixture/known-mcp@1.2.3"],
                    },
                    "missing": {
                        "command": "npx",
                        "args": ["@fixture/unmatched-mcp@1.0.0"],
                    },
                    "masked": {
                        "command": "npx",
                        "args": ["@fixture/masked-mcp@1.0.0"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    manifest = build_release_trust_manifest(repo, _trust_fixture(tmp_path))
    assert len(manifest.dependencies) == len(manifest.entries) == 3
    by_name = {entry.dependency.config_name: entry for entry in manifest.entries}
    assert by_name["known"].evidence.match_state == "exact"
    assert by_name["known"].evidence.version_alignment == "evidence_unversioned"
    assert by_name["missing"].evidence.state == "unmatched"
    assert by_name["masked"].evidence.state == "masked"
    assert by_name["masked"].evidence.grade is None


def test_stale_trust_evidence_is_historical_not_current(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"][0]["scanned_at"] = "2025-01-01T00:00:00+00:00"
    snapshot["generated_at"] = "2025-01-02T00:00:00+00:00"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    manifest = build_release_trust_manifest(repo, trust)
    assert manifest.entries[0].evidence.state == "stale"
    assert manifest.entries[0].evidence.grade == "B"
    assert manifest.trust_source is not None
    assert manifest.trust_source.snapshot_generated_at == "2025-01-02T00:00:00+00:00"
    assert manifest.trust_source.evaluated_at != manifest.trust_source.snapshot_generated_at


@requires_docker
def test_tampering_and_wrong_commit_or_schema_are_detected(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    declaration = _declaration()
    observation = observe_command(repo, ["node", "-e", "process.exit(0)"], image="node:24-slim")
    comparison = compare_bill(declaration, observation)
    capsule = build_capsule(declaration, observation, comparison, build_release_trust_manifest(repo, None))
    output = tmp_path / "capsule"
    root_sha = export_capsule(capsule, output)
    assert verify_capsule(output, expect_root_sha256=root_sha)["valid"] is True
    wrong = verify_capsule(
        output,
        expect_subject_commit="0" * 40,
        expect_producer_commit="1" * 40,
        expect_schema="proof-before-action.capsule.v999",
    )
    codes = {item["code"] for item in wrong["errors"]}
    assert {
        "subject_commit_mismatch",
        "producer_commit_mismatch",
        "expected_schema_mismatch",
    } <= codes
    original_index = (output / "capsule-index.json").read_bytes()
    index = json.loads(original_index)
    index["subject_commit"] = "0" * 40
    (output / "capsule-index.json").write_bytes(canonical_json_bytes(index))
    semantic_tamper = verify_capsule(output)
    assert "index_subject_mismatch" in {item["code"] for item in semantic_tamper["errors"]}
    (output / "capsule-index.json").write_bytes(original_index)
    payload = bytearray((output / "capsule.json").read_bytes())
    payload[len(payload) // 2] ^= 1
    (output / "capsule.json").write_bytes(payload)
    tampered = verify_capsule(output)
    assert tampered["valid"] is False
    assert "artifact_tampered" in {item["code"] for item in tampered["errors"]}


@requires_docker
def test_offline_html_escapes_untrusted_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    declaration = _declaration(name="<img src=x onerror=alert(1)>")
    observation = observe_command(repo, ["node", "-e", "process.exit(0)"], image="node:24-slim")
    comparison = compare_bill(declaration, observation)
    capsule = build_capsule(declaration, observation, comparison, build_release_trust_manifest(repo, None))
    output = tmp_path / "capsule"
    export_capsule(capsule, output)
    page = (output / "report.html").read_text(encoding="utf-8")
    assert "<script" not in page.lower()
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "default-src 'none'" in page
    assert CAPSULE_SCHEMA in (output / "capsule.json").read_text(encoding="utf-8")


def test_sensitive_repository_input_is_blocked_before_execution(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".env").write_text("API_TOKEN=do-not-copy\n", encoding="utf-8")
    with pytest.raises(ObservationBlocked, match="sensitive file"):
        observe_command(
            repo,
            ["node", "-e", "process.exit(0)"],
            image="node:24-slim",
        )


@pytest.mark.parametrize(
    "secret_config",
    [
        '{"mcpServers":{"unsafe":{"command":"node","env":{"OPENAI_API_KEY":"sk-proj-literal"}}}}',
        '{"mcpServers":{"unsafe":{"url":"https://example.test","headers":{"X-API-Key":"literal"}}}}',
        "OPENAI_API_KEY: literal-value",
    ],
)
def test_literal_config_secret_and_sensitive_argv_are_redacted_or_blocked(
    tmp_path: Path, secret_config: str
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        secret_config,
        encoding="utf-8",
    )
    with pytest.raises(ObservationBlocked, match="literal credential"):
        observe_command(
            repo,
            ["node", "-e", "process.exit(0)"],
            image="node:24-slim",
        )
    assert _redact_argv(
        [
            "tool",
            "--header",
            "Authorization: Bearer private-value",
            "--token=another-value",
        ]
    ) == ["tool", "--header", "<redacted>", "--token=<redacted>"]


def test_schema_cli_emits_the_strict_versioned_contract() -> None:
    result = CliRunner().invoke(main, ["schema", "declaration"])
    assert result.exit_code == 0
    schema = json.loads(result.output)
    assert schema["properties"]["schema_version"]["const"] == ("proof-before-action.declaration.v1")
    assert schema["additionalProperties"] is False


def test_capsule_index_rejects_path_expansion() -> None:
    from pydantic import ValidationError

    from mcp_audit.proof_models import CapsuleIndex

    with pytest.raises(ValidationError, match="exactly capsule.json and report.html"):
        CapsuleIndex.model_validate(
            {
                "schema_version": "proof-before-action.capsule-index.v1",
                "capsule_schema_version": CAPSULE_SCHEMA,
                "subject_commit": None,
                "producer_commit": None,
                "artifacts": [
                    {
                        "path": "../../private",
                        "sha256": "a" * 64,
                        "bytes": 1,
                        "content_type": "text/plain",
                        "logical_role": "evidence",
                    }
                ],
            }
        )


@requires_docker
def test_cli_inspect_and_verify_the_portable_capsule(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".DS_Store").write_bytes(b"\0ignored macOS metadata")
    (repo / ".coverage").write_bytes(b"\0ignored coverage data")
    (repo / ".mypy_cache").mkdir()
    (repo / ".mypy_cache/cache").write_bytes(b"\0ignored type-checker data")
    declaration = tmp_path / "declaration.yaml"
    declaration.write_text(
        """
schema_version: proof-before-action.declaration.v1
name: CLI fixture
tools: [node]
permissions: []
destinations: {files: [], databases: [], network: []}
side_effects: {filesystem: none, database: none, network: none}
limitations: []
""".strip(),
        encoding="utf-8",
    )
    output = tmp_path / "capsule"
    runner = CliRunner()
    inspected = runner.invoke(
        main,
        [
            "inspect",
            "--repo",
            str(repo),
            "--declaration",
            str(declaration),
            "--output",
            str(output),
            "--",
            "node",
            "-e",
            "process.exit(0)",
        ],
    )
    assert inspected.exit_code == 0, inspected.output
    receipt = json.loads(inspected.output)
    assert receipt["ok"] is True
    assert receipt["verdict"] == "pass"
    verified = runner.invoke(
        main,
        [
            "verify",
            str(output),
            "--expect-schema",
            CAPSULE_SCHEMA,
            "--expect-root-sha256",
            receipt["root_sha256"],
        ],
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.output)["authority"] == "anchored"
