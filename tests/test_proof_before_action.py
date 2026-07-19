"""End-to-end acceptance coverage for Proof Before Action."""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

import mcp_audit.proof_capsule as proof_capsule_module
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
    sha256_bytes,
)
from mcp_audit.proof_observer import (
    ObservationBlocked,
    _cleanup_docker_resource,
    _cleanup_local_root,
    _command_argv_evidence,
    _redact_argv,
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


def test_cli_docker_timeout_is_a_structured_inspection_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    declaration = tmp_path / "declaration.yaml"
    declaration.write_text(
        """
schema_version: proof-before-action.declaration.v1
name: timeout fixture
tools: [node]
permissions: []
destinations: {files: [], databases: [], network: []}
side_effects: {filesystem: none, database: none, network: none}
limitations: []
""".strip(),
        encoding="utf-8",
    )

    def time_out(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(cmd=["docker"], timeout=20)

    monkeypatch.setattr(subprocess, "run", time_out)
    result = CliRunner().invoke(
        main,
        [
            "inspect",
            "--repo",
            str(repo),
            "--declaration",
            str(declaration),
            "--output",
            str(tmp_path / "capsule"),
            "--",
            "node",
            "-e",
            "process.exit(0)",
        ],
    )
    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload == {
        "ok": False,
        "error": {
            "code": "inspection_blocked",
            "message": "Docker command timed out after 20 seconds",
        },
    }
    assert result.exception is not None
    assert "Traceback" not in result.output


def test_cleanup_readback_fails_closed_for_nonzero_docker_and_remaining_local_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failed = subprocess.CompletedProcess[bytes](
        args=["docker", "rm", "-f", "fixture"],
        returncode=1,
        stdout=b"",
        stderr=b"daemon unavailable",
    )
    monkeypatch.setattr("mcp_audit.proof_observer._run", lambda argv, timeout: failed)
    assert (
        _cleanup_docker_resource(["docker", "rm", "-f", "fixture"], timeout=20)
        == "Docker cleanup command failed with exit code 1"
    )

    local_root = tmp_path / "proof-before-action-fixture"
    local_root.mkdir()
    monkeypatch.setattr(shutil, "rmtree", lambda *args, **kwargs: None)
    assert _cleanup_local_root(local_root) == "local temporary evidence root still exists after cleanup"


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
def test_background_descendant_cannot_mutate_after_observation_completion(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "padding.txt").write_text("x" * (2 * 1024 * 1024), encoding="utf-8")
    child = (
        "const fs=require('fs');let sawWorkspaceTar=false;"
        "setInterval(()=>{let active=false;"
        "for(const entry of fs.readdirSync('/proc')){"
        "if(!/^\\d+$/.test(entry))continue;"
        "try{const argv=fs.readFileSync(`/proc/${entry}/cmdline`,'utf8').split('\\0');"
        "const executable=(argv[0]||'').split('/').pop();"
        "if(executable==='tar'&&argv.some(value=>value==='workspace'||value==='/workspace'))"
        "active=true;}catch{}}"
        "if(active)sawWorkspaceTar=true;"
        "if(sawWorkspaceTar&&!active){"
        "fs.writeFileSync('late-descendant.txt','evasion');"
        "try{fs.writeFileSync('/pba/stdout','attack-completed')}catch{}"
        "process.exit(0);}},1)"
    )
    command = [
        "node",
        "-e",
        (
            "const {spawn}=require('child_process');"
            f"spawn(process.execPath,['-e',{json.dumps(child)}],"
            "{detached:true,stdio:'ignore'}).unref()"
        ),
    ]
    observation = observe_command(repo, command, image="node:24-slim")
    assert observation.command.exit_code == 0
    assert observation.command.timed_out is False
    assert observation.command.stdout_sha256 == sha256_bytes(b"")
    assert observation.file_changes == []
    assert compare_bill(_declaration(), observation).verdict == "pass"


@requires_docker
def test_command_timeout_still_emits_fail_closed_observation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        ["node", "-e", "setTimeout(()=>{},10000)"],
        image="node:24-slim",
        timeout_seconds=1,
    )
    assert observation.command.timed_out is True
    assert observation.command.exit_code is None
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "block"
    assert "command_timeout" in {item.code for item in comparison.findings}


@requires_docker
def test_command_is_unprivileged_and_cannot_rewrite_observer_evidence(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    code = (
        "const fs=require('fs');"
        "if(process.getuid()!==65534||process.getgid()!==65534)process.exit(10);"
        "if(process.env.PATH!=='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')"
        "process.exit(13);"
        "try{fs.writeFileSync('/pba/network.before','forged');process.exit(11)}"
        "catch(error){if(error.code!=='EACCES')process.exit(12)}"
    )
    observation = observe_command(repo, ["node", "-e", code], image="node:24-slim")
    assert observation.command.exit_code == 0
    assert observation.isolation.provider == "docker"
    assert observation.isolation.runtime_user == "65534:65534"
    assert observation.isolation.observer_user == "0:0"
    assert observation.isolation.observer_capabilities == [
        "KILL",
        "SETGID",
        "SETPCAP",
        "SETUID",
    ]
    assert observation.isolation.command_runtime_profile is not None
    profile = observation.isolation.command_runtime_profile
    assert profile.uids == (65534, 65534, 65534, 65534)
    assert profile.gids == (65534, 65534, 65534, 65534)
    assert profile.supplementary_groups == []
    assert profile.capabilities_inheritable == 0
    assert profile.capabilities_permitted == 0
    assert profile.capabilities_effective == 0
    assert profile.capabilities_bounding == 0
    assert profile.capabilities_ambient == 0
    assert profile.no_new_privileges is True
    assert compare_bill(_declaration(), observation).verdict == "pass"


@requires_docker
def test_option_like_command_is_not_consumed_by_setpriv(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(repo, ["--help"], image="node:24-slim")
    assert observation.command.exit_code not in {None, 0}
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "block"
    assert "command_failed" in {item.code for item in comparison.findings}


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
    declared_database_write = _declaration(
        destinations={"files": [], "databases": ["seeded.db"], "network": []},
        side_effects={"filesystem": "none", "database": "write", "network": "none"},
    )
    declared_comparison = compare_bill(declared_database_write, observation)
    assert declared_comparison.verdict == "pass"
    assert declared_comparison.observed_capabilities == ["database_write"]


@pytest.mark.parametrize("transport", [None, "stdio"])
def test_server_descriptor_scalar_transport_is_a_partial_diagnostic(
    tmp_path: Path, transport: object
) -> None:
    repo = _repo(tmp_path)
    (repo / "server.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "packages": [
                    {
                        "identifier": "@fixture/server",
                        "registryType": "npm",
                        "transport": transport,
                        "version": "1.0.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = build_release_trust_manifest(repo, None)
    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies[0].transport == "unknown"
    assert [(item.source_pointer, item.code, item.message) for item in manifest.diagnostics] == [
        (
            "/packages/0/transport",
            "invalid_entry",
            "package transport must be an object",
        )
    ]


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
    _commit_trust_fixture(trust, "initial trust fixture")
    return trust


def _commit_trust_fixture(trust: Path, message: str) -> None:
    if not (trust / ".git").is_dir():
        subprocess.run(["git", "init", "-q", str(trust)], check=True)
        subprocess.run(
            ["git", "-C", str(trust), "config", "user.email", "proof-fixture@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(trust), "config", "user.name", "Proof Fixture"],
            check=True,
        )
    subprocess.run(["git", "-C", str(trust), "add", "."], check=True)
    subprocess.run(["git", "-C", str(trust), "commit", "-q", "-m", message], check=True)


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
    _commit_trust_fixture(trust, "stale trust fixture")
    manifest = build_release_trust_manifest(repo, trust)
    assert manifest.entries[0].evidence.state == "stale"
    assert manifest.entries[0].evidence.grade == "B"
    assert manifest.trust_source is not None
    assert manifest.trust_source.snapshot_generated_at == "2025-01-02T00:00:00+00:00"
    assert manifest.trust_source.evaluated_at != manifest.trust_source.snapshot_generated_at


def test_dirty_trust_source_cannot_emit_authoritative_grade_details(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"][0]["grade"] = "A"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")

    manifest = build_release_trust_manifest(repo, trust)

    assert manifest.trust_source is not None
    assert manifest.trust_source.dirty is True
    evidence = manifest.entries[0].evidence
    assert evidence.state == "unverifiable"
    assert evidence.match_state == "exact"
    assert evidence.grade is None
    assert evidence.transparency is None
    assert evidence.scanned_at is None
    assert evidence.engine is None
    assert evidence.engine_version is None
    assert evidence.scan_mode is None
    assert evidence.network_isolation == "unknown"
    assert (
        "mcp-trust source worktree is dirty; entry-level trust evidence is non-authoritative"
        in evidence.unknown_reasons
    )


def test_ignored_untracked_trust_inputs_cannot_escape_commit_binding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    required = [
        "src/mcp_trust/catalog_snapshot.json",
        "src/mcp_trust/catalog/seed_servers.json",
        "masked-grades.json",
        "src/mcp_trust/core/spec_shift_verdicts.json",
    ]
    subprocess.run(
        ["git", "-C", str(trust), "rm", "--cached", "--quiet", "--", *required],
        check=True,
    )
    (trust / ".gitignore").write_text("\n".join(required) + "\n", encoding="utf-8")
    _commit_trust_fixture(trust, "ignore unbound trust inputs")

    manifest = build_release_trust_manifest(repo, trust)

    assert manifest.trust_source is not None
    assert manifest.trust_source.dirty is False
    evidence = manifest.entries[0].evidence
    assert evidence.state == "unverifiable"
    assert evidence.grade is None
    assert (
        "required mcp-trust inputs are not byte-identical to the trust commit; "
        "entry-level trust evidence is non-authoritative" in evidence.unknown_reasons
    )


@pytest.mark.parametrize(
    ("relative", "payload"),
    [
        ("src/mcp_trust/catalog_snapshot.json", []),
        ("src/mcp_trust/catalog/seed_servers.json", {"servers": {}}),
        ("masked-grades.json", {}),
        ("src/mcp_trust/core/spec_shift_verdicts.json", []),
    ],
)
def test_wrong_shaped_trust_inputs_become_structured_unknown(
    tmp_path: Path,
    relative: str,
    payload: object,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    (trust / relative).write_text(json.dumps(payload), encoding="utf-8")

    manifest = build_release_trust_manifest(repo, trust)

    assert manifest.discovery_coverage == "unknown"
    assert manifest.trust_source is None
    assert manifest.entries[0].evidence.state == "unverifiable"
    assert manifest.entries[0].evidence.grade is None
    assert "mcp-trust source has an unsupported data shape" in manifest.limitations


def test_installed_module_does_not_inherit_an_unrelated_ancestor_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ancestor = tmp_path / "caller"
    ancestor.mkdir()
    subprocess.run(["git", "init", "-q", str(ancestor)], check=True)
    installed_module = ancestor / ".venv/lib/python3.11/site-packages/mcp_audit/proof_capsule.py"
    installed_module.parent.mkdir(parents=True)
    installed_module.write_text("# installed fixture\n", encoding="utf-8")
    monkeypatch.setattr(
        proof_capsule_module,
        "__file__",
        str(installed_module),
    )

    assert proof_capsule_module._producer_state() == (None, None, None)


def test_installed_module_uses_embedded_build_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed_module = tmp_path / "site-packages/mcp_audit/proof_capsule.py"
    installed_module.parent.mkdir(parents=True)
    installed_module.write_text("# installed fixture\n", encoding="utf-8")
    (installed_module.parent / "_build_provenance.json").write_text(
        json.dumps(
            {
                "schema_version": "mcp-audits.build-provenance.v1",
                "commit": "a" * 40,
                "dirty": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        proof_capsule_module,
        "__file__",
        str(installed_module),
    )

    assert proof_capsule_module._producer_state() == (
        "a" * 40,
        False,
        "build-metadata",
    )


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
    wrong_root = verify_capsule(output, expect_root_sha256="0" * 64)
    assert wrong_root["valid"] is False
    assert wrong_root["authority"] == "unverified"
    assert "authority_root_mismatch" in {item["code"] for item in wrong_root["errors"]}
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
    ("config_name", "secret_config"),
    [
        (
            ".mcp.json",
            '{"mcpServers":{"unsafe":{"command":"node","env":{"OPENAI_API_KEY":"sk-proj-literal"}}}}',
        ),
        (
            ".mcp.json",
            '{"mcpServers":{"unsafe":{"url":"https://example.test","headers":{"X-API-Key":"literal"}}}}',
        ),
        ("unsafe.yml", "id-token: literal-value"),
        ("unsafe.yml", "OPENAI_API_KEY: literal-value"),
    ],
)
def test_literal_config_secret_and_sensitive_argv_are_redacted_or_blocked(
    tmp_path: Path, config_name: str, secret_config: str
) -> None:
    repo = _repo(tmp_path)
    (repo / config_name).write_text(
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
    private_argv = [
        "node",
        "/Users/alice/Projects/private-tool/run.js",
        "--config=/home/bob/.config/private.json",
    ]
    recorded_argv, recorded_digest = _command_argv_evidence(private_argv)
    assert recorded_argv == [
        "node",
        "$HOME/Projects/private-tool/run.js",
        "--config=$HOME/.config/private.json",
    ]
    assert recorded_digest == sha256_bytes(canonical_json_bytes(recorded_argv))
    assert recorded_digest != sha256_bytes(canonical_json_bytes(private_argv))


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
    (repo / ".github/workflows").mkdir(parents=True)
    (repo / ".github/workflows/publish.yml").write_text(
        "permissions:\n"
        "  id-token: write\n"
        "steps:\n"
        "  persist-credentials: false\n"
        "  token: ${{ secrets.TOKEN }}\n",
        encoding="utf-8",
    )
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
