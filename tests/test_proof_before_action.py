"""End-to-end acceptance coverage for Proof Before Action."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from click.testing import CliRunner

import mcp_audit.proof_capsule as proof_capsule_module
import mcp_audit_build_backend as build_backend
from mcp_audit.proof_capsule import (
    build_capsule,
    compare_bill,
    export_capsule,
    render_offline_html,
    verify_capsule,
)
from mcp_audit.proof_cli import main
from mcp_audit.proof_models import (
    CAPSULE_SCHEMA,
    ActionDeclaration,
    EvidenceCapsule,
    Observation,
    ReleaseTrustManifest,
    SubjectSnapshotEvidence,
    TrustEvidence,
    canonical_json_bytes,
    sha256_bytes,
)
from mcp_audit.proof_observer import (
    ObservationBlocked,
    _cleanup_docker_resource,
    _cleanup_local_root,
    _command_argv_evidence,
    _file_snapshot,
    _network_evidence,
    _redact_argv,
    _stage_repository,
    _subject_snapshot_evidence,
    _verify_expected_image_id,
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


def _node_image_id() -> str:
    return subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", "node:24-slim"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "input.txt").write_text("stable\n", encoding="utf-8")
    return root


def test_expected_image_id_is_required_and_exact() -> None:
    resolved = "sha256:" + "a" * 64
    with pytest.raises(ObservationBlocked, match="independently sourced"):
        _verify_expected_image_id(resolved, None)
    with pytest.raises(ObservationBlocked, match="must be an exact sha256"):
        _verify_expected_image_id(resolved, "node:24-slim")
    with pytest.raises(ObservationBlocked, match="does not match independently supplied"):
        _verify_expected_image_id(resolved, "sha256:" + "b" * 64)
    _verify_expected_image_id(resolved, resolved)


def _empty_trust(repo: Path, observation: Observation) -> ReleaseTrustManifest:
    return build_release_trust_manifest(
        repo,
        None,
        subject_snapshot=observation.subject_snapshot,
    )


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
            "--expect-image-id",
            "sha256:" + "a" * 64,
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


def test_cli_invalid_declaration_yaml_is_a_structured_inspection_block(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    declaration = tmp_path / "declaration.yaml"
    declaration.write_text("name: [unterminated\n", encoding="utf-8")

    result = CliRunner().invoke(
        main,
        [
            "inspect",
            "--repo",
            str(repo),
            "--declaration",
            str(declaration),
            "--expect-image-id",
            "sha256:" + "a" * 64,
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
    assert payload["ok"] is False
    assert payload["error"]["code"] == "inspection_blocked"
    assert "while parsing a flow sequence" in payload["error"]["message"]
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


def test_staging_keeps_the_open_file_identity_when_the_source_path_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside value\n", encoding="utf-8")
    staged = tmp_path / "staged"
    staged.mkdir()
    real_open = os.open
    swapped = False

    def swapping_open(
        path: str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "input.txt" and dir_fd is not None and not swapped:
            swapped = True
            (repo / "input.txt").unlink()
            (repo / "input.txt").symlink_to(outside)
        return descriptor

    monkeypatch.setattr(os, "open", swapping_open)

    _stage_repository(repo, staged)

    assert (staged / "input.txt").read_text(encoding="utf-8") == "stable\n"
    assert (repo / "input.txt").is_symlink()
    second_stage = tmp_path / "second-stage"
    second_stage.mkdir()
    with pytest.raises(ObservationBlocked, match="symlink or unreadable file"):
        _stage_repository(repo, second_stage)


def test_staging_fails_closed_when_the_repository_walk_cannot_continue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    staged = tmp_path / "staged"
    staged.mkdir()
    real_fwalk = os.fwalk
    captured: dict[str, object] = {}

    def capturing_fwalk(
        top: str | os.PathLike[str],
        topdown: bool = True,
        onerror: Callable[[OSError], object] | None = None,
        *,
        follow_symlinks: bool = False,
        dir_fd: int | None = None,
    ) -> Iterator[tuple[str, list[str], list[str], int]]:
        captured["onerror"] = onerror
        return real_fwalk(
            top,
            topdown=topdown,
            onerror=onerror,
            follow_symlinks=follow_symlinks,
            dir_fd=dir_fd,
        )

    monkeypatch.setattr(os, "fwalk", capturing_fwalk)

    _stage_repository(repo, staged)

    onerror = captured["onerror"]
    assert callable(onerror)
    with pytest.raises(ObservationBlocked, match="could not be traversed completely"):
        onerror(OSError("directory disappeared"))


def test_staging_detects_a_directory_silently_skipped_by_fwalk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    (repo / "child").mkdir()
    (repo / "child/config.json").write_text("{}\n", encoding="utf-8")
    staged = tmp_path / "staged"
    staged.mkdir()
    real_fwalk = os.fwalk

    def skipping_fwalk(
        top: str | os.PathLike[str],
        topdown: bool = True,
        onerror: Callable[[OSError], object] | None = None,
        *,
        follow_symlinks: bool = False,
        dir_fd: int | None = None,
    ) -> Iterator[tuple[str, list[str], list[str], int]]:
        for entry in real_fwalk(
            top,
            topdown=topdown,
            onerror=onerror,
            follow_symlinks=follow_symlinks,
            dir_fd=dir_fd,
        ):
            if Path(entry[0]).name != "child":
                yield entry

    monkeypatch.setattr(os, "fwalk", skipping_fwalk)

    with pytest.raises(ObservationBlocked, match="could not be traversed completely"):
        _stage_repository(repo, staged)


@requires_docker
def test_read_only_final_state_is_unknown_and_deterministic(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    command = ["node", "-e", "require('fs').readFileSync('input.txt')"]
    first = observe_command(
        repo,
        command,
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    second = observe_command(
        repo,
        command,
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    assert first.file_changes == []
    assert first.database_changes == []
    assert first.network.surface.attempted is False
    expected_image_id = _node_image_id()
    assert first.isolation.image_reference == "node:24-slim"
    assert first.isolation.image_id == expected_image_id
    first_comparison = compare_bill(_declaration(), first)
    second_comparison = compare_bill(_declaration(), second)
    assert first_comparison.verdict == "unknown"
    assert "observation_incomplete" in {item.code for item in first_comparison.findings}
    first_capsule = build_capsule(_declaration(), first, first_comparison, _empty_trust(repo, first))
    second_capsule = build_capsule(_declaration(), second, second_comparison, _empty_trust(repo, second))
    assert canonical_json_bytes(first_capsule) == canonical_json_bytes(second_capsule)


@requires_docker
def test_transient_file_write_cannot_be_reported_as_read_only(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        [
            "node",
            "-e",
            "const fs=require('fs');fs.writeFileSync('transient.txt','x');fs.unlinkSync('transient.txt')",
        ],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.file_changes == []
    assert observation.filesystem.complete is False
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "unknown"
    assert "observation_incomplete" in {item.code for item in comparison.findings}


@requires_docker
def test_rolled_back_database_write_cannot_be_reported_as_read_only(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    database = sqlite3.connect(repo / "seeded.db")
    database.execute("CREATE TABLE items(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
    database.execute("INSERT INTO items(value) VALUES ('before')")
    database.commit()
    database.close()
    code = (
        "const {DatabaseSync}=require('node:sqlite');"
        "const db=new DatabaseSync('seeded.db');"
        "db.exec(\"BEGIN;UPDATE items SET value='transient' WHERE id=1;ROLLBACK;\");db.close()"
    )

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.database_changes == []
    assert observation.database.complete is False
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "unknown"
    assert "observation_incomplete" in {item.code for item in comparison.findings}


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
    observation = observe_command(
        repo,
        command,
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    assert observation.command.exit_code == 0
    assert observation.command.timed_out is False
    assert observation.command.stdout_sha256 == sha256_bytes(b"")
    assert observation.file_changes == []
    assert compare_bill(_declaration(), observation).verdict == "unknown"


@requires_docker
def test_command_timeout_still_emits_fail_closed_observation(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        ["node", "-e", "setTimeout(()=>{},10000)"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
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
    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
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
    assert compare_bill(_declaration(), observation).verdict == "unknown"


@requires_docker
def test_option_like_command_is_not_consumed_by_setpriv(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    observation = observe_command(
        repo,
        ["--help"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
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
        expected_image_id=_node_image_id(),
    )
    assert [(item.path, item.change) for item in observation.file_changes] == [("created.txt", "added")]
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "block"
    assert "undeclared_file_write" in {item.code for item in comparison.findings}
    declared_write = _declaration(
        destinations={"files": ["created.txt"], "databases": [], "network": []},
        side_effects={"filesystem": "write", "database": "none", "network": "none"},
    )
    declared_comparison = compare_bill(declared_write, observation)
    assert declared_comparison.verdict == "unknown"
    assert "observation_incomplete" in {item.code for item in declared_comparison.findings}


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
    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    assert len(observation.database_changes) == 1
    change = observation.database_changes[0]
    assert change.path == "seeded.db"
    assert change.change == "modified"
    assert change.changed_tables == ["items"]
    assert observation.filesystem.attempted is None
    comparison = compare_bill(_declaration(), observation)
    assert "undeclared_database_write" in {item.code for item in comparison.findings}
    declared_database_write = _declaration(
        destinations={"files": [], "databases": ["seeded.db"], "network": []},
        side_effects={"filesystem": "none", "database": "write", "network": "none"},
    )
    declared_comparison = compare_bill(declared_database_write, observation)
    assert declared_comparison.verdict == "unknown"
    assert "observation_incomplete" in {item.code for item in declared_comparison.findings}
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
    assert manifest.dependencies == []
    assert [(item.source_pointer, item.code, item.message) for item in manifest.diagnostics] == [
        (
            "/packages/0/transport",
            "invalid_entry",
            "package transport must be an object",
        )
    ]


def test_discovery_preserves_the_selected_server_map_pointer(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        json.dumps(
            {
                "servers": {
                    "known": {
                        "command": "npx",
                        "args": ["@fixture/known-mcp"],
                    },
                    "broken": None,
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = build_release_trust_manifest(repo, None)

    dependency = manifest.dependencies[0]
    assert dependency.source_pointer == "/servers/known"
    material = b".mcp.json\0/servers/known\0npm\0@fixture/known-mcp"
    assert dependency.dependency_id == "dep_" + hashlib.sha256(material).hexdigest()[:20]
    assert manifest.diagnostics[0].source_pointer == "/servers/broken"


@pytest.mark.parametrize(
    ("updates", "pointer"),
    [
        ({"args": [0]}, "/mcpServers/fixture/args/0"),
        ({"args": "not-an-array"}, "/mcpServers/fixture/args"),
        ({"command": 0}, "/mcpServers/fixture/command"),
        ({"url": 0}, "/mcpServers/fixture/url"),
        ({"url": "https://example.invalid/mcp"}, "/mcpServers/fixture"),
        ({"env": []}, "/mcpServers/fixture/env"),
        ({"env": {"TOKEN": 0}}, "/mcpServers/fixture/env/TOKEN"),
        ({"headers": []}, "/mcpServers/fixture/headers"),
        ({"headers": {"X-Test": 0}}, "/mcpServers/fixture/headers/X-Test"),
        ({"type": 0}, "/mcpServers/fixture/type"),
        (
            {"url": "https://gateway.example:not-a-port/mcp"},
            "/mcpServers/fixture/url",
        ),
        ({"url": "https://gateway.example/m\tcp"}, "/mcpServers/fixture/url"),
        (
            {"args": ["--package=@attacker/mcp", "--", "safe"]},
            "/mcpServers/fixture/args",
        ),
        (
            {"args": ["--package", "@attacker/mcp", "--", "safe"]},
            "/mcpServers/fixture/args",
        ),
        ({"args": ["-p", "@attacker/mcp", "safe"]}, "/mcpServers/fixture/args"),
        ({"args": ["-c", "safe"]}, "/mcpServers/fixture/args"),
    ],
)
def test_malformed_server_config_fields_are_partial_and_unmatched(
    tmp_path: Path,
    updates: dict[str, object],
    pointer: str,
) -> None:
    repo = _repo(tmp_path)
    config: dict[str, object] = {
        "command": "npx",
        "args": ["@fixture/known-mcp"],
    }
    config.update(updates)
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"fixture": config}}),
        encoding="utf-8",
    )

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert pointer in {item.source_pointer for item in manifest.diagnostics}


def test_query_bearing_remote_identity_cannot_alias_the_base_endpoint(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "base": {"url": "https://gateway.example/mcp"},
                    "tenant": {
                        "url": "https://gateway.example/mcp?tenant=unreviewed",
                    },
                    "trailing": {"url": "https://gateway.example/mcp/"},
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = build_release_trust_manifest(repo, None)
    identities = {item.config_name: item.identity_name for item in manifest.dependencies}

    assert identities["base"] == "https://gateway.example/mcp"
    assert identities["tenant"] is not None
    assert identities["tenant"].startswith("sha256:")
    assert identities["tenant"] != identities["base"]
    assert "tenant=unreviewed" not in identities["tenant"]
    assert identities["trailing"] == "https://gateway.example/mcp/"
    assert identities["trailing"] != identities["base"]


@pytest.mark.parametrize(
    "section",
    ["dependencies", "devDependencies", "optionalDependencies"],
)
def test_non_object_package_dependency_sections_are_partial(
    tmp_path: Path,
    section: str,
) -> None:
    repo = _repo(tmp_path)
    (repo / "package.json").write_text(json.dumps({section: ["@fixture/mcp"]}), encoding="utf-8")

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert [(item.source_pointer, item.code) for item in manifest.diagnostics] == [
        (f"/{section}", "invalid_manifest")
    ]


@pytest.mark.parametrize(
    ("contents", "pointer"),
    [
        ("project = []\n", "/project"),
        ('[project]\ndependencies = "mcp"\n', "/project/dependencies"),
        ("[project]\ndependencies = [1]\n", "/project/dependencies/0"),
    ],
)
def test_malformed_pyproject_dependency_shapes_are_partial(
    tmp_path: Path,
    contents: str,
    pointer: str,
) -> None:
    repo = _repo(tmp_path)
    (repo / "pyproject.toml").write_text(contents, encoding="utf-8")

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert [(item.source_pointer, item.code) for item in manifest.diagnostics] == [
        (pointer, "invalid_manifest")
    ]


@pytest.mark.parametrize(
    ("state", "match_state"),
    [
        ("current", "unmatched"),
        ("stale", "ambiguous"),
        ("unmatched", "exact"),
        ("ambiguous", "exact"),
        ("masked", "unmatched"),
    ],
)
def test_trust_evidence_rejects_contradictory_state_and_match(
    state: str,
    match_state: str,
) -> None:
    with pytest.raises(ValueError, match="trust evidence"):
        TrustEvidence.model_validate({"state": state, "match_state": match_state})


@pytest.mark.parametrize(
    "updates",
    [
        {"network_isolation": "unknown", "version_alignment": "not_applicable"},
        {"network_isolation": "verified_none", "version_alignment": "dependency_unresolved"},
    ],
)
def test_current_trust_evidence_requires_complete_authority(
    updates: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="current trust evidence"):
        TrustEvidence.model_validate(
            {
                "state": "current",
                "match_state": "exact",
                **updates,
            }
        )


def test_current_trust_evidence_requires_a_complete_scan_record() -> None:
    with pytest.raises(ValueError, match="complete scan record"):
        TrustEvidence.model_validate(
            {
                "state": "current",
                "match_state": "exact",
                "network_isolation": "verified_none",
                "version_alignment": "exact",
            }
        )


def test_current_trust_evidence_rejects_unknown_reasons() -> None:
    with pytest.raises(ValueError, match="must not retain unknown reasons"):
        TrustEvidence.model_validate(
            {
                "state": "current",
                "match_state": "exact",
                "slug": "fixture",
                "grade": "A",
                "transparency": "high",
                "scanned_at": "2026-07-19T00:00:00+00:00",
                "engine": "mcpaudit",
                "engine_version": "2.4.0",
                "scan_mode": "mcpaudit-local-network-off",
                "network_isolation": "verified_none",
                "version_alignment": "exact",
                "unknown_reasons": ["contradiction"],
            }
        )


@pytest.mark.parametrize("field", ["engine_version", "scan_mode"])
def test_masked_trust_evidence_withholds_every_scan_detail(field: str) -> None:
    with pytest.raises(ValueError, match="masked trust evidence"):
        TrustEvidence.model_validate(
            {
                "state": "masked",
                "match_state": "exact",
                "slug": "fixture",
                field: "private",
                "unknown_reasons": ["operator-masked evidence is intentionally withheld"],
            }
        )


def test_non_string_package_dependency_version_is_partial(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "package.json").write_text(
        json.dumps({"dependencies": {"@fixture/mcp": {"version": "1.0.0"}}}),
        encoding="utf-8",
    )

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert manifest.diagnostics[0].source_pointer == "/dependencies/@fixture~1mcp"


@pytest.mark.parametrize(
    ("payload", "pointer"),
    [
        ([], "/"),
        ({"packages": {}}, "/packages"),
    ],
)
def test_malformed_server_descriptor_root_shapes_are_partial(
    tmp_path: Path,
    payload: object,
    pointer: str,
) -> None:
    repo = _repo(tmp_path)
    (repo / "server.json").write_text(json.dumps(payload), encoding="utf-8")

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert manifest.diagnostics[0].source_pointer == pointer


@pytest.mark.parametrize(
    ("field", "value", "pointer"),
    [
        ("registryType", {}, "/packages/0/registryType"),
        ("identifier", {}, "/packages/0/identifier"),
        ("version", {}, "/packages/0/version"),
        ("runtimeHint", {}, "/packages/0/runtimeHint"),
        ("transport", {"type": {}}, "/packages/0/transport/type"),
    ],
)
def test_malformed_server_descriptor_scalar_fields_are_partial(
    tmp_path: Path,
    field: str,
    value: object,
    pointer: str,
) -> None:
    repo = _repo(tmp_path)
    package: dict[str, object] = {
        "registryType": "npm",
        "identifier": "@fixture/mcp",
        "version": "1.0.0",
        "runtimeHint": "npx",
        "transport": {"type": "stdio"},
    }
    package[field] = value
    (repo / "server.json").write_text(
        json.dumps({"name": "fixture", "packages": [package]}),
        encoding="utf-8",
    )

    manifest = build_release_trust_manifest(repo, None)

    assert manifest.discovery_coverage == "partial"
    assert manifest.dependencies == []
    assert manifest.diagnostics[0].source_pointer == pointer


def test_trust_manifest_binds_the_full_dependency_occurrence(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"fixture":{"command":"npx","args":["@fixture/mcp@1.0.0"]}}}',
        encoding="utf-8",
    )
    manifest = build_release_trust_manifest(repo, None)
    forged = manifest.model_dump(mode="json")
    forged["entries"][0]["dependency"]["identity_name"] = "@fixture/other"

    with pytest.raises(ValueError, match="full dependency occurrence"):
        ReleaseTrustManifest.model_validate(forged)


def test_trust_manifest_dependency_ids_are_unique(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"fixture":{"command":"npx","args":["@fixture/mcp@1.0.0"]}}}',
        encoding="utf-8",
    )
    manifest = build_release_trust_manifest(repo, None)
    duplicated = manifest.model_dump(mode="json")
    duplicated["dependencies"].append(dict(duplicated["dependencies"][0]))
    duplicated["entries"].append(dict(duplicated["entries"][0]))

    with pytest.raises(ValueError, match="IDs must be unique"):
        ReleaseTrustManifest.model_validate(duplicated)


def test_ignored_staged_subject_input_marks_the_commit_unbound(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text(".mcp.json\nnode_modules/\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "proof@example.test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Proof Fixture"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    (repo / "node_modules").mkdir()
    (repo / "node_modules/cache.txt").write_text("excluded\n", encoding="utf-8")
    excluded_stage = tmp_path / "excluded-stage"
    excluded_stage.mkdir()
    _stage_repository(repo, excluded_stage)

    excluded_only = _subject_snapshot_evidence(
        repo,
        excluded_stage,
        _file_snapshot(excluded_stage),
    )

    assert excluded_only.repository_dirty is False
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"ignored":{"command":"npx","args":["@fixture/ignored-mcp"]}}}',
        encoding="utf-8",
    )
    ignored_stage = tmp_path / "ignored-stage"
    ignored_stage.mkdir()
    _stage_repository(repo, ignored_stage)
    subject_snapshot = _subject_snapshot_evidence(
        repo,
        ignored_stage,
        _file_snapshot(ignored_stage),
    )
    (repo / ".mcp.json").unlink()

    manifest = build_release_trust_manifest(
        repo,
        None,
        subject_snapshot=subject_snapshot,
    )

    assert manifest.repository_commit == subject_snapshot.repository_commit
    assert manifest.repository_dirty is True
    assert manifest.repository_staged_tree_sha256 == subject_snapshot.staged_tree_sha256
    assert manifest.dependencies[0].source_path == ".mcp.json"
    assert (
        "Subject repository is dirty; its commit does not bind the inspected working tree."
        in manifest.limitations
    )


@requires_docker
def test_loopback_network_attempt_is_detected_without_external_contact(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    code = (
        "const net=require('net');const s=net.connect(9,'127.0.0.1');"
        "s.on('error',()=>process.exit(0));setTimeout(()=>process.exit(0),500)"
    )
    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
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


def test_declaration_omission_is_deterministic(tmp_path: Path) -> None:
    from mcp_audit.proof_models import (
        CommandEvidence,
        DatabaseChange,
        FileChange,
        IsolationEvidence,
        NetworkEvidence,
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
        subject_snapshot=SubjectSnapshotEvidence(
            repository_commit=None,
            repository_dirty=None,
            staged_tree_sha256="d" * 64,
        ),
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
            argv_sha256=sha256_bytes(canonical_json_bytes(["node"])),
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

    clean_unknown = observation.model_copy(
        update={
            "filesystem": unchanged,
            "file_changes": [],
            "database": unchanged,
            "database_changes": [],
            "network": NetworkEvidence(surface=unchanged),
        }
    )
    unknown_comparison = compare_bill(_declaration(), clean_unknown)
    assert unknown_comparison.verdict == "unknown"
    assert "observation_state_unknown" in {item.code for item in unknown_comparison.findings}

    contradictory = clean_unknown.model_copy(
        update={
            "filesystem": unchanged.model_copy(
                update={
                    "attempted": False,
                    "decision": "allowed",
                    "outcome": "succeeded",
                }
            ),
            "database": unchanged.model_copy(
                update={
                    "attempted": False,
                    "decision": "not_applicable",
                    "outcome": "not_applicable",
                }
            ),
            "network": NetworkEvidence(
                surface=unchanged.model_copy(
                    update={
                        "attempted": False,
                        "decision": "not_applicable",
                        "outcome": "not_applicable",
                    }
                )
            ),
        }
    )
    contradictory_comparison = compare_bill(_declaration(), contradictory)
    assert contradictory_comparison.verdict == "unknown"
    assert "observation_state_contradictory" in {item.code for item in contradictory_comparison.findings}

    not_attempted = unchanged.model_copy(
        update={
            "attempted": False,
            "decision": "not_applicable",
            "outcome": "not_applicable",
        }
    )
    transient_effect = unchanged.model_copy(
        update={
            "attempted": True,
            "decision": "allowed",
            "outcome": "succeeded",
        }
    )
    transient_filesystem = clean_unknown.model_copy(
        update={
            "filesystem": transient_effect,
            "database": not_attempted,
            "network": NetworkEvidence(surface=not_attempted),
        }
    )
    transient_filesystem_comparison = compare_bill(_declaration(), transient_filesystem)
    assert transient_filesystem_comparison.verdict == "block"
    assert "undeclared_file_write_attempt" in {item.code for item in transient_filesystem_comparison.findings}

    transient_database = clean_unknown.model_copy(
        update={
            "filesystem": not_attempted,
            "database": transient_effect,
            "network": NetworkEvidence(surface=not_attempted),
        }
    )
    transient_database_comparison = compare_bill(_declaration(), transient_database)
    assert transient_database_comparison.verdict == "block"
    assert "undeclared_database_write_attempt" in {
        item.code for item in transient_database_comparison.findings
    }

    database_file_change = FileChange(
        path="seeded.db",
        change="modified",
        before_sha256="1" * 64,
        after_sha256="2" * 64,
    )
    database_change = DatabaseChange(
        path="seeded.db",
        change="modified",
        before_sha256="1" * 64,
        after_sha256="2" * 64,
        changed_tables=["items"],
    )
    transient_file_with_database_change = clean_unknown.model_copy(
        update={
            "file_changes": [database_file_change],
            "database_changes": [database_change],
            "filesystem": transient_effect.model_copy(update={"complete": True}),
            "database": transient_effect,
            "network": NetworkEvidence(surface=not_attempted),
        }
    )
    database_only_declaration = _declaration(
        destinations={"files": [], "databases": ["seeded.db"], "network": []},
        side_effects={"filesystem": "none", "database": "write", "network": "none"},
    )
    transient_file_with_database_comparison = compare_bill(
        database_only_declaration,
        transient_file_with_database_change,
    )
    assert transient_file_with_database_comparison.verdict == "block"
    assert "undeclared_file_write_attempt" in {
        item.code for item in transient_file_with_database_comparison.findings
    }

    repo = _repo(tmp_path)
    trust_manifest = build_release_trust_manifest(
        repo,
        None,
        subject_snapshot=observation.subject_snapshot,
    )
    forged_comparison = first.model_copy(update={"findings": [], "verdict": "pass"})
    with pytest.raises(ValueError, match="comparison does not match"):
        build_capsule(
            _declaration(),
            observation,
            forged_comparison,
            trust_manifest,
        )
    with pytest.raises(ValueError, match="trust manifest subject evidence"):
        build_capsule(
            _declaration(),
            observation,
            first,
            trust_manifest.model_copy(update={"repository_dirty": True}),
        )


def test_verifier_recomputes_semantic_capsule_bindings(tmp_path: Path) -> None:
    from mcp_audit.proof_models import (
        CommandEvidence,
        IsolationEvidence,
        NetworkEvidence,
        SurfaceObservation,
    )

    unchanged = SurfaceObservation(
        attempted=None,
        decision="unknown",
        outcome="unknown",
        persisted="unchanged",
        mechanism="fixture",
        complete=False,
    )
    observation = Observation(
        subject_snapshot=SubjectSnapshotEvidence(
            repository_commit=None,
            repository_dirty=None,
            staged_tree_sha256="d" * 64,
        ),
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
            argv_sha256=sha256_bytes(canonical_json_bytes(["node"])),
            executable="node",
            exit_code=0,
            timed_out=False,
            stdout_sha256="a" * 64,
            stderr_sha256="a" * 64,
            stdout_bytes=0,
            stderr_bytes=0,
        ),
        filesystem=unchanged,
        database=unchanged,
        network=NetworkEvidence(surface=unchanged),
    )
    command_payload = observation.command.model_dump(mode="json")
    with pytest.raises(ValueError, match="executable must match"):
        CommandEvidence.model_validate({**command_payload, "executable": "python"})
    with pytest.raises(ValueError, match="argv hash does not match"):
        CommandEvidence.model_validate({**command_payload, "argv_sha256": "0" * 64})

    declaration = _declaration()
    comparison = compare_bill(declaration, observation)
    repo = _repo(tmp_path)
    trust_manifest = build_release_trust_manifest(
        repo,
        None,
        subject_snapshot=observation.subject_snapshot,
    )
    capsule = build_capsule(declaration, observation, comparison, trust_manifest)
    output = tmp_path / "capsule"
    export_capsule(capsule, output)
    original_index = json.loads((output / "capsule-index.json").read_bytes())

    def write_consistent_forgery(raw: dict[str, object]) -> None:
        payload = raw["payload"]
        assert isinstance(payload, dict)
        integrity = raw["integrity"]
        assert isinstance(integrity, dict)
        integrity["payload_sha256"] = sha256_bytes(canonical_json_bytes(payload))
        forged = EvidenceCapsule.model_validate(raw)
        capsule_bytes = canonical_json_bytes(forged)
        report_bytes = render_offline_html(forged).encode("utf-8")
        (output / "capsule.json").write_bytes(capsule_bytes)
        (output / "report.html").write_bytes(report_bytes)
        index = json.loads(json.dumps(original_index))
        for artifact in index["artifacts"]:
            path = output / artifact["path"]
            value = path.read_bytes()
            artifact["bytes"] = len(value)
            artifact["sha256"] = sha256_bytes(value)
        (output / "capsule-index.json").write_bytes(canonical_json_bytes(index))

    raw = capsule.model_dump(mode="json")
    raw["payload"]["comparison"]["findings"] = []
    raw["payload"]["comparison"]["verdict"] = "pass"
    write_consistent_forgery(raw)
    result = verify_capsule(output)
    assert "comparison_mismatch" in {item["code"] for item in result["errors"]}

    raw = capsule.model_dump(mode="json")
    raw["payload"]["trust_manifest"]["repository_dirty"] = True
    write_consistent_forgery(raw)
    result = verify_capsule(output)
    assert "subject_manifest_mismatch" in {item["code"] for item in result["errors"]}

    raw = capsule.model_dump(mode="json")
    write_consistent_forgery(raw)
    forged_report = b"<!doctype html><title>forged pass</title>"
    (output / "report.html").write_bytes(forged_report)
    index = json.loads((output / "capsule-index.json").read_bytes())
    report_artifact = next(item for item in index["artifacts"] if item["path"] == "report.html")
    report_artifact["bytes"] = len(forged_report)
    report_artifact["sha256"] = sha256_bytes(forged_report)
    (output / "capsule-index.json").write_bytes(canonical_json_bytes(index))
    result = verify_capsule(output)
    assert "report_projection_mismatch" in {item["code"] for item in result["errors"]}

    write_consistent_forgery(capsule.model_dump(mode="json"))
    capsule_path = output / "capsule.json"
    noncanonical_capsule = json.dumps(json.loads(capsule_path.read_bytes()), indent=2).encode()
    capsule_path.write_bytes(noncanonical_capsule)
    index = json.loads((output / "capsule-index.json").read_bytes())
    capsule_artifact = next(item for item in index["artifacts"] if item["path"] == "capsule.json")
    capsule_artifact["bytes"] = len(noncanonical_capsule)
    capsule_artifact["sha256"] = sha256_bytes(noncanonical_capsule)
    (output / "capsule-index.json").write_bytes(canonical_json_bytes(index))
    result = verify_capsule(output)
    assert "capsule_noncanonical" in {item["code"] for item in result["errors"]}

    write_consistent_forgery(capsule.model_dump(mode="json"))
    index_path = output / "capsule-index.json"
    noncanonical_index = json.dumps(json.loads(index_path.read_bytes()), indent=2).encode()
    index_path.write_bytes(noncanonical_index)
    result = verify_capsule(output)
    assert "index_noncanonical" in {item["code"] for item in result["errors"]}

    def bind_capsule_bytes(capsule_bytes: bytes) -> None:
        (output / "capsule.json").write_bytes(capsule_bytes)
        index = json.loads(json.dumps(original_index))
        for artifact in index["artifacts"]:
            value = (output / artifact["path"]).read_bytes()
            artifact["bytes"] = len(value)
            artifact["sha256"] = sha256_bytes(value)
        (output / "capsule-index.json").write_bytes(canonical_json_bytes(index))

    for field_path, malformed_value in [
        (("observation", "filesystem", "complete"), "false"),
        (("observation", "command", "exit_code"), "0"),
        (("observation", "command", "stdout_bytes"), "0"),
    ]:
        write_consistent_forgery(capsule.model_dump(mode="json"))
        raw = capsule.model_dump(mode="json")
        target = raw["payload"]
        for key in field_path[:-1]:
            target = target[key]
        target[field_path[-1]] = malformed_value
        raw["integrity"]["payload_sha256"] = sha256_bytes(canonical_json_bytes(raw["payload"]))
        bind_capsule_bytes(canonical_json_bytes(raw))
        result = verify_capsule(output)
        assert "capsule_schema_invalid" in {item["code"] for item in result["errors"]}

    write_consistent_forgery(capsule.model_dump(mode="json"))
    raw = capsule.model_dump(mode="json")
    raw["payload"]["observation"]["command"]["stdout_bytes"] = 0.0
    float_capsule = (
        json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    )
    bind_capsule_bytes(float_capsule)
    result = verify_capsule(output)
    assert "capsule_schema_invalid" in {item["code"] for item in result["errors"]}

    write_consistent_forgery(capsule.model_dump(mode="json"))
    index = json.loads((output / "capsule-index.json").read_bytes())
    index["artifacts"][0]["bytes"] = float(index["artifacts"][0]["bytes"])
    float_index = (
        json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    )
    (output / "capsule-index.json").write_bytes(float_index)
    result = verify_capsule(output)
    assert "index_schema_invalid" in {item["code"] for item in result["errors"]}


def test_build_requirement_hooks_delegate_to_uv_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    uv_build = ModuleType("uv_build")
    calls: list[tuple[str, object]] = []
    for hook in ("sdist", "wheel", "editable"):
        name = f"get_requires_for_build_{hook}"

        def requirement_hook(
            config_settings: object,
            *,
            hook_name: str = name,
        ) -> list[str]:
            calls.append((hook_name, config_settings))
            return [hook_name]

        monkeypatch.setattr(uv_build, name, requirement_hook, raising=False)
    monkeypatch.setitem(sys.modules, "uv_build", uv_build)
    settings = {"proof": "before-action"}

    assert build_backend.get_requires_for_build_sdist(settings) == ["get_requires_for_build_sdist"]
    assert build_backend.get_requires_for_build_wheel(settings) == ["get_requires_for_build_wheel"]
    assert build_backend.get_requires_for_build_editable(settings) == ["get_requires_for_build_editable"]
    assert calls == [
        ("get_requires_for_build_sdist", settings),
        ("get_requires_for_build_wheel", settings),
        ("get_requires_for_build_editable", settings),
    ]


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


def test_same_day_scan_uses_deterministic_end_of_day_freshness(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    endpoint = "https://example.invalid/mcp"
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"known": {"url": endpoint}}}),
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    seed_path = trust / "src/mcp_trust/catalog/seed_servers.json"
    seed = json.loads(seed_path.read_text())
    seed[0]["source"] = {"kind": "remote", "reference": endpoint}
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    current = datetime.now(UTC).isoformat()
    snapshot["generated_at"] = current
    snapshot["servers"][0]["scanned_at"] = current
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _commit_trust_fixture(trust, "same-day trust scan")

    manifest = build_release_trust_manifest(repo, trust)
    evidence = manifest.entries[0].evidence

    assert manifest.trust_source is not None
    assert manifest.trust_source.evaluated_at.endswith("T23:59:59.999999+00:00")
    assert evidence.state == "current"
    assert evidence.network_isolation == "verified_none"

    forged = manifest.model_dump(mode="json")
    forged["trust_source"]["dirty"] = True
    with pytest.raises(ValueError, match="clean committed source"):
        ReleaseTrustManifest.model_validate(forged)

    forged = manifest.model_dump(mode="json")
    forged["entries"][0]["evidence"]["scanned_at"] = "2025-01-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="recorded freshness"):
        ReleaseTrustManifest.model_validate(forged)

    forged = manifest.model_dump(mode="json")
    forged["discovery_coverage"] = "partial"
    with pytest.raises(ValueError, match="diagnostic-free discovery"):
        ReleaseTrustManifest.model_validate(forged)


@pytest.mark.parametrize(
    "generated_at",
    [
        "not-a-date",
        "2026-07-18T00:00:00",
        "2026-06-30T00:00:00+00:00",
        "2999-01-01T00:00:00+00:00",
    ],
)
def test_invalid_or_impossible_trust_generation_time_is_unknown(
    tmp_path: Path,
    generated_at: str,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["generated_at"] = generated_at
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _commit_trust_fixture(trust, "invalid trust generation time")

    manifest = build_release_trust_manifest(repo, trust)

    assert manifest.discovery_coverage == "unknown"
    assert manifest.trust_source is None
    assert manifest.entries[0].evidence.state == "unverifiable"
    assert manifest.entries[0].evidence.grade is None
    assert "mcp-trust source has an unsupported data shape" in manifest.limitations


def test_unproven_network_isolation_cannot_be_current_trust_evidence(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    endpoint = "https://example.invalid/mcp"
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"known": {"url": endpoint}}}),
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    seed_path = trust / "src/mcp_trust/catalog/seed_servers.json"
    seed = json.loads(seed_path.read_text())
    seed[0]["source"] = {"kind": "remote", "reference": endpoint}
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"][0]["scan_mode"] = "mcpaudit-local-network-unknown"
    snapshot["servers"][0]["sandbox"]["network"] = "unknown"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _commit_trust_fixture(trust, "network isolation unproven")

    evidence = build_release_trust_manifest(repo, trust).entries[0].evidence

    assert evidence.match_state == "exact"
    assert evidence.version_alignment == "not_applicable"
    assert evidence.network_isolation == "unknown"
    assert evidence.state == "unverifiable"
    assert "mcp-trust record does not prove network isolation" in evidence.unknown_reasons


@pytest.mark.parametrize(
    ("scan_mode", "network"),
    [
        ("static-analysis", "not_applicable"),
        ("mcpaudit-local-network-off", "none"),
    ],
)
def test_not_applicable_or_contradictory_network_isolation_is_not_current(
    tmp_path: Path,
    scan_mode: str,
    network: str,
) -> None:
    repo = _repo(tmp_path)
    endpoint = "https://example.invalid/mcp"
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"known": {"url": endpoint}}}),
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    seed_path = trust / "src/mcp_trust/catalog/seed_servers.json"
    seed = json.loads(seed_path.read_text())
    seed[0]["source"] = {"kind": "remote", "reference": endpoint}
    seed_path.write_text(json.dumps(seed), encoding="utf-8")
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["servers"][0]["scan_mode"] = scan_mode
    snapshot["servers"][0]["sandbox"] = {"mode": "not_applicable", "network": network}
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    _commit_trust_fixture(trust, "network isolation not applicable")

    evidence = build_release_trust_manifest(repo, trust).entries[0].evidence

    assert evidence.match_state == "exact"
    assert evidence.version_alignment == "not_applicable"
    assert evidence.network_isolation == "not_applicable"
    assert evidence.state == "unverifiable"
    assert "network isolation was not applicable to the recorded scan" in evidence.unknown_reasons


def test_ipv6_network_counters_are_observed(tmp_path: Path) -> None:
    before = tmp_path / "network.before"
    after = tmp_path / "network.after"
    before6 = tmp_path / "network6.before"
    after6 = tmp_path / "network6.after"
    snmp = (
        "Ip: OutRequests\nIp: 0\n"
        "Tcp: ActiveOpens PassiveOpens AttemptFails\nTcp: 0 0 0\n"
        "Udp: OutDatagrams\nUdp: 0\n"
    )
    before.write_text(snmp, encoding="utf-8")
    after.write_text(snmp, encoding="utf-8")
    before6.write_text(
        "Ip6OutRequests 0\nUdp6OutDatagrams 0\n",
        encoding="utf-8",
    )
    after6.write_text(
        "Ip6OutRequests 1\nUdp6OutDatagrams 1\n",
        encoding="utf-8",
    )

    evidence = _network_evidence(before, after, before6, after6, timed_out=False)

    assert evidence.surface.complete is False
    assert evidence.surface.attempted is True
    assert "Unix-domain socket activity" in " ".join(evidence.surface.limitations)
    assert evidence.counters["Ip6.OutRequests"] == 1
    assert evidence.counters["Udp6.OutDatagrams"] == 1


def test_missing_ipv6_counters_make_network_observation_incomplete(tmp_path: Path) -> None:
    before = tmp_path / "network.before"
    after = tmp_path / "network.after"
    before.write_text("Ip: OutRequests\nIp: 0\n", encoding="utf-8")
    after.write_text("Ip: OutRequests\nIp: 0\n", encoding="utf-8")

    evidence = _network_evidence(
        before,
        after,
        tmp_path / "missing-network6.before",
        tmp_path / "missing-network6.after",
        timed_out=False,
    )

    assert evidence.surface.complete is False
    assert evidence.surface.attempted is None


@requires_docker
def test_ipv6_udp_attempt_is_detected_and_blocked(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    code = (
        "const dgram=require('dgram');const socket=dgram.createSocket('udp6');"
        "socket.send(Buffer.from('x'),9,'::1',error=>{socket.close();if(error)process.exit(2)})"
    )

    observation = observe_command(
        repo,
        ["node", "-e", code],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )

    assert observation.command.exit_code == 0
    assert observation.network.surface.complete is False
    assert observation.network.surface.attempted is True
    assert "Unix-domain socket activity" in " ".join(observation.network.surface.limitations)
    assert observation.network.counters["Udp6.OutDatagrams"] > 0
    comparison = compare_bill(_declaration(), observation)
    assert comparison.verdict == "block"
    assert "undeclared_network_attempt" in {item.code for item in comparison.findings}


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


def test_loaded_trust_bytes_must_match_the_recorded_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    snapshot_path = trust / "src/mcp_trust/catalog_snapshot.json"
    original_read_bytes = Path.read_bytes

    def read_bytes(path: Path) -> bytes:
        value = original_read_bytes(path)
        if path == snapshot_path:
            payload = json.loads(value)
            payload["servers"][0]["grade"] = "A"
            return json.dumps(payload).encode()
        return value

    monkeypatch.setattr(Path, "read_bytes", read_bytes)

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
        ("src/mcp_trust/catalog/seed_servers.json", [{"source": "not-an-object"}]),
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


@pytest.mark.parametrize(
    ("relative", "field"),
    [
        ("src/mcp_trust/catalog_snapshot.json", "schema_version"),
        ("src/mcp_trust/core/spec_shift_verdicts.json", "format_version"),
    ],
)
def test_boolean_trust_schema_versions_are_structured_unknown(
    tmp_path: Path,
    relative: str,
    field: str,
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    path = trust / relative
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[field] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    _commit_trust_fixture(trust, "commit Boolean trust schema version")

    manifest = build_release_trust_manifest(repo, trust)

    assert manifest.discovery_coverage == "unknown"
    assert manifest.trust_source is None
    assert manifest.entries[0].evidence.state == "unverifiable"
    assert manifest.entries[0].evidence.grade is None
    assert "mcp-trust source has an unsupported data shape" in manifest.limitations


@pytest.mark.parametrize(
    ("relative", "field_path"),
    [
        ("src/mcp_trust/catalog/seed_servers.json", (0, "slug")),
        ("src/mcp_trust/catalog/seed_servers.json", (0, "source")),
        ("src/mcp_trust/catalog/seed_servers.json", (0, "source", "kind")),
        ("src/mcp_trust/catalog/seed_servers.json", (0, "source", "reference")),
        ("src/mcp_trust/catalog_snapshot.json", ("schema_version",)),
        ("src/mcp_trust/catalog_snapshot.json", ("generated_at",)),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "slug")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "grade")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "transparency")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "scanned_at")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "engine")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "engine_version")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "scan_mode")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "sandbox")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "sandbox", "mode")),
        ("src/mcp_trust/catalog_snapshot.json", ("servers", 0, "sandbox", "network")),
        ("src/mcp_trust/core/spec_shift_verdicts.json", ("format_version",)),
        ("src/mcp_trust/core/spec_shift_verdicts.json", ("servers",)),
    ],
)
def test_malformed_nested_trust_fields_become_structured_unknown(
    tmp_path: Path,
    relative: str,
    field_path: tuple[str | int, ...],
) -> None:
    repo = _repo(tmp_path)
    (repo / ".mcp.json").write_text(
        '{"mcpServers":{"known":{"command":"npx","args":["@fixture/known-mcp"]}}}',
        encoding="utf-8",
    )
    trust = _trust_fixture(tmp_path)
    path = trust / relative
    payload = json.loads(path.read_text(encoding="utf-8"))
    cursor = payload
    for field in field_path[:-1]:
        cursor = cursor[field]
    cursor[field_path[-1]] = ["malformed"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    _commit_trust_fixture(trust, "commit malformed nested trust input")

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
    observation = observe_command(
        repo,
        ["node", "-e", "process.exit(0)"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    comparison = compare_bill(declaration, observation)
    capsule = build_capsule(
        declaration,
        observation,
        comparison,
        build_release_trust_manifest(
            repo,
            None,
            subject_snapshot=observation.subject_snapshot,
        ),
    )
    output = tmp_path / "capsule"
    root_sha = export_capsule(capsule, output)
    assert verify_capsule(output, expect_root_sha256=root_sha)["valid"] is True
    capsule_path = output / "capsule.json"
    index_path = output / "capsule-index.json"
    original_capsule = capsule_path.read_bytes()
    original_index = index_path.read_bytes()
    legacy_capsule = json.loads(original_capsule)
    legacy_capsule["payload"]["observation"].pop("subject_snapshot")
    legacy_capsule["payload"]["trust_manifest"].pop("repository_staged_tree_sha256")
    legacy_capsule["integrity"]["payload_sha256"] = sha256_bytes(
        canonical_json_bytes(legacy_capsule["payload"])
    )
    legacy_capsule_bytes = canonical_json_bytes(legacy_capsule)
    capsule_path.write_bytes(legacy_capsule_bytes)
    legacy_index = json.loads(original_index)
    capsule_artifact = next(
        artifact for artifact in legacy_index["artifacts"] if artifact["path"] == "capsule.json"
    )
    capsule_artifact["sha256"] = sha256_bytes(legacy_capsule_bytes)
    capsule_artifact["bytes"] = len(legacy_capsule_bytes)
    index_path.write_bytes(canonical_json_bytes(legacy_index))
    legacy_result = verify_capsule(output)
    assert legacy_result["valid"] is False
    assert {"subject_snapshot_missing", "subject_manifest_binding_missing"} <= {
        item["code"] for item in legacy_result["errors"]
    }
    capsule_path.write_bytes(original_capsule)
    index_path.write_bytes(original_index)
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
    index = json.loads(original_index)
    index["subject_commit"] = "0" * 40
    index_path.write_bytes(canonical_json_bytes(index))
    semantic_tamper = verify_capsule(output)
    assert "index_subject_mismatch" in {item["code"] for item in semantic_tamper["errors"]}
    index_path.write_bytes(original_index)
    payload = bytearray(capsule_path.read_bytes())
    payload[len(payload) // 2] ^= 1
    capsule_path.write_bytes(payload)
    tampered = verify_capsule(output)
    assert tampered["valid"] is False
    assert "artifact_tampered" in {item["code"] for item in tampered["errors"]}


@requires_docker
def test_offline_html_escapes_untrusted_text(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    declaration = _declaration(name="<img src=x onerror=alert(1)>")
    observation = observe_command(
        repo,
        ["node", "-e", "process.exit(0)"],
        image="node:24-slim",
        expected_image_id=_node_image_id(),
    )
    comparison = compare_bill(declaration, observation)
    capsule = build_capsule(
        declaration,
        observation,
        comparison,
        build_release_trust_manifest(
            repo,
            None,
            subject_snapshot=observation.subject_snapshot,
        ),
    )
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
            expected_image_id=_node_image_id(),
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
            expected_image_id=_node_image_id(),
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
            "--expect-image-id",
            _node_image_id(),
            "--output",
            str(output),
            "--",
            "node",
            "-e",
            "process.exit(0)",
        ],
    )
    assert inspected.exit_code == 1, inspected.output
    receipt = json.loads(inspected.output)
    assert receipt["ok"] is False
    assert receipt["verdict"] == "unknown"
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
