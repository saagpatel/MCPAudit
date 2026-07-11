"""SafeForge runtime binding, isolation, and adversarial decision tests."""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

import pytest

from mcp_audit.safeforge import StageId
from mcp_audit.safeforge_consumer import ForgeReceiptV0Input
from mcp_audit.safeforge_runtime import (
    _FORK_PROBE_CODE,
    _LIMITS,
    _digest_bytes,
    _digest_json,
    _execute_runtime,
    _run_sandboxed,
    _RuntimeBlocked,
    _verify_installed_packages,
    _verify_lock_sources,
    _verify_runtime_capabilities,
)


def _receipt() -> ForgeReceiptV0Input:
    input_schema = {
        "additionalProperties": False,
        "properties": {"message": {"type": "string"}},
        "required": ["message"],
        "type": "object",
    }
    output_schema = {"additionalProperties": True, "type": "object"}
    return ForgeReceiptV0Input.model_validate(
        {
            "receipt_id": "safeforge-echo-v1",
            "receipt_version": "0.1.0",
            "created_at": "2026-07-11T20:00:00Z",
            "producer": {
                "name": "mcpforge",
                "version": "0.3.4",
                "source": "io.github.saagpatel/mcpforge",
                "revision": "fixture",
                "dirty": False,
                "executable": "mcpforge",
            },
            "source": {
                "kind": "natural-language",
                "server_id": "safeforge-echo",
                "description_digest": _digest_bytes(b"source"),
                "transport": "stdio",
            },
            "generation": {
                "provider": "replay",
                "model": "fixture",
                "no_execute": True,
                "plan_digest": _digest_bytes(b"plan"),
                "required_env_keys": [],
            },
            "launch": {
                "command": "uv",
                "args": ["--directory", ".", "run", "python", "server.py"],
                "url": None,
                "env_keys": [],
            },
            "artifact": {
                "tree_digest": _digest_bytes(b"tree"),
                "files": [
                    {
                        "path": "uv.lock",
                        "media_type": "text/plain",
                        "digest": _digest_bytes(b"lock"),
                    }
                ],
                "dependency_manifest_digest": _digest_bytes(b"dependencies"),
                "lockfile_digest": _digest_bytes(b"lock"),
                "package_identities": ["fastmcp>=3.1.0"],
            },
            "toolbom": [
                {
                    "tool_id": "safeforge-echo#echo",
                    "name": "echo",
                    "description_digest": _digest_bytes(b"Return the supplied message unchanged."),
                    "input_schema_digest": _digest_json(input_schema),
                    "output_schema_digest": _digest_json(output_schema),
                    "implementation_digest": _digest_bytes(b"implementation"),
                    "observed_capabilities": [],
                    "observed_egress_destinations": [],
                    "annotations": {
                        "read_only": True,
                        "destructive": False,
                        "idempotent": True,
                        "open_world": False,
                    },
                    "declared": {
                        "permissions": [],
                        "auth_scopes": [],
                        "data_zones": [],
                        "egress_destinations": [],
                        "credential_keys": [],
                    },
                }
            ],
            "validation": {
                "mode": "static-no-execute",
                "syntax": "passed",
                "security": "passed",
                "lint": "passed",
                "import_check": "skipped",
                "tests": "skipped",
                "security_warning_count": 0,
                "eligible_for_preinstall_audit": True,
            },
            "limitations": ["fixture"],
        }
    )


def _runtime_payload() -> dict[str, object]:
    return {
        "protocol": "2025-11-25",
        "tools": [
            {
                "name": "echo",
                "description": "Return the supplied message unchanged.",
                "inputSchema": {
                    "additionalProperties": False,
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                    "type": "object",
                },
                "outputSchema": {"additionalProperties": True, "type": "object"},
                "annotations": {
                    "readOnlyHint": True,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": False,
                },
            }
        ],
        "prompts": [],
        "resources": [],
        "call": {"echo": "safeforge"},
    }


def test_runtime_capabilities_match_exact_receipt() -> None:
    _verify_runtime_capabilities(_receipt(), _runtime_payload())


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda payload: payload["tools"].append({"name": "hidden"}), "SF-RUNTIME-TOOLS"),
        (
            lambda payload: payload["tools"][0]["inputSchema"]["properties"].update(
                {"path": {"type": "string"}}
            ),
            "SF-RUNTIME-INPUT-SCHEMA",
        ),
        (
            lambda payload: payload["tools"][0]["annotations"].update({"destructiveHint": True}),
            "SF-RUNTIME-ANNOTATIONS",
        ),
        (
            lambda payload: payload["tools"][0]["annotations"].update({"readOnlyHint": False}),
            "SF-RUNTIME-ANNOTATIONS",
        ),
        (
            lambda payload: payload["tools"][0]["annotations"].update({"idempotentHint": False}),
            "SF-RUNTIME-ANNOTATIONS",
        ),
        (
            lambda payload: payload["tools"][0]["annotations"].update({"openWorldHint": True}),
            "SF-RUNTIME-ANNOTATIONS",
        ),
        (lambda payload: payload["prompts"].append({"name": "hidden"}), "SF-RUNTIME-HIDDEN-CAPABILITY"),
        (lambda payload: payload.update({"call": {"echo": "changed"}}), "SF-RUNTIME-SYNTHETIC-CALL"),
    ],
)
def test_runtime_only_capability_mutations_fail_closed(mutation: object, code: str) -> None:
    payload = deepcopy(_runtime_payload())
    mutation(payload)  # type: ignore[operator]
    with pytest.raises(_RuntimeBlocked) as caught:
        _verify_runtime_capabilities(_receipt(), payload)
    assert caught.value.code == code
    assert caught.value.stage is StageId.AUDIT_CONNECTED


def test_declared_or_dynamic_egress_is_blocked_before_materialization(tmp_path: Path) -> None:
    for declared, observed in [(["example.invalid"], ["network"]), ([], ["network"])]:
        receipt = _receipt()
        receipt.toolbom[0].declared.egress_destinations = declared
        receipt.toolbom[0].observed_capabilities = observed  # type: ignore[assignment]
        if observed:
            receipt.toolbom[0].observed_egress_destinations = ["example.invalid"]
        with pytest.raises(_RuntimeBlocked, match="allowlisting") as caught:
            _execute_runtime(receipt, tmp_path, tmp_path / "runtime")
        assert caught.value.code == "SF-SANDBOX-EGRESS-UNSUPPORTED"


def test_filesystem_capability_is_blocked_before_materialization(tmp_path: Path) -> None:
    receipt = _receipt()
    receipt.toolbom[0].observed_capabilities = ["filesystem"]
    receipt.toolbom[0].declared.permissions = ["filesystem"]
    with pytest.raises(_RuntimeBlocked) as caught:
        _execute_runtime(receipt, tmp_path, tmp_path / "runtime")
    assert caught.value.code == "SF-SANDBOX-FILESYSTEM-UNSUPPORTED"


def test_lock_inventory_substitution_fails_closed(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text('[[package]]\nname = "fastmcp"\nversion = "3.4.4"\n')
    _verify_installed_packages(lock, {"fastmcp": "3.4.4"})
    with pytest.raises(_RuntimeBlocked) as caught:
        _verify_installed_packages(lock, {"fastmcp": "3.4.4", "undeclared-package": "1.0"})
    assert caught.value.code == "SF-SANDBOX-DEPENDENCY-SET"
    with pytest.raises(_RuntimeBlocked):
        _verify_installed_packages(lock, {"fastmcp": "9.9.9"})


def test_lock_source_and_redirect_substitution_fail_closed(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(
        '[[package]]\nname = "safeforge-echo"\nversion = "0.1.0"\nsource = { virtual = "." }\n'
        '[[package]]\nname = "fastmcp"\nversion = "3.4.4"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'wheels = [{ url = "https://files.pythonhosted.org/fastmcp.whl", hash = "sha256:abc" }]\n'
    )
    _verify_lock_sources(lock, "safeforge-echo")

    lock.write_text(
        '[[package]]\nname = "fastmcp"\nversion = "3.4.4"\n'
        'source = { registry = "https://attacker.invalid/simple" }\n'
    )
    with pytest.raises(_RuntimeBlocked) as source:
        _verify_lock_sources(lock, "safeforge-echo")
    assert source.value.code == "SF-SANDBOX-LOCK-SOURCE"

    lock.write_text(
        '[[package]]\nname = "fastmcp"\nversion = "3.4.4"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
        'wheels = [{ url = "https://redirect.invalid/fastmcp.whl", hash = "sha256:abc" }]\n'
    )
    with pytest.raises(_RuntimeBlocked):
        _verify_lock_sources(lock, "safeforge-echo")


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_supervisor_kills_hanging_shutdown_resistant_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    monkeypatch.setitem(_LIMITS, "wall_seconds", 1)
    command = [
        "/usr/local/bin/python3.12",
        "-c",
        "import signal,time; signal.signal(signal.SIGTERM, lambda *_: None); time.sleep(30)",
    ]
    result = _run_sandboxed(command, tmp_path, tmp_path / "artifact", deny_network=True)
    assert result.termination == "wall_time"
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_supervisor_enforces_process_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    monkeypatch.setitem(_LIMITS, "processes", 2)
    command = [
        "/usr/local/bin/python3.12",
        "-c",
        "import os,time; [os.fork() for _ in range(4)]; time.sleep(30)",
    ]
    result = _run_sandboxed(command, tmp_path, tmp_path / "artifact", deny_network=True)
    assert result.termination == "process_count"
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_supervisor_enforces_memory_and_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    monkeypatch.setitem(_LIMITS, "memory_bytes", 10_000_000)
    memory = _run_sandboxed(
        ["/usr/local/bin/python3.12", "-c", "import time; time.sleep(30)"],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
    )
    assert memory.termination == "memory"

    monkeypatch.setitem(_LIMITS, "memory_bytes", 1_610_612_736)
    monkeypatch.setitem(_LIMITS, "disk_bytes", 1_000_000)
    disk = _run_sandboxed(
        [
            "/usr/local/bin/python3.12",
            "-c",
            "from pathlib import Path; import time; "
            'Path("large").write_bytes(b"x"*5_000_000); time.sleep(30)',
        ],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
    )
    assert disk.termination == "disk"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_kernel_denies_artifact_root_escape_and_network(tmp_path: Path) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    code = """import socket
from pathlib import Path
blocked = 0
for action in (
    lambda: Path("/Users/d/.ssh/config").read_bytes(),
    lambda: Path("/Users/d/.safeforge-escape").write_text("x"),
    lambda: socket.create_connection(("127.0.0.1", 9), timeout=0.1),
):
    try:
        action()
    except OSError:
        blocked += 1
raise SystemExit(0 if blocked == 3 else 1)"""
    result = _run_sandboxed(
        ["/usr/local/bin/python3.12", "-c", code],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
    )
    assert result.returncode == 0
    assert result.termination is None


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_kernel_enforces_cpu_limit_and_crash_is_contained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    monkeypatch.setitem(_LIMITS, "cpu_seconds", 1)
    cpu = _run_sandboxed(
        ["/usr/local/bin/python3.12", "-c", "while True: pass"],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
    )
    assert cpu.returncode != 0

    crash = _run_sandboxed(
        ["/usr/local/bin/python3.12", "-c", "import os; os.abort()"],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
    )
    assert crash.returncode != 0


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS Seatbelt acceptance")
def test_generated_code_profile_kernel_denies_child_processes(tmp_path: Path) -> None:
    for name in ("home", "cache", "tmp", "evidence", "artifact"):
        (tmp_path / name).mkdir()
    result = _run_sandboxed(
        ["/usr/local/bin/python3.12", "-c", _FORK_PROBE_CODE],
        tmp_path,
        tmp_path / "artifact",
        deny_network=True,
        deny_fork=True,
    )
    assert result.returncode == 0
    assert result.termination is None
