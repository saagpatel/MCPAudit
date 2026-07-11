"""Read-only ForgeReceiptV0 ingestion and preinstall binding tests."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import anyio
import pytest

from mcp_audit.connector import ServerConnector
from mcp_audit.safeforge import StageId
from mcp_audit.safeforge_consumer import consume_forge_receipt

_NOW = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)
_FILES = {
    ".env.example": "",
    "README.md": "# SafeForge Echo\n",
    "config.json": json.dumps(
        {
            "mcpServers": {
                "safeforge-echo": {
                    "command": "uv",
                    "args": ["--directory", ".", "run", "python", "server.py"],
                }
            }
        },
        indent=2,
    ),
    "fastmcp.json": "{}\n",
    "pyproject.toml": (
        '[project]\nname = "safeforge-echo"\nversion = "0.1.0"\ndependencies = ["fastmcp>=3.1.0"]\n'
    ),
    "server.py": "from fastmcp import FastMCP\nmcp = FastMCP('SafeForge Echo')\n",
    "test_server.py": "def test_placeholder():\n    assert True\n",
}


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return _digest_bytes(encoded)


def _media_type(path: str) -> str:
    if path.endswith(".json"):
        return "application/json"
    if path.endswith(".toml"):
        return "application/toml"
    if path.endswith(".md"):
        return "text/markdown"
    return "text/x-python" if path.endswith(".py") else "text/plain"


def _write_artifact_root(tmp_path: Path, *, server_id: str = "safeforge-echo") -> Path:
    root = tmp_path / "fixture"
    root.mkdir()
    files = dict(_FILES)
    if server_id != "safeforge-echo":
        config = json.loads(files["config.json"])
        config["mcpServers"] = {server_id: config["mcpServers"]["safeforge-echo"]}
        files["config.json"] = json.dumps(config, indent=2)
    for path, content in files.items():
        (root / path).write_text(content, encoding="utf-8")
    return root


def _receipt(root: Path) -> dict[str, object]:
    files = [
        {
            "path": path.name,
            "media_type": _media_type(path.name),
            "digest": _digest_bytes(path.read_bytes()),
        }
        for path in sorted(root.iterdir(), key=lambda item: item.name)
        if path.is_file()
    ]
    by_path = {item["path"]: item for item in files}
    return {
        "receipt_id": "safeforge-echo-v1",
        "receipt_version": "0.1.0",
        "created_at": _NOW.isoformat(),
        "producer": {
            "name": "mcpforge",
            "version": "0.3.4",
            "source": "io.github.saagpatel/mcpforge",
            "revision": "forge-test-revision",
            "dirty": False,
            "executable": "mcpforge",
        },
        "source": {
            "kind": "natural-language",
            "server_id": "safeforge-echo",
            "description_digest": _digest_bytes(b"safe echo fixture"),
            "transport": "stdio",
        },
        "generation": {
            "provider": "replay",
            "model": "safeforge-echo-v1",
            "no_execute": True,
            "plan_digest": _digest_bytes(b"plan"),
            "required_env_keys": [],
        },
        "artifact": {
            "tree_digest": _digest_json(files),
            "files": files,
            "dependency_manifest_digest": by_path["pyproject.toml"]["digest"],
            "lockfile_digest": None,
            "package_identities": ["fastmcp>=3.1.0"],
        },
        "toolbom": [
            {
                "tool_id": "safeforge-echo#echo",
                "name": "echo",
                "description_digest": _digest_bytes(b"echo description"),
                "input_schema_digest": _digest_bytes(b"input schema"),
                "output_schema_digest": _digest_bytes(b"output schema"),
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
        "limitations": ["Static generation evidence only."],
    }


async def _consume(receipt: dict[str, object], root: Path):
    return await consume_forge_receipt(
        receipt,
        root,
        run_id="safeforge-echo-consumer",
        created_at=_NOW,
        coordinator_revision="audit-test-revision",
        coordinator_dirty=False,
    )


async def test_valid_receipt_maps_to_partial_manifest_without_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom_connect(self: ServerConnector, config: object) -> object:
        raise AssertionError("connected scan attempted")

    async def _boom_open_process(*args: object, **kwargs: object) -> object:
        raise AssertionError("process spawn attempted")

    def _boom_popen(*args: object, **kwargs: object) -> object:
        raise AssertionError("subprocess spawn attempted")

    monkeypatch.setattr(ServerConnector, "connect", _boom_connect)
    monkeypatch.setattr(anyio, "open_process", _boom_open_process, raising=False)
    monkeypatch.setattr(subprocess, "Popen", _boom_popen)

    root = _write_artifact_root(tmp_path)
    result = await _consume(_receipt(root), root)

    assert result.accepted
    assert result.findings == []
    assert result.manifest is not None
    assert result.audit_report is not None
    assert [stage.stage_id for stage in result.manifest.stages] == [
        StageId.SOURCE_BIND,
        StageId.FORGE_PLAN,
        StageId.FORGE_GENERATE,
        StageId.VALIDATE_STATIC,
        StageId.CONTRACT_PREINSTALL,
        StageId.AUDIT_CONFIG,
    ]
    assert result.manifest.subject.mcp_protocol_supported == ["unknown"]
    assert result.audit_report.audits[0].connection_status == "skipped"
    assert result.audit_report.scan_timestamp == _NOW
    assert result.audit_report.hostname == "<canonical-host>"
    assert result.audit_report.os_platform == "canonical"
    assert result.audit_report.scan_duration_seconds == 0.0
    assert result.manifest.audit is not None
    assert result.manifest.audit.warning_codes == []


async def test_receipt_schema_failure_blocks_before_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("config audit must not run")

    monkeypatch.setattr("mcp_audit.safeforge_consumer.scan_config_only", _forbidden)
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["api_token"] = "not-accepted"
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-RECEIPT-SCHEMA"


async def test_static_failure_blocks_before_artifact_read(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["validation"]["security"] = "failed"  # type: ignore[index]
    receipt["validation"]["eligible_for_preinstall_audit"] = False  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-STATIC-NOT-PASSED"


async def test_unresolved_security_warning_is_not_preinstall_eligible(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["validation"]["security_warning_count"] = 1  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-RECEIPT-SCHEMA"


async def test_forged_observed_network_without_declaration_is_rejected(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["toolbom"][0]["observed_capabilities"] = ["network"]  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-RECEIPT-SCHEMA"


async def test_forged_observed_filesystem_without_permission_is_rejected(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["toolbom"][0]["observed_capabilities"] = ["filesystem"]  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-RECEIPT-SCHEMA"


async def test_unexpected_file_blocks_before_config_audit(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    (root / ".env").write_text("SYNTHETIC_TEST_VALUE=do-not-read", encoding="utf-8")
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-ARTIFACT-SET"


async def test_changed_file_digest_blocks(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    (root / "server.py").write_text("tampered", encoding="utf-8")
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-ARTIFACT-DIGEST"


async def test_tree_digest_mismatch_blocks(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["artifact"]["tree_digest"] = "sha256:" + "0" * 64  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-TREE-DIGEST"


async def test_dependency_binding_mismatch_blocks(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    receipt = _receipt(root)
    receipt["artifact"]["dependency_manifest_digest"] = "sha256:" + "0" * 64  # type: ignore[index]
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-DEPENDENCY-BINDING"


async def test_config_server_identity_mismatch_blocks(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path, server_id="other-server")
    receipt = _receipt(root)
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-CONFIG-SERVER"


async def test_config_environment_keys_must_match_receipt(tmp_path: Path) -> None:
    root = _write_artifact_root(tmp_path)
    config = json.loads((root / "config.json").read_text())
    config["mcpServers"]["safeforge-echo"]["env"] = {"UNDECLARED_KEY": "synthetic"}
    (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
    receipt = _receipt(root)
    result = await _consume(receipt, root)
    assert not result.accepted
    assert result.findings[0].code == "SF-FORGE-CONFIG-ENV"
