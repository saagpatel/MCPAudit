"""Tests for PinStore — SHA256 hashing and drift detection."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import yaml

from mcp_audit.models import DriftStatus
from mcp_audit.pinning import PinStore
from tests.conftest import make_tool


def _store(tmp_path: Path) -> PinStore:
    return PinStore(path=tmp_path / "pins.yaml")


class TestComputeHash:
    def test_deterministic_for_same_tool(self) -> None:
        store = PinStore.__new__(PinStore)
        store._path = Path("/dev/null")  # type: ignore[attr-defined]
        store._data = {}  # type: ignore[attr-defined]
        tool = make_tool("read_file", description="Read a file", input_schema={"type": "object"})
        assert store.compute_hash(tool) == store.compute_hash(tool)

    def test_differs_for_changed_description(self) -> None:
        store = PinStore.__new__(PinStore)
        store._path = Path("/dev/null")  # type: ignore[attr-defined]
        store._data = {}  # type: ignore[attr-defined]
        t1 = make_tool("read_file", description="Read a file")
        t2 = make_tool("read_file", description="Read a different file")
        assert store.compute_hash(t1) != store.compute_hash(t2)

    def test_differs_for_changed_schema(self) -> None:
        store = PinStore.__new__(PinStore)
        store._path = Path("/dev/null")  # type: ignore[attr-defined]
        store._data = {}  # type: ignore[attr-defined]
        t1 = make_tool("t", input_schema={"type": "object", "properties": {"path": {"type": "string"}}})
        t2 = make_tool("t", input_schema={"type": "object", "properties": {"url": {"type": "string"}}})
        assert store.compute_hash(t1) != store.compute_hash(t2)

    def test_hash_format_is_sha256_prefix(self) -> None:
        store = PinStore.__new__(PinStore)
        store._path = Path("/dev/null")  # type: ignore[attr-defined]
        store._data = {}  # type: ignore[attr-defined]
        h = store.compute_hash(make_tool("t"))
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64


class TestPinServer:
    def test_creates_file_when_not_exists(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        pin_file = tmp_path / "pins.yaml"
        assert not pin_file.exists()
        store.pin_server("my-server", [make_tool("read_file")])
        assert pin_file.exists()

    def test_upserts_existing_entries(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("tool_a", description="v1")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        store2.pin_server("srv", [make_tool("tool_a", description="v2")])
        raw = yaml.safe_load((tmp_path / "pins.yaml").read_text())
        # Still only one entry for tool_a
        assert len(raw["servers"]["srv"]["tools"]) == 1

    def test_multiple_servers_stored_independently(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("server-a", [make_tool("tool1")])
        store.pin_server("server-b", [make_tool("tool2")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        assert store2.tool_count("server-a") == 1
        assert store2.tool_count("server-b") == 1


class TestCheckDrift:
    def test_returns_empty_for_matching_hashes(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        tool = make_tool("read_file", description="Read a file")
        store.pin_server("srv", [tool])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift("srv", [tool])
        assert findings == []

    def test_returns_changed_for_hash_mismatch(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("read_file", description="v1")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift("srv", [make_tool("read_file", description="v2")])
        assert len(findings) == 1
        assert findings[0].status == DriftStatus.CHANGED
        assert findings[0].tool_name == "read_file"
        assert findings[0].summary
        assert "description changed" in findings[0].details
        assert "Review" in findings[0].remediation

    def test_returns_new_for_tool_not_in_pins(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("existing_tool")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift("srv", [make_tool("existing_tool"), make_tool("new_tool")])
        new_findings = [f for f in findings if f.status == DriftStatus.NEW]
        assert len(new_findings) == 1
        assert new_findings[0].tool_name == "new_tool"
        assert "not previously pinned" in new_findings[0].details
        assert "mcp-audit pin" in new_findings[0].remediation

    def test_returns_removed_for_missing_tool(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("tool_a"), make_tool("tool_b")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift("srv", [make_tool("tool_a")])  # tool_b removed
        removed = [f for f in findings if f.status == DriftStatus.REMOVED]
        assert len(removed) == 1
        assert removed[0].tool_name == "tool_b"
        assert removed[0].summary
        assert "tool missing from current scan" in removed[0].details
        assert "refresh" in removed[0].remediation

    def test_changed_finding_identifies_input_schema_changes(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server(
            "srv",
            [
                make_tool(
                    "read_file", input_schema={"type": "object", "properties": {"path": {"type": "string"}}}
                )
            ],
        )
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift(
            "srv",
            [
                make_tool(
                    "read_file", input_schema={"type": "object", "properties": {"url": {"type": "string"}}}
                )
            ],
        )
        assert len(findings) == 1
        assert "input schema changed" in findings[0].details

    def test_changed_finding_handles_legacy_pins_without_snapshot(self, tmp_path: Path) -> None:
        pin_file = tmp_path / "pins.yaml"
        pin_file.write_text(
            """
servers:
  srv:
    tools:
      read_file:
        hash: sha256:old
        pinned_at: '2026-01-01T00:00:00+00:00'
"""
        )
        store = PinStore(path=pin_file)
        findings = store.check_drift("srv", [make_tool("read_file", description="v2")])
        assert len(findings) == 1
        assert findings[0].details == ["pin hash changed; previous schema snapshot unavailable"]

    def test_missing_pin_file_returns_all_new(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        tools = [make_tool("t1"), make_tool("t2")]
        findings = store.check_drift("srv", tools)
        assert all(f.status == DriftStatus.NEW for f in findings)
        assert len(findings) == 2


class TestRemoveServer:
    def test_removes_entries_without_affecting_others(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("server-a", [make_tool("tool1")])
        store.pin_server("server-b", [make_tool("tool2")])
        store.remove_server("server-a")
        store2 = PinStore(path=tmp_path / "pins.yaml")
        assert store2.tool_count("server-a") == 0
        assert store2.tool_count("server-b") == 1

    def test_remove_nonexistent_server_is_noop(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("server-a", [make_tool("tool1")])
        store.remove_server("nonexistent")  # should not raise
        store2 = PinStore(path=tmp_path / "pins.yaml")
        assert store2.tool_count("server-a") == 1


class TestAtomicWrite:
    def test_no_partial_writes(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("tool")])
        pin_file = tmp_path / "pins.yaml"
        # Verify no .tmp file left behind
        tmp_file = pin_file.with_suffix(".yaml.tmp")
        assert not tmp_file.exists()
        # Verify written file is valid YAML
        raw = yaml.safe_load(pin_file.read_text())
        assert "servers" in raw
        assert raw["servers"]["srv"]["tools"]["tool"]["snapshot"] == {
            "description": None,
            "input_schema": None,
        }

    def test_changed_finding_includes_pinned_at(self, tmp_path: Path) -> None:
        before = datetime.now(UTC)
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("t", description="v1")])
        store2 = PinStore(path=tmp_path / "pins.yaml")
        findings = store2.check_drift("srv", [make_tool("t", description="v2")])
        assert len(findings) == 1
        assert findings[0].pinned_at is not None
        assert findings[0].pinned_at >= before
