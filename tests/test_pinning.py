"""Tests for PinStore — SHA256 hashing and drift detection."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from mcp_audit.models import ClientType, DriftStatus, ServerConfig, TransportType
from mcp_audit.pinning import _MAX_PIN_FILE_BYTES, PinStore
from tests.conftest import make_tool


def _store(tmp_path: Path) -> PinStore:
    return PinStore(path=tmp_path / "pins.yaml")


def _hash_store() -> PinStore:
    store = PinStore.__new__(PinStore)
    store._path = Path("/dev/null")
    store._data = {}
    return store


class TestComputeHash:
    def test_deterministic_for_same_tool(self) -> None:
        store = _hash_store()
        tool = make_tool("read_file", description="Read a file", input_schema={"type": "object"})
        assert store.compute_hash(tool) == store.compute_hash(tool)

    def test_differs_for_changed_description(self) -> None:
        store = _hash_store()
        t1 = make_tool("read_file", description="Read a file")
        t2 = make_tool("read_file", description="Read a different file")
        assert store.compute_hash(t1) != store.compute_hash(t2)

    def test_differs_for_changed_schema(self) -> None:
        store = _hash_store()
        t1 = make_tool("t", input_schema={"type": "object", "properties": {"path": {"type": "string"}}})
        t2 = make_tool("t", input_schema={"type": "object", "properties": {"url": {"type": "string"}}})
        assert store.compute_hash(t1) != store.compute_hash(t2)

    def test_hash_format_is_sha256_prefix(self) -> None:
        store = _hash_store()
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


class TestStatus:
    def test_status_summarizes_servers_and_pin_age(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        before = datetime.now(UTC)
        store.pin_server("server-b", [make_tool("tool2")])
        store.pin_server("server-a", [make_tool("tool1"), make_tool("tool3")])

        statuses = PinStore(path=tmp_path / "pins.yaml").status()

        assert [status.server_name for status in statuses] == ["server-a", "server-b"]
        assert [status.tool_count for status in statuses] == [2, 1]
        assert statuses[0].oldest_pinned_at is not None
        assert statuses[0].newest_pinned_at is not None
        assert statuses[0].oldest_pinned_at >= before

    def test_status_handles_legacy_entries_without_pinned_at(self, tmp_path: Path) -> None:
        pin_file = tmp_path / "pins.yaml"
        pin_file.write_text(
            """
servers:
  srv:
    tools:
      read_file:
        hash: sha256:old
"""
        )

        statuses = PinStore(path=pin_file).status()

        assert len(statuses) == 1
        assert statuses[0].server_name == "srv"
        assert statuses[0].tool_count == 1
        assert statuses[0].oldest_pinned_at is None
        assert statuses[0].newest_pinned_at is None

    def test_stale_baselines_reports_pins_missing_from_discovered_configs(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("configured", [make_tool("read_file")])
        store.pin_server("removed", [make_tool("write_file"), make_tool("delete_file")])

        stale = PinStore(path=tmp_path / "pins.yaml").stale_baselines({"configured"})

        assert [status.server_name for status in stale] == ["removed"]
        assert stale[0].tool_count == 2
        assert "pin --clear" in stale[0].remediation

    def test_stale_baselines_empty_when_all_pinned_servers_are_discovered(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("configured", [make_tool("read_file")])

        stale = PinStore(path=tmp_path / "pins.yaml").stale_baselines({"configured"})

        assert stale == []


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

    def test_renamed_tool_reports_removed_and_new(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("read_file")])
        store2 = PinStore(path=tmp_path / "pins.yaml")

        findings = store2.check_drift("srv", [make_tool("read_file_v2")])

        statuses = {(finding.tool_name, finding.status) for finding in findings}
        assert statuses == {
            ("read_file", DriftStatus.REMOVED),
            ("read_file_v2", DriftStatus.NEW),
        }

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


def _config(**kw: object) -> ServerConfig:
    base: dict[str, object] = dict(
        name="srv",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )
    base.update(kw)
    return ServerConfig(**base)  # type: ignore[arg-type]


class TestConfigSnapshot:
    def test_pin_server_stores_config_snapshot_when_given(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        cfg = _config(command="npx", args=["pkg@1.2.3"], env_keys=["API_KEY"])
        store.pin_server("srv", [make_tool("t")], cfg)
        snap = store.baseline_config("srv")
        assert snap is not None
        assert snap["command"] == "npx"
        assert snap["args"] == ["pkg@1.2.3"]
        assert snap["transport"] == "stdio"
        assert snap["env_keys"] == ["API_KEY"]

    def test_baseline_config_none_when_no_snapshot(self, tmp_path: Path) -> None:
        # Pinned without a server_config (older-style / tools-only pin) → no snapshot.
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("t")])
        assert store.baseline_config("srv") is None

    def test_package_hashes_captured_and_accessible(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        cfg = _config(command="npx", args=["pkg@1.2.3"])
        store.pin_server("srv", [make_tool("t")], cfg, {"npm:pkg:1.2.3": "sha512-X"})
        assert store.baseline_package_hashes("srv") == {"npm:pkg:1.2.3": "sha512-X"}

    def test_refresh_without_package_hashes_preserves_existing(self, tmp_path: Path) -> None:
        # A schema-only re-pin (no package_hashes) must NOT wipe a previously
        # captured registry baseline.
        store = _store(tmp_path)
        cfg = _config(command="npx", args=["pkg@1.2.3"])
        store.pin_server("srv", [make_tool("t")], cfg, {"npm:pkg:1.2.3": "sha512-X"})
        store.pin_server("srv", [make_tool("t", description="v2")], cfg)  # refresh, no pkg hashes
        assert store.baseline_package_hashes("srv") == {"npm:pkg:1.2.3": "sha512-X"}

    def test_baseline_package_hashes_none_without_capture(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("t")], _config(command="npx", args=["pkg@1.2.3"]))
        assert store.baseline_package_hashes("srv") is None

    def test_baseline_config_none_for_unknown_server(self, tmp_path: Path) -> None:
        assert _store(tmp_path).baseline_config("nope") is None

    def test_config_snapshot_persists_across_reload(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("t")], _config(command="uvx", args=["x"]))
        reloaded = PinStore(path=tmp_path / "pins.yaml")
        snap = reloaded.baseline_config("srv")
        assert snap is not None
        assert snap["command"] == "uvx"

    def test_config_snapshot_records_header_key_names_only(self, tmp_path: Path) -> None:
        store = _store(tmp_path)
        cfg = _config(transport=TransportType.HTTP, url="https://x", headers_keys=["Authorization"])
        store.pin_server("srv", [make_tool("t")], cfg)
        snap = store.baseline_config("srv")
        assert snap is not None
        assert snap["headers_keys"] == ["Authorization"]
        assert snap["url"] == "https://x"


class TestArtifactHashNamespaces:
    """Regression: MCP026 registry byte-hashes must not collide with the MCP024
    on-disk launch-artifact baseline, which already owns the 'artifact_hashes' key."""

    def test_registry_hashes_do_not_clobber_launch_integrity_baseline(self, tmp_path: Path) -> None:
        # A local script arg makes _config_snapshot populate the MCP024 baseline
        # ('artifact_hashes', keyed by filesystem path).
        script = tmp_path / "server.py"
        script.write_text("print('hi')\n")
        cfg = _config(command="uvx", args=[str(script)])
        store = _store(tmp_path)

        store.pin_server(
            "srv",
            [make_tool("t")],
            cfg,
            artifact_hashes={"pypi:thing:1.0.0": "deadbeef"},
        )

        # MCP024 launch-artifact baseline is intact and still keyed by path.
        launch = store.baseline_artifacts("srv")
        assert launch is not None
        assert str(script.resolve()) in launch
        assert "pypi:thing:1.0.0" not in launch

        # MCP026 registry byte-hashes live in their own namespace, keyed by ref.
        registry = store.baseline_artifact_hashes("srv")
        assert registry == {"pypi:thing:1.0.0": "deadbeef"}

    def test_registry_hashes_preserved_on_schema_only_refresh(self, tmp_path: Path) -> None:
        cfg = _config(command="uvx", args=["x"])
        store = _store(tmp_path)
        store.pin_server("srv", [make_tool("t")], cfg, artifact_hashes={"pypi:x:2.0.0": "abc"})
        # A later schema-only refresh (no artifact_hashes) must not wipe the baseline.
        store.pin_server("srv", [make_tool("t")], cfg)
        assert store.baseline_artifact_hashes("srv") == {"pypi:x:2.0.0": "abc"}


def test_check_drift_tolerates_malformed_pinned_at(tmp_path: Path) -> None:
    """A hand-edited or corrupt pinned_at must not crash drift checking."""
    path = tmp_path / "pins.yaml"
    store = PinStore(path=path)
    store.pin_server("srv", [make_tool("t", description="original")])

    data = yaml.safe_load(path.read_text())
    data["servers"]["srv"]["tools"]["t"]["pinned_at"] = "not-a-timestamp"
    path.write_text(yaml.safe_dump(data))

    reloaded = PinStore(path=path)

    changed = reloaded.check_drift("srv", [make_tool("t", description="changed")])
    assert [finding.status for finding in changed] == [DriftStatus.CHANGED]
    assert changed[0].pinned_at is None

    removed = reloaded.check_drift("srv", [])
    assert [finding.status for finding in removed] == [DriftStatus.REMOVED]
    assert removed[0].pinned_at is None


class TestConcurrentSafety:
    def test_second_store_mutation_preserves_first_stores_writes(self, tmp_path: Path) -> None:
        # Classic lost update: both stores load before either writes. Without
        # re-read-under-lock, beta's write erases alpha's pins entirely.
        path = tmp_path / "pins.yaml"
        store_a = PinStore(path=path)
        store_b = PinStore(path=path)
        store_a.pin_server("alpha", [make_tool("t1")])
        store_b.pin_server("beta", [make_tool("t2")])
        assert set(PinStore(path=path).pinned_servers()) == {"alpha", "beta"}

    def test_remove_server_preserves_concurrent_writes(self, tmp_path: Path) -> None:
        path = tmp_path / "pins.yaml"
        store_a = PinStore(path=path)
        store_a.pin_server("alpha", [make_tool("t1")])
        store_b = PinStore(path=path)
        store_a.pin_server("gamma", [make_tool("t3")])
        store_b.remove_server("alpha")
        assert set(PinStore(path=path).pinned_servers()) == {"gamma"}


class TestHostileFileBounds:
    def test_oversized_pin_file_treated_as_empty(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        path = tmp_path / "pins.yaml"
        path.write_text("x" * (_MAX_PIN_FILE_BYTES + 1))
        with caplog.at_level(logging.WARNING):
            store = PinStore(path=path)
        assert store.pinned_servers() == []
        assert "pin file" in caplog.text

    def test_alias_expansion_rejected(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        # Billion-laughs shape: anchors referenced by aliases must not expand.
        bomb = 'a: &a ["x", "x"]\nb: &b [*a, *a]\nc: [*b, *b]\n'
        path = tmp_path / "pins.yaml"
        path.write_text(bomb)
        with caplog.at_level(logging.WARNING):
            store = PinStore(path=path)
        assert store.pinned_servers() == []

    def test_written_file_never_contains_anchors(self, tmp_path: Path) -> None:
        # A shared object reference must not serialize as a YAML anchor, or our
        # own writes would be rejected by the alias-free loader on next read.
        path = tmp_path / "pins.yaml"
        store = PinStore(path=path)
        shared = {"k": "sha256:aa"}
        store._data = {"servers": {"one": {"pkg": shared}, "two": {"pkg": shared}}}
        store._write()
        text = path.read_text()
        assert "&id" not in text and "*id" not in text
        assert set(PinStore(path=path).pinned_servers()) == {"one", "two"}
