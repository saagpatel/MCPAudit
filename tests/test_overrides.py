"""Tests for OverrideApplier and load_override_config."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding
from mcp_audit.overrides import (
    OverrideApplier,
    OverrideConfig,
    PermissionOverride,
    ServerToolOverride,
    load_override_config,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "override_config.yaml"


def _finding(
    category: PermissionCategory,
    tool: str = "tool1",
    confidence: Confidence = Confidence.HIGH,
) -> PermissionFinding:
    return PermissionFinding(
        category=category,
        confidence=confidence,
        evidence=["test"],
        tool_name=tool,
    )


def _applier(*overrides: ServerToolOverride) -> OverrideApplier:
    return OverrideApplier(OverrideConfig(overrides=list(overrides)))


def _override(
    server: str,
    tool: str,
    notes: str | None = None,
    **kwargs: bool | None,
) -> ServerToolOverride:
    return ServerToolOverride(
        server=server,
        tool=tool,
        permissions=PermissionOverride(**kwargs),
        notes=notes,
    )


class TestLoadOverrideConfig:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        cfg = load_override_config(tmp_path / "nonexistent.yaml")
        assert cfg.overrides == []

    def test_loads_fixture_yaml(self) -> None:
        cfg = load_override_config(FIXTURE_PATH)
        assert len(cfg.overrides) == 3

    def test_fixture_first_override_server(self) -> None:
        cfg = load_override_config(FIXTURE_PATH)
        assert cfg.overrides[0].server == "test-server"
        assert cfg.overrides[0].tool == "read_file"

    def test_fixture_notes_loaded(self) -> None:
        cfg = load_override_config(FIXTURE_PATH)
        assert cfg.overrides[0].notes == "Manually verified read-only"


class TestOverrideApplierRemove:
    def test_false_removes_matching_finding(self) -> None:
        findings = [_finding(PermissionCategory.FILE_WRITE, tool="write_tool")]
        applier = _applier(_override("srv", "write_tool", file_write=False))
        result = applier.apply("srv", findings)
        assert not any(f.category == PermissionCategory.FILE_WRITE for f in result)

    def test_false_does_not_affect_other_categories(self) -> None:
        findings = [
            _finding(PermissionCategory.FILE_WRITE, tool="tool1"),
            _finding(PermissionCategory.NETWORK, tool="tool1"),
        ]
        applier = _applier(_override("srv", "tool1", file_write=False))
        result = applier.apply("srv", findings)
        cats = {f.category for f in result}
        assert PermissionCategory.FILE_WRITE not in cats
        assert PermissionCategory.NETWORK in cats

    def test_false_does_not_affect_other_tools(self) -> None:
        findings = [
            _finding(PermissionCategory.FILE_WRITE, tool="tool_a"),
            _finding(PermissionCategory.FILE_WRITE, tool="tool_b"),
        ]
        applier = _applier(_override("srv", "tool_a", file_write=False))
        result = applier.apply("srv", findings)
        remaining = [f for f in result if f.category == PermissionCategory.FILE_WRITE]
        assert len(remaining) == 1
        assert remaining[0].tool_name == "tool_b"

    def test_false_for_nonexistent_category_is_noop(self) -> None:
        findings = [_finding(PermissionCategory.NETWORK, tool="tool1")]
        applier = _applier(_override("srv", "tool1", shell_execution=False))
        result = applier.apply("srv", findings)
        assert result == findings

    def test_wildcard_tool_removes_from_all_tools(self) -> None:
        findings = [
            _finding(PermissionCategory.DESTRUCTIVE, tool="tool_a"),
            _finding(PermissionCategory.DESTRUCTIVE, tool="tool_b"),
        ]
        applier = _applier(_override("srv", "*", destructive=False))
        result = applier.apply("srv", findings)
        assert not any(f.category == PermissionCategory.DESTRUCTIVE for f in result)


class TestOverrideApplierAdd:
    def test_true_adds_manual_finding_when_absent(self) -> None:
        applier = _applier(_override("srv", "tool1", file_read=True))
        result = applier.apply("srv", [])
        # tool "*" expands to {"*"} when findings is empty; let's use non-empty
        findings = [_finding(PermissionCategory.NETWORK, tool="tool1")]
        result = applier.apply("srv", findings)
        added = [f for f in result if f.category == PermissionCategory.FILE_READ]
        assert len(added) == 1
        assert added[0].confidence == Confidence.MANUAL
        assert added[0].tool_name == "tool1"

    def test_true_does_not_duplicate_existing_finding(self) -> None:
        findings = [_finding(PermissionCategory.FILE_READ, tool="tool1")]
        applier = _applier(_override("srv", "tool1", file_read=True))
        result = applier.apply("srv", findings)
        file_reads = [f for f in result if f.category == PermissionCategory.FILE_READ]
        assert len(file_reads) == 1

    def test_notes_appear_in_evidence(self) -> None:
        findings = [_finding(PermissionCategory.NETWORK, tool="tool1")]
        applier = _applier(_override("srv", "tool1", notes="verified safe", file_read=True))
        result = applier.apply("srv", findings)
        added = next(f for f in result if f.category == PermissionCategory.FILE_READ)
        assert "verified safe" in added.evidence[0]

    def test_default_evidence_when_no_notes(self) -> None:
        findings = [_finding(PermissionCategory.NETWORK, tool="tool1")]
        applier = _applier(_override("srv", "tool1", file_read=True))
        result = applier.apply("srv", findings)
        added = next(f for f in result if f.category == PermissionCategory.FILE_READ)
        assert "manual" in added.evidence[0]

    def test_wildcard_tool_adds_to_all_existing_tools(self) -> None:
        findings = [
            _finding(PermissionCategory.NETWORK, tool="tool_a"),
            _finding(PermissionCategory.NETWORK, tool="tool_b"),
        ]
        applier = _applier(_override("srv", "*", file_read=True))
        result = applier.apply("srv", findings)
        added = [f for f in result if f.category == PermissionCategory.FILE_READ]
        tool_names = {f.tool_name for f in added}
        assert tool_names == {"tool_a", "tool_b"}


class TestOverrideApplierServerMatching:
    def test_server_star_wildcard_applies_to_any_server(self) -> None:
        findings = [_finding(PermissionCategory.DESTRUCTIVE, tool="tool1")]
        applier = _applier(_override("*", "tool1", destructive=False))
        result = applier.apply("any-server-name", findings)
        assert not any(f.category == PermissionCategory.DESTRUCTIVE for f in result)

    def test_server_specific_does_not_apply_to_other_server(self) -> None:
        findings = [_finding(PermissionCategory.DESTRUCTIVE, tool="tool1")]
        applier = _applier(_override("other-server", "tool1", destructive=False))
        result = applier.apply("my-server", findings)
        assert len(result) == 1

    def test_empty_override_config_returns_unchanged(self) -> None:
        findings = [_finding(PermissionCategory.SHELL_EXEC, tool="tool1")]
        applier = OverrideApplier(OverrideConfig())
        result = applier.apply("srv", findings)
        assert result == findings
