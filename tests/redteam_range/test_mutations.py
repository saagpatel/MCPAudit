"""Mutation operator contracts over the inert shared base fixture."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam.range.harness import run_detectors
from redteam.range.mutations import OPERATORS, MutationOperator, TwinInput
from redteam.surface import ServerSurface, extract_from_source

ROOT = Path(__file__).parents[2]
BASE = ROOT / "redteam/fixtures/servers/base"
BASE_SURFACE = ServerSurface.load(BASE / "surface.json")
BASE_SOURCE = (BASE / "server.py.txt").read_text(encoding="utf-8")

CATEGORIES = {
    "hidden-instruction",
    "invisible-unicode",
    "shadowed-name",
    "concealed-exfiltration",
    "ssrf",
    "egress",
    "lethal-trifecta",
    "surface-drift",
    "capability-escalation",
    "provenance-drift",
    "integrity-drift",
    "annotation-contradiction",
    "external-schema-ref",
}


def _flatten(value: object, prefix: str = "") -> dict[str, object]:
    """Flatten JSON-like values to stable dotted/indexed paths."""
    if isinstance(value, dict):
        flattened: dict[str, object] = {}
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            flattened.update(_flatten(child, path))
        return flattened
    if isinstance(value, list):
        flattened = {}
        for index, child in enumerate(value):
            flattened.update(_flatten(child, f"{prefix}[{index}]"))
        return flattened
    return {prefix: value}


def _changed_paths(before: object, after: object) -> set[str]:
    left = _flatten(before)
    right = _flatten(after)
    return {path for path in left.keys() | right.keys() if left.get(path) != right.get(path)}


def test_operator_registry_is_unique_and_uses_fixed_categories() -> None:
    assert len(OPERATORS) == 31
    ids = [operator.id for operator in OPERATORS]
    assert len(ids) == len(set(ids))
    assert {operator.category for operator in OPERATORS} == CATEGORIES


def test_external_schema_ref_operator_targets_mcp053() -> None:
    operator = next(operator for operator in OPERATORS if operator.id == "external-schema-ref")
    twin = operator.apply(TwinInput(surface=BASE_SURFACE, source=BASE_SOURCE))

    schema = twin.surface.tools[0].input_schema
    properties = schema.get("properties")
    assert isinstance(properties, dict)
    value = properties.get("value")
    assert isinstance(value, dict)
    assert value.get("$ref") == "https://schemas.example.test/value"
    result = run_detectors(twin.surface, baseline=None, fleet=[])
    assert "MCP053" in {finding.check_id for finding in result.findings}


@pytest.mark.parametrize("operator", OPERATORS, ids=lambda operator: operator.id)
def test_operator_changes_only_declared_paths(operator: MutationOperator, tmp_path: Path) -> None:
    twin = operator.apply(TwinInput(surface=BASE_SURFACE, source=BASE_SOURCE))

    assert twin.operator_id == operator.id
    assert twin.twin_id == operator.id
    assert twin.category == operator.category
    assert len(twin.mutation_record) == 1
    record = twin.mutation_record[0]
    assert record["operator_id"] == operator.id
    raw_paths = record["field_paths_changed"]
    assert isinstance(raw_paths, list)
    declared = {path for path in raw_paths if isinstance(path, str)}
    assert len(declared) == len(raw_paths)
    assert declared

    before = BASE_SURFACE.model_dump(mode="json")
    after = twin.surface.model_dump(mode="json")
    changed = _changed_paths(before, after)
    if BASE_SOURCE != twin.source:
        changed.add("source")

    companion_paths = {path for path in declared if path.startswith("companions.")}
    surface_paths = declared - companion_paths
    # Collapse changed leaves under the declared path (e.g. config.args[0]
    # under config.args), then require an exact one-to-one path set.
    matched: set[str] = set()
    for path in changed:
        candidates = {
            allowed
            for allowed in surface_paths
            if path == allowed or path.startswith(f"{allowed}.") or path.startswith(f"{allowed}[")
        }
        assert len(candidates) == 1, f"undeclared or ambiguous structural change: {path}"
        matched.update(candidates)
    assert matched == surface_paths, f"declared paths without changes: {sorted(surface_paths - matched)}"

    assert twin.companions is not None
    companion_presence = {
        "companions.baseline": twin.companions.baseline is not None,
        "companions.fleet": bool(twin.companions.fleet),
        "companions.integrity": twin.companions.integrity is not None,
    }
    assert companion_paths == {path for path, present in companion_presence.items() if present}
    assert operator.expected_ids
    assert operator.predicted in {"catch", "miss"}
    assert operator.rationale

    source_path = tmp_path / "server.py.txt"
    source_path.write_text(twin.source, encoding="utf-8")
    extracted = extract_from_source(source_path)
    if operator.id != "exfil-handler-only":
        assert isinstance(extracted, ServerSurface)
    if isinstance(extracted, ServerSurface):
        # The restricted extractor can represent tool names and descriptions.
        # Schema property descriptions, config launch overrides, and annotations
        # are not all represented by the base AST grammar.
        if not any("input_schema" in path or path.startswith("config.") for path in declared):
            assert [tool.name for tool in extracted.tools] == [tool.name for tool in twin.surface.tools]
            assert [tool.description for tool in extracted.tools] == [
                tool.description for tool in twin.surface.tools
            ]
        assert [tool.annotations for tool in extracted.tools] == [
            tool.annotations for tool in twin.surface.tools
        ]
        if operator.id not in {"hidden-param", "external-schema-ref"}:
            assert [tool.input_schema for tool in extracted.tools] == [
                tool.input_schema for tool in twin.surface.tools
            ]
