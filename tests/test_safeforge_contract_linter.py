"""Contract compatibility tests for the ForgeReceiptV0 handoff."""

from __future__ import annotations

from copy import deepcopy

from mcp_audit.safeforge_consumer import ForgeReceiptV0Input
from mcp_audit.safeforge_contract_linter import ContractChange, lint_forge_receipt_schema


def _schema() -> dict[str, object]:
    return ForgeReceiptV0Input.model_json_schema()


def test_exact_semantic_schema_is_compatible() -> None:
    result = lint_forge_receipt_schema(_schema())
    assert result.compatible
    assert result.issues == []
    assert result.producer_schema_digest == result.consumer_schema_digest


def test_annotation_only_changes_remain_compatible() -> None:
    schema = deepcopy(_schema())
    schema["title"] = "Renamed producer model"
    schema["description"] = "Documentation does not alter accepted instances."
    result = lint_forge_receipt_schema(schema)
    assert result.compatible


def test_required_field_order_is_not_semantic_drift() -> None:
    schema = deepcopy(_schema())
    schema["required"] = list(reversed(schema["required"]))  # type: ignore[arg-type]
    result = lint_forge_receipt_schema(schema)
    assert result.compatible


def test_new_optional_field_is_additive_but_blocked_by_strict_v0_consumer() -> None:
    schema = deepcopy(_schema())
    schema["properties"]["producer_note"] = {"type": "string"}  # type: ignore[index]
    result = lint_forge_receipt_schema(schema)
    assert not result.compatible
    assert result.issues[0].change is ContractChange.ADDITIVE
    assert result.issues[0].path == "$/properties/producer_note"


def test_required_field_or_version_change_is_breaking() -> None:
    schema = deepcopy(_schema())
    schema["required"] = [name for name in schema["required"] if name != "artifact"]  # type: ignore[index]
    result = lint_forge_receipt_schema(schema)
    assert not result.compatible
    assert any(issue.change is ContractChange.BREAKING for issue in result.issues)


def test_consumer_only_constraint_is_breaking() -> None:
    schema = deepcopy(_schema())
    producer = schema["$defs"]["ForgeProducerInput"]  # type: ignore[index]
    producer["properties"]["version"].pop("minLength", None)  # type: ignore[index]
    producer["properties"]["version"]["maxLength"] = 20  # type: ignore[index]
    result = lint_forge_receipt_schema(schema)
    assert not result.compatible
    assert any(issue.path.endswith("/maxLength") for issue in result.issues)


def test_external_or_missing_reference_returns_structured_incompatibility() -> None:
    for schema in (
        {"$ref": "https://example.invalid/schema.json"},
        {"$ref": "#/$defs/missing", "$defs": {}},
    ):
        result = lint_forge_receipt_schema(schema)
        assert not result.compatible
        assert result.issues[0].change is ContractChange.BREAKING
        assert "cannot be normalized safely" in result.issues[0].message


def test_cyclic_reference_returns_structured_incompatibility() -> None:
    schema = {"$ref": "#/$defs/A", "$defs": {"A": {"$ref": "#/$defs/A"}}}
    result = lint_forge_receipt_schema(schema)
    assert not result.compatible
    assert "cyclic schema reference" in result.issues[0].message
