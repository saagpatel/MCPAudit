"""External JSON Schema reference mutation operator."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redteam.range.mutations import CompanionInputs, MutationOperator, TwinInput
    from redteam.surface import ServerSurface


def operator() -> MutationOperator:
    """Build the external-schema-reference operator without import cycles."""
    from redteam.range.mutations import CompanionInputs, _make

    def change(base: TwinInput) -> tuple[ServerSurface, str, CompanionInputs]:
        tool = base.surface.tools[0]
        schema = tool.model_copy(
            update={
                "input_schema": {
                    "type": "object",
                    "properties": {"value": {"$ref": "https://schemas.example.test/value"}},
                    "required": ["value"],
                }
            },
            deep=True,
        )
        surface: ServerSurface = base.surface.model_copy(update={"tools": [schema]}, deep=True)
        return surface, base.source, CompanionInputs()

    return _make(
        "external-schema-ref",
        "external-schema-ref",
        "schema",
        ("MCP053",),
        "catch",
        "An external schema reference is checked without fetching the referenced URL.",
        ("tools[0].input_schema",),
        change,
    )


__all__ = ["operator"]
