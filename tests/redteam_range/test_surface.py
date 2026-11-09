"""Inert surface round-trip, wire mapping and conservative AST boundaries."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from redteam.catalog import load_catalog
from redteam.range.base.build import ALLOWLIST, FIXTURE, fixture_hashes, fixture_name
from redteam.surface import ServerSurface, Unknown, extract_from_source


def test_base_manifest_hashes() -> None:
    manifest = json.loads((FIXTURE / "MANIFEST.json").read_text())
    assert manifest["files"] == fixture_hashes(FIXTURE)
    assert list(manifest["files"]) == sorted(manifest["files"])
    assert manifest["mcpforge_version"]
    assert manifest["init_command"] == [
        "mcpforge",
        "init",
        "range-base",
        "--transport",
        "stdio",
        "-o",
        "<fresh-tmp-dir>",
    ]
    assert {path.name for path in FIXTURE.iterdir()} == {
        *(fixture_name(name) for name in ALLOWLIST),
        "MANIFEST.json",
        "surface.json",
    }


def test_base_ast_equals_committed_surface() -> None:
    expected = ServerSurface.load(FIXTURE / "surface.json")
    assert extract_from_source(FIXTURE / "server.py.txt") == expected
    assert expected.source == "ast"
    assert expected.server_name == "range-base"
    assert [tool.name for tool in expected.tools] == ["echo"]


def test_round_trip_and_wire_converters() -> None:
    surface = ServerSurface.model_validate(
        {
            "server_name": "synthetic",
            "source": "fixture",
            "config": {"command": "python", "args": ["server.py"], "env_keys": ["TOKEN_NAME"]},
            "tools": [
                {
                    "name": "echo",
                    "description": "Echo text",
                    "title": "Echo",
                    "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
                    "annotations": {
                        "title": "Hint title",
                        "readOnlyHint": True,
                        "destructiveHint": False,
                        "idempotentHint": True,
                        "openWorldHint": False,
                    },
                }
            ],
            "resources": [{"uri": "fixture://help", "name": "help", "description": "Local help"}],
        }
    )
    encoded = surface.to_json()
    assert encoded == json.dumps(surface.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    assert ServerSurface.from_json(encoded) == surface
    config = surface.to_config()
    assert config.env_keys == ["TOKEN_NAME"]
    assert config.command == "python" and config.args == ["server.py"]
    tool = surface.to_tools()[0]
    assert tool.title == "Echo" and tool.input_schema == surface.tools[0].input_schema
    assert tool.annotations is not None
    assert tool.annotations.title == "Hint title"
    assert tool.annotations.read_only_hint is True and tool.annotations.destructive_hint is False
    assert tool.annotations.idempotent_hint is True and tool.annotations.open_world_hint is False
    assert surface.to_resources()[0].uri == "fixture://help"


def test_env_values_are_rejected() -> None:
    with pytest.raises(ValidationError):
        ServerSurface.model_validate(
            {"server_name": "bad", "source": "fixture", "config": {"env": {"KEY": "value"}}}
        )


def test_literal_tools_and_primitive_defaults(tmp_path: Path) -> None:
    path = tmp_path / "inert.py.txt"
    path.write_text('''from fastmcp import FastMCP
mcp = FastMCP("literal")
@mcp.tool(name="display", description="Literal description", annotations={"readOnlyHint": True})
def show(text: str, count: int = 2, ratio: float = 0.5, *, enabled: bool = False) -> str:
    """Overridden docstring."""
    raise RuntimeError("This body must never execute")
@mcp.tool()
async def other(value: str = "default"):
    """Docstring fallback."""
    return value
''')
    surface = extract_from_source(path)
    assert isinstance(surface, ServerSurface)
    first, second = surface.to_tools()
    assert first.name == "display" and first.description == "Literal description"
    assert first.annotations is not None and first.annotations.read_only_hint is True
    assert first.input_schema == {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "count": {"type": "integer", "default": 2},
            "ratio": {"type": "number", "default": 0.5},
            "enabled": {"type": "boolean", "default": False},
        },
        "required": ["text"],
    }
    assert second.description == "Docstring fallback."


@pytest.mark.parametrize(
    "source",
    [
        "mcp = FastMCP(get_name())",
        'mcp = FastMCP("x", instructions="hidden metadata")',
        'mcp = FastMCP("x")\n@mcp.tool(name=compute())\ndef f(x: str): pass',
        'mcp = FastMCP("x")\n@mcp.tool(annotations={"readOnlyHint": "true"})\ndef f(x: str): pass',
        'mcp = FastMCP("x")\n@mcp.tool(annotations={"unknownHint": True})\ndef f(x: str): pass',
        'mcp = FastMCP("x")\n@mcp.tool(annotations=None)\ndef f(x: str): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(x: list[str]): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(x): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(x: int = True): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(x: str = None): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(*args: str): pass',
        'mcp = FastMCP("x")\n@mcp.tool\ndef f(x: str, /): pass',
        'mcp = FastMCP("x")\n@mcp.tool\n@other\ndef f(x: str): pass',
        'mcp = FastMCP("x")\n@mcp.resource("fixture://x")\ndef f(x: str): pass',
        'mcp = FastMCP("x")\nif enabled:\n @mcp.tool\n def f(x: str): pass',
        'mcp = FastMCP("x")\nmcp = other',
        'mcp = FastMCP("x")\nmcp.add_tool(other)',
        'mcp = FastMCP("x")\nclass Dynamic: pass',
        'mcp = FastMCP("x")\n@mcp.tool(name="same")\ndef f(x: str): pass\n'
        '@mcp.tool(name="same")\ndef g(x: str): pass',
        'import os\nmcp = FastMCP("x")',
        'raise RuntimeError("must not execute")',
        "def broken(",
        "",
    ],
)
def test_unknown_unsupported_ast(tmp_path: Path, source: str) -> None:
    path = tmp_path / "inert.py.txt"
    path.write_text(source)
    result = extract_from_source(path)
    assert isinstance(result, Unknown)
    assert result.status == "UNKNOWN" and result.reason
    assert str(tmp_path) not in result.reason


def test_unknown_missing_file(tmp_path: Path) -> None:
    result = extract_from_source(tmp_path / "missing.py.txt")
    assert isinstance(result, Unknown) and result.reason == "FileNotFoundError"


def test_unknown_metadata_reason_omits_input_values(tmp_path: Path) -> None:
    path = tmp_path / "inert.py.txt"
    path.write_text(
        'mcp = FastMCP("x")\n@mcp.tool(annotations={"readOnlyHint": "invalid-value-marker"})\n'
        "def f(x: str): pass"
    )
    result = extract_from_source(path)
    assert isinstance(result, Unknown)
    assert "annotations.readOnlyHint" in result.reason and "bool_type" in result.reason
    assert "invalid-value-marker" not in result.reason


def test_catalog_is_exact_validation_corpus_snapshot() -> None:
    catalog = load_catalog()
    names = {"pypi:mcp-server-git": "git", "npm:@modelcontextprotocol/server-filesystem": "filesystem"}
    assert set(catalog) == set(names)
    corpus = Path(__file__).parents[1] / "validation/servers"
    for key, surface in catalog.items():
        original = json.loads((corpus / f"{names[key]}.json").read_text())
        assert surface.source == "catalog"
        assert surface.provenance and "unversioned" in surface.provenance
        assert "not a verified current surface" in surface.provenance
        assert surface.server_name == original["server_name"]
        assert [tool.model_dump(exclude_none=True) for tool in surface.tools] == original["tools"]
