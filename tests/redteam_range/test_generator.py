"""Generation is deterministic and rejects malformed mutation records."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from redteam.range.gen.__main__ import BASE, generate
from redteam.range.mutations import OPERATORS, TwinInput, validate_twin
from redteam.surface import ServerSurface


def test_generation_is_deterministic(tmp_path: Path) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    generate(first)
    generate(second)
    files = sorted(path.relative_to(first) for path in first.rglob("*") if path.is_file())
    assert len(files) == 63
    assert files == sorted(path.relative_to(second) for path in second.rglob("*") if path.is_file())
    assert all((first / path).read_bytes() == (second / path).read_bytes() for path in files)
    assert json.loads((first / "index.json").read_text()) == [op.id for op in OPERATORS]
    assert "external-schema-ref" in json.loads((first / "index.json").read_text())


def test_validator_rejects_undeclared_change() -> None:
    base = TwinInput(ServerSurface.load(BASE / "surface.json"), (BASE / "server.py.txt").read_text())
    twin = OPERATORS[0].apply(base)
    twin.surface.server_name = "unexpected"
    with pytest.raises(ValueError):
        validate_twin(base, twin)


def test_validator_rejects_extra_and_missing_records() -> None:
    base = TwinInput(ServerSurface.load(BASE / "surface.json"), (BASE / "server.py.txt").read_text())
    twin = OPERATORS[0].apply(base)
    twin.mutation_record[0]["field_paths_changed"] = ["tools", "source", "config.command"]
    with pytest.raises(ValueError):
        validate_twin(base, twin)
    twin.mutation_record.clear()
    with pytest.raises(ValueError):
        validate_twin(base, twin)
