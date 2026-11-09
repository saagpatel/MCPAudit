"""Builder boundaries without invoking or importing any scaffold server."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from redteam.range.base import build as builder
from redteam.range.base.build import build


def test_missing_mcpforge_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCPFORGE", "definitely-not-an-installed-mcpforge")
    with pytest.raises(RuntimeError, match="mcpforge is unavailable; set MCPFORGE"):
        build()


def test_generated_fixture_python_is_inert() -> None:
    root = Path(__file__).parents[2] / "redteam/fixtures/servers"
    assert not list(root.rglob("*.py"))


def test_builder_allowlist_regeneration_and_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original_fixture = builder.FIXTURE
    fixture = tmp_path / "fixture"
    manifest = json.loads((original_fixture / "MANIFEST.json").read_text())
    changed = False
    calls: list[list[str]] = []
    read_bytes = Path.read_bytes

    def guarded_read(path: Path) -> bytes:
        assert path.name != ".env.example", "builder must never open generated environment docs"
        return read_bytes(path)

    def fake_run(
        args: list[str], *, check: bool, capture_output: bool, text: bool = False
    ) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
        calls.append(args)
        assert check and capture_output
        if args[1:] == ["--version"]:
            assert text
            return subprocess.CompletedProcess(args, 0, manifest["mcpforge_version"] + "\n", "")
        assert args[1:-1] == ["init", "range-base", "--transport", "stdio", "-o"]
        output = Path(args[-1])
        assert not output.exists()
        output.mkdir()
        for name in builder.ALLOWLIST:
            data = read_bytes(original_fixture / builder.fixture_name(name))
            (output / name).write_bytes(data + (b"\n" if changed and name == "README.md" else b""))
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(builder, "ROOT", tmp_path)
    monkeypatch.setattr(builder, "FIXTURE", fixture)
    monkeypatch.setattr(shutil, "which", lambda executable: "mcpforge")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(Path, "read_bytes", guarded_read)
    build(regen=True)
    assert {path.name for path in fixture.iterdir()} == {
        *(builder.fixture_name(name) for name in builder.ALLOWLIST),
        "MANIFEST.json",
        "surface.json",
    }
    build()
    changed = True
    with pytest.raises(RuntimeError, match="scaffold differs"):
        build()
    assert len(calls) == 6
    assert not list((tmp_path / "build/redteam").iterdir())
