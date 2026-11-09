"""Regenerate/verify the allowlisted inert mcpforge scaffold, without running it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from redteam.surface import ServerSurface, Unknown, extract_from_source

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "redteam/fixtures/servers/base"
ALLOWLIST = ("README.md", "config.json", "fastmcp.json", "pyproject.toml", "server.py", "test_server.py")
INIT_COMMAND = ["mcpforge", "init", "range-base", "--transport", "stdio", "-o", "<fresh-tmp-dir>"]


def fixture_name(name: str) -> str:
    return name + ".txt" if name.endswith(".py") else name


def fixture_hashes(directory: Path) -> dict[str, str]:
    return {
        fixture_name(name): hashlib.sha256((directory / fixture_name(name)).read_bytes()).hexdigest()
        for name in sorted(ALLOWLIST)
    }


def build(*, regen: bool = False) -> None:
    executable = shutil.which(os.environ.get("MCPFORGE", "mcpforge"))
    if executable is None:
        raise RuntimeError("mcpforge is unavailable; set MCPFORGE to its executable or put it on PATH")
    version = subprocess.run(
        [executable, "--version"], check=True, capture_output=True, text=True
    ).stdout.strip()
    output_root = ROOT / "build/redteam"
    output_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="base-", dir=output_root) as tmp:
        scaffold = Path(tmp) / "scaffold"
        subprocess.run([executable, *INIT_COMMAND[1:-1], str(scaffold)], check=True, capture_output=True)
        # Open only these six files. In particular, never inspect .env.example.
        contents: dict[str, bytes] = {}
        for name in ALLOWLIST:
            source = scaffold / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError(f"missing or non-regular allowlisted scaffold file: {name}")
            contents[fixture_name(name)] = source.read_bytes()
        manifest = {
            "mcpforge_version": version,
            "init_command": INIT_COMMAND,
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(contents.items())},
        }
        surface = extract_from_source(scaffold / "server.py")
        if isinstance(surface, Unknown):
            raise RuntimeError(f"generated scaffold metadata is UNKNOWN: {surface.reason}")
        if regen:
            FIXTURE.mkdir(parents=True, exist_ok=True)
            for name, data in contents.items():
                (FIXTURE / name).write_bytes(data)
            (FIXTURE / "MANIFEST.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (FIXTURE / "surface.json").write_text(surface.to_json(), encoding="utf-8")
        else:
            committed: object = json.loads((FIXTURE / "MANIFEST.json").read_text(encoding="utf-8"))
            if manifest != committed:
                raise RuntimeError(
                    "mcpforge scaffold differs from MANIFEST.json; review before make base REGEN=1"
                )
            if not isinstance(committed, dict) or fixture_hashes(FIXTURE) != committed.get("files"):
                raise RuntimeError("committed fixture hashes do not match MANIFEST.json")
            if surface != ServerSurface.load(FIXTURE / "surface.json"):
                raise RuntimeError("generated AST surface differs from the committed surface.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--regen", action="store_true", help="replace the committed allowlisted baseline")
    args = parser.parse_args()
    try:
        build(regen=args.regen)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"base fixture: {exc}\n")
    print("base fixture regenerated" if args.regen else "base fixture verified")


if __name__ == "__main__":
    main()
