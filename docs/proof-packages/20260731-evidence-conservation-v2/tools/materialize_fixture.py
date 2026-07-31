#!/usr/bin/env python3
"""Decode one fixture into an empty disposable directory; invoke nothing."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

from package_lib import decode_artifact, tar_members


def _safe_destination(root: Path, relative: str) -> Path:
    destination = (root / relative).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact escaped destination: {relative}") from exc
    return destination


def _write_file(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(mode)
    if stat.S_IMODE(path.stat().st_mode) != mode:
        raise OSError(f"POSIX mode was not preserved for {path.name}")


def materialize(fixture: dict[str, Any], destination: Path) -> dict[str, Any]:
    destination = destination.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise FileExistsError("destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for encoded in fixture["artifacts"]:
        content = decode_artifact(encoded)
        mode = int(encoded["materialization_mode"], 8)
        name = str(encoded["name"])
        if encoded["media_type"] != "application/x-tar":
            path = _safe_destination(destination, name)
            _write_file(path, content, mode)
            written.append(path.relative_to(destination).as_posix())
            continue
        archive_root_name = {
            "refresh-candidate.tar": "refresh-candidate",
            "recovery-anchor.tar": "recovery-anchor",
        }.get(name, Path(name).stem)
        archive_root = _safe_destination(destination, archive_root_name)
        archive_root.mkdir(parents=True, exist_ok=True)
        deferred_directories: list[tuple[Path, int]] = []
        for relative, (member_content, member_mode) in tar_members(content).items():
            path = _safe_destination(archive_root, relative)
            if member_content is None:
                path.mkdir(parents=True, exist_ok=True)
                deferred_directories.append((path, member_mode))
                continue
            _write_file(path, member_content, member_mode)
            written.append(path.relative_to(destination).as_posix())
        for path, member_mode in sorted(
            deferred_directories,
            key=lambda item: len(item[0].parts),
            reverse=True,
        ):
            path.chmod(member_mode)
            if stat.S_IMODE(path.stat().st_mode) != member_mode:
                raise OSError(f"POSIX directory mode was not preserved for {path.name}")
    return {
        "schema": "FixtureMaterializationV2",
        "fixture_id": fixture["fixture_id"],
        "destination": str(destination),
        "written_paths": sorted(written),
        "consumer_invoked": False,
        "ctime_policy": "completed_before_any_future_verification_and_excluded",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    result = materialize(fixture, args.destination)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
