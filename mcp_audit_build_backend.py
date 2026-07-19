"""PEP 517 wrapper that binds built distributions to their source revision."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parent
_PACKAGE_ROOT = _ROOT / "src/mcp_audit"
_PROVENANCE_PATH = _PACKAGE_ROOT / "_build_provenance.json"
_SCHEMA = "mcp-audits.build-provenance.v1"


def build_sdist(
    sdist_directory: str,
    config_settings: Mapping[Any, Any] | None = None,
) -> str:
    with _generated_provenance():
        from uv_build import build_sdist as uv_build_sdist

        return cast(str, uv_build_sdist(sdist_directory, config_settings))


def build_wheel(
    wheel_directory: str,
    config_settings: Mapping[Any, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    with _generated_provenance():
        from uv_build import build_wheel as uv_build_wheel

        return cast(
            str,
            uv_build_wheel(wheel_directory, config_settings, metadata_directory),
        )


def build_editable(
    wheel_directory: str,
    config_settings: Mapping[Any, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    from uv_build import build_editable as uv_build_editable

    return cast(
        str,
        uv_build_editable(wheel_directory, config_settings, metadata_directory),
    )


def get_requires_for_build_sdist(
    config_settings: Mapping[Any, Any] | None = None,
) -> list[str]:
    from uv_build import get_requires_for_build_sdist

    return list(get_requires_for_build_sdist(config_settings))


def get_requires_for_build_wheel(
    config_settings: Mapping[Any, Any] | None = None,
) -> list[str]:
    from uv_build import get_requires_for_build_wheel

    return list(get_requires_for_build_wheel(config_settings))


def get_requires_for_build_editable(
    config_settings: Mapping[Any, Any] | None = None,
) -> list[str]:
    from uv_build import get_requires_for_build_editable

    return list(get_requires_for_build_editable(config_settings))


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: Mapping[Any, Any] | None = None,
) -> str:
    from uv_build import prepare_metadata_for_build_wheel

    return cast(
        str,
        prepare_metadata_for_build_wheel(metadata_directory, config_settings),
    )


def prepare_metadata_for_build_editable(
    metadata_directory: str,
    config_settings: Mapping[Any, Any] | None = None,
) -> str:
    from uv_build import prepare_metadata_for_build_editable

    return cast(
        str,
        prepare_metadata_for_build_editable(metadata_directory, config_settings),
    )


@contextmanager
def _generated_provenance() -> Iterator[None]:
    if _PROVENANCE_PATH.exists():
        if _git_root() is not None:
            raise RuntimeError(
                "source checkout contains pre-generated build provenance; refusing an ambiguous build"
            )
        _validate_provenance(_PROVENANCE_PATH)
        yield
        return
    payload = _source_provenance()
    _PROVENANCE_PATH.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    try:
        yield
    finally:
        _PROVENANCE_PATH.unlink(missing_ok=True)


def _source_provenance() -> dict[str, str | bool | None]:
    root = _git_root()
    if root is None:
        return {
            "schema_version": _SCHEMA,
            "commit": None,
            "dirty": None,
        }
    commit_result = _git("rev-parse", "HEAD")
    status_result = _git("status", "--porcelain", "--untracked-files=all")
    if commit_result.returncode != 0 or status_result.returncode != 0:
        return {
            "schema_version": _SCHEMA,
            "commit": None,
            "dirty": None,
        }
    commit = commit_result.stdout.decode().strip()
    dirty = bool(status_result.stdout)
    tracked_result = _git("ls-files", "-z", "--", "src/mcp_audit")
    if tracked_result.returncode != 0:
        dirty = True
    else:
        tracked = {item for item in tracked_result.stdout.decode().split("\0") if item}
        actual = {
            path.relative_to(_ROOT).as_posix()
            for path in _PACKAGE_ROOT.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
            and path != _PROVENANCE_PATH
        }
        if not actual.issubset(tracked):
            dirty = True
    return {
        "schema_version": _SCHEMA,
        "commit": commit if len(commit) == 40 else None,
        "dirty": dirty,
    }


def _validate_provenance(path: Path) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("build provenance is unreadable") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != _SCHEMA:
        raise RuntimeError("build provenance schema is unsupported")
    commit = payload.get("commit")
    dirty = payload.get("dirty")
    if commit is not None and (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise RuntimeError("build provenance commit is invalid")
    if dirty is not None and not isinstance(dirty, bool):
        raise RuntimeError("build provenance dirty state is invalid")


def _git_root() -> Path | None:
    result = _git("rev-parse", "--show-toplevel")
    if result.returncode != 0:
        return None
    try:
        root = Path(result.stdout.decode().strip()).resolve()
    except (OSError, UnicodeError):
        return None
    return root if root == _ROOT else None


def _git(*args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(_ROOT), *args],
            check=False,
            capture_output=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.SubprocessError):
        return subprocess.CompletedProcess(["git", *args], 1, b"", b"")
