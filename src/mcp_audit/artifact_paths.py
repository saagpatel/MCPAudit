"""Preflight CLI artifact destinations before any report file is written."""

from collections.abc import Iterable
from pathlib import Path

import click

from mcp_audit.terminal_text import strip_controls


def _identity(path: Path) -> tuple[Path, tuple[int, int] | None]:
    resolved = path.resolve()
    try:
        info = resolved.stat()
    except FileNotFoundError:
        return resolved, None
    return resolved, (info.st_dev, info.st_ino)


def validate_artifact_paths(outputs: Iterable[tuple[str, Path | None]], inputs: Iterable[Path]) -> None:
    """Reject input/output and output/output aliases, including hard links."""
    destinations = [(flag, path) for flag, path in outputs if path is not None]
    if not destinations:
        return
    try:
        protected = [(_identity(path), "an input file") for path in inputs]
    except (OSError, RuntimeError) as exc:
        raise click.BadParameter(
            f"Cannot verify input paths: {type(exc).__name__}", param_hint=destinations[0][0]
        ) from None
    for flag, path in destinations:
        try:
            resolved, inode = _identity(path)
        except (OSError, RuntimeError) as exc:
            raise click.BadParameter(
                f"Cannot verify output path: {type(exc).__name__}", param_hint=flag
            ) from None
        for (other_path, other_inode), label in protected:
            if resolved == other_path or (inode is not None and inode == other_inode):
                raise click.BadParameter(
                    strip_controls(f"Output {path} aliases {label}; no artifacts written."),
                    param_hint=flag,
                )
        protected.append(((resolved, inode), f"artifact destination {flag}"))
