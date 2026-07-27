"""Click commands for the experimental offline Agent UI Contract Auditor."""

from __future__ import annotations

import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

import click
from pydantic import BaseModel

from mcp_audit.agent_ui_models import (
    A2UIFixtureManifest,
    A2UIMessage,
    AgentUIReport,
    MCPAppsFixture,
)
from mcp_audit.agent_ui_scanner import (
    AgentUIInputError,
    render_agent_ui_html,
    report_json_bytes,
    scan_agent_ui_path_with_identity,
)


class AgentUIUsageError(click.ClickException):
    exit_code = 2


@click.group("agent-ui")
def agent_ui() -> None:
    """Audit program-owned MCP Apps metadata and A2UI JSONL fixtures offline."""


@agent_ui.command("scan")
@click.argument(
    "fixture",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--json",
    "json_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the canonical machine-readable report.",
)
@click.option(
    "--html",
    "html_path",
    type=click.Path(path_type=Path, dir_okay=False),
    help="Write the inert offline HTML projection.",
)
@click.option("--force", is_flag=True, default=False, help="Replace existing regular report files.")
def scan_command(
    fixture: Path,
    json_path: Path | None,
    html_path: Path | None,
    force: bool,
) -> None:
    """Statically scan one synthetic fixture without executing or connecting."""
    try:
        report, input_identity = scan_agent_ui_path_with_identity(fixture)
        json_bytes = report_json_bytes(report)
        html_bytes = render_agent_ui_html(report).encode("utf-8")
        artifacts = [
            item
            for item in (
                (json_path, json_bytes) if json_path is not None else None,
                (html_path, html_bytes) if html_path is not None else None,
            )
            if item is not None
        ]
        _write_artifacts(fixture, input_identity, artifacts, force=force)
    except (AgentUIInputError, OSError, ValueError) as exc:
        raise AgentUIUsageError(str(exc)) from exc
    if json_path is None:
        click.echo(json_bytes.decode("utf-8"), nl=False)
    if report.verdict != "pass":
        raise click.exceptions.Exit(1)


@agent_ui.command("schema")
@click.argument(
    "contract",
    type=click.Choice(
        [
            "mcp-apps-fixture",
            "a2ui-fixture-manifest",
            "a2ui-message",
            "report",
        ]
    ),
)
def schema_command(contract: str) -> None:
    """Print one authoritative strict JSON Schema."""
    models: dict[str, type[BaseModel]] = {
        "mcp-apps-fixture": MCPAppsFixture,
        "a2ui-fixture-manifest": A2UIFixtureManifest,
        "a2ui-message": A2UIMessage,
        "report": AgentUIReport,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))


def _same_path(first: Path, second: Path) -> bool:
    try:
        if first.resolve(strict=False) == second.resolve(strict=False):
            return True
        if first.exists() and second.exists():
            return os.path.samefile(first, second)
        return False
    except RuntimeError as exc:
        raise ValueError("cannot establish safe input/output path identity") from exc


@dataclass
class _StagedArtifact:
    parent_fd: int
    temporary_name: str
    target_name: str
    target_path: Path
    inode: tuple[int, int]


def _require_descriptor_bound_writes() -> None:
    required = (os.open, os.stat, os.link, os.rename, os.unlink)
    if any(function not in os.supports_dir_fd for function in required):
        raise ValueError("descriptor-bound artifact writes are unsupported on this platform")


def _open_artifact_parent(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path.parent, flags)
    except OSError as exc:
        raise ValueError(f"output parent does not exist or is inaccessible: {path.parent}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"output parent is not a directory: {path.parent}")
    return descriptor


def _validate_artifact_target(
    parent_fd: int,
    path: Path,
    *,
    force: bool,
) -> None:
    try:
        target = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(target.st_mode):
        raise ValueError(f"refusing symlink output: {path}")
    if not stat.S_ISREG(target.st_mode):
        raise ValueError(f"output is not a regular file: {path}")
    if not force:
        raise ValueError(f"output already exists (use --force): {path}")


def _validate_input_alias(
    parent_fd: int,
    path: Path,
    input_identity: tuple[int, int],
) -> None:
    try:
        target = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (target.st_dev, target.st_ino) == input_identity:
        raise ValueError(f"output must not alias the input fixture: {path}")


def _stage_artifact(parent_fd: int, path: Path, content: bytes) -> _StagedArtifact:
    descriptor: int | None = None
    temporary_name = ""
    for _ in range(16):
        temporary_name = f".{path.name}.{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(
                temporary_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError:
            continue
        break
    if descriptor is None:
        raise ValueError(f"could not allocate a staging file for output: {path}")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.unlink(temporary_name, dir_fd=parent_fd)
        raise
    staged_stat = os.stat(temporary_name, dir_fd=parent_fd, follow_symlinks=False)
    return _StagedArtifact(
        parent_fd=parent_fd,
        temporary_name=temporary_name,
        target_name=path.name,
        target_path=path,
        inode=(staged_stat.st_dev, staged_stat.st_ino),
    )


def _rollback_created_artifacts(artifacts: list[_StagedArtifact]) -> None:
    for artifact in reversed(artifacts):
        try:
            target = os.stat(
                artifact.target_name,
                dir_fd=artifact.parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            continue
        if (target.st_dev, target.st_ino) == artifact.inode:
            os.unlink(artifact.target_name, dir_fd=artifact.parent_fd)


def _write_artifacts(
    fixture: Path,
    input_identity: tuple[int, int],
    artifacts: list[tuple[Path, bytes]],
    *,
    force: bool,
) -> None:
    if not artifacts:
        return
    _require_descriptor_bound_writes()
    for path, _ in artifacts:
        if _same_path(fixture, path):
            raise ValueError(f"output must not alias the input fixture: {path}")
    for index, (path, _) in enumerate(artifacts):
        for other_path, _ in artifacts[index + 1 :]:
            if _same_path(path, other_path):
                raise ValueError("JSON and HTML outputs must use distinct paths")

    parent_fds: list[int] = []
    staged: list[_StagedArtifact] = []
    committed_without_force: list[_StagedArtifact] = []
    try:
        for path, content in artifacts:
            parent_fd = _open_artifact_parent(path)
            parent_fds.append(parent_fd)
            _validate_input_alias(parent_fd, path, input_identity)
            _validate_artifact_target(parent_fd, path, force=force)
            staged.append(_stage_artifact(parent_fd, path, content))
        for artifact in staged:
            if force:
                os.rename(
                    artifact.temporary_name,
                    artifact.target_name,
                    src_dir_fd=artifact.parent_fd,
                    dst_dir_fd=artifact.parent_fd,
                )
            else:
                try:
                    os.link(
                        artifact.temporary_name,
                        artifact.target_name,
                        src_dir_fd=artifact.parent_fd,
                        dst_dir_fd=artifact.parent_fd,
                        follow_symlinks=False,
                    )
                except FileExistsError as exc:
                    raise ValueError(f"output already exists (use --force): {artifact.target_path}") from exc
                committed_without_force.append(artifact)
    except BaseException:
        if not force:
            _rollback_created_artifacts(committed_without_force)
        raise
    finally:
        for artifact in staged:
            try:
                os.unlink(artifact.temporary_name, dir_fd=artifact.parent_fd)
            except FileNotFoundError:
                pass
        for descriptor in parent_fds:
            os.close(descriptor)
