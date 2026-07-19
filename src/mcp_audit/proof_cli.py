"""Standalone Proof Before Action command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import click
import yaml
from pydantic import BaseModel, ValidationError

from mcp_audit.proof_capsule import (
    build_capsule,
    compare_bill,
    export_capsule,
    verify_capsule,
)
from mcp_audit.proof_models import (
    ActionDeclaration,
    CapsuleIndex,
    EvidenceCapsule,
    Observation,
    ReleaseTrustManifest,
)
from mcp_audit.proof_observer import ObservationBlocked, observe_command
from mcp_audit.proof_trust import build_release_trust_manifest


@click.group()
def main() -> None:
    """Observe first, compare with declared limits, then emit portable evidence."""


@main.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--repo",
    type=click.Path(path_type=Path, exists=True, file_okay=False, readable=True),
    required=True,
)
@click.option(
    "--declaration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False, readable=True),
    required=True,
)
@click.option(
    "--trust-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False, readable=True),
)
@click.option("--image", default="node:24-slim", show_default=True)
@click.option("--timeout", "timeout_seconds", default=45, type=click.IntRange(1, 600))
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def inspect(
    repo: Path,
    declaration: Path,
    trust_root: Path | None,
    image: str,
    timeout_seconds: int,
    output: Path,
    command: tuple[str, ...],
) -> None:
    """Run COMMAND in the disposable observer and export JSON plus offline HTML."""
    try:
        payload = yaml.safe_load(declaration.read_text(encoding="utf-8"))
        declared = ActionDeclaration.model_validate(payload)
        observed = observe_command(
            repo,
            list(command),
            image=image,
            timeout_seconds=timeout_seconds,
        )
        comparison = compare_bill(declared, observed)
        trust = build_release_trust_manifest(repo, trust_root)
        capsule = build_capsule(declared, observed, comparison, trust)
        root_sha256 = export_capsule(capsule, output)
    except (OSError, ValueError, ValidationError, ObservationBlocked) as exc:
        click.echo(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "inspection_blocked",
                        "message": str(exc).replace(str(Path.home()), "$HOME"),
                    },
                },
                sort_keys=True,
            )
        )
        raise click.exceptions.Exit(2) from None
    click.echo(
        json.dumps(
            {
                "ok": comparison.verdict == "pass",
                "verdict": comparison.verdict,
                "output": str(output).replace(str(Path.home()), "$HOME"),
                "root_sha256": root_sha256,
            },
            sort_keys=True,
        )
    )
    if comparison.verdict != "pass":
        raise click.exceptions.Exit(1)


@main.command("verify")
@click.argument(
    "capsule_root",
    type=click.Path(path_type=Path, exists=True, file_okay=False, readable=True),
)
@click.option("--expect-subject-commit")
@click.option("--expect-producer-commit")
@click.option("--expect-schema")
@click.option("--expect-root-sha256")
def verify_command(
    capsule_root: Path,
    expect_subject_commit: str | None,
    expect_producer_commit: str | None,
    expect_schema: str | None,
    expect_root_sha256: str | None,
) -> None:
    """Verify hashes, schemas, commits, and optional external root authority."""
    result = verify_capsule(
        capsule_root,
        expect_subject_commit=expect_subject_commit,
        expect_producer_commit=expect_producer_commit,
        expect_schema=expect_schema,
        expect_root_sha256=expect_root_sha256,
    )
    click.echo(json.dumps(result, sort_keys=True))
    if not result["valid"]:
        raise click.exceptions.Exit(1)


@main.command("schema")
@click.argument(
    "contract",
    type=click.Choice(["declaration", "observation", "trust-manifest", "capsule", "capsule-index"]),
)
def schema_command(contract: str) -> None:
    """Print one authoritative JSON Schema for local tooling and compatibility checks."""
    models: dict[str, type[BaseModel]] = {
        "declaration": ActionDeclaration,
        "observation": Observation,
        "trust-manifest": ReleaseTrustManifest,
        "capsule": EvidenceCapsule,
        "capsule-index": CapsuleIndex,
    }
    click.echo(json.dumps(models[contract].model_json_schema(), sort_keys=True))
