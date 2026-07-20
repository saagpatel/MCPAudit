"""Machine-readable CLI for the experimental fixture-only adapter."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError

from mcp_audit.evidence_enforcement import (
    ApprovalBindingError,
    ApprovedPolicyIntentV1,
    ObservedEvidenceV1,
    PolicyOutcomeError,
    PolicyRecommendationV1,
    ServerIdentity,
    apply_fixture_policy,
    approve_recommendation,
    digest_model,
    dry_run_diff,
    observed_evidence_from_report,
    parse_model,
    read_fixture_state,
    recommend_fixture_policy,
    rollback_fixture_policy,
    state_digest,
)
from mcp_audit.models import AuditReport


class JsonEnforcementGroup(click.Group):
    """Keep subgroup usage failures inside the machine-output contract."""

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.UsageError:
            message = "input validation failed"
            payload = {
                "status": "invalid_input",
                "error": {"code": "invalid_input", "message": message},
            }
            click.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            click.echo(message, err=True)
            raise click.exceptions.Exit(2) from None


@click.group("enforcement-fixture", cls=JsonEnforcementGroup)
def enforcement_fixture() -> None:
    """Experimental fixture-only evidence-to-enforcement commands."""


@enforcement_fixture.command("prepare")
@click.option("--audit-report", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--origin", required=True)
@click.option("--server-name", required=True)
@click.option("--source-sha256", required=True)
@click.option("--provenance", multiple=True, required=True)
@click.option("--created-at", required=True)
@click.option("--expires-at", required=True)
@click.option("--rollback-id", required=True)
@click.option("--state-dir", type=click.Path(path_type=Path), required=True)
def prepare(
    audit_report: Path,
    origin: str,
    server_name: str,
    source_sha256: str,
    provenance: tuple[str, ...],
    created_at: str,
    expires_at: str,
    rollback_id: str,
    state_dir: Path,
) -> None:
    """Create observed evidence, a recommendation, and a no-write dry-run diff."""

    def operation() -> dict[str, Any]:
        report = parse_model(audit_report, AuditReport)
        evidence = observed_evidence_from_report(
            report,
            origin=origin,
            server_name=server_name,
            canonical_source_sha256=source_sha256,
            provenance=list(provenance),
        )
        current = read_fixture_state(state_dir, evidence.subject)
        recommendation = recommend_fixture_policy(
            evidence,
            created_at=_timestamp(created_at),
            expires_at=_timestamp(expires_at),
            pre_state_sha256=state_digest(current),
            rollback_id=rollback_id,
        )
        return {
            "status": "prepared",
            "evidence": evidence.model_dump(mode="json"),
            "evidence_sha256": digest_model(evidence),
            "recommendation": recommendation.model_dump(mode="json"),
            "recommendation_sha256": digest_model(recommendation),
            "dry_run": dry_run_diff(evidence, recommendation, state_dir),
        }

    _run(operation)


@enforcement_fixture.command("approve")
@click.option("--recommendation", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--approved-at", required=True)
@click.option("--expires-at", required=True)
@click.option("--operator-label", required=True)
def approve(
    recommendation: Path,
    approved_at: str,
    expires_at: str,
    operator_label: str,
) -> None:
    """Emit an approval bound to one exact recommendation."""

    def operation() -> dict[str, Any]:
        value = parse_model(recommendation, PolicyRecommendationV1)
        approval = approve_recommendation(
            value,
            approved_at=_timestamp(approved_at),
            expires_at=_timestamp(expires_at),
            operator_label=operator_label,
        )
        return {
            "status": "approved",
            "approval": approval.model_dump(mode="json"),
            "approval_sha256": digest_model(approval),
        }

    _run(operation)


@enforcement_fixture.command("apply")
@click.option("--evidence", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--recommendation", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--approval", type=click.Path(path_type=Path, exists=True), required=True)
@click.option("--state-dir", type=click.Path(path_type=Path), required=True)
def apply(
    evidence: Path,
    recommendation: Path,
    approval: Path,
    state_dir: Path,
) -> None:
    """Apply only to named program-owned fixture state and verify behavior."""

    def operation() -> dict[str, Any]:
        return apply_fixture_policy(
            parse_model(evidence, ObservedEvidenceV1),
            parse_model(recommendation, PolicyRecommendationV1),
            parse_model(approval, ApprovedPolicyIntentV1),
            state_dir,
        )

    _run(operation)


@enforcement_fixture.command("rollback")
@click.option("--origin", required=True)
@click.option("--server-name", required=True)
@click.option("--rollback-id", required=True)
@click.option("--state-dir", type=click.Path(path_type=Path), required=True)
@click.option("--rolled-back-at", required=True)
def rollback(
    origin: str,
    server_name: str,
    rollback_id: str,
    state_dir: Path,
    rolled_back_at: str,
) -> None:
    """Restore the exact captured program-owned fixture state."""

    def operation() -> dict[str, Any]:
        return rollback_fixture_policy(
            state_dir,
            subject=ServerIdentity(origin=origin, server_name=server_name),
            rollback_id=rollback_id,
            rolled_back_at=_timestamp(rolled_back_at),
        )

    _run(operation)


def _timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _run(operation: Any) -> None:
    try:
        payload = operation()
        exit_code = 0
    except (ApprovalBindingError, PolicyOutcomeError) as exc:
        payload = {
            "status": "blocked",
            "error": {"code": "fail_closed", "message": str(exc)},
        }
        exit_code = 1
        click.echo(str(exc), err=True)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        del exc
        message = "input validation failed"
        payload = {"status": "invalid_input", "error": {"code": "invalid_input", "message": message}}
        exit_code = 2
        click.echo(message, err=True)
    except Exception as exc:
        message = "unexpected enforcement failure"
        payload = {
            "status": "blocked",
            "error": {"code": "fail_closed", "message": message},
        }
        exit_code = 1
        click.echo(f"{message}: {type(exc).__name__}", err=True)
    click.echo(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    if exit_code:
        raise click.exceptions.Exit(exit_code)
