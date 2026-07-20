"""Contract and behavioral tests for the experimental fixture-only adapter."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

import mcp_audit.evidence_enforcement as enforcement
from mcp_audit import cli
from mcp_audit.evidence_enforcement import (
    ApprovalBindingError,
    ApprovedPolicyIntentV1,
    ArgumentConstraints,
    Decision,
    EffectiveStateV1,
    FixturePolicyState,
    ObservedEvidenceV1,
    PolicyOutcomeError,
    PolicyRecommendationV1,
    RuntimeRestrictions,
    ServerIdentity,
    ToolDecision,
    apply_fixture_policy,
    approve_recommendation,
    canonical_json_bytes,
    compile_policy,
    digest_model,
    dry_run_diff,
    observed_evidence_from_report,
    read_fixture_state,
    recommend_fixture_policy,
    rollback_fixture_policy,
    state_digest,
    verify_target_runtime,
)
from mcp_audit.models import (
    AUDIT_REPORT_SCHEMA_VERSION,
    AuditReport,
    ClientType,
    ConnectionMode,
    ScanWarning,
    ServerAudit,
    ServerConfig,
    ToolInfo,
    TransportType,
)

NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
ORIGIN = "fixture://mcpaudit/evidence-enforcement"
SERVER = "synthetic-policy-server"


@pytest.fixture(autouse=True)
def _fixed_enforcement_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(minutes=2),
    )


def _report(
    *,
    status: str = "connected",
    tools: list[ToolInfo] | None = None,
    warnings: list[ScanWarning] | None = None,
    env_keys: list[str] | None = None,
) -> AuditReport:
    fixture_tools = (
        tools
        if tools is not None
        else [
            ToolInfo(name=name, input_schema={"type": "object", "additionalProperties": False})
            for name in ("read_fixture", "write_fixture", "delete_fixture")
        ]
    )
    server = ServerConfig(
        name=SERVER,
        client=ClientType.CLAUDE_CODE,
        config_path="examples/enforcement-fixture/synthetic-audit-report.json",
        project_path="/synthetic/program-owned-fixture",
        command="fixture-only",
        args=["--no-real-server"],
        env_keys=env_keys or [],
        transport=TransportType.STDIO,
    )
    audit = ServerAudit(server=server, connection_status=status, tools=fixture_tools)
    return AuditReport(
        scan_timestamp=NOW,
        hostname="fixture-host",
        os_platform="fixture-os",
        connection_mode=ConnectionMode.ATTEMPTED,
        servers_discovered=1,
        servers_connected=1 if status == "connected" else 0,
        servers_failed=0 if status == "connected" else 1,
        total_tools=len(fixture_tools),
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.0,
        warnings=warnings or [],
    )


def _evidence(report: AuditReport | None = None) -> ObservedEvidenceV1:
    return observed_evidence_from_report(
        report or _report(),
        origin=ORIGIN,
        server_name=SERVER,
        canonical_source_sha256=DIGEST_A,
        provenance=["synthetic-connected-audit-report-v1"],
    )


def _state_dir(tmp_path: Path) -> Path:
    return tmp_path / "mcpaudit-enforcement-fixture-test"


def _recommendation(evidence: ObservedEvidenceV1, state_dir: Path) -> PolicyRecommendationV1:
    state = read_fixture_state(state_dir, evidence.subject)
    return recommend_fixture_policy(
        evidence,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        pre_state_sha256=state_digest(state),
        rollback_id="rollback-fixture-001",
    )


def _approval(recommendation: PolicyRecommendationV1) -> ApprovedPolicyIntentV1:
    return approve_recommendation(
        recommendation,
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        operator_label="fixture-operator",
    )


def _bundle(
    tmp_path: Path,
) -> tuple[Path, ObservedEvidenceV1, PolicyRecommendationV1, ApprovedPolicyIntentV1]:
    state_dir = _state_dir(tmp_path)
    evidence = _evidence()
    recommendation = _recommendation(evidence, state_dir)
    approval = _approval(recommendation)
    return state_dir, evidence, recommendation, approval


def test_models_are_strict_versioned_utc_and_canonical() -> None:
    evidence = _evidence()
    payload = evidence.model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ObservedEvidenceV1.model_validate(payload)

    payload.pop("unexpected")
    payload["observed_at"] = "2026-07-20T12:00:00-07:00"
    with pytest.raises(ValidationError, match="explicit UTC"):
        ObservedEvidenceV1.model_validate(payload)

    assert canonical_json_bytes(evidence).endswith(b"\n")
    assert canonical_json_bytes(evidence) == canonical_json_bytes(
        ObservedEvidenceV1.model_validate_json(evidence.model_dump_json())
    )
    assert digest_model(evidence).startswith("sha256:")


def test_audit_report_v1_is_preserved_and_converted_without_authorizing() -> None:
    report = _report()
    evidence = _evidence(report)

    assert report.schema_version == AUDIT_REPORT_SCHEMA_VERSION == 1
    assert evidence.audit_report_schema_version == 1
    assert evidence.authoritative
    assert [tool.name for tool in evidence.tools] == [
        "delete_fixture",
        "read_fixture",
        "write_fixture",
    ]
    assert evidence.canonical_source_sha256 == DIGEST_A
    assert evidence.launch_sha256 != evidence.canonical_source_sha256


def test_checked_in_synthetic_report_is_connected_audit_report_v1() -> None:
    report = AuditReport.model_validate_json(
        Path("examples/enforcement-fixture/synthetic-audit-report.json").read_text(encoding="utf-8")
    )

    assert report.schema_version == 1
    assert report.connection_mode is ConnectionMode.ATTEMPTED
    assert report.audits[0].connection_status == "connected"
    assert {tool.name for tool in report.audits[0].tools} == set(
        ("read_fixture", "write_fixture", "delete_fixture")
    )


@pytest.mark.parametrize(
    "report",
    [
        _report(status="failed"),
        _report(warnings=[ScanWarning(code="fixture_warning", message="coverage reduced")]),
        _report(tools=[]),
    ],
)
def test_degraded_or_missing_evidence_cannot_recommend_allow(report: AuditReport, tmp_path: Path) -> None:
    evidence = _evidence(report)
    with pytest.raises(PolicyOutcomeError, match="not authoritative"):
        _recommendation(evidence, _state_dir(tmp_path))


def test_compiler_translates_only_exact_tool_decisions(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, _ = _bundle(tmp_path)
    del state_dir, evidence
    compiled = compile_policy(recommendation)

    assert compiled.supported
    assert compiled.allowed_tools == ["read_fixture", "write_fixture"]
    assert compiled.denied_tools == ["delete_fixture"]
    assert compiled.approval_tools == ["write_fixture"]


@pytest.mark.parametrize("mutation", ["remapped", "missing", "extra", "duplicate"])
def test_compiler_and_approval_refuse_noncanonical_fixture_decisions(
    mutation: str,
    tmp_path: Path,
) -> None:
    _, _, recommendation, _ = _bundle(tmp_path)
    decisions = list(recommendation.decisions)
    if mutation == "remapped":
        decisions = [
            item.model_copy(update={"decision": Decision.ALLOW})
            if item.tool.name == "delete_fixture"
            else item
            for item in decisions
        ]
    elif mutation == "missing":
        decisions = decisions[:-1]
    elif mutation == "extra":
        decisions.append(
            decisions[-1].model_copy(
                update={
                    "tool": decisions[-1].tool.model_copy(
                        update={
                            "name": "extra_fixture",
                            "origin_qualified_name": (f"{recommendation.subject.qualified}::extra_fixture"),
                        }
                    )
                }
            )
        )
    else:
        decisions.append(decisions[0])
    changed = recommendation.model_copy(update={"decisions": decisions})

    compiled = compile_policy(changed)

    assert not compiled.supported
    assert any(error.field == "decisions" for error in compiled.errors)
    with pytest.raises(PolicyOutcomeError, match="fixed fixture policy"):
        _approval(changed)
    path = tmp_path / f"{mutation}-recommendation.json"
    path.write_bytes(canonical_json_bytes(changed))
    cli_result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "approve",
            "--recommendation",
            str(path),
            "--approved-at",
            "2026-07-20T12:01:00Z",
            "--expires-at",
            "2026-07-20T13:00:00Z",
            "--operator-label",
            "fixture-operator",
        ],
    )
    expected_exit = 2 if mutation == "duplicate" else 1
    expected_code = "invalid_input" if mutation == "duplicate" else "fail_closed"
    assert cli_result.exit_code == expected_exit
    assert json.loads(cli_result.stdout)["error"]["code"] == expected_code


def test_apply_refuses_matching_approval_for_remapped_fixture_decision(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    decisions = [
        item.model_copy(update={"decision": Decision.ALLOW}) if item.tool.name == "delete_fixture" else item
        for item in recommendation.decisions
    ]
    changed = recommendation.model_copy(update={"decisions": decisions})
    matching_approval = approval.model_copy(update={"recommendation_sha256": digest_model(changed)})

    with pytest.raises(PolicyOutcomeError, match="unsupported policy translation"):
        apply_fixture_policy(evidence, changed, matching_approval, state_dir)

    assert not state_dir.exists()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("network_egress", ["https://example.invalid"]),
        ("filesystem_resources", ["/synthetic/path"]),
        ("secret_reference_names", ["FIXTURE_TOKEN"]),
    ],
)
def test_compiler_refuses_unsupported_restrictions(field: str, value: list[str], tmp_path: Path) -> None:
    _, _, recommendation, _ = _bundle(tmp_path)
    restrictions = recommendation.restrictions.model_copy(update={field: value})
    constrained = recommendation.model_copy(update={"restrictions": restrictions})

    compiled = compile_policy(constrained)

    assert not compiled.supported
    assert compiled.errors[0].code == "unsupported_translation"
    assert field in compiled.errors[0].field


def test_compiler_refuses_argument_constraints(tmp_path: Path) -> None:
    _, _, recommendation, _ = _bundle(tmp_path)
    first = recommendation.decisions[0].model_copy(
        update={"argument_constraints": ArgumentConstraints(exact_equals={"id": "fixture"})}
    )
    constrained = recommendation.model_copy(update={"decisions": [first, *recommendation.decisions[1:]]})

    compiled = compile_policy(constrained)

    assert not compiled.supported
    assert compiled.errors[0].field.endswith(".argument_constraints")


def test_secret_references_are_names_only_and_values_are_rejected() -> None:
    with pytest.raises(ValidationError):
        RuntimeRestrictions(secret_reference_names=["FIXTURE_TOKEN=planted-secret"])


def test_dry_run_is_deterministic_and_makes_no_state_change(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, _ = _bundle(tmp_path)
    first = dry_run_diff(evidence, recommendation, state_dir)
    second = dry_run_diff(evidence, recommendation, state_dir)

    assert first == second
    assert first["evidence_sha256"] == digest_model(evidence)
    assert first["recommendation_sha256"] == digest_model(recommendation)
    assert first["pre_state_sha256"] == recommendation.pre_state_sha256
    assert not state_dir.exists()


def test_apply_proves_readback_negative_controls_and_fail_closed(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)

    result = apply_fixture_policy(
        evidence,
        recommendation,
        approval,
        state_dir,
    )

    assert result["status"] == "applied"
    effective = EffectiveStateV1.model_validate(result["effective_state"])
    assert effective.gateway_config.allowed_tools == ["read_fixture", "write_fixture"]
    assert effective.gateway_config.denied_tools == ["delete_fixture"]
    assert effective.gateway_config.sensitive_tools == ["write_fixture"]
    assert effective.handler_counters["read_fixture"] == 1
    assert effective.handler_counters["write_fixture"] == 0
    assert effective.handler_counters["delete_fixture"] == 0
    assert effective.handler_counters["unknown_fixture"] == 0
    assert effective.fail_closed_runtime_error
    assert effective.supported_intent_matches
    assert effective.negative_controls_passed
    probes = {probe.tool_name: probe for probe in effective.behavioral_probes}
    assert probes["read_fixture"].allowed
    assert not probes["write_fixture"].allowed
    assert "approval" in probes["write_fixture"].reason.lower()
    assert not probes["delete_fixture"].allowed
    assert not probes["unknown_fixture"].allowed


def test_only_allowed_tool_reaches_real_fixture_handler_canary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    original_handler = enforcement._fixture_handler
    invocations: list[str] = []

    def tracking_handler(
        tool_name: str,
        counters: dict[str, int],
    ) -> Callable[[], None]:
        handler = original_handler(tool_name, counters)

        def tracked() -> None:
            invocations.append(tool_name)
            handler()

        return tracked

    monkeypatch.setattr(enforcement, "_fixture_handler", tracking_handler)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)

    assert invocations == ["read_fixture"]


def test_identical_reapplication_is_noop_with_same_effective_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    first = apply_fixture_policy(evidence, recommendation, approval, state_dir)
    state_mtime = (state_dir / "state.json").stat().st_mtime_ns
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(minutes=3),
    )
    second = apply_fixture_policy(evidence, recommendation, approval, state_dir)

    assert second["status"] == "no_op"
    assert second["no_op"]
    assert first["effective_state_sha256"] == second["effective_state_sha256"]
    assert (state_dir / "state.json").stat().st_mtime_ns == state_mtime


def test_noop_requires_exact_approval_and_rollback_lineage(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    current = read_fixture_state(state_dir, evidence.subject)
    unrelated = recommendation.model_copy(
        update={
            "pre_state_sha256": state_digest(current),
            "rollback_id": "rollback-unrelated-noop",
        }
    )
    unrelated_approval = _approval(unrelated)

    with pytest.raises(ApprovalBindingError, match="rollback lineage"):
        apply_fixture_policy(evidence, unrelated, unrelated_approval, state_dir)
    assert read_fixture_state(state_dir, evidence.subject) == current


def test_rollback_restores_exact_pre_state_digest_and_decisions(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)

    result = rollback_fixture_policy(
        state_dir,
        subject=evidence.subject,
        rollback_id=recommendation.rollback_id,
        rolled_back_at=NOW + timedelta(minutes=4),
    )

    assert result["restored_state_sha256"] == recommendation.pre_state_sha256
    assert result["captured_state_sha256"] == recommendation.pre_state_sha256
    restored = read_fixture_state(state_dir, evidence.subject)
    assert restored == FixturePolicyState(subject=evidence.subject)
    probes = {item["tool_name"]: item for item in result["behavioral_probes"]}
    assert all(not item["allowed"] for item in probes.values())
    assert all(item["handler_executions"] == 0 for item in probes.values())


def _replace_tool(
    recommendation: PolicyRecommendationV1,
    mutation: Callable[[ToolDecision], ToolDecision],
) -> PolicyRecommendationV1:
    return recommendation.model_copy(
        update={"decisions": [mutation(recommendation.decisions[0]), *recommendation.decisions[1:]]}
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.model_copy(update={"canonical_source_sha256": "sha256:" + "b" * 64}),
        lambda value: value.model_copy(update={"launch_sha256": "sha256:" + "b" * 64}),
        lambda value: _replace_tool(
            value,
            lambda decision: decision.model_copy(
                update={"tool": decision.tool.model_copy(update={"schema_sha256": "sha256:" + "b" * 64})}
            ),
        ),
        lambda value: value.model_copy(update={"evidence_sha256": "sha256:" + "b" * 64}),
        lambda value: value.model_copy(update={"target_runtime_version": "4.1.1"}),
    ],
    ids=["source", "launch", "schema", "evidence", "runtime"],
)
def test_changed_binding_invalidates_old_approval(
    mutate: Callable[[PolicyRecommendationV1], PolicyRecommendationV1],
    tmp_path: Path,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    changed = mutate(recommendation)

    with pytest.raises(ApprovalBindingError):
        apply_fixture_policy(
            evidence,
            changed,
            approval,
            state_dir,
        )


def test_changed_tool_set_fails_before_old_approval_can_apply(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    changed = recommendation.model_copy(update={"decisions": recommendation.decisions[:-1]})

    with pytest.raises(PolicyOutcomeError, match="unsupported policy translation"):
        apply_fixture_policy(evidence, changed, approval, state_dir)


def test_expired_approval_blocks_application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, _ = _bundle(tmp_path)
    approval = approve_recommendation(
        recommendation,
        approved_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        operator_label="fixture-operator",
    )
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(minutes=6),
    )
    with pytest.raises(ApprovalBindingError, match="expired"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)


def test_state_drift_blocks_application(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    recommendation = recommend_fixture_policy(
        evidence,
        created_at=NOW,
        expires_at=NOW + timedelta(hours=2),
        pre_state_sha256=state_digest(read_fixture_state(state_dir, evidence.subject)),
        rollback_id="rollback-fixture-002",
    )
    approval = _approval(recommendation)
    drifted = FixturePolicyState(subject=evidence.subject, denied_tools=["drifted_tool"])
    (state_dir / "state.json").write_bytes(canonical_json_bytes(drifted))

    with pytest.raises(ApprovalBindingError, match="pre-state"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)


def test_runtime_version_is_exactly_pinned() -> None:
    import importlib.metadata

    assert importlib.metadata.version("agent-governance-toolkit-core") == "4.1.0"


def test_runtime_version_drift_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement.importlib.metadata.version",
        lambda distribution: "4.1.1",
    )

    with pytest.raises(PolicyOutcomeError, match="version mismatch"):
        verify_target_runtime()


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("observed-evidence-v1.schema.json", ObservedEvidenceV1),
        ("policy-recommendation-v1.schema.json", PolicyRecommendationV1),
        ("approved-policy-intent-v1.schema.json", ApprovedPolicyIntentV1),
        ("effective-state-v1.schema.json", EffectiveStateV1),
    ],
)
def test_checked_in_schemas_match_models(filename: str, model: Any) -> None:
    expected = json.loads((Path("examples/schemas") / filename).read_text(encoding="utf-8"))
    assert expected == model.model_json_schema()


def _write_json(path: Path, value: BaseModelLike) -> None:
    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json")
    else:
        payload = value
    path.write_text(json.dumps(payload), encoding="utf-8")


BaseModelLike = Any


def test_cli_success_emits_exactly_one_json_object_and_no_secret_values(tmp_path: Path) -> None:
    recommendation = _recommendation(_evidence(), _state_dir(tmp_path))
    path = tmp_path / "recommendation.json"
    _write_json(path, recommendation)

    result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "approve",
            "--recommendation",
            str(path),
            "--approved-at",
            "2026-07-20T12:01:00Z",
            "--expires-at",
            "2026-07-20T13:00:00Z",
            "--operator-label",
            "fixture-operator",
        ],
    )

    assert result.exit_code == 0
    assert len(result.stdout.strip().splitlines()) == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "approved"
    assert "planted-secret" not in result.stdout


def test_cli_invalid_input_is_exit_2_with_one_json_object(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{", encoding="utf-8")

    result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "approve",
            "--recommendation",
            str(path),
            "--approved-at",
            "2026-07-20T12:01:00Z",
            "--expires-at",
            "2026-07-20T13:00:00Z",
            "--operator-label",
            "fixture-operator",
        ],
    )

    assert result.exit_code == 2
    assert len(result.stdout.strip().splitlines()) == 1
    assert json.loads(result.stdout)["status"] == "invalid_input"
    assert result.stderr


def test_cli_usage_error_is_exit_2_with_one_json_object() -> None:
    result = CliRunner().invoke(
        cli.main,
        ["enforcement-fixture", "approve", "--recommendation", "/missing/fixture.json"],
    )

    assert result.exit_code == 2
    assert len(result.stdout.strip().splitlines()) == 1
    assert json.loads(result.stdout)["error"]["code"] == "invalid_input"
    assert result.stderr.strip() == "input validation failed"


def test_cli_policy_outcome_is_exit_1_with_one_json_object(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    _write_json(report_path, _report(status="failed"))

    result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "prepare",
            "--audit-report",
            str(report_path),
            "--origin",
            ORIGIN,
            "--server-name",
            SERVER,
            "--source-sha256",
            DIGEST_A,
            "--provenance",
            "synthetic-connected-audit-report-v1",
            "--created-at",
            "2026-07-20T12:00:00Z",
            "--expires-at",
            "2026-07-20T14:00:00Z",
            "--rollback-id",
            "rollback-fixture-001",
            "--state-dir",
            str(_state_dir(tmp_path)),
        ],
    )

    assert result.exit_code == 1
    assert len(result.stdout.strip().splitlines()) == 1
    assert json.loads(result.stdout)["status"] == "blocked"
    assert result.stderr


def test_rollback_snapshot_cannot_replay_after_restore(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    rollback_fixture_policy(
        state_dir,
        subject=evidence.subject,
        rollback_id=recommendation.rollback_id,
        rolled_back_at=NOW + timedelta(minutes=3),
    )

    with pytest.raises(ApprovalBindingError, match="current state"):
        rollback_fixture_policy(
            state_dir,
            subject=evidence.subject,
            rollback_id=recommendation.rollback_id,
            rolled_back_at=NOW + timedelta(minutes=4),
        )


def test_connected_but_stale_evidence_cannot_recommend_or_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(minutes=16),
    )
    stale = _evidence()
    assert stale.connected
    assert stale.stale
    with pytest.raises(PolicyOutcomeError, match="stale"):
        recommend_fixture_policy(
            stale,
            created_at=NOW + timedelta(minutes=16),
            expires_at=NOW + timedelta(hours=1),
            pre_state_sha256=state_digest(default := FixturePolicyState(subject=stale.subject)),
            rollback_id="rollback-stale",
        )
    assert default.subject == stale.subject

    monkeypatch.setattr("mcp_audit.evidence_enforcement._utc_now", lambda: NOW)
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(minutes=16),
    )
    with pytest.raises(PolicyOutcomeError, match="stale"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)
    assert not state_dir.exists()


def test_recommendation_semantics_must_match_evidence(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, _ = _bundle(tmp_path)
    mismatched = recommendation.model_copy(
        update={
            "subject": ServerIdentity(
                origin="fixture://different-origin",
                server_name="different-server",
            )
        }
    )
    approval = _approval(mismatched)

    with pytest.raises(ApprovalBindingError, match="derive from evidence"):
        apply_fixture_policy(evidence, mismatched, approval, state_dir)
    assert not state_dir.exists()


def test_application_uses_trusted_clock_and_rejects_future_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert "now" not in inspect.signature(apply_fixture_policy).parameters
    help_result = CliRunner().invoke(cli.main, ["enforcement-fixture", "apply", "--help"])
    assert help_result.exit_code == 0
    assert "--now" not in help_result.stdout

    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    monkeypatch.setattr(
        "mcp_audit.evidence_enforcement._utc_now",
        lambda: NOW + timedelta(seconds=30),
    )
    with pytest.raises(ApprovalBindingError, match="future-dated"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)
    assert not state_dir.exists()


def test_approval_is_revoked_after_rollback(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    rollback_fixture_policy(
        state_dir,
        subject=evidence.subject,
        rollback_id=recommendation.rollback_id,
        rolled_back_at=NOW + timedelta(minutes=3),
    )

    with pytest.raises(ApprovalBindingError, match="revoked"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)


def test_secret_like_references_are_rejected_and_cli_redacts_values(tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        RuntimeRestrictions(secret_reference_names=["sk-proj-planted-secret"])

    recommendation = _recommendation(_evidence(), _state_dir(tmp_path))
    payload = recommendation.model_dump(mode="json")
    payload["restrictions"]["secret_reference_names"] = ["FIXTURE_TOKEN=planted-secret"]
    path = tmp_path / "secret-bearing-recommendation.json"
    _write_json(path, payload)
    result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "approve",
            "--recommendation",
            str(path),
            "--approved-at",
            "2026-07-20T12:01:00Z",
            "--expires-at",
            "2026-07-20T13:00:00Z",
            "--operator-label",
            "fixture-operator",
        ],
    )

    assert result.exit_code == 2
    assert len(result.stdout.strip().splitlines()) == 1
    assert "planted-secret" not in result.stdout
    assert "planted-secret" not in result.stderr


def test_unexpected_cli_exception_is_one_fail_closed_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recommendation = _recommendation(_evidence(), _state_dir(tmp_path))
    path = tmp_path / "recommendation.json"
    _write_json(path, recommendation)

    def fail_unexpectedly(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise RuntimeError("planted-secret")

    monkeypatch.setattr(
        "mcp_audit.enforcement_cli.approve_recommendation",
        fail_unexpectedly,
    )
    result = CliRunner().invoke(
        cli.main,
        [
            "enforcement-fixture",
            "approve",
            "--recommendation",
            str(path),
            "--approved-at",
            "2026-07-20T12:01:00Z",
            "--expires-at",
            "2026-07-20T13:00:00Z",
            "--operator-label",
            "fixture-operator",
        ],
    )

    assert result.exit_code == 1
    assert len(result.stdout.strip().splitlines()) == 1
    assert json.loads(result.stdout)["error"]["code"] == "fail_closed"
    assert "planted-secret" not in result.stdout
    assert "planted-secret" not in result.stderr


def test_fixture_directory_and_temporary_symlinks_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "canary"
    canary.write_text("unchanged", encoding="utf-8")
    linked_state = _state_dir(tmp_path)
    linked_state.symlink_to(outside, target_is_directory=True)
    evidence = _evidence()
    with pytest.raises(ValueError, match="symbolic link"):
        read_fixture_state(linked_state, evidence.subject)
    assert canary.read_text(encoding="utf-8") == "unchanged"

    linked_state.unlink()
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    current = read_fixture_state(state_dir, evidence.subject)
    drifted = current.model_copy(update={"denied_tools": []})
    enforcement._atomic_write(state_dir / "state.json", canonical_json_bytes(drifted))
    changed = recommendation.model_copy(
        update={
            "pre_state_sha256": state_digest(drifted),
            "rollback_id": "rollback-fixture-002",
        }
    )
    changed_approval = _approval(changed)
    state_bytes = (state_dir / "state.json").read_bytes()
    temporary = state_dir / "state.json.tmp"
    temporary.symlink_to(canary)

    with pytest.raises(ValueError, match="symbolic link"):
        apply_fixture_policy(evidence, changed, changed_approval, state_dir)
    assert canary.read_text(encoding="utf-8") == "unchanged"
    assert (state_dir / "state.json").read_bytes() == state_bytes
    temporary.unlink()
    assert read_fixture_state(state_dir, evidence.subject) == drifted


def test_rollback_probe_failure_never_leaves_partial_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    applied = read_fixture_state(state_dir, evidence.subject)
    original_probe = enforcement.probe_fixture_state
    calls = 0

    def fail_after_write(state: FixturePolicyState) -> list[enforcement.BehavioralProbe]:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("post-write probe failure")
        return original_probe(state)

    monkeypatch.setattr(enforcement, "probe_fixture_state", fail_after_write)
    with pytest.raises(PolicyOutcomeError, match="applied state was restored"):
        rollback_fixture_policy(
            state_dir,
            subject=evidence.subject,
            rollback_id=recommendation.rollback_id,
            rolled_back_at=NOW + timedelta(minutes=3),
        )

    assert read_fixture_state(state_dir, evidence.subject) == applied
    with pytest.raises(ApprovalBindingError, match="revoked"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)


def test_apply_rereads_persisted_state_and_compensates_false_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    original_write = enforcement._write_fixture_state

    def corrupt_after_write(
        target_dir: Path,
        state: FixturePolicyState,
        *,
        prior: FixturePolicyState,
        rollback_id: str,
        approval_sha256: str,
    ) -> None:
        original_write(
            target_dir,
            state,
            prior=prior,
            rollback_id=rollback_id,
            approval_sha256=approval_sha256,
        )
        corrupted = state.model_copy(update={"denied_tools": ["corrupted_fixture"]})
        enforcement._atomic_write(
            target_dir / "state.json",
            canonical_json_bytes(corrupted),
        )

    monkeypatch.setattr(enforcement, "_write_fixture_state", corrupt_after_write)
    with pytest.raises(PolicyOutcomeError, match="prior state was restored"):
        apply_fixture_policy(evidence, recommendation, approval, state_dir)

    assert read_fixture_state(state_dir, evidence.subject) == FixturePolicyState(subject=evidence.subject)


def test_apply_detects_prewrite_state_race_and_restores_prior_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    original_write = enforcement._write_fixture_state

    def race_before_write(
        target_dir: Path,
        state: FixturePolicyState,
        *,
        prior: FixturePolicyState,
        rollback_id: str,
        approval_sha256: str,
    ) -> None:
        drifted = prior.model_copy(update={"allowed_tools": ["read_fixture"]})
        enforcement._atomic_write(
            target_dir / "state.json",
            canonical_json_bytes(drifted),
        )
        original_write(
            target_dir,
            state,
            prior=prior,
            rollback_id=rollback_id,
            approval_sha256=approval_sha256,
        )

    monkeypatch.setattr(enforcement, "_write_fixture_state", race_before_write)
    with pytest.raises(PolicyOutcomeError, match="prior state was restored") as exc_info:
        apply_fixture_policy(evidence, recommendation, approval, state_dir)

    assert isinstance(exc_info.value.__cause__, ApprovalBindingError)
    assert "pre-state changed before write" in str(exc_info.value.__cause__)
    assert read_fixture_state(state_dir, evidence.subject) == FixturePolicyState(subject=evidence.subject)
    assert not (state_dir / "rollback.json").exists()


def test_failed_second_apply_restores_prior_rollback_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    apply_fixture_policy(evidence, recommendation, approval, state_dir)
    current = read_fixture_state(state_dir, evidence.subject)
    rollback_path = state_dir / "rollback.json"
    previous_rollback = rollback_path.read_bytes()
    drifted = current.model_copy(update={"denied_tools": []})
    enforcement._atomic_write(state_dir / "state.json", canonical_json_bytes(drifted))
    changed = recommendation.model_copy(
        update={
            "pre_state_sha256": state_digest(drifted),
            "rollback_id": "rollback-fixture-002",
        }
    )
    changed_approval = _approval(changed)
    original_write = enforcement._write_fixture_state

    def corrupt_after_write(
        target_dir: Path,
        state: FixturePolicyState,
        *,
        prior: FixturePolicyState,
        rollback_id: str,
        approval_sha256: str,
    ) -> None:
        original_write(
            target_dir,
            state,
            prior=prior,
            rollback_id=rollback_id,
            approval_sha256=approval_sha256,
        )
        corrupted = state.model_copy(update={"denied_tools": ["corrupted_fixture"]})
        enforcement._atomic_write(
            target_dir / "state.json",
            canonical_json_bytes(corrupted),
        )

    monkeypatch.setattr(enforcement, "_write_fixture_state", corrupt_after_write)
    with pytest.raises(PolicyOutcomeError, match="prior state was restored"):
        apply_fixture_policy(evidence, changed, changed_approval, state_dir)

    assert read_fixture_state(state_dir, evidence.subject) == drifted
    assert rollback_path.read_bytes() == previous_rollback


def test_public_schemas_require_identity_and_explicit_utc_patterns(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    result = apply_fixture_policy(evidence, recommendation, approval, state_dir)
    effective = EffectiveStateV1.model_validate(result["effective_state"])
    cases: list[tuple[Any, dict[str, Any], str]] = [
        (ObservedEvidenceV1, evidence.model_dump(mode="json"), "schema_version"),
        (
            PolicyRecommendationV1,
            recommendation.model_dump(mode="json"),
            "target_runtime_version",
        ),
        (ApprovedPolicyIntentV1, approval.model_dump(mode="json"), "target_adapter"),
        (EffectiveStateV1, effective.model_dump(mode="json"), "schema_version"),
    ]
    for model, payload, required_field in cases:
        payload.pop(required_field)
        with pytest.raises(ValidationError):
            model.model_validate(payload)
        schema = model.model_json_schema()
        assert required_field in schema["required"]

    timestamp_fields: list[tuple[Any, list[str]]] = [
        (ObservedEvidenceV1, ["observed_at"]),
        (PolicyRecommendationV1, ["created_at", "expires_at"]),
        (ApprovedPolicyIntentV1, ["approved_at", "expires_at"]),
        (EffectiveStateV1, ["applied_at"]),
    ]
    for model, fields in timestamp_fields:
        properties = model.model_json_schema()["properties"]
        for field in fields:
            assert properties[field]["format"] == "date-time"
            assert properties[field]["pattern"] == r"(?:Z|\+00:00)$"


def test_effective_state_rejects_contradictory_pass_summaries(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, approval = _bundle(tmp_path)
    result = apply_fixture_policy(evidence, recommendation, approval, state_dir)
    contradictory = dict(result["effective_state"])
    contradictory.update(
        {
            "audit_decisions": [],
            "behavioral_probes": [],
            "handler_counters": {},
            "supported_intent_matches": True,
            "negative_controls_passed": True,
        }
    )
    with pytest.raises(ValidationError, match="fixture probes"):
        EffectiveStateV1.model_validate(contradictory)


def test_unsupported_translation_causes_no_state_change(tmp_path: Path) -> None:
    state_dir, evidence, recommendation, _ = _bundle(tmp_path)
    constrained = recommendation.model_copy(
        update={"restrictions": RuntimeRestrictions(filesystem_resources=["/synthetic/unsupported"])}
    )
    approval = _approval(constrained)
    with pytest.raises(PolicyOutcomeError, match="unsupported"):
        apply_fixture_policy(evidence, constrained, approval, state_dir)
    assert not state_dir.exists()
