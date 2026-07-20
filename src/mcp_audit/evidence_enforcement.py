"""Experimental fixture-only evidence-to-enforcement adapter.

This module intentionally targets one published Agent Governance Toolkit
runtime. It does not discover, wrap, launch, or reconfigure normal MCP servers.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Final, Literal, TypeVar

from agent_os.integrations.base import GovernancePolicy
from agent_os.mcp_gateway import ApprovalStatus, GatewayConfig, MCPGateway
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mcp_audit.models import AUDIT_REPORT_SCHEMA_VERSION, AuditReport

OBSERVED_EVIDENCE_SCHEMA: Final = "mcpaudit.observed-evidence.v1"
POLICY_RECOMMENDATION_SCHEMA: Final = "mcpaudit.policy-recommendation.v1"
APPROVED_POLICY_INTENT_SCHEMA: Final = "mcpaudit.approved-policy-intent.v1"
EFFECTIVE_STATE_SCHEMA: Final = "mcpaudit.effective-state.v1"
FIXTURE_STATE_SCHEMA: Final = "mcpaudit.enforcement-fixture-state.v1"
TARGET_ADAPTER: Final = "microsoft-agt-mcp-gateway"
TARGET_RUNTIME_DISTRIBUTION: Final = "agent-governance-toolkit-core"
TARGET_RUNTIME_VERSION: Final = "4.1.0"
FIXTURE_TOOLS: Final = ("read_fixture", "write_fixture", "delete_fixture")
STATE_DIR_PREFIX: Final = "mcpaudit-enforcement-fixture-"
STATE_OWNER_MARKER: Final = ".mcpaudit-enforcement-fixture-owner"
STATE_OWNER_VALUE: Final = "mcpaudit.enforcement-fixture-state-owner.v1\n"
REVOKED_APPROVALS_FILE: Final = "revoked-approvals.json"
STATE_LOCK_FILE: Final = ".mcpaudit-enforcement-fixture.lock"
MAX_EVIDENCE_AGE: Final = timedelta(minutes=15)
UTC_JSON_PATTERN: Final = r"(?:Z|\+00:00)$"

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
SecretReferenceName = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,127}$"),
]
UtcTimestamp = Annotated[
    datetime,
    Field(json_schema_extra={"pattern": UTC_JSON_PATTERN}),
]
T = TypeVar("T", bound=BaseModel)


class StrictModel(BaseModel):
    """Base for versioned enforcement contracts."""

    model_config = ConfigDict(extra="forbid")


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL = "approval"


FIXTURE_POLICY_DECISIONS: Final[tuple[tuple[str, Decision], ...]] = (
    ("delete_fixture", Decision.DENY),
    ("read_fixture", Decision.ALLOW),
    ("write_fixture", Decision.APPROVAL),
)


class ServerIdentity(StrictModel):
    origin: str = Field(min_length=1)
    server_name: str = Field(min_length=1)

    @property
    def qualified(self) -> str:
        return f"{self.origin}::{self.server_name}"


class ToolIdentity(StrictModel):
    origin_qualified_name: str = Field(min_length=1)
    name: str = Field(min_length=1)
    schema_sha256: Digest


class ArgumentConstraints(StrictModel):
    exact_equals: dict[str, str | int | bool | None] = Field(default_factory=dict)


class RuntimeRestrictions(StrictModel):
    network_egress: list[str] = Field(default_factory=list)
    filesystem_resources: list[str] = Field(default_factory=list)
    secret_reference_names: list[SecretReferenceName] = Field(default_factory=list)


class ToolDecision(StrictModel):
    tool: ToolIdentity
    decision: Decision
    argument_constraints: ArgumentConstraints = Field(default_factory=ArgumentConstraints)


class ObservedEvidenceV1(StrictModel):
    schema_version: Literal["mcpaudit.observed-evidence.v1"]
    observed_at: UtcTimestamp
    audit_report_schema_version: Literal[1]
    subject: ServerIdentity
    client_scope: str = Field(min_length=1)
    transport: str = Field(min_length=1)
    canonical_source_sha256: Digest
    launch_sha256: Digest
    tools: list[ToolIdentity] = Field(default_factory=list)
    connected: bool
    stale: bool = False
    warning_codes: list[str] = Field(default_factory=list)
    drifted: bool = False
    missing: bool = False
    masked: bool = False
    unverifiable: bool = False
    provenance: list[str] = Field(min_length=1)
    unknowns: list[str] = Field(default_factory=list)
    secret_reference_names: list[SecretReferenceName] = Field(default_factory=list)

    @model_validator(mode="after")
    def evidence_is_consistent(self) -> ObservedEvidenceV1:
        _require_utc(self.observed_at, "observed_at")
        names = [tool.origin_qualified_name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool identities must be unique")
        if any(tool.origin_qualified_name != f"{self.subject.qualified}::{tool.name}" for tool in self.tools):
            raise ValueError("tool identities must be origin-qualified to the evidence subject")
        RuntimeRestrictions(secret_reference_names=self.secret_reference_names)
        return self

    @property
    def authoritative(self) -> bool:
        return (
            self.connected
            and not self.stale
            and not self.warning_codes
            and not self.drifted
            and not self.missing
            and not self.masked
            and not self.unverifiable
            and not self.unknowns
        )


class PolicyRecommendationV1(StrictModel):
    schema_version: Literal["mcpaudit.policy-recommendation.v1"]
    evidence_sha256: Digest
    subject: ServerIdentity
    client_scope: str = Field(min_length=1)
    transport: str = Field(min_length=1)
    canonical_source_sha256: Digest
    launch_sha256: Digest
    decisions: list[ToolDecision] = Field(min_length=1)
    restrictions: RuntimeRestrictions = Field(default_factory=RuntimeRestrictions)
    created_at: UtcTimestamp
    expires_at: UtcTimestamp
    provenance: list[str] = Field(min_length=1)
    unknowns: list[str] = Field(default_factory=list)
    target_adapter: Literal["microsoft-agt-mcp-gateway"]
    target_runtime_distribution: Literal["agent-governance-toolkit-core"]
    target_runtime_version: Literal["4.1.0"]
    pre_state_sha256: Digest
    rollback_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def recommendation_is_consistent(self) -> PolicyRecommendationV1:
        _require_utc(self.created_at, "created_at")
        _require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise ValueError("recommendation expiry must follow creation")
        names = [item.tool.origin_qualified_name for item in self.decisions]
        if len(names) != len(set(names)):
            raise ValueError("tool decisions must be unique")
        if any(
            item.tool.origin_qualified_name != f"{self.subject.qualified}::{item.tool.name}"
            for item in self.decisions
        ):
            raise ValueError("tool decisions must be origin-qualified to the recommendation subject")
        return self


class ApprovedPolicyIntentV1(StrictModel):
    schema_version: Literal["mcpaudit.approved-policy-intent.v1"]
    recommendation_sha256: Digest
    evidence_sha256: Digest
    subject: ServerIdentity
    target_adapter: Literal["microsoft-agt-mcp-gateway"]
    target_runtime_version: Literal["4.1.0"]
    pre_state_sha256: Digest
    approved_at: UtcTimestamp
    expires_at: UtcTimestamp
    operator_label: str = Field(min_length=1)
    rollback_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def approval_is_consistent(self) -> ApprovedPolicyIntentV1:
        _require_utc(self.approved_at, "approved_at")
        _require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must follow approval time")
        return self


class AuditDecision(StrictModel):
    tool_name: str
    allowed: bool
    reason: str
    approval_status: Literal["pending", "approved", "denied"] | None = None


class BehavioralProbe(StrictModel):
    tool_name: str
    allowed: bool
    handler_executions: int = Field(ge=0)
    reason: str


class GatewayConfigReadback(StrictModel):
    policy_name: str
    allowed_tools: list[str]
    denied_tools: list[str]
    sensitive_tools: list[str]
    rate_limit: int
    builtin_sanitization: bool


class EffectiveStateV1(StrictModel):
    schema_version: Literal["mcpaudit.effective-state.v1"]
    subject: ServerIdentity
    target_adapter: Literal["microsoft-agt-mcp-gateway"]
    target_runtime_distribution: Literal["agent-governance-toolkit-core"]
    target_runtime_version: Literal["4.1.0"]
    applied_at: UtcTimestamp
    allowed_tools: list[str]
    denied_tools: list[str]
    approval_tools: list[str]
    gateway_config: GatewayConfigReadback
    audit_decisions: list[AuditDecision]
    behavioral_probes: list[BehavioralProbe]
    fail_closed_runtime_error: bool
    handler_counters: dict[str, int]
    supported_intent_matches: bool
    negative_controls_passed: bool

    @model_validator(mode="after")
    def effective_state_is_consistent(self) -> EffectiveStateV1:
        _require_utc(self.applied_at, "applied_at")
        if self.allowed_tools != self.gateway_config.allowed_tools:
            raise ValueError("effective allowed tools must match gateway readback")
        if self.denied_tools != self.gateway_config.denied_tools:
            raise ValueError("effective denied tools must match gateway readback")
        if self.approval_tools != self.gateway_config.sensitive_tools:
            raise ValueError("effective approval tools must match gateway readback")
        supported = (
            self.allowed_tools == self.gateway_config.allowed_tools
            and self.denied_tools == self.gateway_config.denied_tools
            and self.approval_tools == self.gateway_config.sensitive_tools
        )
        if self.supported_intent_matches != supported:
            raise ValueError("supported-intent summary contradicts gateway readback")
        expected_names = {*FIXTURE_TOOLS, "unknown_fixture"}
        probes = {probe.tool_name: probe for probe in self.behavioral_probes}
        if set(probes) != expected_names or len(probes) != len(self.behavioral_probes):
            raise ValueError("effective state must include exactly the fixture probes")
        if set(self.handler_counters) != expected_names:
            raise ValueError("handler counters must include exactly the fixture probes")
        for name, probe in probes.items():
            if self.handler_counters[name] != probe.handler_executions:
                raise ValueError("handler counters must match behavioral probes")
            expected_allowed = (
                name in self.allowed_tools
                and name not in self.denied_tools
                and name not in self.approval_tools
            )
            if probe.allowed != expected_allowed:
                raise ValueError("behavioral probe contradicts effective policy")
            if probe.handler_executions != (1 if expected_allowed else 0):
                raise ValueError("behavioral probe contradicts handler execution count")
        audit_by_name = {decision.tool_name: decision for decision in self.audit_decisions}
        if set(audit_by_name) != expected_names or len(audit_by_name) != len(self.audit_decisions):
            raise ValueError("effective state must include exactly the fixture audit decisions")
        if any(audit_by_name[name].allowed != probes[name].allowed for name in expected_names):
            raise ValueError("audit decisions must match behavioral probes")
        negative_controls = self.fail_closed_runtime_error and all(
            (
                probes[name].allowed and probes[name].handler_executions == 1
                if name == "read_fixture" and name in self.allowed_tools
                else not probes[name].allowed and probes[name].handler_executions == 0
            )
            for name in expected_names
        )
        if self.negative_controls_passed != negative_controls:
            raise ValueError("negative-control summary contradicts probe evidence")
        return self


class FixturePolicyState(StrictModel):
    schema_version: Literal["mcpaudit.enforcement-fixture-state.v1"] = FIXTURE_STATE_SCHEMA
    subject: ServerIdentity
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    approval_tools: list[str] = Field(default_factory=list)
    target_runtime_version: Literal["4.1.0"] = TARGET_RUNTIME_VERSION


class RevokedApprovalLedger(StrictModel):
    schema_version: Literal["mcpaudit.revoked-approvals.v1"] = "mcpaudit.revoked-approvals.v1"
    approval_sha256: list[Digest] = Field(default_factory=list)


class UnsupportedTranslation(StrictModel):
    code: str
    field: str
    message: str


class CompiledPolicy(StrictModel):
    supported: bool
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    approval_tools: list[str] = Field(default_factory=list)
    errors: list[UnsupportedTranslation] = Field(default_factory=list)


class ApprovalBindingError(ValueError):
    """Approval does not bind the current evidence, recommendation, or state."""


class PolicyOutcomeError(RuntimeError):
    """A valid request failed closed under policy or runtime verification."""


def canonical_json_bytes(value: BaseModel | dict[str, Any] | list[Any]) -> bytes:
    payload: Any = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def digest_model(value: BaseModel | dict[str, Any] | list[Any]) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def observed_evidence_from_report(
    report: AuditReport,
    *,
    origin: str,
    server_name: str,
    canonical_source_sha256: str,
    provenance: list[str],
) -> ObservedEvidenceV1:
    """Extract connected synthetic evidence without changing AuditReport v1."""
    if report.schema_version != AUDIT_REPORT_SCHEMA_VERSION:
        raise ValueError("AuditReport schema version must be 1")
    matches = [audit for audit in report.audits if audit.server.name == server_name]
    if len(matches) != 1:
        raise ValueError("report must contain exactly one matching server")
    audit = matches[0]
    subject = ServerIdentity(origin=origin, server_name=server_name)
    tools = [
        ToolIdentity(
            origin_qualified_name=f"{subject.qualified}::{tool.name}",
            name=tool.name,
            schema_sha256=digest_model(tool.input_schema or {}),
        )
        for tool in sorted(audit.tools, key=lambda item: item.name)
    ]
    launch_payload = {
        "client": audit.server.client.value,
        "scope": audit.server.project_path or "global",
        "transport": audit.server.transport.value,
        "command": audit.server.command,
        "args": audit.server.args,
        "url": audit.server.url,
        "env_key_names": sorted(audit.server.env_keys),
        "header_key_names": sorted(audit.server.headers_keys),
    }
    observed_at = report.scan_timestamp.astimezone(UTC)
    now = _utc_now()
    return ObservedEvidenceV1(
        schema_version=OBSERVED_EVIDENCE_SCHEMA,
        observed_at=report.scan_timestamp.astimezone(UTC),
        audit_report_schema_version=1,
        subject=subject,
        client_scope=audit.server.project_path or "global",
        transport=audit.server.transport.value,
        canonical_source_sha256=canonical_source_sha256,
        launch_sha256=digest_model(launch_payload),
        tools=tools,
        connected=audit.connection_status == "connected",
        stale=_evidence_is_stale(observed_at, now),
        warning_codes=sorted(warning.code for warning in report.warnings),
        drifted=any(
            (
                audit.drift_findings,
                audit.provenance_findings,
                audit.integrity_findings,
                audit.package_verify_findings,
                audit.artifact_verify_findings,
            )
        ),
        missing=not tools,
        masked=False,
        unverifiable=audit.connection_status != "connected",
        provenance=provenance,
        unknowns=[] if audit.connection_status == "connected" else ["server_not_connected"],
        secret_reference_names=sorted(set(audit.server.env_keys + audit.server.headers_keys)),
    )


def recommend_fixture_policy(
    evidence: ObservedEvidenceV1,
    *,
    created_at: datetime,
    expires_at: datetime,
    pre_state_sha256: str,
    rollback_id: str,
) -> PolicyRecommendationV1:
    """Create the fixed three-tool recommendation only from authoritative evidence."""
    _require_utc(created_at, "created_at")
    _require_evidence_freshness(evidence, as_of=created_at)
    if not evidence.authoritative:
        raise PolicyOutcomeError("evidence is not authoritative enough to recommend an allow")
    by_name = {tool.name: tool for tool in evidence.tools}
    if set(by_name) != set(FIXTURE_TOOLS):
        raise PolicyOutcomeError("fixture evidence must expose exactly the three fixture tools")
    decisions = [
        ToolDecision(tool=by_name["read_fixture"], decision=Decision.ALLOW),
        ToolDecision(tool=by_name["write_fixture"], decision=Decision.APPROVAL),
        ToolDecision(tool=by_name["delete_fixture"], decision=Decision.DENY),
    ]
    return PolicyRecommendationV1(
        schema_version=POLICY_RECOMMENDATION_SCHEMA,
        evidence_sha256=digest_model(evidence),
        subject=evidence.subject,
        client_scope=evidence.client_scope,
        transport=evidence.transport,
        canonical_source_sha256=evidence.canonical_source_sha256,
        launch_sha256=evidence.launch_sha256,
        decisions=decisions,
        restrictions=RuntimeRestrictions(secret_reference_names=evidence.secret_reference_names),
        created_at=created_at,
        expires_at=expires_at,
        provenance=[*evidence.provenance, "mcpaudit:fixture-recommendation-v1"],
        unknowns=list(evidence.unknowns),
        target_adapter=TARGET_ADAPTER,
        target_runtime_distribution=TARGET_RUNTIME_DISTRIBUTION,
        target_runtime_version=TARGET_RUNTIME_VERSION,
        pre_state_sha256=pre_state_sha256,
        rollback_id=rollback_id,
    )


def approve_recommendation(
    recommendation: PolicyRecommendationV1,
    *,
    approved_at: datetime,
    expires_at: datetime,
    operator_label: str,
) -> ApprovedPolicyIntentV1:
    """Bind an operator's explicit approval to the exact recommendation."""
    if _fixture_decision_mapping(recommendation) != FIXTURE_POLICY_DECISIONS:
        raise PolicyOutcomeError("recommendation does not match the fixed fixture policy")
    if expires_at > recommendation.expires_at:
        raise ValueError("approval cannot outlive its recommendation")
    return ApprovedPolicyIntentV1(
        schema_version=APPROVED_POLICY_INTENT_SCHEMA,
        recommendation_sha256=digest_model(recommendation),
        evidence_sha256=recommendation.evidence_sha256,
        subject=recommendation.subject,
        target_adapter=TARGET_ADAPTER,
        target_runtime_version=TARGET_RUNTIME_VERSION,
        pre_state_sha256=recommendation.pre_state_sha256,
        approved_at=approved_at,
        expires_at=expires_at,
        operator_label=operator_label,
        rollback_id=recommendation.rollback_id,
    )


def compile_policy(recommendation: PolicyRecommendationV1) -> CompiledPolicy:
    """Compile only exact tool decisions; reject every unsupported constraint."""
    errors: list[UnsupportedTranslation] = []
    if _fixture_decision_mapping(recommendation) != FIXTURE_POLICY_DECISIONS:
        errors.append(
            UnsupportedTranslation(
                code="unsupported_translation",
                field="decisions",
                message="adapter v1 requires the exact fixed fixture decision mapping",
            )
        )
    restriction_fields = {
        "restrictions.network_egress": recommendation.restrictions.network_egress,
        "restrictions.filesystem_resources": recommendation.restrictions.filesystem_resources,
        "restrictions.secret_reference_names": recommendation.restrictions.secret_reference_names,
    }
    for field_name, value in restriction_fields.items():
        if value:
            errors.append(
                UnsupportedTranslation(
                    code="unsupported_translation",
                    field=field_name,
                    message="AGT MCPGateway v4.1.0 cannot enforce this restriction exactly",
                )
            )
    for item in recommendation.decisions:
        if item.argument_constraints.exact_equals:
            errors.append(
                UnsupportedTranslation(
                    code="unsupported_translation",
                    field=f"decisions.{item.tool.name}.argument_constraints",
                    message="adapter v1 does not translate argument constraints",
                )
            )
    if errors:
        return CompiledPolicy(supported=False, errors=errors)
    return CompiledPolicy(
        supported=True,
        allowed_tools=sorted(
            item.tool.name
            for item in recommendation.decisions
            if item.decision in {Decision.ALLOW, Decision.APPROVAL}
        ),
        denied_tools=sorted(
            item.tool.name for item in recommendation.decisions if item.decision is Decision.DENY
        ),
        approval_tools=sorted(
            item.tool.name for item in recommendation.decisions if item.decision is Decision.APPROVAL
        ),
    )


def _fixture_decision_mapping(
    recommendation: PolicyRecommendationV1,
) -> tuple[tuple[str, Decision], ...]:
    return tuple(sorted((item.tool.name, item.decision) for item in recommendation.decisions))


def validate_approval(
    evidence: ObservedEvidenceV1,
    recommendation: PolicyRecommendationV1,
    approval: ApprovedPolicyIntentV1,
    *,
    current_state_sha256: str,
    now: datetime,
    identical_reapplication: bool = False,
) -> None:
    """Reject replay across any evidence, subject, runtime, state, or expiry change."""
    _require_utc(now, "now")
    validate_recommendation_matches_evidence(evidence, recommendation)
    _require_evidence_freshness(evidence, as_of=now)
    bindings: list[tuple[str, object, object]] = [
        ("evidence digest", digest_model(evidence), recommendation.evidence_sha256),
        ("recommendation evidence", recommendation.evidence_sha256, approval.evidence_sha256),
        ("recommendation digest", digest_model(recommendation), approval.recommendation_sha256),
        ("subject", recommendation.subject, approval.subject),
        ("target adapter", recommendation.target_adapter, approval.target_adapter),
        (
            "runtime version",
            recommendation.target_runtime_version,
            approval.target_runtime_version,
        ),
        ("approved pre-state", recommendation.pre_state_sha256, approval.pre_state_sha256),
        ("rollback identity", recommendation.rollback_id, approval.rollback_id),
    ]
    mismatches = [label for label, left, right in bindings if left != right]
    if mismatches:
        raise ApprovalBindingError("approval binding mismatch: " + ", ".join(mismatches))
    if not identical_reapplication and current_state_sha256 != recommendation.pre_state_sha256:
        raise ApprovalBindingError("approval binding mismatch: pre-state")
    if now > recommendation.expires_at or now > approval.expires_at:
        raise ApprovalBindingError("approval or recommendation has expired")
    if recommendation.created_at > now or approval.approved_at > now:
        raise ApprovalBindingError("recommendation or approval is future-dated")
    if approval.approved_at < recommendation.created_at:
        raise ApprovalBindingError("approval predates recommendation")


def validate_recommendation_matches_evidence(
    evidence: ObservedEvidenceV1,
    recommendation: PolicyRecommendationV1,
) -> None:
    """Require every duplicated recommendation identity to derive from the evidence."""
    evidence_tools = sorted(
        (tool.origin_qualified_name, tool.name, tool.schema_sha256) for tool in evidence.tools
    )
    recommendation_tools = sorted(
        (
            item.tool.origin_qualified_name,
            item.tool.name,
            item.tool.schema_sha256,
        )
        for item in recommendation.decisions
    )
    bindings: list[tuple[str, object, object]] = [
        ("evidence digest", digest_model(evidence), recommendation.evidence_sha256),
        ("subject", evidence.subject, recommendation.subject),
        ("client scope", evidence.client_scope, recommendation.client_scope),
        ("transport", evidence.transport, recommendation.transport),
        (
            "canonical source",
            evidence.canonical_source_sha256,
            recommendation.canonical_source_sha256,
        ),
        ("launch identity", evidence.launch_sha256, recommendation.launch_sha256),
        ("tool identities", evidence_tools, recommendation_tools),
        ("unknowns", evidence.unknowns, recommendation.unknowns),
        (
            "secret references",
            sorted(evidence.secret_reference_names),
            sorted(recommendation.restrictions.secret_reference_names),
        ),
        (
            "provenance",
            [*evidence.provenance, "mcpaudit:fixture-recommendation-v1"],
            recommendation.provenance,
        ),
    ]
    mismatches = [label for label, expected, actual in bindings if expected != actual]
    if mismatches:
        raise ApprovalBindingError("recommendation does not derive from evidence: " + ", ".join(mismatches))


def default_fixture_state(subject: ServerIdentity) -> FixturePolicyState:
    return FixturePolicyState(subject=subject)


def state_digest(state: FixturePolicyState) -> str:
    return digest_model(state)


def read_fixture_state(state_dir: Path, subject: ServerIdentity) -> FixturePolicyState:
    _validate_fixture_state_dir(state_dir)
    path = state_dir / "state.json"
    if not _path_exists_without_following(path):
        return default_fixture_state(subject)
    state = FixturePolicyState.model_validate_json(_read_managed_text(path))
    if state.subject != subject:
        raise ApprovalBindingError("fixture state belongs to a different subject")
    return state


def intended_fixture_state(
    recommendation: PolicyRecommendationV1, compiled: CompiledPolicy
) -> FixturePolicyState:
    if not compiled.supported:
        raise PolicyOutcomeError("unsupported policy translation")
    return FixturePolicyState(
        subject=recommendation.subject,
        allowed_tools=compiled.allowed_tools,
        denied_tools=compiled.denied_tools,
        approval_tools=compiled.approval_tools,
    )


def dry_run_diff(
    evidence: ObservedEvidenceV1,
    recommendation: PolicyRecommendationV1,
    state_dir: Path,
) -> dict[str, Any]:
    """Return deterministic digests and set deltas without writing fixture state."""
    verify_target_runtime()
    validate_recommendation_matches_evidence(evidence, recommendation)
    _require_evidence_freshness(evidence, as_of=recommendation.created_at)
    current = read_fixture_state(state_dir, recommendation.subject)
    compiled = compile_policy(recommendation)
    intended = intended_fixture_state(recommendation, compiled) if compiled.supported else None
    return {
        "evidence_sha256": digest_model(evidence),
        "recommendation_sha256": digest_model(recommendation),
        "target_runtime_sha256": digest_model(
            {
                "adapter": TARGET_ADAPTER,
                "distribution": TARGET_RUNTIME_DISTRIBUTION,
                "version": TARGET_RUNTIME_VERSION,
            }
        ),
        "pre_state_sha256": state_digest(current),
        "intended_effective_state_sha256": state_digest(intended) if intended else None,
        "rollback_sha256": state_digest(current),
        "changes": {
            "allow": _set_diff(current.allowed_tools, intended.allowed_tools if intended else []),
            "deny": _set_diff(current.denied_tools, intended.denied_tools if intended else []),
            "approval": _set_diff(current.approval_tools, intended.approval_tools if intended else []),
        },
        "translation": compiled.model_dump(mode="json"),
    }


def apply_fixture_policy(
    evidence: ObservedEvidenceV1,
    recommendation: PolicyRecommendationV1,
    approval: ApprovedPolicyIntentV1,
    state_dir: Path,
) -> dict[str, Any]:
    """Atomically apply and behaviorally verify policy against in-process toy handlers."""
    now = _utc_now()
    verify_target_runtime()
    compiled = compile_policy(recommendation)
    if not compiled.supported:
        raise PolicyOutcomeError("unsupported policy translation")
    intended = intended_fixture_state(recommendation, compiled)
    approval_sha256 = digest_model(approval)
    current = read_fixture_state(state_dir, recommendation.subject)
    no_op = intended == current
    if approval_sha256 in _read_revoked_approvals(state_dir):
        raise ApprovalBindingError("approval has been revoked by rollback")
    if no_op:
        _validate_no_op_lineage(
            state_dir,
            current=current,
            recommendation=recommendation,
            approval_sha256=approval_sha256,
        )
    validate_approval(
        evidence,
        recommendation,
        approval,
        current_state_sha256=state_digest(current),
        now=now,
        identical_reapplication=no_op,
    )
    with _fixture_state_lock(state_dir):
        return _apply_fixture_policy_locked(
            evidence,
            recommendation,
            approval,
            state_dir,
            compiled=compiled,
            intended=intended,
            approval_sha256=approval_sha256,
        )


def _apply_fixture_policy_locked(
    evidence: ObservedEvidenceV1,
    recommendation: PolicyRecommendationV1,
    approval: ApprovedPolicyIntentV1,
    state_dir: Path,
    *,
    compiled: CompiledPolicy,
    intended: FixturePolicyState,
    approval_sha256: str,
) -> dict[str, Any]:
    """Recheck state under the fixture lock, then apply or verify an exact no-op."""
    current = read_fixture_state(state_dir, recommendation.subject)
    no_op = intended == current
    if approval_sha256 in _read_revoked_approvals(state_dir):
        raise ApprovalBindingError("approval has been revoked by rollback")
    if no_op:
        _validate_no_op_lineage(
            state_dir,
            current=current,
            recommendation=recommendation,
            approval_sha256=approval_sha256,
        )
    validate_approval(
        evidence,
        recommendation,
        approval,
        current_state_sha256=state_digest(current),
        now=_utc_now(),
        identical_reapplication=no_op,
    )
    persisted = current
    if no_op:
        effective = probe_effective_state(
            current,
            applied_at=approval.approved_at,
            expected=compiled,
        )
        if not effective.supported_intent_matches or not effective.negative_controls_passed:
            raise PolicyOutcomeError("effective-state or negative-control verification failed")
    else:
        rollback_path = state_dir / "rollback.json"
        previous_rollback = (
            _read_managed_text(rollback_path).encode()
            if _path_exists_without_following(rollback_path)
            else None
        )
        try:
            _write_fixture_state(
                state_dir,
                intended,
                prior=current,
                rollback_id=approval.rollback_id,
                approval_sha256=approval_sha256,
            )
            persisted = read_fixture_state(state_dir, recommendation.subject)
            if state_digest(persisted) != state_digest(intended):
                raise PolicyOutcomeError("persisted state did not match intended state")
            effective = probe_effective_state(
                persisted,
                applied_at=approval.approved_at,
                expected=compiled,
            )
            if not effective.supported_intent_matches or not effective.negative_controls_passed:
                raise PolicyOutcomeError("persisted state failed behavioral verification")
        except Exception as exc:
            try:
                try:
                    compensated = read_fixture_state(state_dir, recommendation.subject)
                except Exception:
                    _atomic_write(state_dir / "state.json", canonical_json_bytes(current))
                    compensated = read_fixture_state(state_dir, recommendation.subject)
                if state_digest(compensated) != state_digest(current):
                    _atomic_write(state_dir / "state.json", canonical_json_bytes(current))
                    compensated = read_fixture_state(state_dir, recommendation.subject)
                if state_digest(compensated) != state_digest(current):
                    raise PolicyOutcomeError("application compensation readback failed")
                if previous_rollback is None:
                    _remove_managed_file(rollback_path)
                else:
                    _atomic_write(rollback_path, previous_rollback)
                restored_rollback = (
                    _read_managed_text(rollback_path).encode()
                    if _path_exists_without_following(rollback_path)
                    else None
                )
                if restored_rollback != previous_rollback:
                    raise PolicyOutcomeError("rollback-lineage compensation failed")
            except Exception as compensation_exc:
                raise PolicyOutcomeError(
                    "application verification failed and compensation failed"
                ) from compensation_exc
            raise PolicyOutcomeError("application verification failed; prior state was restored") from exc
    return {
        "status": "no_op" if no_op else "applied",
        "no_op": no_op,
        "pre_state_sha256": state_digest(current),
        "effective_state": effective.model_dump(mode="json"),
        "effective_state_sha256": digest_model(effective),
        "stored_state_sha256": state_digest(persisted),
        "rollback_id": approval.rollback_id,
    }


def rollback_fixture_policy(
    state_dir: Path,
    *,
    subject: ServerIdentity,
    rollback_id: str,
    rolled_back_at: datetime,
) -> dict[str, Any]:
    """Restore the exact captured fixture state and verify its decisions."""
    _require_utc(rolled_back_at, "rolled_back_at")
    verify_target_runtime()
    _validate_fixture_state_dir(state_dir)
    snapshot_path = state_dir / "rollback.json"
    if not _path_exists_without_following(snapshot_path):
        raise ApprovalBindingError("rollback snapshot does not exist")
    with _fixture_state_lock(state_dir):
        return _rollback_fixture_policy_locked(
            state_dir,
            subject=subject,
            rollback_id=rollback_id,
            rolled_back_at=rolled_back_at,
        )


def _rollback_fixture_policy_locked(
    state_dir: Path,
    *,
    subject: ServerIdentity,
    rollback_id: str,
    rolled_back_at: datetime,
) -> dict[str, Any]:
    """Recheck and restore the captured state while holding the fixture lock."""
    snapshot_path = state_dir / "rollback.json"
    if not _path_exists_without_following(snapshot_path):
        raise ApprovalBindingError("rollback snapshot does not exist")
    payload = json.loads(_read_managed_text(snapshot_path))
    if payload.get("rollback_id") != rollback_id:
        raise ApprovalBindingError("rollback identity mismatch")
    prior = FixturePolicyState.model_validate(payload.get("prior_state"))
    if prior.subject != subject:
        raise ApprovalBindingError("rollback snapshot belongs to a different subject")
    captured_digest = payload.get("prior_state_sha256")
    if state_digest(prior) != captured_digest:
        raise ApprovalBindingError("rollback snapshot digest mismatch")
    current = read_fixture_state(state_dir, subject)
    if state_digest(current) != payload.get("applied_state_sha256"):
        raise ApprovalBindingError("current state does not match the rollback snapshot's applied state")
    approval_sha256 = payload.get("approval_sha256")
    if not isinstance(approval_sha256, str):
        raise ApprovalBindingError("rollback snapshot lacks approval identity")
    behavior = probe_fixture_state(prior)
    _revoke_approval(state_dir, approval_sha256)
    try:
        _atomic_write(state_dir / "state.json", canonical_json_bytes(prior))
        restored = read_fixture_state(state_dir, subject)
        if state_digest(restored) != captured_digest:
            raise PolicyOutcomeError("rollback readback did not match captured state")
        behavior = probe_fixture_state(restored)
    except Exception as exc:
        try:
            _atomic_write(state_dir / "state.json", canonical_json_bytes(current))
            compensated = read_fixture_state(state_dir, subject)
            if state_digest(compensated) != state_digest(current):
                raise PolicyOutcomeError("rollback compensation readback failed")
        except Exception as compensation_exc:
            raise PolicyOutcomeError(
                "rollback verification failed and compensation failed"
            ) from compensation_exc
        raise PolicyOutcomeError("rollback failed; applied state was restored") from exc
    return {
        "status": "rolled_back",
        "rollback_id": rollback_id,
        "rolled_back_at": rolled_back_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "restored_state_sha256": state_digest(restored),
        "captured_state_sha256": captured_digest,
        "behavioral_probes": [probe.model_dump(mode="json") for probe in behavior],
    }


def probe_effective_state(
    state: FixturePolicyState,
    *,
    applied_at: datetime,
    expected: CompiledPolicy,
) -> EffectiveStateV1:
    verify_target_runtime()
    policy = GovernancePolicy(
        name="mcpaudit-fixture",
        allowed_tools=state.allowed_tools or ["__mcpaudit_deny_all__"],
    )
    gateway = MCPGateway(
        policy,
        denied_tools=state.denied_tools,
        sensitive_tools=state.approval_tools,
    )
    config: GatewayConfig = MCPGateway.wrap_mcp_server(
        {"fixture": True},
        policy,
        denied_tools=state.denied_tools,
        sensitive_tools=state.approval_tools,
    )
    probes, counters = _exercise_gateway(gateway)

    def failing_callback(agent_id: str, tool_name: str, params: dict[str, Any]) -> ApprovalStatus:
        del agent_id, tool_name, params
        raise RuntimeError("synthetic approval failure")

    failing_gateway = MCPGateway(
        policy,
        denied_tools=state.denied_tools,
        sensitive_tools=state.approval_tools,
        approval_callback=failing_callback,
    )
    fail_closed = True
    if state.approval_tools:
        runtime_allowed, _ = failing_gateway.intercept_tool_call("fixture-agent", state.approval_tools[0], {})
        fail_closed = not runtime_allowed
    audit = [
        AuditDecision(
            tool_name=entry.tool_name,
            allowed=entry.allowed,
            reason=entry.reason,
            approval_status=entry.approval_status.value if entry.approval_status else None,
        )
        for entry in gateway.audit_log
    ]
    allowed_tools = sorted(config.allowed_tools)
    if allowed_tools == ["__mcpaudit_deny_all__"]:
        allowed_tools = []
    readback = GatewayConfigReadback(
        policy_name=config.policy_name,
        allowed_tools=allowed_tools,
        denied_tools=sorted(config.denied_tools),
        sensitive_tools=sorted(config.sensitive_tools),
        rate_limit=config.rate_limit,
        builtin_sanitization=config.builtin_sanitization,
    )
    supported_matches = (
        allowed_tools == expected.allowed_tools
        and sorted(config.denied_tools) == expected.denied_tools
        and sorted(config.sensitive_tools) == expected.approval_tools
    )
    by_name = {probe.tool_name: probe for probe in probes}
    negative_passed = (
        by_name["delete_fixture"].allowed is False
        and by_name["delete_fixture"].handler_executions == 0
        and by_name["unknown_fixture"].allowed is False
        and by_name["unknown_fixture"].handler_executions == 0
        and fail_closed
    )
    if "read_fixture" in state.allowed_tools:
        negative_passed = (
            negative_passed
            and by_name["read_fixture"].allowed
            and by_name["read_fixture"].handler_executions == 1
        )
    if "write_fixture" in state.approval_tools:
        negative_passed = (
            negative_passed
            and not by_name["write_fixture"].allowed
            and by_name["write_fixture"].handler_executions == 0
        )
    return EffectiveStateV1(
        schema_version=EFFECTIVE_STATE_SCHEMA,
        subject=state.subject,
        target_adapter=TARGET_ADAPTER,
        target_runtime_distribution=TARGET_RUNTIME_DISTRIBUTION,
        target_runtime_version=TARGET_RUNTIME_VERSION,
        applied_at=applied_at.astimezone(UTC),
        allowed_tools=allowed_tools,
        denied_tools=sorted(config.denied_tools),
        approval_tools=sorted(config.sensitive_tools),
        gateway_config=readback,
        audit_decisions=audit,
        behavioral_probes=probes,
        fail_closed_runtime_error=fail_closed,
        handler_counters=counters,
        supported_intent_matches=supported_matches,
        negative_controls_passed=negative_passed,
    )


def probe_fixture_state(state: FixturePolicyState) -> list[BehavioralProbe]:
    expected = CompiledPolicy(
        supported=True,
        allowed_tools=state.allowed_tools,
        denied_tools=state.denied_tools,
        approval_tools=state.approval_tools,
    )
    return probe_effective_state(
        state,
        applied_at=datetime(1970, 1, 1, tzinfo=UTC),
        expected=expected,
    ).behavioral_probes


def parse_model(path: Path, model: type[T]) -> T:
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def verify_target_runtime() -> None:
    """Fail closed unless the exact published compatibility runtime is active."""
    try:
        installed = importlib.metadata.version(TARGET_RUNTIME_DISTRIBUTION)
    except importlib.metadata.PackageNotFoundError as exc:
        raise PolicyOutcomeError("target runtime distribution is not installed") from exc
    if installed != TARGET_RUNTIME_VERSION:
        raise PolicyOutcomeError(
            f"target runtime version mismatch: expected {TARGET_RUNTIME_VERSION}, found {installed}"
        )


def _exercise_gateway(gateway: MCPGateway) -> tuple[list[BehavioralProbe], dict[str, int]]:
    counters = {name: 0 for name in (*FIXTURE_TOOLS, "unknown_fixture")}
    handlers = {name: _fixture_handler(name, counters) for name in (*FIXTURE_TOOLS, "unknown_fixture")}
    probes: list[BehavioralProbe] = []
    for tool_name in (*FIXTURE_TOOLS, "unknown_fixture"):
        allowed, reason = gateway.intercept_tool_call("fixture-agent", tool_name, {})
        if allowed:
            handlers[tool_name]()
        probes.append(
            BehavioralProbe(
                tool_name=tool_name,
                allowed=allowed,
                handler_executions=counters[tool_name],
                reason=reason,
            )
        )
    return probes, counters


def _fixture_handler(tool_name: str, counters: dict[str, int]) -> Callable[[], None]:
    """Return a toy handler whose only effect is its program-owned invocation canary."""

    def handler() -> None:
        counters[tool_name] += 1

    return handler


def _write_fixture_state(
    state_dir: Path,
    state: FixturePolicyState,
    *,
    prior: FixturePolicyState,
    rollback_id: str,
    approval_sha256: str,
) -> None:
    _ensure_owned_fixture_state_dir(state_dir)
    observed = read_fixture_state(state_dir, prior.subject)
    if state_digest(observed) != state_digest(prior):
        raise ApprovalBindingError("approval binding mismatch: pre-state changed before write")
    rollback = {
        "rollback_id": rollback_id,
        "approval_sha256": approval_sha256,
        "prior_state": prior.model_dump(mode="json"),
        "prior_state_sha256": state_digest(prior),
        "applied_state_sha256": state_digest(state),
    }
    _atomic_write(state_dir / "rollback.json", canonical_json_bytes(rollback))
    _atomic_write(state_dir / "state.json", canonical_json_bytes(state))


def _atomic_write(path: Path, content: bytes) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    if _path_is_symlink(path) or _path_is_symlink(temporary):
        raise ValueError("fixture state paths must not be symbolic links")
    if _path_exists_without_following(temporary):
        raise ValueError("fixture temporary path already exists")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        if _path_is_symlink(path):
            raise ValueError("fixture state target became a symbolic link")
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if _path_exists_without_following(temporary):
            temporary.unlink()


def _validate_fixture_state_dir(state_dir: Path) -> None:
    if not state_dir.name.startswith(STATE_DIR_PREFIX):
        raise ValueError(f"fixture state directory name must start with {STATE_DIR_PREFIX!r}")
    if _path_is_symlink(state_dir):
        raise ValueError("fixture state directory must not be a symbolic link")
    if _path_exists_without_following(state_dir) and not state_dir.is_dir():
        raise ValueError("fixture state path must be a directory")
    managed_names = (
        STATE_OWNER_MARKER,
        STATE_LOCK_FILE,
        "state.json",
        "rollback.json",
        REVOKED_APPROVALS_FILE,
    )
    for name in managed_names:
        path = state_dir / name
        if _path_is_symlink(path) or _path_is_symlink(path.with_suffix(path.suffix + ".tmp")):
            raise ValueError("fixture state paths must not be symbolic links")
    marker = state_dir / STATE_OWNER_MARKER
    managed_state_exists = any(
        _path_exists_without_following(state_dir / name)
        for name in (STATE_LOCK_FILE, "state.json", "rollback.json", REVOKED_APPROVALS_FILE)
    )
    if managed_state_exists and not _path_exists_without_following(marker):
        raise ValueError("fixture state directory is missing its ownership marker")
    if _path_exists_without_following(marker) and _read_managed_text(marker) != STATE_OWNER_VALUE:
        raise ValueError("fixture state ownership marker is invalid")


def _ensure_owned_fixture_state_dir(state_dir: Path) -> None:
    _validate_fixture_state_dir(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    if _path_is_symlink(state_dir):
        raise ValueError("fixture state directory became a symbolic link")
    marker = state_dir / STATE_OWNER_MARKER
    if not _path_exists_without_following(marker):
        if any(state_dir.iterdir()):
            raise ValueError("unowned fixture state directory must be empty")
        _atomic_write(marker, STATE_OWNER_VALUE.encode())
    _validate_fixture_state_dir(state_dir)


@contextmanager
def _fixture_state_lock(state_dir: Path) -> Iterator[None]:
    """Serialize every fixture mutation and hold the same inode for all callers."""
    _ensure_owned_fixture_state_dir(state_dir)
    path = state_dir / STATE_LOCK_FILE
    if _path_is_symlink(path):
        raise ValueError("fixture lock must not be a symbolic link")
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        try:
            import fcntl
        except ImportError as exc:
            raise PolicyOutcomeError("platform file locking is unavailable") from exc
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _read_revoked_approvals(state_dir: Path) -> set[str]:
    _validate_fixture_state_dir(state_dir)
    path = state_dir / REVOKED_APPROVALS_FILE
    if not _path_exists_without_following(path):
        return set()
    ledger = RevokedApprovalLedger.model_validate_json(_read_managed_text(path))
    return set(ledger.approval_sha256)


def _validate_no_op_lineage(
    state_dir: Path,
    *,
    current: FixturePolicyState,
    recommendation: PolicyRecommendationV1,
    approval_sha256: str,
) -> None:
    """Allow no-op only when this exact approval created the current fixture state."""
    _validate_fixture_state_dir(state_dir)
    path = state_dir / "rollback.json"
    if not _path_exists_without_following(path):
        raise ApprovalBindingError("no-op state lacks exact approval and rollback lineage")
    payload = json.loads(_read_managed_text(path))
    prior = FixturePolicyState.model_validate(payload.get("prior_state"))
    bindings: list[tuple[str, object, object]] = [
        ("approval", payload.get("approval_sha256"), approval_sha256),
        ("rollback identity", payload.get("rollback_id"), recommendation.rollback_id),
        ("applied state", payload.get("applied_state_sha256"), state_digest(current)),
        ("approved pre-state", payload.get("prior_state_sha256"), recommendation.pre_state_sha256),
        ("captured pre-state", state_digest(prior), recommendation.pre_state_sha256),
        ("subject", prior.subject, recommendation.subject),
    ]
    mismatches = [label for label, actual, expected in bindings if actual != expected]
    if mismatches:
        raise ApprovalBindingError(
            "no-op state lacks exact approval and rollback lineage: " + ", ".join(mismatches)
        )


def _revoke_approval(state_dir: Path, approval_sha256: str) -> None:
    _ensure_owned_fixture_state_dir(state_dir)
    approvals = _read_revoked_approvals(state_dir)
    approvals.add(approval_sha256)
    ledger = RevokedApprovalLedger(approval_sha256=sorted(approvals))
    _atomic_write(state_dir / REVOKED_APPROVALS_FILE, canonical_json_bytes(ledger))


def _read_managed_text(path: Path) -> str:
    if _path_is_symlink(path):
        raise ValueError("fixture state paths must not be symbolic links")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        with os.fdopen(descriptor, "r", encoding="utf-8", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def _remove_managed_file(path: Path) -> None:
    if not _path_exists_without_following(path):
        return
    if _path_is_symlink(path):
        raise ValueError("fixture state paths must not be symbolic links")
    path.unlink()
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def _path_is_symlink(path: Path) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def _path_exists_without_following(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def _set_diff(before: list[str], after: list[str]) -> dict[str, list[str]]:
    return {
        "add": sorted(set(after) - set(before)),
        "remove": sorted(set(before) - set(after)),
    }


def _require_utc(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must be an explicit UTC timestamp")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _evidence_is_stale(observed_at: datetime, as_of: datetime) -> bool:
    _require_utc(observed_at, "observed_at")
    _require_utc(as_of, "as_of")
    return observed_at > as_of or as_of - observed_at > MAX_EVIDENCE_AGE


def _require_evidence_freshness(evidence: ObservedEvidenceV1, *, as_of: datetime) -> None:
    if evidence.stale or _evidence_is_stale(evidence.observed_at, as_of):
        raise PolicyOutcomeError("evidence is stale or future-dated")
