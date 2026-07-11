"""SafeForge Pipeline manifest v0 contract and fail-closed validator.

This module defines the portable evidence envelope only. It does not generate,
install, launch, scan, grade, or publish an MCP server.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

SAFEFORGE_CONTRACT_ID: Literal["safeforge.pipeline"] = "safeforge.pipeline"
SAFEFORGE_CONTRACT_VERSION: Literal["0.1.0"] = "0.1.0"
SAFEFORGE_PROFILE: Literal["research-mvp"] = "research-mvp"

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$")]
ToolName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")]
EnvKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StageId(StrEnum):
    SOURCE_BIND = "source.bind"
    FORGE_PLAN = "forge.plan"
    FORGE_GENERATE = "forge.generate"
    VALIDATE_STATIC = "validate.static"
    CONTRACT_PREINSTALL = "contract.preinstall"
    AUDIT_CONFIG = "audit.config"
    SANDBOX_PREPARE = "sandbox.prepare"
    SANDBOX_MATERIALIZE = "sandbox.materialize"
    AUDIT_CONNECTED = "audit.connected"
    TRUST_GRADE = "trust.grade"
    RUNTIME_POLICY_BIND = "runtime.policy.bind"
    PUBLICATION_DRY_RUN = "publication.dry_run"
    RECEIPT_FINALIZE = "receipt.finalize"


RESEARCH_MVP_STAGE_ORDER: tuple[StageId, ...] = tuple(StageId)


class StageState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"
    STALE = "stale"
    BLOCKED = "blocked"


class PipelineDecision(StrEnum):
    BUILDING = "building"
    ELIGIBLE = "eligible"
    BLOCKED = "blocked"
    STALE = "stale"


class FindingSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


class ContractHeader(_StrictModel):
    contract_id: Literal["safeforge.pipeline"] = SAFEFORGE_CONTRACT_ID
    contract_version: Literal["0.1.0"] = SAFEFORGE_CONTRACT_VERSION
    profile: Literal["research-mvp"] = SAFEFORGE_PROFILE


class ProducerIdentity(_StrictModel):
    name: Identifier
    version: str = Field(min_length=1)
    source: str = Field(min_length=1, description="Package or repository identity; never a secret URL.")
    revision: str = Field(min_length=1)
    dirty: bool
    executable: str | None = None


class RunInfo(_StrictModel):
    run_id: Identifier
    created_at: datetime
    coordinator: ProducerIdentity
    decision: PipelineDecision = PipelineDecision.BUILDING


class Subject(_StrictModel):
    server_id: Identifier
    source_kind: Literal["natural-language", "openapi", "structured-plan", "scaffold"]
    source_spec_digest: Digest
    transport: Literal["stdio", "streamable-http"]
    mcp_protocol_supported: list[str] = Field(min_length=1)
    mcp_protocol_negotiated: str | None = None

    @model_validator(mode="after")
    def negotiated_protocol_is_supported(self) -> Subject:
        if (
            self.mcp_protocol_negotiated is not None
            and self.mcp_protocol_negotiated not in self.mcp_protocol_supported
        ):
            raise ValueError("negotiated MCP protocol must be listed in mcp_protocol_supported")
        return self


class ArtifactReference(_StrictModel):
    artifact_id: Identifier
    media_type: str = Field(min_length=1)
    digest: Digest
    uri: str | None = Field(
        default=None,
        description="Portable relative reference only; absolute and file URIs are rejected.",
    )

    @model_validator(mode="after")
    def portable_uri(self) -> ArtifactReference:
        if self.uri is None:
            return self
        normalized = self.uri.replace("\\", "/")
        parts = normalized.split("/")
        if normalized.startswith("/") or ":" in parts[0] or "://" in normalized or ".." in parts:
            raise ValueError("artifact uri must be portable and relative")
        return self


class ArtifactInventory(_StrictModel):
    tree_digest: Digest
    files: list[ArtifactReference] = Field(min_length=1)
    dependency_manifest_digest: Digest
    lockfile_digest: Digest | None = None
    package_identities: list[str] = Field(default_factory=list)


class ToolAnnotations(_StrictModel):
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool


class DeclaredCapabilities(_StrictModel):
    permissions: list[str] = Field(default_factory=list)
    auth_scopes: list[str] = Field(default_factory=list)
    data_zones: list[str] = Field(default_factory=list)
    egress_destinations: list[str] = Field(default_factory=list)
    credential_keys: list[EnvKey] = Field(default_factory=list)


class ToolBOMEntry(_StrictModel):
    tool_id: str = Field(min_length=3)
    name: ToolName
    description_digest: Digest
    input_schema_digest: Digest
    output_schema_digest: Digest | None = None
    implementation_digest: Digest
    observed_capabilities: list[Literal["filesystem", "network"]] = Field(default_factory=list)
    observed_egress_destinations: list[str] = Field(default_factory=list)
    annotations: ToolAnnotations
    declared: DeclaredCapabilities


class Coverage(_StrictModel):
    requested: list[str] = Field(default_factory=list)
    executed: list[str] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    unavailable: list[str] = Field(default_factory=list)


_TERMINAL_STATES = {
    StageState.PASSED,
    StageState.FAILED,
    StageState.SKIPPED,
    StageState.UNKNOWN,
    StageState.STALE,
    StageState.BLOCKED,
}


class StageAttempt(_StrictModel):
    stage_id: StageId
    attempt: int = Field(ge=1)
    state: StageState
    required: bool = True
    producer: ProducerIdentity
    started_at: datetime | None = None
    finished_at: datetime | None = None
    inputs: list[ArtifactReference] = Field(default_factory=list)
    outputs: list[ArtifactReference] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    finding_ids: list[str] = Field(default_factory=list)
    failure_codes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def state_shape(self) -> StageAttempt:
        if self.state in _TERMINAL_STATES and self.finished_at is None:
            raise ValueError("terminal stage attempt requires finished_at")
        if self.state in {StageState.PENDING, StageState.RUNNING} and self.finished_at is not None:
            raise ValueError("non-terminal stage attempt cannot have finished_at")
        if self.started_at and self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at cannot precede started_at")
        if self.state is StageState.PASSED and self.failure_codes:
            raise ValueError("passed stage attempt cannot contain failure_codes")
        if self.state is StageState.FAILED and not self.failure_codes:
            raise ValueError("failed stage attempt requires failure_codes")
        if self.state in {StageState.SKIPPED, StageState.UNKNOWN, StageState.STALE, StageState.BLOCKED}:
            if not self.limitations:
                raise ValueError(f"{self.state.value} stage attempt requires limitations")
        return self


class SandboxEvidence(_StrictModel):
    provider: str = Field(min_length=1)
    isolates: bool
    image_digest: Digest
    network: Literal["none", "restricted", "host"]
    mounts: list[str] = Field(default_factory=list)
    credential_mode: Literal["none", "dummy", "live"]
    policy_digest: Digest


class AuditEvidence(_StrictModel):
    report: ArtifactReference
    report_schema_version: int = Field(ge=1)
    detector_ids: list[str] = Field(min_length=1)
    connection_statuses: dict[str, Literal["connected", "failed", "timeout", "skipped"]]
    warning_codes: list[str] = Field(default_factory=list)


class PolicyEvidence(_StrictModel):
    kind: Literal["audit", "egress"]
    policy_id: Identifier
    policy_version: str = Field(min_length=1)
    policy_digest: Digest
    result: Literal["passed", "failed", "unknown"]


class GradeEvidence(_StrictModel):
    grade: str = Field(min_length=1)
    transparency: str = Field(min_length=1)
    audit_report_digest: Digest
    grading_policy_version: str = Field(min_length=1)
    current: bool


class PublicationEvidence(_StrictModel):
    target: str = Field(min_length=1)
    metadata_digest: Digest
    schema_version: str = Field(min_length=1)
    result: Literal["passed", "failed", "unknown"]
    dry_run: Literal[True] = True


class IntegrityEvidence(_StrictModel):
    hash_algorithm: Literal["sha256"] = "sha256"
    receipt_refs: list[ArtifactReference] = Field(min_length=1)
    signature_refs: list[ArtifactReference] = Field(default_factory=list)


class SafeForgeManifest(_StrictModel):
    contract: ContractHeader
    run: RunInfo
    subject: Subject
    producers: list[ProducerIdentity] = Field(min_length=1)
    artifact: ArtifactInventory
    toolbom: list[ToolBOMEntry] = Field(min_length=1)
    stages: list[StageAttempt] = Field(min_length=1)
    sandbox: SandboxEvidence | None = None
    audit: AuditEvidence | None = None
    policies: list[PolicyEvidence] = Field(default_factory=list)
    grade: GradeEvidence | None = None
    publication: PublicationEvidence | None = None
    integrity: IntegrityEvidence | None = None
    limitations: list[str] = Field(default_factory=list)


class SafeForgeFinding(_StrictModel):
    code: str
    severity: FindingSeverity
    message: str
    stage_id: StageId | None = None


class SafeForgeValidationResult(_StrictModel):
    valid: bool
    findings: list[SafeForgeFinding] = Field(default_factory=list)
    manifest: SafeForgeManifest | None = None


def validate_safeforge_manifest(
    payload: Mapping[str, Any], *, require_final: bool = False
) -> SafeForgeValidationResult:
    """Validate Manifest v0 shape and fail-closed pipeline semantics."""
    try:
        manifest = SafeForgeManifest.model_validate(payload)
    except ValidationError as exc:
        return SafeForgeValidationResult(
            valid=False,
            findings=[
                SafeForgeFinding(
                    code="SF-CONTRACT-SCHEMA",
                    severity=FindingSeverity.ERROR,
                    message=_validation_error_message(exc),
                )
            ],
        )

    findings: list[SafeForgeFinding] = []
    findings.extend(_validate_artifacts(manifest))
    findings.extend(_validate_producers(manifest))
    findings.extend(_validate_toolbom(manifest))
    findings.extend(_validate_stage_attempts(manifest))
    findings.extend(_validate_stage_order(manifest))
    if require_final:
        findings.extend(_validate_final_manifest(manifest))

    return SafeForgeValidationResult(
        valid=not any(item.severity is FindingSeverity.ERROR for item in findings),
        findings=findings,
        manifest=manifest,
    )


def safeforge_manifest_json_schema() -> dict[str, Any]:
    """Return the canonical generated JSON Schema for Manifest v0."""
    return SafeForgeManifest.model_json_schema()


def _validate_toolbom(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    seen: set[str] = set()
    for tool in manifest.toolbom:
        expected = f"{manifest.subject.server_id}#{tool.name}"
        if tool.tool_id != expected:
            findings.append(
                _error("SF-CONTRACT-TOOL-ID", f"tool_id {tool.tool_id!r} must equal {expected!r}")
            )
        if tool.tool_id in seen:
            findings.append(_error("SF-CONTRACT-TOOL-DUPLICATE", f"duplicate tool_id {tool.tool_id!r}"))
        seen.add(tool.tool_id)
        if "filesystem" in tool.observed_capabilities and "filesystem" not in tool.declared.permissions:
            findings.append(
                _error(
                    "SF-CONTRACT-FILESYSTEM-UNDECLARED",
                    f"tool {tool.name!r} has observed filesystem capability without permission",
                )
            )
        if "network" in tool.observed_capabilities:
            declared = {_normalize_destination(item) for item in tool.declared.egress_destinations}
            undeclared = set(tool.observed_egress_destinations) - declared
            if undeclared:
                findings.append(
                    _error(
                        "SF-CONTRACT-EGRESS-UNDECLARED",
                        f"tool {tool.name!r} has undeclared observed egress: {sorted(undeclared)}",
                    )
                )
            if not tool.observed_egress_destinations and not tool.annotations.open_world:
                findings.append(
                    _error(
                        "SF-CONTRACT-EGRESS-DYNAMIC",
                        f"tool {tool.name!r} has dynamic network capability without open_world",
                    )
                )
    return findings


def _normalize_destination(value: str) -> str:
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        from urllib.parse import urlsplit

        return urlsplit(value).hostname or value
    return value.lower().strip(".")


def _validate_artifacts(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    seen: set[str] = set()
    for artifact in manifest.artifact.files:
        if artifact.artifact_id in seen:
            findings.append(
                _error(
                    "SF-CONTRACT-ARTIFACT-DUPLICATE",
                    f"duplicate artifact_id {artifact.artifact_id!r}",
                )
            )
        seen.add(artifact.artifact_id)
    return findings


def _validate_producers(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    names = [producer.name for producer in manifest.producers]
    if len(names) != len(set(names)):
        findings.append(_error("SF-CONTRACT-PRODUCER-DUPLICATE", "producer names must be unique"))
    declared = set(names)
    declared.add(manifest.run.coordinator.name)
    for stage in manifest.stages:
        if stage.producer.name not in declared:
            findings.append(
                _error(
                    "SF-CONTRACT-PRODUCER-UNDECLARED",
                    f"stage producer {stage.producer.name!r} is not declared",
                    stage.stage_id,
                )
            )
    return findings


def _validate_stage_attempts(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    grouped: dict[StageId, list[StageAttempt]] = defaultdict(list)
    seen: set[tuple[StageId, int]] = set()
    for item in manifest.stages:
        key = (item.stage_id, item.attempt)
        if key in seen:
            findings.append(
                _error(
                    "SF-CONTRACT-ATTEMPT-DUPLICATE",
                    f"duplicate attempt {item.attempt} for {item.stage_id.value}",
                    item.stage_id,
                )
            )
        seen.add(key)
        grouped[item.stage_id].append(item)
        if item.required and item.state is StageState.SKIPPED:
            findings.append(
                _error(
                    "SF-CONTRACT-REQUIRED-SKIPPED",
                    "required stage cannot be skipped",
                    item.stage_id,
                )
            )

    for stage_id, attempts in grouped.items():
        attempts.sort(key=lambda item: item.attempt)
        numbers = [item.attempt for item in attempts]
        if numbers != list(range(1, len(numbers) + 1)):
            findings.append(
                _error(
                    "SF-CONTRACT-ATTEMPT-SEQUENCE",
                    f"attempts must be contiguous from 1; got {numbers}",
                    stage_id,
                )
            )
        for previous, current in zip(attempts, attempts[1:], strict=False):
            if not _transition_allowed(previous.state, current.state):
                findings.append(
                    _error(
                        "SF-CONTRACT-STATE-TRANSITION",
                        f"illegal transition {previous.state.value} -> {current.state.value}",
                        stage_id,
                    )
                )
    return findings


def _validate_stage_order(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    latest = _latest_attempts(manifest)
    active = {
        StageState.RUNNING,
        StageState.PASSED,
        StageState.FAILED,
        StageState.UNKNOWN,
        StageState.STALE,
    }
    for index, stage_id in enumerate(RESEARCH_MVP_STAGE_ORDER):
        current = latest.get(stage_id)
        if current is None or current.state not in active:
            continue
        unmet = [
            prior.value
            for prior in RESEARCH_MVP_STAGE_ORDER[:index]
            if prior not in latest or latest[prior].state is not StageState.PASSED
        ]
        if unmet:
            findings.append(
                _error(
                    "SF-CONTRACT-STAGE-ORDER",
                    f"stage ran before required predecessors passed: {', '.join(unmet)}",
                    stage_id,
                )
            )
    return findings


def _validate_final_manifest(manifest: SafeForgeManifest) -> list[SafeForgeFinding]:
    findings: list[SafeForgeFinding] = []
    latest = _latest_attempts(manifest)
    for stage_id in RESEARCH_MVP_STAGE_ORDER:
        current = latest.get(stage_id)
        if current is None:
            findings.append(_error("SF-CONTRACT-STAGE-MISSING", "required final stage is missing", stage_id))
        elif current.state is not StageState.PASSED:
            findings.append(
                _error(
                    "SF-CONTRACT-STAGE-NOT-PASSED",
                    f"required final stage is {current.state.value}",
                    stage_id,
                )
            )

    required_sections = {
        "sandbox": manifest.sandbox,
        "audit": manifest.audit,
        "policies": manifest.policies,
        "grade": manifest.grade,
        "publication": manifest.publication,
        "integrity": manifest.integrity,
    }
    for name, value in required_sections.items():
        if not value:
            findings.append(_error("SF-CONTRACT-EVIDENCE-MISSING", f"final manifest requires {name}"))

    if manifest.run.decision is not PipelineDecision.ELIGIBLE:
        findings.append(_error("SF-CONTRACT-DECISION", "final research manifest decision must be eligible"))
    if manifest.grade is not None and not manifest.grade.current:
        findings.append(_error("SF-TRUST-STALE", "final manifest cannot use a stale grade"))
    if (
        manifest.grade is not None
        and manifest.audit is not None
        and manifest.grade.audit_report_digest != manifest.audit.report.digest
    ):
        findings.append(_error("SF-TRUST-AUDIT-BINDING", "grade must bind the exact MCPAudit report digest"))
    if manifest.audit is not None:
        if any(status != "connected" for status in manifest.audit.connection_statuses.values()):
            findings.append(
                _error("SF-AUDIT-CONNECTION", "all final connected-audit statuses must be connected")
            )
        if manifest.audit.warning_codes:
            findings.append(
                _error("SF-AUDIT-COVERAGE", "final audit cannot contain unresolved coverage warnings")
            )
    if manifest.sandbox is not None:
        if not manifest.sandbox.isolates or manifest.sandbox.network != "none":
            findings.append(
                _error("SF-SANDBOX-ISOLATION", "final sandbox must isolate with network disabled")
            )
        if manifest.sandbox.credential_mode != "none":
            findings.append(
                _error("SF-SANDBOX-CREDENTIALS", "credential-free research fixture requires none mode")
            )
    if manifest.policies and any(policy.result != "passed" for policy in manifest.policies):
        findings.append(_error("SF-POLICY-NOT-PASSED", "all final policies must pass"))
    policy_kinds = {policy.kind for policy in manifest.policies}
    if policy_kinds != {"audit", "egress"}:
        findings.append(
            _error("SF-POLICY-COVERAGE", "final manifest requires audit and egress policy evidence")
        )
    if manifest.publication is not None and manifest.publication.result != "passed":
        findings.append(_error("SF-PUBLISH-DRY-RUN", "publication dry-run must pass"))
    return findings


def _latest_attempts(manifest: SafeForgeManifest) -> dict[StageId, StageAttempt]:
    latest: dict[StageId, StageAttempt] = {}
    for item in manifest.stages:
        if item.stage_id not in latest or item.attempt > latest[item.stage_id].attempt:
            latest[item.stage_id] = item
    return latest


def _transition_allowed(previous: StageState, current: StageState) -> bool:
    allowed = {
        StageState.PENDING: {
            StageState.RUNNING,
            StageState.PASSED,
            StageState.FAILED,
            StageState.SKIPPED,
            StageState.UNKNOWN,
            StageState.BLOCKED,
        },
        StageState.RUNNING: {StageState.PASSED, StageState.FAILED, StageState.UNKNOWN},
        StageState.PASSED: {StageState.STALE},
        StageState.FAILED: {
            StageState.RUNNING,
            StageState.PASSED,
            StageState.FAILED,
            StageState.UNKNOWN,
        },
        StageState.UNKNOWN: {
            StageState.RUNNING,
            StageState.PASSED,
            StageState.FAILED,
            StageState.UNKNOWN,
        },
        StageState.STALE: {
            StageState.RUNNING,
            StageState.PASSED,
            StageState.FAILED,
            StageState.UNKNOWN,
        },
        StageState.SKIPPED: {StageState.RUNNING, StageState.PASSED, StageState.FAILED},
        StageState.BLOCKED: {StageState.RUNNING, StageState.PASSED, StageState.FAILED},
    }
    return current in allowed[previous]


def _validation_error_message(exc: ValidationError) -> str:
    first = exc.errors(include_url=False)[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}" if location else str(first["msg"])


def _error(code: str, message: str, stage_id: StageId | None = None) -> SafeForgeFinding:
    return SafeForgeFinding(
        code=code,
        severity=FindingSeverity.ERROR,
        message=message,
        stage_id=stage_id,
    )
