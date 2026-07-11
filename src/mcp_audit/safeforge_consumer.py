"""Read-only ForgeReceiptV0 consumer for the SafeForge preinstall boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from mcp_audit import __version__
from mcp_audit.api import scan_config_only
from mcp_audit.models import AuditReport
from mcp_audit.report import scrub_report_identifiers
from mcp_audit.safeforge import (
    ArtifactInventory,
    ArtifactReference,
    AuditEvidence,
    ContractHeader,
    Coverage,
    DeclaredCapabilities,
    FindingSeverity,
    PipelineDecision,
    ProducerIdentity,
    RunInfo,
    SafeForgeFinding,
    SafeForgeManifest,
    StageAttempt,
    StageId,
    StageState,
    Subject,
    ToolAnnotations,
    ToolBOMEntry,
    validate_safeforge_manifest,
)

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$")]
ToolName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]*$")]
EnvKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")]
ConnectionStatus = Literal["connected", "failed", "timeout", "skipped"]
_CONNECTION_STATUSES = {"connected", "failed", "timeout", "skipped"}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ForgeProducerInput(_StrictModel):
    name: Literal["mcpforge"] = "mcpforge"
    version: str
    source: Literal["io.github.saagpatel/mcpforge"] = "io.github.saagpatel/mcpforge"
    revision: str
    dirty: bool
    executable: Literal["mcpforge"] = "mcpforge"


class ForgeSourceInput(_StrictModel):
    kind: Literal["natural-language"] = "natural-language"
    server_id: Identifier
    description_digest: Digest
    transport: Literal["stdio", "streamable-http"]


class ForgeGenerationInput(_StrictModel):
    provider: str
    model: str
    no_execute: Literal[True] = True
    plan_digest: Digest
    required_env_keys: list[EnvKey] = Field(default_factory=list)


class ForgeArtifactFileInput(_StrictModel):
    path: str
    media_type: str
    digest: Digest

    @model_validator(mode="after")
    def portable_path(self) -> ForgeArtifactFileInput:
        normalized = self.path.replace("\\", "/")
        parts = normalized.split("/")
        if normalized.startswith("/") or ":" in parts[0] or ".." in parts:
            raise ValueError("artifact path must be portable and relative")
        return self


class ForgeArtifactInventoryInput(_StrictModel):
    tree_digest: Digest
    files: list[ForgeArtifactFileInput] = Field(min_length=1)
    dependency_manifest_digest: Digest
    lockfile_digest: Digest | None = None
    package_identities: list[str] = Field(default_factory=list)


class ForgeToolAnnotationsInput(_StrictModel):
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool


class ForgeDeclaredCapabilitiesInput(_StrictModel):
    permissions: list[str] = Field(default_factory=list)
    auth_scopes: list[str] = Field(default_factory=list)
    data_zones: list[str] = Field(default_factory=list)
    egress_destinations: list[str] = Field(default_factory=list)
    credential_keys: list[EnvKey] = Field(default_factory=list)


class ForgeToolBOMInput(_StrictModel):
    tool_id: str
    name: ToolName
    description_digest: Digest
    input_schema_digest: Digest
    output_schema_digest: Digest
    implementation_digest: Digest
    observed_capabilities: list[Literal["filesystem", "network"]] = Field(default_factory=list)
    observed_egress_destinations: list[str] = Field(default_factory=list)
    annotations: ForgeToolAnnotationsInput
    declared: ForgeDeclaredCapabilitiesInput

    @model_validator(mode="after")
    def observed_network_is_declared(self) -> ForgeToolBOMInput:
        if "filesystem" in self.observed_capabilities and "filesystem" not in self.declared.permissions:
            raise ValueError("observed filesystem capability requires the filesystem permission")
        if "network" not in self.observed_capabilities:
            return self
        declared = {_normalize_destination(item) for item in self.declared.egress_destinations}
        undeclared = set(self.observed_egress_destinations) - declared
        if undeclared:
            raise ValueError(f"observed egress destinations are undeclared: {sorted(undeclared)}")
        if not self.observed_egress_destinations and not self.annotations.open_world:
            raise ValueError("observed dynamic network capability requires open_world")
        return self


class ForgeValidationInput(_StrictModel):
    mode: Literal["static-no-execute"] = "static-no-execute"
    syntax: Literal["passed", "failed", "skipped", "unknown"]
    security: Literal["passed", "failed", "skipped", "unknown"]
    lint: Literal["passed", "failed", "skipped", "unknown"]
    import_check: Literal["skipped"] = "skipped"
    tests: Literal["skipped"] = "skipped"
    security_warning_count: int = Field(ge=0)
    eligible_for_preinstall_audit: bool


class ForgeReceiptV0Input(_StrictModel):
    receipt_id: Identifier
    receipt_version: Literal["0.1.0"] = "0.1.0"
    created_at: datetime
    producer: ForgeProducerInput
    source: ForgeSourceInput
    generation: ForgeGenerationInput
    artifact: ForgeArtifactInventoryInput
    toolbom: list[ForgeToolBOMInput] = Field(min_length=1)
    validation: ForgeValidationInput
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def internal_bindings(self) -> ForgeReceiptV0Input:
        paths = [item.path for item in self.artifact.files]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact paths must be unique")
        tool_ids = [item.tool_id for item in self.toolbom]
        if len(tool_ids) != len(set(tool_ids)):
            raise ValueError("tool IDs must be unique")
        for tool in self.toolbom:
            expected = f"{self.source.server_id}#{tool.name}"
            if tool.tool_id != expected:
                raise ValueError(f"tool_id {tool.tool_id!r} must equal {expected!r}")
        expected_eligible = all(
            state == "passed"
            for state in (self.validation.syntax, self.validation.security, self.validation.lint)
        )
        if self.validation.eligible_for_preinstall_audit != expected_eligible:
            raise ValueError("preinstall eligibility must match static validation states")
        if self.validation.security_warning_count and self.validation.eligible_for_preinstall_audit:
            raise ValueError("preinstall eligibility requires zero unresolved security warnings")
        return self


class SafeForgePreinstallResult(_StrictModel):
    accepted: bool
    findings: list[SafeForgeFinding] = Field(default_factory=list)
    manifest: SafeForgeManifest | None = None
    audit_report: AuditReport | None = None


async def consume_forge_receipt(
    receipt_payload: Mapping[str, Any],
    artifact_root: Path,
    *,
    run_id: str,
    created_at: datetime,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> SafeForgePreinstallResult:
    """Verify a forge receipt and run config-only audit without spawning a server."""
    try:
        receipt = ForgeReceiptV0Input.model_validate(receipt_payload)
    except ValidationError as exc:
        return _blocked("SF-FORGE-RECEIPT-SCHEMA", _validation_error_message(exc))

    if not receipt.validation.eligible_for_preinstall_audit:
        return _blocked(
            "SF-FORGE-STATIC-NOT-PASSED",
            "forge receipt is not eligible for preinstall audit",
            StageId.VALIDATE_STATIC,
        )

    artifact_error = _verify_artifact_root(receipt, artifact_root)
    if artifact_error is not None:
        return artifact_error

    config_path = artifact_root.resolve() / "config.json"
    try:
        config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return _blocked("SF-FORGE-CONFIG-INVALID", f"config.json could not be parsed: {exc}")
    config_error = _validate_config_binding(receipt, config_payload)
    if config_error is not None:
        return config_error

    report = await scan_config_only(config_payload, source="safeforge://forge-receipt-v0")
    report = scrub_report_identifiers(report)
    report = report.model_copy(
        update={
            "scan_timestamp": created_at,
            "hostname": "<canonical-host>",
            "os_platform": "canonical",
            "scan_duration_seconds": 0.0,
        }
    )
    unexpected_statuses = sorted({audit.connection_status for audit in report.audits} - _CONNECTION_STATUSES)
    if unexpected_statuses:
        return _blocked(
            "SF-AUDIT-STATUS",
            f"config-only audit returned unsupported connection statuses: {unexpected_statuses}",
            StageId.AUDIT_CONFIG,
        )
    if report.warnings:
        return _blocked(
            "SF-AUDIT-COVERAGE",
            "config-only audit returned unresolved coverage warnings",
            StageId.AUDIT_CONFIG,
        )

    manifest = _build_partial_manifest(
        receipt,
        receipt_payload,
        report,
        run_id=run_id,
        created_at=created_at,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    validation = validate_safeforge_manifest(manifest.model_dump(mode="json"))
    if not validation.valid or validation.manifest is None:
        return SafeForgePreinstallResult(accepted=False, findings=validation.findings)
    return SafeForgePreinstallResult(
        accepted=True,
        manifest=validation.manifest,
        audit_report=report,
    )


def _verify_artifact_root(
    receipt: ForgeReceiptV0Input, artifact_root: Path
) -> SafeForgePreinstallResult | None:
    root = artifact_root.resolve()
    if not root.is_dir():
        return _blocked("SF-FORGE-ARTIFACT-MISSING", "artifact root is missing or not a directory")

    entries = list(root.rglob("*"))
    symlinks = [path.relative_to(root).as_posix() for path in entries if path.is_symlink()]
    if symlinks:
        return _blocked(
            "SF-FORGE-ARTIFACT-SYMLINK",
            f"artifact root contains symlinks: {', '.join(sorted(symlinks))}",
        )
    actual = sorted(path.relative_to(root).as_posix() for path in entries if path.is_file())
    expected = sorted(item.path for item in receipt.artifact.files)
    if actual != expected:
        return _blocked(
            "SF-FORGE-ARTIFACT-SET",
            f"artifact set differs: expected {expected}, got {actual}",
        )

    ordered = sorted(receipt.artifact.files, key=lambda item: item.path)
    for item in ordered:
        digest = _digest_bytes((root / item.path).read_bytes())
        if digest != item.digest:
            return _blocked(
                "SF-FORGE-ARTIFACT-DIGEST",
                f"artifact digest mismatch for {item.path}",
            )
    tree_digest = _digest_json([item.model_dump(mode="json") for item in ordered])
    if tree_digest != receipt.artifact.tree_digest:
        return _blocked("SF-FORGE-TREE-DIGEST", "artifact tree digest does not match receipt")

    dependency = next((item for item in ordered if item.path == "pyproject.toml"), None)
    if dependency is None or dependency.digest != receipt.artifact.dependency_manifest_digest:
        return _blocked(
            "SF-FORGE-DEPENDENCY-BINDING",
            "dependency manifest digest does not match pyproject.toml",
        )
    return None


def _validate_config_binding(
    receipt: ForgeReceiptV0Input, config_payload: object
) -> SafeForgePreinstallResult | None:
    if not isinstance(config_payload, dict):
        return _blocked("SF-FORGE-CONFIG-SHAPE", "config.json must contain an object")
    servers = config_payload.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {receipt.source.server_id}:
        return _blocked(
            "SF-FORGE-CONFIG-SERVER",
            "config server identity does not match forge receipt",
        )
    server = servers[receipt.source.server_id]
    if not isinstance(server, dict):
        return _blocked("SF-FORGE-CONFIG-SHAPE", "server config must contain an object")
    if receipt.source.transport == "stdio" and ("url" in server or not server.get("command")):
        return _blocked(
            "SF-FORGE-CONFIG-TRANSPORT",
            "stdio receipt must bind a local command config without a URL",
        )
    env = server.get("env", {})
    if not isinstance(env, dict) or set(env) != set(receipt.generation.required_env_keys):
        return _blocked(
            "SF-FORGE-CONFIG-ENV",
            "config environment key names do not match forge receipt",
        )
    return None


def _build_partial_manifest(
    receipt: ForgeReceiptV0Input,
    receipt_payload: Mapping[str, Any],
    report: AuditReport,
    *,
    run_id: str,
    created_at: datetime,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> SafeForgeManifest:
    forge_producer = ProducerIdentity(**receipt.producer.model_dump())
    coordinator = ProducerIdentity(
        name="mcp-audit",
        version=__version__,
        source="io.github.saagpatel/mcp-audit",
        revision=coordinator_revision,
        dirty=coordinator_dirty,
        executable="mcp-audit",
    )
    file_refs = [
        ArtifactReference(
            artifact_id=f"forge-file-{index:02d}",
            media_type=item.media_type,
            digest=item.digest,
            uri=item.path,
        )
        for index, item in enumerate(sorted(receipt.artifact.files, key=lambda item: item.path), 1)
    ]
    receipt_ref = ArtifactReference(
        artifact_id="forge-receipt",
        media_type="application/vnd.safeforge.forge-receipt+json",
        digest=_digest_json(receipt.model_dump(mode="json")),
    )
    plan_ref = ArtifactReference(
        artifact_id="forge-plan",
        media_type="application/vnd.safeforge.plan+json",
        digest=receipt.generation.plan_digest,
    )
    source_ref = ArtifactReference(
        artifact_id="source-spec",
        media_type="text/plain; digest-only=true",
        digest=receipt.source.description_digest,
    )
    validation_ref = ArtifactReference(
        artifact_id="static-validation",
        media_type="application/vnd.safeforge.validation+json",
        digest=_digest_json(receipt.validation.model_dump(mode="json")),
    )
    preinstall_ref = ArtifactReference(
        artifact_id="preinstall-decision",
        media_type="application/vnd.safeforge.preinstall+json",
        digest=_digest_json(
            {
                "receipt": _digest_json(dict(receipt_payload)),
                "tree": receipt.artifact.tree_digest,
                "config": next(item.digest for item in receipt.artifact.files if item.path == "config.json"),
            }
        ),
    )
    report_ref = ArtifactReference(
        artifact_id="config-audit-report",
        media_type="application/vnd.mcp-audit.report+json",
        digest=_digest_json(report.model_dump(mode="json")),
    )

    return SafeForgeManifest(
        contract=ContractHeader(),
        run=RunInfo(
            run_id=run_id,
            created_at=created_at,
            coordinator=coordinator,
            decision=PipelineDecision.BUILDING,
        ),
        subject=Subject(
            server_id=receipt.source.server_id,
            source_kind="natural-language",
            source_spec_digest=receipt.source.description_digest,
            transport=receipt.source.transport,
            mcp_protocol_supported=["unknown"],
        ),
        producers=[forge_producer, coordinator],
        artifact=ArtifactInventory(
            tree_digest=receipt.artifact.tree_digest,
            files=file_refs,
            dependency_manifest_digest=receipt.artifact.dependency_manifest_digest,
            lockfile_digest=receipt.artifact.lockfile_digest,
            package_identities=receipt.artifact.package_identities,
        ),
        toolbom=[
            ToolBOMEntry(
                tool_id=tool.tool_id,
                name=tool.name,
                description_digest=tool.description_digest,
                input_schema_digest=tool.input_schema_digest,
                output_schema_digest=tool.output_schema_digest,
                implementation_digest=tool.implementation_digest,
                observed_capabilities=tool.observed_capabilities,
                observed_egress_destinations=tool.observed_egress_destinations,
                annotations=ToolAnnotations(**tool.annotations.model_dump()),
                declared=DeclaredCapabilities(**tool.declared.model_dump()),
            )
            for tool in receipt.toolbom
        ],
        stages=[
            _passed_stage(StageId.SOURCE_BIND, forge_producer, receipt.created_at, outputs=[source_ref]),
            _passed_stage(
                StageId.FORGE_PLAN,
                forge_producer,
                receipt.created_at,
                inputs=[source_ref],
                outputs=[plan_ref],
            ),
            _passed_stage(
                StageId.FORGE_GENERATE,
                forge_producer,
                receipt.created_at,
                inputs=[plan_ref],
                outputs=file_refs,
            ),
            _passed_stage(
                StageId.VALIDATE_STATIC,
                forge_producer,
                receipt.created_at,
                inputs=file_refs,
                outputs=[validation_ref, receipt_ref],
                coverage=Coverage(
                    requested=["syntax", "security", "lint"],
                    executed=["syntax", "security", "lint"],
                    skipped=["import", "tests"],
                ),
            ),
            _passed_stage(
                StageId.CONTRACT_PREINSTALL,
                coordinator,
                created_at,
                inputs=[receipt_ref, validation_ref, *file_refs],
                outputs=[preinstall_ref],
            ),
            _passed_stage(
                StageId.AUDIT_CONFIG,
                coordinator,
                created_at,
                inputs=[preinstall_ref],
                outputs=[report_ref],
                coverage=Coverage(
                    requested=["config-health", "permission-inference"],
                    executed=["config-health", "permission-inference"],
                ),
            ),
        ],
        audit=AuditEvidence(
            report=report_ref,
            report_schema_version=report.schema_version,
            detector_ids=["config-health", "permission-inference"],
            connection_statuses=cast(
                dict[str, ConnectionStatus],
                {audit.server.name: audit.connection_status for audit in report.audits},
            ),
            warning_codes=[warning.code for warning in report.warnings],
        ),
        limitations=[
            *receipt.limitations,
            "The forge receipt does not declare an MCP protocol version; preinstall records unknown.",
            "Config-only audit did not install dependencies, launch the server, or contact endpoints.",
        ],
    )


def _passed_stage(
    stage_id: StageId,
    producer: ProducerIdentity,
    timestamp: datetime,
    *,
    inputs: list[ArtifactReference] | None = None,
    outputs: list[ArtifactReference] | None = None,
    coverage: Coverage | None = None,
) -> StageAttempt:
    return StageAttempt(
        stage_id=stage_id,
        attempt=1,
        state=StageState.PASSED,
        producer=producer,
        started_at=timestamp,
        finished_at=timestamp,
        inputs=inputs or [],
        outputs=outputs or [],
        coverage=coverage or Coverage(),
    )


def _blocked(code: str, message: str, stage_id: StageId | None = None) -> SafeForgePreinstallResult:
    return SafeForgePreinstallResult(
        accepted=False,
        findings=[
            SafeForgeFinding(
                code=code,
                severity=FindingSeverity.ERROR,
                message=message,
                stage_id=stage_id,
            )
        ],
    )


def _validation_error_message(exc: ValidationError) -> str:
    first = exc.errors(include_url=False)[0]
    location = ".".join(str(part) for part in first["loc"])
    return f"{location}: {first['msg']}" if location else str(first["msg"])


def _digest_json(value: object) -> Digest:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return _digest_bytes(encoded)


def _digest_bytes(value: bytes) -> Digest:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _normalize_destination(value: str) -> str:
    if value.startswith(("http://", "https://", "ws://", "wss://")):
        from urllib.parse import urlsplit

        return urlsplit(value).hostname or value
    return value.lower().strip(".")
