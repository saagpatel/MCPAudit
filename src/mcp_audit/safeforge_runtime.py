"""Fail-closed SafeForge runtime pipeline for the zero-egress research profile."""

# ruff: noqa: E501 -- policy strings and embedded isolated-worker programs are kept auditable.

from __future__ import annotations

import hashlib
import json
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mcp_audit.safeforge import (
    ArtifactReference,
    AuditEvidence,
    Coverage,
    FindingSeverity,
    GradeEvidence,
    IntegrityEvidence,
    PipelineDecision,
    PolicyEvidence,
    PublicationEvidence,
    SafeForgeFinding,
    SafeForgeManifest,
    SandboxEvidence,
    StageAttempt,
    StageId,
    StageState,
    validate_safeforge_manifest,
)
from mcp_audit.safeforge_consumer import ForgeReceiptV0Input, _verify_artifact_root
from mcp_audit.safeforge_coordinator import SafeForgeCoordinatorResult, run_safeforge_preinstall

_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
_UV = Path("/opt/homebrew/bin/uv")
_PYTHON = Path("/usr/local/bin/python3.12")
_MAX_OUTPUT = 65_536
_LIMITS = {
    "cpu_seconds": 20,
    "memory_bytes": 1_610_612_736,
    "disk_bytes": 805_306_368,
    "processes": 12,
    "wall_seconds": 45,
    "file_bytes": 67_108_864,
    "open_files": 256,
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RuntimeStepEvidence(_StrictModel):
    step: str
    passed: bool
    returncode: int
    termination: str | None = None
    stdout_digest: str
    stderr_digest: str


class SafeForgePipelineResult(_StrictModel):
    accepted: bool
    preinstall: SafeForgeCoordinatorResult
    manifest: SafeForgeManifest | None = None
    findings: list[SafeForgeFinding] = Field(default_factory=list)
    runtime_steps: list[RuntimeStepEvidence] = Field(default_factory=list)


@dataclass(frozen=True)
class _CommandResult:
    returncode: int
    stdout: str
    stderr: str
    termination: str | None

    def evidence(self, step: str) -> RuntimeStepEvidence:
        return RuntimeStepEvidence(
            step=step,
            passed=self.returncode == 0 and self.termination is None,
            returncode=self.returncode,
            termination=self.termination,
            stdout_digest=_digest_bytes(self.stdout.encode()),
            stderr_digest=_digest_bytes(self.stderr.encode()),
        )


class _RuntimeBlocked(RuntimeError):
    def __init__(
        self,
        code: str,
        stage: StageId,
        message: str,
        *,
        steps: list[RuntimeStepEvidence] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.steps = steps or []


async def run_safeforge_pipeline(
    producer_schema: dict[str, Any],
    receipt_payload: Mapping[str, Any],
    artifact_root: Path,
    *,
    run_id: str,
    created_at: datetime,
    coordinator_revision: str,
    coordinator_dirty: bool,
) -> SafeForgePipelineResult:
    """Resume the preinstall result through a disposable, zero-egress runtime."""
    preinstall = await run_safeforge_preinstall(
        producer_schema,
        receipt_payload,
        artifact_root,
        run_id=run_id,
        created_at=created_at,
        coordinator_revision=coordinator_revision,
        coordinator_dirty=coordinator_dirty,
    )
    if not preinstall.accepted or preinstall.preinstall is None or preinstall.preinstall.manifest is None:
        return SafeForgePipelineResult(accepted=False, preinstall=preinstall)
    try:
        receipt = ForgeReceiptV0Input.model_validate(receipt_payload)
    except ValidationError as exc:
        return _blocked_result(preinstall, "SF-FORGE-RECEIPT-SCHEMA", StageId.CONTRACT_PREINSTALL, str(exc))

    root = Path(tempfile.mkdtemp(prefix="safeforge-runtime-", dir="/private/tmp"))
    steps: list[RuntimeStepEvidence] = []
    runtime_payload: dict[str, Any] | None = None
    installed: dict[str, str] = {}
    cleanup_verified = False
    try:
        runtime_payload, installed, steps = _execute_runtime(receipt, artifact_root, root)
    except _RuntimeBlocked as exc:
        return _blocked_result(preinstall, exc.code, exc.stage, str(exc), steps=exc.steps or steps)
    finally:
        _kill_root_processes(root)
        shutil.rmtree(root, ignore_errors=True)
        cleanup_verified = not root.exists()

    if runtime_payload is None or not cleanup_verified:
        return _blocked_result(
            preinstall,
            "SF-SANDBOX-CLEANUP",
            StageId.SANDBOX_MATERIALIZE,
            "disposable runtime cleanup could not be verified",
            steps=steps,
        )
    try:
        manifest = _finalize_manifest(
            preinstall.preinstall.manifest,
            receipt,
            runtime_payload,
            installed,
            created_at,
            cleanup_verified,
        )
    except _RuntimeBlocked as exc:
        return _blocked_result(preinstall, exc.code, exc.stage, str(exc), steps=steps)
    validation = validate_safeforge_manifest(manifest.model_dump(mode="json"), require_final=True)
    if not validation.valid or validation.manifest is None:
        return SafeForgePipelineResult(
            accepted=False,
            preinstall=preinstall,
            manifest=manifest,
            findings=validation.findings,
            runtime_steps=steps,
        )
    return SafeForgePipelineResult(
        accepted=True,
        preinstall=preinstall,
        manifest=validation.manifest,
        runtime_steps=steps,
    )


def _execute_runtime(
    receipt: ForgeReceiptV0Input, artifact_root: Path, root: Path
) -> tuple[dict[str, Any], dict[str, str], list[RuntimeStepEvidence]]:
    if not _SANDBOX_EXEC.is_file() or not _UV.is_file() or not _PYTHON.is_file():
        raise _RuntimeBlocked(
            "SF-SANDBOX-UNAVAILABLE",
            StageId.SANDBOX_PREPARE,
            "macOS Seatbelt, uv, and CPython 3.12 are required",
        )
    if receipt.source.transport != "stdio":
        raise _RuntimeBlocked(
            "SF-SANDBOX-TRANSPORT",
            StageId.SANDBOX_PREPARE,
            "the research runtime supports only stdio",
        )
    expected_launch = ["--directory", ".", "run", "python", "server.py"]
    if (
        receipt.launch is None
        or receipt.launch.command != "uv"
        or receipt.launch.args != expected_launch
        or receipt.launch.url is not None
        or receipt.launch.env_keys
    ):
        raise _RuntimeBlocked(
            "SF-SANDBOX-LAUNCH-UNSUPPORTED",
            StageId.SANDBOX_PREPARE,
            "research runtime requires the receipt-bound uv/python/server.py launch shape",
        )
    if receipt.artifact.lockfile_digest is None:
        raise _RuntimeBlocked(
            "SF-FORGE-LOCK-MISSING",
            StageId.SANDBOX_MATERIALIZE,
            "runtime materialization requires a receipt-bound uv.lock",
        )
    if any(tool.declared.credential_keys for tool in receipt.toolbom):
        raise _RuntimeBlocked(
            "SF-SANDBOX-CREDENTIALS",
            StageId.SANDBOX_PREPARE,
            "credential-bearing receipts are outside the research profile",
        )
    if any(
        tool.declared.egress_destinations or "network" in tool.observed_capabilities
        for tool in receipt.toolbom
    ):
        raise _RuntimeBlocked(
            "SF-SANDBOX-EGRESS-UNSUPPORTED",
            StageId.SANDBOX_PREPARE,
            "redirect-safe hostname allowlisting is unproven; network receipts fail closed",
        )
    if any(
        "filesystem" in tool.observed_capabilities or "filesystem" in tool.declared.permissions
        for tool in receipt.toolbom
    ):
        raise _RuntimeBlocked(
            "SF-SANDBOX-FILESYSTEM-UNSUPPORTED",
            StageId.SANDBOX_PREPARE,
            "the research runtime supports only tools with no filesystem capability",
        )

    project = root / "artifact"
    shutil.copytree(artifact_root.resolve(), project, symlinks=True)
    for name in ("home", "cache", "tmp", "evidence"):
        (root / name).mkdir()
    steps: list[RuntimeStepEvidence] = []
    _assert_artifact_binding(receipt, project, StageId.SANDBOX_PREPARE)
    _verify_lock_sources(project / "uv.lock", receipt.source.server_id)

    probe = _run_sandboxed([str(_PYTHON), "-c", _PROBE_CODE], root, project, deny_network=True)
    steps.append(probe.evidence("sandbox.prepare.probe"))
    if probe.returncode != 0 or probe.termination:
        raise _RuntimeBlocked(
            "SF-SANDBOX-PROBE",
            StageId.SANDBOX_PREPARE,
            "Seatbelt denial probe failed",
            steps=steps,
        )
    try:
        proof = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        raise _RuntimeBlocked(
            "SF-SANDBOX-PROBE",
            StageId.SANDBOX_PREPARE,
            "probe output was invalid",
            steps=steps,
        ) from exc
    if proof != {
        "home_read_denied": True,
        "home_write_denied": True,
        "keychain_denied": True,
        "network_denied": True,
        "outside_write_denied": True,
    }:
        raise _RuntimeBlocked(
            "SF-SANDBOX-PROBE",
            StageId.SANDBOX_PREPARE,
            "one or more kernel denials were not proven",
            steps=steps,
        )

    env = _environment(root)
    seed_env = {**env, "UV_PROJECT_ENVIRONMENT": str(root / "seed-venv")}
    seed = _run_sandboxed(
        [
            str(_UV),
            "sync",
            "--project",
            str(project),
            "--locked",
            "--no-install-project",
            "--python",
            str(_PYTHON),
        ],
        root,
        project,
        deny_network=False,
        extra_env=seed_env,
    )
    steps.append(seed.evidence("sandbox.prepare.dependencies"))
    if seed.returncode != 0 or seed.termination:
        raise _RuntimeBlocked(
            "SF-SANDBOX-DEPENDENCIES",
            StageId.SANDBOX_PREPARE,
            "locked dependency cache preparation failed",
            steps=steps,
        )
    shutil.rmtree(root / "seed-venv", ignore_errors=True)

    materialize_env = {
        **env,
        "UV_OFFLINE": "1",
        "UV_PROJECT_ENVIRONMENT": str(root / "runtime-venv"),
    }
    materialize = _run_sandboxed(
        [
            str(_UV),
            "sync",
            "--project",
            str(project),
            "--offline",
            "--locked",
            "--no-install-project",
            "--python",
            str(_PYTHON),
        ],
        root,
        project,
        deny_network=True,
        extra_env=materialize_env,
    )
    steps.append(materialize.evidence("sandbox.materialize"))
    if materialize.returncode != 0 or materialize.termination:
        raise _RuntimeBlocked(
            "SF-SANDBOX-MATERIALIZE",
            StageId.SANDBOX_MATERIALIZE,
            "offline locked materialization failed",
            steps=steps,
        )

    python = root / "runtime-venv" / "bin" / "python"
    packages = _run_sandboxed([str(python), "-c", _PACKAGES_CODE], root, project, deny_network=True)
    steps.append(packages.evidence("sandbox.materialize.inventory"))
    if packages.returncode != 0 or packages.termination:
        raise _RuntimeBlocked(
            "SF-SANDBOX-INVENTORY",
            StageId.SANDBOX_MATERIALIZE,
            "installed package inventory failed",
            steps=steps,
        )
    installed = json.loads(packages.stdout)
    _verify_installed_packages(project / "uv.lock", installed)

    fork_probe = _run_sandboxed(
        [str(python), "-c", _FORK_PROBE_CODE],
        root,
        project,
        deny_network=True,
        deny_fork=True,
    )
    steps.append(fork_probe.evidence("sandbox.prepare.process-denial"))
    if fork_probe.returncode != 0 or fork_probe.termination:
        raise _RuntimeBlocked(
            "SF-SANDBOX-PROCESS-DENIAL",
            StageId.SANDBOX_PREPARE,
            "generated-code profile did not prove child-process denial",
            steps=steps,
        )

    tests = _run_sandboxed(
        [str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider"],
        root,
        project,
        deny_network=True,
        deny_fork=True,
    )
    steps.append(tests.evidence("audit.connected.generated-tests"))
    if tests.returncode != 0 or tests.termination:
        raise _RuntimeBlocked(
            "SF-RUNTIME-TESTS",
            StageId.AUDIT_CONNECTED,
            "generated tests failed or breached a limit",
            steps=steps,
        )

    protocol = _run_sandboxed(
        [str(python), "-c", _PROTOCOL_CODE],
        root,
        project,
        deny_network=True,
        deny_fork=True,
    )
    steps.append(protocol.evidence("audit.connected.protocol"))
    if protocol.returncode != 0 or protocol.termination:
        raise _RuntimeBlocked(
            "SF-RUNTIME-PROTOCOL",
            StageId.AUDIT_CONNECTED,
            "MCP negotiation or synthetic call failed",
            steps=steps,
        )
    try:
        payload = json.loads(protocol.stdout)
    except json.JSONDecodeError as exc:
        raise _RuntimeBlocked(
            "SF-RUNTIME-EVIDENCE",
            StageId.AUDIT_CONNECTED,
            "runtime evidence was not one JSON object",
            steps=steps,
        ) from exc
    try:
        _verify_runtime_capabilities(receipt, payload)
    except _RuntimeBlocked as exc:
        exc.steps = steps
        raise
    _assert_artifact_binding(receipt, project, StageId.AUDIT_CONNECTED)
    return payload, installed, steps


def _finalize_manifest(
    partial: SafeForgeManifest,
    receipt: ForgeReceiptV0Input,
    runtime_payload: dict[str, Any],
    installed: dict[str, str],
    timestamp: datetime,
    cleanup_verified: bool,
) -> SafeForgeManifest:
    if receipt.launch is None:
        raise _RuntimeBlocked(
            "SF-SANDBOX-LAUNCH-UNSUPPORTED",
            StageId.RECEIPT_FINALIZE,
            "final receipt requires a receipt-bound launch configuration",
        )
    launch = receipt.launch
    manifest = partial.model_copy(deep=True)
    coordinator = manifest.run.coordinator
    runtime_digest = _digest_json(
        {"runtime": runtime_payload, "installed": installed, "profile": "macos-seatbelt-zero-egress-v1"}
    )
    runtime_ref = ArtifactReference(
        artifact_id="connected-runtime-report",
        media_type="application/vnd.safeforge.runtime+json",
        digest=runtime_digest,
    )
    environment_ref = ArtifactReference(
        artifact_id="locked-runtime-environment",
        media_type="application/vnd.safeforge.environment+json",
        digest=_digest_json(installed),
    )
    policy_payload = {
        "profile": "macos-seatbelt-zero-egress-v1",
        "artifact": manifest.artifact.tree_digest,
        "audit": runtime_digest,
        "execution_mode": "fastmcp-in-memory-no-fork",
        "launch": launch.model_dump(mode="json"),
        "tools": [tool.tool_id for tool in manifest.toolbom],
    }
    policy_digest = _digest_json(policy_payload)
    sandbox_policy_digest = _digest_bytes(_seatbelt_profile(True, deny_fork=True).encode())
    manifest.stages.extend(
        [
            _passed(StageId.SANDBOX_PREPARE, coordinator, timestamp),
            _passed(StageId.SANDBOX_MATERIALIZE, coordinator, timestamp, outputs=[environment_ref]),
            _passed(StageId.AUDIT_CONNECTED, coordinator, timestamp, outputs=[runtime_ref]),
            _passed(StageId.TRUST_GRADE, coordinator, timestamp, inputs=[runtime_ref]),
            _passed(StageId.RUNTIME_POLICY_BIND, coordinator, timestamp, inputs=[runtime_ref]),
            _passed(StageId.PUBLICATION_DRY_RUN, coordinator, timestamp),
            _passed(StageId.RECEIPT_FINALIZE, coordinator, timestamp, inputs=[runtime_ref]),
        ]
    )
    manifest.subject.mcp_protocol_supported = [runtime_payload["protocol"]]
    manifest.subject.mcp_protocol_negotiated = runtime_payload["protocol"]
    manifest.sandbox = SandboxEvidence(
        provider="macos-seatbelt-zero-egress-v1",
        isolates=True,
        image_digest=_digest_json({"python": "3.12", "provider": "seatbelt"}),
        network="none",
        mounts=[],
        credential_mode="none",
        policy_digest=sandbox_policy_digest,
        home_isolated=True,
        cache_isolated=True,
        filesystem_denied=True,
        network_denied=True,
        keychain_denied=True,
        process_group_terminated=True,
        cleanup_verified=cleanup_verified,
        limits=_LIMITS,
    )
    manifest.audit = AuditEvidence(
        report=runtime_ref,
        report_schema_version=1,
        detector_ids=["runtime-capability-binding", "synthetic-tool-call", "process-cleanup"],
        connection_statuses={receipt.source.server_id: "connected"},
        warning_codes=[],
    )
    manifest.grade = GradeEvidence(
        grade="A",
        transparency="All research-profile runtime gates passed inside a zero-egress Seatbelt boundary.",
        audit_report_digest=runtime_digest,
        grading_policy_version="safeforge.research-grade.v1",
        current=True,
        confidence="high",
        limitations=[
            "Zero-egress macOS research profile only; no VM boundary or hostname allowlisting claim.",
            "MCP negotiation uses an in-memory transport so generated code can be kernel-denied child processes.",
            "Seatbelt does not provide a process-metadata namespace; generated child creation is denied.",
        ],
    )
    policy_kinds: tuple[Literal["audit", "egress"], ...] = ("audit", "egress")
    manifest.policies = [
        PolicyEvidence(
            kind=kind,
            policy_id=f"safeforge-{kind}-research",
            policy_version="1",
            policy_digest=policy_digest,
            result="passed",
            artifact_digest=manifest.artifact.tree_digest,
            audit_digest=runtime_digest,
        )
        for kind in policy_kinds
    ]
    manifest.publication = PublicationEvidence(
        target="local-install-plan",
        metadata_digest=_digest_json(
            {
                "server_id": receipt.source.server_id,
                "packages": receipt.artifact.package_identities,
                "execution_mode": "fastmcp-in-memory-no-fork",
                "launch": launch.model_dump(mode="json"),
            }
        ),
        schema_version="1",
        result="passed",
        dry_run=True,
    )
    receipt_ref = ArtifactReference(
        artifact_id="forge-receipt-final-binding",
        media_type="application/vnd.safeforge.forge-receipt+json",
        digest=_digest_json(receipt.model_dump(mode="json")),
    )
    manifest.integrity = IntegrityEvidence(receipt_refs=[receipt_ref, runtime_ref])
    manifest.run.decision = PipelineDecision.ELIGIBLE
    manifest.limitations = [
        "Runtime execution used no credentials and no network.",
        "MCP negotiation used FastMCP's in-memory protocol transport under process-fork denial.",
        "Declared-egress receipts remain blocked until redirect-safe allowlisting is proven.",
    ]
    return manifest


def _verify_runtime_capabilities(receipt: ForgeReceiptV0Input, payload: dict[str, Any]) -> None:
    tools = payload.get("tools")
    if not isinstance(tools, list) or {item.get("name") for item in tools if isinstance(item, dict)} != {
        item.name for item in receipt.toolbom
    }:
        raise _RuntimeBlocked(
            "SF-RUNTIME-TOOLS", StageId.AUDIT_CONNECTED, "runtime tool set differs from ToolBOM"
        )
    if payload.get("prompts") or payload.get("resources"):
        raise _RuntimeBlocked(
            "SF-RUNTIME-HIDDEN-CAPABILITY",
            StageId.AUDIT_CONNECTED,
            "undeclared prompt or resource discovered",
        )
    by_name = {item["name"]: item for item in tools}
    for expected in receipt.toolbom:
        actual = by_name[expected.name]
        annotations = actual.get("annotations") or {}
        normalized = {
            "read_only": annotations.get("readOnlyHint"),
            "destructive": annotations.get("destructiveHint"),
            "idempotent": annotations.get("idempotentHint"),
            "open_world": annotations.get("openWorldHint"),
        }
        if _digest_bytes((actual.get("description") or "").encode()) != expected.description_digest:
            raise _RuntimeBlocked(
                "SF-RUNTIME-DESCRIPTION", StageId.AUDIT_CONNECTED, "runtime tool description changed"
            )
        if _digest_json(actual.get("inputSchema")) != expected.input_schema_digest:
            raise _RuntimeBlocked(
                "SF-RUNTIME-INPUT-SCHEMA", StageId.AUDIT_CONNECTED, "runtime input schema changed"
            )
        if _digest_json(actual.get("outputSchema")) != expected.output_schema_digest:
            raise _RuntimeBlocked(
                "SF-RUNTIME-OUTPUT-SCHEMA", StageId.AUDIT_CONNECTED, "runtime output schema changed"
            )
        if normalized != expected.annotations.model_dump():
            raise _RuntimeBlocked(
                "SF-RUNTIME-ANNOTATIONS", StageId.AUDIT_CONNECTED, "runtime annotations contradict ToolBOM"
            )
    if payload.get("call") != {"echo": "safeforge"}:
        raise _RuntimeBlocked(
            "SF-RUNTIME-SYNTHETIC-CALL", StageId.AUDIT_CONNECTED, "bounded synthetic echo result changed"
        )


def _verify_installed_packages(lock_path: Path, installed: dict[str, str]) -> None:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    allowed: dict[str, set[str]] = {}
    for item in lock.get("package", []):
        allowed.setdefault(_normalize_name(item["name"]), set()).add(item["version"])
    actual = {_normalize_name(name): version for name, version in installed.items()}
    if "fastmcp" not in actual or any(
        name not in allowed or version not in allowed[name] for name, version in actual.items()
    ):
        raise _RuntimeBlocked(
            "SF-SANDBOX-DEPENDENCY-SET", StageId.SANDBOX_MATERIALIZE, "installed packages differ from uv.lock"
        )


def _assert_artifact_binding(receipt: ForgeReceiptV0Input, artifact_root: Path, stage: StageId) -> None:
    failure = _verify_artifact_root(receipt, artifact_root)
    if failure is None:
        return
    code = failure.findings[0].code if failure.findings else "SF-FORGE-ARTIFACT-RECHECK"
    raise _RuntimeBlocked(
        code,
        stage,
        "the materialized artifact tree no longer matches the forge receipt",
    )


def _verify_lock_sources(lock_path: Path, server_id: str) -> None:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    for package in lock.get("package", []):
        name = _normalize_name(package["name"])
        source = package.get("source")
        if name == _normalize_name(server_id) and source == {"virtual": "."}:
            continue
        if source != {"registry": "https://pypi.org/simple"}:
            raise _RuntimeBlocked(
                "SF-SANDBOX-LOCK-SOURCE",
                StageId.SANDBOX_PREPARE,
                "a lock source is outside the PyPI allowlist",
            )
        downloads = []
        if isinstance(package.get("sdist"), dict):
            downloads.append(package["sdist"])
        downloads.extend(package.get("wheels", []))
        for download in downloads:
            parsed = urlsplit(download.get("url", ""))
            if (
                parsed.scheme != "https"
                or parsed.hostname != "files.pythonhosted.org"
                or not str(download.get("hash", "")).startswith("sha256:")
            ):
                raise _RuntimeBlocked(
                    "SF-SANDBOX-LOCK-SOURCE",
                    StageId.SANDBOX_PREPARE,
                    "a locked distribution is outside the exact download allowlist",
                )


def _run_sandboxed(
    command: list[str],
    root: Path,
    cwd: Path,
    *,
    deny_network: bool,
    deny_fork: bool = False,
    extra_env: dict[str, str] | None = None,
) -> _CommandResult:
    stdout_path = root / "evidence" / f"{time.monotonic_ns()}-stdout"
    stderr_path = root / "evidence" / f"{time.monotonic_ns()}-stderr"
    env = {**_environment(root), **(extra_env or {})}
    profile = _seatbelt_profile(deny_network, root, deny_fork=deny_fork)
    termination: str | None = None
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [str(_SANDBOX_EXEC), "-p", profile, *command],
            cwd=cwd,
            env=env,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
            preexec_fn=_apply_rlimits,
        )
        deadline = time.monotonic() + _LIMITS["wall_seconds"]
        while process.poll() is None:
            if time.monotonic() >= deadline:
                termination = "wall_time"
            else:
                count, rss = _process_group_metrics(process.pid)
                if count > _LIMITS["processes"]:
                    termination = "process_count"
                elif rss > _LIMITS["memory_bytes"]:
                    termination = "memory"
                elif _directory_size(root) > _LIMITS["disk_bytes"]:
                    termination = "disk"
            if termination:
                _kill_group(process.pid)
                break
            time.sleep(0.05)
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            termination = termination or "shutdown"
            _kill_group(process.pid)
            returncode = process.wait(timeout=5)
    return _CommandResult(
        returncode=returncode,
        stdout=stdout_path.read_text(encoding="utf-8", errors="replace")[:_MAX_OUTPUT],
        stderr=stderr_path.read_text(encoding="utf-8", errors="replace")[:_MAX_OUTPUT],
        termination=termination,
    )


def _environment(root: Path) -> dict[str, str]:
    return {
        "HOME": str(root / "home"),
        "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(root / "tmp"),
        "UV_CACHE_DIR": str(root / "cache"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "NO_COLOR": "1",
        "FASTMCP_SHOW_SERVER_BANNER": "false",
    }


def _seatbelt_profile(deny_network: bool, root: Path | None = None, *, deny_fork: bool = False) -> str:
    boundary = str(root) if root is not None else "/private/tmp/<runtime-root>"
    write_paths = (
        [f"{boundary}/{name}" for name in ("home", "cache", "tmp", "evidence")] if deny_fork else [boundary]
    )
    rules = [
        "(version 1)",
        "(allow default)",
        '(deny file-read* (subpath "/Users"))',
        '(deny file-read* (subpath "/Volumes"))',
        '(deny file-read* (subpath "/Library/Keychains"))',
        "(deny file-write*)",
        '(allow file-write* (literal "/dev/null"))',
        '(deny mach-lookup (global-name "com.apple.securityd"))',
        '(deny mach-lookup (global-name "com.apple.security.agent"))',
    ]
    rules.extend(f'(allow file-write* (subpath "{path}"))' for path in write_paths)
    if deny_network:
        rules.append("(deny network*)")
    if deny_fork:
        rules.append("(deny process-fork)")
    return "".join(rules)


def _apply_rlimits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (_LIMITS["cpu_seconds"], _LIMITS["cpu_seconds"]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_LIMITS["file_bytes"], _LIMITS["file_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_LIMITS["open_files"], _LIMITS["open_files"]))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _process_group_metrics(pgid: int) -> tuple[int, int]:
    result = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,rss="], capture_output=True, text=True, check=False
    )
    count = 0
    rss = 0
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] == str(pgid):
            count += 1
            rss += int(fields[2]) * 1024
    return count, rss


def _directory_size(root: Path) -> int:
    total = 0
    for base, _dirs, files in os.walk(root):
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except OSError:
                pass
    return total


def _kill_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _kill_root_processes(root: Path) -> None:
    marker = str(root)
    result = subprocess.run(["/bin/ps", "-axo", "pid=,command="], capture_output=True, text=True, check=False)
    for line in result.stdout.splitlines():
        if marker not in line:
            continue
        try:
            os.kill(int(line.strip().split(maxsplit=1)[0]), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass


def _passed(
    stage: StageId,
    producer: Any,
    timestamp: datetime,
    *,
    inputs: list[ArtifactReference] | None = None,
    outputs: list[ArtifactReference] | None = None,
) -> StageAttempt:
    return StageAttempt(
        stage_id=stage,
        attempt=1,
        state=StageState.PASSED,
        producer=producer,
        started_at=timestamp,
        finished_at=timestamp,
        inputs=inputs or [],
        outputs=outputs or [],
        coverage=Coverage(),
    )


def _blocked_result(
    preinstall: SafeForgeCoordinatorResult,
    code: str,
    stage: StageId,
    message: str,
    *,
    steps: list[RuntimeStepEvidence] | None = None,
) -> SafeForgePipelineResult:
    finding = SafeForgeFinding(code=code, severity=FindingSeverity.ERROR, message=message, stage_id=stage)
    manifest = None
    if preinstall.preinstall is not None and preinstall.preinstall.manifest is not None:
        manifest = preinstall.preinstall.manifest.model_copy(deep=True)
        manifest.run.decision = PipelineDecision.BLOCKED
        manifest.stages.append(
            StageAttempt(
                stage_id=stage,
                attempt=1,
                state=StageState.BLOCKED,
                producer=manifest.run.coordinator,
                finished_at=manifest.run.created_at,
                failure_codes=[code],
                limitations=[message],
            )
        )
    return SafeForgePipelineResult(
        accepted=False,
        preinstall=preinstall,
        manifest=manifest,
        findings=[finding],
        runtime_steps=steps or [],
    )


def _normalize_name(value: str) -> str:
    return value.lower().replace("_", "-").replace(".", "-")


def _digest_json(value: object) -> str:
    return _digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


_PROBE_CODE = r"""import json, os, pwd, socket, subprocess
from pathlib import Path
host_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
def denied(fn):
    try:
        fn()
    except (OSError, PermissionError):
        return True
    return False
print(json.dumps({
    "home_read_denied": denied(lambda: next(host_home.iterdir())),
    "home_write_denied": denied(lambda: (host_home / ".safeforge-probe").write_text("x")),
    "keychain_denied": subprocess.run(["/usr/bin/security", "default-keychain", "-d", "user"], capture_output=True).returncode != 0,
    "network_denied": denied(lambda: socket.create_connection(("127.0.0.1", 9), timeout=0.1)),
    "outside_write_denied": denied(lambda: Path("/private/tmp/safeforge-outside-write").write_text("x")),
}, sort_keys=True))"""

_PACKAGES_CODE = r"""import importlib.metadata, json
print(json.dumps(dict(sorted({dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions()}.items()))))"""

_FORK_PROBE_CODE = r"""import os
try:
    child = os.fork()
except OSError:
    raise SystemExit(0)
if child == 0:
    os._exit(0)
os.waitpid(child, 0)
raise SystemExit(1)"""

_PROTOCOL_CODE = r"""import asyncio, json
from fastmcp import Client
from server import mcp
async def main():
    async with Client(mcp) as client:
        initialized = client.initialize_result
        tools = await client.list_tools()
        try:
            prompts = await client.list_prompts()
        except Exception:
            prompts = []
        try:
            resources = await client.list_resources()
        except Exception:
            resources = []
        call = await client.call_tool("echo", {"message": "safeforge"})
        print(json.dumps({
            "protocol": initialized.protocolVersion if initialized is not None else None,
            "tools": [item.model_dump(mode="json", by_alias=True) for item in tools],
            "prompts": [item.model_dump(mode="json", by_alias=True) for item in prompts],
            "resources": [item.model_dump(mode="json", by_alias=True) for item in resources],
            "call": call.data,
        }, sort_keys=True))
asyncio.run(main())"""
