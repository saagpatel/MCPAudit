"""Actual-vs-declared comparison, deterministic capsule export, and verification."""

from __future__ import annotations

import fnmatch
import hmac
import html
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Literal

from mcp_audit import __version__
from mcp_audit.proof_models import (
    CAPSULE_INDEX_SCHEMA,
    CAPSULE_SCHEMA,
    ActionDeclaration,
    BillComparison,
    CapsuleIndex,
    CapsuleIntegrity,
    CapsulePayload,
    ComparisonFinding,
    EvidenceCapsule,
    IndexedArtifact,
    Observation,
    ProducerEvidence,
    ReleaseTrustManifest,
    SurfaceObservation,
    canonical_json_bytes,
    sha256_bytes,
)

_MAX_INDEX_BYTES = 1024 * 1024
_MAX_CAPSULE_BYTES = 32 * 1024 * 1024
_MAX_REPORT_BYTES = 8 * 1024 * 1024


def compare_bill(declaration: ActionDeclaration, observation: Observation) -> BillComparison:
    capabilities: list[str] = []
    findings: list[ComparisonFinding] = []
    executable = observation.command.executable
    database_paths = {item.path for item in observation.database_changes}
    non_database_file_changes = [item for item in observation.file_changes if item.path not in database_paths]
    if executable not in declaration.tools:
        findings.append(
            ComparisonFinding(
                code="undeclared_tool",
                severity="error",
                message=f"observed executable {executable!r} is not declared",
                evidence=[executable],
            )
        )
    filesystem_attempt_without_persisted_change = (
        observation.filesystem.attempted is True and not non_database_file_changes
    )
    filesystem_effect_observed = (
        bool(non_database_file_changes) or filesystem_attempt_without_persisted_change
    )
    if filesystem_effect_observed:
        capabilities.append("file_write")
        if declaration.side_effects.filesystem != "write" and "file_write" not in declaration.permissions:
            findings.append(
                ComparisonFinding(
                    code=(
                        "undeclared_file_write"
                        if non_database_file_changes
                        else "undeclared_file_write_attempt"
                    ),
                    severity="error",
                    message=(
                        "the command changed files without declaring file-write authority"
                        if non_database_file_changes
                        else "the command attempted a file write without declaring file-write authority"
                    ),
                    evidence=[item.path for item in non_database_file_changes],
                )
            )
        outside = [
            item.path
            for item in non_database_file_changes
            if declaration.destinations.files
            and not any(fnmatch.fnmatch(item.path, pattern) for pattern in declaration.destinations.files)
        ]
        if outside:
            findings.append(
                ComparisonFinding(
                    code="expanded_file_destination",
                    severity="error",
                    message="observed file changes expanded beyond declared destinations",
                    evidence=outside,
                )
            )
    database_effect_observed = bool(observation.database_changes) or observation.database.attempted is True
    if database_effect_observed:
        capabilities.append("database_write")
        if declaration.side_effects.database != "write" and "database_write" not in declaration.permissions:
            findings.append(
                ComparisonFinding(
                    code=(
                        "undeclared_database_write"
                        if observation.database_changes
                        else "undeclared_database_write_attempt"
                    ),
                    severity="error",
                    message=(
                        "the command changed a database without declaring database-write authority"
                        if observation.database_changes
                        else (
                            "the command attempted a database write without declaring "
                            "database-write authority"
                        )
                    ),
                    evidence=[item.path for item in observation.database_changes],
                )
            )
        outside = [
            item.path
            for item in observation.database_changes
            if declaration.destinations.databases
            and not any(fnmatch.fnmatch(item.path, pattern) for pattern in declaration.destinations.databases)
        ]
        if outside:
            findings.append(
                ComparisonFinding(
                    code="expanded_database_destination",
                    severity="error",
                    message="observed database changes expanded beyond declared destinations",
                    evidence=outside,
                )
            )
    if observation.network.surface.attempted:
        capabilities.append("network")
        if declaration.side_effects.network not in {"attempt", "connect"} and (
            "network" not in declaration.permissions
        ):
            findings.append(
                ComparisonFinding(
                    code="undeclared_network_attempt",
                    severity="error",
                    message="the command attempted network activity without declaring network authority",
                    evidence=[key for key, value in observation.network.counters.items() if value > 0],
                )
            )
        elif declaration.destinations.network:
            findings.append(
                ComparisonFinding(
                    code="network_destination_unknown",
                    severity="unknown",
                    message="kernel counters observed activity but cannot identify the destination",
                )
            )
    if observation.command.timed_out:
        findings.append(
            ComparisonFinding(
                code="command_timeout",
                severity="error",
                message="the command exceeded the observation time limit",
            )
        )
    elif observation.command.exit_code != 0:
        findings.append(
            ComparisonFinding(
                code="command_failed",
                severity="error",
                message=f"the command exited with status {observation.command.exit_code}",
            )
        )
    if (
        not observation.filesystem.complete
        or not observation.database.complete
        or not observation.network.surface.complete
    ):
        findings.append(
            ComparisonFinding(
                code="observation_incomplete",
                severity="unknown",
                message="one or more requested observation surfaces were incomplete",
            )
        )
    surfaces = (
        observation.filesystem,
        observation.database,
        observation.network.surface,
    )
    if any(
        surface.complete
        and (
            surface.attempted is None
            or surface.decision == "unknown"
            or surface.outcome == "unknown"
            or surface.persisted == "unknown"
        )
        for surface in surfaces
    ):
        findings.append(
            ComparisonFinding(
                code="observation_state_unknown",
                severity="unknown",
                message="a completed observation surface retained an unknown state",
            )
        )
    if any(surface.complete and _surface_state_is_contradictory(surface) for surface in surfaces):
        findings.append(
            ComparisonFinding(
                code="observation_state_contradictory",
                severity="unknown",
                message="a completed observation surface contained contradictory state fields",
            )
        )
    verdict: Literal["pass", "block", "unknown"] = (
        "block"
        if any(item.severity == "error" for item in findings)
        else "unknown"
        if any(item.severity == "unknown" for item in findings)
        else "pass"
    )
    return BillComparison(
        declared_tools=sorted(declaration.tools),
        observed_tools=[executable],
        declared_permissions=sorted(declaration.permissions),
        observed_capabilities=sorted(set(capabilities)),
        findings=findings,
        verdict=verdict,
    )


def _surface_state_is_contradictory(surface: SurfaceObservation) -> bool:
    if surface.attempted is False:
        return (
            surface.decision != "not_applicable"
            or surface.outcome != "not_applicable"
            or surface.persisted != "unchanged"
        )
    if surface.attempted is True and (
        surface.decision == "not_applicable" or surface.outcome == "not_applicable"
    ):
        return True
    if (surface.decision == "not_applicable") != (surface.outcome == "not_applicable"):
        return True
    if surface.decision == "blocked" and surface.outcome == "succeeded":
        return True
    return surface.persisted == "changed" and surface.attempted is not True


def build_capsule(
    declaration: ActionDeclaration,
    observation: Observation,
    comparison: BillComparison,
    trust_manifest: ReleaseTrustManifest,
) -> EvidenceCapsule:
    subject = observation.subject_snapshot
    if subject is None:
        raise ValueError("new capsules require staged subject snapshot evidence")
    if not _trust_manifest_matches_subject(observation, trust_manifest):
        raise ValueError("trust manifest subject evidence does not match the staged observation snapshot")
    if comparison != compare_bill(declaration, observation):
        raise ValueError("comparison does not match the declaration and observation")
    commit, dirty, provenance_source = _producer_state()
    producer_limitations: list[str] = []
    if commit is None:
        producer_limitations.append(
            "Producer commit is UNKNOWN; producer authority cannot be bound to source."
        )
    if dirty:
        producer_limitations.append(
            "Producer worktree is dirty; the producer commit does not bind all executing code."
        )
    limitations = sorted(
        set(
            declaration.limitations
            + observation.limitations
            + trust_manifest.limitations
            + producer_limitations
            + [
                "Internal hashes prove consistency, not authority; anchor capsule-index.json externally.",
                "Containment is partial because container/VM/hypervisor escape resistance is not proven.",
            ]
        )
    )
    payload = CapsulePayload(
        declaration=declaration,
        observation=observation,
        comparison=comparison,
        trust_manifest=trust_manifest,
        producer=ProducerEvidence(
            version=__version__,
            commit=commit,
            dirty=dirty,
            provenance_source=provenance_source,
        ),
        limitations=limitations,
    )
    return EvidenceCapsule(
        payload=payload,
        integrity=CapsuleIntegrity(payload_sha256=sha256_bytes(canonical_json_bytes(payload))),
    )


def _trust_manifest_matches_subject(
    observation: Observation,
    trust_manifest: ReleaseTrustManifest,
) -> bool:
    subject = observation.subject_snapshot
    return bool(
        subject is not None
        and trust_manifest.repository_commit == subject.repository_commit
        and trust_manifest.repository_dirty == subject.repository_dirty
        and trust_manifest.repository_staged_tree_sha256 == subject.staged_tree_sha256
        and trust_manifest.dependencies == subject.dependencies
        and trust_manifest.diagnostics == subject.diagnostics
    )


def export_capsule(capsule: EvidenceCapsule, output: Path) -> str:
    if output.is_symlink():
        raise ValueError("output directory must not be a symlink")
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    capsule_bytes = canonical_json_bytes(capsule)
    html_bytes = render_offline_html(capsule).encode("utf-8")
    if len(capsule_bytes) > _MAX_CAPSULE_BYTES or len(html_bytes) > _MAX_REPORT_BYTES:
        raise ValueError("capsule or offline report exceeds the verification size limit")
    (output / "capsule.json").write_bytes(capsule_bytes)
    (output / "report.html").write_bytes(html_bytes)
    artifacts = [
        IndexedArtifact(
            path="capsule.json",
            sha256=sha256_bytes(capsule_bytes),
            bytes=len(capsule_bytes),
            content_type="application/json",
            logical_role="evidence",
        ),
        IndexedArtifact(
            path="report.html",
            sha256=sha256_bytes(html_bytes),
            bytes=len(html_bytes),
            content_type="text/html",
            logical_role="view",
        ),
    ]
    index = CapsuleIndex(
        subject_commit=capsule.payload.trust_manifest.repository_commit,
        producer_commit=capsule.payload.producer.commit,
        artifacts=artifacts,
    )
    index_bytes = canonical_json_bytes(index)
    (output / "capsule-index.json").write_bytes(index_bytes)
    return sha256_bytes(index_bytes)


def render_offline_html(capsule: EvidenceCapsule) -> str:
    comparison = capsule.payload.comparison
    trust = capsule.payload.trust_manifest
    color = "#4ade80" if comparison.verdict == "pass" else "#fb7185"
    findings = (
        "".join(
            f"<li><code>{html.escape(item.code)}</code> {html.escape(item.message)}</li>"
            for item in comparison.findings
        )
        or "<li>No declaration mismatch was found.</li>"
    )
    trust_rows = (
        "".join(
            "<tr>"
            f"<td>{html.escape(entry.dependency.config_name)}</td>"
            f"<td>{html.escape(entry.dependency.identity_name or 'unknown')}</td>"
            f"<td>{html.escape(entry.evidence.state)}</td>"
            f"<td>{html.escape(entry.evidence.grade or 'unknown')}</td>"
            "</tr>"
            for entry in trust.entries
        )
        or "<tr><td colspan='4'>No MCP dependency was discovered.</td></tr>"
    )
    limitations = "".join(f"<li>{html.escape(item)}</li>" for item in capsule.payload.limitations)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Proof Before Action</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 20px;
background:#10141b;color:#e5e7eb}}h1,h2{{line-height:1.2}}code{{color:#93c5fd}}
.verdict{{color:{color};font-size:1.4rem;font-weight:700}}table{{width:100%;border-collapse:collapse}}
th,td{{border:1px solid #374151;padding:8px;text-align:left}}.muted{{color:#9ca3af}}
</style></head><body>
<h1>Proof Before Action</h1>
<p><strong>Action:</strong> {html.escape(capsule.payload.declaration.name)}</p>
<p class="verdict">Actual vs declared: {html.escape(comparison.verdict.upper())}</p>
<p class="muted">Offline projection. The canonical evidence is capsule.json.</p>
<h2>Observed effects</h2>
<ul>
<li>File changes: {len(capsule.payload.observation.file_changes)}</li>
<li>Database changes: {len(capsule.payload.observation.database_changes)}</li>
<li>Network attempt observed: {html.escape(str(capsule.payload.observation.network.surface.attempted))}</li>
</ul>
<h2>Declaration comparison</h2><ul>{findings}</ul>
<h2>Release trust manifest</h2>
<table><thead><tr><th>Config</th><th>Identity</th><th>Evidence state</th><th>Grade</th></tr></thead>
<tbody>{trust_rows}</tbody></table>
<h2>Limitations and unknowns</h2><ul>{limitations}</ul>
</body></html>
"""


def verify_capsule(
    root: Path,
    *,
    expect_subject_commit: str | None = None,
    expect_producer_commit: str | None = None,
    expect_schema: str | None = None,
    expect_root_sha256: str | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    required = ("capsule.json", "report.html", "capsule-index.json")
    for name in required:
        path = root / name
        if path.is_symlink():
            errors.append({"code": "unsafe_artifact", "message": f"{name} is a symlink"})
        elif not path.is_file():
            errors.append({"code": "missing_artifact", "message": f"{name} is missing"})
    if errors:
        return {"valid": False, "errors": errors}
    sizes = {
        "capsule-index.json": _MAX_INDEX_BYTES,
        "capsule.json": _MAX_CAPSULE_BYTES,
        "report.html": _MAX_REPORT_BYTES,
    }
    for name, maximum in sizes.items():
        if (root / name).stat().st_size > maximum:
            errors.append({"code": "artifact_too_large", "message": name})
    if errors:
        return {"valid": False, "errors": errors}
    index_bytes = (root / "capsule-index.json").read_bytes()
    root_sha256 = sha256_bytes(index_bytes)
    try:
        raw_index = json.loads(index_bytes)
        index = CapsuleIndex.model_validate_json(index_bytes, strict=True)
        canonical_index_bytes = canonical_json_bytes(raw_index)
    except Exception as exc:  # Pydantic reports a stable failure class below.
        return {
            "valid": False,
            "root_sha256": root_sha256,
            "errors": [{"code": "index_schema_invalid", "message": type(exc).__name__}],
        }
    if canonical_index_bytes != index_bytes:
        errors.append(
            {
                "code": "index_noncanonical",
                "message": "capsule index is not canonical JSON",
            }
        )
    if index.schema_version != CAPSULE_INDEX_SCHEMA:
        errors.append({"code": "index_schema_unsupported", "message": index.schema_version})
    for artifact in index.artifacts:
        path = root / artifact.path
        if path.is_symlink():
            errors.append({"code": "unsafe_artifact", "message": artifact.path})
            continue
        if not path.is_file():
            errors.append({"code": "missing_artifact", "message": artifact.path})
            continue
        value = path.read_bytes()
        if len(value) != artifact.bytes or sha256_bytes(value) != artifact.sha256:
            errors.append({"code": "artifact_tampered", "message": artifact.path})
    capsule_bytes = (root / "capsule.json").read_bytes()
    try:
        raw = json.loads(capsule_bytes)
        actual_schema = raw.get("schema_version")
        if actual_schema != CAPSULE_SCHEMA:
            errors.append({"code": "capsule_schema_unsupported", "message": str(actual_schema)})
        capsule = EvidenceCapsule.model_validate_json(capsule_bytes, strict=True)
        canonical_capsule_bytes = canonical_json_bytes(raw)
    except Exception as exc:
        errors.append({"code": "capsule_schema_invalid", "message": type(exc).__name__})
        capsule = None
    if capsule is not None:
        if canonical_capsule_bytes != capsule_bytes:
            errors.append(
                {
                    "code": "capsule_noncanonical",
                    "message": "capsule is not canonical JSON",
                }
            )
        payload_digest = sha256_bytes(canonical_json_bytes(raw["payload"]))
        if payload_digest != capsule.integrity.payload_sha256:
            errors.append({"code": "payload_tampered", "message": "payload hash mismatch"})
        subject_snapshot_missing = capsule.payload.observation.subject_snapshot is None
        manifest_binding_missing = capsule.payload.trust_manifest.repository_staged_tree_sha256 is None
        if subject_snapshot_missing:
            errors.append(
                {
                    "code": "subject_snapshot_missing",
                    "message": "staged subject snapshot evidence is required",
                }
            )
        if manifest_binding_missing:
            errors.append(
                {
                    "code": "subject_manifest_binding_missing",
                    "message": "trust manifest staged-tree binding is required",
                }
            )
        if (
            not subject_snapshot_missing
            and not manifest_binding_missing
            and not _trust_manifest_matches_subject(
                capsule.payload.observation,
                capsule.payload.trust_manifest,
            )
        ):
            errors.append(
                {
                    "code": "subject_manifest_mismatch",
                    "message": "trust manifest does not match the staged observation snapshot",
                }
            )
        expected_comparison = compare_bill(
            capsule.payload.declaration,
            capsule.payload.observation,
        )
        if capsule.payload.comparison != expected_comparison:
            errors.append(
                {
                    "code": "comparison_mismatch",
                    "message": "comparison does not match the declaration and observation",
                }
            )
        expected_report = render_offline_html(capsule).encode("utf-8")
        if (root / "report.html").read_bytes() != expected_report:
            errors.append(
                {
                    "code": "report_projection_mismatch",
                    "message": "offline report does not match the canonical capsule projection",
                }
            )
        if expect_schema and capsule.schema_version != expect_schema:
            errors.append(
                {
                    "code": "expected_schema_mismatch",
                    "message": f"expected {expect_schema}, got {capsule.schema_version}",
                }
            )
        subject_commit = capsule.payload.trust_manifest.repository_commit
        producer_commit = capsule.payload.producer.commit
        if index.subject_commit != subject_commit:
            errors.append(
                {
                    "code": "index_subject_mismatch",
                    "message": "capsule index subject commit does not match the capsule",
                }
            )
        if index.producer_commit != producer_commit:
            errors.append(
                {
                    "code": "index_producer_mismatch",
                    "message": "capsule index producer commit does not match the capsule",
                }
            )
        if expect_subject_commit and subject_commit != expect_subject_commit:
            errors.append(
                {
                    "code": "subject_commit_mismatch",
                    "message": f"expected {expect_subject_commit}, got {subject_commit}",
                }
            )
        if expect_producer_commit and producer_commit != expect_producer_commit:
            errors.append(
                {
                    "code": "producer_commit_mismatch",
                    "message": f"expected {expect_producer_commit}, got {producer_commit}",
                }
            )
    root_matches = bool(expect_root_sha256 and hmac.compare_digest(root_sha256, expect_root_sha256))
    if expect_root_sha256 and not root_matches:
        errors.append(
            {
                "code": "authority_root_mismatch",
                "message": f"expected {expect_root_sha256}, got {root_sha256}",
            }
        )
    return {
        "valid": not errors,
        "root_sha256": root_sha256,
        "authority": "anchored" if root_matches else "unverified",
        "errors": errors,
    }


def _producer_state() -> tuple[
    str | None,
    bool | None,
    Literal["build-metadata", "source-checkout"] | None,
]:
    embedded = _embedded_build_provenance()
    if embedded is not None:
        return (*embedded, "build-metadata")
    module_path = Path(__file__).resolve()
    root = module_path.parents[2]
    expected_module = root / "src/mcp_audit/proof_capsule.py"
    try:
        if expected_module.resolve() != module_path:
            return None, None, None
    except OSError:
        return None, None, None
    try:
        top_level = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": os.environ.get("PATH", "")},
        ).stdout.strip()
        if Path(top_level).resolve() != root:
            return None, None, None
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": os.environ.get("PATH", "")},
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": os.environ.get("PATH", "")},
        ).stdout
        return commit, bool(status), "source-checkout"
    except (OSError, subprocess.SubprocessError):
        return None, None, None


def _embedded_build_provenance() -> tuple[str | None, bool | None] | None:
    path = Path(__file__).with_name("_build_provenance.json")
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != "mcp-audits.build-provenance.v1":
            return None, None
        commit = payload.get("commit")
        dirty = payload.get("dirty")
        if commit is not None and (
            not isinstance(commit, str)
            or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
        ):
            return None, None
        if dirty is not None and not isinstance(dirty, bool):
            return None, None
        return commit, dirty
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, None
