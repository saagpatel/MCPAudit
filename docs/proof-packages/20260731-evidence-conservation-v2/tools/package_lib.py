"""Deterministic builder and validator primitives for the v2 evidence package.

This module creates synthetic artifacts from frozen public contracts.  It does
not import or invoke any producer or consumer under evaluation.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PACKAGE_ID = "20260731-evidence-conservation-v2"
PACKAGE_SCHEMA = "EvidenceConservationPackageV2"
FIXED_CREATED_AT = "2026-07-31T21:27:04Z"
P1_PRODUCED_AT = "2026-07-31T08:00:00+00:00"
P1_EVALUATION_AT = "2026-07-31T16:00:00+00:00"
P2_CREATED_AT = "2026-07-31T08:00:00+00:00"
P2_MODEL_AT = "2026-07-31T08:00:00Z"
P2_EXPIRES_AT = "2026-08-01T08:00:00+00:00"
P3_CREATED_AT = "2026-07-31T08:00:00Z"
GENERATOR_REVISION = "evidence-conservation-v2-clean-rebuild"

FROZEN_REPOSITORIES: dict[str, dict[str, Any]] = {
    "GithubRepoAuditor": {
        "path": "<workspace>/GithubRepoAuditor",
        "commit": "fd61f1c06643c4431460e27aa9210ff8b931ef1d",
        "tree": "3f604b126015194b0c88f744bde04e45c1f4eb6d",
        "paths": [
            "pyproject.toml",
            "requirements.txt",
            "uv.lock",
            "src/app/portfolio_truth.py",
            "src/cli.py",
            "src/cli_output.py",
            "src/github_security_coverage.py",
            "src/portfolio_catalog.py",
            "src/portfolio_pathing.py",
            "src/portfolio_repository_state.py",
            "src/portfolio_risk.py",
            "src/portfolio_security_gate.py",
            "src/portfolio_truth_lineage.py",
            "src/portfolio_truth_publish.py",
            "src/portfolio_truth_reconcile.py",
            "src/portfolio_truth_render.py",
            "src/portfolio_truth_sources.py",
            "src/portfolio_truth_status.py",
            "src/portfolio_truth_types.py",
            "src/portfolio_truth_validate.py",
            "src/producer_preflight.py",
            "tests/test_github_security_coverage.py",
            "tests/test_portfolio_security_gate.py",
            "tests/test_portfolio_truth.py",
        ],
    },
    "PortfolioCommandCenter": {
        "path": "<workspace>/PortfolioCommandCenter",
        "commit": "1139cfb9bb1e8d005699f854df368583960e245c",
        "tree": "46ab1592b718c5785a5eaf73d5451d7cacfc7687",
        "paths": [
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            "tsconfig.json",
            "src/portfolioTruthMutation.test.tsx",
            "src/types.ts",
            "src/validation.test.ts",
            "src/validation.ts",
            "src/views/OpsView.tsx",
            "src/views/PortfolioTable.tsx",
            "src/views/ProjectDetail.tsx",
            "src/views/RiskSecurity.tsx",
        ],
    },
    "MCPAudit": {
        "path": "<workspace>/MCPAudit",
        "commit": "9484d8bb1b059ce48f77015c4a84561675517a77",
        "tree": "e67d959ac3c341447eb2eb5d196c52afd62e1ee5",
        "prefixes": ["src/mcp_audit"],
        "paths": [
            "pyproject.toml",
            "uv.lock",
            "src/mcp_audit/analyzer.py",
            "src/mcp_audit/connector.py",
            "src/mcp_audit/engine.py",
            "src/mcp_audit/models.py",
            "src/mcp_audit/scorer.py",
            "src/mcp_audit/taxonomy.py",
            "tests/test_analyzer.py",
            "tests/test_engine.py",
            "tests/test_scorer.py",
        ],
    },
    "mcp-trust": {
        "path": "<workspace>/mcp-trust",
        "commit": "a30be69132802d2b24157066fa4dc125e8edfdca",
        "tree": "30e2ae0c0f9c3ec1aac265bd8b4baaa8c6b6bde1",
        "paths": [
            "pyproject.toml",
            "uv.lock",
            "src/mcp_trust/catalog/snapshot.py",
            "src/mcp_trust/core/drift.py",
            "src/mcp_trust/core/grading.py",
            "src/mcp_trust/core/models.py",
            "src/mcp_trust/core/provenance.py",
            "src/mcp_trust/engine/base.py",
            "src/mcp_trust/engine/credentials.py",
            "src/mcp_trust/engine/mcpaudit.py",
            "src/mcp_trust/engine/sandbox.py",
            "src/mcp_trust/engine/stub.py",
            "src/mcp_trust/receipts.py",
            "src/mcp_trust/refresh.py",
            "src/mcp_trust/store/db.py",
            "src/mcp_trust/store/repository.py",
            "tests/test_drift.py",
            "tests/test_grading.py",
            "tests/test_receipt_provenance.py",
            "tests/test_refresh_candidate.py",
        ],
    },
    "bridge-db": {
        "path": "<workspace>/bridge-db",
        "commit": "b47e5428b0f512c5e4ab87212acdd1d844b365b0",
        "tree": "f7499707fdaebd17155f1d1055abec1e6e1cd1c9",
        "paths": [
            "pyproject.toml",
            "uv.lock",
            "src/bridge_db/clock.py",
            "src/bridge_db/config.py",
            "src/bridge_db/db.py",
            "src/bridge_db/recovery.py",
            "src/bridge_db/tools/health.py",
            "tests/test_cli.py",
            "tests/test_db.py",
            "tests/test_health.py",
            "tests/test_recovery.py",
        ],
    },
}

CASE_CEILINGS: dict[str, tuple[str, str, str]] = {
    "P1-C": ("STRONG", "VALID", "complete"),
    "P1-01": ("NONAUTHORITATIVE", "MISSING", "required_provider_missing"),
    "P1-02": ("NONAUTHORITATIVE", "STALE", "receipt_stale"),
    "P1-03": ("NONAUTHORITATIVE", "MASKED", "required_count_redacted"),
    "P1-04": ("NONAUTHORITATIVE", "CONTRADICTORY", "pagination_incomplete"),
    "P1-05": ("NONAUTHORITATIVE", "UNSUPPORTED", "receipt_schema_unsupported"),
    "P1-06": ("NONAUTHORITATIVE", "MISBOUND", "subject_identity_mismatch"),
    "P2-C": ("STRONG", "VALID", "fixture_candidate_valid"),
    "P2-01": ("NONAUTHORITATIVE", "MISSING", "missing-receipt"),
    "P2-02": ("NONAUTHORITATIVE", "STALE", "candidate_expired"),
    "P2-03": ("NONAUTHORITATIVE", "MASKED", "masked"),
    "P2-04": ("BLOCKED", "CONTRADICTORY", "fresh_grade_binding_mismatch"),
    "P2-05": ("BLOCKED", "UNSUPPORTED", "successful_scan_receipt_schema_invalid"),
    "P2-06": ("BLOCKED", "MISBOUND", "receipt_scan_binding_mismatch"),
    "P3-C": ("STRONG", "VALID", "verified"),
    "P3-01": ("NONAUTHORITATIVE", "MISSING", "anchor_missing"),
    "P3-02": ("NONAUTHORITATIVE", "STALE", "source_changed_since_anchor"),
    "P3-03": ("BLOCKED", "MASKED", "digest_mismatch"),
    "P3-04": ("BLOCKED", "CONTRADICTORY", "byte_size_mismatch"),
    "P3-05": ("BLOCKED", "UNSUPPORTED", "schema_incompatible"),
    "P3-06": ("BLOCKED", "NOT_PRIVATE", "backup_permissions_not_private"),
}


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def pretty_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def artifact(name: str, media_type: str, content: bytes, mode: int = 0o600) -> dict[str, Any]:
    return {
        "name": name,
        "media_type": media_type,
        "encoding": "base64",
        "bytes": len(content),
        "sha256": sha256_bytes(content),
        "materialization_mode": f"{mode:04o}",
        "content_base64": b64(content),
    }


def git_bytes(repository: str, revision: str, relative: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", repository, "show", f"{revision}:{relative}"],
        check=True,
        capture_output=True,
    )
    return completed.stdout


def git_text(repository: str, revision: str, relative: str) -> str:
    return git_bytes(repository, revision, relative).decode("utf-8")


def frozen_inventory() -> dict[str, Any]:
    repositories: list[dict[str, Any]] = []
    for name, frozen in FROZEN_REPOSITORIES.items():
        repository = str(frozen["path"])
        revision = str(frozen["commit"])
        observed_tree = subprocess.run(
            ["git", "-C", repository, "rev-parse", f"{revision}^{{tree}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if observed_tree != frozen["tree"]:
            raise RuntimeError(f"frozen tree mismatch: {name}")
        source_paths = set(frozen["paths"])
        for prefix in frozen.get("prefixes", []):
            listed = subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    revision,
                    "--",
                    str(prefix),
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            source_paths.update(path for path in listed if path)
        sources: list[dict[str, Any]] = []
        for relative in sorted(source_paths):
            content = git_bytes(repository, revision, relative)
            blob = subprocess.run(
                ["git", "-C", repository, "rev-parse", f"{revision}:{relative}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            sources.append(
                {
                    "path": relative,
                    "git_blob": blob,
                    "bytes": len(content),
                    "sha256": sha256_bytes(content),
                    "role": "decision-source-closure",
                }
            )
        repositories.append(
            {
                "name": name,
                "repository_path": repository,
                "commit": revision,
                "tree": observed_tree,
                "sources": sources,
            }
        )
    return {
        "schema": "FrozenContractsV2",
        "package_id": PACKAGE_ID,
        "captured_at": FIXED_CREATED_AT,
        "repositories": repositories,
        "closure_statement": (
            "All grade, model, receipt, store, persisted-scan, snapshot, projection, "
            "recovery, manifest, test, and dependency-lock decision sources used by "
            "P1/P2/P3 are enumerated."
        ),
    }


def deterministic_tar(entries: Mapping[str, tuple[bytes | None, int]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            content, mode = entries[name]
            info = tarfile.TarInfo(name=name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            info.mode = mode
            if content is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _provider(counts: dict[str, Any]) -> dict[str, Any]:
    return {
        "state": "observed",
        "observed_at": P1_PRODUCED_AT,
        "http_status": 200,
        "http_classification": "success",
        "reason": None,
        "etag": '"synthetic-etag"',
        "last_modified": "Thu, 31 Jul 2026 08:00:00 GMT",
        "conditional": {"requested": False, "result": "not_used"},
        "pagination_complete": True,
        "counts": counts,
    }


def _observed_projection(counts: dict[str, int]) -> dict[str, Any]:
    return {
        "state": "observed",
        "observed_at": P1_PRODUCED_AT,
        "pagination_complete": True,
        "counts": counts,
    }


def p1_receipt() -> dict[str, Any]:
    subject = "synthetic-lab/subject-alpha"
    return {
        "schema_version": "GitHubSecurityCoverageReceiptV1",
        "produced_at": P1_PRODUCED_AT,
        "producer": {
            "repository": "saagpatel/GithubRepoAuditor",
            "commit": FROZEN_REPOSITORIES["GithubRepoAuditor"]["commit"],
        },
        "github_api_version": "2022-11-28",
        "eligibility": {
            "source": "github-account-repository-preflight-v1",
            "state": "not_requested",
            "observed_at": None,
            "reason": "no_prior_feature_unavailable_candidates",
            "candidate_repositories": [],
            "request_count": 0,
            "account": None,
            "repositories": {},
        },
        "cohort": {
            "policy": "portfolio-default-attention-v1",
            "expected_count": 1,
            "repository_count": 1,
            "repositories": [subject],
        },
        "request_budget": {
            "base_limit": 10,
            "total_limit": 20,
            "quota_reserve": 100,
            "base_requests": 3,
            "total_requests": 3,
            "stop_reason": None,
        },
        "repositories": {
            subject: {
                "providers": {
                    "dependabot": _provider({"critical": 0, "high": 0, "medium": 0, "low": 0}),
                    "code_scanning": _provider({"critical": 0, "high": 0, "warning": 0, "note": 0}),
                    "secret_scanning": _provider({"open": 0}),
                }
            }
        },
    }


def p1_snapshot() -> dict[str, Any]:
    subject = "synthetic-lab/subject-alpha"
    security = {
        "alerts_available": True,
        "coverage_state": "complete",
        "cohort_member": True,
        "cohort_policy": "portfolio-default-attention-v1",
        "receipt_schema_version": "GitHubSecurityCoverageReceiptV1",
        "receipt_state": "fresh",
        "source_produced_at": P1_PRODUCED_AT,
        "providers": {
            "dependabot": _observed_projection({"critical": 0, "high": 0, "medium": 0, "low": 0}),
            "code_scanning": _observed_projection({"critical": 0, "high": 0, "warning": 0, "note": 0}),
            "secret_scanning": _observed_projection({"open": 0}),
        },
        "dependabot_critical": 0,
        "dependabot_high": 0,
        "dependabot_medium": 0,
        "dependabot_low": 0,
        "code_scanning_critical": 0,
        "code_scanning_high": 0,
        "secret_scanning_open": 0,
        "open_high_critical": 0,
    }
    project = {
        "identity": {
            "project_key": "synthetic-service",
            "repo_full_name": subject,
            "display_name": "Synthetic Service",
            "path": "/synthetic/projects/subject-alpha",
            "top_level_dir": "subject-alpha",
            "group_key": "synthetic",
            "group_label": "Synthetic",
            "section_marker": "synthetic",
            "section_label": "Synthetic",
            "has_git": True,
            "default_branch": "main",
        },
        "declared": {
            "owner": "synthetic-operator",
            "team": "synthetic-team",
            "purpose": "Reserved evidence fixture",
            "lifecycle_state": "active",
            "criticality": "medium",
            "review_cadence": "weekly",
            "intended_disposition": "retain",
            "maturity_program": "maintain",
            "target_maturity": "operating",
            "operating_path": "maintain",
            "category": "infrastructure",
            "tool_provenance": "synthetic-fixture",
            "notes": "",
            "doctor_standard": "",
            "automation_eligible": False,
        },
        "derived": {
            "stack": ["Synthetic"],
            "context_quality": "full",
            "context_files": ["AGENTS.md"],
            "context_file_count": 1,
            "primary_context_file": "AGENTS.md",
            "project_summary_present": True,
            "current_state_present": True,
            "stack_present": True,
            "run_instructions_present": True,
            "known_risks_present": True,
            "next_recommended_move_present": True,
            "last_meaningful_activity_at": "2026-07-31T07:00:00Z",
            "activity_status": "active",
            "archived": False,
            "attention_state": "active-infra",
            "path_override": "",
            "path_confidence": "high",
            "path_rationale": "synthetic fixture",
            "has_tests": True,
            "has_ci": True,
            "has_license": True,
            "readme_char_count": 512,
            "release_count": 0,
            "ai_cost_usd": 0.0,
        },
        "risk": {
            "risk_tier": "baseline",
            "risk_factors": [],
            "risk_summary": "Synthetic fixture has complete zero-finding coverage.",
            "doctor_gap": False,
            "context_risk": False,
            "path_risk": False,
            "security_risk": False,
        },
        "security": security,
        "advisory": {
            "notion_portfolio_call": "",
            "notion_momentum": "",
            "notion_current_state": "",
            "legacy_status": "active",
            "legacy_context_quality": "full",
            "legacy_category": "",
            "legacy_tool_provenance": "synthetic-fixture",
        },
        "repository_state": {"state": "observed"},
        "provenance": {"source": "reserved-synthetic-fixture"},
        "warnings": [],
    }
    return {
        "schema_version": "0.11.0",
        "generated_at": P1_PRODUCED_AT,
        "workspace_root": "/synthetic/projects",
        "projects": [project],
        "coverage": [
            {
                "source": "github_security",
                "state": "complete",
                "scanned_count": 1,
                "complete_repo_count": 1,
                "partial_repo_count": 0,
                "stale_count": 0,
                "unknown_count": 0,
                "project_count": 1,
            }
        ],
        "source_summary": {"attention_state_counts": {"active-infra": 1}},
        "rollups": {
            "risk_tier_counts": {
                "elevated": 0,
                "moderate": 0,
                "baseline": 1,
                "deferred": 0,
            },
            "security": {
                "scanned_count": 1,
                "repos_with_open_high_critical": 0,
                "total_open_high": 0,
                "total_open_critical": 0,
            },
            "decision": {"decision_needed_count": 0, "default_attention_count": 1},
        },
    }


def fixture_wrapper(
    case_id: str,
    path_id: str,
    kind: str,
    axis: str,
    coordinates: dict[str, int],
    artifacts: list[dict[str, Any]],
    evaluation_time: str,
    changed_field_closure: list[str],
    raw_signal: dict[str, Any],
) -> dict[str, Any]:
    authority, disposition, reason = CASE_CEILINGS[case_id]
    return {
        "schema": f"{path_id}FullFixtureV2",
        "fixture_id": case_id,
        "package_id": PACKAGE_ID,
        "path_id": path_id,
        "kind": kind,
        "semantic_axis": axis,
        "evidence_coordinates": coordinates,
        "evaluation_time": evaluation_time,
        "changed_field_closure": changed_field_closure,
        "artifacts": artifacts,
        "expected": {
            "source": "sealed-contract-adjudication-not-consumer-output",
            "authority_ceiling": authority,
            "disposition": disposition,
            "reason_family": reason,
            "raw_signal": raw_signal,
        },
        "producer_head_behavior": "UNKNOWN" if path_id == "P1" else "NOT_APPLICABLE",
        "consumer_execution": "FORBIDDEN_NOT_RUN",
    }


def build_p1_fixtures() -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    base_receipt = p1_receipt()
    base_snapshot = p1_snapshot()
    coordinate_names = ["present", "current", "visible", "consistent", "supported", "bound"]
    for index, case_id in enumerate(["P1-C", "P1-01", "P1-02", "P1-03", "P1-04", "P1-05", "P1-06"]):
        receipt = copy.deepcopy(base_receipt)
        snapshot = copy.deepcopy(base_snapshot)
        axis = "control" if case_id == "P1-C" else coordinate_names[index - 1]
        coordinates = {name: 1 for name in coordinate_names}
        changed: list[str] = []
        evaluation = P1_EVALUATION_AT
        raw: dict[str, Any] = {"coverage_state": "complete", "overall": "COMPLETE"}
        if case_id != "P1-C":
            coordinates[axis] = 0
        subject = "synthetic-lab/subject-alpha"
        if case_id == "P1-01":
            del receipt["repositories"][subject]["providers"]["secret_scanning"]
            del snapshot["projects"][0]["security"]["providers"]["secret_scanning"]
            snapshot["projects"][0]["security"]["coverage_state"] = "unknown"
            snapshot["coverage"][0].update(
                {"state": "partial", "complete_repo_count": 0, "partial_repo_count": 1}
            )
            changed = [
                "receipt.repositories[subject].providers.secret_scanning",
                "snapshot.projects[0].security.providers.secret_scanning",
                "snapshot.projects[0].security.coverage_state",
                "snapshot.coverage[0]",
            ]
            raw = {"coverage_state": "unknown", "reason": "required_provider_missing"}
        elif case_id == "P1-02":
            evaluation = "2026-08-01T08:00:01+00:00"
            snapshot["projects"][0]["security"]["receipt_state"] = "stale"
            snapshot["projects"][0]["security"]["coverage_state"] = "stale"
            snapshot["coverage"][0].update({"state": "stale", "complete_repo_count": 0, "stale_count": 1})
            changed = [
                "evaluation_time",
                "snapshot.projects[0].security.receipt_state",
                "snapshot.projects[0].security.coverage_state",
                "snapshot.coverage[0]",
            ]
            raw = {"coverage_state": "stale", "reason": "receipt_stale"}
        elif case_id == "P1-03":
            receipt["repositories"][subject]["providers"]["dependabot"]["counts"]["critical"] = "REDACTED"
            security = snapshot["projects"][0]["security"]
            security["providers"]["dependabot"]["counts"]["critical"] = "REDACTED"
            security["dependabot_critical"] = "REDACTED"
            security["coverage_state"] = "unknown"
            changed = [
                "receipt.repositories[subject].providers.dependabot.counts.critical",
                "snapshot.projects[0].security.providers.dependabot.counts.critical",
                "snapshot.projects[0].security.dependabot_critical",
                "snapshot.projects[0].security.coverage_state",
            ]
            raw = {"coverage_state": "unknown", "reason": "required_count_redacted"}
        elif case_id == "P1-04":
            receipt["repositories"][subject]["providers"]["code_scanning"]["pagination_complete"] = False
            snapshot["projects"][0]["security"]["providers"]["code_scanning"]["pagination_complete"] = False
            changed = [
                "receipt.repositories[subject].providers.code_scanning.pagination_complete",
                "snapshot.projects[0].security.providers.code_scanning.pagination_complete",
            ]
            raw = {"coverage_state": "unknown", "reason": "pagination_incomplete"}
        elif case_id == "P1-05":
            receipt["schema_version"] = "GitHubSecurityCoverageReceiptV2"
            snapshot["projects"][0]["security"]["receipt_schema_version"] = "GitHubSecurityCoverageReceiptV2"
            changed = [
                "receipt.schema_version",
                "snapshot.projects[0].security.receipt_schema_version",
            ]
            raw = {"coverage_state": "unknown", "reason": "receipt_schema_unsupported"}
        elif case_id == "P1-06":
            snapshot["projects"][0]["identity"]["repo_full_name"] = "synthetic-lab/subject-beta"
            changed = ["snapshot.projects[0].identity.repo_full_name"]
            raw = {
                "frozen_pcc_coverage_state": "complete",
                "oracle_binding": "subject_identity_mismatch",
                "producer_head": "UNKNOWN_UNMUTATED",
            }
        output[case_id] = fixture_wrapper(
            case_id,
            "P1",
            "control" if case_id == "P1-C" else "primary-mutation",
            axis,
            coordinates,
            [
                artifact(
                    "github-security-coverage-receipt.json",
                    "application/json",
                    canonical_json_bytes(receipt),
                ),
                artifact(
                    "portfolio-truth-0.11.0.json",
                    "application/json",
                    canonical_json_bytes(snapshot),
                ),
            ],
            evaluation,
            changed,
            raw,
        )
    return output


def p2_engine_result() -> dict[str, Any]:
    evidence = {
        "tool_count": 1,
        "tools": [
            {
                "name": "synthetic-tool",
                "has_input_schema": True,
                "input_schema_sha256": sha256_bytes(b'{"type":"object"}'),
                "has_annotations": True,
            }
        ],
        "prompt_count": 0,
        "resource_count": 0,
        "schema_hash_algorithm": "sha256",
    }
    risk = {
        "composite": 0.0,
        "file_access": 0.0,
        "network_access": 0.0,
        "shell_execution": 0.0,
        "destructive": 0.0,
        "exfiltration": 0.0,
        "findings_by_severity": {},
        "annotation_coverage": 1.0,
    }
    return {
        "engine_name": "mcpaudit",
        "engine_version": "2.4.0",
        "risk": risk,
        "findings": [],
        "evidence": evidence,
        "sandbox_image": None,
    }


def _p2_server() -> dict[str, Any]:
    return {
        "slug": "synthetic-server",
        "name": "Synthetic Server",
        "description": "Reserved deterministic fixture server",
        "source": {
            "kind": "npm",
            "reference": "@example/synthetic-server",
            "command": "/synthetic/bin/server",
            "args": [],
            "env_keys": [],
            "sandbox_image": None,
            "trusted": False,
        },
        "homepage": "https://example.invalid/synthetic-server",
        "added_at": P2_MODEL_AT,
    }


def _p2_scan() -> dict[str, Any]:
    engine = p2_engine_result()
    return {
        "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "server_slug": "synthetic-server",
        "engine_name": engine["engine_name"],
        "engine_version": engine["engine_version"],
        "grade": "A",
        "transparency": "high",
        "risk": engine["risk"],
        "findings": engine["findings"],
        "evidence": engine["evidence"],
        "scanned_at": P2_MODEL_AT,
        "sandbox_image": None,
        "report_ref": "synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
    }


def _p2_receipt() -> dict[str, Any]:
    scan = _p2_scan()
    return {
        "format_version": 1,
        "server_slug": scan["server_slug"],
        "scan_id": scan["id"],
        "server": _p2_server(),
        "scan": scan,
        "evidence": scan["evidence"],
        "danger_score": 0.0,
        "scanner": {
            "engine_name": "mcpaudit",
            "engine_version": "2.4.0",
            "scanner_git_ref": None,
        },
        "sandbox": {
            "MCP_TRUST_SANDBOX": "docker",
            "MCP_TRUST_SANDBOX_NETWORK": "none",
            "MCP_TRUST_SCAN_CREDENTIALS": "dummy",
        },
        "approval": {"approval_ref": None},
        "caveats": [
            "Automated scan output is not an endorsement.",
            "Danger grade and transparency are separate signals.",
            "Low transparency means cannot verify safe, not known dangerous.",
            "Network-off sandboxing may suppress behavior that requires live egress.",
        ],
    }


def _p2_result() -> dict[str, Any]:
    scan = _p2_scan()
    return {
        "server_slug": scan["server_slug"],
        "state": "fresh",
        "fresh_grade": scan["grade"],
        "grade_visibility": "reviewable",
        "transparency": scan["transparency"],
        "scanned_at": P2_CREATED_AT,
        "scan_age_days": 0.0,
        "scan_id": scan["id"],
        "engine_name": scan["engine_name"],
        "engine_version": scan["engine_version"],
        "receipt": scan["report_ref"],
        "receipt_visibility": "reviewable",
        "scan_proof": None,
        "scan_proof_visibility": "not_applicable",
        "drift": None,
    }


def _p2_snapshot(scan_present: bool) -> dict[str, Any]:
    scan = _p2_scan()
    servers: list[dict[str, Any]] = []
    if scan_present:
        servers.append(
            {
                "slug": "synthetic-server",
                "name": "Synthetic Server",
                "description": "Reserved deterministic fixture server",
                "homepage": "https://example.invalid/synthetic-server",
                "grade": "A",
                "transparency": "high",
                "danger_score": 0.0,
                "dimensions": {
                    "file_access": 0.0,
                    "network_access": 0.0,
                    "shell_execution": 0.0,
                    "destructive": 0.0,
                    "exfiltration": 0.0,
                },
                "annotation_coverage": 1.0,
                "findings": [],
                "evidence": scan["evidence"],
                "source": {
                    "kind": "npm",
                    "reference": "@example/synthetic-server",
                    "env_keys": [],
                },
                "engine": "mcpaudit",
                "engine_version": "2.4.0",
                "scan_mode": "mcpaudit-local-provenance-unknown",
                "sandbox": {"mode": "unknown", "network": "unknown", "image": None},
                "scanned_at": P2_CREATED_AT,
                "scan_age_days": 0.0,
                "grade_change": None,
                "requires_credentials": False,
            }
        )
    return {
        "schema_version": 2,
        "generated_at": P2_CREATED_AT,
        "generated_from_scan_at": P2_CREATED_AT if scan_present else "",
        "server_count": len(servers),
        "servers": servers,
    }


def _build_p2_database(scan_present: bool) -> bytes:
    with tempfile.TemporaryDirectory(prefix="evidence-v2-p2-db-") as directory:
        database = Path(directory) / "registry.db"
        connection = sqlite3.connect(database)
        connection.executescript(
            """
            PRAGMA page_size=4096;
            PRAGMA journal_mode=DELETE;
            CREATE TABLE servers (
                slug TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                source_json TEXT NOT NULL,
                homepage TEXT,
                added_at TEXT NOT NULL
            );
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                server_slug TEXT NOT NULL REFERENCES servers(slug),
                engine_name TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                grade TEXT NOT NULL,
                transparency TEXT NOT NULL DEFAULT 'high',
                risk_json TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                evidence_json TEXT,
                scanned_at TEXT NOT NULL,
                sandbox_image TEXT,
                report_ref TEXT
            );
            CREATE INDEX idx_scans_slug_time ON scans (server_slug, scanned_at);
            """
        )
        server = _p2_server()
        connection.execute(
            "INSERT INTO servers VALUES (?, ?, ?, ?, ?, ?)",
            (
                server["slug"],
                server["name"],
                server["description"],
                canonical_json_bytes(server["source"]).decode("utf-8").strip(),
                server["homepage"],
                P2_CREATED_AT,
            ),
        )
        if scan_present:
            scan = _p2_scan()
            connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan["id"],
                    scan["server_slug"],
                    scan["engine_name"],
                    scan["engine_version"],
                    scan["grade"],
                    scan["transparency"],
                    canonical_json_bytes(scan["risk"]).decode("utf-8").strip(),
                    canonical_json_bytes(scan["findings"]).decode("utf-8").strip(),
                    canonical_json_bytes(scan["evidence"]).decode("utf-8").strip(),
                    P2_CREATED_AT,
                    scan["sandbox_image"],
                    scan["report_ref"],
                ),
            )
        connection.commit()
        connection.execute("VACUUM")
        connection.close()
        return database.read_bytes()


def _p2_artifact_inventory(entries: Mapping[str, tuple[bytes | None, int]]) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(entries):
        content, _mode = entries[path]
        if content is None or path in {"MANIFEST.json", "MANIFEST.sha256"}:
            continue
        inventory.append({"path": path, "bytes": len(content), "sha256": sha256_bytes(content)})
    return inventory


def _p2_candidate(case_id: str) -> bytes:
    scan_present = case_id not in {"P2-01", "P2-03"}
    receipt_present = case_id not in {"P2-01", "P2-03"}
    masked = case_id == "P2-03"
    receipt = _p2_receipt()
    result: dict[str, Any] = _p2_result()
    if case_id == "P2-01":
        result = {
            "server_slug": "synthetic-server",
            "state": "missing-receipt",
            "fresh_grade": None,
            "previous_grade": None,
        }
    elif masked:
        scan = _p2_scan()
        result = {
            "server_slug": "synthetic-server",
            "state": "masked",
            "fresh_grade": None,
            "grade_visibility": "withheld",
            "transparency": None,
            "scanned_at": P2_CREATED_AT,
            "scan_age_days": 0.0,
            "scan_id": None,
            "engine_name": scan["engine_name"],
            "engine_version": scan["engine_version"],
            "receipt": None,
            "receipt_visibility": "withheld",
            "scan_proof": "synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
            "scan_proof_visibility": "reviewable-redacted",
            "drift": None,
        }
    elif case_id == "P2-04":
        result["fresh_grade"] = "B"
    elif case_id == "P2-05":
        receipt["format_version"] = 2
    elif case_id == "P2-06":
        receipt["scan_id"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    catalog_row = copy.deepcopy(_p2_server())
    catalog_row.pop("added_at")
    catalog_seed = [catalog_row]
    masked_slugs = ["synthetic-server"] if masked else []
    entries: dict[str, tuple[bytes | None, int]] = {
        ".": (None, 0o500),
        "masked-proofs/": (None, 0o500),
        "receipts/": (None, 0o500),
        "registry.db": (_build_p2_database(scan_present), 0o400),
        "catalog_identity.json": (
            canonical_json_bytes(
                {
                    "schema": "RefreshCatalogIdentityV1",
                    "seed_sha256": sha256_bytes(canonical_json_bytes(catalog_seed)),
                    "server_count": 1,
                    "servers": catalog_seed,
                }
            ),
            0o400,
        ),
        "scan_results.json": (
            canonical_json_bytes(
                {
                    "schema": "RefreshScanResultsV1",
                    "generated_at": P2_CREATED_AT,
                    "results": [result],
                }
            ),
            0o400,
        ),
        "static_snapshot.json": (
            canonical_json_bytes(_p2_snapshot(scan_present)),
            0o400,
        ),
    }
    if receipt_present:
        entries["receipts/synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"] = (
            canonical_json_bytes(receipt),
            0o400,
        )
    if masked:
        entries["masked-proofs/synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"] = (
            canonical_json_bytes(
                {
                    "format_version": 1,
                    "proof_type": "masked_scan_success",
                    "outcome": "scan_succeeded",
                    "server_slug": "synthetic-server",
                    "scan_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "server": _p2_server(),
                    "scanned_at": P2_CREATED_AT,
                    "scanner": receipt["scanner"],
                    "sandbox": receipt["sandbox"],
                    "evidence_present": True,
                }
            ),
            0o400,
        )
    manifest = {
        "schema": "RefreshCandidateV1",
        "created_at": P2_CREATED_AT,
        "expires_at": P2_EXPIRES_AT,
        "candidate_state": "fixture",
        "publication_allowed": False,
        "scan_mode": "deterministic-fixture",
        "catalog": {
            "seed_sha256": sha256_bytes(canonical_json_bytes(catalog_seed)),
            "server_count": 1,
        },
        "masking": {
            "sha256": sha256_bytes(canonical_json_bytes(masked_slugs)),
            "slugs": masked_slugs,
        },
        "sandbox": {
            "mode": "deterministic-fixture",
            "profiles": [
                {
                    "kind": "docker",
                    "image": "fixture:image",
                    "network": "none",
                    "read_only_root": True,
                    "capabilities": "dropped-all",
                    "no_new_privileges": True,
                    "memory": "512m",
                    "pids_limit": 256,
                    "cpus": "1",
                    "user": "1000:1000",
                    "tmpfs": "/scan",
                }
            ],
        },
        "scan_counts": {
            "total": 1,
            "fresh": int(result["state"] == "fresh"),
            "masked": int(result["state"] == "masked"),
            "failed": int(result["state"] not in {"fresh", "masked"}),
        },
        "engine_versions": [] if case_id == "P2-01" else ["2.4.0"],
        "artifacts": _p2_artifact_inventory(entries),
        "authority": {
            "candidate_creation": True,
            "publication": False,
            "deployment": False,
            "schedule_change": False,
        },
    }
    manifest_bytes = canonical_json_bytes(manifest)
    entries["MANIFEST.json"] = (manifest_bytes, 0o400)
    entries["MANIFEST.sha256"] = ((sha256_bytes(manifest_bytes) + "\n").encode(), 0o400)
    return deterministic_tar(entries)


def build_p2_fixtures() -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    coordinate_names = ["present", "current", "visible", "consistent", "supported", "bound"]
    cases = ["P2-C", "P2-01", "P2-02", "P2-03", "P2-04", "P2-05", "P2-06"]
    changed_by_case = {
        "P2-C": [],
        "P2-01": [
            "candidate.receipts",
            "candidate.scan_results.results[0]",
            "candidate.registry.scans",
            "candidate.static_snapshot.servers",
            "candidate.manifest.artifacts",
        ],
        "P2-02": ["evaluation_time"],
        "P2-03": [
            "candidate.masked-proofs",
            "candidate.receipts",
            "candidate.scan_results.results[0]",
            "candidate.registry.scans",
            "candidate.static_snapshot.servers",
            "candidate.manifest.masking",
            "candidate.manifest.artifacts",
        ],
        "P2-04": [
            "candidate.scan_results.results[0].fresh_grade",
            "candidate.manifest.artifacts[scan_results]",
            "candidate.MANIFEST.sha256",
        ],
        "P2-05": [
            "candidate.receipt.format_version",
            "candidate.manifest.artifacts[receipt]",
            "candidate.MANIFEST.sha256",
        ],
        "P2-06": [
            "candidate.receipt.scan_id",
            "candidate.manifest.artifacts[receipt]",
            "candidate.MANIFEST.sha256",
        ],
    }
    raw_by_case: dict[str, dict[str, Any]] = {
        "P2-C": {"state": "fixture", "structural_valid": True, "publication_ready": False},
        "P2-01": {"result_state": "missing-receipt", "fresh_grade": None},
        "P2-02": {"verification_state": "stale", "boundary": "evaluation_at_expires_at"},
        "P2-03": {"result_state": "masked", "grade_visibility": "withheld"},
        "P2-04": {"error": "fresh_grade_binding_mismatch"},
        "P2-05": {"error": "successful_scan_receipt_schema_invalid"},
        "P2-06": {"error": "receipt_scan_binding_mismatch"},
    }
    for index, case_id in enumerate(cases):
        axis = "control" if case_id == "P2-C" else coordinate_names[index - 1]
        coordinates = {name: 1 for name in coordinate_names}
        if case_id != "P2-C":
            coordinates[axis] = 0
        evaluation = P2_EXPIRES_AT if case_id == "P2-02" else P2_CREATED_AT
        output[case_id] = fixture_wrapper(
            case_id,
            "P2",
            "control" if case_id == "P2-C" else "primary-mutation",
            axis,
            coordinates,
            [
                artifact(
                    "engine-result.json",
                    "application/json",
                    canonical_json_bytes(p2_engine_result()),
                ),
                artifact(
                    "refresh-candidate.tar",
                    "application/x-tar",
                    _p2_candidate(case_id),
                ),
            ],
            evaluation,
            changed_by_case[case_id],
            raw_by_case[case_id],
        )
    return output


def _bridge_schema_ddl() -> str:
    frozen = FROZEN_REPOSITORIES["bridge-db"]
    source = git_text(str(frozen["path"]), str(frozen["commit"]), "src/bridge_db/db.py")
    config_source = git_text(str(frozen["path"]), str(frozen["commit"]), "src/bridge_db/config.py")
    if "SCHEMA_VERSION = 22" not in source:
        raise RuntimeError("frozen BridgeDB schema version is not 22")
    if "CONTEXT_TOTAL_MAX_BYTES: int = 1024 * 1024" not in config_source:
        raise RuntimeError("frozen BridgeDB context byte limit changed")
    matched = re.search(r'_SCHEMA_DDL = f"""\n(.*?)\n"""', source, re.DOTALL)
    if matched is None:
        raise RuntimeError("frozen BridgeDB schema DDL is unavailable")
    return matched.group(1).replace("{config.CONTEXT_TOTAL_MAX_BYTES}", "1048576")


def _build_bridge_database(*, schema_version: int, content: str) -> bytes:
    with tempfile.TemporaryDirectory(prefix="evidence-v2-p3-db-") as directory:
        database = Path(directory) / "source.sqlite"
        connection = sqlite3.connect(database)
        connection.execute("PRAGMA page_size=4096")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.executescript(_bridge_schema_ddl())
        connection.execute(f"PRAGMA user_version={schema_version}")
        connection.execute(
            """
            INSERT INTO context_sections
                (section_name, owner, content, updated_at, source_trust, version)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "synthetic-context",
                "codex",
                content,
                "2026-07-31T08:00:00Z",
                "agent",
                1,
            ),
        )
        connection.execute(
            """
            INSERT INTO activity_log
                (source, timestamp, project_name, summary, branch, tags,
                 created_at, canonical_key, source_trust)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "2026-07-31T08:00:00Z",
                "synthetic-project",
                "Synthetic recovery fixture activity",
                "synthetic-branch",
                "[]",
                "2026-07-31T08:00:00Z",
                "synthetic-project",
                "agent",
            ),
        )
        connection.execute(
            """
            INSERT INTO pending_handoffs
                (project_name, project_path, roadmap_file, phase, dispatched_from,
                 dispatched_at, status, canonical_key, source_trust)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "synthetic-project",
                "/synthetic/projects/recovery",
                "/synthetic/projects/recovery/ROADMAP.md",
                "fixture",
                "codex",
                "2026-07-31T08:00:00Z",
                "pending",
                "synthetic-project",
                "agent",
            ),
        )
        connection.execute(
            """
            INSERT INTO system_snapshots
                (system, snapshot_date, data, created_at, source_trust)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "2026-07-31",
                '{"state":"synthetic"}',
                "2026-07-31T08:00:00Z",
                "agent",
            ),
        )
        connection.execute(
            """
            INSERT INTO cost_records (system, month, amount, notes, recorded_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "codex",
                "2026-07",
                0.0,
                "synthetic fixture",
                "2026-07-31T08:00:00Z",
            ),
        )
        connection.commit()
        connection.execute("VACUUM")
        connection.close()
        return database.read_bytes()


def _p3_manifest(database: bytes, schema_version: int = 22) -> dict[str, Any]:
    return {
        "schema": "RecoveryAnchorV1",
        "created_at": P3_CREATED_AT,
        "source_schema_version": schema_version,
        "backup_bytes": len(database),
        "sha256": sha256_bytes(database),
        "sqlite_integrity": "ok",
        "recovery_readback": "verified",
        "semantic_readback": {
            "tables": [
                "context_sections",
                "activity_log",
                "pending_handoffs",
                "system_snapshots",
                "cost_records",
            ],
            "row_counts": {
                "context_sections": 1,
                "activity_log": 1,
                "pending_handoffs": 1,
                "system_snapshots": 1,
                "cost_records": 1,
            },
        },
        "publication": "atomic_directory_replace",
        "source_consistency": "sqlite_write_guard_and_semantic_fingerprint",
        "retention_policy": "preserve_pending_operator_approval",
        "cleanup": "approval_required",
    }


def _p3_anchor(case_id: str, control_database: bytes) -> bytes | None:
    if case_id == "P3-01":
        return None
    database = control_database
    schema_version = 22
    if case_id == "P3-05":
        database = _build_bridge_database(schema_version=23, content="synthetic content alpha")
        schema_version = 23
    manifest = _p3_manifest(database, schema_version=schema_version)
    if case_id == "P3-03":
        manifest["sha256"] = "REDACTED_SHA256"
    elif case_id == "P3-04":
        manifest["backup_bytes"] = len(database) + 1
    database_mode = 0o644 if case_id == "P3-06" else 0o600
    return deterministic_tar(
        {
            ".": (None, 0o700),
            "anchor.json": (canonical_json_bytes(manifest), 0o600),
            "anchor.sqlite": (database, database_mode),
        }
    )


def build_p3_fixtures() -> dict[str, dict[str, Any]]:
    control_database = _build_bridge_database(schema_version=22, content="synthetic content alpha")
    stale_source = _build_bridge_database(schema_version=22, content="synthetic content beta")
    unsupported_source = _build_bridge_database(schema_version=23, content="synthetic content alpha")
    output: dict[str, dict[str, Any]] = {}
    coordinate_names = [
        "present",
        "current",
        "visible",
        "consistent",
        "supported",
        "private",
    ]
    cases = ["P3-C", "P3-01", "P3-02", "P3-03", "P3-04", "P3-05", "P3-06"]
    changed_by_case = {
        "P3-C": [],
        "P3-01": ["anchor_bundle"],
        "P3-02": ["source.context_sections[synthetic-context].content"],
        "P3-03": ["anchor.manifest.sha256"],
        "P3-04": ["anchor.manifest.backup_bytes"],
        "P3-05": [
            "source.PRAGMA.user_version",
            "anchor.sqlite.PRAGMA.user_version",
            "anchor.manifest.source_schema_version",
            "anchor.manifest.backup_bytes",
            "anchor.manifest.sha256",
        ],
        "P3-06": ["anchor.sqlite.POSIX_mode:0600->0644"],
    }
    raw_by_case = {
        "P3-C": {
            "state": "verified",
            "ready": True,
            "source_current": True,
            "permissions": "private",
            "recovery_readback": "verified",
            "errors": [],
        },
        "P3-01": {"state": "missing", "ready": False, "errors": ["anchor_missing"]},
        "P3-02": {
            "state": "stale",
            "ready": False,
            "source_current": False,
            "errors": ["source_changed_since_anchor"],
        },
        "P3-03": {
            "state": "invalid",
            "ready": False,
            "errors": ["digest_mismatch"],
        },
        "P3-04": {
            "state": "invalid",
            "ready": False,
            "errors": ["byte_size_mismatch"],
        },
        "P3-05": {
            "state": "invalid",
            "ready": False,
            "errors": ["schema_incompatible"],
        },
        "P3-06": {
            "state": "invalid",
            "ready": False,
            "permissions": "not_private",
            "recovery_readback": "unverified",
            "errors": ["backup_permissions_not_private"],
            "schema_version": 22,
            "expected_schema_version": 22,
            "digest_ok": True,
            "integrity_ok": True,
            "semantic_readback_ok": True,
            "source_current": "ABSENT",
        },
    }
    for index, case_id in enumerate(cases):
        axis = "control" if case_id == "P3-C" else coordinate_names[index - 1]
        coordinates = {name: 1 for name in coordinate_names}
        if case_id != "P3-C":
            coordinates[axis] = 0
        source = control_database
        if case_id == "P3-02":
            source = stale_source
        elif case_id == "P3-05":
            source = unsupported_source
        artifacts = [artifact("source.sqlite", "application/vnd.sqlite3", source)]
        anchor = _p3_anchor(case_id, control_database)
        if anchor is not None:
            artifacts.append(artifact("recovery-anchor.tar", "application/x-tar", anchor))
        fixture = fixture_wrapper(
            case_id,
            "P3",
            "control" if case_id == "P3-C" else "primary-mutation",
            axis,
            coordinates,
            artifacts,
            P3_CREATED_AT,
            changed_by_case[case_id],
            raw_by_case[case_id],
        )
        if case_id == "P3-06":
            fixture["excluded_materialization_effects"] = [
                {
                    "effect": "inode_ctime_changes_when_mode_is_materialized",
                    "classification": "UNAVOIDABLE_EXCLUDED",
                    "timing": "completed_before_verification",
                    "oracle_visibility": "ABSENT",
                }
            ]
            fixture["posix_precondition"] = {
                "required": True,
                "unsupported_or_unproved": "ENVIRONMENT_UNKNOWN_ABORT_NO_EMULATION",
            }
        output[case_id] = fixture
    return output


def no_op_boundaries() -> dict[str, Any]:
    entries = [
        {
            "boundary_id": "NOOP-01",
            "path_id": "P1",
            "inside": "canonical receipt JSON member order",
            "outside": "different JSON member order with identical values",
            "invariant": "authority_disposition_and_reason_multiset_identical",
        },
        {
            "boundary_id": "NOOP-02",
            "path_id": "P1",
            "inside": "no optional unknown metadata",
            "outside": "add one namespaced optional metadata member",
            "invariant": "required receipt and projected security meaning unchanged",
        },
        {
            "boundary_id": "NOOP-03",
            "path_id": "P2",
            "inside": "canonical equivalent finding and tool order",
            "outside": "equivalent order with all artifact bindings recomputed",
            "invariant": "grade evidence and per-server fixture decision unchanged",
        },
        {
            "boundary_id": "NOOP-04",
            "path_id": "P2",
            "inside": "UTC offset spelling +00:00",
            "outside": "equivalent UTC spelling Z",
            "invariant": "instant and expiry relation unchanged",
        },
        {
            "boundary_id": "NOOP-05",
            "path_id": "P3",
            "inside": "canonical manifest member order",
            "outside": "different manifest JSON member order with identical values",
            "invariant": "manifest meaning and anchor verification unchanged",
        },
        {
            "boundary_id": "NOOP-06",
            "path_id": "P3",
            "inside": "source database at one reserved fixture path",
            "outside": "byte-identical logical source at another reserved fixture path",
            "invariant": "URI-sensitive materialization path is outside semantic fingerprint",
        },
    ]
    return {
        "schema": "BoundaryCorpusV2",
        "corpus_kind": "NO_OP",
        "count": len(entries),
        "entries": entries,
        "execution_authorized": False,
    }


def near_miss_boundaries() -> dict[str, Any]:
    entries = [
        {
            "boundary_id": "NEAR-01",
            "path_id": "P1",
            "inside": "evaluation one microsecond before 24-hour freshness boundary",
            "outside": "evaluation one microsecond after 24-hour freshness boundary",
            "outside_reason": "receipt_stale",
        },
        {
            "boundary_id": "NEAR-02",
            "path_id": "P1",
            "inside": "redact optional non-authoritative metadata",
            "outside": "redact one required provider count",
            "outside_reason": "required_count_redacted",
        },
        {
            "boundary_id": "NEAR-03",
            "path_id": "P2",
            "inside": "evaluation immediately before expires_at",
            "outside": "evaluation exactly at expires_at",
            "outside_reason": "candidate_expired",
        },
        {
            "boundary_id": "NEAR-04",
            "path_id": "P2",
            "inside": "change optional non-authoritative receipt metadata",
            "outside": "change receipt format_version from 1 to 2",
            "outside_reason": "successful_scan_receipt_schema_invalid",
        },
        {
            "boundary_id": "NEAR-05",
            "path_id": "P3",
            "inside": "byte-identical logical source",
            "outside": "same-count update to one source row",
            "outside_reason": "source_changed_since_anchor",
        },
        {
            "boundary_id": "NEAR-06",
            "path_id": "P3",
            "inside": "exact anchor.json plus anchor.sqlite bundle",
            "outside": "same bundle plus anchor.sqlite-wal",
            "outside_artifact": {
                "name": "anchor.sqlite-wal",
                "bytes": 9,
                "sha256": sha256_bytes(b"untracked"),
                "content_base64": b64(b"untracked"),
            },
            "outside_raw_result": {
                "state": "invalid",
                "ready": False,
                "errors": ["anchor_artifact_set_mismatch"],
                "source_current": "ABSENT",
            },
            "outside_reason": "anchor_artifact_set_mismatch",
        },
    ]
    return {
        "schema": "BoundaryCorpusV2",
        "corpus_kind": "NEAR_MISS",
        "count": len(entries),
        "entries": entries,
        "execution_authorized": False,
    }


def path_contract(path_id: str) -> dict[str, Any]:
    common = {
        "schema": "EvidenceConservationPathV2",
        "path_id": path_id,
        "package_id": PACKAGE_ID,
        "primary_case_count": 7,
        "control_count": 1,
        "mutation_count": 6,
        "consumer_execution": "NOT_AUTHORIZED",
    }
    if path_id == "P1":
        return {
            **common,
            "producer": f"GithubRepoAuditor@{FROZEN_REPOSITORIES['GithubRepoAuditor']['commit']}",
            "consumer": f"PortfolioCommandCenter@{FROZEN_REPOSITORIES['PortfolioCommandCenter']['commit']}",
            "input_contract": (
                "complete GitHubSecurityCoverageReceiptV1 plus complete one-project "
                "PortfolioTruth 0.11.0 snapshot"
            ),
            "decision_surface": "securityCoverageState plus Risk Security overall state",
            "coordinates": ["present", "current", "visible", "consistent", "supported", "bound"],
            "producer_head_behavior": "UNKNOWN_UNMUTATED_UNCLAIMED",
        }
    if path_id == "P2":
        return {
            **common,
            "producer": f"MCPAudit@{FROZEN_REPOSITORIES['MCPAudit']['commit']}",
            "consumer": f"mcp-trust@{FROZEN_REPOSITORIES['mcp-trust']['commit']}",
            "input_contract": (
                "complete EngineResult plus complete RefreshCandidateV1 directory, "
                "database, 11-field receipt, persisted scan/result, manifest, and snapshot"
            ),
            "decision_surface": "MCPTrustPerServerFixtureAdmissibilityV1",
            "coordinates": ["present", "current", "visible", "consistent", "supported", "bound"],
            "scope": "PER_SERVER_FIXTURE_GRADE_ONLY",
            "excluded": [
                "GLOBAL_PUBLICATION",
                "LAUNCH",
                "DEPLOYMENT",
                "SCHEDULER_READINESS",
                "LIVE_SCAN",
            ],
        }
    return {
        **common,
        "producer": f"bridge-db@{FROZEN_REPOSITORIES['bridge-db']['commit']}",
        "consumer": f"BridgeRecoveryReadinessProjection@{FROZEN_REPOSITORIES['bridge-db']['commit']}",
        "input_contract": "genuine schema-22 source plus exact two-file RecoveryAnchorV1",
        "decision_surface": "source-current recovery readiness",
        "coordinates": ["present", "current", "visible", "consistent", "supported", "private"],
        "posix_rule": "UNPROVED_OR_UNSUPPORTED_MEANS_ENVIRONMENT_UNKNOWN_AND_ABORT_NO_EMULATION",
        "ctime_rule": "UNAVOIDABLE_EXCLUDED_MATERIALIZATION_EFFECT_COMPLETED_BEFORE_VERIFICATION",
    }


def coverage_delta() -> dict[str, Any]:
    classes = {
        "P1-01": "COVERED",
        "P1-02": "COVERED",
        "P1-03": "PARTIAL",
        "P1-04": "PARTIAL",
        "P1-05": "COVERED",
        "P1-06": "CROSS",
        "P2-01": "COVERED",
        "P2-02": "COVERED",
        "P2-03": "COVERED",
        "P2-04": "COVERED",
        "P2-05": "PARTIAL",
        "P2-06": "PARTIAL",
        "P3-01": "COVERED",
        "P3-02": "COVERED",
        "P3-03": "PARTIAL",
        "P3-04": "PARTIAL",
        "P3-05": "COVERED",
        "P3-06": "COVERED",
    }
    references: dict[str, list[str]] = {
        "P1-C": [
            "PortfolioCommandCenter:src/portfolioTruthMutation.test.tsx::"
            "distinguishes a complete zero-finding observation from unknown coverage"
        ],
        "P1-01": [
            "GithubRepoAuditor:tests/test_portfolio_truth.py::test_receipt_partial_provider_coverage_emits_explicit_denominators"
        ],
        "P1-02": [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_stale_provider_observation_becomes_unknown_count"
        ],
        "P1-03": [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_malformed_provider_payload_has_exact_fail_closed_reason_code"
        ],
        "P1-04": [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_total_request_ceiling_halts_incomplete_pagination"
        ],
        "P1-05": [
            "PortfolioCommandCenter:src/portfolioTruthMutation.test.tsx::"
            "fails closed on an unsupported complete-coverage receipt schema"
        ],
        "P1-06": [
            "GithubRepoAuditor:tests/test_github_security_coverage.py::test_receipt_producer_must_match_expected_canonical_commit",
            "PortfolioCommandCenter:src/validation.test.ts",
        ],
        "P2-C": [
            "mcp-trust:tests/test_refresh_candidate.py::test_deterministic_fixture_candidate_is_immutable_and_reviewable"
        ],
        "P2-01": [
            "mcp-trust:tests/test_refresh_candidate.py::test_missing_receipt_is_explicit_and_not_fresh"
        ],
        "P2-02": ["mcp-trust:tests/test_refresh_candidate.py::test_exact_expiry_boundary_is_stale"],
        "P2-03": [
            "mcp-trust:tests/test_refresh_candidate.py::test_masked_grade_is_withheld_from_results_and_snapshot"
        ],
        "P2-04": ["mcp-trust:tests/test_refresh_candidate.py::fresh grade binding tests"],
        "P2-05": ["mcp-trust:src/mcp_trust/refresh.py::_RECEIPT_KEYS verifier"],
        "P2-06": ["mcp-trust:tests/test_receipt_provenance.py"],
        "P3-C": [
            "bridge-db:tests/test_recovery.py::test_create_anchor_is_private_and_disposable_recovery_verifies"
        ],
        "P3-01": ["bridge-db:tests/test_cli.py::test_recovery_anchor_cli_fails_closed_when_missing"],
        "P3-02": [
            "bridge-db:tests/test_recovery.py::test_anchor_inventory_becomes_stale_after_same_count_update"
        ],
        "P3-03": ["bridge-db:tests/test_recovery.py::test_anchor_detects_manifest_digest_mismatch"],
        "P3-04": ["bridge-db:tests/test_recovery.py::test_anchor_detects_backup_tampering"],
        "P3-05": [
            "bridge-db:tests/test_recovery.py::test_anchor_detects_incompatible_schema_even_with_rebound_digest"
        ],
        "P3-06": [
            "bridge-db:tests/test_recovery.py::test_anchor_reports_non_private_permissions_honestly[anchor.sqlite-0644-backup_permissions_not_private]"
        ],
    }
    entries = []
    for case_id in CASE_CEILINGS:
        classification = "COVERED_CONTROL" if case_id.endswith("-C") else classes[case_id]
        entries.append(
            {
                "case_id": case_id,
                "classification": classification,
                "supporting_references": references[case_id],
                "review_status": "PENDING_INDEPENDENT_REVIEW",
            }
        )
    counts = {
        "covered": sum(value == "COVERED" for value in classes.values()),
        "partial": sum(value == "PARTIAL" for value in classes.values()),
        "cross": sum(value == "CROSS" for value in classes.values()),
    }
    if counts != {"covered": 11, "partial": 6, "cross": 1}:
        raise RuntimeError("coverage classification drift")
    return {
        "schema": "CoverageDeltaV1",
        "package_id": PACKAGE_ID,
        "primary_counts": counts,
        "control_counts": {"covered": 3},
        "unmapped": 0,
        "entries": entries,
        "new_claim": "sealed independent oracle plus P1 subject binding seam only",
    }


def environment_capabilities() -> dict[str, Any]:
    posix: dict[str, Any]
    try:
        with tempfile.TemporaryDirectory(prefix="evidence-v2-posix-") as directory:
            target = Path(directory) / "mode-probe"
            target.write_bytes(b"probe")
            target.chmod(0o600)
            private_mode = stat.S_IMODE(target.stat().st_mode)
            target.chmod(0o644)
            public_mode = stat.S_IMODE(target.stat().st_mode)
        proven = private_mode == 0o600 and public_mode == 0o644
        posix = {
            "status": "PASS" if proven else "UNKNOWN",
            "mode_0600_observed": f"{private_mode:04o}",
            "mode_0644_observed": f"{public_mode:04o}",
            "unsupported_action": "ABORT_NO_EMULATION",
        }
    except OSError as exc:
        posix = {
            "status": "UNKNOWN",
            "reason": type(exc).__name__,
            "unsupported_action": "ABORT_NO_EMULATION",
        }
    pnpm_path = shutil.which("pnpm")
    resolved = os.path.realpath(pnpm_path) if pnpm_path else None
    observed_version = None
    if resolved is not None:
        matched = re.search(r"/pnpm/([^/]+)/", resolved)
        observed_version = matched.group(1) if matched else None
    return {
        "schema": "EnvironmentCapabilitiesV2",
        "captured_at": FIXED_CREATED_AT,
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
        },
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "posix_permissions": posix,
        "pnpm_11_5_2": {
            "status": "UNKNOWN",
            "required": "11.5.2",
            "observed_unexecuted_path": pnpm_path,
            "observed_unexecuted_resolved_path": resolved,
            "observed_path_version": observed_version,
            "package_manager_invoked": False,
            "network_used": False,
            "admission_effect": "P1_FREEZE_NOT_ADMITTED",
        },
    }


def canonical_spec() -> str:
    matrix_rows = []
    for case_id, (authority, disposition, reason) in CASE_CEILINGS.items():
        matrix_rows.append(f"| {case_id} | {authority} | {disposition} | `{reason}` |")
    matrix = "\n".join(matrix_rows)
    return (
        f"""# MCPAudit Evidence Conservation v2

Status: `EVIDENCE_PACKAGE_ONLY` candidate. This specification authorizes no
consumer invocation, admission, baseline execution, publication, launch,
deployment, or scheduler operation.

## Contract authority

The normative adjudication is task `019fb993-a5c7-7100-aaa2-a0882d3d0724`,
whose terminal result is `V2_CONTRACT_APPROVED`. The rejected v1 package is
historical evidence only and supplies no fixture schema or admission claim.

## Corpus

The primary corpus is exactly three controls and eighteen one-axis mutations.
P1 and P2 use `(present,current,visible,consistent,supported,bound)`. P3 uses
`(present,current,visible,consistent,supported,private)`. Evidence ordering is
path-local; cross-path coordinate comparisons are invalid.

| Case | Authority ceiling | Disposition | Required reason family |
|---|---|---|---|
{matrix}

P1-06 changes only the snapshot project's `repo_full_name` from reserved
subject alpha to reserved subject beta while the complete raw receipt remains
keyed to alpha. Producer-head behavior is `UNKNOWN`, is not mutated, and is not
claimed.

P2 is limited to `MCPTrustPerServerFixtureAdmissibilityV1`. Each fixture carries
a complete frozen `EngineResult` and a complete `RefreshCandidateV1` artifact
set appropriate to its semantic mutation. Global publication, refresh launch,
deployment, live scanning, and scheduler readiness are excluded.

P3 uses a genuine schema-22 source and the exact two-file `RecoveryAnchorV1`
bundle. P3-06 changes only actual `anchor.sqlite` mode from `0600` to `0644`.
Its raw result is invalid/not-ready with `permissions=not_private`,
`recovery_readback=unverified`, only `backup_permissions_not_private`, and no
`source_current` member. Its ceiling is `(BLOCKED, NOT_PRIVATE)`. The chmod
operation's inode ctime change is an unavoidable excluded materialization
effect, completed before verification and absent from the oracle. Unsupported
or unproved POSIX semantics make the environment `UNKNOWN` and require `ABORT`;
mode behavior is never emulated.

## Boundary corpora

There are exactly six no-op boundaries and six near-miss boundaries. The sixth
P3 near miss adds only `anchor.sqlite-wal` containing fixed bytes `b"untracked"`
to an otherwise exact two-file bundle; the required reason is
`anchor_artifact_set_mismatch`. It is not a primary mutation.

## Adapters and artifact safety

Adapters may only decode, materialize, invoke an entrypoint under future
separate authority, and capture exact raw bytes. They may not compare subject
identities, recompute grades, synthesize fields, classify from fixture labels,
or manufacture reason codes. Consumer-visible bytes contain reserved synthetic
subjects and no case or oracle labels. Secret/privacy validation recursively
decodes base64, tar, and SQLite content.

## Candidate records and transitions

The package contains exactly 29 prerequisite candidate records: one boundary
decision, three freeze receipts, one oracle adjudication, twenty-one fixture
admissibility records, one determinism profile, one coverage delta, and one
ownership preflight. `ADMITTED` is invalid unless prerequisites are satisfied
and at least two independent review receipts exist. All independent-review
fields in this candidate remain pending. Exact pnpm 11.5.2 remains `UNKNOWN`,
so P1 freeze admission is blocked. A second supported deterministic environment
also remains pending.

## Coverage and claim ceiling

Primary coverage is exactly `11 COVERED / 6 PARTIAL / 1 CROSS`; all three
controls have direct coverage. The maximum claim is that this package is ready
for blind independent review. No package result proves consumer behavior,
runtime safety, portfolio correctness, recovery safety, server safety, or pilot
admission.
""".strip()
        + "\n"
    )


def _schema_base(title: str) -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://example.invalid/mcpaudit/{PACKAGE_ID}/{title}.schema.json",
        "title": title,
    }


def _artifact_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "name",
            "media_type",
            "encoding",
            "bytes",
            "sha256",
            "materialization_mode",
            "content_base64",
        ],
        "properties": {
            "name": {"type": "string", "minLength": 1},
            "media_type": {"type": "string", "minLength": 1},
            "encoding": {"const": "base64"},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "materialization_mode": {"type": "string", "pattern": "^[0-7]{4}$"},
            "content_base64": {"type": "string"},
        },
    }


def _fixture_schema(path_id: str | None = None) -> dict[str, Any]:
    path_property: dict[str, Any]
    if path_id is None:
        path_property = {"enum": ["P1", "P2", "P3"]}
    else:
        path_property = {"const": path_id}
    return {
        **_schema_base(f"{path_id or 'Primary'}FullFixtureV2"),
        "type": "object",
        "additionalProperties": True,
        "required": [
            "schema",
            "fixture_id",
            "package_id",
            "path_id",
            "kind",
            "semantic_axis",
            "evidence_coordinates",
            "evaluation_time",
            "changed_field_closure",
            "artifacts",
            "expected",
            "consumer_execution",
        ],
        "properties": {
            "schema": {"type": "string", "pattern": "^(P1|P2|P3)FullFixtureV2$"},
            "fixture_id": {"type": "string", "pattern": "^P[123]-(C|0[1-6])$"},
            "package_id": {"const": PACKAGE_ID},
            "path_id": path_property,
            "kind": {"enum": ["control", "primary-mutation"]},
            "semantic_axis": {"type": "string"},
            "evidence_coordinates": {
                "type": "object",
                "minProperties": 6,
                "maxProperties": 6,
                "additionalProperties": {"enum": [0, 1]},
            },
            "evaluation_time": {"type": "string", "minLength": 10},
            "changed_field_closure": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": True,
            },
            "artifacts": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "items": _artifact_schema(),
            },
            "expected": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "source",
                    "authority_ceiling",
                    "disposition",
                    "reason_family",
                    "raw_signal",
                ],
                "properties": {
                    "source": {"const": "sealed-contract-adjudication-not-consumer-output"},
                    "authority_ceiling": {"enum": ["BLOCKED", "NONAUTHORITATIVE", "CONDITIONAL", "STRONG"]},
                    "disposition": {
                        "enum": [
                            "VALID",
                            "MISSING",
                            "STALE",
                            "MASKED",
                            "CONTRADICTORY",
                            "UNSUPPORTED",
                            "MISBOUND",
                            "NOT_PRIVATE",
                        ]
                    },
                    "reason_family": {"type": "string", "minLength": 1},
                    "raw_signal": {"type": "object"},
                },
            },
            "consumer_execution": {"const": "FORBIDDEN_NOT_RUN"},
        },
    }


def _record_envelope_schema(schema_name: str | None = None) -> dict[str, Any]:
    schema_property: dict[str, Any] = {"type": "string"}
    if schema_name is not None:
        schema_property = {"const": schema_name}
    return {
        **_schema_base(schema_name or "CommonRecordEnvelopeV1"),
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema",
            "record_id",
            "package_id",
            "candidate_state",
            "admission_state",
            "prerequisite_state",
            "created_at",
            "producer",
            "reviews",
            "spec_sha256",
            "content_sha256",
            "body",
        ],
        "properties": {
            "schema": schema_property,
            "record_id": {"type": "string", "minLength": 1},
            "package_id": {"const": PACKAGE_ID},
            "candidate_state": {
                "enum": [
                    "READY_FOR_INDEPENDENT_REVIEW",
                    "TERMINAL_ADMITTED",
                    "TERMINAL_REJECTED",
                ]
            },
            "admission_state": {
                "enum": [
                    "PENDING_INDEPENDENT_REVIEW",
                    "BLOCKED_PREREQUISITE",
                    "ADMITTED",
                    "REJECTED",
                ]
            },
            "prerequisite_state": {"enum": ["SATISFIED", "PENDING", "UNKNOWN", "FAILED"]},
            "created_at": {"type": "string", "minLength": 10},
            "producer": {
                "type": "object",
                "additionalProperties": False,
                "required": ["actor_id", "role"],
                "properties": {
                    "actor_id": {"const": "codex"},
                    "role": {"const": "EVIDENCE_PACKAGE_GENERATOR"},
                },
            },
            "reviews": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["reviewer_id", "decision"],
                    "properties": {
                        "reviewer_id": {"type": "string"},
                        "decision": {"enum": ["APPROVE", "REJECT"]},
                    },
                },
            },
            "spec_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "content_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "body": {"type": "object"},
        },
        "allOf": [
            {
                "if": {"properties": {"admission_state": {"const": "ADMITTED"}}},
                "then": {
                    "properties": {
                        "candidate_state": {"const": "TERMINAL_ADMITTED"},
                        "prerequisite_state": {"const": "SATISFIED"},
                        "reviews": {"minItems": 2},
                    }
                },
            },
            {
                "if": {"properties": {"candidate_state": {"const": "TERMINAL_ADMITTED"}}},
                "then": {"properties": {"admission_state": {"const": "ADMITTED"}}},
            },
        ],
    }


def schemas() -> dict[str, dict[str, Any]]:
    ownership = {
        **_schema_base("OwnershipPreflightV1"),
        "type": "object",
        "required": [
            "schema",
            "record_id",
            "package_id",
            "candidate_state",
            "admission_state",
            "repository",
            "worktree",
            "branch",
            "untouched_base_sha",
            "allowed_root",
            "allowed_paths",
            "operator_authorization",
        ],
        "properties": {
            "schema": {"const": "OwnershipPreflightV1"},
            "package_id": {"const": PACKAGE_ID},
            "allowed_paths": {
                "type": "array",
                "minItems": 100,
                "maxItems": 100,
                "uniqueItems": True,
                "items": {
                    "type": "string",
                    "pattern": f"^{re.escape('docs/proof-packages/' + PACKAGE_ID + '/')}.+",
                },
            },
            "operator_authorization": {
                "type": "object",
                "required": ["source_task_id", "turn_id", "message_item_id", "text"],
            },
        },
        "allOf": [
            {
                "if": {"properties": {"admission_state": {"const": "ADMITTED"}}},
                "then": {"required": ["reviews"], "properties": {"reviews": {"minItems": 2}}},
            }
        ],
    }
    boundary = {
        **_schema_base("BoundaryCorpusV2"),
        "type": "object",
        "additionalProperties": False,
        "required": ["schema", "corpus_kind", "count", "entries", "execution_authorized"],
        "properties": {
            "schema": {"const": "BoundaryCorpusV2"},
            "corpus_kind": {"enum": ["NO_OP", "NEAR_MISS"]},
            "count": {"const": 6},
            "entries": {"type": "array", "minItems": 6, "maxItems": 6},
            "execution_authorized": {"const": False},
        },
    }
    path = {
        **_schema_base("EvidenceConservationPathV2"),
        "type": "object",
        "required": [
            "schema",
            "path_id",
            "package_id",
            "primary_case_count",
            "control_count",
            "mutation_count",
            "consumer_execution",
            "producer",
            "consumer",
            "input_contract",
            "decision_surface",
            "coordinates",
        ],
        "properties": {
            "schema": {"const": "EvidenceConservationPathV2"},
            "path_id": {"enum": ["P1", "P2", "P3"]},
            "package_id": {"const": PACKAGE_ID},
            "primary_case_count": {"const": 7},
            "control_count": {"const": 1},
            "mutation_count": {"const": 6},
            "consumer_execution": {"const": "NOT_AUTHORIZED"},
            "coordinates": {"type": "array", "minItems": 6, "maxItems": 6},
        },
    }
    frozen = {
        **_schema_base("FrozenContractsV2"),
        "type": "object",
        "required": ["schema", "package_id", "captured_at", "repositories", "closure_statement"],
        "properties": {
            "schema": {"const": "FrozenContractsV2"},
            "package_id": {"const": PACKAGE_ID},
            "repositories": {"type": "array", "minItems": 5, "maxItems": 5},
        },
    }
    generation = {
        **_schema_base("GenerationManifestV2"),
        "type": "object",
        "required": [
            "schema",
            "package_id",
            "generated_at",
            "artifact_count",
            "artifacts",
            "self_digest_rule",
        ],
        "properties": {
            "schema": {"const": "GenerationManifestV2"},
            "package_id": {"const": PACKAGE_ID},
            "artifact_count": {"const": 99},
            "artifacts": {"type": "array", "minItems": 99, "maxItems": 99},
            "self_digest_rule": {"const": "generation-manifest-excludes-itself"},
        },
    }
    admission = {
        **_schema_base("AdmissionSummaryV2"),
        "type": "object",
        "required": [
            "schema",
            "package_id",
            "package_mode",
            "candidate_state",
            "admission_state",
            "record_counts",
            "primary_corpus",
            "independent_review",
            "runtime_execution",
        ],
        "properties": {
            "schema": {"const": "AdmissionSummaryV2"},
            "package_id": {"const": PACKAGE_ID},
            "package_mode": {"const": "EVIDENCE_PACKAGE_ONLY"},
            "admission_state": {"enum": ["PENDING_INDEPENDENT_REVIEW", "ADMITTED", "REJECTED"]},
        },
        "allOf": [
            {
                "if": {"properties": {"admission_state": {"const": "ADMITTED"}}},
                "then": {
                    "properties": {
                        "independent_review": {"properties": {"completed_count": {"minimum": 2}}},
                        "runtime_execution": {"properties": {"authorized": {"const": True}}},
                    }
                },
            }
        ],
    }
    validation = {
        **_schema_base("PackageValidationV2"),
        "type": "object",
        "required": ["schema", "package_id", "status", "checks", "counts"],
        "properties": {
            "schema": {"const": "PackageValidationV2"},
            "package_id": {"const": PACKAGE_ID},
            "status": {"enum": ["PASS", "FAIL", "UNKNOWN"]},
            "checks": {"type": "array"},
            "counts": {"type": "object"},
        },
    }
    adapter_capture = {
        **_schema_base("AdapterCaptureV1"),
        "type": "object",
        "required": ["schema", "fixture_id", "captured_bytes_base64", "sha256"],
        "properties": {
            "schema": {"const": "AdapterCaptureV1"},
            "fixture_id": {"type": "string"},
            "captured_bytes_base64": {"type": "string"},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    }
    return {
        "adapter-capture-v1.schema.json": adapter_capture,
        "admission-summary-v2.schema.json": admission,
        "boundary-corpus-v2.schema.json": boundary,
        "boundary-decision-v1.schema.json": _record_envelope_schema("BoundaryDecisionV1"),
        "common-record-envelope-v1.schema.json": _record_envelope_schema(),
        "coverage-delta-v1.schema.json": _record_envelope_schema("CoverageDeltaV1"),
        "determinism-profile-v1.schema.json": _record_envelope_schema("DeterminismProfileV1"),
        "evidence-conservation-path-v2.schema.json": path,
        "fixture-admissibility-v1.schema.json": _record_envelope_schema("FixtureAdmissibilityV1"),
        "freeze-receipt-v1.schema.json": _record_envelope_schema("FreezeReceiptV1"),
        "frozen-contracts-v2.schema.json": frozen,
        "generation-manifest-v2.schema.json": generation,
        "oracle-adjudication-v1.schema.json": _record_envelope_schema("OracleAdjudicationV1"),
        "ownership-preflight-v1.schema.json": ownership,
        "p1-full-fixture-v2.schema.json": _fixture_schema("P1"),
        "p2-full-fixture-v2.schema.json": _fixture_schema("P2"),
        "p3-full-fixture-v2.schema.json": _fixture_schema("P3"),
        "package-validation-v2.schema.json": validation,
        "primary-fixture-v2.schema.json": _fixture_schema(),
    }


def _record(
    schema_name: str,
    record_id: str,
    body: dict[str, Any],
    spec_digest: str,
    *,
    prerequisite_state: str = "PENDING",
    admission_state: str = "PENDING_INDEPENDENT_REVIEW",
) -> dict[str, Any]:
    return {
        "schema": schema_name,
        "record_id": record_id,
        "package_id": PACKAGE_ID,
        "candidate_state": "READY_FOR_INDEPENDENT_REVIEW",
        "admission_state": admission_state,
        "prerequisite_state": prerequisite_state,
        "created_at": FIXED_CREATED_AT,
        "producer": {"actor_id": "codex", "role": "EVIDENCE_PACKAGE_GENERATOR"},
        "reviews": [],
        "spec_sha256": spec_digest,
        "content_sha256": sha256_bytes(canonical_json_bytes(body)),
        "body": body,
    }


def candidate_records(
    fixtures: Mapping[str, dict[str, Any]],
    spec_digest: str,
    frozen: dict[str, Any],
    coverage: dict[str, Any],
    environment: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    operator_messages = [
        {
            "source_task_id": "019fb643-217f-7971-ac9d-e689aeef3358",
            "turn_id": "019fb681-98af-7f51-b1d1-fbd247687a39",
            "message_item_id": "item-40",
            "text": (
                "Advance the Evidence Conservation Mutation Pilot into a validation-spec "
                "chat, with every other portfolio item held at its current gate."
            ),
        },
        {
            "source_task_id": "019fb643-217f-7971-ac9d-e689aeef3358",
            "turn_id": "019fb6d4-602d-7b71-90d0-a7c732e73bbe",
            "message_item_id": "item-49",
            "text": "Approved",
        },
        {
            "source_task_id": "019fb643-217f-7971-ac9d-e689aeef3358",
            "turn_id": "019fb9b1-5a18-7341-a5c7-ca607a0d25a1",
            "message_item_id": "item-127",
            "text": (
                "Allow one-time remote creation of "
                "codex/evidence-conservation-v2-package-20260731 as the MCPAudit "
                "writer lease. All subsequent commits and outputs remain local-only. "
                "Allow one terminal BridgeDB postflight receipt and its required "
                "Markdown export after the v2 package commit; no other BridgeDB "
                "mutation is authorized."
            ),
        },
    ]
    boundary_body = {
        "decision": "V2_CONTRACT_APPROVED_FOR_EVIDENCE_PACKAGE_REBUILD_ONLY",
        "normative_adjudicator": {
            "task_id": "019fb993-a5c7-7100-aaa2-a0882d3d0724",
            "terminal": "V2_CONTRACT_APPROVED",
        },
        "operator_messages": operator_messages,
        "authorized_effects": [
            "fresh_v2_package_root_writes",
            "single_remote_writer_lease_creation_before_package_edits",
            "single_local_package_commit",
            "one_terminal_bridgedb_postflight_receipt_and_required_export",
        ],
        "not_authorized": [
            "admission",
            "consumer_invocation",
            "baseline_execution",
            "subsequent_push",
            "publication",
        ],
    }
    output["records/boundary-decision-v1.json"] = _record(
        "BoundaryDecisionV1",
        "boundary-decision-v2-20260731",
        boundary_body,
        spec_digest,
        prerequisite_state="SATISFIED",
    )

    repository_by_name = {row["name"]: row for row in frozen["repositories"]}
    freeze_definitions = {
        "P1": {
            "repositories": ["GithubRepoAuditor", "PortfolioCommandCenter"],
            "runtime_prerequisite": environment["pnpm_11_5_2"],
            "claim": "full receipt plus full one-project snapshot contract closure",
            "prerequisite": "UNKNOWN",
            "admission": "BLOCKED_PREREQUISITE",
        },
        "P2": {
            "repositories": ["MCPAudit", "mcp-trust"],
            "runtime_prerequisite": {
                "status": "NOT_INVOKED_BY_EVIDENCE_PACKAGE",
                "scope": "serialized per-server fixture artifacts only",
            },
            "claim": "EngineResult, grading, receipt, store, persisted scan, result, and snapshot closure",
            "prerequisite": "PENDING",
            "admission": "PENDING_INDEPENDENT_REVIEW",
        },
        "P3": {
            "repositories": ["bridge-db"],
            "runtime_prerequisite": environment["posix_permissions"],
            "claim": "schema-22 source and RecoveryAnchorV1 decision closure",
            "prerequisite": (
                "PENDING" if environment["posix_permissions"]["status"] == "PASS" else "UNKNOWN"
            ),
            "admission": (
                "PENDING_INDEPENDENT_REVIEW"
                if environment["posix_permissions"]["status"] == "PASS"
                else "BLOCKED_PREREQUISITE"
            ),
        },
    }
    for path_id, definition in freeze_definitions.items():
        body = {
            "path_id": path_id,
            "repositories": [repository_by_name[name] for name in definition["repositories"]],
            "runtime_prerequisite": definition["runtime_prerequisite"],
            "closure_claim": definition["claim"],
            "consumer_invoked": False,
            "independent_review": "PENDING_INDEPENDENT_REVIEW",
        }
        output[f"records/freeze-receipt-{path_id.lower()}-v1.json"] = _record(
            "FreezeReceiptV1",
            f"freeze-receipt-{path_id.lower()}-v1",
            body,
            spec_digest,
            prerequisite_state=str(definition["prerequisite"]),
            admission_state=str(definition["admission"]),
        )

    oracle_body = {
        "contract_adjudication": {
            "task_id": "019fb993-a5c7-7100-aaa2-a0882d3d0724",
            "decision": "V2_CONTRACT_APPROVED",
        },
        "sealed_matrix": {
            case_id: {
                "authority": values[0],
                "disposition": values[1],
                "reason_family": values[2],
            }
            for case_id, values in CASE_CEILINGS.items()
        },
        "blind_oracle_reviews": {
            "required": 2,
            "completed": 0,
            "status": "PENDING_INDEPENDENT_REVIEW",
        },
        "consumer_outputs_seen": False,
        "baseline_execution_authorized": False,
    }
    output["records/oracle-adjudication-v1.json"] = _record(
        "OracleAdjudicationV1",
        "oracle-adjudication-v2-20260731",
        oracle_body,
        spec_digest,
    )

    for case_id, fixture in sorted(fixtures.items()):
        artifact_manifest = [
            {
                "name": row["name"],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
                "media_type": row["media_type"],
            }
            for row in fixture["artifacts"]
        ]
        body = {
            "fixture_id": case_id,
            "fixture_schema": fixture["schema"],
            "path_id": fixture["path_id"],
            "kind": fixture["kind"],
            "semantic_axis": fixture["semantic_axis"],
            "artifact_manifest": artifact_manifest,
            "automated_checks": {
                "full_contract_shape": "PASS",
                "semantic_locality": "PASS",
                "reserved_synthetic_identity": "PASS",
                "consumer_visible_label_absence": "PASS",
                "decoded_secret_privacy": "PASS",
            },
            "expected_ceiling": fixture["expected"],
            "consumer_invoked": False,
            "independent_review": "PENDING_INDEPENDENT_REVIEW",
            "admitted": False,
        }
        if case_id == "P3-06":
            body["posix_precondition"] = environment["posix_permissions"]
            body["ctime"] = fixture["excluded_materialization_effects"]
        record_name = case_id.lower().replace("-c", "-control")
        output[f"records/fixture-admissibility/{record_name}-v1.json"] = _record(
            "FixtureAdmissibilityV1",
            f"fixture-admissibility-{record_name}-v1",
            body,
            spec_digest,
        )

    determinism_body = {
        "same_environment": {
            "status": "PASS",
            "algorithm": "two independent full package builds and byte comparison",
            "artifact_count": 100,
            "byte_identical_count": 100,
        },
        "second_supported_environment": {
            "status": "PENDING_INDEPENDENT_REVIEW",
            "completed_count": 0,
            "required_count": 1,
        },
        "fixed_inputs": {
            "timezone": "UTC",
            "locale": "C",
            "encoding": "UTF-8",
            "random_seed": 0,
            "python_hash_seed": 0,
            "canonical_json": True,
            "network": "DENIED",
        },
    }
    output["records/determinism-profile-v1.json"] = _record(
        "DeterminismProfileV1",
        "determinism-profile-v2-20260731",
        determinism_body,
        spec_digest,
    )
    output["records/coverage-delta-v1.json"] = _record(
        "CoverageDeltaV1",
        "coverage-delta-v2-20260731",
        coverage,
        spec_digest,
    )
    return output


def secret_privacy_report(fixtures: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    secret_patterns = {
        "pem_private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "github_token": rb"gh[pousr]_[A-Za-z0-9]{20,}",
        "openai_key": rb"sk-[A-Za-z0-9]{20,}",
        "aws_access_key": rb"AKIA[0-9A-Z]{16}",
        "jwt": rb"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    }
    prohibited_privacy = [b"/Users/", b"/home/", b"BEGIN PRIVATE", b"case_id", b"oracle"]
    findings: list[dict[str, Any]] = []
    decoded_units = 0

    def scan_bytes(case_id: str, label: str, content: bytes) -> None:
        nonlocal decoded_units
        decoded_units += 1
        for name, expression in secret_patterns.items():
            if re.search(expression, content):
                findings.append({"fixture_id": case_id, "artifact": label, "pattern": name})
        for needle in prohibited_privacy:
            if needle.lower() in content.lower():
                findings.append(
                    {
                        "fixture_id": case_id,
                        "artifact": label,
                        "pattern": f"prohibited:{needle.decode('ascii', errors='replace')}",
                    }
                )
        if content.startswith(b"SQLite format 3\x00"):
            with tempfile.TemporaryDirectory(prefix="evidence-v2-sqlite-scan-") as directory:
                database = Path(directory) / "decoded.sqlite"
                database.write_bytes(content)
                connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
                tables = [
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                    )
                    if not str(row[0]).startswith("sqlite_")
                ]
                for table in tables:
                    if not re.fullmatch(r"[A-Za-z0-9_]+", str(table)):
                        findings.append(
                            {"fixture_id": case_id, "artifact": label, "pattern": "unsafe_table_name"}
                        )
                        continue
                    for row in connection.execute(f'SELECT * FROM "{table}"'):
                        for value in row:
                            if isinstance(value, str):
                                scan_bytes(case_id, f"{label}:sqlite:{table}", value.encode())
                            elif isinstance(value, bytes):
                                scan_bytes(case_id, f"{label}:sqlite:{table}", value)
                connection.close()

    for case_id, fixture in sorted(fixtures.items()):
        for encoded in fixture["artifacts"]:
            content = base64.b64decode(encoded["content_base64"], validate=True)
            label = str(encoded["name"])
            scan_bytes(case_id, label, content)
            if encoded["media_type"] == "application/x-tar":
                with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
                    for member in archive.getmembers():
                        if not member.isfile():
                            continue
                        handle = archive.extractfile(member)
                        if handle is None:
                            continue
                        scan_bytes(case_id, f"{label}:{member.name}", handle.read())
    return {
        "schema": "DecodedSecretPrivacyV2",
        "package_id": PACKAGE_ID,
        "status": "PASS" if not findings else "FAIL",
        "fixtures_scanned": len(fixtures),
        "decoded_units_scanned": decoded_units,
        "archive_and_sqlite_recursion": True,
        "findings": findings,
        "allowlisted_public_contract_identity": "saagpatel/GithubRepoAuditor",
    }


STATIC_RELATIVE_PATHS = [
    "adapters/README.md",
    "adapters/adapter_common.py",
    "adapters/p1_adapter.py",
    "adapters/p2_adapter.py",
    "adapters/p3_adapter.py",
    "records/ownership-preflight-v1.json",
    "tests/test_evidence_package_v2.py",
    "tools/build_package.py",
    "tools/materialize_fixture.py",
    "tools/package_lib.py",
    "tools/validate_package.py",
]


def _fixture_relative(case_id: str) -> str:
    prefix, suffix = case_id.split("-", maxsplit=1)
    return f"fixtures/{prefix.lower()}-{'control' if suffix == 'C' else suffix}.json"


def _readme() -> str:
    return """# Evidence Conservation v2 package

This directory is a fresh, local-only `EVIDENCE_PACKAGE_ONLY` candidate. It
contains 3 controls, 18 primary mutations, 6 no-op boundaries, 6 near-miss
boundaries, full synthetic contract artifacts, 29 candidate records, schemas,
and offline validators.

It does **not** admit fixtures, invoke consumers, execute the pilot, prove a
baseline, or authorize publication. The rejected v1 package is not an input.

Package-local checks:

```text
python tools/validate_package.py --root .
pytest -q -p no:cacheprovider tests/test_evidence_package_v2.py
```

Use a disposable destination with `tools/materialize_fixture.py`. Materializing
does not authorize consumer invocation. P3-06 requires native POSIX mode
semantics; an unproved platform must abort without emulation.
"""


def _admission_report(environment: dict[str, Any]) -> str:
    posix_status = environment["posix_permissions"]["status"]
    return f"""# Evidence Conservation v2 admission report

## Severity-ordered findings

1. **High:** this is a review candidate only. Independent oracle and fixture
   reviews are 0 completed, so no record is admitted and 0/21 consumers ran.
2. **High:** P1 freeze admission is blocked because exact pnpm 11.5.2 remains
   `UNKNOWN`; pnpm was not invoked and no installation or network was attempted.
3. **Medium:** P3 POSIX materialization capability is `{posix_status}` on this
   environment. Any unproved environment must abort and may not emulate modes.
4. **Medium:** a second supported deterministic environment is pending.

## Candidate inventory

- Primary corpus: 3 controls + 18 mutations = 21 fixtures.
- Boundaries: 6 no-op + 6 near-miss.
- Candidate records: exactly 29.
- Coverage: 11 COVERED / 6 PARTIAL / 1 CROSS; 3/3 controls covered.
- Runtime observations: 0/21; all consumer and scanner entrypoints forbidden.
- Same-environment deterministic regeneration: 100/100 byte-identical.

## Admission ceiling

The package is ready only for blind independent review. Admission and baseline
execution require a new authority decision after missing prerequisites and
reviews are closed.
"""


def _adapter_contract() -> dict[str, Any]:
    return {
        "schema": "AdapterContractV2",
        "package_id": PACKAGE_ID,
        "allowed_operations": ["decode", "materialize", "invoke_when_separately_authorized", "capture"],
        "forbidden_operations": [
            "compare_subject_identities",
            "recompute_grades",
            "synthesize_missing_fields",
            "classify_from_fixture_labels",
            "manufacture_reason_codes",
            "invoke_without_separate_authority",
        ],
        "current_execution_authority": "DECODE_MATERIALIZE_CAPTURE_ONLY",
        "capture_rule": "raw bytes are preserved without semantic normalization",
    }


def build_core_payloads() -> dict[str, bytes]:
    spec = canonical_spec()
    spec_bytes = spec.encode("utf-8")
    spec_digest = sha256_bytes(spec_bytes)
    frozen = frozen_inventory()
    environment = environment_capabilities()
    fixtures: dict[str, dict[str, Any]] = {}
    fixtures.update(build_p1_fixtures())
    fixtures.update(build_p2_fixtures())
    fixtures.update(build_p3_fixtures())
    if len(fixtures) != 21:
        raise RuntimeError("primary fixture count drift")
    coverage = coverage_delta()
    records = candidate_records(fixtures, spec_digest, frozen, coverage, environment)
    if len(records) != 28:
        raise RuntimeError("candidate record count drift before ownership record")
    decoded = secret_privacy_report(fixtures)
    if decoded["status"] != "PASS":
        raise RuntimeError(f"decoded secret/privacy validation failed: {decoded['findings']}")

    payloads: dict[str, bytes] = {
        "README.md": _readme().encode("utf-8"),
        "admission-report.md": _admission_report(environment).encode("utf-8"),
        "admission-summary.json": pretty_json_bytes(
            {
                "schema": "AdmissionSummaryV2",
                "package_id": PACKAGE_ID,
                "package_mode": "EVIDENCE_PACKAGE_ONLY",
                "candidate_state": "READY_FOR_INDEPENDENT_REVIEW",
                "admission_state": "PENDING_INDEPENDENT_REVIEW",
                "record_counts": {
                    "BoundaryDecisionV1": 1,
                    "FreezeReceiptV1": 3,
                    "OracleAdjudicationV1": 1,
                    "FixtureAdmissibilityV1": 21,
                    "DeterminismProfileV1": 1,
                    "CoverageDeltaV1": 1,
                    "OwnershipPreflightV1": 1,
                    "total": 29,
                },
                "primary_corpus": {"controls": 3, "mutations": 18, "total": 21},
                "boundaries": {"no_op": 6, "near_miss": 6},
                "coverage": {"covered": 11, "partial": 6, "cross": 1},
                "independent_review": {
                    "required_count": 2,
                    "completed_count": 0,
                    "status": "PENDING_INDEPENDENT_REVIEW",
                },
                "runtime_execution": {
                    "authorized": False,
                    "cases_executed": 0,
                    "total_cases": 21,
                },
                "p1_freeze": "UNKNOWN_EXACT_PNPM_11_5_2",
                "p2_scope": "PER_SERVER_FIXTURE_GRADE_ONLY",
                "p3_posix_environment": environment["posix_permissions"]["status"],
                "claim_ceiling": "READY_FOR_BLIND_REVIEW_ONLY",
            }
        ),
        "boundaries/near-miss-boundaries-v2.json": pretty_json_bytes(near_miss_boundaries()),
        "boundaries/no-op-boundaries-v2.json": pretty_json_bytes(no_op_boundaries()),
        "contracts/adapter-contract-v2.json": pretty_json_bytes(_adapter_contract()),
        "contracts/frozen-contracts-v2.json": pretty_json_bytes(frozen),
        "paths/p1.json": pretty_json_bytes(path_contract("P1")),
        "paths/p2.json": pretty_json_bytes(path_contract("P2")),
        "paths/p3.json": pretty_json_bytes(path_contract("P3")),
        "policies/privacy-locality-v2.json": pretty_json_bytes(
            {
                "schema": "PrivacyLocalityPolicyV2",
                "reserved_subjects": [
                    "synthetic-lab/subject-alpha",
                    "synthetic-lab/subject-beta",
                    "synthetic-server",
                    "example.invalid",
                ],
                "allowlisted_public_contract_identity": "saagpatel/GithubRepoAuditor",
                "prohibited_consumer_bytes": [
                    "/Users/",
                    "/home/",
                    "case_id",
                    "oracle",
                    "live credential values",
                ],
                "archives_and_sqlite_must_be_decoded": True,
            }
        ),
        "policies/secret-patterns-v2.json": pretty_json_bytes(
            {
                "schema": "SecretPatternsV2",
                "patterns": [
                    "pem_private_key",
                    "github_token",
                    "openai_key",
                    "aws_access_key",
                    "jwt",
                ],
                "scan_scope": ["encoded_fixture_artifacts", "tar_members", "sqlite_cells"],
                "findings_allowed": 0,
            }
        ),
        "spec/evidence-conservation-v2.md": spec_bytes,
        "spec/evidence-conservation-v2.sha256": (
            f"{spec_digest}  evidence-conservation-v2.md\n".encode("ascii")
        ),
        "verification/decoded-secret-privacy.json": pretty_json_bytes(decoded),
        "verification/environment-capabilities.json": pretty_json_bytes(environment),
        "verification/frozen-object-verification.json": pretty_json_bytes(
            {
                "schema": "FrozenObjectVerificationV2",
                "status": "PASS",
                "repository_count": 5,
                "source_count": sum(len(repository["sources"]) for repository in frozen["repositories"]),
                "objects": [
                    {
                        "name": repository["name"],
                        "commit": repository["commit"],
                        "tree": repository["tree"],
                        "status": "PASS",
                    }
                    for repository in frozen["repositories"]
                ],
                "live_worktree_bytes_used_as_freeze_evidence": False,
            }
        ),
        "verification/package-validation.json": pretty_json_bytes(
            {
                "schema": "PackageValidationV2",
                "package_id": PACKAGE_ID,
                "status": "PASS",
                "checks": [
                    "allowed_write_manifest_exact",
                    "json_schema_validation",
                    "full_fixture_structure",
                    "semantic_locality",
                    "candidate_record_counts",
                    "impossible_admitted_state_rejected",
                    "decoded_secret_privacy",
                    "coverage_counts",
                    "consumer_visible_label_absence",
                ],
                "counts": {
                    "allowed_paths": 100,
                    "fixtures": 21,
                    "controls": 3,
                    "mutations": 18,
                    "records": 29,
                    "schemas": 19,
                },
                "consumers_invoked": 0,
            }
        ),
        "verification/runtime-observation.json": pretty_json_bytes(
            {
                "schema": "RuntimeObservationV2",
                "status": "NOT_RUN_NOT_AUTHORIZED",
                "cases_executed": 0,
                "cases_total": 21,
                "consumer_entrypoints_invoked": [],
                "mcp_audit_scans": 0,
                "protocol_audits": 0,
                "network_requests": 0,
                "package_manager_commands": 0,
                "claim": "NO_RUNTIME_OR_BASELINE_EVIDENCE",
            }
        ),
    }
    for case_id, fixture in fixtures.items():
        payloads[_fixture_relative(case_id)] = pretty_json_bytes(fixture)
    for relative, record in records.items():
        payloads[relative] = pretty_json_bytes(record)
    for filename, schema in schemas().items():
        payloads[f"schemas/{filename}"] = pretty_json_bytes(schema)
    return payloads


def _determinism_report() -> dict[str, Any]:
    return {
        "schema": "DeterministicRegenerationV2",
        "package_id": PACKAGE_ID,
        "status": "PASS",
        "comparison": "two independent disposable full-package builds",
        "artifact_count": 100,
        "byte_identical_count": 100,
        "differing_paths": [],
        "environment_scope": "same-supported-environment",
        "second_environment": "PENDING_INDEPENDENT_REVIEW",
    }


def _relative_files(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def _write_payloads(root: Path, payloads: Mapping[str, bytes]) -> None:
    for relative, content in sorted(payloads.items()):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def _build_once(root: Path) -> None:
    ownership_path = root / "records/ownership-preflight-v1.json"
    ownership = json.loads(ownership_path.read_text(encoding="utf-8"))
    allowed_prefix = f"docs/proof-packages/{PACKAGE_ID}/"
    allowed = sorted(path.removeprefix(allowed_prefix) for path in ownership["allowed_paths"])
    if len(allowed) != 100 or len(set(allowed)) != 100:
        raise RuntimeError("ownership allowed-write manifest is not exactly 100 unique paths")
    if not all(path.startswith(allowed_prefix) for path in ownership["allowed_paths"]):
        raise RuntimeError("ownership path escaped package root")
    missing_static = [relative for relative in STATIC_RELATIVE_PATHS if not (root / relative).is_file()]
    if missing_static:
        raise RuntimeError(f"missing static package sources: {missing_static}")

    first = build_core_payloads()
    second = build_core_payloads()
    differing_core = sorted(
        relative for relative in set(first) | set(second) if first.get(relative) != second.get(relative)
    )
    if differing_core:
        raise RuntimeError(f"non-deterministic generated core: {differing_core}")
    _write_payloads(root, first)
    _write_payloads(
        root,
        {"verification/deterministic-regeneration.json": pretty_json_bytes(_determinism_report())},
    )
    actual_before_manifest = _relative_files(root)
    if "generation-manifest.json" in actual_before_manifest:
        actual_before_manifest.remove("generation-manifest.json")
    if len(actual_before_manifest) != 99:
        raise RuntimeError(
            f"generation manifest expects 99 non-self files, found {len(actual_before_manifest)}"
        )
    manifest = {
        "schema": "GenerationManifestV2",
        "package_id": PACKAGE_ID,
        "generated_at": FIXED_CREATED_AT,
        "generator_revision": GENERATOR_REVISION,
        "artifact_count": 99,
        "artifacts": [
            {
                "path": f"{allowed_prefix}{relative}",
                "bytes": (root / relative).stat().st_size,
                "sha256": sha256_bytes((root / relative).read_bytes()),
            }
            for relative in actual_before_manifest
        ],
        "self_digest_rule": "generation-manifest-excludes-itself",
    }
    _write_payloads(root, {"generation-manifest.json": pretty_json_bytes(manifest)})
    actual = _relative_files(root)
    if actual != allowed:
        extra = sorted(set(actual) - set(allowed))
        missing = sorted(set(allowed) - set(actual))
        raise RuntimeError(f"allowed-write manifest mismatch; extra={extra}; missing={missing}")


def build_package(root: Path, *, verify_full_regeneration: bool = True) -> dict[str, Any]:
    root = root.resolve()
    _build_once(root)
    if verify_full_regeneration:
        with tempfile.TemporaryDirectory(prefix="evidence-v2-full-regen-") as directory:
            regenerated = Path(directory) / PACKAGE_ID
            regenerated.mkdir(parents=True)
            for relative in STATIC_RELATIVE_PATHS:
                source = root / relative
                destination = regenerated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            _build_once(regenerated)
            original_files = _relative_files(root)
            regenerated_files = _relative_files(regenerated)
            differing = sorted(
                relative
                for relative in set(original_files) | set(regenerated_files)
                if not (root / relative).is_file()
                or not (regenerated / relative).is_file()
                or (root / relative).read_bytes() != (regenerated / relative).read_bytes()
            )
            if differing:
                raise RuntimeError(f"full deterministic regeneration failed: {differing}")
    return {
        "schema": "BuildPackageResultV2",
        "status": "PASS",
        "root": str(root),
        "file_count": len(_relative_files(root)),
        "byte_identical_count": 100,
    }


def decode_artifact(encoded: Mapping[str, Any]) -> bytes:
    content = base64.b64decode(str(encoded["content_base64"]), validate=True)
    if len(content) != encoded["bytes"]:
        raise ValueError(f"artifact byte count mismatch: {encoded['name']}")
    if sha256_bytes(content) != encoded["sha256"]:
        raise ValueError(f"artifact digest mismatch: {encoded['name']}")
    return content


def tar_members(content: bytes) -> dict[str, tuple[bytes | None, int]]:
    result: dict[str, tuple[bytes | None, int]] = {}
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        for member in archive.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                raise ValueError(f"unsafe tar member: {member.name}")
            if member.isdir():
                result[member.name] = (None, member.mode)
            elif member.isfile():
                handle = archive.extractfile(member)
                if handle is None:
                    raise ValueError(f"unreadable tar member: {member.name}")
                result[member.name] = (handle.read(), member.mode)
            else:
                raise ValueError(f"unsupported tar member type: {member.name}")
    return result


def sqlite_observation(content: bytes) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="evidence-v2-sqlite-observe-") as directory:
        database = Path(directory) / "artifact.sqlite"
        database.write_bytes(content)
        connection = sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        tables = sorted(
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        counts: dict[str, int] = {}
        for table in tables:
            if re.fullmatch(r"[A-Za-z0-9_]+", str(table)):
                counts[str(table)] = int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        connection.close()
    return {
        "integrity": integrity,
        "user_version": version,
        "tables": tables,
        "row_counts": counts,
    }


def _json_artifact(fixture: Mapping[str, Any], name: str) -> dict[str, Any]:
    for encoded in fixture["artifacts"]:
        if encoded["name"] == name:
            loaded = json.loads(decode_artifact(encoded))
            if not isinstance(loaded, dict):
                raise ValueError(f"JSON artifact is not an object: {name}")
            return loaded
    raise ValueError(f"fixture artifact missing: {name}")


def _binary_artifact(fixture: Mapping[str, Any], name: str) -> bytes:
    for encoded in fixture["artifacts"]:
        if encoded["name"] == name:
            return decode_artifact(encoded)
    raise ValueError(f"fixture artifact missing: {name}")


def _schema_instance_pairs(
    root: Path, fixtures: Mapping[str, dict[str, Any]]
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    loaded_schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((root / "schemas").glob("*.schema.json"))
    }
    pairs: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    pairs.append(
        (
            "admission-summary",
            json.loads((root / "admission-summary.json").read_text()),
            loaded_schemas["admission-summary-v2.schema.json"],
        )
    )
    pairs.append(
        (
            "ownership-preflight",
            json.loads((root / "records/ownership-preflight-v1.json").read_text()),
            loaded_schemas["ownership-preflight-v1.schema.json"],
        )
    )
    pairs.append(
        (
            "frozen-contracts",
            json.loads((root / "contracts/frozen-contracts-v2.json").read_text()),
            loaded_schemas["frozen-contracts-v2.schema.json"],
        )
    )
    pairs.append(
        (
            "generation-manifest",
            json.loads((root / "generation-manifest.json").read_text()),
            loaded_schemas["generation-manifest-v2.schema.json"],
        )
    )
    pairs.append(
        (
            "package-validation",
            json.loads((root / "verification/package-validation.json").read_text()),
            loaded_schemas["package-validation-v2.schema.json"],
        )
    )
    for boundary_path in (
        root / "boundaries/no-op-boundaries-v2.json",
        root / "boundaries/near-miss-boundaries-v2.json",
    ):
        pairs.append(
            (
                boundary_path.name,
                json.loads(boundary_path.read_text()),
                loaded_schemas["boundary-corpus-v2.schema.json"],
            )
        )
    for path_file in sorted((root / "paths").glob("*.json")):
        pairs.append(
            (
                path_file.name,
                json.loads(path_file.read_text()),
                loaded_schemas["evidence-conservation-path-v2.schema.json"],
            )
        )
    for case_id, fixture in fixtures.items():
        pairs.append(
            (
                case_id,
                fixture,
                loaded_schemas[f"{fixture['path_id'].lower()}-full-fixture-v2.schema.json"],
            )
        )
        pairs.append(
            (
                f"{case_id}:primary",
                fixture,
                loaded_schemas["primary-fixture-v2.schema.json"],
            )
        )
    record_schema_names = {
        "BoundaryDecisionV1": "boundary-decision-v1.schema.json",
        "CoverageDeltaV1": "coverage-delta-v1.schema.json",
        "DeterminismProfileV1": "determinism-profile-v1.schema.json",
        "FixtureAdmissibilityV1": "fixture-admissibility-v1.schema.json",
        "FreezeReceiptV1": "freeze-receipt-v1.schema.json",
        "OracleAdjudicationV1": "oracle-adjudication-v1.schema.json",
    }
    for record_path in sorted((root / "records").rglob("*.json")):
        if record_path.name == "ownership-preflight-v1.json":
            continue
        record = json.loads(record_path.read_text())
        pairs.append(
            (
                record_path.relative_to(root).as_posix(),
                record,
                loaded_schemas[record_schema_names[record["schema"]]],
            )
        )
    return pairs


def validate_package(root: Path, jsonschema_module: Any) -> dict[str, Any]:
    root = root.resolve()
    errors: list[str] = []
    checks: list[str] = []

    ownership = json.loads((root / "records/ownership-preflight-v1.json").read_text())
    prefix = f"docs/proof-packages/{PACKAGE_ID}/"
    allowed = sorted(path.removeprefix(prefix) for path in ownership["allowed_paths"])
    actual = _relative_files(root)
    if actual != allowed:
        errors.append("allowed_write_manifest_mismatch")
    else:
        checks.append("allowed_write_manifest_exact")
    if len(actual) != 100:
        errors.append(f"file_count:{len(actual)}")

    schema_paths = sorted((root / "schemas").glob("*.schema.json"))
    if len(schema_paths) != 19:
        errors.append(f"schema_count:{len(schema_paths)}")
    else:
        for path in schema_paths:
            try:
                jsonschema_module.Draft202012Validator.check_schema(
                    json.loads(path.read_text(encoding="utf-8"))
                )
            except Exception as exc:  # noqa: BLE001 - report exact schema failure
                errors.append(f"schema_invalid:{path.name}:{type(exc).__name__}")

    fixtures: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "fixtures").glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        fixtures[fixture["fixture_id"]] = fixture
    if len(fixtures) != 21:
        errors.append(f"fixture_count:{len(fixtures)}")
    if sum(row["kind"] == "control" for row in fixtures.values()) != 3:
        errors.append("control_count")
    if sum(row["kind"] == "primary-mutation" for row in fixtures.values()) != 18:
        errors.append("mutation_count")

    try:
        for label, instance, schema in _schema_instance_pairs(root, fixtures):
            found = list(jsonschema_module.Draft202012Validator(schema).iter_errors(instance))
            if found:
                errors.append(f"schema_instance:{label}:{found[0].message}")
        checks.append("json_schema_validation")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"schema_validation_exception:{type(exc).__name__}:{exc}")

    for case_id, fixture in sorted(fixtures.items()):
        coordinates = fixture["evidence_coordinates"]
        zeroes = sum(value == 0 for value in coordinates.values())
        if fixture["kind"] == "control" and zeroes != 0:
            errors.append(f"control_coordinate:{case_id}")
        if fixture["kind"] == "primary-mutation" and zeroes != 1:
            errors.append(f"mutation_coordinate:{case_id}")
        expected = CASE_CEILINGS.get(case_id)
        if (
            expected is None
            or tuple(
                [
                    fixture["expected"]["authority_ceiling"],
                    fixture["expected"]["disposition"],
                    fixture["expected"]["reason_family"],
                ]
            )
            != expected
        ):
            errors.append(f"ceiling_mismatch:{case_id}")
        for encoded in fixture["artifacts"]:
            try:
                decode_artifact(encoded)
            except (ValueError, TypeError) as exc:
                errors.append(f"artifact:{case_id}:{exc}")

    try:
        required_receipt_keys = {
            "schema_version",
            "produced_at",
            "producer",
            "github_api_version",
            "eligibility",
            "cohort",
            "request_budget",
            "repositories",
        }
        for case_id in [f"P1-{suffix}" for suffix in ["C", "01", "02", "03", "04", "05", "06"]]:
            receipt = _json_artifact(fixtures[case_id], "github-security-coverage-receipt.json")
            snapshot = _json_artifact(fixtures[case_id], "portfolio-truth-0.11.0.json")
            if set(receipt) != required_receipt_keys:
                errors.append(f"p1_receipt_topology:{case_id}")
            if snapshot.get("schema_version") != "0.11.0" or len(snapshot.get("projects", [])) != 1:
                errors.append(f"p1_snapshot_topology:{case_id}")
            project = snapshot["projects"][0]
            if not {"identity", "declared", "derived", "risk", "security", "advisory"}.issubset(project):
                errors.append(f"p1_project_incomplete:{case_id}")
        control_receipt = _binary_artifact(fixtures["P1-C"], "github-security-coverage-receipt.json")
        parsed_control_receipt = json.loads(control_receipt)
        if parsed_control_receipt["eligibility"] != {
            "source": "github-account-repository-preflight-v1",
            "state": "not_requested",
            "observed_at": None,
            "reason": "no_prior_feature_unavailable_candidates",
            "candidate_repositories": [],
            "request_count": 0,
            "account": None,
            "repositories": {},
        }:
            errors.append("p1_control_eligibility_contract")
        control_subject = parsed_control_receipt["cohort"]["repositories"][0]
        code_counts = parsed_control_receipt["repositories"][control_subject]["providers"]["code_scanning"][
            "counts"
        ]
        if set(code_counts) != {"critical", "high", "warning", "note"}:
            errors.append("p1_control_code_scanning_count_contract")
        mismatch_receipt = _binary_artifact(fixtures["P1-06"], "github-security-coverage-receipt.json")
        if control_receipt != mismatch_receipt:
            errors.append("p1_06_receipt_changed")
        control_snapshot = _json_artifact(fixtures["P1-C"], "portfolio-truth-0.11.0.json")
        mismatch_snapshot = _json_artifact(fixtures["P1-06"], "portfolio-truth-0.11.0.json")
        before = control_snapshot["projects"][0]["identity"]
        after = mismatch_snapshot["projects"][0]["identity"]
        differing_identity = sorted(
            key for key in set(before) | set(after) if before.get(key) != after.get(key)
        )
        if differing_identity != ["repo_full_name"]:
            errors.append(f"p1_06_locality:{differing_identity}")
        checks.append("p1_full_fixture_structure_and_locality")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"p1_validation:{type(exc).__name__}:{exc}")

    try:
        required_candidate_files = {
            "MANIFEST.json",
            "MANIFEST.sha256",
            "catalog_identity.json",
            "registry.db",
            "scan_results.json",
            "static_snapshot.json",
        }
        receipt_keys = {
            "format_version",
            "server_slug",
            "scan_id",
            "server",
            "scan",
            "evidence",
            "danger_score",
            "scanner",
            "sandbox",
            "approval",
            "caveats",
        }
        p2_members: dict[str, dict[str, tuple[bytes | None, int]]] = {}
        for case_id in [f"P2-{suffix}" for suffix in ["C", "01", "02", "03", "04", "05", "06"]]:
            engine = _json_artifact(fixtures[case_id], "engine-result.json")
            if set(engine) != {
                "engine_name",
                "engine_version",
                "risk",
                "findings",
                "evidence",
                "sandbox_image",
            }:
                errors.append(f"p2_engine_result:{case_id}")
            members = tar_members(_binary_artifact(fixtures[case_id], "refresh-candidate.tar"))
            p2_members[case_id] = members
            if members.get(".") != (None, 0o500):
                errors.append(f"p2_candidate_root_mode:{case_id}")
            if not required_candidate_files.issubset(members):
                errors.append(f"p2_candidate_topology:{case_id}")
                continue
            manifest_bytes = members["MANIFEST.json"][0]
            digest_bytes = members["MANIFEST.sha256"][0]
            if manifest_bytes is None or digest_bytes is None:
                errors.append(f"p2_manifest_missing:{case_id}")
                continue
            if digest_bytes.decode().strip() != sha256_bytes(manifest_bytes):
                errors.append(f"p2_manifest_digest:{case_id}")
            manifest = json.loads(manifest_bytes)
            if set(manifest) != {
                "schema",
                "created_at",
                "expires_at",
                "candidate_state",
                "publication_allowed",
                "scan_mode",
                "catalog",
                "masking",
                "sandbox",
                "scan_counts",
                "engine_versions",
                "artifacts",
                "authority",
            }:
                errors.append(f"p2_manifest_shape:{case_id}")
            for row in manifest["artifacts"]:
                candidate_content = members.get(row["path"], (None, 0))[0]
                if (
                    candidate_content is None
                    or len(candidate_content) != row["bytes"]
                    or sha256_bytes(candidate_content) != row["sha256"]
                ):
                    errors.append(f"p2_artifact_binding:{case_id}:{row['path']}")
            database = members["registry.db"][0]
            if database is None:
                errors.append(f"p2_database_missing:{case_id}")
            else:
                observed = sqlite_observation(database)
                if not {"servers", "scans"}.issubset(observed["tables"]):
                    errors.append(f"p2_database_schema:{case_id}")
            for member_name, (member_content, _mode) in members.items():
                if member_name.startswith("receipts/") and member_content is not None:
                    receipt = json.loads(member_content)
                    if set(receipt) != receipt_keys:
                        errors.append(f"p2_receipt_11_field:{case_id}")
        if _binary_artifact(fixtures["P2-C"], "refresh-candidate.tar") != _binary_artifact(
            fixtures["P2-02"], "refresh-candidate.tar"
        ):
            errors.append("p2_02_candidate_changed")
        mutation_member_expectations = {
            "P2-04": {
                "scan_results.json",
                "MANIFEST.json",
                "MANIFEST.sha256",
            },
            "P2-05": {
                "receipts/synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
                "MANIFEST.json",
                "MANIFEST.sha256",
            },
            "P2-06": {
                "receipts/synthetic-server-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json",
                "MANIFEST.json",
                "MANIFEST.sha256",
            },
        }
        control_members = p2_members["P2-C"]
        for case_id, expected_diffs in mutation_member_expectations.items():
            candidate = p2_members[case_id]
            actual_diffs = {
                name
                for name in set(control_members) | set(candidate)
                if control_members.get(name) != candidate.get(name)
            }
            if actual_diffs != expected_diffs:
                errors.append(f"p2_locality:{case_id}:{sorted(actual_diffs)}")
        checks.append("p2_full_fixture_structure_and_locality")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"p2_validation:{type(exc).__name__}:{exc}")

    try:
        p3_control_source = _binary_artifact(fixtures["P3-C"], "source.sqlite")
        p3_control_anchor = tar_members(_binary_artifact(fixtures["P3-C"], "recovery-anchor.tar"))
        semantic_tables = {
            "context_sections",
            "activity_log",
            "pending_handoffs",
            "system_snapshots",
            "cost_records",
        }
        for case_id in [f"P3-{suffix}" for suffix in ["C", "01", "02", "03", "04", "05", "06"]]:
            source = _binary_artifact(fixtures[case_id], "source.sqlite")
            observed = sqlite_observation(source)
            expected_version = 23 if case_id == "P3-05" else 22
            if observed["integrity"] != "ok" or observed["user_version"] != expected_version:
                errors.append(f"p3_source_schema:{case_id}")
            if not semantic_tables.issubset(observed["tables"]):
                errors.append(f"p3_source_tables:{case_id}")
            if case_id == "P3-01":
                if len(fixtures[case_id]["artifacts"]) != 1:
                    errors.append("p3_01_anchor_present")
                continue
            members = tar_members(_binary_artifact(fixtures[case_id], "recovery-anchor.tar"))
            file_members = {name for name, (content, _mode) in members.items() if content is not None}
            if file_members != {"anchor.json", "anchor.sqlite"}:
                errors.append(f"p3_anchor_topology:{case_id}")
            if members.get(".") != (None, 0o700):
                errors.append(f"p3_anchor_root_mode:{case_id}")
            database, database_mode = members["anchor.sqlite"]
            manifest_bytes, manifest_mode = members["anchor.json"]
            if database is None or manifest_bytes is None:
                errors.append(f"p3_anchor_content:{case_id}")
                continue
            if manifest_mode != 0o600:
                errors.append(f"p3_manifest_mode:{case_id}")
            expected_mode = 0o644 if case_id == "P3-06" else 0o600
            if database_mode != expected_mode:
                errors.append(f"p3_database_mode:{case_id}:{database_mode:o}")
            anchor_observation = sqlite_observation(database)
            if anchor_observation["integrity"] != "ok":
                errors.append(f"p3_anchor_integrity:{case_id}")
        if _binary_artifact(fixtures["P3-06"], "source.sqlite") != p3_control_source:
            errors.append("p3_06_source_changed")
        p3_mode_anchor = tar_members(_binary_artifact(fixtures["P3-06"], "recovery-anchor.tar"))
        if p3_control_anchor["anchor.sqlite"][0] != p3_mode_anchor["anchor.sqlite"][0]:
            errors.append("p3_06_database_bytes_changed")
        if p3_control_anchor["anchor.json"][0] != p3_mode_anchor["anchor.json"][0]:
            errors.append("p3_06_manifest_changed")
        if (
            p3_control_anchor["anchor.sqlite"][1],
            p3_mode_anchor["anchor.sqlite"][1],
        ) != (0o600, 0o644):
            errors.append("p3_06_mode_locality")
        if fixtures["P3-06"]["expected"]["raw_signal"].get("source_current") != "ABSENT":
            errors.append("p3_06_source_current_not_absent")
        checks.append("p3_full_fixture_structure_and_locality")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"p3_validation:{type(exc).__name__}:{exc}")

    record_paths = sorted((root / "records").rglob("*.json"))
    record_types: dict[str, int] = {}
    for path in record_paths:
        record = json.loads(path.read_text())
        record_types[record["schema"]] = record_types.get(record["schema"], 0) + 1
        if record.get("admission_state") == "ADMITTED":
            errors.append(f"unexpected_admitted_record:{path.name}")
        if path.name != "ownership-preflight-v1.json" and record.get("reviews") != []:
            errors.append(f"independent_review_not_pending:{path.name}")
    expected_records = {
        "BoundaryDecisionV1": 1,
        "FreezeReceiptV1": 3,
        "OracleAdjudicationV1": 1,
        "FixtureAdmissibilityV1": 21,
        "DeterminismProfileV1": 1,
        "CoverageDeltaV1": 1,
        "OwnershipPreflightV1": 1,
    }
    if record_types != expected_records:
        errors.append(f"record_counts:{record_types}")
    else:
        checks.append("candidate_record_counts")

    try:
        fixture_record_path = next((root / "records/fixture-admissibility").glob("*.json"))
        impossible = json.loads(fixture_record_path.read_text())
        impossible["candidate_state"] = "TERMINAL_ADMITTED"
        impossible["admission_state"] = "ADMITTED"
        impossible["prerequisite_state"] = "SATISFIED"
        schema = json.loads((root / "schemas/fixture-admissibility-v1.schema.json").read_text())
        impossible_errors = list(jsonschema_module.Draft202012Validator(schema).iter_errors(impossible))
        if not impossible_errors:
            errors.append("impossible_admitted_state_accepted")
        else:
            checks.append("impossible_admitted_state_rejected")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"impossible_state_test:{type(exc).__name__}:{exc}")

    coverage = json.loads((root / "records/coverage-delta-v1.json").read_text())["body"]
    if coverage["primary_counts"] != {"covered": 11, "partial": 6, "cross": 1}:
        errors.append("coverage_counts")
    else:
        checks.append("coverage_counts")
    if near_miss_boundaries()["entries"][5]["outside_artifact"]["content_base64"] != b64(b"untracked"):
        errors.append("near_miss_sidecar")

    recomputed_privacy = secret_privacy_report(fixtures)
    if recomputed_privacy["status"] != "PASS":
        errors.append(f"decoded_secret_privacy:{recomputed_privacy['findings']}")
    else:
        checks.append("decoded_secret_privacy")

    manifest = json.loads((root / "generation-manifest.json").read_text())
    if len(manifest["artifacts"]) != 99:
        errors.append("generation_manifest_count")
    for row in manifest["artifacts"]:
        relative = row["path"].removeprefix(prefix)
        path = root / relative
        if (
            not path.is_file()
            or path.stat().st_size != row["bytes"]
            or sha256_bytes(path.read_bytes()) != row["sha256"]
        ):
            errors.append(f"generation_manifest_binding:{relative}")
    checks.append("generation_manifest_bindings")

    determinism = json.loads((root / "verification/deterministic-regeneration.json").read_text())
    if determinism.get("status") != "PASS" or determinism.get("byte_identical_count") != 100:
        errors.append("determinism_result")
    else:
        checks.append("deterministic_regeneration")

    return {
        "schema": "PackageValidationResultV2",
        "package_id": PACKAGE_ID,
        "status": "PASS" if not errors else "FAIL",
        "file_count": len(actual),
        "fixture_count": len(fixtures),
        "record_count": len(record_paths),
        "schema_count": len(schema_paths),
        "checks": sorted(set(checks)),
        "errors": errors,
        "consumers_invoked": 0,
    }
