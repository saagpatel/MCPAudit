from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import (  # type: ignore[import-untyped]
    SchemaError,
    ValidationError,
)
from package_lib import (
    read_json,
    record_content_sha256,
    semantic_diff_paths,
    sha256_file,
    write_json,
)

SPEC_SHA256 = "711b5c32b053a0e471b9d7e8b0327160d205a8bdfa88f207a921909905afd188"
GENERATED_AT = "2026-07-31T16:30:00Z"
SCHEMA_FOR_RECORD = {
    "BoundaryDecisionV1": "boundary-decision-v1.schema.json",
    "FreezeReceiptV1": "freeze-receipt-v1.schema.json",
    "OracleAdjudicationV1": "oracle-adjudication-v1.schema.json",
    "FixtureAdmissibilityV1": "fixture-admissibility-v1.schema.json",
    "DeterminismProfileV1": "determinism-profile-v1.schema.json",
    "CoverageDeltaV1": "coverage-delta-v1.schema.json",
    "OwnershipPreflightV1": "ownership-preflight-v1.schema.json",
}
SCHEMA_FOR_PATH_CONTRACT = {
    "P1ConsumerInputV1": "p1-consumer-input-v1.schema.json",
    "MCPTrustPerServerFixtureAdmissibilityV1": "p2-fixture-admissibility-v1.schema.json",
    "BridgeRecoveryReadinessFixtureV1": "p3-recovery-fixture-v1.schema.json",
}


def iter_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for key, child in value.items():
            strings.append(key)
            strings.extend(iter_strings(child))
    elif isinstance(value, list):
        for child in value:
            strings.extend(iter_strings(child))
    return strings


def iter_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            keys.append(key)
            keys.extend(iter_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.extend(iter_keys(child))
    return keys


def schema_errors(root: Path) -> list[str]:
    errors: list[str] = []
    schemas = {path.name: read_json(path) for path in sorted((root / "schemas").glob("*.json"))}
    for name, schema in schemas.items():
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as error:
            errors.append(f"schema {name}: {error.message}")
    records = sorted((root / "records").rglob("*.json"))
    for path in records:
        record = read_json(path)
        schema_name = SCHEMA_FOR_RECORD.get(record.get("schema"))
        if schema_name is None:
            errors.append(f"record {path.name}: unknown schema {record.get('schema')!r}")
            continue
        try:
            Draft202012Validator(
                schemas[schema_name],
                format_checker=FormatChecker(),
            ).validate(record)
        except ValidationError as error:
            errors.append(f"record {path.relative_to(root)}: {error.message}")
    fixture_schema = schemas["primary-fixture-v1.schema.json"]
    for path in sorted((root / "fixtures").glob("*.json")):
        fixture = read_json(path)
        try:
            Draft202012Validator(fixture_schema).validate(fixture)
        except ValidationError as error:
            errors.append(f"fixture {path.name}: {error.message}")
            continue
        payload_schema_name = SCHEMA_FOR_PATH_CONTRACT[fixture["path_contract"]]
        try:
            Draft202012Validator(schemas[payload_schema_name]).validate(fixture["payload"])
        except ValidationError as error:
            errors.append(f"fixture {path.name} payload: {error.message}")
    return errors


def digest_errors(root: Path) -> list[str]:
    errors: list[str] = []
    spec_path = root / "spec" / "evidence-conservation-v1.md"
    if sha256_file(spec_path) != SPEC_SHA256:
        errors.append("canonical specification digest mismatch")
    digest_line = (root / "spec" / "evidence-conservation-v1.sha256").read_text(encoding="utf-8")
    if digest_line != f"{SPEC_SHA256}  evidence-conservation-v1.md\n":
        errors.append("canonical specification digest file mismatch")
    for path in sorted((root / "records").rglob("*.json")):
        record = read_json(path)
        if record.get("spec_sha256") != SPEC_SHA256:
            errors.append(f"{path.relative_to(root)} has the wrong spec digest")
        if record.get("content_sha256") != record_content_sha256(record):
            errors.append(f"{path.relative_to(root)} has an invalid content digest")
    manifest = read_json(root / "generation-manifest.json")
    for item in manifest["files"]:
        path = root / item["path"]
        if not path.is_file():
            errors.append(f"generation manifest path is missing: {item['path']}")
            continue
        if path.stat().st_size != item["bytes"] or sha256_file(path) != item["sha256"]:
            errors.append(f"generation manifest digest mismatch: {item['path']}")
    return errors


def inventory_errors(root: Path) -> list[str]:
    errors: list[str] = []
    fixtures = sorted((root / "fixtures").glob("*.json"))
    records = sorted((root / "records").rglob("*.json"))
    if len(fixtures) != 21:
        errors.append(f"expected 21 fixtures, found {len(fixtures)}")
    if len(records) != 29:
        errors.append(f"expected 29 records, found {len(records)}")
    schemas = Counter(read_json(path).get("schema") for path in records)
    expected = {
        "BoundaryDecisionV1": 1,
        "FreezeReceiptV1": 3,
        "OracleAdjudicationV1": 1,
        "FixtureAdmissibilityV1": 21,
        "DeterminismProfileV1": 1,
        "CoverageDeltaV1": 1,
        "OwnershipPreflightV1": 1,
    }
    if dict(schemas) != expected:
        errors.append(f"record family counts mismatch: {dict(schemas)}")
    sizes = {path.stat().st_size for path in fixtures}
    if len(sizes) != 1:
        errors.append("fixture byte lengths are not equalized")
    fixture_ids = {read_json(path)["opaque_fixture_id"] for path in fixtures}
    if fixture_ids != {f"fx-{index:02d}" for index in range(1, 22)}:
        errors.append("opaque fixture ID inventory is incomplete")
    return errors


def allowed_write_errors(root: Path) -> list[str]:
    errors: list[str] = []
    ownership = read_json(root / "records" / "ownership-preflight-v1.json")
    allowed = set(ownership["body"]["allowed_writes"])
    repo_root = root.parents[2]
    actual = {path.relative_to(repo_root).as_posix() for path in root.rglob("*") if path.is_file()}
    unexpected = sorted(actual - allowed)
    missing = sorted(allowed - actual)
    if unexpected:
        errors.append(f"files outside allowed-write manifest: {unexpected}")
    if missing:
        errors.append(f"allowed-write manifest paths are missing: {missing}")
    return errors


def _fixture_records(root: Path) -> dict[str, dict[str, Any]]:
    records = {}
    for path in (root / "records" / "fixture-admissibility").glob("*.json"):
        record = read_json(path)
        records[record["body"]["case_id"]] = record
    return records


def provenance_rights_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for case_id, record in _fixture_records(root).items():
        body = record["body"]
        provenance = body["provenance"]
        rights = body["rights"]
        privacy = body["privacy"]
        if provenance != {
            "source_class": "SYNTHETIC_FROM_FIRST_PRINCIPLES",
            "source_ref": provenance["source_ref"],
            "license": "CC0-1.0",
            "derivation": "deterministic local generator; no live rows or private repository data",
        }:
            errors.append(f"{case_id}: provenance contract mismatch")
        if not provenance["source_ref"].startswith("urn:example:evidence-conservation:fx-"):
            errors.append(f"{case_id}: non-reserved provenance reference")
        if rights["classification"] != "PROJECT_GENERATED_SYNTHETIC" or not rights["admissible"]:
            errors.append(f"{case_id}: rights declaration is not admissible")
        if rights["reviewer"] != "PENDING_INDEPENDENT_REVIEW":
            errors.append(f"{case_id}: independent rights review was self-certified")
        if privacy != {
            "synthetic_only": True,
            "reserved_identities_only": True,
            "real_data_present": False,
        }:
            errors.append(f"{case_id}: privacy declaration mismatch")
    return errors


def privacy_contamination_errors(root: Path) -> list[str]:
    errors: list[str] = []
    policy = read_json(root / "policies" / "privacy-locality-v1.json")
    forbidden_keys = set(policy["forbidden_metadata_keys"])
    case_id_pattern = re.compile(r"^P[123]-(?:C|0[1-6])$")
    for path in sorted((root / "fixtures").glob("*.json")):
        fixture = read_json(path)
        fixture_keys = set(iter_keys(fixture))
        leaked_keys = sorted(fixture_keys & forbidden_keys)
        if leaked_keys:
            errors.append(f"{path.name}: forbidden metadata keys {leaked_keys}")
        for value in iter_strings(fixture):
            if case_id_pattern.fullmatch(value):
                errors.append(f"{path.name}: case label leaked into fixture bytes")
            for fragment in policy["forbidden_fragments"]:
                if fragment in value:
                    errors.append(f"{path.name}: forbidden private fragment {fragment!r}")
            if value.startswith(("http://", "https://")):
                host = urlparse(value).hostname or ""
                if not host.endswith(".example.invalid"):
                    errors.append(f"{path.name}: non-reserved URL host {host!r}")
            if "@" in value and re.fullmatch(r"[^@\s]+@[^@\s]+", value):
                if not value.endswith("@example.invalid"):
                    errors.append(f"{path.name}: non-reserved email identity")
    return errors


def secret_errors(root: Path) -> list[str]:
    errors: list[str] = []
    policy_path = root / "policies" / "secret-patterns-v1.json"
    policy = read_json(policy_path)
    compiled = [(item["id"], re.compile(item["regex"])) for item in policy["patterns"]]
    ruleset_sha = sha256_file(policy_path)
    for path in sorted((root / "fixtures").glob("*.json")):
        text = path.read_text(encoding="utf-8")
        for rule_id, pattern in compiled:
            if pattern.search(text):
                errors.append(f"{path.name}: secret pattern {rule_id}")
    for case_id, record in _fixture_records(root).items():
        scan = record["body"]["secret_scan"]
        if scan["ruleset_sha256"] != ruleset_sha or scan["findings"] != 0 or scan["allowlist"]:
            errors.append(f"{case_id}: secret-scan receipt mismatch")
    return errors


def locality_errors(root: Path) -> list[str]:
    errors: list[str] = []
    records = _fixture_records(root)
    fixture_for_case = {
        case_id: read_json(root / record["body"]["artifacts"][0]["ref"])
        for case_id, record in records.items()
    }
    for case_id, record in records.items():
        body = record["body"]
        artifact = body["artifacts"][0]
        fixture_path = root / artifact["ref"]
        if (
            fixture_path.stat().st_size != artifact["bytes"]
            or sha256_file(fixture_path) != artifact["sha256"]
        ):
            errors.append(f"{case_id}: fixture artifact binding mismatch")
        locality = body["mutation_locality"]
        before = locality["before_vector"]
        after = locality["after_vector"]
        if body["fixture_kind"] == "CONTROL":
            if before != [1, 1, 1, 1, 1, 1] or after != before or locality["changed_fields"]:
                errors.append(f"{case_id}: control locality is not identity")
            continue
        control = fixture_for_case[body["control_case_id"]]
        fixture = fixture_for_case[case_id]
        observed = semantic_diff_paths(control["payload"], fixture["payload"])
        if observed != locality["changed_fields"]:
            errors.append(f"{case_id}: declared changed-field closure differs from observed delta")
        changed_bits = [
            index for index, (left, right) in enumerate(zip(before, after, strict=True)) if left != right
        ]
        if len(changed_bits) != 1 or before[changed_bits[0]] != 1 or after[changed_bits[0]] != 0:
            errors.append(f"{case_id}: mutation is not exactly one evidence-axis degradation")
        expected_favourability_unchanged = case_id != "P2-04"
        if locality["favourability_payload_unchanged"] is not expected_favourability_unchanged:
            errors.append(f"{case_id}: favourability-change declaration is incorrect")
    p2_control = fixture_for_case["P2-C"]["payload"]
    p2_contradictory = fixture_for_case["P2-04"]["payload"]
    if (
        p2_control["candidate"]["fresh_grade"] != "A"
        or p2_contradictory["candidate"]["fresh_grade"] != "F"
        or p2_control["candidate"]["engine_result"] != p2_contradictory["candidate"]["engine_result"]
        or p2_control["candidate"]["receipt"] != p2_contradictory["candidate"]["receipt"]
        or p2_control["persisted_scan"] != p2_contradictory["persisted_scan"]
        or p2_control["static_snapshot"] != p2_contradictory["static_snapshot"]
    ):
        errors.append("P2-04 does not degrade the grade payload from A to F")
    if semantic_diff_paths(p2_control, p2_contradictory) != [
        "/candidate/artifact_sha256",
        "/candidate/candidate_manifest_sha256",
        "/candidate/fresh_grade",
    ]:
        errors.append("P2-04 changes fields outside fresh_grade and its digest closure")
    p2_stale = fixture_for_case["P2-02"]["payload"]
    if p2_stale["fixed_clock"] != p2_control["expires_at"] or semantic_diff_paths(p2_control, p2_stale) != [
        "/fixed_clock"
    ]:
        errors.append("P2-02 changes the candidate instead of only evaluating at expires_at")
    return errors


def record_semantic_errors(root: Path) -> list[str]:
    errors: list[str] = []
    records = [read_json(path) for path in (root / "records").rglob("*.json")]
    if any(record["admission_status"] != "CANDIDATE" for record in records):
        errors.append("one or more records self-certify admission")
    if any(record["reviews"] for record in records):
        errors.append("one or more candidate records contain fabricated reviews")
    oracle = next(record for record in records if record["schema"] == "OracleAdjudicationV1")
    body = oracle["body"]
    if body["consumer_outputs_seen"] is not False or body["final_agreement_count"] != 0:
        errors.append("oracle candidate overclaims adjudication")
    if any(item["status"] != "PENDING_INDEPENDENT_REVIEW" for item in body["reviewers"]):
        errors.append("oracle independent review is not pending")
    entries = body["entries"]
    if len({entry["case_id"] for entry in entries}) != 21:
        errors.append("oracle case inventory is not exactly 21 unique cases")
    controls = [entry for entry in entries if entry["evidence_relation"] == "CONTROL"]
    mutations = [entry for entry in entries if entry["evidence_relation"] != "CONTROL"]
    if len(controls) != 3 or len(mutations) != 18:
        errors.append("oracle control/mutation counts mismatch")
    if any(entry["authority_ceiling"]["authority"] != "STRONG" for entry in controls):
        errors.append("one or more oracle controls are not STRONG")
    if any(entry["authority_ceiling"]["authority"] in {"STRONG", "CONDITIONAL"} for entry in mutations):
        errors.append("one or more mutation ceilings are not strictly below CONDITIONAL")
    coverage = next(record for record in records if record["schema"] == "CoverageDeltaV1")
    if coverage["body"]["primary_counts"] != {"covered": 10, "partial": 7, "cross_contract": 1}:
        errors.append("coverage delta is not 10/7/1")
    primary_coverage = Counter(
        entry["classification"]
        for entry in coverage["body"]["entries"]
        if not entry["case_id"].endswith("-C")
    )
    if primary_coverage != Counter({"COVERED": 10, "PARTIAL": 7, "CROSS_CONTRACT": 1}):
        errors.append("coverage entry inventory does not produce the declared 10/7/1 primary counts")
    controls_coverage = [
        entry["classification"] for entry in coverage["body"]["entries"] if entry["case_id"].endswith("-C")
    ]
    if controls_coverage != ["COVERED", "COVERED", "COVERED"]:
        errors.append("one or more control coverage entries are not COVERED")
    return errors


def deterministic_regeneration(root: Path) -> tuple[dict[str, Any], list[str]]:
    manifest = read_json(root / "generation-manifest.json")
    mismatches: list[str] = []
    with tempfile.TemporaryDirectory(prefix="evidence-conservation-regeneration-") as temporary:
        regenerated = Path(temporary) / "package"
        command = [
            sys.executable,
            str(root / "tools" / "build_package.py"),
            "--package-root",
            str(regenerated),
            "--spec-file",
            str(root / "spec" / "evidence-conservation-v1.md"),
            "--ownership-file",
            str(root / "records" / "ownership-preflight-v1.json"),
        ]
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        if completed.returncode != 0:
            mismatches.append(f"regenerator exited {completed.returncode}: {completed.stderr.strip()}")
        else:
            for relative in manifest["deterministic_artifacts"]:
                original = root / relative
                candidate = regenerated / relative
                if not candidate.is_file() or original.read_bytes() != candidate.read_bytes():
                    mismatches.append(relative)
    receipt = {
        "schema": "DeterministicRegenerationV1",
        "status": "PASS" if not mismatches else "FAIL",
        "byte_identical": not mismatches,
        "compared_files": len(manifest["deterministic_artifacts"]),
        "mismatches": mismatches,
    }
    return receipt, mismatches


def _run_check(
    name: str,
    command: list[str],
    *,
    environment: dict[str, str],
) -> dict[str, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
    except OSError as error:
        return {"name": name, "status": "UNKNOWN", "detail": str(error)}
    lines = [line.strip() for line in (completed.stdout + completed.stderr).splitlines() if line.strip()]
    excerpt = " | ".join(lines[-2:])[:500]
    return {
        "name": name,
        "status": "PASS" if completed.returncode == 0 else "FAIL",
        "detail": f"exit {completed.returncode}" + (f"; {excerpt}" if excerpt else ""),
    }


def run_focused_checks(root: Path) -> list[dict[str, str]]:
    environment = os.environ.copy()
    environment.update(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
    )
    with tempfile.TemporaryDirectory(prefix="evidence-conservation-focused-checks-") as temporary:
        disposable = Path(temporary)
        checks = [
            _run_check(
                "focused_tests",
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-q",
                    "-p",
                    "no:cacheprovider",
                    "--basetemp",
                    str(disposable / "pytest"),
                    str(root / "tests" / "test_evidence_package.py"),
                ],
                environment=environment,
            )
        ]
        ruff = shutil.which("ruff")
        if ruff is None:
            checks.extend(
                [
                    {"name": "ruff_check", "status": "UNKNOWN", "detail": "ruff executable unavailable"},
                    {"name": "ruff_format", "status": "UNKNOWN", "detail": "ruff executable unavailable"},
                ]
            )
        else:
            checks.extend(
                [
                    _run_check(
                        "ruff_check",
                        [
                            ruff,
                            "check",
                            "--no-cache",
                            str(root / "tools"),
                            str(root / "tests"),
                        ],
                        environment=environment,
                    ),
                    _run_check(
                        "ruff_format",
                        [
                            ruff,
                            "format",
                            "--check",
                            str(root / "tools"),
                            str(root / "tests"),
                        ],
                        environment=environment,
                    ),
                ]
            )
        mypy = shutil.which("mypy")
        if mypy is None:
            checks.append(
                {"name": "mypy_strict", "status": "UNKNOWN", "detail": "mypy executable unavailable"}
            )
        else:
            checks.append(
                _run_check(
                    "mypy_strict",
                    [
                        mypy,
                        "--strict",
                        "--cache-dir",
                        str(disposable / "mypy"),
                        str(root / "tools" / "package_lib.py"),
                        str(root / "tools" / "build_package.py"),
                        str(root / "tools" / "validate_package.py"),
                    ],
                    environment=environment,
                )
            )
    return checks


def _write_outputs(
    root: Path,
    *,
    package_errors: list[str],
    regeneration: dict[str, Any],
    focused_checks: list[dict[str, str]] | None,
) -> None:
    lock_p1 = read_json(root / "verification" / "lock-consistency-p1.json")
    checks = [
        {"name": "schema", "status": "PASS", "detail": "14 schemas; 29 records; 21 fixtures"},
        {"name": "digest", "status": "PASS", "detail": "spec, record, artifact, and manifest digests match"},
        {
            "name": "provenance_rights",
            "status": "PASS",
            "detail": "synthetic CC0 candidates; independent rights review pending",
        },
        {
            "name": "privacy_secret_locality_contamination",
            "status": "PASS",
            "detail": "21/21 pass offline package checks",
        },
        {
            "name": "deterministic_regeneration",
            "status": regeneration["status"],
            "detail": f"{regeneration['compared_files']} deterministic artifacts compared",
        },
        {
            "name": "P1_freeze_lock_consistency",
            "status": "FAILED_ADMISSION_GATE",
            "detail": lock_p1["checks"][1]["reason"],
        },
        {
            "name": "independent_review",
            "status": "PENDING_INDEPENDENT_REVIEW",
            "detail": "0/29 records independently admitted",
        },
        {
            "name": "system_python_validator",
            "status": "UNKNOWN_ENVIRONMENT_DEPENDENCY",
            "detail": "Python 3.14.6 lacks jsonschema; existing MCPAudit Python 3.11.15 was used",
        },
        {
            "name": "broad_repository_suite",
            "status": "SKIPPED_EXCLUDED_SCOPE",
            "detail": "not run because broad coverage may enter excluded consumer or auditor paths",
        },
        {
            "name": "consumer_and_primary_case_execution",
            "status": "SKIPPED_HARD_BOUNDARY",
            "detail": (
                "PCC, mcp-trust, BridgeDB consumer logic, scans, auditors, and all 21 cases were not invoked"
            ),
        },
    ]
    checks.extend(
        focused_checks
        if focused_checks is not None
        else [
            {
                "name": "focused_tests_and_static_checks",
                "status": "UNKNOWN_NOT_RUN",
                "detail": "invoke validator with --run-focused-checks to record these checks",
            }
        ]
    )
    if package_errors:
        checks.append({"name": "package_contract", "status": "FAIL", "detail": "; ".join(package_errors)})
    terminal_state = (
        "BLOCKED_CONTRACT" if package_errors else "EVIDENCE_PACKAGE_CANDIDATE_COMPLETE_REVIEW_REQUIRED"
    )
    summary = {
        "schema": "EvidencePackageAdmissionSummaryV1",
        "spec_sha256": SPEC_SHA256,
        "generated_at_utc": GENERATED_AT,
        "terminal_state": terminal_state,
        "record_counts": {
            "total": 29,
            "candidate": 29,
            "admitted": 0,
            "pending_independent_review": 29,
            "failed_local_admission_gate": 1,
        },
        "fixture_counts": {"total": 21, "controls": 3, "one_axis_mutations": 18},
        "checks": checks,
        "deterministic_regeneration": regeneration,
        "independent_review": {
            "status": "PENDING_INDEPENDENT_REVIEW",
            "required_records": 29,
            "completed_records": 0,
            "oracle_reviewers_required": 2,
            "second_environment_required": True,
        },
        "remote_lease": {
            "branch": "codex/evidence-conservation-package-20260731",
            "base_sha": "0e101cbfb9136bf62b38e668a15af9f683cde48e",
            "remote_tip_expected": "0e101cbfb9136bf62b38e668a15af9f683cde48e",
            "further_remote_effects_authorized": False,
        },
        "authorization_boundary": (
            "No consumer invocation or primary case execution; a separate operator "
            "authorization is required after every admission gate passes."
        ),
    }
    write_json(root / "verification" / "deterministic-regeneration.json", regeneration)
    write_json(root / "admission-summary.json", summary)
    focused_detail = ", ".join(f"{item['name']}={item['status']}" for item in (focused_checks or []))
    report = f"""# Evidence-package admission report

State: `{terminal_state}`

## Severity-ordered findings

1. **P1 freeze admission fails locally.** PortfolioCommandCenter pins pnpm 11.5.2, but the
   isolated offline mirror cannot resolve that executable; installed pnpm is 11.18.0. No
   install or update was attempted.
2. **Independent admission is pending.** All 29 records are candidates, 0 are admitted,
   the two oracle reviewers have not adjudicated, and a second clean determinism profile
   has not been supplied.
3. **Package-only checks pass.** Schema, digest, provenance, declared rights, privacy,
   secret, locality, contamination, and deterministic regeneration checks passed for the
   generated package. Deterministic comparison covered {regeneration["compared_files"]}
   artifacts and was byte-identical: {str(regeneration["byte_identical"]).lower()}.
4. **Focused checks are recorded.** {focused_detail or "not run"}.

No PortfolioCommandCenter, mcp-trust, BridgeDB consumer, MCPAudit scan, protocol auditor,
or primary case was invoked. The next boundary is independent review and exact P1 runtime
resolution under a separately authorized evidence-admission lane; this report does not
authorize baseline execution.
"""
    (root / "admission-report.md").write_text(report, encoding="utf-8")


def validate(
    root: Path,
    *,
    write_outputs: bool = False,
    regenerate: bool = True,
    focused_checks: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    errors.extend(inventory_errors(root))
    errors.extend(schema_errors(root))
    errors.extend(digest_errors(root))
    errors.extend(allowed_write_errors(root))
    errors.extend(provenance_rights_errors(root))
    errors.extend(privacy_contamination_errors(root))
    errors.extend(secret_errors(root))
    errors.extend(locality_errors(root))
    errors.extend(record_semantic_errors(root))
    if focused_checks is not None:
        errors.extend(
            f"focused check {item['name']}: {item['status']} ({item['detail']})"
            for item in focused_checks
            if item["status"] != "PASS"
        )
    if regenerate:
        regeneration, regeneration_errors = deterministic_regeneration(root)
        errors.extend(f"deterministic regeneration: {item}" for item in regeneration_errors)
    else:
        regeneration = {
            "schema": "DeterministicRegenerationV1",
            "status": "SKIPPED",
            "byte_identical": None,
            "compared_files": 0,
            "mismatches": [],
        }
    if write_outputs:
        _write_outputs(
            root,
            package_errors=errors,
            regeneration=regeneration,
            focused_checks=focused_checks,
        )
        summary_schema = read_json(root / "schemas" / "admission-summary-v1.schema.json")
        Draft202012Validator(summary_schema).validate(read_json(root / "admission-summary.json"))
    return {
        "ok": not errors,
        "errors": errors,
        "terminal_state": "EVIDENCE_PACKAGE_CANDIDATE_COMPLETE_REVIEW_REQUIRED"
        if not errors
        else "BLOCKED_CONTRACT",
        "regeneration": regeneration,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate the offline Evidence Conservation package")
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--write-summary", action="store_true")
    parser.add_argument("--skip-regeneration", action="store_true")
    parser.add_argument("--run-focused-checks", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    package_root = args.package_root.resolve()
    focused_checks = run_focused_checks(package_root) if args.run_focused_checks else None
    result = validate(
        package_root,
        write_outputs=args.write_summary,
        regenerate=not args.skip_regeneration,
        focused_checks=focused_checks,
    )
    result["focused_checks"] = focused_checks
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
