#!/usr/bin/env python3
"""Validate bounded MCPAudit repository delivery evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

INPUT_SCHEMA: Final = "mcpaudit.delivery-evidence.v1"
OUTPUT_SCHEMA: Final = "mcpaudit.delivery-evidence-validation.v1"
MAX_INPUT_BYTES: Final = 1_048_576
BOUNDARIES: Final = (
    "source",
    "local",
    "ci",
    "runtime",
    "publication",
    "deployment",
    "adoption",
    "human_acceptance",
)
RFC3339_UTC: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")


class DeliveryEvidenceInputError(ValueError):
    """The input cannot be safely or structurally evaluated."""


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeliveryEvidenceInputError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise DeliveryEvidenceInputError(f"non-finite JSON number is unsupported: {value}")


def _read_file(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise DeliveryEvidenceInputError("input must be an accessible non-symlink file") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise DeliveryEvidenceInputError("input must be a regular non-symlink file")
    if metadata.st_size > MAX_INPUT_BYTES:
        raise DeliveryEvidenceInputError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DeliveryEvidenceInputError("input must be an accessible non-symlink file") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise DeliveryEvidenceInputError("input must be a regular file")
        if (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
            raise DeliveryEvidenceInputError("input identity changed before it was opened")
        if before.st_size > MAX_INPUT_BYTES:
            raise DeliveryEvidenceInputError(f"input exceeds {MAX_INPUT_BYTES} bytes")
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)

        def identity(value: os.stat_result) -> tuple[int, int, int, int]:
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)

        if identity(before) != identity(after):
            raise DeliveryEvidenceInputError("input changed during read")
        if len(raw) > MAX_INPUT_BYTES:
            raise DeliveryEvidenceInputError(f"input exceeds {MAX_INPUT_BYTES} bytes")
        return raw
    except OSError as exc:
        raise DeliveryEvidenceInputError("input could not be read safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _object(value: Any, field: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DeliveryEvidenceInputError(f"{field} must be an object")
    missing, unexpected = sorted(keys - set(value)), sorted(set(value) - keys)
    if missing or unexpected:
        raise DeliveryEvidenceInputError(
            f"{field} keys mismatch; missing={missing!r}; unexpected={unexpected!r}"
        )
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise DeliveryEvidenceInputError(f"{field} must be a non-empty bounded string")
    return value


def _digest(value: Any, field: str, *, sha256: bool = False) -> str:
    text = _text(value, field)
    prefix = "sha256:" if sha256 else ""
    size = 64 if sha256 else 40
    candidate = text[len(prefix) :] if text.startswith(prefix) else ""
    if not sha256:
        candidate = text
    if (sha256 and not text.startswith(prefix)) or len(candidate) != size:
        raise DeliveryEvidenceInputError(f"{field} has an invalid digest")
    if any(character not in "0123456789abcdef" for character in candidate):
        raise DeliveryEvidenceInputError(f"{field} must be lowercase hexadecimal")
    return text


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or RFC3339_UTC.fullmatch(value) is None:
        raise DeliveryEvidenceInputError(f"{field} must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise DeliveryEvidenceInputError(f"{field} must be an RFC 3339 UTC timestamp") from exc
    if parsed.tzinfo != UTC:
        raise DeliveryEvidenceInputError(f"{field} must use UTC")
    return parsed


def _status(value: Any, field: str) -> str:
    if not isinstance(value, str) or value not in {"PASS", "FAIL", "UNKNOWN"}:
        raise DeliveryEvidenceInputError(f"{field} must be PASS, FAIL, or UNKNOWN")
    return value


def _finding(code: str, severity: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message, "severity": severity}


def validate(document: Any) -> dict[str, Any]:
    root = _object(
        document,
        "document",
        {
            "schema_version",
            "artifact",
            "producer",
            "freshness",
            "repository_policy",
            "integration",
            "branch",
            "retention",
            "claims",
            "claim_ceiling",
        },
    )
    if root["schema_version"] != INPUT_SCHEMA:
        raise DeliveryEvidenceInputError(f"schema_version must be {INPUT_SCHEMA}")
    artifact = _object(
        root["artifact"],
        "artifact",
        {
            "repository",
            "revision",
            "source_sha256",
            "environment_required",
            "environment_sha256",
        },
    )
    repository = _text(artifact["repository"], "artifact.repository")
    revision = _digest(artifact["revision"], "artifact.revision")
    source = _digest(artifact["source_sha256"], "artifact.source_sha256", sha256=True)
    if not isinstance(artifact["environment_required"], bool):
        raise DeliveryEvidenceInputError("artifact.environment_required must be boolean")
    environment = artifact["environment_sha256"]
    if environment is not None:
        environment = _digest(environment, "artifact.environment_sha256", sha256=True)

    producer = _object(root["producer"], "producer", {"name", "produced_at"})
    _text(producer["name"], "producer.name")
    produced_at = _timestamp(producer["produced_at"], "producer.produced_at")
    freshness = _object(root["freshness"], "freshness", {"as_of", "current_state_max_age_seconds"})
    as_of = _timestamp(freshness["as_of"], "freshness.as_of")
    max_age = freshness["current_state_max_age_seconds"]
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 86_400:
        raise DeliveryEvidenceInputError("freshness.current_state_max_age_seconds must be 1..86400")
    if produced_at > as_of:
        raise DeliveryEvidenceInputError("producer.produced_at cannot be later than freshness.as_of")

    policy = _object(root["repository_policy"], "repository_policy", {"delete_branch_on_merge"})
    if not isinstance(policy["delete_branch_on_merge"], bool):
        raise DeliveryEvidenceInputError("repository_policy.delete_branch_on_merge must be boolean")
    integration = _object(
        root["integration"],
        "integration",
        {
            "protected_main",
            "pull_request",
            "review",
            "security",
            "ci",
        },
    )
    protected = _object(
        integration["protected_main"], "integration.protected_main", {"revision", "reachable"}
    )
    protected_revision = _digest(protected["revision"], "integration.protected_main.revision")
    if protected["reachable"] is not None and not isinstance(protected["reachable"], bool):
        raise DeliveryEvidenceInputError("integration.protected_main.reachable must be boolean or null")
    pull_request = _object(
        integration["pull_request"],
        "integration.pull_request",
        {
            "number",
            "state",
            "head_revision",
            "integration_revision",
        },
    )
    if (
        not isinstance(pull_request["number"], int)
        or isinstance(pull_request["number"], bool)
        or pull_request["number"] < 1
    ):
        raise DeliveryEvidenceInputError("integration.pull_request.number must be positive")
    if pull_request["state"] != "merged":
        raise DeliveryEvidenceInputError("integration.pull_request.state must be merged")
    head_revision = _digest(pull_request["head_revision"], "integration.pull_request.head_revision")
    merged_revision = _digest(
        pull_request["integration_revision"], "integration.pull_request.integration_revision"
    )
    review = _object(
        integration["review"], "integration.review", {"revision", "status", "unresolved_threads"}
    )
    review_revision = _digest(review["revision"], "integration.review.revision")
    review_status = _status(review["status"], "integration.review.status")
    if (
        not isinstance(review["unresolved_threads"], int)
        or isinstance(review["unresolved_threads"], bool)
        or review["unresolved_threads"] < 0
    ):
        raise DeliveryEvidenceInputError("integration.review.unresolved_threads must be non-negative")
    security = _object(
        integration["security"], "integration.security", {"revision", "source_sha256", "status"}
    )
    security_revision = _digest(security["revision"], "integration.security.revision")
    security_source = _digest(security["source_sha256"], "integration.security.source_sha256", sha256=True)
    security_status = _status(security["status"], "integration.security.status")

    findings: list[dict[str, str]] = []
    if any(
        item != revision
        for item in (protected_revision, head_revision, merged_revision, review_revision, security_revision)
    ):
        findings.append(_finding("MCPDELIVERY002", "FAIL", "immutable receipt revision differs from target"))
    if security_source != source:
        findings.append(
            _finding("MCPDELIVERY003", "FAIL", "security receipt source digest differs from target")
        )
    if protected["reachable"] is False:
        findings.append(_finding("MCPDELIVERY004", "FAIL", "target is not reachable from protected main"))
    elif protected["reachable"] is None:
        findings.append(_finding("MCPDELIVERY004", "UNKNOWN", "protected-main reachability is unknown"))
    if review_status == "FAIL" or review["unresolved_threads"]:
        findings.append(_finding("MCPDELIVERY005", "FAIL", "review evidence is not clean"))
    elif review_status == "UNKNOWN":
        findings.append(_finding("MCPDELIVERY005", "UNKNOWN", "review evidence is unknown"))
    if security_status != "PASS":
        findings.append(
            _finding("MCPDELIVERY006", security_status, f"security evidence is {security_status.lower()}")
        )

    ci_items = integration["ci"]
    if not isinstance(ci_items, list) or not 1 <= len(ci_items) <= 64:
        raise DeliveryEvidenceInputError("integration.ci must contain 1..64 receipts")
    seen_ci: set[str] = set()
    ci_evidence_proven = True
    for index, raw_ci in enumerate(ci_items):
        ci = _object(raw_ci, f"integration.ci[{index}]", {"name", "revision", "status", "environment_sha256"})
        name = _text(ci["name"], f"integration.ci[{index}].name")
        if name in seen_ci:
            raise DeliveryEvidenceInputError("integration.ci names must be unique")
        seen_ci.add(name)
        ci_revision = _digest(ci["revision"], f"integration.ci[{index}].revision")
        ci_status = _status(ci["status"], f"integration.ci[{index}].status")
        ci_environment = ci["environment_sha256"]
        if ci_environment is not None:
            ci_environment = _digest(
                ci_environment, f"integration.ci[{index}].environment_sha256", sha256=True
            )
        if ci_revision != revision:
            ci_evidence_proven = False
            findings.append(
                _finding("MCPDELIVERY002", "FAIL", f"CI receipt {name} revision differs from target")
            )
        if ci_status != "PASS":
            ci_evidence_proven = False
            findings.append(
                _finding("MCPDELIVERY007", ci_status, f"CI receipt {name} is {ci_status.lower()}")
            )
        if environment is not None and ci_environment is not None and ci_environment != environment:
            ci_evidence_proven = False
            findings.append(
                _finding("MCPDELIVERY008", "FAIL", f"CI receipt {name} environment differs from target")
            )
        elif artifact["environment_required"] and ci_environment != environment:
            ci_evidence_proven = False
            findings.append(
                _finding("MCPDELIVERY008", "UNKNOWN", f"CI receipt {name} lacks exact environment binding")
            )
    if artifact["environment_required"] and environment is None:
        ci_evidence_proven = False
        findings.append(
            _finding("MCPDELIVERY008", "UNKNOWN", "required target environment binding is missing")
        )

    branch = _object(root["branch"], "branch", {"evidence_class", "ref", "state", "observed_at", "revision"})
    if branch["evidence_class"] != "mutable_convenience":
        raise DeliveryEvidenceInputError("branch.evidence_class must be mutable_convenience")
    _text(branch["ref"], "branch.ref")
    if branch["state"] not in {"present", "absent", "unknown"}:
        raise DeliveryEvidenceInputError("branch.state must be present, absent, or unknown")
    branch_observed = _timestamp(branch["observed_at"], "branch.observed_at")
    branch_revision = branch["revision"]
    if branch["state"] == "present":
        branch_revision = _digest(branch_revision, "branch.revision")
        if branch_revision != revision:
            findings.append(_finding("MCPDELIVERY001", "FAIL", "live branch revision differs from target"))
    elif branch_revision is not None:
        raise DeliveryEvidenceInputError("branch.revision must be null unless branch.state is present")
    if branch["state"] == "unknown":
        findings.append(_finding("MCPDELIVERY014", "UNKNOWN", "live branch state is unknown"))
    if branch_observed > as_of or (as_of - branch_observed).total_seconds() > max_age:
        findings.append(
            _finding("MCPDELIVERY009", "FAIL", "current branch observation is stale or future-dated")
        )

    retention = _object(
        root["retention"],
        "retention",
        {
            "required",
            "reason",
            "consumer",
            "lifecycle",
            "mutation_authority",
            "deletion_policy",
            "exception_path",
        },
    )
    if not isinstance(retention["required"], bool):
        raise DeliveryEvidenceInputError("retention.required must be boolean")
    exception = retention["exception_path"]
    if exception not in {"none", "repository_setting_exception", "bounded_post_merge_restoration"}:
        raise DeliveryEvidenceInputError("retention.exception_path is unsupported")
    details = ("reason", "consumer", "lifecycle", "mutation_authority", "deletion_policy")
    if retention["required"]:
        for key in details:
            _text(retention[key], f"retention.{key}")
        if policy["delete_branch_on_merge"] and exception == "none":
            findings.append(
                _finding("MCPDELIVERY010", "FAIL", "retention contradicts automatic post-merge deletion")
            )
        if branch["state"] != "present" or branch_revision != revision:
            findings.append(
                _finding(
                    "MCPDELIVERY011", "UNKNOWN", "retention completion requires fresh exact live-ref readback"
                )
            )
    elif any(retention[key] is not None for key in details) or exception != "none":
        raise DeliveryEvidenceInputError("optional retention must use null details and exception_path none")

    claims = root["claims"]
    if not isinstance(claims, list) or not 1 <= len(claims) <= len(BOUNDARIES):
        raise DeliveryEvidenceInputError("claims must contain 1..8 entries")
    seen_boundaries: set[str] = set()
    claim_statuses: dict[str, str] = {}
    for index, raw_claim in enumerate(claims):
        claim = _object(
            raw_claim,
            f"claims[{index}]",
            {
                "boundary",
                "status",
                "evidence_boundaries",
                "current_state",
                "observed_at",
            },
        )
        boundary = claim["boundary"]
        if boundary not in BOUNDARIES or boundary in seen_boundaries:
            raise DeliveryEvidenceInputError("claim boundaries must be supported and unique")
        seen_boundaries.add(boundary)
        claim_status = _status(claim["status"], f"claims[{index}].status")
        claim_statuses[boundary] = claim_status
        supports = claim["evidence_boundaries"]
        if not isinstance(supports, list) or not supports or any(item not in BOUNDARIES for item in supports):
            raise DeliveryEvidenceInputError("claim evidence_boundaries must be non-empty and supported")
        if claim_status == "PASS" and boundary not in supports:
            findings.append(
                _finding(
                    "MCPDELIVERY012",
                    "FAIL",
                    f"{boundary} passing claim lacks evidence from its own boundary",
                )
            )
        if not isinstance(claim["current_state"], bool):
            raise DeliveryEvidenceInputError("claim.current_state must be boolean")
        observed_at = claim["observed_at"]
        if claim["current_state"]:
            observed = _timestamp(observed_at, f"claims[{index}].observed_at")
            if observed > as_of or (as_of - observed).total_seconds() > max_age:
                findings.append(
                    _finding("MCPDELIVERY009", "FAIL", f"current {boundary} claim is stale or future-dated")
                )
        elif observed_at is not None:
            observed = _timestamp(observed_at, f"claims[{index}].observed_at")
            if observed > as_of:
                findings.append(
                    _finding("MCPDELIVERY009", "FAIL", f"historical {boundary} claim is future-dated")
                )

    claim_ceiling = _object(
        root["claim_ceiling"],
        "claim_ceiling",
        {"proven_boundaries", "unproven_boundaries", "statement"},
    )
    declared_proven = [boundary for boundary in BOUNDARIES if claim_statuses.get(boundary) == "PASS"]
    declared_unproven = [boundary for boundary in BOUNDARIES if boundary not in declared_proven]
    if claim_ceiling["proven_boundaries"] != declared_proven:
        findings.append(
            _finding("MCPDELIVERY013", "FAIL", "claim ceiling proven boundaries differ from claims")
        )
    if claim_ceiling["unproven_boundaries"] != declared_unproven:
        findings.append(
            _finding("MCPDELIVERY013", "FAIL", "claim ceiling unproven boundaries differ from claims")
        )
    effective_proven = [
        boundary
        for boundary in BOUNDARIES
        if claim_statuses.get(boundary) == "PASS" and (boundary != "ci" or ci_evidence_proven)
    ]
    effective_unproven = [boundary for boundary in BOUNDARIES if boundary not in effective_proven]
    statement = _text(claim_ceiling["statement"], "claim_ceiling.statement")
    effective_claim_ceiling = {
        "proven_boundaries": effective_proven,
        "unproven_boundaries": effective_unproven,
        "statement": statement,
    }
    findings.sort(key=lambda item: (item["code"], item["severity"], item["message"]))
    severities = {item["severity"] for item in findings}
    verdict = "FAIL" if "FAIL" in severities else "UNKNOWN" if "UNKNOWN" in severities else "PASS"
    return {
        "schema_version": OUTPUT_SCHEMA,
        "verdict": verdict,
        "artifact": {"repository": repository, "revision": revision, "source_sha256": source},
        "claim_ceiling": effective_claim_ceiling,
        "findings": findings,
    }


def load_and_validate(path: Path) -> dict[str, Any]:
    raw = _read_file(path)
    try:
        document = json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise DeliveryEvidenceInputError("input must be valid UTF-8 JSON") from exc
    result = validate(document)
    result["input_sha256"] = "sha256:" + hashlib.sha256(_canonical(document)).hexdigest()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        result = load_and_validate(args.evidence)
    except DeliveryEvidenceInputError as exc:
        result = {"schema_version": OUTPUT_SCHEMA, "verdict": "FAIL", "error": str(exc)}
        sys.stdout.buffer.write(_canonical(result))
        return 2
    sys.stdout.buffer.write(_canonical(result))
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 3}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
