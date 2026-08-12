"""Deterministic rule engine for synthetic MCP result parcel scenarios."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import ValidationError

from mcp_audit.result_parcel_models import (
    CURRENT_PROTOCOL_VERSION,
    INLINE_ADVISORY_BYTES,
    MAX_FINDINGS,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_KEY_LENGTH,
    REPORT_SCHEMA,
    SCENARIO_SCHEMA,
    TASKS_EXTENSION,
    ChunkStreamDelivery,
    DecisionDimension,
    InlineDelivery,
    ParcelAnalysisReport,
    ParcelCoverage,
    ParcelDimensions,
    ParcelFinding,
    ParcelRecommendation,
    ParcelScenario,
    ProgressDelivery,
    ReferenceDelivery,
    SemanticsClass,
    TaskDelivery,
    canonical_json_bytes,
)

REPORT_ASSUMPTIONS: Final = [
    "all payloads, clocks, identities, failures, and digests are synthetic declarations",
    "the lab performs no MCP, network, object-store, environment, keychain, OAuth, or credential read",
    "host support is scenario evidence, not an ecosystem adoption claim",
    (
        "resource_link is MCP core content; retention, deletion, chunk streaming, "
        "and object-store behavior are not implied"
    ),
    "the io.modelcontextprotocol/tasks delivery mode is a separately negotiated extension, not MCP core",
]


class ParcelInputError(ValueError):
    """A stable file boundary failure for a supplied scenario."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_json_limits(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeds the scenario limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_JSON_KEY_LENGTH:
                raise ValueError("JSON object key exceeds the scenario limit")
            _validate_json_limits(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_limits(child, depth + 1)
    elif isinstance(value, float) and not (float("-inf") < value < float("inf")):
        raise ValueError("non-finite JSON number")


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    evidence_code: str,
    explanation: str,
    input_fields: list[str],
) -> ParcelFinding:
    return ParcelFinding(
        rule_id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        title=title,
        evidence_code=evidence_code,
        explanation=explanation,
        input_fields=input_fields,
    )


def _unknown_report(raw: bytes, evidence: str) -> ParcelAnalysisReport:
    return ParcelAnalysisReport(
        schema_version=REPORT_SCHEMA,
        scenario_schema_version=None,
        scenario_id=None,
        scenario_digest_sha256=_raw_digest(raw),
        protocol_version=None,
        verdict="unknown",
        recommendation=None,
        dimensions=None,
        findings=[
            _finding(
                "MCPPARCEL000",
                "unknown",
                "Parcel scenario evidence is malformed or unsupported",
                evidence,
                "No delivery recommendation is made until one bounded v1 scenario validates.",
                ["scenario"],
            )
        ],
        unknowns=["scenario contract was not established"],
        coverage=ParcelCoverage(
            input_state="malformed" if evidence != "unsupported_protocol_version" else "unsupported",
            state="unknown",
            limitations=["analysis stopped before rule evaluation"],
        ),
        assumptions=REPORT_ASSUMPTIONS,
        claim="synthetic_scenario_recommendation_unknown",
    )


def parse_scenario_bytes(raw: bytes) -> ParcelScenario | ParcelAnalysisReport:
    """Strictly parse one bounded scenario or return a structured UNKNOWN report."""

    if len(raw) > MAX_INPUT_BYTES:
        return _unknown_report(raw[: MAX_INPUT_BYTES + 1], "input_size_limit_exceeded")
    try:
        payload = json.loads(
            raw,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
        _validate_json_limits(payload)
        scenario = ParcelScenario.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValidationError, ValueError):
        return _unknown_report(raw, "scenario_validation_failed")
    if scenario.protocol_version != CURRENT_PROTOCOL_VERSION:
        return _unknown_report(raw, "unsupported_protocol_version")
    return scenario


def scan_scenario_bytes(raw: bytes) -> ParcelAnalysisReport:
    parsed = parse_scenario_bytes(raw)
    if isinstance(parsed, ParcelAnalysisReport):
        return parsed
    return analyze_scenario(parsed)


def scan_scenario_path(path: Path) -> ParcelAnalysisReport:
    """Read one regular, non-symlink scenario through one bounded descriptor."""

    try:
        before = path.lstat()
    except OSError as exc:
        raise ParcelInputError("cannot stat parcel scenario input") from exc
    if stat.S_ISLNK(before.st_mode):
        raise ParcelInputError("refusing symlink parcel scenario input")
    if not stat.S_ISREG(before.st_mode):
        raise ParcelInputError("parcel scenario input is not a regular file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ParcelInputError("parcel scenario input is not a regular file")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise ParcelInputError("parcel scenario identity changed before open")
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
    except OSError as exc:
        raise ParcelInputError("cannot read parcel scenario input") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, int, int, int]:
        return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)

    if identity(opened) != identity(after):
        raise ParcelInputError("parcel scenario changed while it was being read")
    return scan_scenario_bytes(raw)


def _dimension(state: str, *reasons: str) -> DecisionDimension:
    return DecisionDimension(state=state, reasons=list(reasons))  # type: ignore[arg-type]


def _synthetic_digest(scenario_id: str, size_bytes: int) -> str:
    return hashlib.sha256(f"synthetic:{scenario_id}:{size_bytes}".encode()).hexdigest()


def analyze_scenario(scenario: ParcelScenario) -> ParcelAnalysisReport:
    """Apply transparent input-addressable rules to one validated scenario."""

    findings: list[ParcelFinding] = []
    unknowns: list[str] = []
    conditions: list[str] = []
    reasons: list[str] = []
    delivery = scenario.delivery
    payload = scenario.payload

    if delivery.host_support == "unsupported":
        findings.append(
            _finding(
                "MCPPARCEL001",
                "error",
                "Host does not support the selected delivery mode",
                "host_capability_unsupported",
                "The declared host capability blocks this delivery mode.",
                ["delivery.mode", "delivery.host_support"],
            )
        )
    elif delivery.host_support == "unknown":
        unknowns.append("selected delivery mode support is unverified for the host")

    if isinstance(delivery, InlineDelivery):
        reasons.append("one complete MCP tool result has no retrieval round trip")
        if not delivery.result_complete:
            findings.append(
                _finding(
                    "MCPPARCEL002",
                    "error",
                    "Inline result is incomplete",
                    "inline_result_incomplete",
                    "MCP complete tool results must contain the final content represented by the scenario.",
                    ["delivery.result_complete"],
                )
            )
        if payload.size_bytes > INLINE_ADVISORY_BYTES:
            findings.append(
                _finding(
                    "MCPPARCEL003",
                    "warning",
                    "Large inline result increases transfer and context pressure",
                    "inline_payload_above_advisory_bound",
                    (
                        f"Declared size {payload.size_bytes} exceeds the lab advisory "
                        f"bound {INLINE_ADVISORY_BYTES}."
                    ),
                    ["payload.size_bytes", "delivery.mode"],
                )
            )
            conditions.append("confirm the actual host and transport payload limits")

    if isinstance(delivery, ChunkStreamDelivery):
        reasons.append(
            "incremental delivery can limit a retry to missing chunks when the extension defines it"
        )
        indexes = [chunk.index for chunk in delivery.chunks]
        expected = list(range(delivery.expected_chunks))
        if len(indexes) != len(set(indexes)):
            findings.append(
                _finding(
                    "MCPPARCEL007",
                    "error",
                    "Duplicate stream chunks create replay ambiguity",
                    "duplicate_chunk_index",
                    "The same chunk index appears more than once; content cannot be assembled idempotently.",
                    ["delivery.chunks", "delivery.idempotency_key_present"],
                )
            )
        if indexes != sorted(indexes):
            findings.append(
                _finding(
                    "MCPPARCEL007",
                    "error",
                    "Chunk order is not deterministic",
                    "chunk_order_invalid",
                    "Chunk indexes are not monotonically ordered in the supplied stream.",
                    ["delivery.chunks"],
                )
            )
        if indexes != expected or delivery.interrupted:
            findings.append(
                _finding(
                    "MCPPARCEL007",
                    "error",
                    "Stream did not deliver the complete parcel",
                    "stream_incomplete",
                    "The observed chunk indexes or interruption state do not cover the declared sequence.",
                    ["delivery.expected_chunks", "delivery.chunks", "delivery.interrupted"],
                )
            )
        if sum(chunk.size_bytes for chunk in delivery.chunks) != payload.size_bytes:
            findings.append(
                _finding(
                    "MCPPARCEL007",
                    "error",
                    "Chunk sizes do not bind the declared payload size",
                    "chunk_size_mismatch",
                    "The sum of chunk sizes differs from payload.size_bytes.",
                    ["delivery.chunks", "payload.size_bytes"],
                )
            )
        if not delivery.idempotency_key_present:
            findings.append(
                _finding(
                    "MCPPARCEL008",
                    "warning",
                    "Stream retry has no declared idempotency key",
                    "stream_idempotency_unbound",
                    (
                        "A retry may duplicate already accepted chunks because no stable "
                        "operation key is declared."
                    ),
                    ["delivery.idempotency_key_present"],
                )
            )

    if isinstance(delivery, ProgressDelivery):
        reasons.append("progress can report operation status while the final result remains separate")
        if delivery.carries_result_payload:
            findings.append(
                _finding(
                    "MCPPARCEL009",
                    "error",
                    "Progress was used as a result-byte stream",
                    "progress_payload_conflation",
                    (
                        "MCP progress semantics report progress; streamed result bytes are "
                        "a provider or local extension."
                    ),
                    ["delivery.semantics", "delivery.carries_result_payload"],
                )
            )
        if not delivery.final_result_present:
            findings.append(
                _finding(
                    "MCPPARCEL009",
                    "error",
                    "Progress ended without a final result",
                    "progress_final_result_missing",
                    "Progress updates do not replace the complete operation result.",
                    ["delivery.final_result_present"],
                )
            )
        if any(
            b <= a
            for a, b in zip(
                delivery.progress_values,
                delivery.progress_values[1:],
                strict=False,
            )
        ):
            findings.append(
                _finding(
                    "MCPPARCEL009",
                    "warning",
                    "Progress values are not strictly increasing",
                    "progress_not_increasing",
                    "The supplied progress sequence contains a duplicate or decrease.",
                    ["delivery.progress_values"],
                )
            )

    if isinstance(delivery, ReferenceDelivery):
        reasons.append("a resource link keeps the initial tool result small and supports later retrieval")
        status = delivery.retrieval_status
        if scenario.retention.ttl_ms is None:
            unknowns.append("reference expiry is unknown because no TTL is declared")
        else:
            expires_at = scenario.retention.created_at_ms + scenario.retention.ttl_ms
            if scenario.retention.observed_at_ms >= expires_at and status not in {"expired", "missing"}:
                findings.append(
                    _finding(
                        "MCPPARCEL004",
                        "error",
                        "Reference is usable after its declared expiry",
                        "reference_expiry_contradiction",
                        "The virtual observation time is at or beyond created_at_ms + ttl_ms.",
                        ["retention.created_at_ms", "retention.ttl_ms", "retention.observed_at_ms"],
                    )
                )
        if status in {"missing", "stale", "expired"}:
            findings.append(
                _finding(
                    "MCPPARCEL004",
                    "error",
                    "Reference cannot return the declared parcel",
                    f"reference_{status}",
                    "The synthetic retrieval state is not a current available blob.",
                    ["delivery.retrieval_status", "retention.ttl_ms"],
                )
            )
        elif status == "partial":
            findings.append(
                _finding(
                    "MCPPARCEL010",
                    "error",
                    "Reference retrieval returned only part of the parcel",
                    "reference_partial_retrieval",
                    "bytes_retrieved is lower than payload.size_bytes.",
                    ["delivery.bytes_retrieved", "payload.size_bytes"],
                )
            )
        elif status == "unknown":
            unknowns.append("reference retrieval outcome is unknown")
        if scenario.retention.cleanup_owner == "unknown":
            unknowns.append("reference cleanup ownership is unknown")
        elif (
            scenario.retention.cleanup_owner != "none" and scenario.retention.delete_supported != "supported"
        ):
            findings.append(
                _finding(
                    "MCPPARCEL011",
                    ("warning" if scenario.retention.delete_supported == "unsupported" else "unknown"),
                    "Retained parcel cleanup is not proven",
                    "retained_cleanup_unproven",
                    "The scenario assigns a cleanup owner without a supported deletion path.",
                    ["retention.cleanup_owner", "retention.delete_supported"],
                )
            )

    if isinstance(delivery, TaskDelivery):
        reasons.append("the negotiated Tasks extension provides durable polling and deferred final results")
        if delivery.extension_id != TASKS_EXTENSION:
            raise AssertionError("strict model admitted an unexpected task extension")
        if delivery.task_status == "unknown":
            unknowns.append("task result availability is unknown because task status is unknown")
        elif delivery.task_status != "completed" or not delivery.final_result_present:
            findings.append(
                _finding(
                    "MCPPARCEL012",
                    "error",
                    "Task does not expose a completed final result",
                    "task_result_unavailable",
                    "The extension task is not completed with its final tool result present.",
                    ["delivery.task_status", "delivery.final_result_present"],
                )
            )
        if scenario.retention.cleanup_owner != "none" and scenario.retention.delete_supported != "supported":
            findings.append(
                _finding(
                    "MCPPARCEL011",
                    ("warning" if scenario.retention.delete_supported == "unsupported" else "unknown"),
                    "Retained task-result cleanup is not proven",
                    "retained_cleanup_unproven",
                    "The task result has a retention owner without a supported deletion path.",
                    ["retention.cleanup_owner", "retention.delete_supported"],
                )
            )

    authority = scenario.retrieval_authority
    principal_binding_required = authority.required or (
        isinstance(delivery, ReferenceDelivery) and payload.sensitivity in {"confidential", "secret"}
    )
    if principal_binding_required:
        if authority.enforcement == "unknown" or authority.outcome == "unknown":
            unknowns.append("retrieval authorization enforcement or outcome is unknown")
        elif authority.enforcement != "enforced" or authority.principal_bound is not True:
            findings.append(
                _finding(
                    "MCPPARCEL005",
                    "error",
                    "Retrieval authority is not bound to the principal",
                    "retrieval_authority_unbound",
                    "A retained or sensitive result must be re-authorized at retrieval in this scenario.",
                    ["retrieval_authority.enforcement", "retrieval_authority.principal_bound"],
                )
            )
        if authority.outcome == "denied":
            findings.append(
                _finding(
                    "MCPPARCEL005",
                    "error",
                    "Authorized retrieval was denied",
                    "retrieval_authorization_denied",
                    "The declared caller cannot retrieve the parcel.",
                    ["retrieval_authority.outcome"],
                )
            )

    integrity = scenario.integrity
    if integrity.observed_content_type is None:
        unknowns.append("content type cannot be verified because the observation is absent")
    elif integrity.observed_content_type != integrity.declared_content_type:
        findings.append(
            _finding(
                "MCPPARCEL006",
                "error",
                "Retrieved content type differs from the parcel contract",
                "content_type_mismatch",
                "The observed and declared content types differ.",
                ["integrity.declared_content_type", "integrity.observed_content_type"],
            )
        )
    if integrity.algorithm == "sha256":
        if integrity.observed_digest is None:
            unknowns.append("integrity cannot be verified because the observed digest is absent")
        elif integrity.expected_digest != integrity.observed_digest:
            findings.append(
                _finding(
                    "MCPPARCEL006",
                    "error",
                    "Parcel integrity digest does not match",
                    "integrity_digest_mismatch",
                    "The observed SHA-256 differs from the expected digest.",
                    ["integrity.expected_digest", "integrity.observed_digest"],
                )
            )
    elif integrity.algorithm == "none":
        findings.append(
            _finding(
                "MCPPARCEL006",
                "warning",
                "Parcel has no declared integrity check",
                "integrity_not_declared",
                "Size and content type alone cannot prove retrieved bytes are the intended result.",
                ["integrity.algorithm"],
            )
        )
    else:
        unknowns.append("parcel integrity mechanism is unknown")

    sensitive = payload.sensitivity in {"confidential", "secret"}
    if scenario.redaction.required and scenario.redaction.stage == "unknown":
        unknowns.append("required redaction stage is unknown")
    elif scenario.redaction.required and scenario.redaction.stage != "before_packaging":
        findings.append(
            _finding(
                "MCPPARCEL013",
                "error",
                "Redaction occurs after the parcel crosses its packaging boundary",
                "redaction_after_packaging",
                (
                    "Raw sensitive material is already present in the package or retained "
                    "object before redaction."
                ),
                ["redaction.required", "redaction.stage"],
            )
        )
    if scenario.redaction.stage == "before_packaging" and scenario.redaction.raw_payload_retained:
        findings.append(
            _finding(
                "MCPPARCEL013",
                "warning",
                "Pre-redaction raw payload is still retained",
                "raw_payload_retained",
                "The delivered parcel is redacted, but the raw source remains a separate disclosure surface.",
                ["redaction.raw_payload_retained", "retention.cleanup_owner"],
            )
        )

    if payload.sensitivity == "unknown":
        unknowns.append("payload sensitivity is unknown")

    exposure_state = (
        "high"
        if sensitive
        and (isinstance(delivery, InlineDelivery) or scenario.redaction.stage != "before_packaging")
        else "moderate"
        if payload.sensitivity != "public" or scenario.retention.retained
        else "low"
    )
    if payload.sensitivity == "unknown":
        exposure_state = "unknown"
    if scenario.redaction.required and scenario.redaction.stage == "unknown":
        exposure_state = "unknown"
    durability_state = "high" if isinstance(delivery, (ReferenceDelivery, TaskDelivery)) else "moderate"
    if isinstance(delivery, ReferenceDelivery) and delivery.retrieval_status != "available":
        durability_state = "low" if delivery.retrieval_status != "unknown" else "unknown"
    if isinstance(delivery, ChunkStreamDelivery) and (delivery.interrupted or findings):
        durability_state = "low"
    retry_state = (
        "high"
        if isinstance(delivery, ChunkStreamDelivery) and not delivery.idempotency_key_present
        else "moderate"
    )
    if isinstance(delivery, InlineDelivery):
        retry_state = "low"
    cleanup_state = (
        "high"
        if scenario.retention.retained
        and (
            scenario.retention.cleanup_owner == "unknown"
            or scenario.retention.delete_supported != "supported"
        )
        else "moderate"
        if scenario.retention.retained
        else "low"
    )

    error_findings = [finding for finding in findings if finding.severity == "error"]
    unknown_findings = [finding for finding in findings if finding.severity == "unknown"]
    verdict: Literal["pass", "fail", "unknown"]
    if error_findings:
        suitability = "unsuitable"
        verdict = "fail"
        claim = "synthetic_scenario_has_material_delivery_risk"
        reasons.append("one or more declared failure conditions prevent reliable delivery")
    elif unknowns or unknown_findings or delivery.host_support == "unknown":
        suitability = "unknown"
        verdict = "unknown"
        claim = "synthetic_scenario_recommendation_unknown"
        reasons.append("material evidence remains unknown")
    elif findings or conditions:
        suitability = "conditional"
        verdict = "pass"
        claim = "synthetic_scenario_suitable_under_declared_conditions"
        reasons.append("the declared mode is usable only with the listed mitigations")
    else:
        suitability = "suitable"
        verdict = "pass"
        claim = "synthetic_scenario_suitable_under_declared_conditions"
        reasons.append("the supplied deterministic evidence contains no material contradiction")

    findings = sorted(findings, key=lambda item: (item.rule_id, item.evidence_code))[:MAX_FINDINGS]
    return ParcelAnalysisReport(
        schema_version=REPORT_SCHEMA,
        scenario_schema_version=SCENARIO_SCHEMA,
        scenario_id=scenario.scenario_id,
        scenario_digest_sha256=hashlib.sha256(canonical_json_bytes(scenario)).hexdigest(),
        protocol_version=scenario.protocol_version,
        verdict=verdict,
        recommendation=ParcelRecommendation(
            suitability=suitability,  # type: ignore[arg-type]
            selected_mode=delivery.mode,
            reasons=reasons,
            conditions=conditions,
        ),
        dimensions=ParcelDimensions(
            information_exposure=_dimension(
                exposure_state,
                f"sensitivity={payload.sensitivity}",
                f"redaction_stage={scenario.redaction.stage}",
            ),
            durability=_dimension(
                durability_state,
                f"delivery_mode={delivery.mode}",
                f"retained={scenario.retention.retained}",
            ),
            retry_idempotency_risk=_dimension(
                retry_state,
                (
                    "inline retry replaces one result"
                    if isinstance(delivery, InlineDelivery)
                    else "retry behavior depends on declared mode evidence"
                ),
            ),
            cleanup_burden=_dimension(
                cleanup_state,
                f"cleanup_owner={scenario.retention.cleanup_owner}",
                f"delete_supported={scenario.retention.delete_supported}",
            ),
        ),
        findings=findings,
        unknowns=sorted(set(unknowns)),
        coverage=ParcelCoverage(
            input_state="valid",
            state="unknown" if verdict == "unknown" else "complete",
            limitations=[
                "local synthetic analysis only; no host, server, transport, or object store was contacted"
            ],
        ),
        assumptions=REPORT_ASSUMPTIONS,
        claim=claim,  # type: ignore[arg-type]
    )


def generate_synthetic_scenario(
    *,
    scenario_id: str,
    size_bytes: int,
    mode: str,
    sensitivity: str = "internal",
) -> ParcelScenario:
    """Generate metadata for a large synthetic parcel without allocating payload bytes."""

    digest = _synthetic_digest(scenario_id, size_bytes)
    common: dict[str, Any] = {
        "schema_version": SCENARIO_SCHEMA,
        "scenario_id": scenario_id,
        "title": f"Synthetic {mode} parcel ({size_bytes} bytes)",
        "protocol_version": CURRENT_PROTOCOL_VERSION,
        "payload": {
            "payload_class": "binary" if mode == "resource_link" else "text",
            "sensitivity": sensitivity,
            "size_bytes": size_bytes,
            "content_type": "application/octet-stream" if mode == "resource_link" else "text/plain",
            "synthetic": True,
        },
        "retention": {
            "retained": mode == "resource_link",
            "ttl_ms": 60_000 if mode == "resource_link" else None,
            "created_at_ms": 0,
            "observed_at_ms": 1_000,
            "cleanup_owner": "server" if mode == "resource_link" else "none",
            "delete_supported": "supported" if mode == "resource_link" else "unsupported",
        },
        "integrity": {
            "algorithm": "sha256",
            "expected_digest": digest,
            "observed_digest": digest,
            "declared_content_type": "application/octet-stream" if mode == "resource_link" else "text/plain",
            "observed_content_type": "application/octet-stream" if mode == "resource_link" else "text/plain",
        },
        "retrieval_authority": {
            "required": mode == "resource_link",
            "enforcement": "enforced" if mode == "resource_link" else "not_enforced",
            "principal_bound": True if mode == "resource_link" else False,
            "outcome": "allowed",
        },
        "redaction": {"required": False, "stage": "none", "raw_payload_retained": False},
        "evidence_provenance": [
            {
                "evidence_class": "standard",
                "title": "MCP 2026-07-28 tool result semantics",
                "url": ("https://modelcontextprotocol.io/specification/2026-07-28/server/tools"),
                "version": CURRENT_PROTOCOL_VERSION,
                "commit": "5f5440bb26a62e2cf3440b92da5a667efa03b267",
            }
        ],
    }
    if mode == "inline":
        common["delivery"] = {
            "mode": "inline",
            "semantics": SemanticsClass.MCP_CORE.value,
            "host_support": "supported",
            "result_complete": True,
        }
    elif mode == "resource_link":
        common["delivery"] = {
            "mode": "resource_link",
            "semantics": SemanticsClass.MCP_CORE.value,
            "host_support": "supported",
            "uri": "parcel://synthetic/result",
            "retrieval_status": "available",
            "bytes_retrieved": size_bytes,
        }
    else:
        raise ValueError("synthetic generator supports inline or resource_link")
    return ParcelScenario.model_validate(common)


def builtin_scenarios() -> dict[str, ParcelScenario]:
    """Return deterministic install-safe built-ins."""

    return {
        "small-inline": generate_synthetic_scenario(
            scenario_id="small-inline", size_bytes=1_024, mode="inline", sensitivity="public"
        ),
        "large-inline": generate_synthetic_scenario(
            scenario_id="large-inline", size_bytes=8_388_608, mode="inline"
        ),
        "large-resource-link": generate_synthetic_scenario(
            scenario_id="large-resource-link", size_bytes=8_388_608, mode="resource_link"
        ),
    }


def report_json_bytes(report: ParcelAnalysisReport) -> bytes:
    return canonical_json_bytes(report)
