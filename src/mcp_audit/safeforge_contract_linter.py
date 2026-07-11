"""Portable, read-only schema compatibility gate for SafeForge handoffs."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mcp_audit.safeforge_consumer import ForgeReceiptV0Input

_ANNOTATION_KEYS = {"default", "description", "examples", "title"}
_MAX_SCHEMA_DEPTH = 64
_MAX_SCHEMA_NODES = 10_000


class _SchemaNormalizationError(ValueError):
    pass


class ContractChange(StrEnum):
    EXACT = "exact"
    ADDITIVE = "additive"
    BREAKING = "breaking"


class ContractLintIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    change: ContractChange
    message: str


class ForgeReceiptContractLint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    compatible: bool
    producer_schema_digest: str
    consumer_schema_digest: str
    issues: list[ContractLintIssue] = Field(default_factory=list)


def lint_forge_receipt_schema(producer_schema: dict[str, Any]) -> ForgeReceiptContractLint:
    """Compare a producer schema with the exact contract accepted by MCPAudit.

    Annotation-only JSON Schema changes are ignored. New optional producer fields
    are classified as additive, but remain incompatible because the v0 consumer
    rejects unknown receipt fields. Every other semantic difference is breaking.
    """
    consumer_schema = ForgeReceiptV0Input.model_json_schema()
    try:
        producer = _normalize_schema(producer_schema, producer_schema, budget=[_MAX_SCHEMA_NODES])
    except (KeyError, RecursionError, TypeError, _SchemaNormalizationError) as exc:
        return ForgeReceiptContractLint(
            compatible=False,
            producer_schema_digest=_digest(producer_schema),
            consumer_schema_digest=_digest(
                _normalize_schema(consumer_schema, consumer_schema, budget=[_MAX_SCHEMA_NODES])
            ),
            issues=[
                ContractLintIssue(
                    path="$",
                    change=ContractChange.BREAKING,
                    message=f"producer schema cannot be normalized safely: {exc}",
                )
            ],
        )
    consumer = _normalize_schema(consumer_schema, consumer_schema, budget=[_MAX_SCHEMA_NODES])
    issues: list[ContractLintIssue] = []
    _compare(producer, consumer, "$", issues)
    return ForgeReceiptContractLint(
        compatible=not issues,
        producer_schema_digest=_digest(producer),
        consumer_schema_digest=_digest(consumer),
        issues=issues,
    )


def _normalize_schema(
    value: Any,
    root: dict[str, Any],
    keyword: str | None = None,
    *,
    depth: int = 0,
    references: frozenset[str] = frozenset(),
    budget: list[int],
) -> Any:
    if depth > _MAX_SCHEMA_DEPTH:
        raise _SchemaNormalizationError("schema exceeds maximum depth")
    budget[0] -= 1
    if budget[0] < 0:
        raise _SchemaNormalizationError("schema exceeds maximum node count")
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            if not reference.startswith("#/"):
                raise _SchemaNormalizationError("only local fragment references are supported")
            if reference in references:
                raise _SchemaNormalizationError(f"cyclic schema reference: {reference}")
            target: Any = root
            for part in reference.removeprefix("#/").split("/"):
                target = target[part.replace("~1", "/").replace("~0", "~")]
            return _normalize_schema(
                target,
                root,
                keyword,
                depth=depth + 1,
                references=references | {reference},
                budget=budget,
            )
        return {
            key: _normalize_schema(
                item,
                root,
                key,
                depth=depth + 1,
                references=references,
                budget=budget,
            )
            for key, item in sorted(value.items())
            if key not in _ANNOTATION_KEYS and key != "$defs"
        }
    if isinstance(value, list):
        normalized = [
            _normalize_schema(
                item,
                root,
                depth=depth + 1,
                references=references,
                budget=budget,
            )
            for item in value
        ]
        if keyword in {"enum", "required"}:
            return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
        return normalized
    return value


def _compare(
    producer: Any,
    consumer: Any,
    path: str,
    issues: list[ContractLintIssue],
) -> None:
    if type(producer) is not type(consumer):
        issues.append(
            ContractLintIssue(
                path=path,
                change=ContractChange.BREAKING,
                message="schema node type differs",
            )
        )
        return
    if isinstance(producer, dict):
        producer_required = set(producer.get("required", []))
        for key in sorted(set(producer) | set(consumer)):
            child_path = f"{path}/{key}"
            if key not in consumer:
                change = (
                    ContractChange.ADDITIVE
                    if path.endswith("/properties") and key not in producer_required
                    else ContractChange.BREAKING
                )
                issues.append(
                    ContractLintIssue(
                        path=child_path,
                        change=change,
                        message="producer schema has a node the consumer contract does not accept",
                    )
                )
            elif key not in producer:
                issues.append(
                    ContractLintIssue(
                        path=child_path,
                        change=ContractChange.BREAKING,
                        message="consumer requires a schema node absent from the producer contract",
                    )
                )
            else:
                _compare(producer[key], consumer[key], child_path, issues)
        return
    if isinstance(producer, list):
        if producer != consumer:
            issues.append(
                ContractLintIssue(
                    path=path,
                    change=ContractChange.BREAKING,
                    message="schema list differs",
                )
            )
        return
    if producer != consumer:
        issues.append(
            ContractLintIssue(
                path=path,
                change=ContractChange.BREAKING,
                message=f"producer value {producer!r} differs from consumer value {consumer!r}",
            )
        )


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"
