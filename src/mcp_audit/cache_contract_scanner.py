"""Deterministic state machine for synthetic MCP cache traces."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Literal

from mcp.types import (
    BlobResourceContents,
    Prompt,
    Resource,
    ResourceTemplate,
    TextResourceContents,
    Tool,
)
from pydantic import ValidationError

from mcp_audit.cache_contract_models import (
    CURRENT_PROTOCOL_VERSION,
    MAX_FINDINGS,
    MAX_INPUT_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_KEY_LENGTH,
    MAX_KEY_BYTES,
    MAX_LOGICAL_MS,
    MAX_RESULT_BYTES,
    MAX_RETAINED_ENTRIES,
    REPORT_SCHEMA,
    TRACE_SCHEMA,
    CacheAuditReport,
    CacheCoverage,
    CacheFinding,
    CacheRequest,
    CacheSeverity,
    CacheTrace,
    NotificationEvent,
    RefreshErrorEvent,
    RefreshEvent,
    RequirementLevel,
    ResponseEvent,
    UseEvent,
    canonical_json_bytes,
)

SUPPORTED_METHODS: Final = frozenset(
    {
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "resources/read",
    }
)
LIST_METHODS: Final = frozenset(
    {
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
    }
)
PAYLOAD_FIELDS: Final = {
    "tools/list": "tools",
    "prompts/list": "prompts",
    "resources/list": "resources",
    "resources/templates/list": "resourceTemplates",
    "resources/read": "contents",
}
LIST_NOTIFICATION_METHODS: Final = {
    "notifications/tools/list_changed": frozenset({"tools/list"}),
    "notifications/prompts/list_changed": frozenset({"prompts/list"}),
    "notifications/resources/list_changed": frozenset({"resources/list", "resources/templates/list"}),
}
RESOURCE_UPDATED: Final = "notifications/resources/updated"

REPORT_ASSUMPTIONS: Final = [
    (
        "cache_partition is a synthetic assertion of one authorization context; "
        "the auditor does not inspect tokens or credentials"
    ),
    (
        "notification events are normative only when subscription_validated is true; "
        "wire subscription behavior is otherwise outside the trace"
    ),
    (
        "the analyzer evaluates supplied synthetic evidence only and does not prove "
        "a live client, server, proxy, transport, authorization, or confidentiality property"
    ),
]


class CacheContractInputError(ValueError):
    """Raised only for file-system input failures that cannot yield a report."""


@dataclass
class _Entry:
    event: ResponseEvent | RefreshEvent
    key: tuple[str, str, str]
    scope: str | None
    ttl_ms: int | None
    expires_at_ms: int | None
    invalidated_globally: int | None = None
    invalidated_partitions: dict[str, int] = field(default_factory=dict)
    refresh_errors: dict[str, list[tuple[int, int]]] = field(default_factory=dict)
    successful_refreshes: dict[str, int] = field(default_factory=dict)


@dataclass
class _OrderingBaseline:
    ordered_items: tuple[str, ...]
    item_multiset: tuple[str, ...]
    event_sequence: int
    epoch: int


@dataclass
class _PageBaseline:
    scope: str
    event_sequence: int
    principal: str
    cache_partition: str
    base_params: str


class _FindingCollector:
    def __init__(self) -> None:
        self.findings: list[CacheFinding] = []
        self._overflowed = False
        self._has_concrete = False

    def add(self, finding: CacheFinding) -> None:
        is_concrete = finding.severity != CacheSeverity.UNKNOWN
        if len(self.findings) < MAX_FINDINGS - 1:
            self.findings.append(finding)
            self._has_concrete = self._has_concrete or is_concrete
            return
        self._overflowed = True
        if is_concrete and not self._has_concrete:
            self.findings[-1] = finding
            self._has_concrete = True

    def finish(self) -> list[CacheFinding]:
        if self._overflowed:
            self.findings.append(
                _finding(
                    "MCPCACHE000",
                    CacheSeverity.UNKNOWN,
                    RequirementLevel.UNKNOWN,
                    "Finding coverage exceeded the simulator bound",
                    "trace",
                    "finding_limit_exceeded",
                    "Split the synthetic trace into smaller causally complete traces.",
                )
            )
        return sorted(
            self.findings,
            key=lambda finding: (
                finding.rule_id,
                finding.event_sequences,
                finding.target,
                finding.evidence,
            ),
        )


def _finding(
    rule_id: str,
    severity: CacheSeverity,
    requirement_level: RequirementLevel,
    title: str,
    target: str,
    evidence: str,
    remediation: str,
    *,
    protocol_version: str | None = CURRENT_PROTOCOL_VERSION,
    event_sequences: list[int] | None = None,
    assumptions: list[str] | None = None,
) -> CacheFinding:
    return CacheFinding(
        rule_id=rule_id,  # type: ignore[arg-type]
        severity=severity,
        requirement_level=requirement_level,
        title=title,
        target=target,
        evidence=evidence,
        remediation=remediation,
        protocol_version=protocol_version,
        event_sequences=event_sequences or [],
        assumptions=assumptions or [],
    )


def _event_target(sequence: int) -> str:
    return f"event:{sequence}"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _request_key(request: CacheRequest) -> tuple[str, str, str]:
    return (
        request.protocol_version,
        request.method,
        _json_bytes(request.params).decode("utf-8"),
    )


def _page_base_params(request: CacheRequest) -> str:
    params = dict(request.params)
    params.pop("cursor", None)
    return _json_bytes(params).decode("utf-8")


def _trace_digest(trace: CacheTrace) -> str:
    payload = trace.model_dump(mode="json")
    payload["events"] = [
        event.model_dump(mode="json") for event in sorted(trace.events, key=lambda item: item.sequence)
    ]
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _raw_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = child
    return value


def _validate_json_limits(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting exceeds the trace limit")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > MAX_JSON_KEY_LENGTH:
                raise ValueError("JSON object key exceeds the trace limit")
            _validate_json_limits(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_limits(child, depth + 1)
    elif isinstance(value, float) and not (float("-inf") < value < float("inf")):
        raise ValueError("non-finite JSON number")


def _unknown_report(raw: bytes, evidence: str) -> CacheAuditReport:
    finding = _finding(
        "MCPCACHE000",
        CacheSeverity.UNKNOWN,
        RequirementLevel.UNKNOWN,
        "Cache trace evidence is malformed or unsupported",
        "trace",
        evidence,
        "Provide one valid, bounded mcpaudit.cache-contract.trace.v1 fixture.",
        protocol_version=None,
    )
    return CacheAuditReport(
        schema_version=REPORT_SCHEMA,
        trace_schema_version=None,
        trace_digest_sha256=_raw_digest(raw),
        protocol_versions=[],
        verdict="unknown",
        coverage=CacheCoverage(
            state="unknown",
            input_state="malformed",
            total_events=0,
            analyzed_events=0,
            retained_entries=0,
            limitations=["input validation did not establish a complete synthetic trace"],
        ),
        findings=[finding],
        assumptions=REPORT_ASSUMPTIONS,
        claim="supplied_trace_contract_unknown",
    )


def scan_cache_bytes(raw: bytes) -> CacheAuditReport:
    """Parse and analyze one bounded synthetic cache trace."""

    if len(raw) > MAX_INPUT_BYTES:
        return _unknown_report(raw, "input_size_limit_exceeded")
    try:
        payload = json.loads(
            raw,
            parse_constant=_reject_nonstandard_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
        _validate_json_limits(payload)
        trace = CacheTrace.model_validate(payload)
        for event in trace.events:
            if isinstance(event, (ResponseEvent, RefreshEvent)):
                if len(_json_bytes(event.result)) > MAX_RESULT_BYTES:
                    raise ValueError("result body exceeds the simulator limit")
                if len(_json_bytes(event.request.params)) > MAX_KEY_BYTES:
                    raise ValueError("request key exceeds the simulator limit")
            elif isinstance(event, (UseEvent, RefreshErrorEvent)):
                if len(_json_bytes(event.request.params)) > MAX_KEY_BYTES:
                    raise ValueError("request key exceeds the simulator limit")
            elif isinstance(event, NotificationEvent):
                if len(_json_bytes(event.params)) > MAX_KEY_BYTES:
                    raise ValueError("notification key exceeds the simulator limit")
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValidationError,
        ValueError,
    ):
        return _unknown_report(raw, "trace_validation_failed")
    return analyze_cache_trace(trace)


def scan_cache_path(path: Path) -> CacheAuditReport:
    """Read one regular non-symlink input through a single bounded descriptor."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CacheContractInputError("cannot stat cache trace input") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise CacheContractInputError("refusing symlink cache trace input")
    if not stat.S_ISREG(metadata.st_mode):
        raise CacheContractInputError("cache trace input is not a regular file")

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
            raise CacheContractInputError("cache trace input is not a regular file")
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            raise CacheContractInputError("cache trace identity changed before it was opened")
        chunks: list[bytes] = []
        remaining = MAX_INPUT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise CacheContractInputError("cannot read cache trace input") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    finished_identity = (
        finished.st_dev,
        finished.st_ino,
        finished.st_size,
        finished.st_mtime_ns,
    )
    if opened_identity != finished_identity:
        raise CacheContractInputError("cache trace changed while it was being read")
    return scan_cache_bytes(raw)


def _record_input_required_violation(
    event: ResponseEvent | RefreshEvent,
    collector: _FindingCollector,
) -> None:
    collector.add(
        _finding(
            "MCPCACHE009",
            CacheSeverity.HIGH,
            RequirementLevel.PROTOCOL_MUST,
            "A non-cacheable multi-round-trip result was stored",
            _event_target(event.sequence),
            "input_required_result_cached",
            "Do not cache input_required results or retry results carrying inputResponses/requestState.",
            event_sequences=[event.sequence],
        )
    )


def _validate_response_metadata(
    event: ResponseEvent | RefreshEvent,
    collector: _FindingCollector,
) -> tuple[str | None, int | None]:
    result = event.result
    sequence = event.sequence
    result_type_present = "resultType" in result
    if not result_type_present:
        collector.add(
            _finding(
                "MCPCACHE001",
                CacheSeverity.HIGH,
                RequirementLevel.PROTOCOL_MUST,
                "Required cache metadata is missing",
                _event_target(sequence),
                "required_result_type_missing",
                "Include resultType, integer ttlMs >= 0, and cacheScope on current complete results.",
                event_sequences=[sequence],
            )
        )

    result_type = result.get("resultType")
    if result_type == "input_required":
        _record_input_required_violation(event, collector)
        return None, None
    if result_type_present and result_type != "complete":
        collector.add(
            _finding(
                "MCPCACHE000",
                CacheSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Result type is not covered by the cache contract",
                _event_target(sequence),
                "unsupported_result_type",
                "Use resultType complete for cacheable evidence or preserve this result as unsupported.",
                event_sequences=[sequence],
            )
        )
        return None, None

    if result_type == "complete":
        missing = [field for field in ("ttlMs", "cacheScope") if field not in result]
        if missing:
            collector.add(
                _finding(
                    "MCPCACHE001",
                    CacheSeverity.HIGH,
                    RequirementLevel.PROTOCOL_MUST,
                    "Required cache metadata is missing",
                    _event_target(sequence),
                    "required_cache_hints_missing",
                    "Include integer ttlMs >= 0 and cacheScope on current complete results.",
                    event_sequences=[sequence],
                )
            )

    payload_valid = _payload_members_valid(event.request.method, result)
    if not payload_valid:
        collector.add(
            _finding(
                "MCPCACHE000",
                CacheSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Cacheable result payload is incomplete or malformed",
                _event_target(sequence),
                "cacheable_payload_unverified",
                "Supply the required list/read result payload for the declared method.",
                event_sequences=[sequence],
            )
        )

    scope_raw = result.get("cacheScope")
    scope: str | None
    if isinstance(scope_raw, str) and scope_raw in {"public", "private"}:
        scope = scope_raw
    elif "cacheScope" in result:
        scope = None
        collector.add(
            _finding(
                "MCPCACHE002",
                CacheSeverity.HIGH,
                RequirementLevel.PROTOCOL_MUST,
                "Cache scope metadata is invalid",
                _event_target(sequence),
                "invalid_cache_scope",
                "Use exactly public or private for cacheScope.",
                event_sequences=[sequence],
            )
        )
    else:
        scope = None

    ttl_raw = result.get("ttlMs")
    ttl_ms: int | None
    if isinstance(ttl_raw, int) and not isinstance(ttl_raw, bool) and ttl_raw >= 0:
        if ttl_raw <= MAX_LOGICAL_MS:
            ttl_ms = ttl_raw
        else:
            ttl_ms = None
            collector.add(
                _finding(
                    "MCPCACHE000",
                    CacheSeverity.UNKNOWN,
                    RequirementLevel.SIMULATOR_POLICY,
                    "TTL exceeds the bounded logical-clock model",
                    _event_target(sequence),
                    "ttl_outside_simulator_clock",
                    "Use a synthetic TTL within the documented logical-clock bound.",
                    event_sequences=[sequence],
                )
            )
    elif "ttlMs" in result:
        ttl_ms = None
        collector.add(
            _finding(
                "MCPCACHE002",
                CacheSeverity.HIGH,
                RequirementLevel.PROTOCOL_MUST,
                "TTL metadata is invalid",
                _event_target(sequence),
                "invalid_ttl",
                "Use an integer ttlMs value greater than or equal to zero.",
                event_sequences=[sequence],
            )
        )
    else:
        ttl_ms = None
    if result_type != "complete" or not payload_valid:
        return None, None
    return scope, ttl_ms


def _payload_members_valid(method: str, result: dict[str, Any]) -> bool:
    payload = result.get(PAYLOAD_FIELDS[method])
    if not isinstance(payload, list):
        return False

    try:
        if method == "tools/list":
            for member in payload:
                Tool.model_validate(member)
        elif method == "prompts/list":
            for member in payload:
                Prompt.model_validate(member)
        elif method == "resources/list":
            for member in payload:
                Resource.model_validate(member)
        elif method == "resources/templates/list":
            for member in payload:
                ResourceTemplate.model_validate(member)
        else:
            for member in payload:
                try:
                    TextResourceContents.model_validate(member)
                except ValidationError:
                    BlobResourceContents.model_validate(member)
    except ValidationError:
        return False
    return True


def _validate_pagination_cursor_shapes(
    event: ResponseEvent | RefreshEvent | RefreshErrorEvent | UseEvent,
    collector: _FindingCollector,
) -> bool:
    if event.request.method not in LIST_METHODS:
        return True

    request_cursor_malformed = "cursor" in event.request.params and not isinstance(
        event.request.params["cursor"], str
    )
    response_cursor_malformed = isinstance(event, (ResponseEvent, RefreshEvent)) and (
        "nextCursor" in event.result and not isinstance(event.result["nextCursor"], str)
    )
    if not request_cursor_malformed and not response_cursor_malformed:
        return True

    collector.add(
        _finding(
            "MCPCACHE000",
            CacheSeverity.UNKNOWN,
            RequirementLevel.PROTOCOL_CONTRACT,
            "List pagination cursor shape is malformed",
            _event_target(event.sequence),
            "pagination_cursor_shape_unverified",
            "Use string cursor and nextCursor values, or omit the field when no cursor is present.",
            event_sequences=[event.sequence],
        )
    )
    return False


def _contains_mrtr_retry(request: CacheRequest) -> bool:
    return "inputResponses" in request.params or "requestState" in request.params


def _refresh_error_allows_ttl_stale(
    entry: _Entry,
    event: UseEvent,
    invalidated_at: int | None,
) -> bool:
    if entry.expires_at_ms is None:
        return False
    partition_key = "public" if entry.scope == "public" else event.request.cache_partition
    latest_success = entry.successful_refreshes.get(partition_key, -1)
    return any(
        latest_success < error_sequence < event.sequence
        and (
            error_at_ms >= entry.expires_at_ms
            or (invalidated_at is not None and latest_success < invalidated_at < error_sequence)
        )
        for error_sequence, error_at_ms in entry.refresh_errors.get(partition_key, [])
    )


def _refresh_error_allows_notification_stale(
    entry: _Entry,
    event: UseEvent,
    invalidated_at: int | None,
) -> bool:
    if invalidated_at is None:
        return False
    partition_key = "public" if entry.scope == "public" else event.request.cache_partition
    latest_success = entry.successful_refreshes.get(partition_key, -1)
    return any(
        latest_success < invalidated_at < error_sequence < event.sequence
        for error_sequence, _ in entry.refresh_errors.get(partition_key, [])
    )


def _is_valid_successful_refresh(
    event: RefreshEvent,
    scope: str | None,
    ttl_ms: int | None,
    cursor_shapes_valid: bool,
) -> bool:
    return (
        event.result.get("resultType") == "complete"
        and _payload_members_valid(event.request.method, event.result)
        and scope is not None
        and ttl_ms is not None
        and cursor_shapes_valid
        and not _contains_mrtr_retry(event.request)
    )


def _notification_relevant(entry: _Entry, event: NotificationEvent) -> bool | None:
    affected_methods = LIST_NOTIFICATION_METHODS.get(event.method)
    if affected_methods is not None:
        return entry.event.request.method in affected_methods
    if event.method != RESOURCE_UPDATED:
        return None
    if entry.event.request.method != "resources/read":
        return False
    notification_uri = event.params.get("uri")
    request_uri = entry.event.request.params.get("uri")
    if not isinstance(notification_uri, str) or not isinstance(request_uri, str):
        return None
    return notification_uri == request_uri


def _ordering_items(result: dict[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    tools = result.get("tools")
    if not isinstance(tools, list):
        return None
    try:
        ordered = tuple(_json_bytes(tool).decode("utf-8") for tool in tools)
    except (TypeError, ValueError):
        return None
    return ordered, tuple(sorted(ordered))


def analyze_cache_trace(trace: CacheTrace) -> CacheAuditReport:
    """Run the pure state machine over explicit sequence and logical time."""

    collector = _FindingCollector()
    entries: dict[str, _Entry] = {}
    ungradable_entry_ids: set[str] = set()
    ordering: dict[tuple[tuple[str, str, str], str], _OrderingBaseline] = {}
    ordering_epochs: dict[tuple[str, str], int] = {}
    page_scopes: dict[tuple[str, str, str], _PageBaseline] = {}
    partition_principals: dict[str, tuple[str, int]] = {}
    conflicted_partitions: set[str] = set()
    ordering_partition_principals: dict[str, str] = {}
    ordering_conflicted_partitions: set[str] = set()
    analyzed_events = 0
    limitations: set[str] = set()
    protocol_versions: set[str] = {trace.protocol_version}
    trace_version_supported = trace.protocol_version == CURRENT_PROTOCOL_VERSION

    if not trace_version_supported:
        collector.add(
            _finding(
                "MCPCACHE000",
                CacheSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Trace protocol version is unsupported",
                "trace",
                "unsupported_protocol_version",
                f"Use {CURRENT_PROTOCOL_VERSION} for current cache-contract analysis.",
                protocol_version=trace.protocol_version,
            )
        )
        limitations.add("unsupported protocol versions are not graded as safe")
    if not trace.trace_complete:
        collector.add(
            _finding(
                "MCPCACHE000",
                CacheSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Trace declares incomplete evidence",
                "trace",
                "trace_truncated_or_incomplete",
                "Provide a causally complete trace covering every relevant cache decision.",
            )
        )
        limitations.add("the trace declares that relevant evidence may be missing")

    ordered_events = sorted(trace.events, key=lambda event: event.sequence)
    clock_reliable = all(
        previous.at_ms <= current.at_ms
        for previous, current in zip(ordered_events, ordered_events[1:], strict=False)
    )
    if not clock_reliable:
        collector.add(
            _finding(
                "MCPCACHE000",
                CacheSeverity.UNKNOWN,
                RequirementLevel.UNKNOWN,
                "Logical clock conflicts with causal sequence",
                "trace",
                "clock_sequence_ambiguous",
                "Make at_ms nondecreasing in explicit sequence order.",
                event_sequences=[
                    event.sequence
                    for event in ordered_events
                    if event.at_ms
                    < max(
                        (prior.at_ms for prior in ordered_events if prior.sequence < event.sequence),
                        default=event.at_ms,
                    )
                ][:8],
            )
        )
        limitations.add("TTL and change-event timing could not be fully evaluated")

    for event in ordered_events:
        analyzed_events += 1
        if not isinstance(event, NotificationEvent):
            protocol_versions.add(event.request.protocol_version)
        if not trace_version_supported:
            continue

        cursor_shapes_valid = True
        response_metadata: tuple[str | None, int | None] | None = None
        response_expires_at_ms: int | None = None
        source: _Entry | None = None
        source_state_eligible = True
        if isinstance(event, NotificationEvent):
            if not event.subscription_validated:
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Notification subscription validity is unverified",
                        _event_target(event.sequence),
                        "notification_subscription_unverified",
                        "Set subscription_validated only from a normalized, acknowledged subscription trace.",
                        event_sequences=[event.sequence],
                    )
                )
                continue
            if event.method not in LIST_NOTIFICATION_METHODS and event.method != RESOURCE_UPDATED:
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Notification method is outside the supported cache mapping",
                        _event_target(event.sequence),
                        "unsupported_notification_method",
                        "Use a current MCP list-change or exact resource-updated notification.",
                        event_sequences=[event.sequence],
                    )
                )
                continue
            if event.method == RESOURCE_UPDATED and (
                not isinstance(event.params.get("uri"), str) or not event.params["uri"]
            ):
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Resource-updated notification URI is missing or malformed",
                        _event_target(event.sequence),
                        "resource_notification_uri_unverified",
                        "Provide the non-empty resource URI carried by the current notification.",
                        event_sequences=[event.sequence],
                    )
                )
                continue
        else:
            request = event.request
            if request.protocol_version != CURRENT_PROTOCOL_VERSION:
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Event protocol version is unsupported",
                        _event_target(event.sequence),
                        "unsupported_event_protocol_version",
                        f"Use {CURRENT_PROTOCOL_VERSION} for current cache-contract analysis.",
                        protocol_version=request.protocol_version,
                        event_sequences=[event.sequence],
                    )
                )
                limitations.add("one or more event protocol versions are unsupported")
                continue
            if request.method not in SUPPORTED_METHODS:
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Method is outside the list/read cache-auditor scope",
                        _event_target(event.sequence),
                        "unsupported_cacheable_method",
                        "Use a supported list/read method; server/discover remains an explicit coverage gap.",
                        event_sequences=[event.sequence],
                    )
                )
                limitations.add("server/discover and non-list/read methods are outside this auditor")
                continue
            if request.method == "resources/read":
                request_uri = request.params.get("uri")
                if not isinstance(request_uri, str) or not request_uri:
                    collector.add(
                        _finding(
                            "MCPCACHE000",
                            CacheSeverity.UNKNOWN,
                            RequirementLevel.UNKNOWN,
                            "Resource-read request URI is missing or malformed",
                            _event_target(event.sequence),
                            "resource_request_uri_unverified",
                            "Provide the non-empty resource URI used by the current resources/read request.",
                            event_sequences=[event.sequence],
                        )
                    )
                    continue
            if isinstance(event, (ResponseEvent, RefreshEvent)) and _contains_mrtr_retry(request):
                collector.add(
                    _finding(
                        "MCPCACHE009",
                        CacheSeverity.HIGH,
                        RequirementLevel.PROTOCOL_MUST,
                        "A multi-round-trip retry result was cached",
                        _event_target(event.sequence),
                        "mrtr_retry_result_cached",
                        "Do not cache results from requests carrying inputResponses or requestState.",
                        event_sequences=[event.sequence],
                    )
                )
            if isinstance(event, (ResponseEvent, RefreshEvent)):
                response_metadata = _validate_response_metadata(event, collector)
            cursor_shapes_valid = _validate_pagination_cursor_shapes(event, collector)
            if not cursor_shapes_valid:
                limitations.add("one or more list pagination cursor shapes were malformed")
                continue
            if isinstance(event, (ResponseEvent, RefreshEvent)):
                assert response_metadata is not None
                _, response_ttl_ms = response_metadata
                if response_ttl_ms is not None and clock_reliable:
                    if event.at_ms <= MAX_LOGICAL_MS - response_ttl_ms:
                        response_expires_at_ms = event.at_ms + response_ttl_ms
                    else:
                        collector.add(
                            _finding(
                                "MCPCACHE000",
                                CacheSeverity.UNKNOWN,
                                RequirementLevel.SIMULATOR_POLICY,
                                "Expiry exceeds the bounded logical-clock model",
                                _event_target(event.sequence),
                                "expiry_outside_simulator_clock",
                                ("Use receipt time and TTL values whose sum remains in the clock range."),
                                event_sequences=[event.sequence],
                            )
                        )
            if isinstance(event, (RefreshEvent, RefreshErrorEvent, UseEvent)):
                source = entries.get(event.source_event_id)
                if source is None and event.source_event_id in ungradable_entry_ids:
                    continue
                if source is None or source.event.sequence >= event.sequence:
                    if isinstance(event, RefreshEvent):
                        title = "Refresh source is missing or non-causal"
                        evidence = "refresh_source_unverified"
                        remediation = "Reference an earlier retained response or refresh event."
                    else:
                        title = "Cache source is missing or non-causal"
                        evidence = "cache_source_unverified"
                        remediation = "Reference an earlier retained response or refresh event."
                    collector.add(
                        _finding(
                            "MCPCACHE000",
                            CacheSeverity.UNKNOWN,
                            RequirementLevel.UNKNOWN,
                            title,
                            _event_target(event.sequence),
                            evidence,
                            remediation,
                            event_sequences=[event.sequence],
                        )
                    )
                    continue
                if source.scope is None:
                    continue
                source_state_eligible = source.ttl_ms is not None and source.expires_at_ms is not None

        if isinstance(event, NotificationEvent):
            event_principal = event.principal
            event_partition = event.cache_partition
        else:
            event_principal = event.request.principal
            event_partition = event.request.cache_partition
        prior_partition_principal = partition_principals.get(event_partition)
        partition_mapping_consistent = (
            event_partition not in conflicted_partitions
            and prior_partition_principal is not None
            and prior_partition_principal[0] == event_principal
        )
        partition_state_eligible = source_state_eligible and (
            not isinstance(event, (ResponseEvent, RefreshEvent))
            or (
                response_metadata is not None
                and response_metadata[0] is not None
                and response_metadata[1] is not None
                and response_expires_at_ms is not None
            )
        )
        if partition_state_eligible:
            if event_partition not in conflicted_partitions and prior_partition_principal is None:
                partition_principals[event_partition] = (event_principal, event.sequence)
                partition_mapping_consistent = True
            elif (
                event_partition not in conflicted_partitions
                and prior_partition_principal is not None
                and prior_partition_principal[0] != event_principal
            ):
                partition_mapping_consistent = False
                conflicted_partitions.add(event_partition)
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Principal labels conflict within one asserted authorization partition",
                        _event_target(event.sequence),
                        "authorization_partition_mapping_ambiguous",
                        "Use consistent principal labels or distinct authorization-context partitions.",
                        event_sequences=[prior_partition_principal[1], event.sequence],
                    )
                )
                limitations.add("one or more authorization-partition assertions were ambiguous")

        if isinstance(event, NotificationEvent):
            for entry in entries.values():
                relevant = _notification_relevant(entry, event)
                if relevant is None:
                    collector.add(
                        _finding(
                            "MCPCACHE000",
                            CacheSeverity.UNKNOWN,
                            RequirementLevel.UNKNOWN,
                            "Notification relevance cannot be established",
                            _event_target(event.sequence),
                            "notification_relevance_unknown",
                            "Provide an exact supported method and resource URI relationship.",
                            event_sequences=[entry.event.sequence, event.sequence],
                        )
                    )
                    continue
                if not relevant:
                    continue
                if entry.scope is None:
                    continue
                if entry.scope == "private" and not partition_mapping_consistent:
                    continue
                if entry.scope == "private" and (
                    entry.event.request.cache_partition != event.cache_partition
                ):
                    continue
                if entry.scope == "public":
                    entry.invalidated_globally = event.sequence
                    ordering_partition = "public"
                else:
                    entry.invalidated_partitions[event.cache_partition] = event.sequence
                    ordering_partition = event.cache_partition
                ordering_epoch_key = (entry.event.request.method, ordering_partition)
                ordering_epochs[ordering_epoch_key] = ordering_epochs.get(ordering_epoch_key, 0) + 1
            continue

        request = event.request

        if isinstance(event, (ResponseEvent, RefreshEvent)):
            assert response_metadata is not None
            scope, ttl_ms = response_metadata
            try:
                key = _request_key(request)
            except (TypeError, ValueError):
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.UNKNOWN,
                        "Request key cannot be canonicalized",
                        _event_target(event.sequence),
                        "request_key_unverifiable",
                        "Use bounded JSON request parameters without non-finite numbers.",
                        event_sequences=[event.sequence],
                    )
                )
                continue

            if isinstance(event, RefreshEvent):
                assert source is not None
                if source.key != key:
                    collector.add(
                        _finding(
                            "MCPCACHE004",
                            CacheSeverity.HIGH,
                            RequirementLevel.PROTOCOL_MUST,
                            "Refresh crossed a request cache key",
                            _event_target(event.sequence),
                            "refresh_request_key_mismatch",
                            "Bind refreshes to the same protocol version, method, and parameters.",
                            event_sequences=[source.event.sequence, event.sequence],
                        )
                    )
                if (
                    source.scope == "private"
                    and source.event.request.cache_partition != request.cache_partition
                ):
                    collector.add(
                        _finding(
                            "MCPCACHE003",
                            CacheSeverity.HIGH,
                            RequirementLevel.PROTOCOL_MUST,
                            "Private cache entry crossed an authorization partition during refresh",
                            _event_target(event.sequence),
                            "private_cross_partition_refresh",
                            "Refresh private entries only inside their asserted authorization partition.",
                            event_sequences=[source.event.sequence, event.sequence],
                        )
                    )
                elif (
                    ((source.scope == "public" and scope == "public") or partition_mapping_consistent)
                    and source.key == key
                    and _is_valid_successful_refresh(
                        event,
                        scope,
                        ttl_ms,
                        cursor_shapes_valid,
                    )
                ):
                    partition_key = "public" if source.scope == "public" else request.cache_partition
                    source.successful_refreshes[partition_key] = event.sequence

            if scope is None:
                ungradable_entry_ids.add(event.event_id)
                continue

            if len(entries) >= MAX_RETAINED_ENTRIES:
                collector.add(
                    _finding(
                        "MCPCACHE000",
                        CacheSeverity.UNKNOWN,
                        RequirementLevel.SIMULATOR_POLICY,
                        "Retained cache entries exceed the simulator bound",
                        _event_target(event.sequence),
                        "retained_entry_limit_exceeded",
                        "Split the trace while preserving complete causal evidence.",
                        event_sequences=[event.sequence],
                    )
                )
                limitations.add("later cache entries were not retained")
                continue

            entry = _Entry(
                event=event,
                key=key,
                scope=scope,
                ttl_ms=ttl_ms,
                expires_at_ms=response_expires_at_ms,
            )
            entries[event.event_id] = entry

            if (
                event.page_group is not None
                and request.method in LIST_METHODS
                and scope is not None
                and cursor_shapes_valid
            ):
                page_key = (
                    request.protocol_version,
                    request.method,
                    event.page_group,
                )
                prior_page = page_scopes.get(page_key)
                base_params = _page_base_params(request)
                if prior_page is not None:
                    identity_matches = (
                        prior_page.principal == request.principal
                        and prior_page.cache_partition == request.cache_partition
                        and prior_page.base_params == base_params
                    )
                    if not identity_matches:
                        collector.add(
                            _finding(
                                "MCPCACHE000",
                                CacheSeverity.UNKNOWN,
                                RequirementLevel.UNKNOWN,
                                "Linked page-chain request identity is inconsistent",
                                _event_target(event.sequence),
                                "page_chain_request_identity_ambiguous",
                                (
                                    "Use one principal, authorization partition, and non-cursor "
                                    "parameter set for an explicitly linked page chain."
                                ),
                                event_sequences=[prior_page.event_sequence, event.sequence],
                            )
                        )
                    elif prior_page.scope != scope:
                        collector.add(
                            _finding(
                                "MCPCACHE008",
                                CacheSeverity.HIGH,
                                RequirementLevel.PROTOCOL_MUST,
                                "Paginated list pages use inconsistent cache scopes",
                                _event_target(event.sequence),
                                "page_chain_cache_scope_mismatch",
                                ("Use one cacheScope for every page in the explicitly linked list request."),
                                event_sequences=[prior_page.event_sequence, event.sequence],
                            )
                        )
                else:
                    page_scopes[page_key] = _PageBaseline(
                        scope=scope,
                        event_sequence=event.sequence,
                        principal=request.principal,
                        cache_partition=request.cache_partition,
                        base_params=base_params,
                    )

            ordering_partition_consistent = scope == "public"
            if scope == "private":
                prior_ordering_principal = ordering_partition_principals.get(request.cache_partition)
                established_partition_principal = partition_principals.get(request.cache_partition)
                if established_partition_principal is not None:
                    if prior_ordering_principal is None:
                        prior_ordering_principal = established_partition_principal[0]
                        ordering_partition_principals[request.cache_partition] = prior_ordering_principal
                    elif prior_ordering_principal != established_partition_principal[0]:
                        ordering_conflicted_partitions.add(request.cache_partition)
                ordering_partition_consistent = (
                    request.cache_partition not in conflicted_partitions
                    and request.cache_partition not in ordering_conflicted_partitions
                    and prior_ordering_principal == request.principal
                )
                if (
                    request.cache_partition not in conflicted_partitions
                    and request.cache_partition not in ordering_conflicted_partitions
                ):
                    if prior_ordering_principal is None:
                        ordering_partition_principals[request.cache_partition] = request.principal
                        ordering_partition_consistent = True
                    elif prior_ordering_principal != request.principal:
                        ordering_conflicted_partitions.add(request.cache_partition)
                        ordering_partition_consistent = False

            if (
                request.method == "tools/list"
                and "cursor" not in request.params
                and "nextCursor" not in event.result
                and scope is not None
                and ordering_partition_consistent
            ):
                ordering_items = _ordering_items(event.result)
                if ordering_items is not None:
                    partition_key = "public" if scope == "public" else request.cache_partition
                    epoch = ordering_epochs.get((request.method, partition_key), 0)
                    baseline_key = (key, partition_key)
                    baseline = ordering.get(baseline_key)
                    if (
                        baseline is not None
                        and baseline.epoch == epoch
                        and baseline.item_multiset == ordering_items[1]
                        and baseline.ordered_items != ordering_items[0]
                    ):
                        collector.add(
                            _finding(
                                "MCPCACHE006",
                                CacheSeverity.MEDIUM,
                                RequirementLevel.PROTOCOL_SHOULD,
                                "Stable tools list changed deterministic order",
                                _event_target(event.sequence),
                                "tools_list_order_drift",
                                "Return an unchanged unpaginated tool set in the same deterministic order.",
                                event_sequences=[baseline.event_sequence, event.sequence],
                            )
                        )
                    ordering[baseline_key] = _OrderingBaseline(
                        ordered_items=ordering_items[0],
                        item_multiset=ordering_items[1],
                        event_sequence=event.sequence,
                        epoch=epoch,
                    )
            continue

        assert source is not None
        if (
            source.scope == "private"
            and source.event.request.cache_partition == request.cache_partition
            and partition_state_eligible
            and not partition_mapping_consistent
        ):
            continue
        try:
            use_key = _request_key(request)
        except (TypeError, ValueError):
            collector.add(
                _finding(
                    "MCPCACHE000",
                    CacheSeverity.UNKNOWN,
                    RequirementLevel.UNKNOWN,
                    "Request key cannot be canonicalized",
                    _event_target(event.sequence),
                    "request_key_unverifiable",
                    "Use bounded JSON request parameters without non-finite numbers.",
                    event_sequences=[event.sequence],
                )
            )
            continue
        key_matches = source.key == use_key
        if not key_matches:
            collector.add(
                _finding(
                    "MCPCACHE004",
                    CacheSeverity.HIGH,
                    RequirementLevel.PROTOCOL_MUST,
                    "Cached result crossed a request cache key",
                    _event_target(event.sequence),
                    "cache_request_key_mismatch",
                    "Bind reuse to the same protocol version, method, and result-affecting parameters.",
                    event_sequences=[source.event.sequence, event.sequence],
                )
            )
        if isinstance(event, RefreshErrorEvent):
            same_private_partition = (
                source.scope != "private" or source.event.request.cache_partition == request.cache_partition
            )
            consistent_private_principal = (
                source.scope != "private" or source.event.request.principal == request.principal
            )
            if source.scope == "private" and not same_private_partition:
                collector.add(
                    _finding(
                        "MCPCACHE003",
                        CacheSeverity.HIGH,
                        RequirementLevel.PROTOCOL_MUST,
                        "Private cache entry crossed an authorization partition during failed refresh",
                        _event_target(event.sequence),
                        "private_cross_partition_refresh_error",
                        (
                            "Associate private refresh failures only with their asserted "
                            "authorization partition."
                        ),
                        event_sequences=[source.event.sequence, event.sequence],
                    )
                )
            if (
                source_state_eligible
                and key_matches
                and same_private_partition
                and consistent_private_principal
                and (source.scope == "public" or partition_mapping_consistent)
            ):
                partition_key = "public" if source.scope == "public" else request.cache_partition
                source.refresh_errors.setdefault(partition_key, []).append((event.sequence, event.at_ms))
            continue

        if source.scope == "private":
            if source.event.request.cache_partition != request.cache_partition:
                collector.add(
                    _finding(
                        "MCPCACHE003",
                        CacheSeverity.HIGH,
                        RequirementLevel.PROTOCOL_MUST,
                        "Private cache entry crossed an authorization partition",
                        _event_target(event.sequence),
                        "private_cross_partition_reuse",
                        "Partition private entries by the complete authorization context.",
                        event_sequences=[source.event.sequence, event.sequence],
                    )
                )
        if not source_state_eligible:
            continue

        invalidated_at = (
            source.invalidated_globally
            if source.scope == "public"
            else source.invalidated_partitions.get(request.cache_partition)
        )
        notification_stale_allowed = _refresh_error_allows_notification_stale(
            source,
            event,
            invalidated_at,
        )
        if invalidated_at is not None and invalidated_at < event.sequence and not notification_stale_allowed:
            collector.add(
                _finding(
                    "MCPCACHE007",
                    CacheSeverity.MEDIUM,
                    RequirementLevel.PROTOCOL_CONTRACT,
                    "Cached result was used after a relevant change notification",
                    _event_target(event.sequence),
                    "use_after_normative_invalidation",
                    "Refresh the exact invalidated entry before its next use.",
                    event_sequences=[source.event.sequence, invalidated_at, event.sequence],
                    assumptions=["no unsuperseded recorded refresh error permits serving the stale response"],
                )
            )
        if (
            clock_reliable
            and source.expires_at_ms is not None
            and event.at_ms >= source.expires_at_ms
            and not _refresh_error_allows_ttl_stale(source, event, invalidated_at)
        ):
            collector.add(
                _finding(
                    "MCPCACHE005",
                    CacheSeverity.MEDIUM,
                    RequirementLevel.PROTOCOL_SHOULD,
                    "Cached result was used after its observable TTL",
                    _event_target(event.sequence),
                    "use_at_or_after_ttl_boundary",
                    "Re-fetch on access after expiry and record a valid refresh before reuse.",
                    event_sequences=[source.event.sequence, event.sequence],
                    assumptions=[
                        (
                            "the complete trace records no unsuperseded failed refresh "
                            "that permits stale serving"
                        )
                    ],
                )
            )

    findings = collector.finish()
    has_concrete = any(finding.severity != CacheSeverity.UNKNOWN for finding in findings)
    has_unknown = any(finding.severity == CacheSeverity.UNKNOWN for finding in findings)
    if has_concrete:
        verdict: str = "fail"
        claim: str = "supplied_trace_violates_observable_contract"
    elif has_unknown:
        verdict = "unknown"
        claim = "supplied_trace_contract_unknown"
    else:
        verdict = "pass"
        claim = "supplied_trace_satisfies_observable_contract"

    coverage_state: str
    if has_unknown or not trace.trace_complete:
        coverage_state = "incomplete"
    else:
        coverage_state = "complete"
    input_state: Literal["valid", "malformed", "unsupported"]
    if any(version != CURRENT_PROTOCOL_VERSION for version in protocol_versions):
        input_state = "unsupported"
    else:
        input_state = "valid"
    return CacheAuditReport(
        schema_version=REPORT_SCHEMA,
        trace_schema_version=TRACE_SCHEMA,
        trace_digest_sha256=_trace_digest(trace),
        protocol_versions=sorted(protocol_versions),
        verdict=verdict,  # type: ignore[arg-type]
        coverage=CacheCoverage(
            state=coverage_state,  # type: ignore[arg-type]
            input_state=input_state,
            total_events=len(trace.events),
            analyzed_events=analyzed_events,
            retained_entries=len(entries),
            limitations=sorted(limitations),
        ),
        findings=findings,
        assumptions=REPORT_ASSUMPTIONS,
        claim=claim,  # type: ignore[arg-type]
    )


def report_json_bytes(report: CacheAuditReport) -> bytes:
    """Serialize a cache report in the canonical output contract."""

    return canonical_json_bytes(report)
