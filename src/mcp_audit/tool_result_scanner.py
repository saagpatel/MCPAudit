"""Offline evaluation of paired MCP ``tools/list`` and ``tools/call`` fixtures."""

from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import signal
import stat
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Never
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import ValidationError

from mcp_audit.tool_result_models import (
    CURRENT_PROTOCOL_REVISION,
    CallExchange,
    ChannelPolicy,
    ToolResultFinding,
    ToolResultFixture,
    ToolResultReport,
    ToolResultRuleId,
    ToolResultSeverity,
    canonical_json_bytes,
    sha256_bytes,
)

_MAX_INPUT_BYTES = 1_048_576
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 16_384
_MAX_STRING_BYTES = 65_536
_MAX_SCHEMA_DEPTH = 32
_MAX_SCHEMA_NODES = 1_024
_MAX_SCHEMA_REFERENCES = 128
_MAX_SCHEMA_BRANCHES = 128
_MAX_VALIDATION_SECONDS = 1.0
_MAX_CONTENT_BLOCKS = 64
_MAX_RESOURCE_BYTES = 262_144
_MAX_URI_BYTES = 4_096

_DRAFT_2020_12_URIS = {
    "https://json-schema.org/draft/2020-12/schema",
    "https://json-schema.org/draft/2020-12/schema#",
}
_SCHEMA_BRANCH_KEYS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_REFERENCE_KEYS = {"$ref", "$dynamicRef"}
_UNSUPPORTED_SCHEMA_KEYS = {"pattern", "patternProperties", "$recursiveRef", "$recursiveAnchor"}

_SUPPORTED_INPUTS = [
    "One strict program-owned mcpaudit.tool-result.fixture.v1 JSON document.",
    f"Paired tools/list and tools/call JSON-RPC evidence evaluated as MCP {CURRENT_PROTOCOL_REVISION}.",
    "JSON Schema 2020-12 output schemas without regex keywords, external references, or custom vocabularies.",
]

_UNSUPPORTED_INPUTS = [
    "Live MCP connections, server discovery, tool execution, raw logs, transcripts, "
    "credentials, and private data.",
    "Protocol revisions other than 2026-07-28 and forward resultType extensions.",
    "Network or filesystem schema references, regex validation, custom vocabularies, "
    "and over-budget schemas.",
    "Semantic truth, model behavior, authorization, UI safety, hidden-data absence, "
    "and production conformance.",
]

_CLAIM_CEILING = [
    "Findings apply only to observable fields in the supplied program-owned synthetic fixture.",
    "A pass does not prove that a tool result is truthful, authorized, safe, complete, "
    "or handled correctly by a host.",
    "Channel equivalence is evaluated only when the fixture declares a representation policy.",
    "Unsupported, malformed, truncated, missing, or resource-exhausted evidence remains UNKNOWN.",
]

_RULE_DETAILS: dict[ToolResultRuleId, tuple[ToolResultSeverity, str, str]] = {
    "MCPTR000": (
        ToolResultSeverity.UNKNOWN,
        "Coverage is incomplete or unsupported",
        "Supply complete evidence for the supported protocol revision and stay within documented bounds.",
    ),
    "MCPTR001": (
        ToolResultSeverity.HIGH,
        "Structured output violates its declared schema",
        "Return structuredContent that is present and valid against the declared outputSchema.",
    ),
    "MCPTR002": (
        ToolResultSeverity.HIGH,
        "Tool identity or call correlation is inconsistent",
        "Keep JSON-RPC IDs, declared tool names, and exposed tool-use identifiers consistently paired.",
    ),
    "MCPTR003": (
        ToolResultSeverity.HIGH,
        "Protocol result or error shape is invalid",
        "Emit the exact JSON-RPC and MCP result/error shape required by the evaluated revision.",
    ),
    "MCPTR004": (
        ToolResultSeverity.HIGH,
        "Content or resource channel shape is invalid",
        "Use valid bounded content/resource blocks and provide every explicitly required channel.",
    ),
    "MCPTR005": (
        ToolResultSeverity.MEDIUM,
        "Declared dual-channel representation contract is not established",
        "Declare independent channels or an exact JSON-equivalence policy and satisfy that policy.",
    ),
    "MCPTR006": (
        ToolResultSeverity.HIGH,
        "Application-only metadata reached a model-visible channel",
        "Keep application-only metadata in _meta and out of tool descriptions, content, "
        "and structuredContent.",
    ),
}

_META_NAME_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?)?$")
_META_LABEL_RE = re.compile(r"^[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")


class ToolResultInputError(ValueError):
    """The fixture could not be read safely."""


class _ValidationTimeout(RuntimeError):
    pass


class _SchemaUnsupported(ValueError):
    pass


@dataclass(frozen=True)
class _ToolDeclaration:
    index: int
    name: str
    output_schema: dict[str, Any] | None


def _finding(
    rule_id: ToolResultRuleId,
    target: str,
    evidence: str,
    *,
    severity_override: ToolResultSeverity | None = None,
) -> ToolResultFinding:
    severity, title, remediation = _RULE_DETAILS[rule_id]
    return ToolResultFinding(
        rule_id=rule_id,
        severity=severity_override or severity,
        title=title,
        target=target,
        evidence=[evidence],
        remediation=remediation,
    )


def _unknown_report(input_bytes: bytes, evidence: str) -> ToolResultReport:
    return ToolResultReport(
        fixtureId="unparseable",
        protocolRevision="unknown",
        inputSha256=sha256_bytes(input_bytes),
        verdict="unknown",
        coverage="incomplete",
        findings=[_finding("MCPTR000", "fixture", evidence)],
        supportedInputs=_SUPPORTED_INPUTS,
        unsupportedInputs=_UNSUPPORTED_INPUTS,
        claimCeiling=_CLAIM_CEILING,
    )


def _reject_json_constant(value: str) -> Never:
    raise ValueError(f"non-finite JSON constant is unsupported: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key is unsupported")
        result[key] = value
    return result


def _check_json_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON depth limit exceeded")
        if isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_STRING_BYTES:
                raise ValueError("JSON string size limit exceeded")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("non-finite JSON numbers are unsupported")
        elif isinstance(item, Mapping):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError("JSON object keys must be strings")
                if len(key.encode("utf-8")) > _MAX_STRING_BYTES:
                    raise ValueError("JSON key size limit exceeded")
                stack.append((nested, depth + 1))
        elif isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)


def scan_tool_result_bytes(input_bytes: bytes) -> ToolResultReport:
    """Parse and evaluate one bounded program-owned fixture."""
    if len(input_bytes) > _MAX_INPUT_BYTES:
        return _unknown_report(input_bytes, "fixture exceeds the 1 MiB input limit")
    try:
        payload = json.loads(
            input_bytes.decode("utf-8"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
        _check_json_bounds(payload)
        fixture = ToolResultFixture.model_validate(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError):
        return _unknown_report(input_bytes, "fixture failed strict bounded JSON parsing")

    evaluator = _Evaluator(fixture)
    findings = evaluator.evaluate()
    findings.sort(key=lambda item: (item.rule_id, item.target, item.evidence))
    has_failure = any(item.severity != ToolResultSeverity.UNKNOWN for item in findings)
    has_unknown = any(item.severity == ToolResultSeverity.UNKNOWN for item in findings)
    verdict: Literal["pass", "fail", "unknown"] = (
        "fail" if has_failure else "unknown" if has_unknown else "pass"
    )
    coverage: Literal["complete", "incomplete", "unsupported"] = "incomplete" if has_unknown else "complete"
    if fixture.protocol_revision != CURRENT_PROTOCOL_REVISION:
        coverage = "unsupported"
    report_fixture_id = fixture.fixture_id
    private_values = _fixture_private_metadata_values(fixture)
    if any(value in report_fixture_id for value in private_values):
        report_fixture_id = "redacted"
    return ToolResultReport(
        fixtureId=report_fixture_id,
        protocolRevision=fixture.protocol_revision,
        inputSha256=sha256_bytes(input_bytes),
        verdict=verdict,
        coverage=coverage,
        findings=findings,
        supportedInputs=_SUPPORTED_INPUTS,
        unsupportedInputs=_UNSUPPORTED_INPUTS,
        claimCeiling=_CLAIM_CEILING,
    )


def scan_tool_result_path_with_identity(path: Path) -> tuple[ToolResultReport, tuple[int, int]]:
    """Read one identity-bound regular file and evaluate its captured bytes."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ToolResultInputError(f"cannot safely open fixture: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ToolResultInputError("fixture must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            input_bytes = handle.read(_MAX_INPUT_BYTES + 1)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ToolResultInputError("fixture identity changed during the read")
        report = scan_tool_result_bytes(input_bytes)
        return report, (before.st_dev, before.st_ino)
    finally:
        os.close(descriptor)


class _Evaluator:
    def __init__(self, fixture: ToolResultFixture) -> None:
        self.fixture = fixture
        self.findings: list[ToolResultFinding] = []
        self.tools: dict[str, _ToolDeclaration] = {}
        self.list_complete = False
        self.model_visible_values: list[Any] = []

    def evaluate(self) -> list[ToolResultFinding]:
        if self.fixture.protocol_revision != CURRENT_PROTOCOL_REVISION:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    "protocolRevision",
                    "the selected MCP revision is unsupported by this auditor version",
                )
            )
            return self.findings
        self._evaluate_tools_list()
        if not self.fixture.calls:
            self.findings.append(_finding("MCPTR000", "calls", "no tools/call evidence was supplied"))
        for index, call in enumerate(self.fixture.calls):
            self._evaluate_call(index, call)
        self._evaluate_metadata_policy()
        return self.findings

    def _evaluate_tools_list(self) -> None:
        exchange = self.fixture.tools_list
        if exchange is None:
            self.findings.append(_finding("MCPTR000", "toolsList", "tools/list evidence is missing"))
            return
        request_id, request_ok = self._validate_request(
            exchange.request,
            method="tools/list",
            target="toolsList.request",
        )
        response = exchange.response
        result, error, response_id, response_ok = self._response_parts(
            response,
            target="toolsList.response",
        )
        self._check_rpc_correlation(request_id, response_id, "toolsList")
        if not request_ok or not response_ok:
            return
        if error is not None:
            if self._validate_error(error, "toolsList.response.error"):
                self.findings.append(
                    _finding(
                        "MCPTR000",
                        "toolsList.response",
                        "tools/list returned a protocol error so declaration coverage is incomplete",
                    )
                )
            return
        if result is None:
            return
        allowed = {
            "resultType",
            "tools",
            "nextCursor",
            "ttlMs",
            "cacheScope",
            "_meta",
        }
        extra = set(result) - allowed
        if extra:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    "toolsList.response.result",
                    "the list result contains unsupported extension fields",
                )
            )
        if result.get("resultType") != "complete":
            self.findings.append(
                _finding(
                    "MCPTR003",
                    "toolsList.response.result.resultType",
                    "MCP 2026-07-28 tools/list requires resultType complete",
                )
            )
        if not _is_nonnegative_number(result.get("ttlMs")):
            self.findings.append(
                _finding(
                    "MCPTR003",
                    "toolsList.response.result.ttlMs",
                    "MCP 2026-07-28 list results require a non-negative ttlMs",
                )
            )
        if result.get("cacheScope") not in {"public", "private"}:
            self.findings.append(
                _finding(
                    "MCPTR003",
                    "toolsList.response.result.cacheScope",
                    "MCP 2026-07-28 list results require public or private cacheScope",
                )
            )
        if "nextCursor" in result and not isinstance(result["nextCursor"], str):
            self.findings.append(
                _finding(
                    "MCPTR003",
                    "toolsList.response.result.nextCursor",
                    "nextCursor must be a string when present",
                )
            )
        self._validate_meta(result.get("_meta"), "toolsList.response.result._meta")
        paginated = (
            exchange.request.get("params", {}).get("cursor") is not None
            or result.get("nextCursor") is not None
        )
        if paginated:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    "toolsList",
                    "one paginated tools/list page cannot establish complete declaration coverage",
                )
            )
        tools = result.get("tools")
        if not isinstance(tools, list):
            self.findings.append(
                _finding(
                    "MCPTR000",
                    "toolsList.response.result.tools",
                    "the required tools array is missing or malformed",
                )
            )
            return
        self.list_complete = not paginated
        for index, tool in enumerate(tools):
            self._validate_tool(index, tool)
        self.model_visible_values.extend(_strip_meta(tool) for tool in tools)

    def _validate_tool(self, index: int, value: Any) -> None:
        target = f"toolsList.response.result.tools[{index}]"
        if not isinstance(value, dict):
            self.findings.append(_finding("MCPTR003", target, "tool declaration is not an object"))
            return
        allowed = {
            "name",
            "title",
            "description",
            "inputSchema",
            "outputSchema",
            "annotations",
            "icons",
            "_meta",
        }
        if set(value) - allowed:
            self.findings.append(_finding("MCPTR003", target, "tool declaration contains unsupported fields"))
        name = value.get("name")
        input_schema = value.get("inputSchema")
        if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 256:
            self.findings.append(_finding("MCPTR003", f"{target}.name", "tool name is missing or invalid"))
            return
        if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
            self.findings.append(
                _finding(
                    "MCPTR003",
                    f"{target}.inputSchema",
                    "MCP 2026-07-28 requires an object-root inputSchema",
                )
            )
        for field in ("title", "description"):
            if field in value and not isinstance(value[field], str):
                self.findings.append(
                    _finding(
                        "MCPTR003",
                        f"{target}.{field}",
                        f"tool {field} must be a string when present",
                    )
                )
        self._validate_tool_annotations(value.get("annotations"), f"{target}.annotations")
        self._validate_icons(value.get("icons"), f"{target}.icons")
        self._validate_meta(value.get("_meta"), f"{target}._meta")
        output_schema = value.get("outputSchema")
        if output_schema is not None and not isinstance(output_schema, dict):
            self.findings.append(
                _finding("MCPTR001", f"{target}.outputSchema", "outputSchema is not a schema object")
            )
            output_schema = None
        if name in self.tools:
            self.findings.append(
                _finding(
                    "MCPTR002",
                    f"{target}.name",
                    "tools/list contains duplicate tool identities",
                )
            )
            return
        self.tools[name] = _ToolDeclaration(index=index, name=name, output_schema=output_schema)

    def _evaluate_call(self, index: int, call: CallExchange) -> None:
        target = f"calls[{index}]"
        request_id, request_ok = self._validate_request(
            call.request,
            method="tools/call",
            target=f"{target}.request",
        )
        tool_name: str | None = None
        params = call.request.get("params") if isinstance(call.request, dict) else None
        if isinstance(params, dict) and isinstance(params.get("name"), str):
            tool_name = params["name"]
        if request_ok and tool_name is not None and self.list_complete and tool_name not in self.tools:
            self.findings.append(
                _finding(
                    "MCPTR002",
                    f"{target}.request.params.name",
                    "tools/call names a tool absent from the paired tools/list evidence",
                )
            )
        correlation = call.tool_use_correlation
        if correlation is not None:
            if correlation.tool_use_id != correlation.result_tool_use_id:
                self.findings.append(
                    _finding(
                        "MCPTR002",
                        f"{target}.toolUseCorrelation",
                        "the exposed tool-use identifier does not match its result identifier",
                    )
                )
            if tool_name is not None and correlation.tool_name != tool_name:
                self.findings.append(
                    _finding(
                        "MCPTR002",
                        f"{target}.toolUseCorrelation.toolName",
                        "the exposed tool-use name does not match tools/call",
                    )
                )

        result, error, response_id, response_ok = self._response_parts(
            call.response,
            target=f"{target}.response",
        )
        self._check_rpc_correlation(request_id, response_id, target)
        if not request_ok or not response_ok:
            return
        if error is not None:
            self._validate_error(error, f"{target}.response.error")
            self.model_visible_values.append(_strip_meta(error))
            return
        if result is None:
            return
        result_type = result.get("resultType")
        if result_type == "input_required":
            if not result.get("inputRequests") and not result.get("requestState"):
                self.findings.append(
                    _finding(
                        "MCPTR003",
                        f"{target}.response.result",
                        "input_required must include inputRequests or requestState",
                    )
                )
            self.findings.append(
                _finding(
                    "MCPTR000",
                    f"{target}.response.result",
                    "input_required payload semantics are outside this auditor version",
                )
            )
            return
        if result_type != "complete":
            rule: ToolResultRuleId = "MCPTR003" if result_type is None else "MCPTR000"
            evidence = (
                "MCP 2026-07-28 complete tool results require resultType"
                if result_type is None
                else "the resultType extension is not supported"
            )
            self.findings.append(_finding(rule, f"{target}.response.result.resultType", evidence))
            return

        allowed = {"resultType", "content", "structuredContent", "isError", "_meta"}
        if set(result) - allowed:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    f"{target}.response.result",
                    "the complete result contains unsupported extension fields",
                )
            )
        if "isError" in result and not isinstance(result["isError"], bool):
            self.findings.append(
                _finding(
                    "MCPTR003",
                    f"{target}.response.result.isError",
                    "isError must be a boolean when present",
                )
            )
        self._validate_meta(result.get("_meta"), f"{target}.response.result._meta")
        content = result.get("content")
        channels: set[str] = set()
        if not isinstance(content, list):
            self.findings.append(
                _finding(
                    "MCPTR003",
                    f"{target}.response.result.content",
                    "complete tool results require a content array",
                )
            )
            content = []
        elif len(content) > _MAX_CONTENT_BLOCKS:
            channels.add("content")
            self.findings.append(
                _finding(
                    "MCPTR000",
                    f"{target}.response.result.content",
                    "content block count exceeds the supported limit",
                )
            )
        else:
            channels.add("content")
            resource_bytes = 0
            for content_index, block in enumerate(content):
                block_channels, block_bytes = self._validate_content_block(
                    block,
                    f"{target}.response.result.content[{content_index}]",
                )
                channels.update(block_channels)
                resource_bytes += block_bytes
            if resource_bytes > _MAX_RESOURCE_BYTES:
                self.findings.append(
                    _finding(
                        "MCPTR000",
                        f"{target}.response.result.content",
                        "decoded resource payloads exceed the 256 KiB per-call limit",
                    )
                )

        has_structured = "structuredContent" in result
        if has_structured:
            channels.add("structuredContent")
        declaration = self.tools.get(tool_name) if tool_name is not None else None
        if declaration is not None and declaration.output_schema is not None:
            if not has_structured:
                self.findings.append(
                    _finding(
                        "MCPTR001",
                        f"{target}.response.result.structuredContent",
                        "a declared outputSchema requires structuredContent",
                    )
                )
            else:
                self._validate_structured_output(
                    declaration.output_schema,
                    result["structuredContent"],
                    f"{target}.response.result.structuredContent",
                )
        self._evaluate_channel_policy(call.channel_policy, content, result, channels, target)
        self.model_visible_values.append(
            {
                "content": _strip_meta(content),
                "structuredContent": _strip_meta(result.get("structuredContent")) if has_structured else None,
            }
        )

    def _validate_request(
        self,
        value: Any,
        *,
        method: str,
        target: str,
    ) -> tuple[str | int | None, bool]:
        if not isinstance(value, dict):
            self.findings.append(_finding("MCPTR003", target, "JSON-RPC request is not an object"))
            return None, False
        if set(value) != {"jsonrpc", "id", "method", "params"}:
            self.findings.append(
                _finding("MCPTR003", target, "JSON-RPC request fields do not match the current shape")
            )
            return _request_id(value.get("id")), False
        request_id = _request_id(value.get("id"))
        valid = True
        if value.get("jsonrpc") != "2.0" or request_id is None or value.get("method") != method:
            self.findings.append(_finding("MCPTR003", target, "JSON-RPC version, id, or method is invalid"))
            valid = False
        params = value.get("params")
        if not isinstance(params, dict):
            self.findings.append(_finding("MCPTR003", f"{target}.params", "params is not an object"))
            return request_id, False
        allowed = (
            {"_meta", "cursor"}
            if method == "tools/list"
            else {
                "_meta",
                "name",
                "arguments",
                "inputResponses",
                "requestState",
            }
        )
        if set(params) - allowed:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    f"{target}.params",
                    "request params contain unsupported extension fields",
                )
            )
        if method == "tools/list" and "cursor" in params and not isinstance(params["cursor"], str):
            self.findings.append(_finding("MCPTR003", f"{target}.params.cursor", "cursor must be a string"))
            valid = False
        if method == "tools/call":
            if not isinstance(params.get("name"), str) or not params["name"]:
                self.findings.append(
                    _finding("MCPTR003", f"{target}.params.name", "tool name is missing or invalid")
                )
                valid = False
            if "arguments" in params and not isinstance(params["arguments"], dict):
                self.findings.append(
                    _finding("MCPTR003", f"{target}.params.arguments", "arguments must be an object")
                )
                valid = False
        meta = params.get("_meta")
        if not self._validate_request_meta(meta, f"{target}.params._meta"):
            valid = False
        return request_id, valid

    def _validate_request_meta(self, value: Any, target: str) -> bool:
        if not self._validate_meta(value, target, required=True):
            return False
        assert isinstance(value, dict)
        valid = True
        if value.get("io.modelcontextprotocol/protocolVersion") != CURRENT_PROTOCOL_REVISION:
            self.findings.append(
                _finding(
                    "MCPTR003",
                    target,
                    "request metadata does not bind the evaluated protocol revision",
                )
            )
            valid = False
        if not isinstance(value.get("io.modelcontextprotocol/clientCapabilities"), dict):
            self.findings.append(
                _finding(
                    "MCPTR003",
                    target,
                    "request metadata lacks clientCapabilities",
                )
            )
            valid = False
        return valid

    def _validate_tool_annotations(self, value: Any, target: str) -> None:
        if value is None:
            return
        allowed = {
            "title",
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        }
        if not isinstance(value, dict) or set(value) - allowed:
            self.findings.append(_finding("MCPTR003", target, "tool annotations shape is invalid"))
            return
        if "title" in value and not isinstance(value["title"], str):
            self.findings.append(_finding("MCPTR003", target, "annotation title must be a string"))
        for key in allowed - {"title"}:
            if key in value and not isinstance(value[key], bool):
                self.findings.append(_finding("MCPTR003", target, "tool annotation hints must be booleans"))
                break

    def _validate_icons(
        self,
        value: Any,
        target: str,
        *,
        rule_id: ToolResultRuleId = "MCPTR003",
    ) -> None:
        if value is None:
            return
        if not isinstance(value, list) or len(value) > 32:
            self.findings.append(_finding(rule_id, target, "icons shape is invalid"))
            return
        for icon in value:
            if not isinstance(icon, dict) or set(icon) - {"src", "mimeType", "sizes", "theme"}:
                self.findings.append(_finding(rule_id, target, "icon shape is invalid"))
                return
            if not _valid_uri(icon.get("src")):
                self.findings.append(_finding(rule_id, target, "icon src is invalid"))
                return
            if "mimeType" in icon and not isinstance(icon["mimeType"], str):
                self.findings.append(_finding(rule_id, target, "icon mimeType is invalid"))
                return
            if "sizes" in icon and (
                not isinstance(icon["sizes"], list)
                or any(not isinstance(size, str) for size in icon["sizes"])
            ):
                self.findings.append(_finding(rule_id, target, "icon sizes are invalid"))
                return
            if "theme" in icon and icon["theme"] not in {"light", "dark"}:
                self.findings.append(_finding(rule_id, target, "icon theme is invalid"))
                return

    def _validate_meta(self, value: Any, target: str, *, required: bool = False) -> bool:
        if value is None and not required:
            return True
        if not isinstance(value, dict):
            self.findings.append(_finding("MCPTR003", target, "_meta must be an object"))
            return False
        if any(not _valid_meta_key(key) for key in value):
            self.findings.append(_finding("MCPTR003", target, "_meta contains an invalid metadata key"))
            return False
        return True

    def _response_parts(
        self,
        value: Any,
        *,
        target: str,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | int | None, bool]:
        if not isinstance(value, dict):
            self.findings.append(_finding("MCPTR003", target, "JSON-RPC response is not an object"))
            return None, None, None, False
        has_result = "result" in value
        has_error = "error" in value
        allowed = (
            {"jsonrpc", "id", "result"}
            if has_result and not has_error
            else {
                "jsonrpc",
                "id",
                "error",
            }
        )
        if has_result == has_error or set(value) - allowed:
            self.findings.append(
                _finding(
                    "MCPTR003",
                    target,
                    "response must contain exactly one result or error with no unsupported fields",
                )
            )
            return None, None, _request_id(value.get("id")), False
        if value.get("jsonrpc") != "2.0":
            self.findings.append(_finding("MCPTR003", target, "response jsonrpc must be 2.0"))
            return None, None, _request_id(value.get("id")), False
        result = value.get("result")
        error = value.get("error")
        if has_result and not isinstance(result, dict):
            self.findings.append(_finding("MCPTR003", f"{target}.result", "result is not an object"))
            return None, None, _request_id(value.get("id")), False
        if has_error and not isinstance(error, dict):
            self.findings.append(_finding("MCPTR003", f"{target}.error", "error is not an object"))
            return None, None, _request_id(value.get("id")), False
        return result, error, _request_id(value.get("id")), True

    def _validate_error(self, error: dict[str, Any], target: str) -> bool:
        if set(error) - {"code", "message", "data"}:
            self.findings.append(_finding("MCPTR003", target, "JSON-RPC error contains unsupported fields"))
            return False
        code = error.get("code")
        message = error.get("message")
        if not isinstance(code, int) or isinstance(code, bool) or not isinstance(message, str) or not message:
            self.findings.append(
                _finding("MCPTR003", target, "JSON-RPC error requires integer code and message")
            )
            return False
        return True

    def _check_rpc_correlation(
        self,
        request_id: str | int | None,
        response_id: str | int | None,
        target: str,
    ) -> None:
        if request_id is None or response_id is None or request_id != response_id:
            self.findings.append(
                _finding(
                    "MCPTR002",
                    f"{target}.response.id",
                    "the response id does not match the paired request id",
                )
            )

    def _validate_content_block(self, value: Any, target: str) -> tuple[set[str], int]:
        if not isinstance(value, dict):
            self.findings.append(_finding("MCPTR004", target, "content block is not an object"))
            return set(), 0
        content_type = value.get("type")
        if content_type == "text":
            if not _exact_or_subset(value, {"type", "text", "annotations", "_meta"}):
                return self._bad_content(target, "text content contains unsupported fields")
            if not isinstance(value.get("text"), str):
                return self._bad_content(target, "text content requires a string")
            self._validate_annotations(value.get("annotations"), f"{target}.annotations")
            self._validate_meta(value.get("_meta"), f"{target}._meta")
            return {"text"}, 0
        if content_type in {"image", "audio"}:
            if not _exact_or_subset(value, {"type", "data", "mimeType", "annotations", "_meta"}):
                return self._bad_content(target, f"{content_type} content contains unsupported fields")
            if not isinstance(value.get("mimeType"), str) or not value["mimeType"]:
                return self._bad_content(target, f"{content_type} content requires mimeType")
            decoded = _decoded_base64_size(value.get("data"))
            if decoded is None:
                return self._bad_content(target, f"{content_type} data is not valid bounded base64")
            self._validate_annotations(value.get("annotations"), f"{target}.annotations")
            self._validate_meta(value.get("_meta"), f"{target}._meta")
            return {content_type}, decoded
        if content_type == "resource_link":
            allowed = {
                "type",
                "uri",
                "name",
                "title",
                "description",
                "mimeType",
                "annotations",
                "size",
                "icons",
                "_meta",
            }
            if not _exact_or_subset(value, allowed):
                return self._bad_content(target, "resource link contains unsupported fields")
            if (
                not _valid_uri(value.get("uri"))
                or not isinstance(value.get("name"), str)
                or not value["name"]
            ):
                return self._bad_content(target, "resource link requires a valid URI and name")
            for field in ("title", "description", "mimeType"):
                if field in value and not isinstance(value[field], str):
                    return self._bad_content(target, f"resource link {field} must be a string")
            if "size" in value and not _is_nonnegative_number(value["size"]):
                return self._bad_content(target, "resource link size must be non-negative")
            self._validate_annotations(value.get("annotations"), f"{target}.annotations")
            self._validate_icons(value.get("icons"), f"{target}.icons", rule_id="MCPTR004")
            self._validate_meta(value.get("_meta"), f"{target}._meta")
            return {"resource_link"}, 0
        if content_type == "resource":
            if not _exact_or_subset(value, {"type", "resource", "annotations", "_meta"}):
                return self._bad_content(target, "embedded resource contains unsupported fields")
            resource = value.get("resource")
            if not isinstance(resource, dict):
                return self._bad_content(target, "embedded resource payload is not an object")
            if not _exact_or_subset(resource, {"uri", "mimeType", "text", "blob", "_meta"}):
                return self._bad_content(target, "embedded resource payload contains unsupported fields")
            if not _valid_uri(resource.get("uri")):
                return self._bad_content(target, "embedded resource requires a valid URI")
            if "mimeType" in resource and not isinstance(resource["mimeType"], str):
                return self._bad_content(target, "embedded resource mimeType must be a string")
            has_text = isinstance(resource.get("text"), str)
            has_blob = isinstance(resource.get("blob"), str)
            if has_text == has_blob:
                return self._bad_content(target, "embedded resource requires exactly one text or blob")
            size = (
                len(resource["text"].encode("utf-8"))
                if has_text
                else _decoded_base64_size(resource.get("blob"))
            )
            if size is None:
                return self._bad_content(target, "embedded resource blob is not valid bounded base64")
            self._validate_annotations(value.get("annotations"), f"{target}.annotations")
            self._validate_meta(value.get("_meta"), f"{target}._meta")
            self._validate_meta(resource.get("_meta"), f"{target}.resource._meta")
            return {"embedded_resource"}, size
        return self._bad_content(target, "content block discriminator is unsupported")

    def _bad_content(self, target: str, evidence: str) -> tuple[set[str], int]:
        self.findings.append(_finding("MCPTR004", target, evidence))
        return set(), 0

    def _validate_annotations(self, value: Any, target: str) -> None:
        if value is None:
            return
        if not isinstance(value, dict) or set(value) - {"audience", "priority", "lastModified"}:
            self.findings.append(_finding("MCPTR004", target, "annotations shape is invalid"))
            return
        audience = value.get("audience")
        if audience is not None and (
            not isinstance(audience, list) or any(item not in {"user", "assistant"} for item in audience)
        ):
            self.findings.append(_finding("MCPTR004", target, "annotation audience is invalid"))
        priority = value.get("priority")
        if priority is not None and (not _is_nonnegative_number(priority) or priority > 1):
            self.findings.append(_finding("MCPTR004", target, "annotation priority is invalid"))
        if "lastModified" in value and not isinstance(value["lastModified"], str):
            self.findings.append(_finding("MCPTR004", target, "lastModified must be a string"))

    def _validate_structured_output(
        self,
        schema: dict[str, Any],
        instance: Any,
        target: str,
    ) -> None:
        try:
            _check_schema_bounds(schema)
            Draft202012Validator.check_schema(schema)
        except _SchemaUnsupported:
            self.findings.append(
                _finding(
                    "MCPTR000",
                    target,
                    "outputSchema uses unsupported or over-budget validation capability",
                )
            )
            return
        except SchemaError:
            self.findings.append(
                _finding("MCPTR001", target, "outputSchema is not valid JSON Schema 2020-12")
            )
            return
        try:
            with _validation_deadline():
                error = next(Draft202012Validator(schema).iter_errors(instance), None)
        except (_SchemaUnsupported, _ValidationTimeout, RecursionError):
            self.findings.append(
                _finding(
                    "MCPTR000",
                    target,
                    "bounded outputSchema validation could not complete",
                )
            )
            return
        except Exception as exc:
            if exc.__class__.__module__.startswith(("jsonschema", "referencing")):
                self.findings.append(
                    _finding(
                        "MCPTR000",
                        target,
                        "same-document schema reference resolution could not complete",
                    )
                )
                return
            raise
        if error is not None:
            self.findings.append(
                _finding(
                    "MCPTR001",
                    target,
                    "structuredContent does not satisfy the declared outputSchema",
                )
            )

    def _evaluate_channel_policy(
        self,
        policy: ChannelPolicy | None,
        content: list[Any],
        result: dict[str, Any],
        channels: set[str],
        target: str,
    ) -> None:
        text_present = any(isinstance(block, dict) and block.get("type") == "text" for block in content)
        has_structured = "structuredContent" in result
        if policy is None:
            if text_present and has_structured:
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy",
                        "both structured and text channels are present without an explicit fixture policy",
                        severity_override=ToolResultSeverity.UNKNOWN,
                    )
                )
            return
        if policy.representation is None and text_present and has_structured:
            self.findings.append(
                _finding(
                    "MCPTR005",
                    f"{target}.channelPolicy.representation",
                    "dual channels require an explicit independent or JSON-equivalence policy",
                    severity_override=ToolResultSeverity.UNKNOWN,
                )
            )
            return
        for required in policy.required_channels:
            if required not in channels:
                self.findings.append(
                    _finding(
                        "MCPTR004",
                        f"{target}.channelPolicy.requiredChannels",
                        "an explicitly required output channel is absent",
                    )
                )
        if policy.representation == "independent":
            return
        if policy.representation == "json_equivalent":
            if not has_structured or policy.text_content_index is None:
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy",
                        "JSON-equivalence policy lacks both compared channels",
                    )
                )
                return
            index = policy.text_content_index
            if index >= len(content) or not isinstance(content[index], dict):
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy.textContentIndex",
                        "JSON-equivalence text index does not identify a content block",
                    )
                )
                return
            block = content[index]
            if block.get("type") != "text" or not isinstance(block.get("text"), str):
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy.textContentIndex",
                        "JSON-equivalence policy does not identify text content",
                    )
                )
                return
            try:
                text_value = json.loads(
                    block["text"],
                    parse_constant=_reject_json_constant,
                    object_pairs_hook=_reject_duplicate_keys,
                )
            except (json.JSONDecodeError, ValueError):
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy",
                        "policy-coupled text is not valid JSON",
                    )
                )
                return
            if not _json_equivalent(text_value, result["structuredContent"]):
                self.findings.append(
                    _finding(
                        "MCPTR005",
                        f"{target}.channelPolicy",
                        "policy-coupled text and structuredContent contradict each other",
                    )
                )

    def _evaluate_metadata_policy(self) -> None:
        keys = set(self.fixture.application_only_metadata_keys)
        if not keys:
            return
        values: dict[str, set[str]] = {key: set() for key in keys}
        _collect_metadata_values(
            self.fixture.model_dump(mode="python", by_alias=True),
            keys,
            values,
        )
        for _key, private_values in values.items():
            if not private_values:
                self.findings.append(
                    _finding(
                        "MCPTR000",
                        "applicationOnlyMetadataKeys",
                        "an application-only metadata policy key did not bind any fixture value",
                    )
                )
                continue
            if any(len(value) < 4 for value in private_values):
                self.findings.append(
                    _finding(
                        "MCPTR000",
                        "applicationOnlyMetadataKeys",
                        "application-only metadata values shorter than four characters are unsupported",
                    )
                )
                continue
            if any(
                _contains_string(model_value, private_value)
                for model_value in self.model_visible_values
                for private_value in private_values
            ):
                self.findings.append(
                    _finding(
                        "MCPTR006",
                        "modelVisibleChannels",
                        "an application-only metadata value is reflected into model-visible evidence",
                    )
                )


def _request_id(value: Any) -> str | int | None:
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _is_nonnegative_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, float):
        return math.isfinite(value) and value >= 0
    return False


def _exact_or_subset(value: Mapping[str, Any], allowed: set[str]) -> bool:
    return not (set(value) - allowed)


def _valid_meta_key(value: str) -> bool:
    if "/" not in value:
        return bool(_META_NAME_RE.fullmatch(value))
    prefix, name = value.rsplit("/", 1)
    labels = prefix.split(".")
    return (
        bool(labels)
        and all(_META_LABEL_RE.fullmatch(label) for label in labels)
        and bool(_META_NAME_RE.fullmatch(name))
    )


def _valid_uri(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_URI_BYTES:
        return False
    if any(ord(character) < 0x20 or character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        if parsed.port is not None and not (0 <= parsed.port <= 65_535):
            return False
    except ValueError:
        return False
    if parsed.scheme in {"http", "https"} and not parsed.netloc:
        return False
    return bool(_SCHEME_RE.fullmatch(parsed.scheme))


def _decoded_base64_size(value: Any) -> int | None:
    if not isinstance(value, str) or len(value.encode("ascii", errors="ignore")) != len(value):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) > _MAX_RESOURCE_BYTES:
        return None
    return len(decoded)


def _check_schema_bounds(schema: dict[str, Any]) -> None:
    dialect = schema.get("$schema")
    if dialect is not None and dialect not in _DRAFT_2020_12_URIS:
        raise _SchemaUnsupported("only JSON Schema 2020-12 is supported")
    nodes = 0
    references = 0
    branches = 0
    stack: list[tuple[Any, int]] = [(schema, 0)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_SCHEMA_NODES or depth > _MAX_SCHEMA_DEPTH:
            raise _SchemaUnsupported("schema traversal bound exceeded")
        if isinstance(value, dict):
            if "$vocabulary" in value:
                raise _SchemaUnsupported("custom vocabulary negotiation is unsupported")
            if set(value) & _UNSUPPORTED_SCHEMA_KEYS:
                raise _SchemaUnsupported("regex and obsolete recursive schema keywords are unsupported")
            for key in _REFERENCE_KEYS:
                if key in value:
                    reference = value[key]
                    references += 1
                    if (
                        references > _MAX_SCHEMA_REFERENCES
                        or not isinstance(reference, str)
                        or not reference.startswith("#")
                    ):
                        raise _SchemaUnsupported("only bounded same-document references are supported")
            for key in _SCHEMA_BRANCH_KEYS:
                candidate = value.get(key)
                if isinstance(candidate, list):
                    branches += len(candidate)
                    if branches > _MAX_SCHEMA_BRANCHES:
                        raise _SchemaUnsupported("schema composition branch bound exceeded")
            stack.extend((nested, depth + 1) for nested in value.values())
        elif isinstance(value, list):
            stack.extend((nested, depth + 1) for nested in value)


@contextmanager
def _validation_deadline() -> Iterator[None]:
    if (
        not hasattr(signal, "setitimer")
        or not hasattr(signal, "ITIMER_REAL")
        or threading.current_thread() is not threading.main_thread()
    ):
        raise _SchemaUnsupported("bounded validation timer is unavailable")

    def timeout_handler(signum: int, frame: object) -> None:
        del signum, frame
        raise _ValidationTimeout("JSON Schema validation exceeded its time budget")

    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    if previous_timer != (0.0, 0.0):
        raise _SchemaUnsupported("an existing process alarm prevents isolated validation timing")
    previous_handler = signal.getsignal(signal.SIGALRM)
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
    except (OSError, ValueError) as exc:
        raise _SchemaUnsupported("bounded validation timer could not be installed") from exc
    try:
        signal.setitimer(signal.ITIMER_REAL, _MAX_VALIDATION_SECONDS)
    except (OSError, ValueError) as exc:
        signal.signal(signal.SIGALRM, previous_handler)
        raise _SchemaUnsupported("bounded validation timer could not be installed") from exc
    try:
        yield
    finally:
        try:
            signal.setitimer(signal.ITIMER_REAL, 0.0)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)


def _strip_meta(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _strip_meta(nested) for key, nested in value.items() if key != "_meta"}
    if isinstance(value, list):
        return [_strip_meta(nested) for nested in value]
    return value


def _collect_metadata_values(
    value: Any,
    keys: set[str],
    output: dict[str, set[str]],
) -> None:
    if isinstance(value, dict):
        meta = value.get("_meta")
        if isinstance(meta, dict):
            for key in keys:
                if key in meta:
                    output[key].update(_string_leaves(meta[key]))
        for nested in value.values():
            _collect_metadata_values(nested, keys, output)
    elif isinstance(value, list):
        for nested in value:
            _collect_metadata_values(nested, keys, output)


def _fixture_private_metadata_values(fixture: ToolResultFixture) -> set[str]:
    keys = set(fixture.application_only_metadata_keys)
    if not keys:
        return set()
    values: dict[str, set[str]] = {key: set() for key in keys}
    _collect_metadata_values(fixture.model_dump(mode="python", by_alias=True), keys, values)
    return {value for key_values in values.values() for value in key_values}


def _string_leaves(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in value.values():
            yield from _string_leaves(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _string_leaves(nested)


def _contains_string(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(_contains_string(nested, needle) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_string(nested, needle) for nested in value)
    return False


def _json_equivalent(first: Any, second: Any) -> bool:
    if first is None or second is None:
        return first is None and second is None
    if isinstance(first, bool) or isinstance(second, bool):
        return isinstance(first, bool) and isinstance(second, bool) and first is second
    if isinstance(first, (int, float)) and isinstance(second, (int, float)):
        return first == second
    if isinstance(first, str) or isinstance(second, str):
        return isinstance(first, str) and isinstance(second, str) and first == second
    if isinstance(first, list) or isinstance(second, list):
        return (
            isinstance(first, list)
            and isinstance(second, list)
            and len(first) == len(second)
            and all(_json_equivalent(left, right) for left, right in zip(first, second, strict=True))
        )
    if isinstance(first, dict) or isinstance(second, dict):
        return (
            isinstance(first, dict)
            and isinstance(second, dict)
            and first.keys() == second.keys()
            and all(_json_equivalent(first[key], second[key]) for key in first)
        )
    return False


def report_json_bytes(report: ToolResultReport) -> bytes:
    return canonical_json_bytes(report)
