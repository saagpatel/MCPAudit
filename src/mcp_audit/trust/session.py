"""Speak MCP to the server under review, list its surface, and exercise read-only-safe tools.

The SDK client negotiates the current protocol (2026-07-28) and falls back to
the 2025-11-25 handshake when a server does not support discovery. Calls use
synthetic inputs only; tool results are never resolved, stored, or forwarded.
"""

from __future__ import annotations

import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.client.streamable_http import streamable_http_client
from mcp.types import Implementation
from mcp.types import Tool as SdkTool

from mcp_audit import __version__
from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.http_transport import BoundedHttpClient, create_mcp_http_client
from mcp_audit.injection import InjectionDetector
from mcp_audit.models import PermissionCategory, ProtocolObservation, ToolAnnotations, ToolInfo
from mcp_audit.protocol import ProtocolCapture, observe_session, observe_transport
from mcp_audit.redaction import redact_text
from mcp_audit.stdio_transport import bounded_stdio_client
from mcp_audit.trust.models import Observation, Phase, ToolSummary
from mcp_audit.trust.public_http import PublicOnlyTransport
from mcp_audit.trust.sandbox import PhaseRecord

CLIENT_INFO = Implementation(name="mcp-audit-trust", version=__version__)
SYNTHETIC_TEXT = "mcpaudit-synthetic"
MAX_PAGES = 20
MAX_DESCRIPTION = 600
_FORBIDDEN = {
    PermissionCategory.DESTRUCTIVE,
    PermissionCategory.FILE_WRITE,
    PermissionCategory.SHELL_EXEC,
    PermissionCategory.EXFILTRATION,
}
_COMBINATORS = ("$ref", "allOf", "anyOf", "oneOf", "not", "if")

Snapshot = Callable[[], Awaitable["PhaseRecord"]]


class _Unsynthesizable(Exception):
    pass


@dataclass(frozen=True)
class ExercisePlan:
    max_calls: int = 10
    call_timeout: float = 20.0
    startup_timeout: float = 90.0
    settle_seconds: float = 0.75
    safe_tools: frozenset[str] = field(default_factory=frozenset)


def convert_tool(tool: SdkTool) -> ToolInfo:
    annotations = None
    if tool.annotations is not None:
        annotations = ToolAnnotations(
            title=tool.annotations.title,
            read_only_hint=tool.annotations.read_only_hint,
            destructive_hint=tool.annotations.destructive_hint,
            idempotent_hint=tool.annotations.idempotent_hint,
            open_world_hint=tool.annotations.open_world_hint,
        )
    return ToolInfo(
        name=tool.name,
        description=tool.description,
        input_schema=dict(tool.input_schema),
        annotations=annotations,
        title=tool.title,
    )


def summarize_tool(tool: ToolInfo) -> ToolSummary:
    inferred = sorted({f.category.value for f in PermissionAnalyzer().analyze_tool_keywords(tool)})
    injection = sorted({f.pattern_name for f in InjectionDetector().scan_tool(tool)})
    description = redact_text(tool.description or "")[:MAX_DESCRIPTION] or None
    hints = tool.annotations
    return ToolSummary(
        name=tool.name,
        description=description,
        read_only_hint=hints.read_only_hint if hints else None,
        destructive_hint=hints.destructive_hint if hints else None,
        open_world_hint=hints.open_world_hint if hints else None,
        inferred=inferred,
        injection=injection,
    )


def skip_reason(tool: ToolInfo, summary: ToolSummary, explicitly_safe: bool) -> str | None:
    """Why a tool is not exercised, or None when it is read-only-safe."""
    if summary.destructive_hint is True:
        return "declares destructiveHint"
    if not explicitly_safe and summary.read_only_hint is not True:
        return "not declared read-only (readOnlyHint)"
    # The veto keeps every side-effect keyword, as the connected canary does.
    strict = PermissionAnalyzer().analyze_tool_keywords(tool, contextual=False)
    vetoes = sorted({f.category.value for f in strict if f.category in _FORBIDDEN})
    if vetoes:
        return "description suggests " + ", ".join(vetoes)
    if summary.injection:
        return "tool text matched injection patterns"
    try:
        synthesize_arguments(tool.input_schema)
    except _Unsynthesizable as exc:
        return f"input schema not suitable for synthetic inputs ({exc})"
    return None


def synthesize_arguments(schema: dict[str, object] | None) -> dict[str, Any]:
    """Fill only required fields with inert synthetic values."""
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        raise _Unsynthesizable("not an object schema")
    value = _synth(schema, "", 0)
    return cast(dict[str, Any], value)


def _synth(schema: object, name: str, depth: int) -> Any:
    if depth > 4:
        raise _Unsynthesizable("schema nests too deeply")
    if not isinstance(schema, dict):
        return SYNTHETIC_TEXT
    if any(key in schema for key in _COMBINATORS):
        raise _Unsynthesizable("schema uses combinators or references")
    if "const" in schema:
        return schema["const"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    if "default" in schema:
        return schema["default"]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "null")
    if kind == "object" or (kind is None and "properties" in schema):
        properties = schema.get("properties")
        props = cast(dict[str, object], properties) if isinstance(properties, dict) else {}
        required = schema.get("required", [])
        if not isinstance(required, list):
            raise _Unsynthesizable("required is not a list")
        return {str(key): _synth(props.get(str(key), {}), str(key), depth + 1) for key in required}
    if kind == "array":
        minimum = schema.get("minItems", 0)
        count = minimum if isinstance(minimum, int) and 0 <= minimum <= 3 else 0
        return [_synth(schema.get("items", {}), name, depth + 1) for _ in range(count)]
    if kind in {"integer", "number"}:
        low = schema.get("minimum", schema.get("exclusiveMinimum"))
        value: float = low + (1 if "exclusiveMinimum" in schema else 0) if isinstance(low, int | float) else 1
        high = schema.get("maximum")
        if isinstance(high, int | float) and value > high:
            value = high
        return int(value) if kind == "integer" else value
    if kind == "boolean":
        return False
    if kind == "null":
        return None
    return _synth_string(schema, name)


def _synth_string(schema: dict[str, object], name: str) -> str:
    fmt = schema.get("format")
    lowered = name.lower()
    if fmt in {"uri", "url"} or lowered in {"url", "uri"} or lowered.endswith("_url"):
        text = "https://example.invalid/mcpaudit-synthetic"
    elif fmt == "email":
        text = "synthetic@example.invalid"
    elif fmt == "date":
        text = "2026-01-01"
    elif fmt == "date-time":
        text = "2026-01-01T00:00:00Z"
    elif fmt == "uuid":
        text = "00000000-0000-4000-8000-000000000000"
    elif lowered in {"path", "file", "filepath", "file_path", "filename", "dir", "directory"}:
        text = "/scratch/mcpaudit-synthetic.txt"
    else:
        text = SYNTHETIC_TEXT
    minimum = schema.get("minLength")
    if isinstance(minimum, int) and len(text) < minimum <= 256:
        text = text + "x" * (minimum - len(text))
    maximum = schema.get("maxLength")
    if isinstance(maximum, int) and 0 < maximum < len(text):
        text = text[:maximum]
    return text


async def _list_all(fetch: Callable[..., Awaitable[Any]], attr: str) -> list[Any]:
    items: list[Any] = []
    cursor: str | None = None
    for _ in range(MAX_PAGES):
        page = await fetch(cursor=cursor)
        items.extend(getattr(page, attr))
        cursor = page.next_cursor
        if not cursor:
            return items
    raise RuntimeError(f"{attr} listing exceeded {MAX_PAGES} pages")


async def _inspect(client: Client, capture: ProtocolCapture, observation: Observation) -> list[ToolInfo]:
    session = observe_session(client)
    observation.protocol_version = session.negotiated_version
    observation.protocol_era = session.era
    observation.server_info = session.server_info
    tools = [convert_tool(t) for t in await _list_all(client.list_tools, "tools")]
    capabilities = client.server_capabilities
    if capabilities.prompts is not None:
        try:
            prompts = await _list_all(client.list_prompts, "prompts")
            observation.prompts = sorted(redact_text(p.name) for p in prompts)
        except Exception as exc:  # noqa: BLE001 - a failed optional listing is recorded, not fatal
            observation.limits.append(f"Prompt listing failed ({type(exc).__name__}).")
    if capabilities.resources is not None:
        try:
            observation.resources = len(await _list_all(client.list_resources, "resources"))
        except Exception as exc:  # noqa: BLE001 - recorded as a coverage gap
            observation.limits.append(f"Resource listing failed ({type(exc).__name__}).")
    observation.tools = [summarize_tool(t) for t in tools]
    return tools


async def _record(observation: Observation, phase: Phase, snapshot: Snapshot, settle: float) -> None:
    await anyio.sleep(settle)
    record = await snapshot()
    phase.file_changes, phase.file_changes_truncated = record.changes, record.truncated
    phase.network, phase.rewrites_checked = record.network, record.rewrites_checked
    observation.phases.append(phase)


async def observe_stdio(
    params: StdioServerParameters,
    snapshot: Snapshot,
    plan: ExercisePlan,
    observation: Observation,
    after_start: Callable[[], Awaitable[None]] | None = None,
) -> list[ToolInfo]:
    """Run one session: startup, listing, read-only-safe calls. Phases attribute effects in time."""
    capture = ProtocolCapture(ProtocolObservation())
    tools: list[ToolInfo] = []
    with tempfile.TemporaryFile("w+", encoding="utf-8", errors="replace") as errlog:
        budget = plan.startup_timeout + plan.max_calls * (plan.call_timeout + plan.settle_seconds + 5) + 30
        try:
            with anyio.fail_after(budget):
                transport = bounded_stdio_client(params, errlog=errlog)
                async with Client(observe_transport(transport, capture), client_info=CLIENT_INFO) as client:
                    if after_start is not None:
                        await after_start()
                    with anyio.fail_after(plan.startup_timeout):
                        tools = await _inspect(client, capture, observation)
                    await _record(observation, Phase(name="startup"), snapshot, plan.settle_seconds)
                    await _exercise(client, tools, plan, observation, snapshot)
            observation.status = "complete"
        except Exception as exc:  # noqa: BLE001 - every failure becomes card evidence
            observation.status = "partial" if observation.tools else "failed"
            observation.error = _describe(exc, errlog)
            if not observation.phases:
                try:
                    await _record(observation, Phase(name="startup", error=observation.error), snapshot, 0)
                except Exception as record_error:  # noqa: BLE001 - the session error already explains it
                    observation.limits.append(f"Startup effects could not be recorded ({record_error}).")
    return tools


async def _exercise(
    client: Client, tools: list[ToolInfo], plan: ExercisePlan, observation: Observation, snapshot: Snapshot
) -> None:
    by_name = {summary.name: summary for summary in observation.tools}
    calls = 0
    for tool in tools:
        summary = by_name[tool.name]
        summary.skip_reason = skip_reason(tool, summary, tool.name in plan.safe_tools)
        if summary.skip_reason is not None:
            continue
        if calls >= plan.max_calls:
            summary.skip_reason = f"call budget ({plan.max_calls}) reached"
            continue
        calls += 1
        arguments = synthesize_arguments(tool.input_schema)
        phase = Phase(name=f"tool:{tool.name}", tool=tool.name, arguments=arguments)
        try:
            with anyio.fail_after(plan.call_timeout):
                result = await client.call_tool(tool.name, arguments)
            phase.is_error = bool(result.is_error)
        except TimeoutError:
            phase.error = f"no response within {plan.call_timeout:.0f}s"
        except Exception as exc:  # noqa: BLE001 - recorded on the phase
            phase.error = type(exc).__name__
        summary.exercised = True
        await _record(observation, phase, snapshot, plan.settle_seconds)


def _leaves(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for child in exc.exceptions for leaf in _leaves(child)]
    return [exc]


def _status_code(exc: BaseException) -> object:
    response = getattr(exc, "response", None)
    return getattr(response, "status_code", None)


def _describe(exc: BaseException, errlog: Any) -> str:
    leaves = _leaves(exc)
    names = ", ".join(dict.fromkeys(type(e).__name__ for e in leaves)) or type(exc).__name__
    errlog.seek(0)
    tail = [line.strip() for line in errlog.read()[-4000:].splitlines() if line.strip()][-3:]
    stderr = redact_text(" | ".join(tail))[:400]
    return f"Session failed ({names})." + (f" Server stderr: {stderr}" if stderr else "")


async def observe_remote(
    url: str, plan: ExercisePlan, observation: Observation, *, public_only: bool = True
) -> list[ToolInfo]:
    """List a remote server's surface over Streamable HTTP. Remote tools are never called.

    With public_only, every connection is vetted at connect time (see public_http).
    """
    capture = ProtocolCapture(ProtocolObservation())
    tools: list[ToolInfo] = []
    try:
        with anyio.fail_after(plan.startup_timeout):
            async with (
                (
                    BoundedHttpClient(transport=PublicOnlyTransport())
                    if public_only
                    else create_mcp_http_client()
                ) as http_client,
                Client(
                    observe_transport(streamable_http_client(url, http_client=http_client), capture),
                    client_info=CLIENT_INFO,
                ) as client,
            ):
                tools = await _inspect(client, capture, observation)
        for summary in observation.tools:
            summary.skip_reason = "remote server: tools are not called from outside"
        observation.status = "complete"
    except Exception as exc:  # noqa: BLE001 - recorded on the card
        leaves = _leaves(exc)
        codes = sorted({str(code) for e in leaves if isinstance(code := _status_code(e), int)})
        names = ", ".join(dict.fromkeys(type(e).__name__ for e in leaves))
        observation.status = "failed"
        observation.error = (
            f"The remote answered HTTP {', '.join(codes)}; its surface could not be listed without "
            "credentials or payment."
            if codes and all(code in {"401", "402", "403"} for code in codes)
            else f"Could not list the remote surface ({names}"
            + (f", HTTP {', '.join(codes)}" if codes else "")
            + ")"
            + (f": {redact_text(str(leaves[0]))[:160]}" if str(leaves[0]) else "")
            + "."
        )
    return tools
