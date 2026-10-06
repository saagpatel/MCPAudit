"""MCP server connector — spawns/connects to servers and enumerates tools."""

from __future__ import annotations

import logging
import os
import re
import threading
import time
import traceback
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import TextIO, TypeVar

import anyio
from mcp import Client, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.types import Implementation, ListPromptsResult, ListResourcesResult, ListToolsResult
from mcp.types import Prompt as SdkPrompt
from mcp.types import Resource as SdkResource
from mcp.types import Tool as SdkTool
from mcp.types import ToolAnnotations as SdkToolAnnotations

from mcp_audit import __version__
from mcp_audit.models import (
    CanarySummary,
    CapabilityTarget,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    PromptInfo,
    ResourceInfo,
    ScanWarning,
    ServerAudit,
    ServerConfig,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)
from mcp_audit.redaction import redact_text
from mcp_audit.rules.result_injection import RESULT_SCAN_LIMIT
from mcp_audit.terminal_text import TerminalSafeLogFilter, strip_controls

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())

_CLIENT_INFO = Implementation(name="mcp-audit", version=__version__)

# Consume suffix candidates even without a suffix, avoiding repeated scans of
# overlapping URL starts in server-controlled text. Possessive runs cannot backtrack.
_SSE_URL_SUFFIX = re.compile(r"(https?://[^\s?#]++)([?#][^\s]*)?", re.IGNORECASE)
_SSE_URL_USERINFO = re.compile(r"(https?://)(?:[^/\s@]*+@)++", re.IGNORECASE)
_REDIRECT_URL = re.compile(
    r"(\b(?:redirect(?:ed|ing)?\s*(?:to|target|->)|redirect\s+location|location['\"]?)\s*[:=]?\s*['\"<]?)"
    # Any token after a redirect phrase is server-chosen and may be an opaque
    # credential, so it is always withheld.
    r"[^\s'\"<>]+",
    re.IGNORECASE,
)
_SSE_LOGGER_NAMES = (
    "mcp.client.sse",
    "mcp.client.streamable_http",
    "httpx2",
    "httpcore2.connection",
    "httpcore2.http11",
    "httpcore2.http2",
    "httpcore2.proxy",
    "httpcore2.socks",
)


def _redact_sse_log_text(value: str) -> str:
    # Negotiated POST endpoints can use arbitrary query keys for session credentials.
    redacted = _REDIRECT_URL.sub(r"\1<redacted-url>", value)
    redacted = _SSE_URL_SUFFIX.sub(
        lambda match: match[1] + "?<redacted>" if match[2] is not None else match[0], redacted
    )
    redacted = _SSE_URL_USERINFO.sub(r"\1<redacted>@", redacted)
    return strip_controls(redact_text(redacted))


def _exception_leaves(exc: BaseException) -> Iterator[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        for child in exc.exceptions:
            yield from _exception_leaves(child)
    else:
        yield exc


def _exception_type_names(exc: BaseException) -> str:
    return "; ".join(dict.fromkeys(type(leaf).__name__ for leaf in _exception_leaves(exc)))


def describe_exception(exc: BaseException) -> str:
    """Return a bounded, redacted summary of an exception and any grouped causes."""
    leaves: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for error in _exception_leaves(exc):
        exception_type = type(error).__name__
        message = str(error)
        if len(message) > 2_000:
            message = message[:2_000]
            # Drop the cut token before redaction, so partial URL credentials
            # cannot survive. Preserve unbroken alphanumeric diagnostic text.
            boundary = next((i for i in range(len(message) - 1, -1, -1) if message[i].isspace()), None)
            if boundary is None:
                boundary = next((i for i in range(len(message) - 1, -1, -1) if message[i] in "'\"<>"), None)
            if boundary is not None:
                message = message[:boundary]
            elif not message.isalnum():
                message = ""
        identity = (exception_type, message)
        if identity not in seen:
            seen.add(identity)
            leaves.append(identity)

    descriptions = [f"{name}: {message}" if message else name for name, message in leaves]
    # Ordinary URLs retain host/path; redirect targets are withheld entirely.
    summary = _redact_sse_log_text("; ".join(descriptions))
    if len(summary) > 500:
        return summary[:499] + "…"
    return summary


class _SseLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # Transport DEBUG records include raw endpoints, headers and protocol payloads.
        if record.levelno <= logging.DEBUG:
            return False
        record.msg = _redact_sse_log_text(record.getMessage())
        record.args = ()
        if record.exc_info is not None:
            record.exc_text = _redact_sse_log_text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        elif record.exc_text is not None:
            record.exc_text = _redact_sse_log_text(record.exc_text)
        if record.stack_info is not None:
            record.stack_info = _redact_sse_log_text(record.stack_info)
        return True


_SSE_LOG_FILTER = _SseLogFilter()


@contextmanager
def _capture_stderr(server_name: str) -> Iterator[TextIO]:
    """Drain stderr continuously into a 4 KiB tail, with synchronous cleanup.

    A private wake marker ends the reader even if a descendant retains stderr.
    Its write is smaller than PIPE_BUF; the reader keeps draining until it sees
    the marker, so neither a full pipe nor async cancellation can strand it.
    """
    read_fd, write_fd = os.pipe()
    tail = bytearray()
    truncated = False
    stopping = threading.Event()
    marker = b"\x00" + os.urandom(32) + b"\x00"
    failures: list[OSError] = []

    def drain() -> None:
        nonlocal truncated
        try:
            while chunk := os.read(read_fd, 4096):
                data = tail + chunk
                position = data.find(marker) if stopping.is_set() else -1
                if position >= 0:
                    truncated = truncated or position > 4096
                    tail[:] = data[:position][-4096:]
                    return
                truncated = truncated or len(data) > 4096
                tail[:] = data[-4096:]
        except OSError as exc:
            failures.append(exc)
        finally:
            os.close(read_fd)

    try:
        errlog = os.fdopen(write_fd, "w", encoding="utf-8")
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    worker = threading.Thread(target=drain, name="mcp-audit-stderr")
    try:
        worker.start()
    except BaseException:
        errlog.close()
        os.close(read_fd)
        raise
    try:
        yield errlog
    finally:
        stopping.set()
        try:
            os.write(errlog.fileno(), marker)
        finally:
            errlog.close()
            worker.join()
        if failures:
            raise failures[0]
        if tail and logger.isEnabledFor(logging.DEBUG):
            text = tail.decode("utf-8", errors="replace")
            if truncated:
                # The retained prefix may have lost the anchor needed for redaction.
                _, newline, text = text.partition("\n")
                if not newline:
                    text = "<stderr truncated; last record exceeded 4 KiB>"
                text = "…[truncated] " + text
            logger.debug(
                "Server %s stderr tail: %s",
                redact_text(strip_controls(server_name)),
                redact_text(strip_controls(text)),
            )


# Known server command substrings → inferred permission categories (for --skip-connect mode).
# Checked as substrings of the full command+args string.
KNOWN_SERVER_COMMANDS: dict[str, list[PermissionCategory]] = {
    "@modelcontextprotocol/server-filesystem": [PermissionCategory.FILE_READ, PermissionCategory.FILE_WRITE],
    "@modelcontextprotocol/server-github": [PermissionCategory.NETWORK, PermissionCategory.FILE_READ],
    "sequential-thinking": [],
    "brave-search": [PermissionCategory.NETWORK],
    "server-brave-search": [PermissionCategory.NETWORK],
    "server-postgres": [
        PermissionCategory.FILE_READ,
        PermissionCategory.FILE_WRITE,
        PermissionCategory.DESTRUCTIVE,
    ],
    "server-sqlite": [
        PermissionCategory.FILE_READ,
        PermissionCategory.FILE_WRITE,
        PermissionCategory.DESTRUCTIVE,
    ],
    "server-puppeteer": [PermissionCategory.NETWORK, PermissionCategory.FILE_WRITE],
    "server-memory": [],
}

# Env key name substrings that imply a remote API call
_CREDENTIAL_SUBSTRINGS = ("TOKEN", "KEY", "SECRET", "API_KEY", "APIKEY", "PASSWORD", "CREDENTIAL")
_REMOTE_URL = re.compile(r"https?://", re.IGNORECASE)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_NETWORK_COMMANDS = {"curl", "wget"}
_PACKAGE_RUNNERS = {"npx", "uvx", "pipx"}
_DESTRUCTIVE_MARKERS = ("rm -rf", "remove-item -recurse", "del /s", "format ")
_TRUNCATION_WARNING = (
    f"Runtime text exceeded {RESULT_SCAN_LIMIT // 1024} KB; only the first "
    f"{RESULT_SCAN_LIMIT // 1024} KB of each oversized result or prompt body was scanned for injection."
)
_Page = TypeVar("_Page", ListToolsResult, ListPromptsResult, ListResourcesResult)
_Item = TypeVar("_Item")


class _ListingPageLimit(ValueError):
    """A surface exists, but its complete listing exceeds the capture bound."""


def _listing_failure_message(label: str, exc: Exception) -> str:
    if isinstance(exc, _ListingPageLimit):
        return f"{label} listing exceeds the 20-page limit; coverage is incomplete."
    reason = _exception_type_names(exc)
    return f"{label} surface incomplete ({reason})."


async def _list_pages(
    fetch: Callable[..., Awaitable[_Page]], items: Callable[[_Page], list[_Item]]
) -> list[_Item]:
    """Admit a surface only after its complete, bounded pagination succeeds."""
    collected: list[_Item] = []
    cursor = None
    for _ in range(20):
        page = await fetch(cursor=cursor, cache_mode="bypass")
        collected.extend(items(page))
        cursor = page.next_cursor
        if not cursor:
            return collected
    raise _ListingPageLimit("Listing exceeds the 20-page limit.")


@dataclass(frozen=True)
class _ServerCapabilities:
    tools: list[ToolInfo]
    prompts: list[PromptInfo]
    resources: list[ResourceInfo]
    surface: dict[str, dict[str, object]] = field(default_factory=dict)
    listing_warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _CanaryProbe:
    audit: ServerAudit
    calls: int
    safe_tools: frozenset[str]
    # prompts/get repeats on every listing; each (prompt, pattern) is reported once.
    prompt_patterns: set[tuple[str, str]] = field(default_factory=set)
    listing_failures: dict[str, str] = field(default_factory=dict)


def canary_tool_eligible(tool: ToolInfo, explicitly_safe: bool = False) -> bool:
    """Only exercise empty-argument tools with no destructive or injection hints.

    Required or complex schemas are skipped rather than inventing arguments.
    Annotation defaults and the operator mark are the gate; the capability
    keyword table and injection patterns veto a call regardless of either.
    """
    from mcp_audit.analyzer import PermissionAnalyzer
    from mcp_audit.injection import InjectionDetector

    schema = tool.input_schema
    if schema is None or schema.get("type") != "object" or schema.get("required"):
        return False
    if "required" in schema and not isinstance(schema["required"], list):
        return False
    if any(key in schema for key in ("$ref", "allOf", "anyOf", "oneOf", "not", "if")):
        return False
    if schema.get("minProperties", 0) != 0:
        return False
    if tool.annotations and tool.annotations.destructive_hint is True:
        return False
    if not explicitly_safe and not (
        tool.annotations
        and tool.annotations.read_only_hint is True
        and tool.annotations.destructive_hint is not True
    ):
        return False
    forbidden = {
        PermissionCategory.DESTRUCTIVE,
        PermissionCategory.FILE_WRITE,
        PermissionCategory.SHELL_EXEC,
        PermissionCategory.EXFILTRATION,
    }
    hazard_tool = tool.model_copy(
        update={
            "description": "\n".join(
                [
                    tool.description or "",
                    (tool.annotations.title or "") if tool.annotations else "",
                    *_result_text(schema),
                ]
            )
        }
    )
    if any(f.category in forbidden for f in PermissionAnalyzer().analyze_tool_keywords(hazard_tool)):
        return False
    if InjectionDetector().scan_tool(hazard_tool):
        return False
    return True


def _result_text(value: object) -> list[str]:
    """Extract text/structured result strings; never resolve resource links or decode blobs."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _result_text(item)]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _result_text(item)]
    return []


class ServerConnector:
    """Connects to MCP servers and enumerates their tools."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        self.scan_warnings: list[ScanWarning] | None = None

    async def connect(
        self, config: ServerConfig, *, canary_calls: int = 0, safe_tools: frozenset[str] = frozenset()
    ) -> ServerAudit:
        """Connect to a server and return a ServerAudit with tool list."""
        audit = ServerAudit(server=config, connection_status="pending")
        probe = None
        if canary_calls:
            if not 1 <= canary_calls <= 100:
                raise ValueError("Canary calls must be between 1 and 100.")
            audit.canary = CanarySummary(
                requested_calls=canary_calls,
                call_budget=canary_calls,
                client_identity=f"{_CLIENT_INFO.name}/{_CLIENT_INFO.version}",
            )
            probe = _CanaryProbe(audit, canary_calls, safe_tools)
        started = time.monotonic()
        try:
            with anyio.move_on_after(self.timeout) as cancel_scope:
                if config.transport == TransportType.STDIO:
                    capabilities = (
                        await self._connect_stdio(config, probe)
                        if probe
                        else await self._connect_stdio(config)
                    )
                elif config.transport == TransportType.HTTP:
                    capabilities = (
                        await self._connect_http(config, probe) if probe else await self._connect_http(config)
                    )
                elif config.transport == TransportType.SSE:
                    logger.warning(
                        "Server %s uses deprecated SSE transport; connecting via legacy SSE",
                        config.name,
                    )
                    capabilities = (
                        await self._connect_sse(config, probe) if probe else await self._connect_sse(config)
                    )
                else:
                    return ServerAudit(
                        server=config,
                        connection_status="failed",
                        connection_error=f"Unknown transport: {config.transport}",
                    )

            if cancel_scope.cancelled_caught:
                logger.debug("Timeout connecting to %s", config.name)
                audit.connection_status = "timeout"
                if audit.canary:
                    audit.canary.status = "partial"
                    audit.canary.warnings.append("Canary session timed out; coverage is incomplete.")
                return audit

            tools = audit.tools if probe else capabilities.tools
            logger.debug("Connected to %s, found %d tools", config.name, len(tools))
            audit.connection_status = "connected"
            if not probe:
                audit.tools = tools
                audit.prompts = capabilities.prompts
                audit.resources = capabilities.resources
                for message in capabilities.listing_warnings:
                    if self.scan_warnings is not None:
                        self.scan_warnings.append(
                            ScanWarning(
                                code="surface_listing_incomplete",
                                message=(
                                    f"Server '{config.name}': {message} "
                                    "A listing this large, or one that never ends, can hide surfaces; "
                                    "review the server before trusting this result."
                                ),
                                servers=[config.name],
                            )
                        )
            audit.has_annotations = any(t.annotations is not None for t in tools)
            if tools:
                annotated = sum(1 for t in tools if t.annotations is not None)
                audit.annotation_coverage = annotated / len(tools)
            return audit

        except Exception as exc:
            message = describe_exception(exc)
            if not isinstance(exc, BaseExceptionGroup):
                # Keep established plain-exception wording while still using
                # the helper's URL and credential redaction.
                prefix = f"{type(exc).__name__}: "
                if message.startswith(prefix):
                    message = message[len(prefix) :]
            logger.debug("Failed to connect to %s: %s", config.name, message)
            if audit.canary:
                audit.connection_status = "failed"
                audit.connection_error = message
                audit.canary.status = "partial"
                audit.canary.warnings.append("Canary session failed; coverage is incomplete.")
                return audit
            return ServerAudit(
                server=config,
                connection_status="failed",
                connection_error=message,
            )
        finally:
            if audit.canary:
                audit.canary.elapsed_seconds = time.monotonic() - started

    async def _connect_stdio(
        self, config: ServerConfig, probe: _CanaryProbe | None = None
    ) -> _ServerCapabilities:
        if not config.command:
            raise ValueError(f"Server {config.name} has no command for stdio transport")

        params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=None,
        )
        with _capture_stderr(config.name) as errlog:
            async with Client(stdio_client(params, errlog=errlog), client_info=_CLIENT_INFO) as client:
                return await self._inspect_session(client, config.name, probe)

    async def _connect_http(
        self, config: ServerConfig, probe: _CanaryProbe | None = None
    ) -> _ServerCapabilities:
        if not config.url:
            raise ValueError(f"Server {config.name} has no URL for HTTP transport")

        for name in _SSE_LOGGER_NAMES:
            logging.getLogger(name).addFilter(_SSE_LOG_FILTER)
        # mcp 2.1.1 maps Client(str) to streamable_http_client.
        async with Client(config.url, client_info=_CLIENT_INFO) as client:
            return await self._inspect_session(client, config.name, probe)

    async def _connect_sse(
        self, config: ServerConfig, probe: _CanaryProbe | None = None
    ) -> _ServerCapabilities:
        if not config.url:
            raise ValueError(f"Server {config.name} has no URL for SSE transport")

        # Filters on a parent logger do not cover child records. Bind each emitting
        # transport logger, retaining the filters across concurrent connections.
        for name in _SSE_LOGGER_NAMES:
            logging.getLogger(name).addFilter(_SSE_LOG_FILTER)
        # Client(str) is Streamable HTTP; legacy SSE must pass sse_client as Transport.
        async with Client(sse_client(config.url), client_info=_CLIENT_INFO) as client:
            return await self._inspect_session(client, config.name, probe)

    async def _inspect_session(
        self, session: Client, server_name: str, probe: _CanaryProbe | None
    ) -> _ServerCapabilities:
        capabilities = await self._list_capabilities(session, server_name, probe)
        if probe is None:
            return capabilities
        from mcp_audit.escalation import detect_session_drift
        from mcp_audit.pinning import surface_hash

        summary = probe.audit.canary
        assert summary is not None
        previous = capabilities.surface
        summary.baseline_hash = surface_hash(previous)
        summary.current_hash = summary.baseline_hash
        for call in range(1, probe.calls + 1):
            if "tools" not in capabilities.surface:
                capabilities = await self._list_capabilities(session, server_name, probe, previous, call - 1)
                probe.audit.drift_findings.extend(
                    detect_session_drift(server_name, previous, capabilities.surface, call - 1)
                )
                previous = {**previous, **capabilities.surface}
                summary.current_hash = surface_hash(previous)
            eligible = [t for t in capabilities.tools if canary_tool_eligible(t, t.name in probe.safe_tools)]
            if not eligible:
                summary.status = "no_safe_tools" if not summary.completed_calls else "partial"
                stop_message = (
                    "Tool listing failed; exercise stopped."
                    if "tools" not in capabilities.surface
                    else "No eligible empty-argument tools remain; exercise stopped."
                )
                summary.warnings.append(stop_message)
                return capabilities
            tool = eligible[(call - 1) % len(eligible)]
            result = await session.call_tool(tool.name, {})
            summary.completed_calls = call
            text = "\n".join(_result_text(result.model_dump(mode="json", by_alias=True)))
            self._scan_runtime_text(probe, tool.name, text, call, CapabilityTarget.TOOL)
            if result.is_error:
                summary.warnings.append(
                    f"Tool call {call} returned an error result; exercise may be ineffective."
                )
            capabilities = await self._list_capabilities(session, server_name, probe, previous, call)
            probe.audit.drift_findings.extend(
                detect_session_drift(server_name, previous, capabilities.surface, call)
            )
            previous = {**previous, **capabilities.surface}
            summary.current_hash = surface_hash(previous)
        summary.status = "partial" if summary.warnings else "complete"
        return capabilities

    async def _list_capabilities(
        self,
        session: Client,
        server_name: str,
        probe: _CanaryProbe | None = None,
        previous: dict[str, dict[str, object]] | None = None,
        after_call: int = 0,
    ) -> _ServerCapabilities:
        tools: list[SdkTool] = []
        prompts: list[PromptInfo] = []
        resources: list[ResourceInfo] = []
        surface: dict[str, dict[str, object]] = {}
        listing_warnings: list[str] = []
        # Every surface is always listed, in both modes: servers can serve surfaces
        # they never advertised, and skipping them would hide them from the static
        # checks. Never-observed, unadvertised surfaces may be unsupported;
        # intermittent availability and page-limit exhaustion degrade coverage.
        advertised = session.server_capabilities
        prompts_advertised = getattr(advertised, "prompts", None) is not None
        resources_advertised = getattr(advertised, "resources", None) is not None
        list_prompts = True
        list_resources = True
        try:
            tools = await _list_pages(session.list_tools, lambda page: page.tools)
            if probe:
                surface["tools"] = {t.name: t.model_dump(mode="json", by_alias=True) for t in tools}
        except Exception as exc:
            if not probe:
                raise
            self._canary_warning(probe, _listing_failure_message("Tool", exc))

        if list_prompts:
            try:
                prompt_items = await _list_pages(session.list_prompts, lambda page: page.prompts)
                prompts = [self._convert_prompt(prompt) for prompt in prompt_items]
                if probe:
                    if "prompts" in probe.listing_failures:
                        self._canary_warning(probe, probe.listing_failures["prompts"])
                    surface["prompts"] = {
                        p.name: p.model_dump(mode="json", by_alias=True) for p in prompt_items
                    }
                    # A failed get preserves only that prompt's last known structure.
                    known_results = (previous or {}).get("prompt_results", {})
                    surface["prompt_results"] = {
                        p.name: known_results[p.name] for p in prompt_items if p.name in known_results
                    }
                    for prompt in prompt_items:
                        if any(a.required for a in prompt.arguments or []):
                            self._canary_warning(probe, "Required-argument prompts/get skipped.")
                            continue
                        assert probe.audit.canary is not None
                        probe.audit.canary.prompt_get_calls += 1
                        try:
                            result = await session.get_prompt(prompt.name, {})
                        except Exception as exc:
                            reason = _exception_type_names(exc)
                            self._canary_warning(probe, f"prompts/get incomplete ({reason}).")
                            continue
                        surface["prompt_results"][prompt.name] = {
                            "description": result.description,
                            "messages": [{"role": m.role} for m in result.messages],
                        }
                        # Rendered text is excluded from drift (it may change normally)
                        # but is scanned like a tool result: a hunt can live in a body.
                        body = "\n".join(_result_text(result.model_dump(mode="json", by_alias=True)))
                        self._scan_runtime_text(probe, prompt.name, body, after_call, CapabilityTarget.PROMPT)
            except Exception as exc:
                if probe:
                    surface.pop("prompts", None)
                    surface.pop("prompt_results", None)
                message = _listing_failure_message("Prompt", exc)
                if probe:
                    probe.listing_failures["prompts"] = message
                if probe and (
                    prompts_advertised or "prompts" in (previous or {}) or isinstance(exc, _ListingPageLimit)
                ):
                    self._canary_warning(probe, message)
                elif not probe and isinstance(exc, _ListingPageLimit):
                    listing_warnings.append(message)
                elif logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Server %s prompt listing unavailable: %s", server_name, describe_exception(exc)
                    )

        if list_resources:
            try:
                resource_items = await _list_pages(session.list_resources, lambda page: page.resources)
                resources = [self._convert_resource(resource) for resource in resource_items]
                if probe:
                    if "resources" in probe.listing_failures:
                        self._canary_warning(probe, probe.listing_failures["resources"])
                    surface["resources"] = {
                        str(r.uri): r.model_dump(mode="json", by_alias=True) for r in resource_items
                    }
            except Exception as exc:
                message = _listing_failure_message("Resource", exc)
                if probe:
                    probe.listing_failures["resources"] = message
                if probe and (
                    resources_advertised
                    or "resources" in (previous or {})
                    or isinstance(exc, _ListingPageLimit)
                ):
                    self._canary_warning(probe, message)
                elif not probe and isinstance(exc, _ListingPageLimit):
                    listing_warnings.append(message)
                elif logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        "Server %s resource listing unavailable: %s", server_name, describe_exception(exc)
                    )

        tool_infos = [self._convert_tool(t) for t in tools]
        if probe:
            if "tools" in surface:
                probe.audit.tools = tool_infos
            if "prompts" in surface:
                probe.audit.prompts = prompts
            if "resources" in surface:
                probe.audit.resources = resources
        return _ServerCapabilities(
            tools=tool_infos,
            prompts=prompts,
            resources=resources,
            surface=surface,
            listing_warnings=listing_warnings,
        )

    @staticmethod
    def _canary_warning(probe: _CanaryProbe, message: str) -> None:
        assert probe.audit.canary is not None
        if message not in probe.audit.canary.warnings:
            probe.audit.canary.warnings.append(message)

    def _scan_runtime_text(
        self, probe: _CanaryProbe, name: str, text: str, after_call: int, target_type: CapabilityTarget
    ) -> None:
        """Scan bounded runtime text; truncation is reported as incomplete coverage."""
        from mcp_audit.injection import InjectionDetector

        if len(text) > RESULT_SCAN_LIMIT:
            text = text[:RESULT_SCAN_LIMIT]
            self._canary_warning(probe, _TRUNCATION_WARNING)
        for finding in InjectionDetector().scan_result(name, text, after_call, target_type):
            if target_type is CapabilityTarget.PROMPT:
                if (name, finding.pattern_name) in probe.prompt_patterns:
                    continue
                probe.prompt_patterns.add((name, finding.pattern_name))
            probe.audit.injection_findings.append(finding)

    def skip_connect_audit(self, config: ServerConfig) -> ServerAudit:
        """Return a ServerAudit with config-inferred permissions (no connection)."""
        findings = self._infer_skip_connect_findings(config)

        return ServerAudit(
            server=config,
            connection_status="skipped",
            permissions=findings,
        )

    def _infer_categories_from_config(self, config: ServerConfig) -> list[PermissionCategory]:
        return [finding.category for finding in self._infer_skip_connect_findings(config)]

    def _infer_skip_connect_findings(self, config: ServerConfig) -> list[PermissionFinding]:
        findings: dict[PermissionCategory, PermissionFinding] = {}

        def add(category: PermissionCategory, evidence: str) -> None:
            existing = findings.get(category)
            if existing is None:
                findings[category] = PermissionFinding(
                    category=category,
                    confidence=Confidence.LOW,
                    evidence=[evidence],
                    tool_name="(config)",
                )
                return
            if evidence not in existing.evidence:
                existing.evidence.append(evidence)

        command_line = _config_command_line(config)
        command_lower = command_line.lower()
        command_name = _command_name(config.command)

        for pattern, categories in KNOWN_SERVER_COMMANDS.items():
            if pattern.lower() in command_lower:
                for category in categories:
                    add(category, f"known server pattern {pattern!r}")

        if config.transport in (TransportType.HTTP, TransportType.SSE) or config.url:
            add(PermissionCategory.NETWORK, f"{config.transport.value} transport declares remote endpoint")

        if _REMOTE_URL.search(command_line):
            add(PermissionCategory.NETWORK, "command or args contain remote URL")

        if command_name in _SHELL_WRAPPERS:
            add(PermissionCategory.SHELL_EXEC, f"shell wrapper command {command_name!r}")

        if command_name in _NETWORK_COMMANDS:
            add(PermissionCategory.NETWORK, f"network transfer command {command_name!r}")

        if command_name in _PACKAGE_RUNNERS:
            add(PermissionCategory.NETWORK, f"package runner command {command_name!r} may download code")

        if any(marker in command_lower for marker in _DESTRUCTIVE_MARKERS):
            add(PermissionCategory.DESTRUCTIVE, "command or args contain destructive shell pattern")

        # Env key names suggesting credential usage → NETWORK
        for key in config.env_keys:
            key_upper = key.upper()
            if any(sub in key_upper for sub in _CREDENTIAL_SUBSTRINGS):
                add(PermissionCategory.NETWORK, f"env key {key!r} suggests remote API")
                break

        return list(findings.values())

    @staticmethod
    def _convert_tool(sdk_tool: SdkTool) -> ToolInfo:
        annotations: ToolAnnotations | None = None
        if sdk_tool.annotations is not None:
            annotations = ServerConnector._convert_annotations(sdk_tool.annotations)

        return ToolInfo(
            name=sdk_tool.name,
            description=sdk_tool.description,
            input_schema=dict(sdk_tool.input_schema) if sdk_tool.input_schema else None,
            annotations=annotations,
        )

    @staticmethod
    def _convert_annotations(sdk_ann: SdkToolAnnotations) -> ToolAnnotations:
        """Convert SDK 2 ToolAnnotations to our model."""
        return ToolAnnotations(
            title=sdk_ann.title,
            read_only_hint=sdk_ann.read_only_hint,
            destructive_hint=sdk_ann.destructive_hint,
            idempotent_hint=sdk_ann.idempotent_hint,
            open_world_hint=sdk_ann.open_world_hint,
        )

    @staticmethod
    def _convert_prompt(sdk_prompt: SdkPrompt) -> PromptInfo:
        arguments: list[str] = []
        for argument in sdk_prompt.arguments or []:
            name = getattr(argument, "name", None)
            if name:
                arguments.append(str(name))
        return PromptInfo(
            name=sdk_prompt.name,
            description=sdk_prompt.description,
            arguments=arguments,
        )

    @staticmethod
    def _convert_resource(sdk_resource: SdkResource) -> ResourceInfo:
        return ResourceInfo(
            uri=str(sdk_resource.uri),
            name=sdk_resource.name,
            description=sdk_resource.description,
            mime_type=sdk_resource.mime_type,
        )


def build_skip_connect_findings_for_category(
    categories: list[PermissionCategory],
) -> list[PermissionFinding]:
    """Utility: wrap inferred categories into PermissionFindings."""
    return [
        PermissionFinding(
            category=cat,
            confidence=Confidence.LOW,
            evidence=["config-inferred"],
            tool_name="(config)",
        )
        for cat in categories
    ]


def _config_command_line(config: ServerConfig) -> str:
    return " ".join(filter(None, [config.command, *config.args, config.url or ""]))


def _command_name(command: str | None) -> str:
    if not command:
        return ""
    normalized = command.replace("\\", "/")
    return PurePath(normalized).name.lower()
