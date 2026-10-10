"""Evidence-only protocol observations from an already connected SDK client."""

from __future__ import annotations

from collections import Counter
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from anyio.abc import ObjectReceiveStream, ObjectSendStream
from mcp import Client
from mcp.client._transport import ReadStream, Transport, TransportStreams, WriteStream
from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCError, JSONRPCRequest, JSONRPCResponse, ListToolsResult
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS
from pydantic import BaseModel, ValidationError

from mcp_audit.models import CacheHintObservation, ProtocolFinding, ProtocolObservation, TransportType
from mcp_audit.redaction import redact_text
from mcp_audit.taxonomy import PROTOCOL_FINDINGS


def observe_session(client: Client) -> ProtocolObservation:
    """Fallback initialization does not prove server/discover was unsupported."""
    version = client.protocol_version
    info = client.server_info
    capabilities = client.server_capabilities
    return ProtocolObservation(
        negotiated_version=version,
        era=(
            "modern"
            if version in MODERN_PROTOCOL_VERSIONS
            else "legacy"
            if version in HANDSHAKE_PROTOCOL_VERSIONS
            else "unknown"
        ),
        discover_supported=True if client.session.discover_result is not None else None,
        server_info={"name": redact_text(info.name), "version": redact_text(info.version)} if info else None,
        extensions=[redact_text(key) for key in capabilities.extensions or {}],
        logging_advertised=capabilities.logging is not None,
    )


def invalid_ttl(exc: BaseException) -> bool:
    """Inspect field locations only; validation messages/inputs may contain secrets."""
    if isinstance(exc, BaseExceptionGroup):
        return any(invalid_ttl(child) for child in exc.exceptions)
    return isinstance(exc, ValidationError) and any(
        error["loc"] and error["loc"][-1] in {"ttl_ms", "ttlMs"} and error["type"] != "missing"
        for error in exc.errors(include_input=False, include_context=False)
    )


def cache_hint_failure(exc: BaseException) -> bool:
    if isinstance(exc, BaseExceptionGroup):
        return any(cache_hint_failure(child) for child in exc.exceptions)
    return isinstance(exc, ValidationError) and any(
        error["loc"] and error["loc"][-1] in {"ttl_ms", "ttlMs", "cache_scope", "cacheScope"}
        for error in exc.errors(include_input=False, include_context=False)
    )


@dataclass
class ProtocolCapture:
    observation: ProtocolObservation
    findings: list[ProtocolFinding] = field(default_factory=list)
    listing: int = 0
    requests: dict[str | int, str] = field(default_factory=dict)
    wire_hints: dict[str, list[CacheHintObservation]] = field(default_factory=dict)
    missing_hints: set[str] = field(default_factory=set)
    invalid_ttls: set[str] = field(default_factory=set)
    discover_unsupported: bool = False

    def sent(self, message: SessionMessage) -> None:
        request = message.message
        if isinstance(request, JSONRPCRequest):
            self.requests[request.id] = request.method

    def received(self, message: SessionMessage | Exception) -> None:
        if isinstance(message, Exception):
            return
        response = message.message
        if not isinstance(response, JSONRPCResponse | JSONRPCError) or response.id is None:
            return
        method = self.requests.pop(response.id, "")
        if (
            isinstance(response, JSONRPCError)
            and method == "server/discover"
            and response.error.code == -32601
        ):
            self.discover_unsupported = True
        if not isinstance(response, JSONRPCResponse) or method not in {
            "server/discover",
            "tools/list",
            "prompts/list",
            "resources/list",
        }:
            return
        raw = response.result
        if raw.get("resultType") != "complete":
            return
        ttl, scope = raw.get("ttlMs"), raw.get("cacheScope")
        if "ttlMs" not in raw or "cacheScope" not in raw:
            self.missing_hints.add(method)
        if "ttlMs" in raw and (type(ttl) is not int or ttl < 0):
            self.invalid_ttls.add(method)
        self.wire_hints.setdefault(method, []).append(
            CacheHintObservation(
                method=method,
                listing=0,
                page=0,
                ttl_ms=ttl if type(ttl) is int else None,
                cache_scope="public" if scope == "public" else "private" if scope == "private" else None,
                ttl_ms_present="ttlMs" in raw,
                cache_scope_present="cacheScope" in raw,
            )
        )

    def wire_rules(self) -> None:
        for method in sorted(self.invalid_ttls):
            self.add("MCP049", method)

    def failed(self, method: str, exc: BaseException) -> None:
        if cache_hint_failure(exc):
            if method in self.missing_hints and self.observation.era == "modern":
                self.add("MCP047", method)
            if invalid_ttl(exc):
                self.add("MCP049", method)
            hints = self.wire_hints.pop(method, [])
            for index, hint in enumerate(hints):
                self.observation.cache_hints.append(
                    hint.model_copy(update={"listing": self.listing, "page": index})
                )
            self.listing += 1

    def add(self, rule_id: str, target: str = "") -> None:
        metadata = PROTOCOL_FINDINGS[rule_id]
        if any(f.rule_id == rule_id and f.target_name == target for f in self.findings):
            return
        self.findings.append(
            ProtocolFinding(
                rule_id=rule_id,
                title=metadata.title,
                summary=metadata.description,
                remediation=metadata.remediation,
                target_name=target,
                requirement_level=(
                    "protocol_must"
                    if rule_id in {"MCP047", "MCP048", "MCP049"} and self.observation.era == "modern"
                    else "protocol_should"
                    if rule_id == "MCP050"
                    else "advisory"
                ),
            )
        )

    def session_rules(self, transport: TransportType) -> None:
        if self.observation.era == "legacy" and transport == TransportType.HTTP:
            self.add("MCP044")
        if self.observation.session_id_minted is True:
            self.add("MCP045")
        if self.observation.era == "modern" and self.observation.logging_advertised is True:
            self.add("MCP046")

    def pages(self, method: str, pages: list[BaseModel]) -> None:
        """Only completed listings supply missing-hint, scope, and ordering evidence."""
        hints: list[CacheHintObservation] = []
        raw_hints = self.wire_hints.pop(method, [])
        for index, page in enumerate(pages):
            explicit = page.model_fields_set
            ttl = getattr(page, "ttl_ms", None) if "ttl_ms" in explicit else None
            scope = getattr(page, "cache_scope", None) if "cache_scope" in explicit else None
            hints.append(
                raw_hints[index].model_copy(update={"listing": self.listing, "page": index})
                if index < len(raw_hints)
                else CacheHintObservation(
                    method=method,
                    listing=self.listing,
                    page=index,
                    ttl_ms=ttl,
                    cache_scope=scope,
                    ttl_ms_present="ttl_ms" in explicit,
                    cache_scope_present="cache_scope" in explicit,
                )
            )
        self.observation.cache_hints.extend(hints)
        self.listing += 1
        if self.observation.era == "modern":
            if any(not h.ttl_ms_present or not h.cache_scope_present for h in hints):
                self.add("MCP047", method)
            if len({h.cache_scope for h in hints if h.cache_scope is not None}) > 1:
                self.add("MCP048", method)
        if method == "tools/list":
            order = [tool.name for page in pages if isinstance(page, ListToolsResult) for tool in page.tools]
            # Compare complete listings only, preserving duplicates in membership.
            previous = self.observation.tools_order
            if previous and previous[-1] != order and Counter(previous[-1]) == Counter(order):
                self.add("MCP050", method)
            previous.append(order)


class _ObservedRead(ObjectReceiveStream[SessionMessage | Exception]):
    def __init__(self, stream: ReadStream[SessionMessage | Exception], capture: ProtocolCapture) -> None:
        self.stream, self.capture = stream, capture

    @property
    def last_context(self) -> object:
        return getattr(self.stream, "last_context", None)

    async def receive(self) -> SessionMessage | Exception:
        message = await self.stream.receive()
        self.capture.received(message)
        return message

    async def aclose(self) -> None:
        await self.stream.aclose()


class _ObservedWrite(ObjectSendStream[SessionMessage]):
    def __init__(self, stream: WriteStream[SessionMessage], capture: ProtocolCapture) -> None:
        self.stream, self.capture = stream, capture

    async def send(self, message: SessionMessage) -> None:
        self.capture.sent(message)
        await self.stream.send(message)

    async def aclose(self) -> None:
        await self.stream.aclose()


@asynccontextmanager
async def observe_transport(
    transport: Transport, capture: ProtocolCapture
) -> AsyncIterator[TransportStreams]:
    """Tap cache hints before the SDK clamps TTLs; forward frames without mutation."""
    async with transport as (read, write):
        yield _ObservedRead(read, capture), _ObservedWrite(write, capture)
