"""Bound HTTP bodies before the SDK buffers JSON or event-stream text."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx2
from mcp.shared._httpx_utils import MCP_DEFAULT_SSE_READ_TIMEOUT, MCP_DEFAULT_TIMEOUT

from mcp_audit.stdio_transport import DEFAULT_MAX_FRAME_BYTES


class HttpBodySizeError(ValueError):
    """An HTTP response exceeded the configured transport bound."""


class _BoundedBody(httpx2.AsyncByteStream):
    def __init__(
        self, stream: httpx2.AsyncByteStream, limit: int, on_error: Callable[[HttpBodySizeError], None]
    ) -> None:
        self.stream = stream
        self.limit = limit
        self.on_error = on_error

    async def __aiter__(self) -> AsyncIterator[bytes]:
        size = 0
        async for chunk in self.stream:
            size += len(chunk)
            if size > self.limit:
                error = HttpBodySizeError(f"HTTP body size exceeds {self.limit} bytes.")
                self.on_error(error)
                raise error
            yield chunk

    async def aclose(self) -> None:
        await self.stream.aclose()


class BoundedHttpClient(httpx2.AsyncClient):
    """Response hooks run before non-streamed reads, redirects, and SSE decoding."""

    def __init__(
        self,
        *,
        max_body_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        headers: dict[str, str] | None = None,
        timeout: httpx2.Timeout | None = None,
        auth: httpx2.Auth | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
    ) -> None:
        if max_body_bytes < 1:
            raise ValueError("HTTP body limit must be positive.")
        self.max_body_bytes = max_body_bytes
        self.on_body_error: Callable[[HttpBodySizeError], None] | None = None
        super().__init__(
            headers={**(headers or {}), "Accept-Encoding": "identity"},
            timeout=timeout or httpx2.Timeout(MCP_DEFAULT_TIMEOUT, read=MCP_DEFAULT_SSE_READ_TIMEOUT),
            auth=auth,
            transport=transport,
            event_hooks={"response": [self._bound_response]},
        )

    def _notify_body_error(self, error: HttpBodySizeError) -> None:
        if self.on_body_error is not None:
            self.on_body_error(error)

    async def _bound_response(self, response: httpx2.Response) -> None:
        # Refuse unsolicited compression before decoding to avoid expansion bombs.
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            error = HttpBodySizeError("Compressed HTTP bodies are not supported by bounded transport.")
            self._notify_body_error(error)
            raise error
        length = response.headers.get("content-length", "")
        if length.isdecimal() and int(length) > self.max_body_bytes:
            error = HttpBodySizeError(f"HTTP body size exceeds {self.max_body_bytes} bytes.")
            self._notify_body_error(error)
            raise error
        assert isinstance(response.stream, httpx2.AsyncByteStream)
        response.stream = _BoundedBody(response.stream, self.max_body_bytes, self._notify_body_error)


def create_mcp_http_client(
    headers: dict[str, str] | None = None,
    timeout: httpx2.Timeout | None = None,
    auth: httpx2.Auth | None = None,
) -> BoundedHttpClient:
    return BoundedHttpClient(headers=headers, timeout=timeout, auth=auth)
