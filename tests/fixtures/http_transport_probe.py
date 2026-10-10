"""Run one HTTP transport probe in an isolated child process."""

from __future__ import annotations

import asyncio
import json
import resource
import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx2

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp_audit.connector import ServerConnector
from mcp_audit.http_transport import BoundedHttpClient, HttpBodySizeError
from mcp_audit.models import ClientType, ServerConfig, TransportType


async def probe(url: str) -> dict[str, object]:
    config = ServerConfig(
        name="local-http-fixture",
        client=ClientType.CLAUDE_DESKTOP,
        config_path="synthetic://http-transport-fixture",
        transport=TransportType.HTTP,
        url=url,
    )
    audit = await ServerConnector(timeout=2).connect(config)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != "darwin":
        peak *= 1024
    return {
        "status": audit.connection_status,
        "error": audit.connection_error,
        "peak_rss_bytes": peak,
    }


class EndlessBody(httpx2.AsyncByteStream):
    def __init__(self) -> None:
        self.emitted = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        chunk = b"x" * 65_536
        while True:
            self.emitted += len(chunk)
            yield chunk

    async def aclose(self) -> None:
        pass


async def probe_mock_body() -> dict[str, object]:
    stream = EndlessBody()
    transport = httpx2.MockTransport(lambda request: httpx2.Response(200, stream=stream))
    async with BoundedHttpClient(transport=transport) as client:
        try:
            await client.get("https://fixture.invalid/")
        except HttpBodySizeError as exc:
            error = str(exc)
        else:
            error = "HTTP response unexpectedly completed"
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform != "darwin":
        peak *= 1024
    return {"error": error, "peak_rss_bytes": peak, "body_bytes": stream.emitted}


def main() -> None:
    result = asyncio.run(probe_mock_body() if sys.argv[1] == "--mock" else probe(sys.argv[1]))
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
