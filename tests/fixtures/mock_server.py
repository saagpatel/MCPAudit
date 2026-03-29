"""Minimal MCP stdio server for integration tests.

Run as: python tests/fixtures/mock_server.py
Responds to initialize and tools/list, then exits cleanly.
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, ToolAnnotations


def make_server() -> Server:  # type: ignore[type-arg]
    app: Server = Server("mock-audit-server")  # type: ignore[type-arg]

    @app.list_tools()  # type: ignore[misc]
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="read_file",
                description="Read a file from disk at the given path.",
                inputSchema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                },
                annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False),
            ),
            Tool(
                name="write_file",
                description="Write content to a file at the given path.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                },
            ),
            Tool(
                name="execute_command",
                description="Run a shell command and return its output.",
                inputSchema={
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                },
            ),
        ]

    return app


async def main() -> None:
    server = make_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
