"""Minimal MCP stdio server for integration tests.

Run as: python tests/fixtures/mock_server.py
Responds to initialize and tools/list, then exits cleanly.
"""

from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Prompt, PromptArgument, Resource, Tool, ToolAnnotations
from pydantic import AnyUrl


def make_server() -> Server:
    app = Server("mock-audit-server")

    @app.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
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

    @app.list_prompts()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name="summarize_file",
                description="Summarize a file after it has been read.",
                arguments=[PromptArgument(name="path", required=True)],
            )
        ]

    @app.list_resources()  # type: ignore[no-untyped-call, untyped-decorator]
    async def list_resources() -> list[Resource]:
        return [
            Resource(
                uri=AnyUrl("file:///tmp/example.txt"),
                name="example",
                description="Example file resource.",
                mimeType="text/plain",
            )
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
