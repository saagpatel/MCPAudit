"""Minimal MCP stdio server for integration tests.

Run as: python tests/fixtures/mock_server.py
Responds to initialize and tools/list, then exits cleanly.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    Prompt,
    PromptArgument,
    Resource,
    Tool,
    ToolAnnotations,
)


def make_server() -> Server[Any]:
    async def on_list_tools(_ctx: object, _params: object) -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name="read_file",
                    description="Read a file from disk at the given path.",
                    input_schema={
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                    annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
                ),
                Tool(
                    name="write_file",
                    description="Write content to a file at the given path.",
                    input_schema={
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
                    input_schema={
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                        "required": ["command"],
                    },
                ),
            ]
        )

    async def on_list_prompts(_ctx: object, _params: object) -> ListPromptsResult:
        return ListPromptsResult(
            prompts=[
                Prompt(
                    name="summarize_file",
                    description="Summarize a file after it has been read.",
                    arguments=[PromptArgument(name="path", required=True)],
                )
            ]
        )

    async def on_list_resources(_ctx: object, _params: object) -> ListResourcesResult:
        return ListResourcesResult(
            resources=[
                Resource(
                    uri="file:///tmp/example.txt",
                    name="example",
                    description="Example file resource.",
                    mime_type="text/plain",
                )
            ]
        )

    return Server(
        "mock-audit-server",
        on_list_tools=on_list_tools,
        on_list_prompts=on_list_prompts,
        on_list_resources=on_list_resources,
    )


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
