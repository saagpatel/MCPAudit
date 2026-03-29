"""MCP server connector — spawns/connects to servers and enumerates tools."""

from __future__ import annotations

import logging

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Tool as SdkTool
from mcp.types import ToolAnnotations as SdkToolAnnotations

from mcp_audit.models import (
    Confidence,
    PermissionCategory,
    PermissionFinding,
    ServerAudit,
    ServerConfig,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)

logger = logging.getLogger(__name__)

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


class ServerConnector:
    """Connects to MCP servers and enumerates their tools."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def connect(self, config: ServerConfig) -> ServerAudit:
        """Connect to a server and return a ServerAudit with tool list."""
        try:
            with anyio.move_on_after(self.timeout) as cancel_scope:
                if config.transport == TransportType.STDIO:
                    tools = await self._connect_stdio(config)
                elif config.transport in (TransportType.HTTP, TransportType.SSE):
                    if config.transport == TransportType.SSE:
                        logger.warning(
                            "Server %s uses deprecated SSE transport; attempting as StreamableHTTP",
                            config.name,
                        )
                    tools = await self._connect_http(config)
                else:
                    return ServerAudit(
                        server=config,
                        connection_status="failed",
                        connection_error=f"Unknown transport: {config.transport}",
                    )

            if cancel_scope.cancelled_caught:
                logger.debug("Timeout connecting to %s", config.name)
                return ServerAudit(server=config, connection_status="timeout")

            logger.debug("Connected to %s, found %d tools", config.name, len(tools))
            audit = ServerAudit(server=config, connection_status="connected", tools=tools)
            audit.has_annotations = any(t.annotations is not None for t in tools)
            if tools:
                annotated = sum(1 for t in tools if t.annotations is not None)
                audit.annotation_coverage = annotated / len(tools)
            return audit

        except Exception as exc:
            logger.debug("Failed to connect to %s: %s", config.name, exc)
            return ServerAudit(
                server=config,
                connection_status="failed",
                connection_error=str(exc),
            )

    async def _connect_stdio(self, config: ServerConfig) -> list[ToolInfo]:
        if not config.command:
            raise ValueError(f"Server {config.name} has no command for stdio transport")

        params = StdioServerParameters(
            command=config.command,
            args=config.args,
            env=None,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return [self._convert_tool(t) for t in result.tools]

    async def _connect_http(self, config: ServerConfig) -> list[ToolInfo]:
        if not config.url:
            raise ValueError(f"Server {config.name} has no URL for HTTP transport")

        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(config.url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                return [self._convert_tool(t) for t in result.tools]

    def skip_connect_audit(self, config: ServerConfig) -> ServerAudit:
        """Return a ServerAudit with config-inferred permissions (no connection)."""
        categories = self._infer_categories_from_config(config)

        findings: list[PermissionFinding] = [
            PermissionFinding(
                category=cat,
                confidence=Confidence.LOW,
                evidence=["config-inferred (--skip-connect)"],
                tool_name="(config)",
            )
            for cat in categories
        ]

        # Env key names suggesting credential usage → NETWORK
        for key in config.env_keys:
            key_upper = key.upper()
            if any(sub in key_upper for sub in _CREDENTIAL_SUBSTRINGS):
                if PermissionCategory.NETWORK not in {f.category for f in findings}:
                    findings.append(
                        PermissionFinding(
                            category=PermissionCategory.NETWORK,
                            confidence=Confidence.LOW,
                            evidence=[f"env key {key!r} suggests remote API"],
                            tool_name="(config)",
                        )
                    )
                break

        return ServerAudit(
            server=config,
            connection_status="skipped",
            permissions=findings,
        )

    def _infer_categories_from_config(self, config: ServerConfig) -> list[PermissionCategory]:
        command_str = " ".join(filter(None, [config.command, *config.args, config.url or ""])).lower()
        for pattern, categories in KNOWN_SERVER_COMMANDS.items():
            if pattern.lower() in command_str:
                return list(categories)
        return []

    @staticmethod
    def _convert_tool(sdk_tool: SdkTool) -> ToolInfo:
        annotations: ToolAnnotations | None = None
        if sdk_tool.annotations is not None:
            annotations = ServerConnector._convert_annotations(sdk_tool.annotations)

        return ToolInfo(
            name=sdk_tool.name,
            description=sdk_tool.description,
            input_schema=dict(sdk_tool.inputSchema) if sdk_tool.inputSchema else None,
            annotations=annotations,
        )

    @staticmethod
    def _convert_annotations(sdk_ann: SdkToolAnnotations) -> ToolAnnotations:
        """Convert SDK camelCase ToolAnnotations to our snake_case model."""
        return ToolAnnotations(
            title=sdk_ann.title,
            read_only_hint=sdk_ann.readOnlyHint,
            destructive_hint=sdk_ann.destructiveHint,
            idempotent_hint=sdk_ann.idempotentHint,
            open_world_hint=sdk_ann.openWorldHint,
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
