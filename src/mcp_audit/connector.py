"""MCP server connector — spawns/connects to servers and enumerates tools."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import Prompt as SdkPrompt
from mcp.types import Resource as SdkResource
from mcp.types import Tool as SdkTool
from mcp.types import ToolAnnotations as SdkToolAnnotations

from mcp_audit.models import (
    Confidence,
    PermissionCategory,
    PermissionFinding,
    PromptInfo,
    ResourceInfo,
    ServerAudit,
    ServerConfig,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)
from mcp_audit.redaction import redact_text

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
_REMOTE_URL = re.compile(r"https?://", re.IGNORECASE)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_NETWORK_COMMANDS = {"curl", "wget"}
_PACKAGE_RUNNERS = {"npx", "uvx", "pipx"}
_DESTRUCTIVE_MARKERS = ("rm -rf", "remove-item -recurse", "del /s", "format ")


@dataclass(frozen=True)
class _ServerCapabilities:
    tools: list[ToolInfo]
    prompts: list[PromptInfo]
    resources: list[ResourceInfo]


class ServerConnector:
    """Connects to MCP servers and enumerates their tools."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    async def connect(self, config: ServerConfig) -> ServerAudit:
        """Connect to a server and return a ServerAudit with tool list."""
        try:
            with anyio.move_on_after(self.timeout) as cancel_scope:
                if config.transport == TransportType.STDIO:
                    capabilities = await self._connect_stdio(config)
                elif config.transport in (TransportType.HTTP, TransportType.SSE):
                    if config.transport == TransportType.SSE:
                        logger.warning(
                            "Server %s uses deprecated SSE transport; attempting as StreamableHTTP",
                            config.name,
                        )
                    capabilities = await self._connect_http(config)
                else:
                    return ServerAudit(
                        server=config,
                        connection_status="failed",
                        connection_error=f"Unknown transport: {config.transport}",
                    )

            if cancel_scope.cancelled_caught:
                logger.debug("Timeout connecting to %s", config.name)
                return ServerAudit(server=config, connection_status="timeout")

            tools = capabilities.tools
            logger.debug("Connected to %s, found %d tools", config.name, len(tools))
            audit = ServerAudit(
                server=config,
                connection_status="connected",
                tools=tools,
                prompts=capabilities.prompts,
                resources=capabilities.resources,
            )
            audit.has_annotations = any(t.annotations is not None for t in tools)
            if tools:
                annotated = sum(1 for t in tools if t.annotations is not None)
                audit.annotation_coverage = annotated / len(tools)
            return audit

        except Exception as exc:
            logger.debug("Failed to connect to %s: %s", config.name, redact_text(str(exc)))
            return ServerAudit(
                server=config,
                connection_status="failed",
                connection_error=redact_text(str(exc)),
            )

    async def _connect_stdio(self, config: ServerConfig) -> _ServerCapabilities:
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
                return await self._list_capabilities(session, config.name)

    async def _connect_http(self, config: ServerConfig) -> _ServerCapabilities:
        if not config.url:
            raise ValueError(f"Server {config.name} has no URL for HTTP transport")

        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(config.url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await self._list_capabilities(session, config.name)

    async def _list_capabilities(self, session: ClientSession, server_name: str) -> _ServerCapabilities:
        tool_result = await session.list_tools()
        prompts: list[PromptInfo] = []
        resources: list[ResourceInfo] = []

        try:
            prompt_result = await session.list_prompts()
            prompts = [self._convert_prompt(prompt) for prompt in prompt_result.prompts]
        except Exception as exc:
            logger.debug("Server %s prompt listing unavailable: %s", server_name, redact_text(str(exc)))

        try:
            resource_result = await session.list_resources()
            resources = [self._convert_resource(resource) for resource in resource_result.resources]
        except Exception as exc:
            logger.debug("Server %s resource listing unavailable: %s", server_name, redact_text(str(exc)))

        return _ServerCapabilities(
            tools=[self._convert_tool(t) for t in tool_result.tools],
            prompts=prompts,
            resources=resources,
        )

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
        mime_type = _get_attr(sdk_resource, "mimeType", "mime_type")
        return ResourceInfo(
            uri=str(sdk_resource.uri),
            name=sdk_resource.name,
            description=sdk_resource.description,
            mime_type=str(mime_type) if mime_type else None,
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


def _get_attr(obj: object, *names: str) -> Any:
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None
