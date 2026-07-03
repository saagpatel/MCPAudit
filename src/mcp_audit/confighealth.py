"""Config-health analysis over discovered server configs.

Pure analysis: takes parsed :class:`ServerConfig` lists and returns structured
:class:`ConfigHealthFinding` records. No I/O beyond an existence check for
local binaries, no rendering — terminal presentation stays with the callers
(the CLI renders warnings; the scan engine embeds findings in the report).
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from mcp_audit.models import (
    ConfigHealthFinding,
    ConfigHealthSeverity,
    ServerConfig,
    TransportType,
)
from mcp_audit.redaction import redact_text

_CREDENTIAL_HEAVY_THRESHOLD = 3
_REMOTE_URL = re.compile(r"https?://", re.IGNORECASE)
_SHELL_WRAPPERS = {"bash", "sh", "zsh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}
_PACKAGE_RUNNERS = {"npx", "uvx", "docker"}
_DOCKER_SUBCOMMANDS = {"container", "image", "pull", "run"}


def duplicate_server_config_counts(servers: list[ServerConfig]) -> dict[str, int]:
    counts = Counter(server.name for server in servers)
    return {name: count for name, count in counts.items() if count > 1}


def _conflicting_scope_server_names(servers: list[ServerConfig]) -> dict[str, list[str]]:
    scopes_by_name: dict[str, set[str]] = {}
    for server in servers:
        scope = "global" if server.project_path is None else f"project:{server.project_path}"
        scopes_by_name.setdefault(server.name, set()).add(scope)
    return {
        name: sorted(scopes)
        for name, scopes in scopes_by_name.items()
        if "global" in scopes and any(scope.startswith("project:") for scope in scopes)
    }


def _conflicting_definition_server_names(servers: list[ServerConfig]) -> dict[str, list[str]]:
    definitions_by_name: dict[str, set[str]] = {}
    for server in servers:
        definitions_by_name.setdefault(server.name, set()).add(_server_definition_summary(server))
    return {
        name: sorted(definitions) for name, definitions in definitions_by_name.items() if len(definitions) > 1
    }


def config_health_findings(servers: list[ServerConfig]) -> list[ConfigHealthFinding]:
    findings: list[ConfigHealthFinding] = []

    for name, count in sorted(duplicate_server_config_counts(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="duplicate_server_name",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' appears {count} times; pins are keyed by server name, so rename "
                    "duplicate MCP server entries before pinning."
                ),
                details=[f"{count} discovered configs share the same server name."],
                remediation="Rename duplicate MCP server entries before creating or refreshing pins.",
            )
        )

    for name, scopes in sorted(_conflicting_scope_server_names(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="conflicting_scope_server_name",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' is configured in both global and project scopes; "
                    "review which entry should be authoritative before pinning."
                ),
                details=scopes,
                remediation=(
                    "If project-local shadowing is intentional, give the project server a unique reviewed "
                    "name before pinning. Otherwise remove the unintended duplicate so reviews and pins "
                    "refer to one authoritative scope."
                ),
            )
        )

    for name, definitions in sorted(_conflicting_definition_server_names(servers).items()):
        findings.append(
            ConfigHealthFinding(
                finding_type="conflicting_server_definition",
                severity=ConfigHealthSeverity.MEDIUM,
                server_name=name,
                summary=(
                    f"'{name}' has multiple command or URL definitions across discovered configs; "
                    "review which one should be trusted."
                ),
                details=definitions,
                remediation=(
                    "Align duplicate server definitions or rename entries so each reviewed server name "
                    "maps to one intended command or URL."
                ),
            )
        )

    for server in servers:
        if server.transport == TransportType.STDIO and not server.command:
            findings.append(
                ConfigHealthFinding(
                    finding_type="missing_stdio_command",
                    severity=ConfigHealthSeverity.HIGH,
                    server_name=server.name,
                    summary=f"'{server.name}' uses stdio but has no command; connected scans will fail.",
                    details=["stdio transport requires a configured command."],
                    remediation="Add a command for the server or remove the incomplete config entry.",
                )
            )
        if _missing_local_binary(server):
            findings.append(
                ConfigHealthFinding(
                    finding_type="missing_local_binary",
                    severity=ConfigHealthSeverity.HIGH,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' command path does not exist locally; connected scans will fail."
                    ),
                    details=[f"Configured command: {server.command}"],
                    remediation=(
                        "Install the referenced local binary, correct the command path, or remove the stale "
                        "server entry."
                    ),
                )
            )
        if server.transport == TransportType.SSE:
            findings.append(
                ConfigHealthFinding(
                    finding_type="deprecated_sse_transport",
                    severity=ConfigHealthSeverity.LOW,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' uses deprecated SSE transport; prefer Streamable HTTP if supported."
                    ),
                    details=["SSE is a legacy MCP transport."],
                    remediation="Move the server to Streamable HTTP when the server supports it.",
                )
            )
        if server.transport in (TransportType.HTTP, TransportType.SSE) or server.url:
            findings.append(
                ConfigHealthFinding(
                    finding_type="remote_endpoint",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' declares a remote endpoint; connected scans may contact "
                        "the network."
                    ),
                    details=["HTTP or SSE MCP transports contact the configured URL during scans."],
                    remediation="Review the remote endpoint before running connected scans.",
                )
            )
        if _REMOTE_URL.search(_config_command_line(server)):
            findings.append(
                ConfigHealthFinding(
                    finding_type="remote_url_argument",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' command or args include a remote URL; review the outbound target."
                    ),
                    details=["The configured command line contains an HTTP or HTTPS URL."],
                    remediation="Review the URL and package source before connecting to the server.",
                )
            )
        package_runner_source = _package_runner_source(server)
        if package_runner_source is not None:
            findings.append(
                ConfigHealthFinding(
                    finding_type="package_runner_source_review",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' launches through package runner '{_command_name(server.command)}'; "
                        "review the package or image source before connecting."
                    ),
                    details=[f"Source: {redact_text(package_runner_source)}"],
                    remediation=(
                        "Pin package versions or container digests where possible and review the source "
                        "before running connected scans."
                    ),
                )
            )
        command_name = _command_name(server.command)
        if command_name in _SHELL_WRAPPERS:
            findings.append(
                ConfigHealthFinding(
                    finding_type="shell_wrapper_launch",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' launches through shell wrapper '{command_name}'; "
                        "review args before connecting."
                    ),
                    details=["Shell wrappers can hide compound commands in arguments."],
                    remediation="Review the shell arguments before running connected scans.",
                )
            )
        credential_count = len(server.env_keys) + len(server.headers_keys)
        if credential_count >= _CREDENTIAL_HEAVY_THRESHOLD:
            findings.append(
                ConfigHealthFinding(
                    finding_type="credential_heavy_config",
                    severity=ConfigHealthSeverity.MEDIUM,
                    server_name=server.name,
                    summary=(
                        f"'{server.name}' references {credential_count} credential key names; "
                        "review their access scope."
                    ),
                    details=["Only credential key names are reported; credential values are not stored."],
                    remediation="Confirm the referenced credentials are scoped to the server's purpose.",
                )
            )

    return findings


def _config_command_line(server: ServerConfig) -> str:
    return " ".join(part for part in [server.command, *server.args] if part)


def _missing_local_binary(server: ServerConfig) -> bool:
    if server.transport != TransportType.STDIO or not server.command:
        return False
    command = server.command.strip()
    if "/" in command or "\\" in command:
        return not Path(command).expanduser().exists()
    return False


def _package_runner_source(server: ServerConfig) -> str | None:
    command_name = _command_name(server.command)
    if command_name not in _PACKAGE_RUNNERS:
        return None
    if command_name == "docker":
        return _docker_image_source(server.args)
    return _first_package_source_arg(server.args)


def _first_package_source_arg(args: list[str]) -> str | None:
    skip_next = False
    for arg in args:
        if skip_next:
            return arg
        if arg in {"--package", "--from", "-p"}:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def _docker_image_source(args: list[str]) -> str | None:
    if not args:
        return None
    index = 0
    if args[0] in _DOCKER_SUBCOMMANDS:
        index = 1
    if len(args) > 1 and args[0] == "container" and args[1] == "run":
        index = 2
    while index < len(args):
        arg = args[index]
        if arg in {"--env", "-e", "--name", "--network", "--platform", "--volume", "-v", "--workdir", "-w"}:
            index += 2
            continue
        if arg.startswith("--") and "=" not in arg:
            index += 1
            continue
        if arg.startswith("-") and "=" not in arg:
            index += 1
            continue
        return arg
    return None


def _server_definition_summary(server: ServerConfig) -> str:
    if server.url:
        return f"{server.transport.value} url={redact_text(server.url)}"
    command = server.command or "missing-command"
    source = _package_runner_source(server)
    if source is not None:
        return f"{server.transport.value} command={_command_name(command)} source={redact_text(source)}"
    return f"{server.transport.value} command={_command_name(command)}"


def _command_name(command: str | None) -> str:
    if not command:
        return ""
    normalized = command.replace("\\", "/").rstrip("/")
    return normalized.rsplit("/", 1)[-1].lower()
