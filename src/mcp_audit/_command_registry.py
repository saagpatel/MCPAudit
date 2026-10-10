"""Explicit command metadata, independent of command implementations."""

from __future__ import annotations

from collections.abc import Mapping
from copy import copy
from dataclasses import dataclass
from importlib import import_module
from typing import Any

import click
from click.shell_completion import CompletionItem


@dataclass(frozen=True)
class CommandSpec:
    module: str
    attribute: str
    help: str
    section: str = "Advanced"
    hidden: bool = False
    subcommands: tuple[str, ...] = ()


@dataclass(frozen=True)
class NamespaceSpec:
    help: str
    children: Mapping[str, CommandSpec]
    section: str = "Advanced"
    hidden: bool = False


class LazyGroup(click.Group):
    """List, render help, and complete names without importing implementations."""

    def __init__(
        self,
        name: str | None = None,
        *,
        registry: Mapping[str, CommandSpec | NamespaceSpec],
        **kwargs: Any,
    ) -> None:
        super().__init__(name=name, **kwargs)
        self.registry = registry

    def list_commands(self, ctx: click.Context) -> list[str]:
        return sorted(self.registry)

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        spec = self.registry.get(cmd_name)
        if spec is None:
            return None
        if isinstance(spec, NamespaceSpec):
            return LazyGroup(name=cmd_name, help=spec.help, registry=spec.children)
        command = getattr(import_module(spec.module), spec.attribute)
        if not isinstance(command, click.Command):
            raise TypeError(f"registry entry {cmd_name!r} is not a Click command")
        # Aliases must not mutate the canonical implementation's metadata.
        command = copy(command)
        command.name = cmd_name
        command.hidden = spec.hidden
        return command

    def format_commands(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        sections: dict[str, list[tuple[str, str]]] = {}
        show_all = bool(ctx.meta.get("help_all"))
        for name, spec in self.registry.items():
            if spec.hidden and not show_all:
                continue
            section = "Compatibility aliases" if spec.hidden else spec.section
            rows = sections.setdefault(section, [])
            rows.append((name, spec.help))
            if show_all:
                if isinstance(spec, NamespaceSpec):
                    for child_name, child in spec.children.items():
                        rows.append((f"{name} {child_name}", child.help))
                        rows.extend((f"{name} {child_name} {leaf}", "") for leaf in child.subcommands)
                else:
                    rows.extend((f"{name} {leaf}", "") for leaf in spec.subcommands)
        for section, rows in sections.items():
            with formatter.section(section):
                formatter.write_dl(rows)

    def shell_complete(self, ctx: click.Context, incomplete: str) -> list[CompletionItem]:
        # Click's default Group implementation resolves every command to complete
        # its name. Include the compatibility spellings here without loading them.
        return [
            CompletionItem(name, help=spec.help)
            for name, spec in sorted(self.registry.items())
            if name.startswith(incomplete)
        ] + click.Command.shell_complete(self, ctx, incomplete)


LAB_COMMANDS = {
    "agent-ui": CommandSpec(
        "mcp_audit.agent_ui_cli",
        "agent_ui",
        "Audit synthetic Agent UI fixtures offline.",
        subcommands=("scan", "schema"),
    ),
    "authorization-posture": CommandSpec(
        "mcp_audit.authorization_posture_cli",
        "authorization_posture",
        "Review saved authorization posture offline.",
        subcommands=("review", "schema"),
    ),
    "cache-contract": CommandSpec(
        "mcp_audit.cache_contract_cli",
        "cache_contract",
        "Audit saved cache contracts offline.",
        subcommands=("scan", "schema"),
    ),
    "enforcement-fixture": CommandSpec(
        "mcp_audit.enforcement_cli",
        "enforcement_fixture",
        "Experimental fixture-only enforcement.",
        subcommands=("prepare", "approve", "apply", "rollback"),
    ),
    "oauth-transcript": CommandSpec(
        "mcp_audit.oauth_transcript_cli",
        "oauth_transcript",
        "Audit synthetic OAuth transcripts offline.",
        subcommands=("scan", "schema"),
    ),
    "result-parcel": CommandSpec(
        "mcp_audit.result_parcel_cli",
        "result_parcel",
        "Audit synthetic result parcels offline.",
        subcommands=("analyze", "builtins", "generate-large", "schema"),
    ),
    "session-resume": CommandSpec(
        "mcp_audit.session_resume_cli",
        "session_resume",
        "Replay offline session/resume faults.",
        subcommands=("list", "run", "schema"),
    ),
    "task-time-machine": CommandSpec(
        "mcp_audit.task_time_machine_cli",
        "task_time_machine",
        "Replay synthetic MCP task timelines.",
        subcommands=("list", "run", "schema"),
    ),
}
SAFEFORGE_COMMANDS = {
    "preinstall": CommandSpec(
        "mcp_audit.safeforge_cli", "safeforge_preinstall", "Verify a forge handoff without execution."
    ),
    "run": CommandSpec("mcp_audit.safeforge_cli", "safeforge_run", "Run the disposable SafeForge pipeline."),
}
SKILLS_COMMANDS = {
    "scan": CommandSpec("mcp_audit.skillscan_cli", "skillscan", "Scan a skill directory or bundle offline."),
}
BASELINE_COMMANDS = {
    "pin": CommandSpec(
        "mcp_audit.pin_cli",
        "pin_command",
        "Create, review, refresh, or clear pin baselines.",
        subcommands=("keygen", "rotate-key", "trust-key"),
    ),
}

COMMANDS: dict[str, CommandSpec | NamespaceSpec] = {
    "check": CommandSpec("mcp_audit.check_cli", "check", "Statically review MCP configuration.", "Everyday"),
    "checkup": CommandSpec("mcp_audit.check_cli", "checkup", "Write a local HTML checkup card.", "Everyday"),
    "inspect": CommandSpec(
        "mcp_audit.check_cli", "inspect", "List configuration source identities.", "Everyday"
    ),
    "demo": CommandSpec("mcp_audit.check_cli", "demo", "Review the bundled synthetic example.", "Everyday"),
    "explain": CommandSpec("mcp_audit._core_cli", "explain", "Explain a finding offline.", "Everyday"),
    "serve": CommandSpec(
        "mcp_audit.server", "serve_command", "Run MCPAudit as an MCP server.", "Integrations"
    ),
    "scan": CommandSpec("mcp_audit._core_cli", "scan", "Full legacy audit with explicit scan modes."),
    "discover": CommandSpec(
        "mcp_audit._core_cli", "discover", "Discover configured servers without connections."
    ),
    "watch": CommandSpec("mcp_audit.watcher", "watch_command", "Watch configuration changes and re-scan."),
    "baseline": NamespaceSpec("Manage saved tool schema baselines.", BASELINE_COMMANDS),
    "skills": NamespaceSpec("Review local skills and bundles.", SKILLS_COMMANDS),
    "safeforge": NamespaceSpec("Verify and run forge handoffs.", SAFEFORGE_COMMANDS),
    "lab": NamespaceSpec("Experimental offline evidence contracts.", LAB_COMMANDS, "Labs"),
    "monitor": CommandSpec(
        "mcp_audit.monitor",
        "monitor_command",
        "Deprecated; scheduled for removal in 3.0.",
        hidden=True,
    ),
}

for _name, _spec in LAB_COMMANDS.items():
    COMMANDS[_name] = CommandSpec(
        _spec.module,
        _spec.attribute,
        _spec.help,
        hidden=True,
        subcommands=_spec.subcommands,
    )
for _name, _spec in (
    ("safeforge-preinstall", SAFEFORGE_COMMANDS["preinstall"]),
    ("safeforge-run", SAFEFORGE_COMMANDS["run"]),
    ("skillscan", SKILLS_COMMANDS["scan"]),
    ("pin", BASELINE_COMMANDS["pin"]),
):
    COMMANDS[_name] = CommandSpec(
        _spec.module,
        _spec.attribute,
        _spec.help,
        hidden=True,
        subcommands=_spec.subcommands,
    )
