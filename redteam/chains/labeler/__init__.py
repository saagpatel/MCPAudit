"""Conservative labels derived from current declared metadata."""

from dataclasses import dataclass
from typing import Literal

from redteam.surface import ServerSurface

Tag = Literal[
    "writes_file",
    "writes_git_config",
    "writes_index",
    "reads_file",
    "runs_command",
    "triggers_git_filter",
    "triggers_hook",
    "fetches_url",
    "unknown",
]
Capability = Literal["read", "write", "execute", "unknown"]
Confidence = Literal["definite", "conditional", "heuristic"]


@dataclass(frozen=True)
class ToolLabel:
    tool: str
    capability: Capability
    tag: Tag
    evidence: str
    confidence: Confidence
    condition: str | None = None


def label_server(surface: ServerSurface) -> list[ToolLabel]:
    labels: list[ToolLabel] = []
    for tool in sorted(surface.tools, key=lambda item: item.name):

        def add(
            cap: Capability,
            tag: Tag,
            confidence: Confidence = "heuristic",
            condition: str | None = None,
            tool_name: str = tool.name,
        ) -> None:
            labels.append(ToolLabel(tool_name, cap, tag, f"tool name: {tool_name}", confidence, condition))

        name = tool.name.lower()
        if name in {"write_file", "edit_file"}:
            add("write", "writes_file")
            add(
                "write",
                "writes_git_config",
                "conditional",
                "Path scope permits writing .git/config and .gitattributes",
            )
        elif name == "git_add":
            add("write", "writes_index")
            add(
                "execute",
                "triggers_git_filter",
                "conditional",
                "Repository has matching .gitattributes and clean filter configuration",
            )
        elif name == "git_commit":
            add("execute", "triggers_hook", "conditional", "Repository has an executable pre-commit hook")
        elif name in {"read_file", "read_multiple_files"}:
            add("read", "reads_file")
        elif name in {"run_command", "execute_command"}:
            add("execute", "runs_command")
        elif name in {"fetch", "fetch_url"}:
            add("read", "fetches_url")
        else:
            add("unknown", "unknown")
    return labels
