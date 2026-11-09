"""Conservative labels derived from current declared metadata."""

import re
from dataclasses import dataclass
from typing import Literal

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import PermissionCategory
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


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text).lower()))


def label_server(surface: ServerSurface) -> list[ToolLabel]:
    labels: dict[tuple[str, Tag], ToolLabel] = {}
    strength = {"heuristic": 0, "conditional": 1, "definite": 2}

    def add(
        tool: str,
        cap: Capability,
        tag: Tag,
        evidence: str,
        confidence: Confidence = "heuristic",
        condition: str | None = None,
    ) -> None:
        key = (tool, tag)
        previous = labels.get(key)
        if previous is None:
            labels[key] = ToolLabel(tool, cap, tag, evidence, confidence, condition)
        else:
            winner = (
                ToolLabel(tool, cap, tag, evidence, confidence, condition)
                if strength[confidence] > strength[previous.confidence]
                else previous
            )
            merged = "; ".join(sorted(set(previous.evidence.split("; ") + [evidence])))
            labels[key] = ToolLabel(tool, winner.capability, tag, merged, winner.confidence, winner.condition)

    for tool in sorted(surface.tools, key=lambda item: item.name):
        name = tool.name.lower()
        evidence = f"tool name: {tool.name}"
        if name in {"write_file", "edit_file"}:
            add(tool.name, "write", "writes_file", evidence, "definite")
        elif name == "git_add":
            add(tool.name, "write", "writes_index", evidence, "definite")
            add(
                tool.name,
                "execute",
                "triggers_git_filter",
                evidence,
                "conditional",
                "Repository has matching .gitattributes and clean filter configuration",
            )
        elif name == "git_commit":
            add(
                tool.name,
                "execute",
                "triggers_hook",
                evidence,
                "conditional",
                "Repository has an executable pre-commit hook",
            )
        elif name in {"read_file", "read_multiple_files"}:
            add(tool.name, "read", "reads_file", evidence, "definite")
        elif name in {"run_command", "execute_command"}:
            add(tool.name, "execute", "runs_command", evidence)
        elif name in {"fetch", "fetch_url"}:
            add(tool.name, "read", "fetches_url", evidence, "definite")

        fields = {"name": tool.name, "description": tool.description or ""}
        properties = tool.input_schema.get("properties")
        if isinstance(properties, dict):
            for key, value in sorted(properties.items(), key=lambda item: str(item[0])):
                if not isinstance(key, str):
                    continue
                path = f"inputSchema.properties.{key}"
                fields[path] = key
                if isinstance(value, dict) and isinstance(value.get("description"), str):
                    fields[f"{path}.description"] = value["description"]
        tokens = {path: _tokens(text) for path, text in fields.items()}
        all_tokens = set().union(*tokens.values())
        rules: tuple[tuple[Capability, Tag, set[str], set[str]], ...] = (
            (
                "execute",
                "runs_command",
                {"run", "runs", "execute", "exec", "bash", "shell"},
                {"command", "cmd", "script"},
            ),
            (
                "write",
                "writes_file",
                {"write", "writes", "create", "save", "put", "edit"},
                {"file", "path", "content"},
            ),
            ("read", "fetches_url", {"fetch", "fetches", "retrieve", "download", "request"}, {"url", "uri"}),
        )
        for cap, tag, verbs, objects in rules:
            if all_tokens & verbs and all_tokens & objects:
                relevant = sorted(path for path, words in tokens.items() if words & (verbs | objects))
                add(tool.name, cap, tag, ", ".join(relevant))

    mapping: dict[PermissionCategory, tuple[Capability, Tag]] = {
        PermissionCategory.SHELL_EXEC: ("execute", "runs_command"),
        PermissionCategory.FILE_WRITE: ("write", "writes_file"),
        PermissionCategory.FILE_READ: ("read", "reads_file"),
        PermissionCategory.NETWORK: ("read", "fetches_url"),
    }
    for finding in PermissionAnalyzer().analyze_server(surface.to_tools()):
        if finding.category in mapping:
            cap, tag = mapping[finding.category]
            paths = ", ".join(finding.field_paths) or ", ".join(finding.evidence)
            add(finding.tool_name, cap, tag, f"PermissionAnalyzer {finding.category.value}: {paths}")
    for label in list(labels.values()):
        if label.tag == "writes_file":
            add(
                label.tool,
                "write",
                "writes_git_config",
                label.evidence,
                "conditional",
                "Path scope permits writing .git/config and .gitattributes",
            )
    for tool in surface.tools:
        if not any(name == tool.name for name, _ in labels):
            add(tool.name, "unknown", "unknown", f"tool name: {tool.name}")
    return sorted(labels.values(), key=lambda label: (label.tool, label.tag))
