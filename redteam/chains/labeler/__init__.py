"""Conservative labels derived from current declared metadata."""

import re
from dataclasses import dataclass
from typing import Literal

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import PermissionCategory
from redteam.surface import ServerSurface

Tag = Literal[
    "writes_file",
    "creates_directory",
    "writes_git_config",
    "writes_index",
    "writes_ref",
    "reads_file",
    "runs_command",
    "runs_browser_script",
    "runs_build",
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

    identity = " ".join(
        (surface.server_name, surface.provenance or "", surface.config.command or "", *surface.config.args)
    ).lower()
    is_xcodebuild = "xcodebuildmcp" in identity
    is_machine_room = "machine-room" in identity or "machine_room" in identity

    browser_tools: set[str] = set()
    restricted_git_tools: set[str] = set()
    for tool in sorted(surface.tools, key=lambda item: item.name):
        name = tool.name.lower()
        evidence = f"tool name: {tool.name}"
        if name in {
            "git_log",
            "git_show",
            "git_status",
            "git_ls_files",
            "git_rev_parse",
            "git_diff",
            "git_diff_staged",
            "git_diff_unstaged",
        }:
            restricted_git_tools.add(tool.name)
            add(tool.name, "read", "reads_file", evidence, "definite")
            continue
        if name in {"git_add", "git_reset", "git_branch", "git_checkout", "git_create_branch", "git_commit"}:
            restricted_git_tools.add(tool.name)
            add(
                tool.name,
                "write",
                "writes_index" if name in {"git_add", "git_reset"} else "writes_ref",
                evidence,
                "definite",
            )
            if name in {"git_add", "git_commit"}:
                add(
                    tool.name,
                    "execute",
                    "triggers_git_filter" if name == "git_add" else "triggers_hook",
                    evidence,
                    "conditional",
                    (
                        "Repository has matching .gitattributes and clean filter configuration"
                        if name == "git_add"
                        else "Repository has an executable pre-commit hook"
                    ),
                )
            continue
        name_tokens = _tokens(tool.name)
        directory_only = (
            bool(name_tokens & {"directory", "dir"})
            and bool(name_tokens & {"create", "make", "mkdir"})
            and "file" not in name_tokens
        )
        fields = {"name": tool.name, "description": tool.description or ""}
        path_fields: set[str] = set()
        content_fields: set[str] = set()
        properties = tool.input_schema.get("properties")
        if isinstance(properties, dict):
            for key, value in sorted(properties.items(), key=lambda item: str(item[0])):
                if not isinstance(key, str):
                    continue
                path = f"inputSchema.properties.{key}"
                fields[path] = key
                parameter_tokens = _tokens(key)
                if parameter_tokens & {"path", "file", "filename", "filepath", "destination", "target"}:
                    path_fields.add(path)
                if parameter_tokens & {"content", "contents", "data", "text", "body", "edits"}:
                    content_fields.add(path)
                if isinstance(value, dict) and isinstance(value.get("description"), str):
                    fields[f"{path}.description"] = value["description"]
        tokens = {path: _tokens(text) for path, text in fields.items()}
        all_tokens = set().union(*tokens.values())
        context_tokens = set().union(*(words for path, words in tokens.items() if path != "name"))
        if (
            (bool(all_tokens & {"javascript", "js"}) or {"java", "script"} <= all_tokens)
            and context_tokens & {"browser", "page", "tab"}
            and all_tokens & {"run", "runs", "execute", "executes", "evaluate", "evaluates"}
            and not all_tokens & {"host", "shell", "command", "cmd", "process", "bash", "rce"}
        ):
            browser_tools.add(tool.name)
            add(
                tool.name,
                "execute",
                "runs_browser_script",
                "JavaScript in browser/page/tab context; overrides host command inference",
            )
        if directory_only:
            add(tool.name, "write", "creates_directory", evidence)
        elif name == "move_file":
            add(tool.name, "write", "writes_file", "move can place an attacker-controlled file at a path")
        if name in {"write_file", "edit_file"}:
            add(tool.name, "write", "writes_file", evidence, "definite")
        elif name in {"read_file", "read_multiple_files"}:
            add(tool.name, "read", "reads_file", evidence, "definite")
        elif name in {"run_command", "execute_command"}:
            add(tool.name, "execute", "runs_command", evidence)
        elif is_xcodebuild and any(word in name for word in ("build", "run")):
            add(tool.name, "execute", "runs_build", evidence)
        elif name in {"fetch", "fetch_url"}:
            add(tool.name, "read", "fetches_url", evidence, "definite")

        if is_machine_room and "start" in all_tokens and "job" in all_tokens:
            relevant = sorted(
                path for path, words in tokens.items() if words & {"start", "job", "command", "process"}
            )
            add(tool.name, "execute", "runs_command", ", ".join(relevant))
        rules: tuple[tuple[Capability, Tag, set[str], set[str]], ...] = (
            (
                "execute",
                "runs_command",
                {"run", "runs", "execute", "exec", "bash", "shell"},
                {"command", "cmd", "script"},
            ),
            ("read", "fetches_url", {"fetch", "fetches", "retrieve", "download", "request"}, {"url", "uri"}),
        )
        for cap, tag, verbs, objects in rules:
            if all_tokens & verbs and all_tokens & objects:
                relevant = sorted(path for path, words in tokens.items() if words & (verbs | objects))
                add(tool.name, cap, tag, ", ".join(relevant))
        if (
            not directory_only
            and all_tokens & {"write", "writes", "create", "save", "put", "edit", "edits"}
            and any(path != content for path in path_fields for content in content_fields)
        ):
            add(tool.name, "write", "writes_file", ", ".join(sorted(path_fields | content_fields)))

    mapping: dict[PermissionCategory, tuple[Capability, Tag]] = {
        PermissionCategory.SHELL_EXEC: ("execute", "runs_command"),
        PermissionCategory.FILE_WRITE: ("write", "writes_file"),
        PermissionCategory.FILE_READ: ("read", "reads_file"),
        PermissionCategory.NETWORK: ("read", "fetches_url"),
    }
    for finding in PermissionAnalyzer().analyze_server(surface.to_tools()):
        if finding.tool_name in restricted_git_tools:
            continue
        # FILE_WRITE is a broad metadata signal, not evidence of arbitrary
        # caller-chosen file contents and destinations. It may enrich an
        # independently established writer label, but cannot create one.
        if (
            finding.category == PermissionCategory.FILE_WRITE
            and (finding.tool_name, "writes_file") not in labels
        ):
            continue
        if finding.category in mapping:
            cap, tag = mapping[finding.category]
            paths = ", ".join(finding.field_paths) or ", ".join(finding.evidence)
            add(finding.tool_name, cap, tag, f"PermissionAnalyzer {finding.category.value}: {paths}")
    for tool_name in browser_tools:
        labels.pop((tool_name, "runs_command"), None)
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
