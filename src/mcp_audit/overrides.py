"""User override config — allow/deny permission findings per server+tool."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding

# Default path for user override config
DEFAULT_OVERRIDE_PATH = Path.home() / ".mcp-audit.yaml"

# Map PermissionOverride field names → PermissionCategory
_FIELD_TO_CATEGORY: dict[str, PermissionCategory] = {
    "file_read": PermissionCategory.FILE_READ,
    "file_write": PermissionCategory.FILE_WRITE,
    "network": PermissionCategory.NETWORK,
    "shell_execution": PermissionCategory.SHELL_EXEC,
    "destructive": PermissionCategory.DESTRUCTIVE,
    "exfiltration": PermissionCategory.EXFILTRATION,
}


class PermissionOverride(BaseModel):
    """Per-category boolean overrides. True = force-add MANUAL finding. False = remove."""

    file_read: bool | None = None
    file_write: bool | None = None
    network: bool | None = None
    shell_execution: bool | None = None
    destructive: bool | None = None
    exfiltration: bool | None = None


class ServerToolOverride(BaseModel):
    """Override rule targeting a specific server+tool combination."""

    server: str  # exact server name or "*" for all servers
    tool: str  # exact tool name or "*" for all tools on server
    permissions: PermissionOverride
    notes: str | None = None


class OverrideConfig(BaseModel):
    """Top-level override configuration loaded from YAML."""

    overrides: list[ServerToolOverride] = []


def load_override_config(path: Path = DEFAULT_OVERRIDE_PATH) -> OverrideConfig:
    """Load override config from path. Returns empty config if path does not exist."""
    if not path.exists():
        return OverrideConfig()
    raw: Any = yaml.safe_load(path.read_text())
    return OverrideConfig.model_validate(raw or {})


class OverrideApplier:
    """Applies user overrides to a list of PermissionFindings post-analysis."""

    def __init__(self, config: OverrideConfig) -> None:
        self._config = config

    def apply(self, server_name: str, findings: list[PermissionFinding]) -> list[PermissionFinding]:
        """Return findings with overrides applied. Does not mutate the input list."""
        # Fast path: no overrides configured
        server_overrides = [o for o in self._config.overrides if o.server == server_name or o.server == "*"]
        if not server_overrides:
            return list(findings)

        result = list(findings)

        for override in server_overrides:
            # Determine which tool names this override applies to
            if override.tool == "*":
                tool_names: set[str] = {f.tool_name for f in result} or {"*"}
            else:
                tool_names = {override.tool}

            evidence = f"override: {override.notes}" if override.notes else "override: manual"

            for field, category in _FIELD_TO_CATEGORY.items():
                value = getattr(override.permissions, field)
                if value is None:
                    continue

                for tool_name in tool_names:
                    if value is False:
                        # Remove all findings for (tool_name, category)
                        result = [
                            f for f in result if not (f.tool_name == tool_name and f.category == category)
                        ]
                    else:
                        # True: upsert — add only if not already present
                        already_present = any(
                            f.tool_name == tool_name and f.category == category for f in result
                        )
                        if not already_present:
                            result.append(
                                PermissionFinding(
                                    category=category,
                                    confidence=Confidence.MANUAL,
                                    evidence=[evidence],
                                    tool_name=tool_name,
                                )
                            )

        return result
