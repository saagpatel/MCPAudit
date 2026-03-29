"""Tool pinning — SHA256 schema snapshots and drift detection."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models import DriftFinding, DriftStatus, ToolInfo

logger = logging.getLogger(__name__)

DEFAULT_PIN_PATH = Path.home() / ".mcp-audit-pins.yaml"


class PinStore:
    """Stores SHA256 hashes of MCP tool schemas and detects drift between scans."""

    def __init__(self, path: Path = DEFAULT_PIN_PATH) -> None:
        self._path = path
        self._data: dict[str, Any] = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_hash(self, tool: ToolInfo) -> str:
        """Return 'sha256:<hex>' hash of the tool's canonical schema."""
        payload = json.dumps(
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        digest = hashlib.sha256(payload.encode()).hexdigest()
        return f"sha256:{digest}"

    def pin_server(self, server_name: str, tools: list[ToolInfo]) -> None:
        """Upsert pin entries for all tools on a server. Writes atomically."""
        now = datetime.now(UTC).isoformat()
        if "servers" not in self._data:
            self._data["servers"] = {}
        server_entry: dict[str, Any] = self._data["servers"].setdefault(server_name, {"tools": {}})
        tool_entries: dict[str, Any] = server_entry.setdefault("tools", {})
        for tool in tools:
            tool_entries[tool.name] = {
                "hash": self.compute_hash(tool),
                "pinned_at": now,
            }
        self._data["pinned_at"] = now
        self._write()

    def check_drift(self, server_name: str, tools: list[ToolInfo]) -> list[DriftFinding]:
        """Compare current tool hashes against stored pins. Returns drift findings."""
        servers: dict[str, Any] = self._data.get("servers", {})
        server_entry: dict[str, Any] = servers.get(server_name, {})
        pinned_tools: dict[str, Any] = server_entry.get("tools", {})

        findings: list[DriftFinding] = []
        current_names = {t.name for t in tools}
        pinned_names = set(pinned_tools.keys())

        # NEW: in current scan but not pinned
        for tool in tools:
            if tool.name not in pinned_names:
                findings.append(
                    DriftFinding(
                        server_name=server_name,
                        tool_name=tool.name,
                        status=DriftStatus.NEW,
                        stored_hash=None,
                        current_hash=self.compute_hash(tool),
                        pinned_at=None,
                    )
                )
            else:
                # CHANGED: hash mismatch
                pin_entry: dict[str, Any] = pinned_tools[tool.name]
                stored_hash: str = pin_entry.get("hash", "")
                current_hash = self.compute_hash(tool)
                if stored_hash != current_hash:
                    pinned_at_str: str | None = pin_entry.get("pinned_at")
                    pinned_at = datetime.fromisoformat(pinned_at_str) if pinned_at_str else None
                    findings.append(
                        DriftFinding(
                            server_name=server_name,
                            tool_name=tool.name,
                            status=DriftStatus.CHANGED,
                            stored_hash=stored_hash,
                            current_hash=current_hash,
                            pinned_at=pinned_at,
                        )
                    )

        # REMOVED: in pins but not in current scan
        for tool_name in pinned_names - current_names:
            pin_entry = pinned_tools[tool_name]
            stored_hash = pin_entry.get("hash", "")
            pinned_at_str = pin_entry.get("pinned_at")
            pinned_at = datetime.fromisoformat(pinned_at_str) if pinned_at_str else None
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    tool_name=tool_name,
                    status=DriftStatus.REMOVED,
                    stored_hash=stored_hash,
                    current_hash=None,
                    pinned_at=pinned_at,
                )
            )

        return findings

    def remove_server(self, server_name: str) -> None:
        """Remove all pins for a server. No-op if server not pinned."""
        servers: dict[str, Any] = self._data.get("servers", {})
        if server_name in servers:
            del servers[server_name]
            self._write()

    def pinned_servers(self) -> list[str]:
        """Return list of server names that have pins."""
        return list(self._data.get("servers", {}).keys())

    def tool_count(self, server_name: str) -> int:
        """Return number of pinned tools for a server."""
        servers: dict[str, Any] = self._data.get("servers", {})
        return len(servers.get(server_name, {}).get("tools", {}))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            raw: Any = yaml.safe_load(self._path.read_text())
            return dict(raw) if isinstance(raw, dict) else {}
        except Exception:
            logger.warning("Failed to parse pin file %s — treating as empty", self._path)
            return {}

    def _write(self) -> None:
        """Write pin data atomically (tmp file → rename)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.dump(self._data, default_flow_style=False, allow_unicode=True))
        tmp.rename(self._path)
