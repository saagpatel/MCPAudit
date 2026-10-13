"""Shared client selection parsing for core commands."""

from __future__ import annotations

from mcp_audit.models import ClientType
from mcp_audit.report import error_console
from mcp_audit.terminal_text import terminal_safe


def _parse_clients(clients_str: str | None) -> list[ClientType] | None:
    """Parse a comma-separated client filter, or return ``None`` for all clients."""
    if not clients_str:
        return None
    result: list[ClientType] = []
    for part in clients_str.split(","):
        part = part.strip()
        try:
            result.append(ClientType(part))
        except ValueError:
            valid = ", ".join(client.value for client in ClientType)
            error_console.print(terminal_safe(f"Unknown client '{part}'. Valid values: {valid}"), style="red")
            raise SystemExit(1) from None
    return result or None
