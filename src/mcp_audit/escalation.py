"""Capability-escalation ("rug pull") detector.

Compares each tool against its operator-blessed pin baseline and flags
security-significant escalations:

  MCP018 (CAPABILITY)            — a tool GAINED a dangerous permission category
                                   it did not hold when pinned.  HIGH when the
                                   gained category is exfiltration/shell_execution/
                                   destructive; MEDIUM for file_write/network.
  MCP019 (DESCRIPTION_INJECTION) — a tool's description GAINED prompt-injection
                                   pattern(s) absent from the pinned baseline.

This is the temporal / supply-chain layer: a previously-trusted MCP server that
ships an update quietly broadening its capability surface or mutating its
description to carry agent-targeting instructions.  Findings are a pure DELTA
against the pin store — a tool matching its baseline produces nothing, so the
false-positive rate is near-zero by construction.

The detector reuses the existing permission inference (``PermissionAnalyzer``)
and injection scanner (``InjectionDetector``); it performs no new inference of
its own.  It reads tool metadata only (never values, never credentials) and
issues no network requests.  Opt-in behind ``--escalation-check`` (which implies
a pin comparison).
"""

from __future__ import annotations

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.injection import InjectionDetector
from mcp_audit.models import (
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    PermissionCategory,
    ToolInfo,
)

# Gained categories that make a capability escalation HIGH vs MEDIUM.
_HIGH_CATEGORIES: frozenset[PermissionCategory] = frozenset(
    {
        PermissionCategory.EXFILTRATION,
        PermissionCategory.SHELL_EXEC,
        PermissionCategory.DESTRUCTIVE,
    }
)
_MEDIUM_CATEGORIES: frozenset[PermissionCategory] = frozenset(
    {
        PermissionCategory.FILE_WRITE,
        PermissionCategory.NETWORK,
    }
)
_DANGEROUS_CATEGORIES: frozenset[PermissionCategory] = _HIGH_CATEGORIES | _MEDIUM_CATEGORIES


class EscalationAnalyzer:
    """Detects capability / description-injection escalation against a pin baseline."""

    def __init__(self) -> None:
        self._analyzer = PermissionAnalyzer()
        self._injection = InjectionDetector()

    def analyze_server(
        self,
        server_name: str,
        baseline_tools: list[ToolInfo],
        current_tools: list[ToolInfo],
    ) -> list[EscalationFinding]:
        """Return escalation findings for one server.

        Only tools present in BOTH the baseline and the current scan are
        compared — a brand-new tool is reported by drift (NEW), not escalation,
        and a removed tool cannot escalate.  Matching is by tool name.
        """
        baseline_by_name = {t.name: t for t in baseline_tools}
        findings: list[EscalationFinding] = []

        for tool in current_tools:
            baseline = baseline_by_name.get(tool.name)
            if baseline is None:
                continue  # new tool — covered by drift NEW, not an escalation

            findings.extend(self._capability_finding(server_name, baseline, tool))
            findings.extend(self._injection_finding(server_name, baseline, tool))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _capability_finding(
        self, server_name: str, baseline: ToolInfo, current: ToolInfo
    ) -> list[EscalationFinding]:
        old_caps = {f.category for f in self._analyzer.analyze_tool(baseline)}
        new_caps = {f.category for f in self._analyzer.analyze_tool(current)}
        gained = (new_caps - old_caps) & _DANGEROUS_CATEGORIES
        if not gained:
            return []

        severity = EscalationSeverity.HIGH if gained & _HIGH_CATEGORIES else EscalationSeverity.MEDIUM
        gained_sorted = sorted(gained, key=lambda c: c.value)
        gained_str = ", ".join(c.value for c in gained_sorted)
        return [
            EscalationFinding(
                kind=EscalationKind.CAPABILITY,
                severity=severity,
                server_name=server_name,
                tool_name=current.name,
                gained_categories=gained_sorted,
                description=(
                    f"Tool '{current.name}' on server '{server_name}' gained capability "
                    f"category(s) [{gained_str}] not present in its pin baseline."
                ),
            )
        ]

    def _injection_finding(
        self, server_name: str, baseline: ToolInfo, current: ToolInfo
    ) -> list[EscalationFinding]:
        old_patterns = {f.pattern_name for f in self._injection.scan_tool(baseline)}
        new_patterns = {f.pattern_name for f in self._injection.scan_tool(current)}
        gained = new_patterns - old_patterns
        if not gained:
            return []

        gained_sorted = sorted(gained)
        gained_str = ", ".join(gained_sorted)
        return [
            EscalationFinding(
                kind=EscalationKind.DESCRIPTION_INJECTION,
                severity=EscalationSeverity.HIGH,
                server_name=server_name,
                tool_name=current.name,
                gained_patterns=gained_sorted,
                description=(
                    f"Tool '{current.name}' on server '{server_name}' gained prompt-injection "
                    f"pattern(s) [{gained_str}] in its description vs the pin baseline."
                ),
            )
        ]
