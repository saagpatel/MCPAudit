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
finding stays scoped to a reviewed baseline delta.

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
    CapabilityTarget,
    DriftFinding,
    DriftStatus,
    EscalationFinding,
    EscalationKind,
    EscalationSeverity,
    PermissionCategory,
    SurfaceFieldChange,
    ToolInfo,
)
from mcp_audit.redaction import redact_data

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


def detect_session_drift(
    server_name: str,
    before: dict[str, dict[str, object]],
    after: dict[str, dict[str, object]],
    after_call: int,
) -> list[DriftFinding]:
    """Compare observed surfaces with their last known successful values.

    The caller retains unavailable categories across failed listings. A failed
    prompts/get retains only that prompt, rather than losing its peers.
    """
    from mcp_audit.pinning import surface_field_diff, surface_hash

    findings: list[DriftFinding] = []
    # An unavailable listing is a coverage warning, not evidence of removal.
    for surface in sorted(before.keys() & after.keys()):
        old_items, new_items = before.get(surface, {}), after.get(surface, {})
        # A missing individual get is unknown, including in the first capture.
        # Prompt additions/removals are established by the successful listing.
        names = (
            old_items.keys() & new_items.keys()
            if surface == "prompt_results"
            else old_items.keys() | new_items.keys()
        )
        for name in sorted(names):
            old, new = old_items.get(name), new_items.get(name)
            if old == new:
                continue
            status = (
                DriftStatus.NEW
                if name not in old_items
                else DriftStatus.REMOVED
                if name not in new_items
                else DriftStatus.CHANGED
            )
            if status == DriftStatus.NEW:
                fields = [SurfaceFieldChange(path="", after_hash=surface_hash(new))]
            elif status == DriftStatus.REMOVED:
                fields = [SurfaceFieldChange(path="", before_hash=surface_hash(old))]
            else:
                fields = surface_field_diff(old, new)
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    tool_name=name,
                    status=status,
                    stored_hash=surface_hash(old) if name in old_items else None,
                    current_hash=surface_hash(new) if name in new_items else None,
                    source="session",
                    severity="high",
                    after_call=after_call,
                    surface=surface,
                    surface_type=(
                        CapabilityTarget.TOOL
                        if surface == "tools"
                        else CapabilityTarget.RESOURCE
                        if surface == "resources"
                        else CapabilityTarget.PROMPT
                    ),
                    field_changes=fields,
                    summary=f"{surface} surface changed after canary call {after_call}.",
                    details=[f"{surface}{field.path or '/'} changed" for field in fields],
                    remediation="Review the changed surface before exercising this session again.",
                )
            )
    return findings


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
        *,
        uncovered_annotations: set[str] | None = None,
        incomplete_reasons: list[str] | None = None,
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

            # Pins store redacted metadata; normalize both sides, including
            # legacy raw snapshots, before re-deriving capability/injection deltas.
            baseline = ToolInfo.model_validate(redact_data(baseline.model_dump()))
            tool = ToolInfo.model_validate(redact_data(tool.model_dump()))
            if uncovered_annotations is not None and tool.name in uncovered_annotations:
                # A v1 snapshot never observed hints: do not invent an annotation delta.
                baseline = baseline.model_copy(update={"annotations": None})
                tool = tool.model_copy(update={"annotations": None})
            else:
                findings.extend(self._annotation_finding(server_name, baseline, tool))
            findings.extend(
                self._capability_finding(server_name, baseline, tool, incomplete_reasons=incomplete_reasons)
            )
            findings.extend(self._injection_finding(server_name, baseline, tool))

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _annotation_finding(
        self, server_name: str, baseline: ToolInfo, current: ToolInfo
    ) -> list[EscalationFinding]:
        old, new = baseline.annotations, current.annotations
        changes: list[str] = []
        if old is not None and old.read_only_hint is True and (new is None or new.read_only_hint is not True):
            changes.append("readOnlyHint")
        if (
            (old is None or old.destructive_hint is not True)
            and new is not None
            and new.destructive_hint is True
        ):
            changes.append("destructiveHint")
        if (
            old is not None
            and old.open_world_hint is False
            and (new is None or new.open_world_hint is not False)
        ):
            changes.append("openWorldHint")
        if not changes:
            return []
        return [
            EscalationFinding(
                kind=EscalationKind.ANNOTATION_DELTA,
                severity=EscalationSeverity.HIGH,
                server_name=server_name,
                tool_name=current.name,
                annotation_changes=changes,
                description="Security-relevant annotation hints changed: " + ", ".join(changes) + ".",
            )
        ]

    def _capability_finding(
        self,
        server_name: str,
        baseline: ToolInfo,
        current: ToolInfo,
        *,
        incomplete_reasons: list[str] | None = None,
    ) -> list[EscalationFinding]:
        old_caps = {
            f.category for f in self._analyzer.analyze_tool(baseline, incomplete_reasons=incomplete_reasons)
        }
        new_caps = {
            f.category for f in self._analyzer.analyze_tool(current, incomplete_reasons=incomplete_reasons)
        }
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
        old_patterns = {f.instruction_pattern or f.pattern_name for f in self._injection.scan_tool(baseline)}
        new_patterns = {f.instruction_pattern or f.pattern_name for f in self._injection.scan_tool(current)}
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
