"""Lethal-trifecta / toxic-flow detector.

Detects when MCP servers hold the canonical agent-exfiltration attack surface:
  Leg 1 — sensitive data access      → PermissionCategory.FILE_READ
  Leg 2 — untrusted-content exposure → PermissionCategory.NETWORK
  Leg 3 — exfiltration/action        → PermissionCategory.EXFILTRATION
                                        | PermissionCategory.SHELL_EXEC
                                        | PermissionCategory.FILE_WRITE

Two tiers of findings:

* Per-server (HIGH) — a single server whose tool findings cover all three legs.
* Fleet-level (MEDIUM, advisory) — the union of legs across all servers == {1,2,3}
  but NO single server already holds all three legs. Non-redundant: suppressed
  when any per-server finding fires.

This detector is purely additive and opt-in behind ``--trifecta-check``.
It re-uses the ``PermissionFinding`` list already computed by the analyzer
and scorer; it never runs new inference, never issues network requests, and
never reads credential values.
"""

from __future__ import annotations

from mcp_audit.models import (
    PermissionCategory,
    ServerAudit,
    TrifectaFinding,
    TrifectaSeverity,
)
from mcp_audit.taxonomy import trifecta_metadata

# ---------------------------------------------------------------------------
# Leg category sets
# ---------------------------------------------------------------------------

_LEG1_CATEGORIES: frozenset[PermissionCategory] = frozenset({PermissionCategory.FILE_READ})
_LEG2_CATEGORIES: frozenset[PermissionCategory] = frozenset({PermissionCategory.NETWORK})
_LEG3_CATEGORIES: frozenset[PermissionCategory] = frozenset(
    {
        PermissionCategory.EXFILTRATION,
        PermissionCategory.SHELL_EXEC,
        PermissionCategory.FILE_WRITE,
    }
)


def _categories_for_audit(audit: ServerAudit) -> set[PermissionCategory]:
    """Return the set of PermissionCategories present in a ServerAudit's findings."""
    cats: set[PermissionCategory] = set()
    for pf in audit.permissions:
        cats.add(pf.category)
    for cf in audit.capability_findings:
        cats.add(cf.category)
    return cats


def _tools_for_category(
    audit: ServerAudit, categories: frozenset[PermissionCategory]
) -> list[tuple[str, str]]:
    """Return (server_name, tool_name) pairs covering any of the given categories."""
    server_name = audit.server.name
    seen: set[str] = set()
    result: list[tuple[str, str]] = []
    for pf in audit.permissions:
        if pf.category in categories and pf.tool_name not in seen:
            seen.add(pf.tool_name)
            result.append((server_name, pf.tool_name))
    for cf in audit.capability_findings:
        if cf.category in categories and cf.target_name not in seen:
            seen.add(cf.target_name)
            result.append((server_name, cf.target_name))
    return result


class TrifectaAnalyzer:
    """Detects lethal-trifecta findings at per-server and fleet level."""

    # ------------------------------------------------------------------
    # Per-server pass
    # ------------------------------------------------------------------

    def analyze_server(self, audit: ServerAudit) -> list[TrifectaFinding]:
        """Return a HIGH finding if this server's findings cover all three legs.

        One finding per server (severity HIGH). Records which tool(s) satisfy
        each leg so the operator can reason about the attack surface.
        """
        cats = _categories_for_audit(audit)
        has_leg1 = bool(cats & _LEG1_CATEGORIES)
        has_leg2 = bool(cats & _LEG2_CATEGORIES)
        has_leg3 = bool(cats & _LEG3_CATEGORIES)

        if not (has_leg1 and has_leg2 and has_leg3):
            return []

        leg1 = _tools_for_category(audit, _LEG1_CATEGORIES)
        leg2 = _tools_for_category(audit, _LEG2_CATEGORIES)
        leg3 = _tools_for_category(audit, _LEG3_CATEGORIES)

        meta = trifecta_metadata(TrifectaSeverity.HIGH)
        return [
            TrifectaFinding(
                severity=TrifectaSeverity.HIGH,
                leg1_contributors=leg1,
                leg2_contributors=leg2,
                leg3_contributors=leg3,
                description=meta.description,
                is_fleet=False,
            )
        ]

    # ------------------------------------------------------------------
    # Fleet-level pass
    # ------------------------------------------------------------------

    def analyze_fleet(self, audits: list[ServerAudit]) -> list[TrifectaFinding]:
        """Return a MEDIUM advisory finding if the fleet's union covers all three legs
        but no single server already has the full trifecta (non-redundant with per-server).

        ``audits`` must be the COMPLETE list of audited servers after per-server
        analysis has already populated ``trifecta_findings``.
        """
        # Suppress fleet finding if any single server already fires per-server.
        for audit in audits:
            if audit.trifecta_findings:
                return []

        # Accumulate legs across the fleet.
        leg1_contributors: list[tuple[str, str]] = []
        leg2_contributors: list[tuple[str, str]] = []
        leg3_contributors: list[tuple[str, str]] = []

        fleet_has_leg1 = False
        fleet_has_leg2 = False
        fleet_has_leg3 = False

        for audit in audits:
            cats = _categories_for_audit(audit)
            if cats & _LEG1_CATEGORIES:
                fleet_has_leg1 = True
                leg1_contributors.extend(_tools_for_category(audit, _LEG1_CATEGORIES))
            if cats & _LEG2_CATEGORIES:
                fleet_has_leg2 = True
                leg2_contributors.extend(_tools_for_category(audit, _LEG2_CATEGORIES))
            if cats & _LEG3_CATEGORIES:
                fleet_has_leg3 = True
                leg3_contributors.extend(_tools_for_category(audit, _LEG3_CATEGORIES))

        if not (fleet_has_leg1 and fleet_has_leg2 and fleet_has_leg3):
            return []

        meta = trifecta_metadata(TrifectaSeverity.MEDIUM)
        return [
            TrifectaFinding(
                severity=TrifectaSeverity.MEDIUM,
                leg1_contributors=leg1_contributors,
                leg2_contributors=leg2_contributors,
                leg3_contributors=leg3_contributors,
                description=meta.description,
                is_fleet=True,
            )
        ]
