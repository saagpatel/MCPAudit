"""Lethal-trifecta / toxic-flow detector.

Detects when MCP servers hold the canonical agent-exfiltration attack surface:
  Leg 1 — sensitive data access      → PermissionCategory.FILE_READ
  Leg 2 — untrusted-content exposure → SSRF-flagged or fetch-verb tool/resource
                                        (genuine ingestion, NOT bare NETWORK reach)
  Leg 3 — exfiltration               → PermissionCategory.EXFILTRATION

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
    RuleOfTwoPosture,
    ServerAudit,
    TrifectaFinding,
    TrifectaSeverity,
)
from mcp_audit.ssrf import SsrfDetector, _has_fetch_verb
from mcp_audit.taxonomy import rule_of_two_action, trifecta_metadata

# ---------------------------------------------------------------------------
# Leg definitions
# ---------------------------------------------------------------------------
#
# Leg 1 and Leg 3 are derived from inferred permission categories. Leg 2 is
# NOT a category — "exposure to untrusted content" means the server actively
# *ingests* external content it does not control. Plain NETWORK capability is
# near-universal across MCP servers and is therefore useless as a signal (it
# fires on ~86% of real servers and never lets the fleet-level pass trigger).
# Instead, Leg 2 reuses the SSRF detector's caller-controlled-fetch signal plus
# fetch-verb tool names — the same notion of "this tool pulls in remote content".

_LEG1_CATEGORIES: frozenset[PermissionCategory] = frozenset({PermissionCategory.FILE_READ})
_LEG3_CATEGORIES: frozenset[PermissionCategory] = frozenset({PermissionCategory.EXFILTRATION})

_ssrf_detector = SsrfDetector()


def _categories_for_audit(audit: ServerAudit) -> set[PermissionCategory]:
    """Return the set of PermissionCategories present in a ServerAudit's findings."""
    cats: set[PermissionCategory] = set()
    for pf in audit.permissions:
        cats.add(pf.category)
    for cf in audit.capability_findings:
        cats.add(cf.category)
    return cats


def _ingestion_contributors(audit: ServerAudit) -> list[tuple[str, str]]:
    """Return (server_name, target) pairs for tools/resources that ingest untrusted content.

    A target qualifies if the SSRF detector flags it (caller-controlled remote
    fetch) or its tool name/description carries a fetch verb. This is Leg 2 of
    the trifecta — genuine untrusted-content ingestion, not mere NETWORK reach.
    """
    server_name = audit.server.name
    seen: set[str] = set()
    result: list[tuple[str, str]] = []

    for finding in _ssrf_detector.scan_server(audit.tools, audit.resources):
        if finding.target_name not in seen:
            seen.add(finding.target_name)
            result.append((server_name, finding.target_name))

    for tool in audit.tools:
        if tool.name not in seen and _has_fetch_verb(tool.name, tool.description):
            seen.add(tool.name)
            result.append((server_name, tool.name))

    return result


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


def _leg_tools(contributors: list[tuple[str, str]], attribute_server: bool = False) -> list[str]:
    """Deduplicate a leg's contributor tool names, preserving first-seen order.

    With ``attribute_server`` (fleet findings span multiple servers) each entry is rendered
    ``tool (server)`` and deduplicated by ``(server, tool)``, so identical tool names on
    different servers stay distinct and the remediation names which server each tool is on.
    """
    seen: set[tuple[str, str] | str] = set()
    tools: list[str] = []
    for server, tool in contributors:
        dedup_key = (server, tool) if attribute_server else tool
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        tools.append(f"{tool} ({server})" if attribute_server else tool)
    return tools


def _compute_rule_of_two(
    leg1: list[tuple[str, str]],
    leg2: list[tuple[str, str]],
    leg3: list[tuple[str, str]],
    attribute_server: bool = False,
) -> RuleOfTwoPosture:
    """Compute the advisory Rule-of-Two posture for a fired trifecta.

    Deterministic and pure (no I/O). Prefers dropping Leg 3 (exfiltration) when it has
    any contributing tool — removing the outbound channel breaks the trifecta with the
    least loss of read/ingest utility and is enforceable today via ``--egress-check``.
    Otherwise drops the leg with the fewest contributing tools (tie-break: lower leg
    number). The other present legs are returned as alternatives. ``attribute_server``
    (set for fleet findings) labels each tool with its owning server.
    """
    tools_by_leg = {
        1: _leg_tools(leg1, attribute_server),
        2: _leg_tools(leg2, attribute_server),
        3: _leg_tools(leg3, attribute_server),
    }
    present = [leg for leg in (1, 2, 3) if tools_by_leg[leg]]

    if tools_by_leg[3]:
        recommended_drop = 3
    elif present:
        recommended_drop = min(present, key=lambda leg: (len(tools_by_leg[leg]), leg))
    else:  # defensive — never reached at a real fire site (all legs are non-empty)
        recommended_drop = 3

    affected_tools = tools_by_leg[recommended_drop]
    alternatives = [
        (leg, rule_of_two_action(leg, tools_by_leg[leg]))
        for leg in (1, 2, 3)
        if leg != recommended_drop and tools_by_leg[leg]
    ]
    return RuleOfTwoPosture(
        legs_present=present,
        recommended_drop=recommended_drop,
        action=rule_of_two_action(recommended_drop, affected_tools),
        affected_tools=affected_tools,
        alternatives=alternatives,
    )


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
        leg1 = _tools_for_category(audit, _LEG1_CATEGORIES)
        leg2 = _ingestion_contributors(audit)
        leg3 = _tools_for_category(audit, _LEG3_CATEGORIES)

        if not (leg1 and leg2 and leg3):
            return []

        meta = trifecta_metadata(TrifectaSeverity.HIGH)
        return [
            TrifectaFinding(
                severity=TrifectaSeverity.HIGH,
                leg1_contributors=leg1,
                leg2_contributors=leg2,
                leg3_contributors=leg3,
                description=meta.description,
                is_fleet=False,
                rule_of_two=_compute_rule_of_two(leg1, leg2, leg3),
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
            ingestion = _ingestion_contributors(audit)
            if ingestion:
                fleet_has_leg2 = True
                leg2_contributors.extend(ingestion)
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
                rule_of_two=_compute_rule_of_two(
                    leg1_contributors,
                    leg2_contributors,
                    leg3_contributors,
                    attribute_server=True,
                ),
            )
        ]
