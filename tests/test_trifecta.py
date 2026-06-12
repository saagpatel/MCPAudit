"""Unit tests for the lethal-trifecta / toxic-flow detector.

Leg definitions (new calibrated model):
  Leg 1 — FILE_READ permission category (unchanged).
  Leg 2 — Untrusted-content ingestion: SSRF-flagged tool/resource OR a tool
           whose name/description carries a fetch verb (fetch, download, scrape,
           crawl, curl, wget, retrieve, visit, ...). NOT the NETWORK category.
  Leg 3 — EXFILTRATION permission category ONLY. SHELL_EXEC and FILE_WRITE do
           NOT satisfy Leg 3.
"""

from __future__ import annotations

from mcp_audit.models import (
    ClientType,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
    ServerConfig,
    ToolInfo,
    TransportType,
    TrifectaSeverity,
)
from mcp_audit.trifecta import TrifectaAnalyzer, _compute_rule_of_two

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server(name: str = "test-server") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_DESKTOP,
        config_path="/test/config.json",
        transport=TransportType.STDIO,
        command="test-cmd",
    )


def _risk() -> RiskScore:
    return RiskScore(
        composite=5.0,
        file_access=5.0,
        network_access=5.0,
        shell_execution=0.0,
        destructive=0.0,
        exfiltration=0.0,
    )


def _pf(category: PermissionCategory, tool: str) -> PermissionFinding:
    return PermissionFinding(
        category=category,
        confidence=Confidence.HIGH,
        evidence=["test"],
        tool_name=tool,
    )


def _fetch_tool() -> ToolInfo:
    """A tool whose name carries a fetch verb — satisfies Leg 2."""
    return ToolInfo(name="fetch_remote", description="Fetches a remote document.")


def _audit(
    name: str,
    categories: list[PermissionCategory],
    ingests: bool = False,
) -> ServerAudit:
    """Build a ServerAudit.

    ``ingests=True`` appends a fetch-verb tool so Leg 2 is satisfied.
    Without it the server has no ingestion signal regardless of categories.
    """
    perms = [_pf(cat, f"tool_{i}") for i, cat in enumerate(categories)]
    tools = [_fetch_tool()] if ingests else []
    return ServerAudit(
        server=_server(name),
        connection_status="connected",
        risk_score=_risk(),
        permissions=perms,
        tools=tools,
    )


analyzer = TrifectaAnalyzer()


# ---------------------------------------------------------------------------
# Per-server positive: all three legs present → HIGH finding
# ---------------------------------------------------------------------------


class TestPerServerPositive:
    def test_all_three_legs_fires_high_finding(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        findings = analyzer.analyze_server(audit)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == TrifectaSeverity.HIGH
        assert not f.is_fleet

    def test_finding_records_contributors_for_all_three_legs(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        f = analyzer.analyze_server(audit)[0]
        # Leg 1: file_read tool
        assert len(f.leg1_contributors) >= 1
        assert all(s == "srv" for s, _ in f.leg1_contributors)
        # Leg 2: ingestion tool (fetch_remote)
        assert len(f.leg2_contributors) >= 1
        assert any(t == "fetch_remote" for _, t in f.leg2_contributors)
        # Leg 3: exfiltration tool
        assert len(f.leg3_contributors) >= 1
        assert all(s == "srv" for s, _ in f.leg3_contributors)

    def test_all_contributor_server_names_match_audit(self) -> None:
        audit = _audit(
            "my-server",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        f = analyzer.analyze_server(audit)[0]
        for contributors in (f.leg1_contributors, f.leg2_contributors, f.leg3_contributors):
            assert all(s == "my-server" for s, _ in contributors)

    def test_download_tool_name_satisfies_leg2(self) -> None:
        """Any fetch-verb tool name satisfies Leg 2."""
        audit = ServerAudit(
            server=_server("srv"),
            connection_status="connected",
            risk_score=_risk(),
            permissions=[
                _pf(PermissionCategory.FILE_READ, "read_files"),
                _pf(PermissionCategory.EXFILTRATION, "send_data"),
            ],
            tools=[ToolInfo(name="download_report", description="Downloads a report.")],
        )
        findings = analyzer.analyze_server(audit)
        assert len(findings) == 1

    def test_crawl_verb_in_description_satisfies_leg2(self) -> None:
        """Fetch verb in description (not just name) satisfies Leg 2."""
        audit = ServerAudit(
            server=_server("srv"),
            connection_status="connected",
            risk_score=_risk(),
            permissions=[
                _pf(PermissionCategory.FILE_READ, "read_files"),
                _pf(PermissionCategory.EXFILTRATION, "send_data"),
            ],
            tools=[ToolInfo(name="page_reader", description="Crawls a web page.")],
        )
        findings = analyzer.analyze_server(audit)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Per-server negatives: each single missing leg → no finding
# ---------------------------------------------------------------------------


class TestPerServerNegatives:
    def test_missing_leg1_file_read_no_finding(self) -> None:
        # No FILE_READ — leg 1 absent
        audit = _audit("srv", [PermissionCategory.EXFILTRATION], ingests=True)
        assert analyzer.analyze_server(audit) == []

    def test_missing_leg2_ingestion_no_finding(self) -> None:
        # FILE_READ + EXFILTRATION but NO ingestion tool → Leg 2 absent
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=False,
        )
        assert analyzer.analyze_server(audit) == []

    def test_missing_leg3_exfiltration_no_finding(self) -> None:
        # FILE_READ + ingestion but NO exfiltration → Leg 3 absent
        audit = _audit("srv", [PermissionCategory.FILE_READ], ingests=True)
        assert analyzer.analyze_server(audit) == []

    def test_empty_permissions_no_finding(self) -> None:
        audit = _audit("srv", [], ingests=False)
        assert analyzer.analyze_server(audit) == []

    def test_network_category_alone_does_not_satisfy_leg2(self) -> None:
        """Regression: NETWORK permission alone must NOT satisfy Leg 2.

        This is the calibration bug that caused 18/21 servers to fire.
        A server with FILE_READ + NETWORK + EXFILTRATION but NO ingestion
        tool must produce zero findings.
        """
        audit = _audit(
            "srv",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            ],
            ingests=False,  # no fetch-verb tool, no SSRF-flagged tool
        )
        assert analyzer.analyze_server(audit) == [], (
            "NETWORK category alone must not satisfy Leg 2 — "
            "it fires on ~86% of servers and is not an ingestion signal"
        )


# ---------------------------------------------------------------------------
# Leg 3 — exfiltration-only: SHELL_EXEC and FILE_WRITE do NOT satisfy Leg 3
# ---------------------------------------------------------------------------


class TestLeg3ExfiltrationOnly:
    def _with_leg3_category(self, leg3: PermissionCategory) -> ServerAudit:
        """Full three-leg server using the given category as the sole Leg 3 candidate."""
        return _audit("srv", [PermissionCategory.FILE_READ, leg3], ingests=True)

    def test_exfiltration_satisfies_leg3(self) -> None:
        findings = analyzer.analyze_server(self._with_leg3_category(PermissionCategory.EXFILTRATION))
        assert len(findings) == 1
        assert findings[0].severity == TrifectaSeverity.HIGH

    def test_shell_exec_alone_does_not_satisfy_leg3(self) -> None:
        """SHELL_EXEC no longer satisfies Leg 3 in the calibrated model."""
        findings = analyzer.analyze_server(self._with_leg3_category(PermissionCategory.SHELL_EXEC))
        assert findings == [], "SHELL_EXEC must not satisfy Leg 3"

    def test_file_write_alone_does_not_satisfy_leg3(self) -> None:
        """FILE_WRITE no longer satisfies Leg 3 in the calibrated model."""
        findings = analyzer.analyze_server(self._with_leg3_category(PermissionCategory.FILE_WRITE))
        assert findings == [], "FILE_WRITE must not satisfy Leg 3"

    def test_destructive_does_not_satisfy_leg3(self) -> None:
        findings = analyzer.analyze_server(self._with_leg3_category(PermissionCategory.DESTRUCTIVE))
        assert findings == [], "DESTRUCTIVE must not satisfy Leg 3"


# ---------------------------------------------------------------------------
# Fleet-level: trifecta formed only by combining multiple servers
# ---------------------------------------------------------------------------


class TestFleetLevel:
    def test_fleet_positive_two_servers(self) -> None:
        # Server A: Leg 1 (file_read) only; Server B: Leg 2 (ingestion) + Leg 3 (exfil)
        audit_a = _audit("server-a", [PermissionCategory.FILE_READ], ingests=False)
        audit_b = _audit("server-b", [PermissionCategory.EXFILTRATION], ingests=True)
        # Confirm neither fires per-server
        audit_a.trifecta_findings = analyzer.analyze_server(audit_a)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)
        assert audit_a.trifecta_findings == []
        assert audit_b.trifecta_findings == []

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert len(fleet) == 1
        f = fleet[0]
        assert f.severity == TrifectaSeverity.MEDIUM
        assert f.is_fleet

    def test_fleet_positive_three_servers(self) -> None:
        # filesystem: leg 1 only; fetch-srv: leg 2 only; slack: leg 3 only
        audit_a = _audit("filesystem", [PermissionCategory.FILE_READ], ingests=False)
        audit_b = _audit("fetch-srv", [], ingests=True)
        audit_c = _audit("slack", [PermissionCategory.EXFILTRATION], ingests=False)
        audit_a.trifecta_findings = analyzer.analyze_server(audit_a)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)
        audit_c.trifecta_findings = analyzer.analyze_server(audit_c)
        assert all(a.trifecta_findings == [] for a in [audit_a, audit_b, audit_c])

        fleet = analyzer.analyze_fleet([audit_a, audit_b, audit_c])
        assert len(fleet) == 1
        assert fleet[0].severity == TrifectaSeverity.MEDIUM

    def test_fleet_contributors_recorded_correctly(self) -> None:
        # leg 1 on srv-a, leg 2+3 on srv-b
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ], ingests=False)
        audit_b = _audit("srv-b", [PermissionCategory.EXFILTRATION], ingests=True)
        audit_a.trifecta_findings = analyzer.analyze_server(audit_a)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert len(fleet) == 1
        f = fleet[0]
        assert any(s == "srv-a" for s, _ in f.leg1_contributors)
        assert any(s == "srv-b" for s, _ in f.leg2_contributors)
        assert any(s == "srv-b" for s, _ in f.leg3_contributors)


# ---------------------------------------------------------------------------
# Fleet suppression: single server already has trifecta → NO fleet finding
# ---------------------------------------------------------------------------


class TestFleetSuppression:
    def test_fleet_suppressed_when_per_server_fires(self) -> None:
        # Server A has all three legs — per-server fires
        audit_a = _audit(
            "srv-a",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        per_server = analyzer.analyze_server(audit_a)
        assert len(per_server) == 1, "per-server must fire for suppression test to be valid"
        audit_a.trifecta_findings = per_server  # simulate CLI wiring

        # Server B contributes additional legs but fleet should NOT fire
        audit_b = _audit("srv-b", [PermissionCategory.FILE_READ], ingests=True)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)  # no exfil → no finding

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert fleet == [], "Fleet finding must be suppressed when per-server trifecta fires"

    def test_fleet_suppressed_multiple_per_server(self) -> None:
        audit_a = _audit(
            "srv-a",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        audit_b = _audit(
            "srv-b",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        audit_a.trifecta_findings = analyzer.analyze_server(audit_a)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)
        assert len(audit_a.trifecta_findings) == 1
        assert len(audit_b.trifecta_findings) == 1

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert fleet == []


# ---------------------------------------------------------------------------
# Benign fleet: missing a leg → nothing
# ---------------------------------------------------------------------------


class TestBenignFleet:
    def test_fleet_missing_leg1_no_finding(self) -> None:
        # No server has FILE_READ
        audit_a = _audit("srv-a", [], ingests=True)
        audit_b = _audit("srv-b", [PermissionCategory.EXFILTRATION], ingests=False)
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_fleet_missing_leg2_no_finding(self) -> None:
        # No server has any ingestion tool
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ], ingests=False)
        audit_b = _audit("srv-b", [PermissionCategory.EXFILTRATION], ingests=False)
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_fleet_missing_leg3_no_finding(self) -> None:
        # No server has EXFILTRATION
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ], ingests=False)
        audit_b = _audit("srv-b", [], ingests=True)
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_fleet_network_category_does_not_satisfy_leg2(self) -> None:
        """Fleet-level regression: NETWORK on every server must not create a fleet Leg 2."""
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ, PermissionCategory.NETWORK])
        audit_b = _audit("srv-b", [PermissionCategory.NETWORK, PermissionCategory.EXFILTRATION])
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        # Neither has an ingestion tool → Leg 2 absent fleet-wide
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_empty_fleet_no_finding(self) -> None:
        assert analyzer.analyze_fleet([]) == []


# ---------------------------------------------------------------------------
# Rule of Two posture (D2)
# ---------------------------------------------------------------------------


class TestRuleOfTwoPosture:
    def test_fired_per_server_finding_carries_posture(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=True,
        )
        posture = analyzer.analyze_server(audit)[0].rule_of_two
        assert posture is not None
        assert posture.legs_present == [1, 2, 3]
        assert posture.recommended_drop == 3  # Leg 3 present -> prefer dropping it
        assert posture.affected_tools  # >= 1 tool
        assert len(posture.alternatives) == 2
        assert {leg for leg, _ in posture.alternatives} == {1, 2}
        assert "--egress-check" in posture.action

    def test_two_leg_server_yields_no_finding_and_no_posture(self) -> None:
        # FILE_READ + EXFILTRATION but no ingestion (Leg 2 absent) -> no finding at all.
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
            ingests=False,
        )
        assert analyzer.analyze_server(audit) == []

    def test_fleet_finding_carries_posture(self) -> None:
        leg1 = _audit("reader", [PermissionCategory.FILE_READ])
        leg2 = _audit("fetcher", [], ingests=True)
        leg3 = _audit("sender", [PermissionCategory.EXFILTRATION])
        findings = analyzer.analyze_fleet([leg1, leg2, leg3])
        assert len(findings) == 1
        posture = findings[0].rule_of_two
        assert posture is not None
        assert posture.legs_present == [1, 2, 3]
        assert posture.recommended_drop == 3

    def test_fewest_tools_branch_when_leg3_empty(self) -> None:
        # Direct unit of the heuristic: Leg 3 empty forces the fewest-tools branch.
        posture = _compute_rule_of_two(
            [("s", "read_a"), ("s", "read_b")],  # leg1: 2 tools
            [("s", "fetch_c")],  # leg2: 1 tool (fewest)
            [],  # leg3: empty
        )
        assert posture.recommended_drop == 2
        assert posture.affected_tools == ["fetch_c"]
        assert posture.legs_present == [1, 2]
        assert {leg for leg, _ in posture.alternatives} == {1}

    def test_tie_break_prefers_lower_leg_number(self) -> None:
        posture = _compute_rule_of_two(
            [("s", "read_a")],  # leg1: 1 tool
            [("s", "fetch_b")],  # leg2: 1 tool (tie)
            [],  # leg3: empty
        )
        assert posture.recommended_drop == 1  # tie -> lower leg number

    def test_affected_tools_are_deduplicated(self) -> None:
        posture = _compute_rule_of_two(
            [("s", "read")],
            [("s", "fetch")],
            [("a", "send"), ("b", "send")],  # same tool name on two servers
        )
        assert posture.recommended_drop == 3
        assert posture.affected_tools == ["send"]  # deduped, order preserved
