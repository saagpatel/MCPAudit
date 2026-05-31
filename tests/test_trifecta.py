"""Unit tests for the lethal-trifecta / toxic-flow detector."""

from __future__ import annotations

from mcp_audit.models import (
    ClientType,
    Confidence,
    PermissionCategory,
    PermissionFinding,
    RiskScore,
    ServerAudit,
    ServerConfig,
    TransportType,
    TrifectaSeverity,
)
from mcp_audit.trifecta import TrifectaAnalyzer

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


def _audit(
    name: str,
    categories: list[PermissionCategory],
) -> ServerAudit:
    perms = [_pf(cat, f"tool_{i}") for i, cat in enumerate(categories)]
    return ServerAudit(
        server=_server(name),
        connection_status="connected",
        risk_score=_risk(),
        permissions=perms,
    )


analyzer = TrifectaAnalyzer()


# ---------------------------------------------------------------------------
# Per-server positive: all three legs present → HIGH finding
# ---------------------------------------------------------------------------


class TestPerServerPositive:
    def test_all_three_legs_fires_high_finding(self) -> None:
        audit = _audit(
            "srv",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            ],
        )
        findings = analyzer.analyze_server(audit)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == TrifectaSeverity.HIGH
        assert not f.is_fleet

    def test_finding_records_correct_leg_contributors(self) -> None:
        audit = _audit(
            "srv",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            ],
        )
        f = analyzer.analyze_server(audit)[0]
        assert any(t == "tool_0" for _, t in f.leg1_contributors)
        assert any(t == "tool_1" for _, t in f.leg2_contributors)
        assert any(t == "tool_2" for _, t in f.leg3_contributors)

    def test_all_contributor_server_names_match_audit(self) -> None:
        audit = _audit(
            "my-server",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.SHELL_EXEC,
            ],
        )
        f = analyzer.analyze_server(audit)[0]
        for contributors in (f.leg1_contributors, f.leg2_contributors, f.leg3_contributors):
            assert all(s == "my-server" for s, _ in contributors)


# ---------------------------------------------------------------------------
# Per-server negatives: each single missing leg → no finding
# ---------------------------------------------------------------------------


class TestPerServerNegatives:
    def test_missing_leg1_file_read_no_finding(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.NETWORK, PermissionCategory.EXFILTRATION],
        )
        assert analyzer.analyze_server(audit) == []

    def test_missing_leg2_network_no_finding(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.EXFILTRATION],
        )
        assert analyzer.analyze_server(audit) == []

    def test_missing_leg3_no_finding(self) -> None:
        audit = _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.NETWORK],
        )
        assert analyzer.analyze_server(audit) == []

    def test_empty_permissions_no_finding(self) -> None:
        audit = _audit("srv", [])
        assert analyzer.analyze_server(audit) == []

    def test_only_destructive_is_not_leg3(self) -> None:
        # DESTRUCTIVE alone does not satisfy leg 3
        audit = _audit(
            "srv",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.DESTRUCTIVE,
            ],
        )
        assert analyzer.analyze_server(audit) == []


# ---------------------------------------------------------------------------
# Leg 3 OR-logic: each of exfiltration/shell_exec/file_write independently satisfies
# ---------------------------------------------------------------------------


class TestLeg3OrLogic:
    def _three_legs_with(self, leg3: PermissionCategory) -> ServerAudit:
        return _audit(
            "srv",
            [PermissionCategory.FILE_READ, PermissionCategory.NETWORK, leg3],
        )

    def test_exfiltration_satisfies_leg3(self) -> None:
        findings = analyzer.analyze_server(self._three_legs_with(PermissionCategory.EXFILTRATION))
        assert len(findings) == 1
        assert findings[0].severity == TrifectaSeverity.HIGH

    def test_shell_exec_satisfies_leg3(self) -> None:
        findings = analyzer.analyze_server(self._three_legs_with(PermissionCategory.SHELL_EXEC))
        assert len(findings) == 1
        assert findings[0].severity == TrifectaSeverity.HIGH

    def test_file_write_satisfies_leg3(self) -> None:
        findings = analyzer.analyze_server(self._three_legs_with(PermissionCategory.FILE_WRITE))
        assert len(findings) == 1
        assert findings[0].severity == TrifectaSeverity.HIGH


# ---------------------------------------------------------------------------
# Fleet-level: trifecta formed only by combining multiple servers
# ---------------------------------------------------------------------------


class TestFleetLevel:
    def test_fleet_positive_two_servers(self) -> None:
        # leg1+leg2 on server A, leg3 on server B → no single server fires → fleet fires
        audit_a = _audit("server-a", [PermissionCategory.FILE_READ, PermissionCategory.NETWORK])
        audit_b = _audit("server-b", [PermissionCategory.EXFILTRATION])
        # Pre-populate trifecta_findings (per-server pass already ran, returned [])
        assert analyzer.analyze_server(audit_a) == []
        assert analyzer.analyze_server(audit_b) == []

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert len(fleet) == 1
        f = fleet[0]
        assert f.severity == TrifectaSeverity.MEDIUM
        assert f.is_fleet

    def test_fleet_positive_three_servers(self) -> None:
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ])
        audit_b = _audit("srv-b", [PermissionCategory.NETWORK])
        audit_c = _audit("srv-c", [PermissionCategory.SHELL_EXEC])
        assert analyzer.analyze_server(audit_a) == []
        assert analyzer.analyze_server(audit_b) == []
        assert analyzer.analyze_server(audit_c) == []

        fleet = analyzer.analyze_fleet([audit_a, audit_b, audit_c])
        assert len(fleet) == 1
        assert fleet[0].severity == TrifectaSeverity.MEDIUM

    def test_fleet_contributors_recorded_correctly(self) -> None:
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ])
        audit_b = _audit("srv-b", [PermissionCategory.NETWORK, PermissionCategory.FILE_WRITE])
        assert analyzer.analyze_server(audit_a) == []
        assert analyzer.analyze_server(audit_b) == []

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
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            ],
        )
        per_server = analyzer.analyze_server(audit_a)
        assert len(per_server) == 1  # per-server fired
        audit_a.trifecta_findings = per_server  # simulate CLI wiring

        # Server B contributes additional legs but fleet should NOT fire
        audit_b = _audit("srv-b", [PermissionCategory.FILE_READ, PermissionCategory.SHELL_EXEC])
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)  # no finding

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert fleet == [], "Fleet finding must be suppressed when per-server trifecta fires"

    def test_fleet_suppressed_multiple_per_server(self) -> None:
        audit_a = _audit(
            "srv-a",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.EXFILTRATION,
            ],
        )
        audit_b = _audit(
            "srv-b",
            [
                PermissionCategory.FILE_READ,
                PermissionCategory.NETWORK,
                PermissionCategory.SHELL_EXEC,
            ],
        )
        audit_a.trifecta_findings = analyzer.analyze_server(audit_a)
        audit_b.trifecta_findings = analyzer.analyze_server(audit_b)

        fleet = analyzer.analyze_fleet([audit_a, audit_b])
        assert fleet == []


# ---------------------------------------------------------------------------
# Benign fleet: missing a leg → nothing
# ---------------------------------------------------------------------------


class TestBenignFleet:
    def test_fleet_missing_leg1_no_finding(self) -> None:
        # No server has FILE_READ
        audit_a = _audit("srv-a", [PermissionCategory.NETWORK])
        audit_b = _audit("srv-b", [PermissionCategory.EXFILTRATION])
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_fleet_missing_leg2_no_finding(self) -> None:
        # No server has NETWORK
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ])
        audit_b = _audit("srv-b", [PermissionCategory.SHELL_EXEC])
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_fleet_missing_leg3_no_finding(self) -> None:
        # No server has exfiltration/shell/file_write
        audit_a = _audit("srv-a", [PermissionCategory.FILE_READ])
        audit_b = _audit("srv-b", [PermissionCategory.NETWORK])
        audit_a.trifecta_findings = []
        audit_b.trifecta_findings = []
        assert analyzer.analyze_fleet([audit_a, audit_b]) == []

    def test_empty_fleet_no_finding(self) -> None:
        assert analyzer.analyze_fleet([]) == []
