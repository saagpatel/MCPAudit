"""Unit tests for the ShadowingAnalyzer.

Covers:
  - Exact collision (MCP015, HIGH)
  - Normalised-only collision (MCP016, MEDIUM)
  - Homoglyph collision (MCP017, HIGH)
  - No collision (namespaced tools) → empty list
  - Single-server (no cross-server comparison) → empty list
  - Three-server exact collision → one finding with all three
  - Exact takes precedence over normalised for the same canonical name
"""

from __future__ import annotations

from mcp_audit.models import (
    ClientType,
    ServerAudit,
    ServerConfig,
    ShadowingKind,
    ShadowingSeverity,
    ToolInfo,
    TransportType,
)
from mcp_audit.shadowing import ShadowingAnalyzer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _server(name: str) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )


def _audit(server_name: str, tool_names: list[str]) -> ServerAudit:
    return ServerAudit(
        server=_server(server_name),
        connection_status="connected",
        tools=[ToolInfo(name=t) for t in tool_names],
    )


_analyzer = ShadowingAnalyzer()


# ---------------------------------------------------------------------------
# No collision
# ---------------------------------------------------------------------------


class TestNoCollision:
    def test_namespaced_tools_produce_no_findings(self) -> None:
        audits = [
            _audit("github", ["github_search", "github_create_issue"]),
            _audit("slack", ["slack_send_message", "slack_list_channels"]),
            _audit("filesystem", ["read_file", "write_file"]),
        ]
        assert _analyzer.analyze_fleet(audits) == []

    def test_single_server_produces_no_findings(self) -> None:
        # Only one server — no cross-server collision possible
        audits = [_audit("only-server", ["search", "read", "write"])]
        assert _analyzer.analyze_fleet(audits) == []

    def test_empty_fleet_produces_no_findings(self) -> None:
        assert _analyzer.analyze_fleet([]) == []

    def test_servers_with_no_tools_produce_no_findings(self) -> None:
        audits = [
            ServerAudit(server=_server("a"), connection_status="failed"),
            ServerAudit(server=_server("b"), connection_status="failed"),
        ]
        assert _analyzer.analyze_fleet(audits) == []


# ---------------------------------------------------------------------------
# Tier 1: EXACT
# ---------------------------------------------------------------------------


class TestExact:
    def test_exact_collision_two_servers_produces_one_high_mcp015(self) -> None:
        audits = [
            _audit("legitimate-server", ["search", "list"]),
            _audit("malicious-server", ["search", "exfiltrate"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ShadowingKind.EXACT
        assert f.severity == ShadowingSeverity.HIGH
        assert f.rule_id == "MCP015"
        assert f.name == "search"
        # Both (server, tool) pairs present
        assert ("legitimate-server", "search") in f.collisions
        assert ("malicious-server", "search") in f.collisions

    def test_exact_collision_first_server_is_presumed_legitimate(self) -> None:
        audits = [
            _audit("first", ["tool_x"]),
            _audit("second", ["tool_x"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        # First collision entry is the first-configured server
        assert findings[0].collisions[0][0] == "first"

    def test_three_server_exact_collision_produces_one_finding_with_all_three(self) -> None:
        audits = [
            _audit("srv-a", ["execute"]),
            _audit("srv-b", ["execute"]),
            _audit("srv-c", ["execute"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ShadowingKind.EXACT
        servers_in_finding = {srv for srv, _ in f.collisions}
        assert servers_in_finding == {"srv-a", "srv-b", "srv-c"}

    def test_multiple_distinct_exact_collisions_each_get_their_own_finding(self) -> None:
        audits = [
            _audit("srv-a", ["search", "delete"]),
            _audit("srv-b", ["search", "delete"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 2
        kinds = {f.kind for f in findings}
        assert kinds == {ShadowingKind.EXACT}

    def test_exact_no_collision_within_same_server(self) -> None:
        # Sanity: a name on one server is trivially unique within that server
        audits = [
            _audit("srv-a", ["query"]),
            _audit("srv-b", ["fetch"]),
        ]
        assert _analyzer.analyze_fleet(audits) == []

    def test_description_mentions_suspect_server(self) -> None:
        audits = [
            _audit("legit", ["run"]),
            _audit("suspect", ["run"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        assert "suspect" in findings[0].description


# ---------------------------------------------------------------------------
# Tier 2: NORMALIZED
# ---------------------------------------------------------------------------


class TestNormalized:
    def test_case_difference_only_produces_mcp016_medium(self) -> None:
        audits = [
            _audit("srv-a", ["readFile"]),
            _audit("srv-b", ["ReadFile"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ShadowingKind.NORMALIZED
        assert f.severity == ShadowingSeverity.MEDIUM
        assert f.rule_id == "MCP016"

    def test_separator_difference_only_produces_mcp016(self) -> None:
        audits = [
            _audit("srv-a", ["read_file"]),
            _audit("srv-b", ["read-file"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        assert findings[0].kind == ShadowingKind.NORMALIZED

    def test_case_and_separator_difference_produces_mcp016(self) -> None:
        audits = [
            _audit("srv-a", ["read_file"]),
            _audit("srv-b", ["readFile"]),
            _audit("srv-c", ["read-file"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ShadowingKind.NORMALIZED
        servers_in = {srv for srv, _ in f.collisions}
        assert servers_in == {"srv-a", "srv-b", "srv-c"}

    def test_exact_takes_precedence_over_normalized_for_same_name(self) -> None:
        # "search" appears exactly on both servers → EXACT only (no extra NORMALIZED)
        audits = [
            _audit("srv-a", ["search"]),
            _audit("srv-b", ["search"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        assert findings[0].kind == ShadowingKind.EXACT

    def test_normalized_not_reported_when_exact_already_covers_canonical(self) -> None:
        # "delete" exact + "Delete" on third server — the normalised form "delete" is
        # already reported under EXACT so NORMALIZED should NOT be added.
        audits = [
            _audit("srv-a", ["delete"]),
            _audit("srv-b", ["delete"]),  # exact match
            _audit("srv-c", ["Delete"]),  # normalises to same
        ]
        findings = _analyzer.analyze_fleet(audits)
        # Only one finding — the exact one covering all three
        assert len(findings) == 1
        assert findings[0].kind == ShadowingKind.EXACT


# ---------------------------------------------------------------------------
# Tier 3: HOMOGLYPH
# ---------------------------------------------------------------------------


class TestHomoglyph:
    def test_cyrillic_lookalike_produces_mcp017_high(self) -> None:
        # "deleтe" — Cyrillic 'т' replaced by Cyrillic 'е'
        # Use Cyrillic 'е' (U+0435) in place of ASCII 'e' to make "delete" look-alike
        cyrillic_delete = "deletе"  # last char is Cyrillic е
        audits = [
            _audit("legit", ["delete"]),
            _audit("spoofed", [cyrillic_delete]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        homoglyph_findings = [f for f in findings if f.kind == ShadowingKind.HOMOGLYPH]
        assert len(homoglyph_findings) == 1
        f = homoglyph_findings[0]
        assert f.severity == ShadowingSeverity.HIGH
        assert f.rule_id == "MCP017"
        # ASCII name should be canonical
        assert f.name == "delete"

    def test_homoglyph_requires_at_least_one_non_ascii_name(self) -> None:
        # Two ASCII names that happen to normalise the same are not homoglyphs
        audits = [
            _audit("srv-a", ["readFile"]),
            _audit("srv-b", ["read_file"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        for f in findings:
            assert f.kind != ShadowingKind.HOMOGLYPH

    def test_two_ascii_exact_match_not_reported_as_homoglyph(self) -> None:
        audits = [
            _audit("srv-a", ["run"]),
            _audit("srv-b", ["run"]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        for f in findings:
            assert f.kind != ShadowingKind.HOMOGLYPH
        assert any(f.kind == ShadowingKind.EXACT for f in findings)

    def test_greek_lookalike_triggers_homoglyph(self) -> None:
        # Greek ο (U+03BF) looks like ASCII 'o'
        greek_tool = "cοpy"  # "copy" with Greek ο
        audits = [
            _audit("srv-legit", ["copy"]),
            _audit("srv-bad", [greek_tool]),
        ]
        findings = _analyzer.analyze_fleet(audits)
        homoglyph_findings = [f for f in findings if f.kind == ShadowingKind.HOMOGLYPH]
        assert len(homoglyph_findings) == 1


# ---------------------------------------------------------------------------
# Model / field assertions
# ---------------------------------------------------------------------------


class TestFindingModel:
    def test_finding_has_correct_rule_id_for_each_kind(self) -> None:
        exact_finding = _analyzer.analyze_fleet(
            [
                _audit("a", ["x"]),
                _audit("b", ["x"]),
            ]
        )
        assert exact_finding[0].rule_id == "MCP015"

        norm_finding = _analyzer.analyze_fleet(
            [
                _audit("a", ["readFile"]),
                _audit("b", ["read_file"]),
            ]
        )
        assert norm_finding[0].rule_id == "MCP016"

        cyrillic = "xе"  # xe with Cyrillic e
        hom_finding = _analyzer.analyze_fleet(
            [
                _audit("a", ["xe"]),
                _audit("b", [cyrillic]),
            ]
        )
        hom = [f for f in hom_finding if f.kind == ShadowingKind.HOMOGLYPH]
        assert len(hom) == 1
        assert hom[0].rule_id == "MCP017"

    def test_finding_has_title_and_remediation(self) -> None:
        audits = [_audit("a", ["go"]), _audit("b", ["go"])]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        assert findings[0].title
        assert findings[0].remediation

    def test_serialises_to_json(self) -> None:
        import json

        audits = [_audit("a", ["run"]), _audit("b", ["run"])]
        findings = _analyzer.analyze_fleet(audits)
        assert len(findings) == 1
        data = json.loads(findings[0].model_dump_json())
        assert data["kind"] == "exact"
        assert data["severity"] == "high"
        assert data["rule_id"] == "MCP015"
        assert "collisions" in data
