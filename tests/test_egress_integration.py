"""Integration coverage: real egress detector → renderers (text/HTML/SARIF) + policy gate.

Exercises the full path the CLI wires under --egress-check: SsrfDetector populates the
caller-controlled signal, EgressDetector derives outbound-destination findings, and those
findings flow through every renderer and the fail_on.egress policy gate.
"""

from __future__ import annotations

import functools
import io
from datetime import UTC, datetime

import anyio
import pytest
from rich.console import Console

from mcp_audit import cli
from mcp_audit.egress import EgressDetector
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    ClientType,
    EgressKind,
    ResourceInfo,
    ServerAudit,
    ServerConfig,
    ToolInfo,
)
from mcp_audit.overrides import OverrideApplier, OverrideConfig
from mcp_audit.policy import PolicyConfig, evaluate_policy
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from mcp_audit.ssrf import SsrfDetector


def _audit() -> ServerAudit:
    """A server exercising all three egress kinds, via the real detector pipeline."""
    audit = ServerAudit(
        server=ServerConfig(
            name="mixed",
            client=ClientType.CLAUDE_DESKTOP,
            config_path="/test/config.json",
        ),
        connection_status="connected",
        tools=[
            ToolInfo(
                name="fetch_url",
                description="Fetch the contents of a URL.",
                input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            )
        ],
        resources=[
            ResourceInfo(uri="https://evil.example/data"),  # fixed, outside allowlist -> MEDIUM
            ResourceInfo(uri="https://api.anthropic.com/data"),  # allowlisted multi-tenant -> LOW
        ],
    )
    # The CLI runs SSRF first to feed egress; mirror that ordering here.
    audit.ssrf_findings = SsrfDetector().scan_server(audit.tools, audit.resources)
    audit.egress_findings = EgressDetector({"anthropic.com"}).scan_server(audit)
    return audit


def _report(audit: ServerAudit) -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime(2026, 6, 12, 12, 0, 0, tzinfo=UTC),
        hostname="h",
        os_platform="Test",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=0,
        audits=[audit],
        scan_duration_seconds=0.0,
    )


def test_detector_produces_all_three_kinds() -> None:
    kinds = {f.kind for f in _audit().egress_findings}
    assert kinds == {
        EgressKind.UNBOUNDED_EGRESS,
        EgressKind.DESTINATION_OUTSIDE_ALLOWLIST,
        EgressKind.TRUSTED_DESTINATION_RESIDUAL,
    }


class TestSarif:
    def test_egress_rules_and_levels(self) -> None:
        sarif = SarifGenerator().generate(_report(_audit()))
        results = sarif["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results if r["ruleId"].startswith("MCP04")}
        assert by_rule["MCP041"]["level"] == "error"  # unbounded HIGH
        assert by_rule["MCP040"]["level"] == "warning"  # outside-allowlist MEDIUM
        assert by_rule["MCP042"]["level"] == "note"  # residual LOW
        # Registered rules include all three egress ids.
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert {"MCP040", "MCP041", "MCP042"} <= rule_ids
        # Result properties carry the destination + kind.
        assert by_rule["MCP040"]["properties"]["destination_host"] == "evil.example"
        assert by_rule["MCP041"]["properties"]["kind"] == "unbounded_egress"


class TestTerminal:
    def test_egress_section_renders(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=True, width=140, highlight=False)
        ReportGenerator(console=console).render_terminal(_report(_audit()))
        out = buf.getvalue()
        assert "Egress" in out
        assert "evil.example" in out
        assert "caller-controlled" in out  # unbounded destination label

    def test_fixed_destination_label_includes_specific_target(self) -> None:
        fixed = next(
            f for f in _audit().egress_findings if f.kind is EgressKind.DESTINATION_OUTSIDE_ALLOWLIST
        )
        assert ReportGenerator._egress_destination_label(fixed) == "evil.example (https://evil.example/data)"


class TestHtml:
    def test_egress_table_renders(self) -> None:
        html = HtmlReportGenerator().generate(_report(_audit()))
        assert "Egress" in html
        assert "evil.example" in html
        assert "api.anthropic.com" in html


class TestPolicyGate:
    def test_fail_on_egress_gates_on_high(self) -> None:
        # A HIGH (unbounded) finding fails a medium gate.
        result = evaluate_policy(_report(_audit()), PolicyConfig(fail_on_egress_severity="medium"))
        assert not result.passed
        assert any(v.rule == "fail_on.egress" for v in result.violations)

    def test_no_egress_gate_passes(self) -> None:
        result = evaluate_policy(_report(_audit()), PolicyConfig())
        assert not any(v.rule == "fail_on.egress" for v in result.violations)


class TestPerServerAllowlistWiring:
    """The per-server ``servers.<name>.egress_allowlist`` must reach the detector.

    Regression guard for the bug where the field was parsed (and shipped in
    examples/policies/egress.yaml) but never applied: the detector only ever saw the
    global allowlist, so a per-server trusted host was still flagged for that server.
    """

    @staticmethod
    def _fixed_host_audit(name: str) -> ServerAudit:
        return ServerAudit(
            server=ServerConfig(name=name, client=ClientType.CLAUDE_DESKTOP, config_path="/test/config.json"),
            connection_status="connected",
            resources=[ResourceInfo(uri="https://logs.internal.example/data")],
        )

    def test_per_server_allowlist_reaches_detector(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``trusted`` allowlists the host per-server (no finding); ``other`` does not (flagged)."""
        servers = [
            ServerConfig(name=n, client=ClientType.CLAUDE_DESKTOP, config_path="/test/config.json")
            for n in ("trusted", "other")
        ]
        monkeypatch.setattr(cli, "discover_all_configs", lambda clients: servers)

        audit_for = self._fixed_host_audit

        class FakeConnector:
            def __init__(self, timeout: float) -> None: ...

            async def connect(self, srv: ServerConfig) -> ServerAudit:
                return audit_for(srv.name)

        monkeypatch.setattr(cli, "ServerConnector", FakeConnector)

        report = anyio.run(
            functools.partial(
                cli._run_scan_core,
                False,  # skip_connect
                None,  # clients
                10,  # timeout
                None,  # extra_config
                OverrideApplier(OverrideConfig()),
                egress_check=True,
                egress_server_allowlists={"trusted": ["logs.internal.example"]},
            )
        )

        kinds = {a.server.name: {f.kind for f in a.egress_findings} for a in report.audits}
        # Per-server allowlist trusts the host → genuinely trusted, no finding at all.
        assert EgressKind.DESTINATION_OUTSIDE_ALLOWLIST not in kinds["trusted"]
        # The same host on a server without the per-server rule is still flagged.
        assert EgressKind.DESTINATION_OUTSIDE_ALLOWLIST in kinds["other"]


class TestEgressSsrfSubstrate:
    """``--egress-check`` runs SSRF as substrate; its findings must not leak unasked.

    Regression guard: when SSRF was not explicitly requested it feeds egress only, so its
    findings are dropped after consumption — they never surface in output or trip
    fail_on.ssrf. Passing --ssrf-check restores them.
    """

    @staticmethod
    def _caller_controlled_audit(name: str) -> ServerAudit:
        return ServerAudit(
            server=ServerConfig(name=name, client=ClientType.CLAUDE_DESKTOP, config_path="/test/config.json"),
            connection_status="connected",
            tools=[
                ToolInfo(
                    name="fetch_url",
                    description="Fetch the contents of a URL.",
                    input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
                )
            ],
        )

    def _run(self, monkeypatch: pytest.MonkeyPatch, *, ssrf_check: bool) -> ServerAudit:
        servers = [ServerConfig(name="s", client=ClientType.CLAUDE_DESKTOP, config_path="/test/config.json")]
        monkeypatch.setattr(cli, "discover_all_configs", lambda clients: servers)
        audit_for = self._caller_controlled_audit

        class FakeConnector:
            def __init__(self, timeout: float) -> None: ...

            async def connect(self, srv: ServerConfig) -> ServerAudit:
                return audit_for(srv.name)

        monkeypatch.setattr(cli, "ServerConnector", FakeConnector)

        report = anyio.run(
            functools.partial(
                cli._run_scan_core,
                False,  # skip_connect
                None,  # clients
                10,  # timeout
                None,  # extra_config
                OverrideApplier(OverrideConfig()),
                ssrf_check=ssrf_check,
                egress_check=True,
            )
        )
        return report.audits[0]

    def test_substrate_ssrf_findings_not_surfaced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        audit = self._run(monkeypatch, ssrf_check=False)
        # SSRF ran (egress derived an unbounded finding from it) but its findings are dropped.
        assert audit.ssrf_findings == []
        assert any(f.kind is EgressKind.UNBOUNDED_EGRESS for f in audit.egress_findings)

    def test_explicit_ssrf_check_surfaces_findings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        audit = self._run(monkeypatch, ssrf_check=True)
        # Asked-for SSRF is retained alongside egress.
        assert audit.ssrf_findings
        assert any(f.kind is EgressKind.UNBOUNDED_EGRESS for f in audit.egress_findings)
