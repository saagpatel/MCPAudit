"""Detector docs must describe what the detectors do.

Each test reads a specific claim from a published detector doc and checks the
detector against it:

- docs/ESCALATION-DETECTION.md: absent annotation hints add no category, and
  `destructive`/`network` are reported as gained when content or a declared
  hint adds them (the MCP018 table lists both as gained categories).
- docs/SSRF-DETECTION.md: every listed fetch-verb root is a fetch verb, and
  `http` and `request` are deliberately not.
- docs/SHADOWING-DETECTION.md: a group mixing an exact pair with a case
  variant on another server reports MCP015 and MCP016 together.
"""

from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.escalation import EscalationAnalyzer
from mcp_audit.models import (
    ClientType,
    EscalationKind,
    PermissionCategory,
    ServerAudit,
    ServerConfig,
    ShadowingKind,
    SsrfSeverity,
    ToolAnnotations,
    ToolInfo,
    TransportType,
)
from mcp_audit.shadowing import ShadowingAnalyzer
from mcp_audit.ssrf import SsrfDetector

DOCS = Path(__file__).resolve().parents[1] / "docs"
WEATHER = "Return the current weather"


def _doc(name: str) -> str:
    return " ".join((DOCS / name).read_text(encoding="utf-8").split())


def _gained(current: ToolInfo) -> set[PermissionCategory]:
    findings = EscalationAnalyzer().analyze_server(
        "srv", [ToolInfo(name="w", description=WEATHER)], [current]
    )
    return {c for f in findings if f.kind == EscalationKind.CAPABILITY for c in f.gained_categories}


def test_escalation_doc_describes_destructive_and_network_gains() -> None:
    doc = _doc("ESCALATION-DETECTION.md")
    assert "never reported as gained" not in doc
    assert "Absent annotation hints add no category" in doc
    assert _gained(ToolInfo(name="w", description="Return the latest weather report")) == set()
    assert PermissionCategory.DESTRUCTIVE in _gained(
        ToolInfo(name="w", description=WEATHER + " and delete the cache")
    )
    assert PermissionCategory.NETWORK in _gained(
        ToolInfo(name="w", description=WEATHER + " from an HTTP API endpoint")
    )
    declared = ToolInfo(name="w", description=WEATHER, annotations=ToolAnnotations(destructive_hint=True))
    assert PermissionCategory.DESTRUCTIVE in _gained(declared)


def _fetch_verb_finding(root: str) -> list[tuple[SsrfSeverity, str]]:
    tool = ToolInfo(
        name=f"{root}_target",
        description="Takes a target.",
        input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
    )
    return [(f.severity, f.pattern_name) for f in SsrfDetector().scan_server([tool], [])]


def test_ssrf_doc_fetch_verb_roots_match_detector() -> None:
    doc = _doc("SSRF-DETECTION.md")
    sentence = re.search(r"A \*\*fetch verb\*\* is detected when(.*?)\.\s", doc)
    assert sentence is not None
    roots = re.findall(r"`([a-z]+)`", sentence.group(1))
    assert roots
    high = [(SsrfSeverity.HIGH, "url_param_with_fetch_verb")]
    assert [root for root in roots if _fetch_verb_finding(root) != high] == []
    assert "`http` and `request` are deliberately not fetch verbs" in doc
    for root in ("http", "request"):
        assert root not in roots
        assert _fetch_verb_finding(root) == [(SsrfSeverity.MEDIUM, "url_param")]


def _audit(server: str, tools: list[str]) -> ServerAudit:
    config = ServerConfig(
        name=server,
        client=ClientType.CLAUDE_CODE,
        config_path="fixture.json",
        command="x",
        transport=TransportType.STDIO,
    )
    return ServerAudit(
        server=config,
        connection_status="connected",
        tools=[ToolInfo(name=t, description="Echo a value.") for t in tools],
    )


def test_shadowing_doc_describes_exact_pair_plus_variant() -> None:
    doc = _doc("SHADOWING-DETECTION.md")
    assert "no double-reporting" not in doc
    assert "MCP016 **also** fires for the full group" in doc
    mixed = ShadowingAnalyzer().analyze_fleet(
        [_audit("srv-a", ["delete"]), _audit("srv-b", ["delete"]), _audit("srv-c", ["Delete"])]
    )
    assert {f.kind for f in mixed} == {ShadowingKind.EXACT, ShadowingKind.NORMALIZED}
    exact_only = ShadowingAnalyzer().analyze_fleet([_audit("srv-a", ["delete"]), _audit("srv-b", ["delete"])])
    assert {f.kind for f in exact_only} == {ShadowingKind.EXACT}
