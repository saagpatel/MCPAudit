"""Detector docs must describe what the detectors do.

Each test reads a specific claim from a published detector doc and checks the
detector against it. Each passes as soon as the doc and the code agree,
whichever side changes. In all three cases the code looks deliberate (a code
comment or a committed test backs it), so the likely fix is the doc.

- docs/ESCALATION-DETECTION.md, False-Positive Notes: "`destructive`/`network`
  are never reported as gained". The same doc's MCP018 table lists
  `destructive` (HIGH) and `network` (MEDIUM) as gained categories, and the
  analyzer reports them when a description gains that content.
- docs/SSRF-DETECTION.md, Tools: the fetch-verb roots listed include `http`
  and `request`. src/mcp_audit/ssrf.py deliberately excludes both ("they
  appear in most network tool descriptions").
- docs/SHADOWING-DETECTION.md, MCP016: "Only fires when the canonical
  normalised form is **not already an exact match** for any pair" followed by
  "no double-reporting". tests/test_shadowing.py::
  test_mixed_exact_and_cased_variant_keeps_third_server_visible requires
  NORMALIZED alongside EXACT for such a group.

These tests fail on current main. They document the drift; they do not fix it.
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
    ToolInfo,
    TransportType,
)
from mcp_audit.shadowing import ShadowingAnalyzer
from mcp_audit.ssrf import SsrfDetector

DOCS = Path(__file__).resolve().parents[1] / "docs"
WEATHER = "Return the current weather"


def _doc(name: str) -> str:
    return " ".join((DOCS / name).read_text(encoding="utf-8").split())


def test_escalation_never_gained_note_matches_analyzer() -> None:
    if "`destructive`/`network` are never reported as gained" not in _doc("ESCALATION-DETECTION.md"):
        return
    probes = {
        PermissionCategory.DESTRUCTIVE: " and delete the cache",
        PermissionCategory.NETWORK: " from an HTTP API endpoint",
    }
    for category, suffix in probes.items():
        findings = EscalationAnalyzer().analyze_server(
            "srv",
            [ToolInfo(name="w", description=WEATHER)],
            [ToolInfo(name="w", description=WEATHER + suffix)],
        )
        gained = {c for f in findings if f.kind == EscalationKind.CAPABILITY for c in f.gained_categories}
        assert category not in gained, f"doc says {category.value} is never gained; analyzer reported it"


def test_every_documented_fetch_verb_root_is_a_fetch_verb() -> None:
    sentence = re.search(r"A \*\*fetch verb\*\* is detected when(.*?)\.\s", _doc("SSRF-DETECTION.md"))
    assert sentence is not None
    roots = re.findall(r"`([a-z]+)`", sentence.group(1))
    assert roots
    missing = []
    for root in roots:
        tool = ToolInfo(
            name=f"{root}_target",
            description="Takes a target.",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
        )
        found = [(f.severity, f.pattern_name) for f in SsrfDetector().scan_server([tool], [])]
        if found != [(SsrfSeverity.HIGH, "url_param_with_fetch_verb")]:
            missing.append(root)
    assert missing == [], f"documented fetch-verb roots not treated as fetch verbs: {missing}"


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


def test_normalized_no_double_reporting_claim_matches_analyzer() -> None:
    if "no double-reporting" not in _doc("SHADOWING-DETECTION.md"):
        return
    findings = ShadowingAnalyzer().analyze_fleet(
        [_audit("srv-a", ["delete"]), _audit("srv-b", ["delete"]), _audit("srv-c", ["Delete"])]
    )
    kinds = {f.kind for f in findings}
    assert ShadowingKind.EXACT in kinds
    assert ShadowingKind.NORMALIZED not in kinds, "doc promises no double-reporting; got EXACT and NORMALIZED"
