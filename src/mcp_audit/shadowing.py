"""Cross-server tool-name shadowing detector.

Detects when two or more different configured MCP servers expose tools with
colliding or confusable names.  This is a FLEET-LEVEL check only — tool names
are unique within a single server, so collisions are inherently cross-server.

Three tiers:

  MCP015 (EXACT / HIGH)      — ≥2 servers expose the identical tool name.
  MCP016 (NORMALIZED / MED)  — names differ only by case and/or separators
                                (_  -  whitespace) but normalise to the same
                                token.  Only fires when there is no exact match
                                for that canonical name.
  MCP017 (HOMOGLYPH / HIGH)  — a tool name contains non-ASCII confusable
                                characters whose ASCII "skeleton" matches
                                another server's tool name.  Bytes differ but
                                skeletons match.

Legit servers namespace their tools (slack_*, github_*).  In a 21-server real-
world corpus there are ZERO exact or normalised collisions.  Exact-match HIGH
findings are designed to stay low-noise because the detector avoids fuzzy
matching and reports only concrete cross-server collisions.

Detector is purely additive and opt-in behind ``--shadow-check``.  It reads
tool names only (never values, never credentials) and issues no network
requests.
"""

from __future__ import annotations

import re
from collections import defaultdict

from mcp_audit.models import ServerAudit, ShadowingFinding, ShadowingKind, ShadowingSeverity

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

_SEPARATOR_RE = re.compile(r"[_\-\s]+")


def _normalise(name: str) -> str:
    """Lowercase + strip separators (_  -  whitespace) so read_file == readFile == read-file."""
    return _SEPARATOR_RE.sub("", name.lower())


# ---------------------------------------------------------------------------
# Homoglyph / confusable-codepoint map
#
# A curated set of the most-common non-ASCII confusables mapped to their
# ASCII equivalents.  Kept small and documented; no external dependency.
#
# Sources: Unicode Confusables (tr39) subset — Cyrillic + Greek lookalikes that
# appear most frequently in published homoglyph-based phishing and toolname
# spoofing demos.
# ---------------------------------------------------------------------------

_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic → ASCII
    "а": "a",  # а → a
    "е": "e",  # е → e
    "о": "o",  # о → o
    "р": "p",  # р → p
    "с": "c",  # с → c
    "х": "x",  # х → x
    "і": "i",  # і → i
    "у": "y",  # у → y
    # Greek → ASCII
    "ο": "o",  # ο → o
    "α": "a",  # α → a
    "ε": "e",  # ε → e
    "ρ": "p",  # ρ → p
    "ν": "v",  # ν → v
    # Latin lookalikes
    "à": "a",  # à → a
    "á": "a",  # á → a
    "è": "e",  # è → e
    "é": "e",  # é → e
    "ó": "o",  # ó → o
    "ö": "o",  # ö → o
    "ü": "u",  # ü → u
    "í": "i",  # í → i
}


def _skeleton(name: str) -> str:
    """Replace confusable codepoints with their ASCII equivalent, then lowercase.

    Only applied to the original bytes (not after normalisation) so separators
    are preserved for skeleton comparison.
    """
    return "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in name).lower()


def _is_ascii(name: str) -> bool:
    return all(ord(ch) < 128 for ch in name)


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class ShadowingAnalyzer:
    """Detects cross-server tool-name shadowing (exact, normalised, homoglyph)."""

    def analyze_fleet(self, audits: list[ServerAudit]) -> list[ShadowingFinding]:
        """Return shadowing findings across the full fleet.

        Only cross-server collisions are reported.  Tools within the same
        server are never compared (names are unique within a server by the MCP
        spec).  Order in ``audits`` determines which server is presumed
        legitimate (first-configured).

        Precedence: exact > normalised.  A name that collides exactly is
        reported as EXACT only — not also as NORMALIZED.  Homoglyph findings
        are orthogonal (they require at least one non-ASCII tool name).
        """
        # Build an ordered index: server_name → list[tool_name] (preserving
        # config order so the first server wins precedence).
        server_tools: list[tuple[str, list[str]]] = []
        for audit in audits:
            if audit.tools:
                server_tools.append((audit.server.name, [t.name for t in audit.tools]))

        findings: list[ShadowingFinding] = []

        # ---- Tier 1: EXACT ------------------------------------------------
        # Map raw tool name → list of (server_name, tool_name) pairs (in order)
        exact_index: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for server_name, tools in server_tools:
            for tool in tools:
                exact_index[tool].append((server_name, tool))

        for raw_name, collisions in exact_index.items():
            # Filter to cross-server (>1 distinct server)
            servers_seen = {srv for srv, _ in collisions}
            if len(servers_seen) < 2:
                continue
            canonical = raw_name
            findings.append(
                ShadowingFinding(
                    kind=ShadowingKind.EXACT,
                    severity=ShadowingSeverity.HIGH,
                    name=canonical,
                    collisions=collisions,
                    description=self._description(ShadowingKind.EXACT, canonical, collisions),
                )
            )

        # ---- Tier 2: NORMALIZED -------------------------------------------
        # Map normalised form → list of (server_name, raw_tool_name) pairs
        norm_index: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for server_name, tools in server_tools:
            for tool in tools:
                norm_index[_normalise(tool)].append((server_name, tool))

        for norm_form, collisions in norm_index.items():
            if not norm_form:
                continue  # ignore degenerate all-separator names (e.g. '___')
            servers_seen = {srv for srv, _ in collisions}
            if len(servers_seen) < 2:
                continue
            # Skip pure-exact groups (every name byte-identical) — the EXACT tier
            # already covers those. Emit only when there is genuine case/separator
            # variation, and include the FULL group so every shadower stays visible
            # even when a byte-identical subset already fired an EXACT finding.
            if len({tool for _, tool in collisions}) < 2:
                continue
            # Canonical name = first raw name encountered (first-configured server wins)
            canonical = collisions[0][1]
            findings.append(
                ShadowingFinding(
                    kind=ShadowingKind.NORMALIZED,
                    severity=ShadowingSeverity.MEDIUM,
                    name=canonical,
                    collisions=collisions,
                    description=self._description(ShadowingKind.NORMALIZED, canonical, collisions),
                )
            )

        # ---- Tier 3: HOMOGLYPH --------------------------------------------
        # Only fires when raw bytes differ but skeletons match.
        # A finding is only produced when at least one tool name is non-ASCII.
        skel_index: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for server_name, tools in server_tools:
            for tool in tools:
                skel_index[_skeleton(tool)].append((server_name, tool))

        # Track which (server_name, tool_name) pairs we've already reported in
        # exact/normalised so homoglyph doesn't double-report.
        already_reported: set[tuple[str, str]] = set()
        for f in findings:
            already_reported.update(f.collisions)

        for skel_form, collisions in skel_index.items():
            if not skel_form:
                continue  # ignore empty/degenerate skeletons
            servers_seen = {srv for srv, _ in collisions}
            if len(servers_seen) < 2:
                continue
            # At least one tool name must be non-ASCII for this to be a homoglyph
            if all(_is_ascii(tool) for _, tool in collisions):
                continue
            # If every pair is already covered by a prior finding, skip
            novel = [pair for pair in collisions if pair not in already_reported]
            if not novel:
                continue
            canonical = (
                next(tool for _, tool in collisions if _is_ascii(tool))
                if any(_is_ascii(tool) for _, tool in collisions)
                else collisions[0][1]
            )
            findings.append(
                ShadowingFinding(
                    kind=ShadowingKind.HOMOGLYPH,
                    severity=ShadowingSeverity.HIGH,
                    name=canonical,
                    collisions=collisions,
                    description=self._description(ShadowingKind.HOMOGLYPH, canonical, collisions),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _description(
        self,
        kind: ShadowingKind,
        canonical: str,
        collisions: list[tuple[str, str]],
    ) -> str:
        from mcp_audit.taxonomy import shadowing_metadata

        base = shadowing_metadata(kind).description
        first_server = collisions[0][0]
        later = [f"'{srv}'/'{tool}'" for srv, tool in collisions[1:]]
        later_str = ", ".join(later)
        return (
            f"{base}  Canonical name: '{canonical}'.  "
            f"Presumed legitimate: '{first_server}'.  "
            f"Suspect shadower(s): {later_str}."
        )
