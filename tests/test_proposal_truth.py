"""Acceptance checks for the 3.0 proposal's release record and decisions."""

import re
from pathlib import Path

PROPOSAL = Path("docs/3.0-BOUNDARY-PROPOSAL.md")


def test_section_7_marks_every_212_row_as_shipped() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    section_7 = proposal.split("## 7. Migration timeline", maxsplit=1)[1].split(
        "### 2.x security window", maxsplit=1
    )[0]
    rows_212 = [line for line in section_7.splitlines() if line.startswith("| 2.12 |")]

    assert rows_212
    assert all("| Shipped in 2.12.0 |" in line for line in rows_212)
    assert "not tagged yet" not in section_7


def test_section_4_documents_d22_static_translation_truth() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    section_4 = proposal.split("## 4. CLI changes", maxsplit=1)[1].split(
        "### `monitor` deletion", maxsplit=1
    )[0]

    assert "With D22 built, unfiltered static forms are exact" in " ".join(section_4.split())
    assert "`--scan-compatible-sources`" in section_4
    assert "Plain `check` retains its stricter, superset-safe behavior" in " ".join(section_4.split())


def test_section_8_records_d22_b_and_its_selector_contract() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    section_8 = proposal.split("## 8. Decisions", maxsplit=1)[1].split("## 9. Out of scope", maxsplit=1)[0]
    d22 = section_8.split("### D22.", maxsplit=1)[1]

    for detail in (
        "**Decided: (b).**",
        "`check --scan-compatible-sources`",
        "`--include-discovered`",
        "`--project`, `--config-only`, `--connect`, and `--connect-all`",
        "every Claude Code `projects[*]` scope",
        "excludes Cursor project files",
        "cwd `.mcp.json` and `.vscode/mcp.json`",
        "whole-file loss behavior",
        "no server map yields an empty result",
        "`(name, client, config, project)`",
        "identities omit the project path",
        "recommended plain `check` behavior remains superset-safe",
    ):
        assert detail in d22


def _section(proposal: str, start: str, end: str) -> str:
    return proposal.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_status_header_records_implementation_without_claiming_release() -> None:
    header = _flat(PROPOSAL.read_text(encoding="utf-8").split("## 1. Summary", maxsplit=1)[0])

    assert "Status: implemented for 3.0.0, which is not released yet." in header
    assert "O-1 to O-3 on Oct 14 2026, and O-4 on Oct 31 2026" in header
    assert "Nothing in this document changes 2.x behavior" not in header


def test_section_7_records_every_30_area_as_in_300() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    section_7 = _section(proposal, "## 7. Migration timeline", "### 2.x security window")
    rows_30 = [line for line in section_7.splitlines() if line.startswith("| 3.0.0 |")]

    assert rows_30
    assert all(line.endswith("| In 3.0.0 |") for line in rows_30)
    assert "Shipped in 3.0.0" not in section_7
    joined = " ".join(rows_30)
    for item in (
        "H-1",
        "H-2",
        "H-5",
        "D-1",
        "D-2",
        "X-1",
        "X-2",
        "X-3",
        "X-4",
        "X-5",
        "P-1",
        "P-2",
        "S-1",
        "S-2",
        "S-3",
        "S-4",
        "R-1",
        "R-2",
        "R-3",
        "R-4",
        "M-1",
        "M-2",
    ):
        assert re.search(rf"\b{item}\b", joined), item
    assert "| Planned |" not in section_7


def test_section_8_d22_status_is_built_and_parity_proven() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    d22 = _flat(_section(proposal, "### D22.", "### O-1."))

    assert (
        "Status: built as the hidden `check --scan-compatible-sources` flag (D-1) and parity-proven (D-2)"
        in d22
    )
    assert "not yet built" not in d22


def test_section_8_records_owner_decisions_o1_to_o4() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    section_8 = _section(proposal, "## 8. Decisions", "## 9. Out of scope")
    expected = {
        "### O-1.": ("**Decided: (a)**", "Oct 14 2026 PT", "`no_sources_reviewed`", "Why:"),
        "### O-2.": ("**Decided: (a)**", "Oct 14 2026 PT", "`get_high_risk_servers`", "Why:"),
        "### O-3.": ("**Decided: (A)**", "Oct 14 2026 PT", "(C) Exit 2 on the initial scan only", "Why:"),
        "### O-4.": ("**Decided: (b)**", "Oct 31 2026 PT", "`executionSuccessful: false`", "Why:"),
    }
    for heading, details in expected.items():
        entry = _flat(section_8.split(heading, maxsplit=1)[1].split("\n### ", maxsplit=1)[0])
        options = [opt for opt in ("- (a)", "- (b)", "- (c)", "- (A)", "- (B)", "- (C)") if opt in entry]
        assert len(options) >= 2, heading
        for detail in details:
            assert detail in entry, (heading, detail)


def test_section_8_records_converged_implementation_details() -> None:
    proposal = PROPOSAL.read_text(encoding="utf-8")
    details = _flat(
        _section(proposal, "### Implementation details that refined the decisions", "## 9. Out of scope")
    )

    for fact in (
        "`--config`, `--project`, `--config-only`, `--connect`, and `--connect-all`",
        "deduplication by `(name, client, config, project)`",
        "pin, canary, escalation, provenance, integrity, verify-artifacts, and download-artifacts",
        "explicit `fail_on.pin_baseline_withheld: false` is accepted and ignored with a loader warning",
        "`policy_result` carries the violation even without `--policy`",
        "`resume=true` requires the original run ID, the approved manifest SHA-256",
        "Releases are commit-first",
        "tag is created at the approved commit only after all six files",
        "use the `pypi-2x` environment",
        "Main's workflows stay main-only",
    ):
        assert fact in details, fact


def test_section_9_keeps_the_out_of_scope_list_and_no_unbuilt_claim() -> None:
    section_9 = PROPOSAL.read_text(encoding="utf-8").split("## 9. Out of scope", maxsplit=1)[1]

    assert "An enforcing proxy (D13b)." in section_9
    assert "Retiring Proof Before Action v1 capsule" in section_9
    assert "not yet built" not in section_9
