"""Acceptance checks for the approved 3.0 proposal's release and D22 record."""

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

    assert "Once D22 lands, unfiltered static forms become" in section_4
    assert "`--scan-compatible-sources`" in section_4
    assert "plain `check` retains its stricter, superset-safe behavior" in " ".join(section_4.split())


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
