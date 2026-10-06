"""Acceptance checks for the newcomer documentation layout."""

from pathlib import Path


def test_readme_is_a_short_newcomer_entry_point() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 120 <= len(readme.splitlines()) <= 150
    assert readme.count("The package is `mcp-audits`; the command is `mcp-audit`.") == 1
    assert (
        readme.index("mcp-audit                              # static review")
        < readme.index("mcp-audit check --config ./mcp.json")
        < readme.index("mcp-audit demo")
    )


def test_documentation_sections_are_in_their_new_locations() -> None:
    for guide in ("ci", "pinning", "trust-packet", "suppressing", "sandbox"):
        assert Path(f"docs/guides/{guide}.md").is_file()
    assert Path("docs/labs/README.md").is_file()
    assert Path("maintainers/README.md").is_file()
    assert Path("archive/README.md").is_file()
    for release in ("2.5", "2.6", "2.7", "2.8"):
        assert not Path(f"docs/{release}-RELEASE-NOTES.md").exists()
