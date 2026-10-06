"""Regenerate the offline reference from the shipped taxonomy."""

from pathlib import Path

from mcp_audit.taxonomy import render_findings_index


def main() -> None:
    destination = Path(__file__).resolve().parents[1] / "docs" / "findings" / "index.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_findings_index(), encoding="utf-8")


if __name__ == "__main__":
    main()
