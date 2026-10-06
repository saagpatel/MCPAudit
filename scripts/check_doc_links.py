"""Check repository-local Markdown links in user and maintainer documentation."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))")
HEADING_PATTERN = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def _slug(heading: str) -> str:
    plain = re.sub(r"[`*_~]", "", heading).lower()
    plain = re.sub(r"[^\w\- ]", "", plain)
    return re.sub(r"\s+", "-", plain.strip())


def _anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    counts: dict[str, int] = {}
    anchors: set[str] = set()
    for match in HEADING_PATTERN.finditer(text):
        base = _slug(match.group(1))
        count = counts.get(base, 0)
        counts[base] = count + 1
        anchors.add(base if count == 0 else f"{base}-{count}")
    return anchors


def check_links() -> list[str]:
    markdown_files = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
    markdown_files.extend(sorted((ROOT / "maintainers").glob("*.md")))
    markdown_files.extend(sorted((ROOT / "archive").glob("*.md")))
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for source in markdown_files:
        text = source.read_text(encoding="utf-8")
        for match in LINK_PATTERN.finditer(text):
            raw_target = match.group(1) or match.group(2)
            target = unquote(raw_target)
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            target_path = source if not parsed.path else (source.parent / parsed.path).resolve()
            if not target_path.exists():
                errors.append(f"{source.relative_to(ROOT)}: missing link target {parsed.path}")
                continue
            if parsed.fragment:
                if target_path.is_dir():
                    target_path = target_path / "README.md"
                if target_path.suffix.lower() != ".md" or not target_path.is_file():
                    continue
                if target_path not in anchor_cache:
                    anchor_cache[target_path] = _anchors(target_path)
                if unquote(parsed.fragment).lower() not in anchor_cache[target_path]:
                    errors.append(
                        f"{source.relative_to(ROOT)}: missing anchor #{parsed.fragment} "
                        f"in {target_path.relative_to(ROOT)}"
                    )
    return errors


def main() -> int:
    errors = check_links()
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("Repository-local Markdown links are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
