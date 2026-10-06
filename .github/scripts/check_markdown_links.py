#!/usr/bin/env python3
"""Check local Markdown links and heading fragments without network access."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)|<(?:[^:>]+\.md(?:#[^>]*)?)>")
HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$", re.MULTILINE)


def _anchors(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    anchors: set[str] = set()
    counts: dict[str, int] = {}
    for heading in HEADING.findall(text):
        slug = re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-")
        slug = re.sub(r"-+", "-", slug).strip("-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    anchors.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', text, re.IGNORECASE))
    return anchors


def main() -> int:
    failures: list[str] = []
    for source in sorted(ROOT.rglob("*.md")):
        if ".git" in source.parts:
            continue
        text = source.read_text(encoding="utf-8")
        text = re.sub(r"(```.*?```|~~~.*?~~~|`[^`]*`)", "", text, flags=re.DOTALL)
        for match in LINK.finditer(text):
            raw = match.group(1) or match.group(0)[1:-1]
            target = raw.split(maxsplit=1)[0].strip("<>\"'")
            if not target:
                continue
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc:
                continue
            rel = unquote(parsed.path)
            candidate = (source.parent / rel).resolve() if rel else source
            try:
                candidate.relative_to(ROOT)
            except ValueError:
                failures.append(f"{source.relative_to(ROOT)}: link escapes repository: {target}")
                continue
            if candidate.is_dir():
                candidate = candidate / "README.md"
            if not candidate.is_file():
                failures.append(f"{source.relative_to(ROOT)}: missing target: {target}")
                continue
            if parsed.fragment and candidate.suffix.lower() == ".md":
                if unquote(parsed.fragment) not in _anchors(candidate):
                    failures.append(f"{source.relative_to(ROOT)}: missing anchor: {target}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Local Markdown links are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
