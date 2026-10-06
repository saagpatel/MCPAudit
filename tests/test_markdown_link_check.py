import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/scripts/check_markdown_links.py"


def _checker(root: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_markdown_links", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    return module


@pytest.mark.parametrize(("link", "ok"), [("#title", True), ("#missing-heading", False)])
def test_same_document_fragments_are_validated(tmp_path: Path, link: str, ok: bool) -> None:
    (tmp_path / "doc.md").write_text(f"# Title\n\n[here]({link})\n", encoding="utf-8")
    assert (_checker(tmp_path).main() == 0) is ok
