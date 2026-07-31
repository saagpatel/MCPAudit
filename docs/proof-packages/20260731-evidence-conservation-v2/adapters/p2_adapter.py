"""Prepare the exact EngineResult and RefreshCandidateV1; invoke no consumer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapter_common import prepare


def prepare_p2(fixture_path: Path, destination: Path) -> dict[str, Any]:
    return prepare(fixture_path, destination, "P2")
