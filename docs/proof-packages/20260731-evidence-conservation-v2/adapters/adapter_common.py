"""Mechanical adapter helpers: load, materialize, and capture raw bytes only."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, cast

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS = PACKAGE_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from materialize_fixture import materialize  # noqa: E402


def load_fixture(path: Path, expected_path_id: str) -> dict[str, Any]:
    fixture = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    if fixture.get("path_id") != expected_path_id:
        raise ValueError(f"expected {expected_path_id} fixture")
    return fixture


def prepare(path: Path, destination: Path, expected_path_id: str) -> dict[str, Any]:
    return materialize(load_fixture(path, expected_path_id), destination)


def capture_raw(fixture_id: str, raw_bytes: bytes) -> dict[str, Any]:
    """Capture exact output bytes without inspecting or classifying them."""
    return {
        "schema": "AdapterCaptureV1",
        "fixture_id": fixture_id,
        "captured_bytes_base64": base64.b64encode(raw_bytes).decode("ascii"),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
