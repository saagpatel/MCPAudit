"""Prepare source/anchor bytes with native POSIX modes; invoke no consumer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from adapter_common import prepare


def prepare_p3(fixture_path: Path, destination: Path) -> dict[str, Any]:
    # The shared materializer asserts actual modes after chmod. Any unsupported
    # behavior raises and therefore aborts rather than emulating a result.
    return prepare(fixture_path, destination, "P3")
