"""Canonical JSON bytes for tool pins and observed session surfaces."""

from __future__ import annotations

import json


def compact_json_bytes(value: object, *, allow_nan: bool = False) -> bytes:
    """Encode sorted compact UTF-8 JSON without a terminal newline."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=allow_nan
    ).encode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize the v2 compact JSON form with a trailing newline."""
    return compact_json_bytes(value) + b"\n"
