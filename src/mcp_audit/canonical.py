"""Canonical JSON bytes for tool pins and observed session surfaces."""

from __future__ import annotations

import json


def canonical_json_bytes(value: object, *, legacy: bool = False) -> bytes:
    """Serialize v2 compact JSON; retain the original v1 bytes for comparison only."""
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(", ", ": ") if legacy else (",", ":"),
        ensure_ascii=False,
        allow_nan=legacy,
    ).encode("utf-8")
    return payload if legacy else payload + b"\n"
