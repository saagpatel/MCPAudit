"""Shared mechanics for offline labs; input and output policy stays with each lab."""

from __future__ import annotations

import json
import os
from typing import Never

from pydantic import BaseModel

from mcp_audit.canonical import compact_json_bytes


def read_bounded_descriptor(descriptor: int, max_bytes: int) -> bytes:
    """Read at most the budget plus one sentinel byte, including across short reads.

    The caller owns opening, regular-file/identity checks, error mapping, and
    closing the descriptor. The sentinel lets it apply its own oversized-input policy.
    """
    if max_bytes < 0:
        raise ValueError("byte budget must be non-negative")
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _reject_constant(_value: str) -> Never:
    raise ValueError("unsupported JSON constant")


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def strict_json_loads(raw: bytes) -> object:
    """Decode JSON without duplicate members or nonstandard numeric constants.

    Size, depth, node counts, finite-float checks, and schema validation remain
    caller policy. Hook errors never include untrusted keys or values.
    """
    payload: object = json.loads(
        raw, object_pairs_hook=_object_without_duplicates, parse_constant=_reject_constant
    )
    return payload


def validate_json_nesting(raw: bytes, max_depth: int, error_type: type[ValueError]) -> None:
    """Bound container nesting before decoding, ignoring delimiters inside strings."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > max_depth:
                raise error_type(f"JSON nesting exceeds {max_depth} levels")
        elif byte in {0x5D, 0x7D}:
            depth = max(0, depth - 1)


def model_json_bytes(value: object, *, by_alias: bool | None = None, allow_nan: bool = False) -> bytes:
    """Encode a lab model or JSON value with its existing alias and number policy."""
    payload: object = value
    if isinstance(value, BaseModel):
        payload = (
            value.model_dump(mode="json")
            if by_alias is None
            else value.model_dump(mode="json", by_alias=by_alias)
        )
    return compact_json_bytes(payload, allow_nan=allow_nan) + b"\n"
