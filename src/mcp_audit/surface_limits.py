"""Shared listing byte budget and per-item retained text limits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar, cast

from pydantic import BaseModel

from mcp_audit.stdio_transport import DEFAULT_MAX_SURFACE_BYTES
from mcp_audit.text_limits import MAX_FIELD_BYTES, bounded_text

_Model = TypeVar("_Model", bound=BaseModel)
_STRUCTURAL_STRINGS = {"name", "uri", "type", "format", "$ref", "$id", "$schema", "mimeType"}


class SurfaceLimitError(ValueError):
    """The complete listing cannot be admitted within its byte limits."""


@dataclass
class ListingBudget:
    max_surface_bytes: int = DEFAULT_MAX_SURFACE_BYTES
    used_bytes: int = 0
    truncated_items: int = 0

    def check_available(self) -> None:
        if self.used_bytes >= self.max_surface_bytes:
            raise SurfaceLimitError(f"Surface listing exceeds {self.max_surface_bytes} bytes.")

    def charge(self, page: BaseModel) -> None:
        # Charge original metadata, before text truncation, including schema,
        # cursors and extra fields. One budget spans all pages and surfaces.
        size = len(page.model_dump_json(by_alias=True).encode("utf-8"))
        if size > self.max_surface_bytes - self.used_bytes:
            self.used_bytes = self.max_surface_bytes
            raise SurfaceLimitError(f"Surface listing exceeds {self.max_surface_bytes} bytes.")
        self.used_bytes += size

    def cap_item(self, item: _Model) -> _Model:
        data = cast(dict[str, object], item.model_dump(mode="json", by_alias=True, exclude_unset=True))
        # Preserve keys and identifiers: cutting them could merge identities or
        # invent a different schema. Reject the listing if these alone exceed
        # the per-item cap. Traverse iteratively, without recursive text walks.
        pending: list[object] = [data]
        editable: list[tuple[dict[str, object] | list[object], str | int, str]] = []
        remaining = MAX_FIELD_BYTES
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                for key, child in value.items():
                    remaining -= len(key.encode("utf-8", errors="surrogatepass"))
                    if isinstance(child, str):
                        if key in _STRUCTURAL_STRINGS:
                            remaining -= len(child.encode("utf-8", errors="surrogatepass"))
                        else:
                            editable.append((value, key, child))
                    else:
                        pending.append(child)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    if isinstance(child, str):
                        editable.append((value, index, child))
                    else:
                        pending.append(child)
        if remaining < 0:
            self.truncated_items += 1
            raise SurfaceLimitError("Item identifiers or structure exceed the 256 KiB text limit.")
        changed = False
        for container, position, text in editable:
            prefix = bounded_text(text, remaining)
            remaining -= len(prefix.encode("utf-8", errors="surrogatepass"))
            changed = changed or prefix != text
            if isinstance(container, dict):
                assert isinstance(position, str)
                container[position] = prefix
            else:
                assert isinstance(position, int)
                container[position] = prefix
        if not changed:
            return item
        self.truncated_items += 1
        return item.model_validate(data)
