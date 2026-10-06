"""Shared config decoding and value-free diagnostics."""

import json
from collections.abc import Iterable
from pathlib import Path

import json5

from mcp_audit.discovery.base import ConfigParseError, logger
from mcp_audit.models import ClientType


def record_issue(issue: ConfigParseError, parse_errors: list[ConfigParseError] | None) -> None:
    if parse_errors is None:
        logger.warning("%s", issue)
    else:
        parse_errors.append(issue)


def decode_config(
    text: str,
    source: str,
    client: ClientType,
    parse_errors: list[ConfigParseError] | None = None,
    *,
    jsonc: bool = False,
) -> dict[str, object]:
    text = text.lstrip("\ufeff")
    if not text.strip():
        raise ConfigParseError(source, client, "empty config file")
    duplicates = 0

    def pairs_hook(pairs: Iterable[tuple[str, object]]) -> dict[str, object]:
        nonlocal duplicates
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                duplicates += 1
            result[key] = value
        return result

    try:
        data: object = (
            json5.loads(text, object_pairs_hook=pairs_hook)
            if jsonc
            else json.loads(text, object_pairs_hook=pairs_hook)
        )
    except (ValueError, RecursionError) as exc:
        # Parser exceptions can quote credential-bearing input; retain only
        # their type, never the source excerpt.
        raise ConfigParseError(source, client, f"invalid JSON: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise ConfigParseError(source, client, "top-level structure is not an object")
    if duplicates:
        record_issue(
            ConfigParseError(
                source,
                client,
                f"{duplicates} duplicate object key(s); last values retained; "
                "earlier definitions not audited",
                finding_type="duplicate_config_key",
            ),
            parse_errors,
        )
    return data


def read_config(
    path: Path,
    client: ClientType,
    parse_errors: list[ConfigParseError] | None = None,
    *,
    jsonc: bool = False,
) -> dict[str, object]:
    try:
        if not path.is_file():
            raise ConfigParseError(str(path), client, "config path is not a regular file")
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ConfigParseError(str(path), client, f"unreadable config file: {type(exc).__name__}") from exc
    return decode_config(text, str(path), client, parse_errors, jsonc=jsonc)
