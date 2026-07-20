from __future__ import annotations

import json
from typing import Any

from mcp_audit.models import ResourceInfo, ToolInfo
from mcp_audit.ssrf import SsrfDetector, filter_allowlisted_ssrf, fixed_host_from_uri, parse_host_allowlist

_MAX_TEXT_BYTES = 4096
_DETECTOR = SsrfDetector()


def _text(data: bytes) -> str:
    return data[:_MAX_TEXT_BYTES].decode("utf-8", "replace")


def _schema_from_payload(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    candidate = payload.get("input_schema", payload)
    if isinstance(candidate, dict):
        return candidate
    return None


def _description_from_payload(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return None
    value = payload.get("description")
    if isinstance(value, str):
        return value[:512]
    return None


def fuzz_one_input(data: bytes) -> None:
    text = _text(data)

    resource_findings = _DETECTOR.scan_resource(ResourceInfo(uri=text))
    allowlist = parse_host_allowlist(text)
    fixed_host_from_uri(text)
    filter_allowlisted_ssrf(resource_findings, allowlist)

    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError:
        return

    schema = _schema_from_payload(payload)
    if schema is None:
        return

    tool = ToolInfo(
        name="fuzz_fetch_url",
        description=_description_from_payload(payload),
        input_schema=schema,
    )
    _DETECTOR.scan_tool(tool)


def main() -> None:
    import sys

    import atheris  # type: ignore[import-not-found]

    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
