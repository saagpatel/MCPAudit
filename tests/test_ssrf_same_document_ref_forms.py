"""The SSRF schema walker must follow every same-document `$ref` form.

docs/OUTPUT-CONTRACT.md says permission inference "inspects reachable nested
property names through the bounded SSRF schema walker, including objects,
array items, composition branches, and same-document `$ref` targets", and that
for the schema metadata rules "Local references establish reachability through
local `$anchor` declarations and percent-decoded JSON Pointer fragments".

The SSRF walker resolves plain JSON Pointer refs (`#/$defs/Request`, see
test_referenced_definition_is_scanned_at_use_site) but not a local `$anchor`
(`#node`) or a percent-encoded pointer (`#/$defs/a%20b`). Both are
same-document refs, so a URL parameter reached through them should give the
same HIGH url_param_with_fetch_verb finding as the plain form. Instead the
walker reports the medium url_param_traversal_incomplete fallback. This fails
closed (the gap is visible), but the two walkers disagree about the same
schema.

These tests fail on current main. They document the defect; they do not fix it.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_audit.models import SsrfSeverity, ToolInfo
from mcp_audit.ssrf import SsrfDetector

URL_DEF: dict[str, Any] = {"type": "object", "properties": {"url": {"type": "string"}}}

SCHEMAS: dict[str, dict[str, Any]] = {
    "plain-pointer": {
        "type": "object",
        "properties": {"t": {"$ref": "#/$defs/n"}},
        "$defs": {"n": URL_DEF},
    },
    "anchor": {
        "type": "object",
        "properties": {"t": {"$ref": "#node"}},
        "$defs": {"n": {"$anchor": "node", **URL_DEF}},
    },
    "percent-encoded-pointer": {
        "type": "object",
        "properties": {"t": {"$ref": "#/$defs/a%20b"}},
        "$defs": {"a b": URL_DEF},
    },
}


@pytest.mark.parametrize("form", list(SCHEMAS))
def test_same_document_ref_forms_reach_the_url_parameter(form: str) -> None:
    tool = ToolInfo(name="fetch_doc", description="Fetch a document.", input_schema=SCHEMAS[form])
    findings = SsrfDetector().scan_server([tool], [])
    assert [(f.severity, f.pattern_name) for f in findings] == [
        (SsrfSeverity.HIGH, "url_param_with_fetch_verb")
    ]
