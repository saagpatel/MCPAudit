"""Tests for the SSRF (server-side request forgery) capability detector."""

from __future__ import annotations

from mcp_audit.models import (
    CapabilityTarget,
    ResourceInfo,
    SsrfFinding,
    SsrfSeverity,
    ToolInfo,
)
from mcp_audit.ssrf import (
    SsrfDetector,
    filter_allowlisted_ssrf,
    host_in_allowlist,
    parse_host_allowlist,
)


def _ssrf(target_name: str, target_type: CapabilityTarget = CapabilityTarget.RESOURCE) -> SsrfFinding:
    return SsrfFinding(
        target_type=target_type,
        target_name=target_name,
        severity=SsrfSeverity.HIGH,
        pattern_name="test",
        evidence=["e"],
        description="d",
    )


class TestSsrfAllowlist:
    def test_parse_allowlist_normalises(self) -> None:
        assert parse_host_allowlist(" API.Github.com, , internal.svc ") == {
            "api.github.com",
            "internal.svc",
        }
        assert parse_host_allowlist(None) == set()

    def test_host_match_exact_and_subdomain(self) -> None:
        allow = {"example.com"}
        assert host_in_allowlist("example.com", allow)
        assert host_in_allowlist("api.example.com", allow)
        assert not host_in_allowlist("notexample.com", allow)
        assert not host_in_allowlist("example.com.evil.com", allow)

    def test_empty_allowlist_is_noop(self) -> None:
        findings = [_ssrf("https://api.trusted.com/{id}")]
        kept, dropped = filter_allowlisted_ssrf(findings, set())
        assert kept == findings and dropped == 0

    def test_suppresses_fixed_host_resource(self) -> None:
        findings = [_ssrf("https://api.trusted.com/{id}")]
        kept, dropped = filter_allowlisted_ssrf(findings, {"trusted.com"})
        assert kept == [] and dropped == 1

    def test_never_suppresses_caller_controlled_host(self) -> None:
        # Templated host authority is caller-controlled — never allowlistable.
        findings = [_ssrf("https://{host}/path")]
        kept, dropped = filter_allowlisted_ssrf(findings, {"trusted.com"})
        assert kept == findings and dropped == 0

    def test_never_suppresses_tool_param_finding(self) -> None:
        # Tool findings carry a tool name, not a URI — no fixed host to allowlist.
        findings = [_ssrf("fetch_url", target_type=CapabilityTarget.TOOL)]
        kept, dropped = filter_allowlisted_ssrf(findings, {"trusted.com"})
        assert kept == findings and dropped == 0

    def test_non_allowlisted_host_is_kept(self) -> None:
        findings = [_ssrf("https://evil.com/{id}")]
        kept, dropped = filter_allowlisted_ssrf(findings, {"trusted.com"})
        assert kept == findings and dropped == 0


def _tool(name: str, description: str, properties: dict[str, object]) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema={"type": "object", "properties": properties},
    )


# --- Tool: high-severity canonical SSRF ---------------------------------------


def test_url_param_with_fetch_verb_is_high() -> None:
    detector = SsrfDetector()
    tool = _tool("fetch_url", "Fetch the contents of a URL.", {"url": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is SsrfSeverity.HIGH
    assert finding.pattern_name == "url_param_with_fetch_verb"
    assert finding.target_type is CapabilityTarget.TOOL
    assert finding.target_name == "fetch_url"
    assert any("url" in e for e in finding.evidence)


def test_one_finding_per_tool_even_with_many_signals() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "proxy_request",
        "Proxy an HTTP request to a target host.",
        {
            "url": {"type": "string"},
            "endpoint": {"type": "string"},
            "host": {"type": "string"},
        },
    )
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.HIGH


# --- Tool: medium-severity --------------------------------------------------


def test_url_param_without_verb_is_medium() -> None:
    detector = SsrfDetector()
    tool = _tool("store_record", "Store a record.", {"callback_url": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert findings[0].pattern_name == "url_param"


def test_format_uri_param_is_medium() -> None:
    detector = SsrfDetector()
    tool = _tool("register", "Register an entry.", {"endpoint": {"type": "string", "format": "uri"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM


def test_host_param_with_verb_is_medium() -> None:
    detector = SsrfDetector()
    tool = _tool("ping_host", "Ping a host and report latency.", {"host": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert findings[0].pattern_name == "host_param_with_fetch_verb"


# --- Tool: low-severity -----------------------------------------------------


def test_host_param_alone_is_low() -> None:
    detector = SsrfDetector()
    tool = _tool("save_entry", "Persist an entry.", {"hostname": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.LOW
    assert findings[0].pattern_name == "host_param"


# --- Nested JSON Schema parameters -----------------------------------------


def test_nested_object_url_param_is_detected() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "fetch_resource",
        "Fetch a resource.",
        {
            "request": {
                "type": "object",
                "properties": {
                    "targetUrl": {"type": "string", "format": "uri"},
                },
            }
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.HIGH
    assert "URL-shaped parameter 'request.targetUrl'" in findings[0].evidence


def test_array_item_host_param_is_detected() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "ping_targets",
        "Ping configured targets.",
        {
            "targets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"hostname": {"type": "string"}},
                },
            }
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert "host/address parameter 'targets.hostname'" in findings[0].evidence


def test_composed_schema_url_param_is_detected() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="register_callback",
        description="Register a callback.",
        input_schema={
            "allOf": [
                {
                    "type": "object",
                    "properties": {"callbackUrl": {"type": "string"}},
                }
            ]
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert "URL-shaped parameter 'callbackUrl'" in findings[0].evidence


def test_nested_clean_schema_has_no_findings() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "search",
        "Search documents.",
        {
            "filters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
            }
        },
    )

    assert detector.scan_tool(tool) == []


def test_nested_child_does_not_inherit_parent_target_tokens() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "store",
        "Store callback configuration.",
        {
            "callback": {
                "type": "object",
                "properties": {"timeout": {"type": "integer"}},
            }
        },
    )

    finding = detector.scan_tool(tool)[0]

    assert finding.evidence == ["URL-shaped parameter 'callback'"]


def test_schema_metadata_does_not_manufacture_nested_properties() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="store_example",
        description="Store schema documentation.",
        input_schema={
            "type": "object",
            "examples": [
                {
                    "properties": {
                        "targetUrl": {"type": "string", "format": "uri"},
                    }
                }
            ],
        },
    )

    assert detector.scan_tool(tool) == []


def test_cyclic_programmatic_schema_is_finite() -> None:
    detector = SsrfDetector()
    tool = _tool(
        "fetch_resource",
        "Fetch a resource.",
        {
            "request": {
                "type": "object",
                "properties": {"endpoint": {"type": "string"}},
            }
        },
    )
    request_schema = tool.input_schema["properties"]["request"]
    assert isinstance(request_schema, dict)
    request_properties = request_schema["properties"]
    assert isinstance(request_properties, dict)
    request_properties["self"] = request_schema

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert "URL-shaped parameter 'request.endpoint'" in findings[0].evidence


# --- Tool: no finding (avoid flagging plain network tools) ------------------


def test_clean_tool_has_no_findings() -> None:
    detector = SsrfDetector()
    tool = _tool("search", "Search documents by keyword.", {"query": {"type": "string"}})
    assert detector.scan_tool(tool) == []


def test_fetch_verb_without_target_param_is_not_ssrf() -> None:
    # A fetch tool with no caller-controllable target is NETWORK, not SSRF.
    detector = SsrfDetector()
    tool = _tool("fetch_news", "Fetch the latest news.", {"topic": {"type": "string"}})
    assert detector.scan_tool(tool) == []


def test_tool_without_schema_has_no_findings() -> None:
    detector = SsrfDetector()
    assert detector.scan_tool(ToolInfo(name="fetch_url", description="Fetch a URL.")) == []


# --- Resource SSRF ----------------------------------------------------------


def test_resource_remote_host_template_is_high() -> None:
    detector = SsrfDetector()
    findings = detector.scan_resource(ResourceInfo(uri="https://{host}/api/data"))
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.HIGH
    assert findings[0].pattern_name == "remote_uri_host_template"
    assert findings[0].target_type is CapabilityTarget.RESOURCE


def test_resource_remote_path_template_is_low() -> None:
    detector = SsrfDetector()
    findings = detector.scan_resource(ResourceInfo(uri="https://api.example.com/{path}"))
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.LOW
    assert findings[0].pattern_name == "remote_uri_path_template"


def test_resource_fixed_remote_has_no_finding() -> None:
    detector = SsrfDetector()
    assert detector.scan_resource(ResourceInfo(uri="https://api.example.com/data")) == []


def test_resource_local_scheme_template_has_no_finding() -> None:
    detector = SsrfDetector()
    assert detector.scan_resource(ResourceInfo(uri="file:///{name}.txt")) == []


# --- Aggregation + metadata -------------------------------------------------


def test_scan_server_aggregates_tools_and_resources() -> None:
    detector = SsrfDetector()
    tools = [_tool("fetch_url", "Fetch a URL.", {"url": {"type": "string"}})]
    resources = [ResourceInfo(uri="https://{host}/x")]
    findings = detector.scan_server(tools, resources)
    assert len(findings) == 2
    assert {f.target_type for f in findings} == {CapabilityTarget.TOOL, CapabilityTarget.RESOURCE}


def test_high_finding_exposes_stable_taxonomy_metadata() -> None:
    detector = SsrfDetector()
    tool = _tool("fetch_url", "Fetch a URL.", {"url": {"type": "string"}})
    finding = detector.scan_tool(tool)[0]
    assert finding.rule_id == "MCP011"
    assert "SSRF" in finding.title
    assert finding.remediation
    assert finding.description


# --- camelCase parameter tokenization (regression: TS/JS schemas are camelCase) ---


def test_camelcase_url_param_is_detected() -> None:
    detector = SsrfDetector()
    tool = _tool("store", "Store a record.", {"callbackUrl": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert findings[0].pattern_name == "url_param"


def test_acronym_url_param_is_detected() -> None:
    detector = SsrfDetector()
    tool = _tool("store", "Store a record.", {"targetURL": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM


def test_camelcase_url_param_with_fetch_verb_is_high() -> None:
    detector = SsrfDetector()
    tool = _tool("fetchResource", "Fetch a resource.", {"sourceUri": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.HIGH


# --- verb precision (regression: common 'http'/'request' words must not inflate) ---


def test_http_in_name_does_not_inflate_to_high() -> None:
    # A tool that merely reports an HTTP status is not a server-side fetcher.
    detector = SsrfDetector()
    tool = _tool("get_http_status", "Return the HTTP status code.", {"url": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM


def test_request_id_word_does_not_inflate_to_high() -> None:
    detector = SsrfDetector()
    tool = _tool("request_id_lookup", "Look up a request id.", {"endpoint": {"type": "string"}})
    findings = detector.scan_tool(tool)
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM


# --- resource URI precision (regression: userinfo template != host template) ---


def test_resource_templated_credential_on_fixed_host_has_no_finding() -> None:
    detector = SsrfDetector()
    uri = "https://user:{token}@fixed.example.com/path"
    assert detector.scan_resource(ResourceInfo(uri=uri)) == []


def test_resource_query_template_is_low() -> None:
    detector = SsrfDetector()
    findings = detector.scan_resource(ResourceInfo(uri="https://api.example.com/data?id={id}"))
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.LOW
    assert findings[0].pattern_name == "remote_uri_path_template"


def test_resource_userinfo_with_host_template_is_still_high() -> None:
    detector = SsrfDetector()
    findings = detector.scan_resource(ResourceInfo(uri="https://user@{host}/x"))
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.HIGH


# --- robustness (regression: malformed authority must not crash the scan) ---


def test_resource_malformed_bracketed_authority_does_not_crash() -> None:
    detector = SsrfDetector()
    # Bracketed non-IP host raises ValueError in urlparse on Python 3.14+.
    assert detector.scan_resource(ResourceInfo(uri="https://[{host}]/x")) == []
