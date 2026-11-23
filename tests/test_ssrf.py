"""Tests for the SSRF (server-side request forgery) capability detector."""

from __future__ import annotations

import re
from time import perf_counter

from pytest import MonkeyPatch, mark

import mcp_audit.ssrf as ssrf_module
from mcp_audit.models import (
    CapabilityTarget,
    ResourceInfo,
    SsrfFinding,
    SsrfSeverity,
    ToolInfo,
)
from mcp_audit.normalize import render_invisibles
from mcp_audit.ssrf import (
    SsrfDetector,
    filter_allowlisted_ssrf,
    fixed_host_from_uri,
    host_in_allowlist,
    parse_host_allowlist,
    split_uri,
)
from mcp_audit.text_limits import MAX_FIELD_BYTES


def test_word_tokenizer_matches_previous_camel_and_acronym_semantics() -> None:
    camel_boundary = re.compile(r"([a-z0-9])([A-Z])")
    acronym_boundary = re.compile(r"([A-Z]+)([A-Z][a-z])")
    word_re = re.compile(r"[a-z0-9]+")
    samples = (
        "callbackUrl",
        "targetURL",
        "XMLHttpRequest2URL",
        "fooBARBaz",
        "HTTPServer",
        "IPv6Address",
        "get_http_status",
        "punctuation://callback-URL_v2",
        "AAbc ABCd ABc",
        "déjàVu",
    )

    # Raw-text tokens keep the previous semantics; normalized-only tokens follow them.
    for sample in samples:
        previous = acronym_boundary.sub(r"\1_\2", camel_boundary.sub(r"\1_\2", sample))
        expected = word_re.findall(previous.lower())
        assert ssrf_module._word_tokens(sample)[: len(expected)] == expected
    assert ssrf_module._word_tokens("déjàVu") == ["d", "j", "vu", "deja"]
    assert ssrf_module._word_tokens("target_url") == ["target", "url"]


@mark.parametrize(
    "key",
    [
        "u\u200brl",  # zero-width space
        "ur\u200cl",  # zero-width non-joiner
        "u\u200drl",  # zero-width joiner
        "u\u2060rl",  # word joiner
        "u\ufeffrl",  # BOM
        "u\u00adrl",  # soft hyphen
        "u\U000e0072rl",  # tag character
        "ｕｒｌ",  # fullwidth
        "callback\u200bUrl",
        "web\u200bhook",
    ],
    ids=repr,
)
def test_invisible_or_compatibility_characters_do_not_hide_url_param(key: str) -> None:
    tool = _tool("fetch_page", "Fetch the page.", {key: {"type": "string"}})
    findings = SsrfDetector().scan_tool(tool)
    assert [f.pattern_name for f in findings] == ["url_param_with_fetch_verb"]
    assert findings[0].severity is SsrfSeverity.HIGH
    # Evidence names the raw key, with invisible codepoints made visible.
    assert any(render_invisibles(key) in evidence for evidence in findings[0].evidence)


@mark.parametrize(
    "key,pattern",
    [
        ("target\u200burl", "url_param_with_fetch_verb"),
        ("callback\u2060endpoint", "url_param_with_fetch_verb"),
        ("target\u200bhost", "host_param_with_fetch_verb"),
    ],
    ids=repr,
)
def test_invisible_character_between_words_still_separates_them(key: str, pattern: str) -> None:
    # An invisible between two words is a word break, as before normalization was added.
    findings = SsrfDetector().scan_tool(_tool("fetch_one", "Fetch one.", {key: {"type": "string"}}))
    assert [f.pattern_name for f in findings] == [pattern]


@mark.parametrize(
    "key,pattern",
    [
        ("target\u200bｕｒｌ", "url_param_with_fetch_verb"),  # break plus fullwidth
        ("target\u200bu\u200brl", "url_param_with_fetch_verb"),  # one break, one hidden join
        ("ｔａｒｇｅｔ\u2060u\u200bｒｌ", "url_param_with_fetch_verb"),
        ("target\u200bｈｏｓｔ", "host_param_with_fetch_verb"),
        ("upstream\u200bh\u200bost", "host_param_with_fetch_verb"),
        ("target\u200bu\u200brlValue", "url_param_with_fetch_verb"),  # camelCase suffix
        ("u\u200brlForRedirectTargetValue", "url_param_with_fetch_verb"),  # long camelCase tail
        ("myW\u200bebhookHandler", "url_param_with_fetch_verb"),
    ],
    ids=repr,
)
def test_mixed_invisible_and_compatibility_forms_do_not_hide_params(key: str, pattern: str) -> None:
    findings = SsrfDetector().scan_tool(_tool("fetch_one", "Fetch one.", {key: {"type": "string"}}))
    assert [f.pattern_name for f in findings] == [pattern]


@mark.parametrize(
    "description",
    [
        "Please\u200bfеtch it.",
        "Please\u200bf\u200betch it.",
        "Ｐｌｅａｓｅ\u200bｆｅｔｃｈ",
        "Please\u200bf\u200betchsomething now.",  # fetch root before a long suffix
        "Auto\u200bdown\u200bloadsEverything",
    ],
    ids=repr,
)
def test_mixed_invisible_and_confusable_forms_do_not_hide_fetch_verb(description: str) -> None:
    findings = SsrfDetector().scan_tool(_tool("tool", description, {"url": {"type": "string"}}))
    assert [f.pattern_name for f in findings] == ["url_param_with_fetch_verb"]


def test_obfuscated_word_matches_vocabulary_by_substring() -> None:
    # Accepted cost of the substring rule: an invisible inside an identifier is adversarial,
    # so 'gho\u200bst' counts as a host parameter, while clean 'ghost' does not.
    obfuscated = SsrfDetector().scan_tool(_tool("ping_it", "Ping it.", {"gho\u200bst": {"type": "string"}}))
    clean = SsrfDetector().scan_tool(_tool("ping_it", "Ping it.", {"ghost": {"type": "string"}}))
    assert [f.pattern_name for f in obfuscated] == ["host_param_with_fetch_verb"] and clean == []


@mark.parametrize("chunk", ["x\u200b", "ab\u200b", "\u200b", "é\u200b"], ids=repr)
def test_invisible_heavy_description_scan_scales_linearly(chunk: str) -> None:
    def elapsed(size: int) -> float:
        tool = _tool("store_record", chunk * (size // len(chunk)), {"url": {"type": "string"}})
        started = perf_counter()
        SsrfDetector().scan_tool(tool)
        return perf_counter() - started

    # Scaling, not wall clock. Text past the 256 KiB field cap is not scanned.
    small, large = elapsed(16_384), elapsed(65_536)
    assert large < 10 * small + 0.05


def test_invisible_character_between_words_keeps_fetch_verb() -> None:
    findings = SsrfDetector().scan_tool(_tool("tool", "Please\u200bfetch it.", {"url": {"type": "string"}}))
    assert [f.pattern_name for f in findings] == ["url_param_with_fetch_verb"]


@mark.parametrize("key", ["ho\u200bst", "proxy\u2060", "ｈｏｓｔｎａｍｅ"], ids=repr)
def test_invisible_or_compatibility_characters_do_not_hide_host_param(key: str) -> None:
    findings = SsrfDetector().scan_tool(_tool("ping_target", "Ping the target.", {key: {"type": "string"}}))
    assert [f.pattern_name for f in findings] == ["host_param_with_fetch_verb"]


@mark.parametrize("name", ["f\u200betch_page", "f\u0435tch_page", "ｆｅｔｃｈ_page"], ids=repr)
def test_invisible_or_confusable_characters_do_not_hide_fetch_verb(name: str) -> None:
    findings = SsrfDetector().scan_tool(_tool(name, "Get.", {"url": {"type": "string"}}))
    assert [f.pattern_name for f in findings] == ["url_param_with_fetch_verb"]


@mark.parametrize("key", ["q\u200buery", "na\u200bme", "cou\u200bnt"], ids=repr)
def test_invisible_characters_in_benign_keys_stay_quiet(key: str) -> None:
    assert SsrfDetector().scan_tool(_tool("fetch_page", "Fetch the page.", {key: {"type": "string"}})) == []


def test_fetch_verb_is_limited_to_first_256_kibibytes_per_text() -> None:
    cap = MAX_FIELD_BYTES
    assert ssrf_module._has_fetch_verb("x" * (cap - len("fetch") - 1) + " fetch")
    assert not ssrf_module._has_fetch_verb("x" * cap + " fetch")


def test_fetch_verb_utf8_cap_does_not_split_or_overrun_multibyte_text() -> None:
    # The first 128 Ki characters consume the full UTF-8 budget.
    prefix = "é" * (MAX_FIELD_BYTES // 2)
    assert not ssrf_module._has_fetch_verb(prefix + "fetch")
    assert ssrf_module._has_fetch_verb("fetch" + prefix)


def test_megabyte_description_verb_scan_scales_linearly() -> None:
    # An uppercase run exercised the old acronym regex's quadratic failure.
    def scan(size: int) -> tuple[float, list[SsrfFinding]]:
        tool = _tool("store_record", "X" * size, {"url": {"type": "string"}})
        started = perf_counter()
        findings = SsrfDetector().scan_tool(tool)
        return perf_counter() - started, findings

    small_elapsed, _ = scan(256 * 1024)
    large_elapsed, findings = scan(1024 * 1024)
    assert large_elapsed < 10 * small_elapsed + 0.05
    assert len(findings) == 1
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert findings[0].pattern_name == "url_param"


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

    @mark.parametrize("name", ["github:fetch", "https://trusted.com/fetch"])
    def test_never_suppresses_tool_named_like_a_uri(self, name: str) -> None:
        # A tool's name does not constrain its destination, whatever URI it looks like.
        tool = _tool(name, "Fetch a URL.", {"url": {"type": "string"}})
        findings = SsrfDetector().scan_tool(tool)
        kept, dropped = filter_allowlisted_ssrf(findings, {"github.com", "trusted.com"})
        assert kept == findings and dropped == 0 and len(findings) == 1

    def test_suppresses_github_shorthand_resource(self) -> None:
        # github:owner/{repo} is a path template on github.com, like its https:// form.
        findings = [_ssrf("github:owner/{repo}")]
        kept, dropped = filter_allowlisted_ssrf(findings, {"github.com"})
        assert kept == [] and dropped == 1


@mark.parametrize(
    "uri,host",
    [
        ("github:owner/{repo}", "github.com"),
        ("github:{owner}/repo", "github.com"),
        ("GitHub:owner/repo", "github.com"),
        ("github://owner/repo", "owner"),  # authority form: the authority is the host, as before
        ("git:owner/{repo}", None),  # no implied host for other authority-less schemes
        ("s3:bucket/{key}", None),
        ("github:/owner/{repo}", "github.com"),
        # urlparse drops tab, CR and LF, so these have an authority: never the implied host.
        ("github:\n//{host}/repo", None),
        ("github:\r//{host}/repo", None),
        ("github:\t//evil.example/{repo}", None),
        ("github:\\\\{host}/repo", None),  # backslashes another parser may read as "//"
        ("github:owner//{repo}", None),
    ],
)
def test_fixed_host_resolves_github_shorthand(uri: str, host: str | None) -> None:
    assert fixed_host_from_uri(uri) == host


@mark.parametrize(
    "uri",
    [
        "github:\n//{host}/repo",
        "github:\r//{host}/repo",
        "github:\t//{host}/repo",
        "github:\t//evil.example/{repo}",
    ],
    ids=repr,
)
def test_github_allowlist_never_suppresses_a_control_hidden_authority(uri: str) -> None:
    findings = SsrfDetector().scan_resource(ResourceInfo(uri=uri, name="repo"))
    kept, dropped = filter_allowlisted_ssrf(findings, {"github.com"})
    assert findings and kept == findings and dropped == 0


def test_github_shorthand_template_stays_a_low_path_template() -> None:
    findings = SsrfDetector().scan_resource(ResourceInfo(uri="github:owner/{repo}", name="repo"))
    assert [(f.pattern_name, f.severity) for f in findings] == [
        ("remote_uri_path_template", SsrfSeverity.LOW)
    ]


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
    assert "host/address parameter 'targets[].hostname'" in findings[0].evidence


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


def test_unused_definition_does_not_manufacture_finding() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "$defs": {
                "UnusedRequest": {
                    "type": "object",
                    "properties": {"targetUrl": {"type": "string"}},
                }
            },
        },
    )

    assert detector.scan_tool(tool) == []


def test_referenced_definition_is_scanned_at_use_site() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="fetch_resource",
        description="Fetch a resource.",
        input_schema={
            "type": "object",
            "properties": {"request": {"$ref": "#/$defs/Request"}},
            "$defs": {
                "Request": {
                    "type": "object",
                    "properties": {"targetUrl": {"type": "string"}},
                }
            },
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert "URL-shaped parameter 'request.targetUrl'" in findings[0].evidence


def test_tuple_form_array_items_are_scanned_with_indexed_paths() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="fetch_resource",
        description="Fetch a resource.",
        input_schema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": [
                        {
                            "type": "object",
                            "properties": {"targetUrl": {"type": "string"}},
                        },
                        {"type": "string"},
                    ],
                }
            },
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert "URL-shaped parameter 'targets[0].targetUrl'" in findings[0].evidence


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
    input_schema = tool.input_schema
    assert isinstance(input_schema, dict)
    root_properties = input_schema["properties"]
    assert isinstance(root_properties, dict)
    request_schema = root_properties["request"]
    assert isinstance(request_schema, dict)
    request_properties = request_schema["properties"]
    assert isinstance(request_properties, dict)
    request_properties["self"] = request_schema

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert "URL-shaped parameter 'request.endpoint'" in findings[0].evidence


def test_recursive_local_ref_is_finite_and_preserves_use_site() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="fetch_resource",
        description="Fetch a resource.",
        input_schema={
            "type": "object",
            "properties": {"request": {"$ref": "#/$defs/Request"}},
            "$defs": {
                "Request": {
                    "type": "object",
                    "properties": {
                        "endpoint": {"type": "string"},
                        "child": {"$ref": "#/$defs/Request"},
                    },
                }
            },
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert "URL-shaped parameter 'request.endpoint'" in findings[0].evidence


def test_property_budget_exhaustion_is_visible_and_fail_closed(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssrf_module, "_MAX_SCHEMA_PROPERTIES", 1)
    detector = SsrfDetector()
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "targetUrl": {"type": "string"},
            },
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].pattern_name == "schema_traversal_incomplete"
    assert findings[0].severity is SsrfSeverity.MEDIUM
    assert "schema traversal incomplete: property budget exceeded (1)" in findings[0].evidence


def test_node_budget_exhaustion_is_visible_and_fail_closed(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssrf_module, "_MAX_SCHEMA_NODES", 1)
    detector = SsrfDetector()
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema={
            "type": "object",
            "properties": {
                "request": {
                    "type": "object",
                    "properties": {"targetUrl": {"type": "string"}},
                }
            },
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].pattern_name == "schema_traversal_incomplete"
    assert "schema traversal incomplete: node budget exceeded (1)" in findings[0].evidence


def test_depth_budget_exhaustion_is_visible_and_fail_closed(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(ssrf_module, "_MAX_SCHEMA_DEPTH", 2)
    detector = SsrfDetector()
    schema: dict[str, object] = {"type": "string"}
    for name in ("level3", "level2", "level1", "root"):
        schema = {
            "type": "object",
            "properties": {name: schema},
        }
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema=schema,
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].pattern_name == "schema_traversal_incomplete"
    assert "schema traversal incomplete: depth budget exceeded (2)" in findings[0].evidence


def test_unresolved_reference_is_visible_and_fail_closed() -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema={
            "type": "object",
            "properties": {"request": {"$ref": "#/$defs/Missing"}},
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].pattern_name == "schema_traversal_incomplete"
    assert (
        "schema traversal incomplete: unresolved or external reference: #/$defs/Missing"
        in findings[0].evidence
    )


@mark.parametrize(
    ("keyword", "reference"),
    [
        ("$dynamicRef", "#request"),
        ("$recursiveRef", "#"),
    ],
)
def test_dynamic_reference_semantics_are_visible_and_fail_closed(
    keyword: str,
    reference: str,
) -> None:
    detector = SsrfDetector()
    tool = ToolInfo(
        name="search",
        description="Search documents.",
        input_schema={
            "type": "object",
            "properties": {"request": {keyword: reference}},
        },
    )

    findings = detector.scan_tool(tool)

    assert len(findings) == 1
    assert findings[0].pattern_name == "schema_traversal_incomplete"
    assert (
        f"schema traversal incomplete: unsupported dynamic reference {keyword}: {reference}"
        in findings[0].evidence
    )


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
    # Bracketed non-IP host raises ValueError in urlparse on Python 3.14+; the
    # lenient split still sees the templated host, so the scan flags it.
    findings = detector.scan_resource(ResourceInfo(uri="https://[{host}]/x"))
    assert [(f.severity, f.pattern_name) for f in findings] == [
        (SsrfSeverity.HIGH, "remote_uri_host_template")
    ]
    # A malformed authority with no template is not an SSRF signal.
    assert detector.scan_resource(ResourceInfo(uri="http://[::1/x")) == []


def test_split_uri_matches_urlparse_and_survives_malformed_authorities() -> None:
    normal = split_uri("https://user@Example.com:8443/a/b?q=1#f")
    assert (normal.scheme, normal.netloc, normal.path, normal.query, normal.hostname) == (
        "https",
        "user@Example.com:8443",
        "/a/b",
        "q=1",
        "example.com",
    )
    for uri, hostname in (
        ("http://[{host}]/x", "{host}"),
        ("https://[{h}]:{p}/x", "{h}"),
        ("http://[::1/x", "::1"),
    ):
        parts = split_uri(uri)
        assert parts.scheme in {"http", "https"}
        assert parts.hostname == hostname
