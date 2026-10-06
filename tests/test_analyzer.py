"""Unit tests for PermissionAnalyzer."""

import re
from time import perf_counter

import pytest

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import (
    Confidence,
    PermissionCategory,
    PromptInfo,
    ResourceInfo,
    ToolAnnotations,
    ToolInfo,
)
from mcp_audit.rules.patterns import PERMISSION_PATTERNS
from mcp_audit.text_limits import MAX_FIELD_BYTES, bounded_text
from tests.conftest import make_tool

analyzer = PermissionAnalyzer()


@pytest.mark.parametrize("paths", [None, ["/name", "/description", "/input_schema/title"]])
def test_category_matcher_preserves_all_overlapping_pattern_scores_and_evidence(
    paths: list[str] | None,
) -> None:
    # Reference the old independent searches, including multiple strengths,
    # repeated occurrences and overlaps at the same or different offsets.
    patterns = [
        p for strengths in PERMISSION_PATTERNS.values() for group in strengths.values() for p in group
    ]
    samples = [*patterns, "_".join(patterns), " read_file read_file working_directory shutdown "]
    strengths_scores = {"strong": 3, "moderate": 2, "weak": 1}
    for text in samples:
        sources = [(text, 3), (text, 2), ("portfolio terms evaluation", 1)]
        expected: dict[PermissionCategory, tuple[int, list[str], list[str]]] = {}
        for category, strengths in PERMISSION_PATTERNS.items():
            score = 0
            evidence: list[str] = []
            matched_paths: list[str] = []
            for strength, group in strengths.items():
                for pattern in group:
                    for index, (source, weight) in enumerate(sources):
                        if re.search(rf"(?<![a-z]){re.escape(pattern)}(?![a-z])", source):
                            score += strengths_scores[strength] * weight
                            if pattern not in evidence:
                                evidence.append(pattern)
                            if paths is not None and paths[index] not in matched_paths:
                                matched_paths.append(paths[index])
            expected[category] = (score, evidence, matched_paths)
        assert analyzer._score_keywords(sources, paths) == expected, text


def test_five_megabyte_description_analysis_stays_under_one_second() -> None:
    tool = make_tool("status", description="read_file " + "x" * 5_000_000)
    started = perf_counter()
    findings = analyzer.analyze_tool_keywords(tool)
    elapsed = perf_counter() - started
    assert elapsed < 1.0
    assert next(f for f in findings if f.category == PermissionCategory.FILE_READ).evidence == [
        "read_file",
        "read",
    ]


def test_keyword_fields_are_capped_independently_at_256_kibibytes() -> None:
    tool = make_tool(
        "x" * MAX_FIELD_BYTES + " read_file",
        description="y" * MAX_FIELD_BYTES + " delete_file",
        input_schema={"properties": {"z" * MAX_FIELD_BYTES + " shell": {"type": "string"}}},
    )
    assert analyzer.analyze_tool_keywords(tool) == []
    tool.description = "read_file " + "x" * MAX_FIELD_BYTES
    assert {f.category for f in analyzer.analyze_tool_keywords(tool)} == {PermissionCategory.FILE_READ}


def test_bounded_text_caps_utf8_bytes_without_splitting_characters() -> None:
    for character in ("x", "é", "€", "😀"):
        width = len(character.encode("utf-8"))
        text = character * (MAX_FIELD_BYTES // width + 1)
        prefix = bounded_text(text)
        assert len(prefix.encode("utf-8")) <= MAX_FIELD_BYTES
        assert text.startswith(prefix)
        assert 0 < len(text) - len(prefix) <= 1


def test_bounded_text_preserves_surrogates_in_untrusted_input() -> None:
    prefix = "x" * (MAX_FIELD_BYTES - 3) + "\ud800"
    assert bounded_text(prefix + "suffix") == prefix


def _categories(tool: ToolInfo) -> set[PermissionCategory]:
    return {f.category for f in analyzer.analyze_tool(tool)}


def _confidences(tool: ToolInfo, category: PermissionCategory) -> set[Confidence]:
    return {f.confidence for f in analyzer.analyze_tool(tool) if f.category == category}


# ---------------------------------------------------------------------------
# Annotation-based findings
# ---------------------------------------------------------------------------


class TestAnnotationFindings:
    def test_read_only_hint_true_yields_file_read_declared(self) -> None:
        tool = make_tool("mytool", annotations=ToolAnnotations(read_only_hint=True))
        findings = analyzer.analyze_tool(tool)
        cats = {f.category for f in findings}
        confs = {f.confidence for f in findings if f.category == PermissionCategory.FILE_READ}
        assert PermissionCategory.FILE_READ in cats
        assert Confidence.DECLARED in confs

    def test_read_only_hint_true_with_destructive_hint_unset_suppresses_destructive(self) -> None:
        # Per the MCP spec, destructiveHint is meaningful only when
        # readOnlyHint is false; the null-defaults-to-true rule must not
        # override an explicit read-only declaration.
        tool = make_tool("list_files", annotations=ToolAnnotations(read_only_hint=True))
        cats = _categories(tool)
        assert PermissionCategory.DESTRUCTIVE not in cats

    def test_read_only_hint_true_preserves_file_write_evidence(self) -> None:
        tool = make_tool(
            "write_file",
            description="Write content to disk",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.FILE_WRITE in cats
        assert PermissionCategory.DESTRUCTIVE not in cats

    def test_destructive_hint_false_preserves_destructive_evidence(self) -> None:
        tool = make_tool(
            "delete_file",
            annotations=ToolAnnotations(destructive_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.DESTRUCTIVE in cats

    def test_open_world_hint_false_preserves_network_evidence(self) -> None:
        tool = make_tool(
            "fetch",
            description="fetch URL from the web",
            annotations=ToolAnnotations(open_world_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.NETWORK in cats
        assert PermissionCategory.EXFILTRATION not in cats

    def test_destructive_hint_none_defaults_to_declared_destructive(self) -> None:
        """MCP spec: destructiveHint=null means true."""
        tool = make_tool("some_tool", annotations=ToolAnnotations())
        cats = _categories(tool)
        confs = _confidences(tool, PermissionCategory.DESTRUCTIVE)
        assert PermissionCategory.DESTRUCTIVE in cats
        assert Confidence.DECLARED in confs

    def test_open_world_hint_none_defaults_to_declared_network(self) -> None:
        """MCP spec: openWorldHint=null means true."""
        tool = make_tool("some_tool", annotations=ToolAnnotations())
        cats = _categories(tool)
        assert PermissionCategory.NETWORK in cats

    def test_no_annotations_produces_spec_defaults(self) -> None:
        """No annotations → destructiveHint=true + openWorldHint=true by spec."""
        tool = make_tool("plain_tool")
        cats = _categories(tool)
        assert PermissionCategory.DESTRUCTIVE in cats
        assert PermissionCategory.NETWORK in cats

    def test_annotation_wins_over_keyword(self) -> None:
        """If annotation covers a category, keyword finding for that category is skipped."""
        tool = make_tool(
            "fetch_url",
            description="fetch URL from the web — network tool",
            annotations=ToolAnnotations(open_world_hint=True),
        )
        findings = analyzer.analyze_tool(tool)
        network_findings = [f for f in findings if f.category == PermissionCategory.NETWORK]
        # Only one finding for NETWORK (annotation wins, no duplicate from keywords)
        assert len(network_findings) == 1
        assert network_findings[0].confidence == Confidence.DECLARED


# ---------------------------------------------------------------------------
# Keyword-based findings
# ---------------------------------------------------------------------------


class TestKeywordFindings:
    def test_execute_command_yields_shell_exec_high(self) -> None:
        tool = make_tool("execute_command", description="Run a shell command")
        cats = _categories(tool)
        confs = _confidences(tool, PermissionCategory.SHELL_EXEC)
        assert PermissionCategory.SHELL_EXEC in cats
        assert Confidence.HIGH in confs

    def test_delete_file_name_yields_destructive_high(self) -> None:
        tool = make_tool("delete_file")
        confs = _confidences(tool, PermissionCategory.DESTRUCTIVE)
        assert confs == {Confidence.DECLARED}

    def test_send_email_yields_exfiltration_high(self) -> None:
        tool = make_tool("send_email", description="Send an email message to a recipient")
        cats = _categories(tool)
        assert PermissionCategory.EXFILTRATION in cats

    def test_description_fetch_url_yields_network(self) -> None:
        tool = make_tool("request", description="fetches a URL from the internet")
        cats = _categories(tool)
        assert PermissionCategory.NETWORK in cats

    def test_param_name_file_path_yields_file_read(self) -> None:
        # Tool name "get_data" doesn't match file patterns; only the param "filepath" does.
        tool = make_tool(
            "get_data",
            input_schema={"type": "object", "properties": {"filepath": {"type": "string"}}},
            annotations=ToolAnnotations(destructive_hint=False, open_world_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.FILE_READ in cats

    def test_sequential_thinking_yields_no_keyword_findings(self) -> None:
        """'think' / reasoning tools should not match file/network/shell patterns."""
        tool = make_tool(
            "think",
            description="Think through a problem step by step using sequential reasoning",
            annotations=ToolAnnotations(
                read_only_hint=True,
                destructive_hint=False,
                open_world_hint=False,
            ),
        )
        cats = _categories(tool)
        # Honest hints have no dangerous keyword evidence to contradict them.
        assert PermissionCategory.SHELL_EXEC not in cats
        assert PermissionCategory.FILE_WRITE not in cats
        assert PermissionCategory.DESTRUCTIVE not in cats
        assert PermissionCategory.NETWORK not in cats

    def test_write_file_name_yields_file_write(self) -> None:
        tool = make_tool("write_file", description="Write content to a file")
        cats = _categories(tool)
        assert PermissionCategory.FILE_WRITE in cats


# ---------------------------------------------------------------------------
# analyze_server aggregation
# ---------------------------------------------------------------------------


class TestAnalyzeServer:
    def test_aggregates_across_tools(self) -> None:
        tools = [
            make_tool("read_file", annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False)),
            make_tool("execute_command"),
        ]
        findings = analyzer.analyze_server(tools)
        cats = {f.category for f in findings}
        assert PermissionCategory.FILE_READ in cats
        assert PermissionCategory.SHELL_EXEC in cats

    def test_empty_tool_list_returns_empty(self) -> None:
        assert analyzer.analyze_server([]) == []

    def test_evidence_list_not_empty_for_keyword_match(self) -> None:
        tool = make_tool("execute_command", description="Run shell commands")
        findings = analyzer.analyze_tool(tool)
        shell_findings = [f for f in findings if f.category == PermissionCategory.SHELL_EXEC]
        assert shell_findings
        assert shell_findings[0].evidence


class TestAnalyzeCapabilities:
    def test_prompt_argument_command_yields_shell_execution(self) -> None:
        prompt = PromptInfo(name="run_template", description="Prepare a command", arguments=["command"])
        findings = analyzer.analyze_capabilities([prompt], [])
        shell = [f for f in findings if f.category == PermissionCategory.SHELL_EXEC]
        assert shell
        assert shell[0].target_type == "prompt"
        assert shell[0].target_name == "run_template"

    def test_file_resource_uri_yields_file_read(self) -> None:
        resource = ResourceInfo(uri="file:///Users/example/secrets.txt", name="secrets")
        findings = analyzer.analyze_capabilities([], [resource])
        file_read = [f for f in findings if f.category == PermissionCategory.FILE_READ]
        assert file_read
        assert "resource URI scheme 'file'" in file_read[0].evidence

    def test_https_resource_uri_yields_network(self) -> None:
        resource = ResourceInfo(uri="https://example.com/data.json", name="remote-data")
        findings = analyzer.analyze_capabilities([], [resource])
        network = [f for f in findings if f.category == PermissionCategory.NETWORK]
        assert network
        assert network[0].target_type == "resource"
        assert "resource host 'example.com'" in network[0].evidence

    def test_cloud_resource_uri_yields_network(self) -> None:
        resource = ResourceInfo(uri="s3://audit-bucket/{tenant}/events.json", name="tenant events")
        findings = analyzer.analyze_capabilities([], [resource])
        network = [f for f in findings if f.category == PermissionCategory.NETWORK]
        assert network
        assert network[0].confidence == Confidence.HIGH
        assert "resource URI scheme 's3'" in network[0].evidence

    def test_templated_resource_uri_yields_network_review_signal(self) -> None:
        resource = ResourceInfo(uri="mcp://dataset/{tenant}/records", name="templated-records")
        findings = analyzer.analyze_capabilities([], [resource])
        network = [f for f in findings if f.category == PermissionCategory.NETWORK]
        assert network
        assert "resource URI contains template variables" in network[0].evidence

    def test_prompt_endpoint_argument_yields_network(self) -> None:
        prompt = PromptInfo(
            name="call_remote_api",
            description="Prepare an API request plan.",
            arguments=["endpoint", "headers"],
        )
        findings = analyzer.analyze_capabilities([prompt], [])
        network = [f for f in findings if f.category == PermissionCategory.NETWORK]
        assert network
        assert network[0].target_type == "prompt"

    def test_benign_prompt_and_resource_have_no_capability_findings(self) -> None:
        prompt = PromptInfo(name="summarize", description="Summarize selected text.", arguments=["topic"])
        resource = ResourceInfo(uri="memo://daily-note", name="daily note", description="Local memo text")
        findings = analyzer.analyze_capabilities([prompt], [resource])
        assert findings == []


class TestKeywordWordBoundary:
    """Capability keyword patterns are identifier tokens, not substrings: a pattern
    like 'port' or 'rm' must not match inside a larger word such as 'portfolio' or
    'terms'. Regression for content-resource false positives (a safe read-only
    server serving prose got flagged network/destructive/shell on word fragments)."""

    def test_substrings_in_resource_text_yield_no_capabilities(self) -> None:
        # 'port'/'import' in 'important', 'rm' in 'terms'/'performance',
        # 'eval' in 'evaluation' -- substrings of ordinary words, never tokens.
        resource = ResourceInfo(
            uri="memo://important-terms",
            name="On terms and performance",
            description="A careful evaluation of tradeoffs.",
        )
        findings = analyzer.analyze_capabilities([], [resource])
        cats = {f.category for f in findings}
        assert PermissionCategory.NETWORK not in cats
        assert PermissionCategory.DESTRUCTIVE not in cats
        assert PermissionCategory.SHELL_EXEC not in cats
        assert PermissionCategory.FILE_READ not in cats

    def test_substrings_in_prompt_text_yield_no_network(self) -> None:
        # 'port' in 'report' used to create a bogus network signal.
        prompt = PromptInfo(
            name="write_report",
            description="Create a report at the requested output path.",
            arguments=["output_path", "content"],
        )
        findings = analyzer.analyze_capabilities([prompt], [])
        cats = {f.category for f in findings}
        assert PermissionCategory.NETWORK not in cats
        assert PermissionCategory.FILE_WRITE in cats

    def test_real_token_tool_still_detected(self) -> None:
        # The word-boundary fix must not weaken genuine token detection.
        assert PermissionCategory.FILE_READ in _categories(make_tool("read_file"))
        assert PermissionCategory.DESTRUCTIVE in _categories(make_tool("rm", description="remove items"))

    def test_camel_case_tool_tokens_still_detected(self) -> None:
        assert PermissionCategory.FILE_READ in _categories(make_tool("readFile"))
        assert PermissionCategory.SHELL_EXEC in _categories(make_tool("executeCommand"))
        assert PermissionCategory.EXFILTRATION in _categories(make_tool("sendEmail"))
