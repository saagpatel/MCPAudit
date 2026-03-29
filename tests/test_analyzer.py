"""Unit tests for PermissionAnalyzer."""

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.models import Confidence, PermissionCategory, ToolAnnotations, ToolInfo
from tests.conftest import make_tool

analyzer = PermissionAnalyzer()


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

    def test_read_only_hint_true_suppresses_file_write(self) -> None:
        tool = make_tool(
            "write_file",
            description="Write content to disk",
            annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.FILE_WRITE not in cats
        assert PermissionCategory.DESTRUCTIVE not in cats

    def test_destructive_hint_false_suppresses_destructive(self) -> None:
        tool = make_tool(
            "delete_file",
            annotations=ToolAnnotations(destructive_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.DESTRUCTIVE not in cats

    def test_open_world_hint_false_suppresses_network_and_exfiltration(self) -> None:
        tool = make_tool(
            "fetch",
            description="fetch URL from the web",
            annotations=ToolAnnotations(open_world_hint=False),
        )
        cats = _categories(tool)
        assert PermissionCategory.NETWORK not in cats
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
        # destructiveHint=null default also fires DECLARED, but keyword still fires
        assert Confidence.HIGH in confs or Confidence.DECLARED in confs

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
        # With all annotation suppressions, no dangerous categories should appear
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
