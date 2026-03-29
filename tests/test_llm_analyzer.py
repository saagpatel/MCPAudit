"""Tests for LLMAnalyzer — all API calls mocked."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from mcp_audit.llm_analyzer import LLMAnalyzer, _needs_llm
from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding
from tests.conftest import make_tool


def _finding(tool: str, cat: PermissionCategory, conf: Confidence = Confidence.HIGH) -> PermissionFinding:
    return PermissionFinding(category=cat, confidence=conf, evidence=["test"], tool_name=tool)


def _mock_analyzer() -> LLMAnalyzer:
    """Create LLMAnalyzer with mocked Anthropic client (no real API calls)."""
    with patch.dict("sys.modules", {"anthropic": MagicMock()}):
        analyzer = LLMAnalyzer.__new__(LLMAnalyzer)
        analyzer._model = "claude-haiku-4-5-20251001"  # type: ignore[attr-defined]
        analyzer._client = MagicMock()  # type: ignore[attr-defined]
    return analyzer


def _make_response(items: list[dict[str, object]]) -> MagicMock:
    """Build a mock Anthropic response returning the given items as JSON."""
    msg = MagicMock()
    msg.content = [MagicMock(text=json.dumps(items))]
    return msg


class TestNeedsLLM:
    def test_tool_with_no_findings_needs_llm(self) -> None:
        assert _needs_llm(make_tool("t"), []) is True

    def test_tool_with_low_confidence_needs_llm(self) -> None:
        finding = _finding("t", PermissionCategory.NETWORK, Confidence.LOW)
        assert _needs_llm(make_tool("t"), [finding]) is True

    def test_tool_with_high_confidence_skips_llm(self) -> None:
        finding = _finding("t", PermissionCategory.SHELL_EXEC, Confidence.HIGH)
        assert _needs_llm(make_tool("t"), [finding]) is False

    def test_tool_with_declared_confidence_skips_llm(self) -> None:
        finding = _finding("t", PermissionCategory.DESTRUCTIVE, Confidence.DECLARED)
        assert _needs_llm(make_tool("t"), [finding]) is False


class TestAnalyzeServer:
    async def test_skips_tools_with_high_confidence_findings(self) -> None:
        analyzer = _mock_analyzer()
        tools = [make_tool("exec_cmd")]
        existing = [_finding("exec_cmd", PermissionCategory.SHELL_EXEC, Confidence.HIGH)]
        result = await analyzer.analyze_server(tools, existing)
        # Should not call API — no candidates
        analyzer._client.messages.create.assert_not_called()  # type: ignore[attr-defined]
        assert result == []

    async def test_calls_api_for_low_confidence_tools(self) -> None:
        analyzer = _mock_analyzer()
        tools = [make_tool("mystery_tool", description="Does something unclear")]
        existing = [_finding("mystery_tool", PermissionCategory.FILE_READ, Confidence.LOW)]

        mock_resp = _make_response([{"tool": "mystery_tool", "categories": ["network"]}])
        analyzer._client.messages.create.return_value = mock_resp  # type: ignore[attr-defined]

        findings = await analyzer.analyze_server(tools, existing)
        analyzer._client.messages.create.assert_called_once()  # type: ignore[attr-defined]
        assert any(f.category == PermissionCategory.NETWORK for f in findings)

    async def test_returned_findings_have_llm_confidence(self) -> None:
        analyzer = _mock_analyzer()
        tools = [make_tool("ambiguous")]
        mock_resp = _make_response([{"tool": "ambiguous", "categories": ["file_write"]}])
        analyzer._client.messages.create.return_value = mock_resp  # type: ignore[attr-defined]

        findings = await analyzer.analyze_server(tools, [])
        assert all(f.confidence == Confidence.LLM for f in findings)

    async def test_api_error_returns_empty_no_exception(self) -> None:
        analyzer = _mock_analyzer()
        tools = [make_tool("t")]
        analyzer._client.messages.create.side_effect = RuntimeError("API down")  # type: ignore[attr-defined]

        findings = await analyzer.analyze_server(tools, [])
        assert findings == []

    async def test_empty_tool_list_no_api_call(self) -> None:
        analyzer = _mock_analyzer()
        await analyzer.analyze_server([], [])
        analyzer._client.messages.create.assert_not_called()  # type: ignore[attr-defined]

    async def test_batches_at_most_20_tools_per_call(self) -> None:
        analyzer = _mock_analyzer()
        tools = [make_tool(f"tool_{i}") for i in range(25)]
        mock_resp = _make_response([])
        analyzer._client.messages.create.return_value = mock_resp  # type: ignore[attr-defined]

        await analyzer.analyze_server(tools, [])
        # 25 tools → 2 batches (20 + 5)
        assert analyzer._client.messages.create.call_count == 2  # type: ignore[attr-defined]


class TestParseResponse:
    def test_unknown_category_silently_ignored(self) -> None:
        analyzer = _mock_analyzer()
        raw = json.dumps([{"tool": "t", "categories": ["file_read", "unknown_category"]}])
        findings = analyzer._parse_response(raw, {"t"})
        cats = {f.category for f in findings}
        assert PermissionCategory.FILE_READ in cats
        assert len(findings) == 1  # unknown_category dropped

    def test_unknown_tool_name_ignored(self) -> None:
        analyzer = _mock_analyzer()
        raw = json.dumps([{"tool": "ghost_tool", "categories": ["network"]}])
        findings = analyzer._parse_response(raw, {"real_tool"})
        assert findings == []
