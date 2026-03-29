"""LLM-based permission analysis — optional augmentation using Anthropic API."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from mcp_audit.models import Confidence, PermissionCategory, PermissionFinding, ToolInfo

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "claude-haiku-4-5-20251001"
_BATCH_SIZE = 20
_VALID_CATEGORIES = {c.value for c in PermissionCategory}

# Confidences that mean we already have a reliable signal — skip LLM for these tools
_SKIP_CONFIDENCES = {Confidence.DECLARED, Confidence.HIGH, Confidence.MEDIUM}


def _needs_llm(tool: ToolInfo, existing: list[PermissionFinding]) -> bool:
    """Return True if tool has no findings or only LOW-confidence findings."""
    tool_findings = [f for f in existing if f.tool_name == tool.name]
    if not tool_findings:
        return True
    return all(f.confidence == Confidence.LOW for f in tool_findings)


def _build_prompt(tools: list[ToolInfo]) -> str:
    lines: list[str] = []
    for t in tools:
        params: list[str] = []
        if t.input_schema:
            props = t.input_schema.get("properties", {})
            if isinstance(props, dict):
                params = list(props.keys())
        param_str = ", ".join(params) if params else "none"
        desc = t.description or "(no description)"
        lines.append(f"{t.name}: {desc} | params: {param_str}")

    tool_block = "\n".join(lines)
    return f"""You are a security analyzer for MCP (Model Context Protocol) tools.

For each tool below, determine which permission categories apply based on the tool name,
description, and parameter names. Return ONLY a JSON array.

Permission categories: file_read, file_write, network, shell_execution, destructive, exfiltration

Tools:
{tool_block}

Respond with:
[{{"tool": "<name>", "categories": ["<cat>", ...]}}, ...]
Return [] categories if no permissions apply. No explanation, no markdown, only the JSON array."""


class LLMAnalyzer:
    """Augments keyword-based analysis with LLM classification for ambiguous tools."""

    def __init__(self, api_key: str, model: str = _DEFAULT_MODEL) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError("anthropic package not installed. Run: pip install 'mcp-audit[llm]'") from exc
        self._client: Any = anthropic.Anthropic(api_key=api_key)
        self._model = model

    async def analyze_server(
        self,
        tools: list[ToolInfo],
        existing_findings: list[PermissionFinding],
    ) -> list[PermissionFinding]:
        """Return LLM-classified findings for tools with LOW/no confidence.

        Only calls the API for tools that don't already have DECLARED, HIGH, or MEDIUM findings.
        New findings are merged with (not replacing) existing ones.
        """
        candidate_tools = [t for t in tools if _needs_llm(t, existing_findings)]
        if not candidate_tools:
            return []

        new_findings: list[PermissionFinding] = []
        for i in range(0, len(candidate_tools), _BATCH_SIZE):
            batch = candidate_tools[i : i + _BATCH_SIZE]
            batch_findings = await self._classify_batch(batch)
            new_findings.extend(batch_findings)

        return new_findings

    async def _classify_batch(self, tools: list[ToolInfo]) -> list[PermissionFinding]:
        """Call the LLM for a batch of tools and parse the response."""
        prompt = _build_prompt(tools)
        tool_names = {t.name for t in tools}

        try:
            # Use sync client in async context — acceptable for CLI use
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_text: str = response.content[0].text
        except Exception as exc:
            logger.warning("LLM analysis failed for batch: %s", exc)
            return []

        return self._parse_response(raw_text, tool_names)

    def _parse_response(self, raw_text: str, valid_tool_names: set[str]) -> list[PermissionFinding]:
        """Parse LLM JSON response into PermissionFindings."""
        try:
            parsed: Any = json.loads(raw_text.strip())
        except json.JSONDecodeError:
            # Try to extract JSON array from response
            start = raw_text.find("[")
            end = raw_text.rfind("]")
            if start == -1 or end == -1:
                logger.warning("LLM response could not be parsed as JSON")
                return []
            try:
                parsed = json.loads(raw_text[start : end + 1])
            except json.JSONDecodeError:
                logger.warning("LLM response JSON extraction failed")
                return []

        if not isinstance(parsed, list):
            logger.warning("LLM response is not a JSON array")
            return []

        findings: list[PermissionFinding] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            tool_name = item.get("tool", "")
            categories = item.get("categories", [])
            if not isinstance(tool_name, str) or tool_name not in valid_tool_names:
                continue
            if not isinstance(categories, list):
                continue
            for cat_str in categories:
                if not isinstance(cat_str, str) or cat_str not in _VALID_CATEGORIES:
                    continue  # silently ignore unknown categories
                try:
                    category = PermissionCategory(cat_str)
                except ValueError:
                    continue
                findings.append(
                    PermissionFinding(
                        category=category,
                        confidence=Confidence.LLM,
                        evidence=["llm: classified by language model"],
                        tool_name=tool_name,
                    )
                )

        return findings
