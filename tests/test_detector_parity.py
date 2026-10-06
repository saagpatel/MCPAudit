"""Frozen pre-P1-9 category/confidence/evidence snapshots for synthetic surfaces."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from mcp.types import Prompt, Resource, Tool

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.connector import ServerConnector
from mcp_audit.models import PromptInfo, ResourceInfo, ToolInfo
from mcp_audit.ssrf import SsrfDetector
from tests.fixtures.evasion_server import prompts_for, resources_for, tools_for

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests/fixtures/detector_parity.json"


def surfaces() -> Iterator[tuple[str, list[ToolInfo], list[PromptInfo], list[ResourceInfo]]]:
    manifest = json.loads((ROOT / "examples/sandbox/fixtures/connected-tool-manifest.json").read_text())
    for name, surface in manifest["tool_sets"].items():
        yield (
            f"sandbox/{name}",
            [ToolInfo.model_validate(tool) for tool in surface["tools"]],
            [PromptInfo.model_validate(prompt) for prompt in surface["prompts"]],
            [ResourceInfo.model_validate(resource) for resource in surface["resources"]],
        )
    for path in sorted((ROOT / "examples").rglob("*.json")):
        payload = json.loads(path.read_text())
        if not isinstance(payload, dict):
            continue
        for index, audit in enumerate(payload.get("audits", [])):
            yield (
                f"{path.relative_to(ROOT)}/{index}",
                [ToolInfo.model_validate(tool) for tool in audit.get("tools", [])],
                [PromptInfo.model_validate(prompt) for prompt in audit.get("prompts", [])],
                [ResourceInfo.model_validate(resource) for resource in audit.get("resources", [])],
            )
    corpus = json.loads((ROOT / "tests/redteam/corpus.json").read_text())
    for case in corpus["cases"]:
        for stage in ("baseline", "current"):
            yield (
                f"corpus/{case['id']}/{stage}",
                [
                    ServerConnector._convert_tool(Tool.model_validate(tool))
                    for tool in tools_for(case["mode"], stage, 0, "mcp-audit", 0.0)
                ],
                [
                    ServerConnector._convert_prompt(Prompt.model_validate(p))
                    for p in prompts_for(case["mode"], 0)
                ],
                [
                    ServerConnector._convert_resource(Resource.model_validate(r))
                    for r in resources_for(case["mode"])
                ],
            )


def signature(
    analyzer: PermissionAnalyzer,
    ssrf: SsrfDetector,
    tools: list[ToolInfo],
    prompts: list[PromptInfo],
    resources: list[ResourceInfo],
) -> dict[str, object]:
    return {
        "permissions": [
            [f.tool_name, f.category.value, f.confidence.value, f.evidence]
            for f in analyzer.analyze_server(tools)
        ],
        "capabilities": [
            [f.target_type.value, f.target_name, f.category.value, f.confidence.value, f.evidence]
            for f in analyzer.analyze_capabilities(prompts, resources)
        ],
        "ssrf": [
            [f.target_type.value, f.target_name, f.severity.value, f.pattern_name, f.evidence]
            for f in ssrf.scan_server(tools, resources)
        ],
    }


def test_examples_and_redteam_detector_findings_match_pre_p1_9() -> None:
    expected = json.loads(GOLDEN.read_text())
    actual = {
        name: signature(PermissionAnalyzer(), SsrfDetector(), tools, prompts, resources)
        for name, tools, prompts, resources in surfaces()
    }
    assert actual == expected
