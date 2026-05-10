"""Calibration tests for prompt/resource capability and injection signals."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_audit.analyzer import PermissionAnalyzer
from mcp_audit.injection import InjectionDetector
from mcp_audit.models import Confidence, PromptInfo, ResourceInfo
from mcp_audit.scorer import RiskScorer

CASES_PATH = Path("tests/validation/non_tool_cases.json")
_CONFIDENCE_ORDER = ["low", "medium", "high", "declared", "llm"]


def test_non_tool_calibration_cases() -> None:
    analyzer = PermissionAnalyzer()
    detector = InjectionDetector()
    scorer = RiskScorer()
    cases = json.loads(CASES_PATH.read_text())

    for case in cases:
        prompts = [PromptInfo.model_validate(prompt) for prompt in case["prompts"]]
        resources = [ResourceInfo.model_validate(resource) for resource in case["resources"]]

        capabilities = analyzer.analyze_capabilities(prompts, resources)
        injections = detector.scan_server([], prompts, resources)
        non_tool_risk = scorer.score_non_tool(capabilities, injections)

        for expected in case["expected_capabilities"]:
            assert _has_capability(capabilities, expected), (
                f"{case['server_name']} missing capability {expected}"
            )

        for expected in case["expected_injections"]:
            assert _has_injection(injections, expected), f"{case['server_name']} missing injection {expected}"

        if case["expect_non_tool_risk"]:
            assert non_tool_risk is not None, f"{case['server_name']} expected non_tool_risk"
            assert non_tool_risk.composite > 0.0
        else:
            assert non_tool_risk is None, f"{case['server_name']} expected no non_tool_risk"


def _has_capability(findings: list[Any], expected: dict[str, str]) -> bool:
    return any(
        finding.target_type.value == expected["target_type"]
        and finding.target_name == expected["target_name"]
        and finding.category.value == expected["category"]
        and _confidence_meets_min(finding.confidence, expected["min_confidence"])
        for finding in findings
    )


def _has_injection(findings: list[Any], expected: dict[str, str]) -> bool:
    return any(
        finding.target_type.value == expected["target_type"]
        and finding.target_name == expected["target_name"]
        and finding.severity.value == expected["severity"]
        and finding.pattern_name == expected["pattern_name"]
        for finding in findings
    )


def _confidence_meets_min(actual: Confidence, minimum: str) -> bool:
    return _CONFIDENCE_ORDER.index(actual.value) >= _CONFIDENCE_ORDER.index(minimum)
