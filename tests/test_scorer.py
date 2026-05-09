"""Unit tests for RiskScorer."""

from mcp_audit.models import (
    CapabilityFinding,
    CapabilityTarget,
    Confidence,
    InjectionFinding,
    InjectionSeverity,
    PermissionCategory,
    PermissionFinding,
)
from mcp_audit.rules.weights import CATEGORY_WEIGHTS, CONFIDENCE_MULTIPLIERS
from mcp_audit.scorer import RiskScorer

scorer = RiskScorer()


def finding(category: PermissionCategory, confidence: Confidence = Confidence.HIGH) -> PermissionFinding:
    return PermissionFinding(
        category=category,
        confidence=confidence,
        evidence=["test"],
        tool_name="test_tool",
    )


def capability(
    category: PermissionCategory,
    target_type: CapabilityTarget = CapabilityTarget.PROMPT,
    confidence: Confidence = Confidence.HIGH,
) -> CapabilityFinding:
    return CapabilityFinding(
        target_type=target_type,
        target_name="review_code" if target_type == CapabilityTarget.PROMPT else "file:///tmp/data.txt",
        category=category,
        confidence=confidence,
        evidence=["test"],
    )


def injection(
    target_type: CapabilityTarget = CapabilityTarget.PROMPT,
    severity: InjectionSeverity = InjectionSeverity.MEDIUM,
) -> InjectionFinding:
    return InjectionFinding(
        tool_name="target",
        target_type=target_type,
        target_name="target",
        severity=severity,
        pattern_name="role_injection",
        matched_text="assistant:",
        description="Target injects fake conversation turns.",
    )


class TestDimScore:
    def test_shell_exec_high_confidence(self) -> None:
        f = [finding(PermissionCategory.SHELL_EXEC, Confidence.HIGH)]
        score = scorer._dim_score(f, PermissionCategory.SHELL_EXEC)
        expected = CATEGORY_WEIGHTS[PermissionCategory.SHELL_EXEC] * CONFIDENCE_MULTIPLIERS[Confidence.HIGH]
        assert abs(score - expected) < 0.001

    def test_missing_category_returns_zero(self) -> None:
        assert scorer._dim_score([], PermissionCategory.SHELL_EXEC) == 0.0

    def test_takes_max_not_sum_for_same_category(self) -> None:
        findings = [
            finding(PermissionCategory.NETWORK, Confidence.LOW),
            finding(PermissionCategory.NETWORK, Confidence.HIGH),
        ]
        score = scorer._dim_score(findings, PermissionCategory.NETWORK)
        expected = CATEGORY_WEIGHTS[PermissionCategory.NETWORK] * CONFIDENCE_MULTIPLIERS[Confidence.HIGH]
        assert abs(score - expected) < 0.001

    def test_llm_confidence_scores_like_high(self) -> None:
        high_score = scorer._dim_score(
            [finding(PermissionCategory.EXFILTRATION, Confidence.HIGH)],
            PermissionCategory.EXFILTRATION,
        )
        llm_score = scorer._dim_score(
            [finding(PermissionCategory.EXFILTRATION, Confidence.LLM)],
            PermissionCategory.EXFILTRATION,
        )
        assert llm_score == high_score


class TestScoreServer:
    def test_no_findings_all_zeros(self) -> None:
        score = scorer.score_server([])
        assert score.composite == 0.0
        assert score.shell_execution == 0.0
        assert score.file_access == 0.0
        assert score.network_access == 0.0

    def test_shell_exec_high_composite_above_threshold(self) -> None:
        score = scorer.score_server([finding(PermissionCategory.SHELL_EXEC, Confidence.HIGH)])
        assert score.composite >= 2.5
        assert score.shell_execution >= 2.5

    def test_file_access_uses_max_of_read_and_write(self) -> None:
        findings = [
            finding(PermissionCategory.FILE_READ, Confidence.LOW),
            finding(PermissionCategory.FILE_WRITE, Confidence.HIGH),
        ]
        score = scorer.score_server(findings)
        w = CATEGORY_WEIGHTS[PermissionCategory.FILE_WRITE]
        write_score = w * CONFIDENCE_MULTIPLIERS[Confidence.HIGH]
        assert abs(score.file_access - write_score) < 0.001

    def test_read_only_server_low_composite(self) -> None:
        score = scorer.score_server([finding(PermissionCategory.FILE_READ, Confidence.MEDIUM)])
        assert score.composite <= 3.0

    def test_composite_capped_at_ten(self) -> None:
        all_findings = [finding(cat, Confidence.DECLARED) for cat in PermissionCategory]
        score = scorer.score_server(all_findings)
        assert score.composite <= 10.0

    def test_all_dimensions_capped_at_ten(self) -> None:
        # Add many findings for one category
        findings = [finding(PermissionCategory.SHELL_EXEC, Confidence.DECLARED)] * 100
        score = scorer.score_server(findings)
        assert score.shell_execution <= 10.0

    def test_declared_confidence_higher_than_low(self) -> None:
        low_score = scorer.score_server([finding(PermissionCategory.NETWORK, Confidence.LOW)])
        declared_score = scorer.score_server([finding(PermissionCategory.NETWORK, Confidence.DECLARED)])
        assert declared_score.network_access > low_score.network_access

    def test_exfiltration_contributes_to_composite_not_file_access(self) -> None:
        score = scorer.score_server([finding(PermissionCategory.EXFILTRATION, Confidence.HIGH)])
        assert score.exfiltration > 0.0
        assert score.file_access == 0.0

    def test_high_risk_server_composite_above_seven(self) -> None:
        """SHELL_EXEC + EXFILTRATION + FILE_WRITE = 3.0 + 2.5 + 2.0 = 7.5 → high-risk."""
        findings = [
            finding(PermissionCategory.SHELL_EXEC, Confidence.DECLARED),
            finding(PermissionCategory.EXFILTRATION, Confidence.DECLARED),
            finding(PermissionCategory.FILE_WRITE, Confidence.DECLARED),
        ]
        score = scorer.score_server(findings)
        assert score.composite >= 7.0


class TestScoreNonTool:
    def test_no_non_tool_findings_returns_none(self) -> None:
        assert scorer.score_non_tool([], []) is None

    def test_scores_capability_and_injection_without_changing_server_score(self) -> None:
        server_score = scorer.score_server([])
        non_tool_score = scorer.score_non_tool(
            [
                capability(PermissionCategory.FILE_READ, CapabilityTarget.PROMPT, Confidence.MEDIUM),
                capability(PermissionCategory.NETWORK, CapabilityTarget.RESOURCE, Confidence.HIGH),
            ],
            [injection(CapabilityTarget.PROMPT, InjectionSeverity.MEDIUM)],
        )

        assert server_score.composite == 0.0
        assert non_tool_score is not None
        assert abs(non_tool_score.capability_score - 1.95) < 0.001
        assert non_tool_score.injection_score == 4.0
        assert abs(non_tool_score.composite - 5.95) < 0.001
        assert non_tool_score.prompt_findings == 2
        assert non_tool_score.resource_findings == 1

    def test_ignores_tool_injection_for_non_tool_score(self) -> None:
        non_tool_score = scorer.score_non_tool([], [injection(CapabilityTarget.TOOL)])
        assert non_tool_score is None

    def test_counts_high_severity_findings(self) -> None:
        non_tool_score = scorer.score_non_tool(
            [capability(PermissionCategory.SHELL_EXEC, CapabilityTarget.PROMPT, Confidence.HIGH)],
            [injection(CapabilityTarget.RESOURCE, InjectionSeverity.HIGH)],
        )
        assert non_tool_score is not None
        assert non_tool_score.high_severity_findings == 2
