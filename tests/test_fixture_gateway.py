from __future__ import annotations

from typing import Any

import pytest

from mcp_audit.fixture_gateway import ApprovalStatus, FixtureGateway, FixturePolicy


@pytest.fixture
def policy() -> FixturePolicy:
    return FixturePolicy(name="fixture-policy", allowed_tools=["read", "write", "blocked"])


def test_default_deny_and_explicit_deny_override(policy: FixturePolicy) -> None:
    gateway = FixtureGateway(policy, denied_tools=["blocked"])

    assert gateway.intercept_tool_call("agent", "read", {})[0]
    assert not gateway.intercept_tool_call("agent", "missing", {})[0]
    assert not gateway.intercept_tool_call("agent", "blocked", {})[0]


def test_sensitive_tool_requires_exact_approval(policy: FixturePolicy) -> None:
    pending = FixtureGateway(policy, sensitive_tools=["write"])
    approved = FixtureGateway(
        policy,
        sensitive_tools=["write"],
        approval_callback=lambda agent_id, tool_name, params: ApprovalStatus.APPROVED,
    )

    assert not pending.intercept_tool_call("agent", "write", {})[0]
    assert pending.audit_log[-1].approval_status is ApprovalStatus.PENDING
    assert approved.intercept_tool_call("agent", "write", {})[0]
    assert approved.audit_log[-1].approval_status is ApprovalStatus.APPROVED


@pytest.mark.parametrize(
    "callback",
    [
        lambda agent_id, tool_name, params: "approved",
        lambda agent_id, tool_name, params: (_ for _ in ()).throw(RuntimeError("boom")),
    ],
)
def test_invalid_or_failing_approval_callback_denies_without_parameters(
    policy: FixturePolicy,
    callback: Any,
) -> None:
    gateway = FixtureGateway(policy, sensitive_tools=["write"], approval_callback=callback)

    allowed, reason = gateway.intercept_tool_call(
        "agent",
        "write",
        {"secret": "must-not-enter-audit"},
    )

    assert not allowed
    assert "denied" in reason.lower()
    assert not hasattr(gateway.audit_log[-1], "parameters")


def test_rate_limit_fails_closed_and_is_truthful_in_readback(policy: FixturePolicy) -> None:
    gateway = FixtureGateway(policy, rate_limit=1)

    assert gateway.configuration().rate_limit == 1
    assert not gateway.configuration().builtin_sanitization
    assert gateway.intercept_tool_call("agent", "read", {})[0]
    allowed, reason = gateway.intercept_tool_call("agent", "read", {})
    assert not allowed
    assert "rate limit" in reason.lower()
