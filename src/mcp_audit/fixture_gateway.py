"""Fail-closed gateway used only by the synthetic enforcement fixture.

The fixture needs a deliberately small policy surface: exact allow, deny, and
per-call approval decisions plus deterministic audit readback. Keeping that
surface local avoids importing a production gateway runtime into a harness
that never launches or wraps a real MCP server.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

FIXTURE_GATEWAY_VERSION: Final = "1.0.0"


class ApprovalStatus(StrEnum):
    """Result returned by a fixture approval callback."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True)
class FixturePolicy:
    """Exact tool allow-list for the synthetic fixture."""

    name: str
    allowed_tools: tuple[str, ...]

    def __init__(self, *, name: str, allowed_tools: list[str]) -> None:
        if not name:
            raise ValueError("fixture policy name must not be empty")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "allowed_tools", tuple(allowed_tools))


@dataclass(frozen=True)
class GatewayConfig:
    """Normalized, non-authoritative configuration readback."""

    policy_name: str
    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    sensitive_tools: tuple[str, ...]
    rate_limit: int
    builtin_sanitization: bool


@dataclass(frozen=True)
class GatewayAuditEntry:
    """Minimal decision record; request parameters are intentionally omitted."""

    tool_name: str
    allowed: bool
    reason: str
    approval_status: ApprovalStatus | None = None


ApprovalCallback = Callable[[str, str, dict[str, Any]], ApprovalStatus]


class FixtureGateway:
    """Evaluate calls against the fixture's exact, default-deny policy."""

    def __init__(
        self,
        policy: FixturePolicy,
        *,
        denied_tools: list[str] | None = None,
        sensitive_tools: list[str] | None = None,
        approval_callback: ApprovalCallback | None = None,
        rate_limit: int = 100,
    ) -> None:
        if rate_limit < 1:
            raise ValueError("fixture gateway rate limit must be positive")
        self.policy = policy
        self.denied_tools = tuple(denied_tools or [])
        self.sensitive_tools = tuple(sensitive_tools or [])
        self.approval_callback = approval_callback
        self.rate_limit = rate_limit
        self.audit_log: list[GatewayAuditEntry] = []
        self._agent_call_counts: dict[str, int] = {}

    def configuration(self) -> GatewayConfig:
        """Return the exact policy surface used by this gateway instance."""
        return GatewayConfig(
            policy_name=self.policy.name,
            allowed_tools=self.policy.allowed_tools,
            denied_tools=self.denied_tools,
            sensitive_tools=self.sensitive_tools,
            rate_limit=self.rate_limit,
            builtin_sanitization=False,
        )

    def intercept_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[bool, str]:
        """Return a fail-closed decision and append parameter-free audit data."""
        approval: ApprovalStatus | None = None
        try:
            allowed, reason, approval = self._evaluate(agent_id, tool_name, params)
        except Exception:
            allowed = False
            reason = "Internal fixture gateway error - access denied (fail closed)"
            approval = None
        self.audit_log.append(
            GatewayAuditEntry(
                tool_name=tool_name,
                allowed=allowed,
                reason=reason,
                approval_status=approval,
            )
        )
        return allowed, reason

    def _evaluate(
        self,
        agent_id: str,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[bool, str, ApprovalStatus | None]:
        call_count = self._agent_call_counts.get(agent_id, 0)
        if call_count >= self.rate_limit:
            return False, "Fixture gateway rate limit exceeded", None
        self._agent_call_counts[agent_id] = call_count + 1

        if tool_name in self.denied_tools:
            return False, "Tool is explicitly denied", None
        if tool_name not in self.policy.allowed_tools:
            return False, "Tool is not present in the exact allow-list", None
        if tool_name not in self.sensitive_tools:
            return True, "Tool is explicitly allowed", None
        if self.approval_callback is None:
            return False, "Human approval required (pending)", ApprovalStatus.PENDING

        approval = self.approval_callback(agent_id, tool_name, params)
        if not isinstance(approval, ApprovalStatus):
            return False, "Invalid approval result - access denied (fail closed)", None
        if approval is ApprovalStatus.APPROVED:
            return True, "Human approval granted", approval
        if approval is ApprovalStatus.DENIED:
            return False, "Human approval denied", approval
        return False, "Human approval pending", approval
