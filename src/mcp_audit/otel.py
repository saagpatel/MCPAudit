"""Opt-in, counts-only OpenTelemetry spans over the redacted report."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from mcp_audit.coverage import OPTIONAL_CHECKS
from mcp_audit.finding_display import finding_views
from mcp_audit.models import AuditReport
from mcp_audit.taxonomy import FINDING_COPY, config_health_rule_id

if TYPE_CHECKING:
    from opentelemetry.trace import Span, Tracer

_CHECKS = ("config_health", "permissions", "capabilities", "metadata", *OPTIONAL_CHECKS)
_CONFIG_RULES = {
    config_health_rule_id(kind)
    for kind in (
        "config_parse_failure",
        "duplicate_config_key",
        "malformed_server_entry",
        "duplicate_server_name",
        "conflicting_scope_server_name",
        "conflicting_server_definition",
        "missing_stdio_command",
        "missing_local_binary",
        "deprecated_sse_transport",
        "remote_endpoint",
        "remote_url_argument",
        "package_runner_source_review",
        "shell_wrapper_launch",
        "credential_heavy_config",
    )
}
_RULES = set(FINDING_COPY) | _CONFIG_RULES
_CONNECTION_STATES = {"connected", "partial", "failed", "timeout", "skipped"}


def _finding_events(span: Span, report: AuditReport) -> None:
    counts = Counter(view.rule_id if view.rule_id in _RULES else "unknown" for view in finding_views(report))
    span.set_attribute("mcp_audit.finding.count", sum(counts.values()))
    for rule_id, count in sorted(counts.items()):
        span.add_event("mcp_audit.finding", {"mcp_audit.rule.id": rule_id, "mcp_audit.finding.count": count})


def export_report(report: AuditReport, *, tracer: Tracer) -> None:
    """Emit report/server/check spans using a caller-configured tracer.

    Only a redacted copy is inspected. Names, endpoints, paths, environment
    keys, evidence and coverage reasons are never attributes or events. The
    caller owns the tracer's provider, resource, exporter and flush lifecycle.
    Check coverage is report-wide, not per-server execution evidence.
    """
    try:
        from opentelemetry.context import Context
        from opentelemetry.trace import set_span_in_context
    except ImportError as exc:
        raise RuntimeError("OpenTelemetry export requires mcp-audits[otel]") from exc

    redacted = report.redacted()
    # A fresh context excludes ambient trace state and baggage. Span names and
    # text attributes are fixed vocabulary; even dynamic report keys stay local.
    with tracer.start_span(
        "mcp_audit.report", context=Context(), record_exception=False, set_status_on_exception=False
    ) as root:
        context = set_span_in_context(root, Context())
        root.set_attribute("mcp_audit.server.count", len(redacted.audits))
        fleet = redacted.model_copy(update={"audits": []})
        _finding_events(root, fleet)
        for index, audit in enumerate(redacted.audits, start=1):
            with tracer.start_span(
                "mcp_audit.server", context=context, record_exception=False, set_status_on_exception=False
            ) as server:
                server.set_attribute("mcp_audit.server.index", index)
                state = audit.connection_status
                server.set_attribute(
                    "mcp_audit.connection.state", state if state in _CONNECTION_STATES else "unknown"
                )
                server.set_attribute("mcp_audit.tool.count", len(audit.tools))
                local = redacted.model_copy(
                    update={
                        "audits": [audit],
                        "config_health_findings": [],
                        "fleet_trifecta_findings": [],
                        "shadowing_findings": [],
                        "policy_result": None,
                    }
                )
                _finding_events(server, local)
        checks = dict.fromkeys((*_CHECKS, *redacted.coverage))
        for name in checks:
            coverage = redacted.coverage.get(name)
            with tracer.start_span(
                "mcp_audit.check", context=context, record_exception=False, set_status_on_exception=False
            ) as check:
                check.set_attribute("mcp_audit.check.name", name if name in _CHECKS else "unknown")
                check.set_attribute("mcp_audit.coverage.state", coverage.state if coverage else "unknown")
