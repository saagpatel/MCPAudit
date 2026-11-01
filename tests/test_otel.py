"""Fixture-backed acceptance tests for the counts-only telemetry boundary."""

from __future__ import annotations

import builtins
import json
from collections.abc import Mapping, Sequence
from importlib.metadata import metadata
from pathlib import Path
from types import ModuleType

import pytest
from opentelemetry.context import Context, attach, detach, set_value
from opentelemetry.trace import (
    INVALID_SPAN_CONTEXT,
    Link,
    NonRecordingSpan,
    NoOpTracer,
    Span,
    SpanKind,
    get_current_span,
)
from opentelemetry.util.types import Attributes, AttributeValue
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from mcp_audit.models import (
    AuditReport,
    CheckCoverage,
    ConfigHealthFinding,
    ConfigHealthSeverity,
    CoverageState,
)
from mcp_audit.otel import export_report


class RecordingSpan(NonRecordingSpan):
    def __init__(self, name: str, context: Context | None) -> None:
        super().__init__(INVALID_SPAN_CONTEXT)
        self.name = name
        self.parent_context = context
        self.attributes: dict[str, AttributeValue] = {}
        self.events: list[tuple[str, dict[str, AttributeValue]]] = []
        self.ended = False

    def set_attribute(self, key: str, value: AttributeValue) -> None:
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Attributes = None, timestamp: int | None = None) -> None:
        self.events.append((name, dict(attributes or {})))

    def end(self, end_time: int | None = None) -> None:
        self.ended = True


class RecordingTracer(NoOpTracer):
    def __init__(self) -> None:
        self.spans: list[RecordingSpan] = []

    def start_span(
        self,
        name: str,
        context: Context | None = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Attributes = None,
        links: Sequence[Link] | None = None,
        start_time: int | None = None,
        record_exception: bool = True,
        set_status_on_exception: bool = True,
    ) -> Span:
        assert not record_exception and not set_status_on_exception
        span = RecordingSpan(name, context)
        self.spans.append(span)
        return span


@pytest.fixture
def report(fixtures_dir: Path) -> AuditReport:
    return AuditReport.model_validate_json((fixtures_dir / "reports/sample_audit_report.json").read_text())


def _events(span: RecordingSpan) -> dict[str, int]:
    result: dict[str, int] = {}
    for name, attributes in span.events:
        assert name == "mcp_audit.finding"
        assert set(attributes) == {"mcp_audit.rule.id", "mcp_audit.finding.count"}
        rule, count = attributes["mcp_audit.rule.id"], attributes["mcp_audit.finding.count"]
        assert isinstance(rule, str) and isinstance(count, int)
        result[rule] = count
    return result


def test_otel_extra_declares_the_api_dependency() -> None:
    package = metadata("mcp-audits")
    assert "otel" in (package.get_all("Provides-Extra") or [])
    requirements = [Requirement(value) for value in package.get_all("Requires-Dist") or []]
    api = next(requirement for requirement in requirements if requirement.name == "opentelemetry-api")
    # 1.45.1 is the floor past the unbounded ``tracestate`` parsing advisory.
    assert api.specifier == SpecifierSet(">=1.45.1,<2")
    assert api.marker is not None
    assert api.marker.evaluate({"extra": "otel"})
    assert not api.marker.evaluate({"extra": ""})


def test_server_spans_and_rule_count_events(report: AuditReport) -> None:
    first = report.audits[0]
    first.permissions *= 2
    # Duplicate configured names still identify separate rows, without names on the wire.
    report.audits.append(first.model_copy(deep=True))
    tracer = RecordingTracer()
    export_report(report, tracer=tracer)
    root = tracer.spans[0]
    servers = [span for span in tracer.spans if span.name == "mcp_audit.server"]
    assert root.name == "mcp_audit.report" and root.parent_context == Context()
    assert root.attributes["mcp_audit.server.count"] == 2
    assert _events(root) == {"MCP010": 1}
    assert [span.attributes["mcp_audit.server.index"] for span in servers] == [1, 2]
    for span in servers:
        assert get_current_span(span.parent_context) is root
        assert span.attributes["mcp_audit.connection.state"] == "connected"
        assert span.attributes["mcp_audit.tool.count"] == len(first.tools)
        assert _events(span) == {"MCP001": 1, "MCP004": 2, "MCP009": 1}
        assert span.attributes["mcp_audit.finding.count"] == sum(_events(span).values())
    assert all(span.ended for span in tracer.spans)


def test_check_spans_preserve_coverage_and_do_not_infer_completion(report: AuditReport) -> None:
    states: tuple[tuple[str, CoverageState], ...] = (
        ("config_health", "complete"),
        ("permissions", "partial"),
        ("metadata", "not_run"),
        ("inject_check", "not_requested"),
    )
    report.coverage = {
        name: CheckCoverage(state=state, reason="fixture reason, not exported") for name, state in states
    }
    tracer = RecordingTracer()
    export_report(report, tracer=tracer)
    checks = [span for span in tracer.spans if span.name == "mcp_audit.check"]
    by_name = {span.attributes["mcp_audit.check.name"]: span for span in checks}
    for name, coverage in report.coverage.items():
        assert by_name[name].attributes["mcp_audit.coverage.state"] == coverage.state
    assert by_name["capabilities"].attributes["mcp_audit.coverage.state"] == "unknown"
    assert all(get_current_span(span.parent_context) is tracer.spans[0] for span in checks)


def test_export_reads_only_the_returned_redacted_report(
    report: AuditReport, monkeypatch: pytest.MonkeyPatch
) -> None:
    replacement = report.redacted()
    replacement.audits = []
    replacement.coverage = {"metadata": CheckCoverage(state="not_run", reason="fixture")}
    calls: list[AuditReport] = []

    def redacted(self: AuditReport, *, identifiers: bool = False) -> AuditReport:
        calls.append(self)
        return replacement

    monkeypatch.setattr(AuditReport, "redacted", redacted)
    tracer = RecordingTracer()
    export_report(report, tracer=tracer)
    assert calls == [report]
    assert tracer.spans[0].attributes["mcp_audit.server.count"] == 0
    assert not any(span.name == "mcp_audit.server" for span in tracer.spans)


def test_no_hostnames_identifiers_unredacted_payloads_or_ambient_context(report: AuditReport) -> None:
    marker = "fixture-private-identifier.example.test"
    report.hostname = marker
    audit = report.audits[0]
    audit.server.name = marker
    audit.server.url = f"https://{marker}/mcp?token=fixture-credential"
    audit.server.args = ["--password", "fixture-credential"]
    audit.server.env_keys = ["FIXTURE_TOKEN"]
    audit.connection_status = marker
    audit.tools[0].input_schema = {"properties": {"password": {"default": "fixture-credential"}}}
    audit.permissions[0].evidence = [marker, "password=fixture-credential"]
    report.coverage[marker] = CheckCoverage(state="partial", reason=marker)
    report.config_health_findings = [
        ConfigHealthFinding(
            finding_type=marker,
            severity=ConfigHealthSeverity.HIGH,
            summary=marker,
            remediation=marker,
        )
    ]
    before = report.model_dump_json()
    tracer = RecordingTracer()
    token = attach(set_value("fixture-baggage", marker))
    try:
        export_report(report, tracer=tracer)
    finally:
        detach(token)
    payload = json.dumps([(span.name, span.attributes, span.events) for span in tracer.spans])
    assert marker not in payload
    assert "fixture-credential" not in payload
    assert "FIXTURE_TOKEN" not in payload
    assert "password" not in payload and "input_schema" not in payload
    assert all("fixture-baggage" not in (span.parent_context or {}) for span in tracer.spans)
    assert _events(tracer.spans[0]) == {"MCP010": 1, "unknown": 1}
    assert any(
        span.attributes.get("mcp_audit.check.name") == "unknown"
        and span.attributes.get("mcp_audit.coverage.state") == "partial"
        for span in tracer.spans
    )
    assert (
        next(span for span in tracer.spans if span.name == "mcp_audit.server").attributes[
            "mcp_audit.connection.state"
        ]
        == "unknown"
    )
    assert report.model_dump_json() == before


def test_static_fixture_and_fleet_findings_have_no_server_attribution(fixtures_dir: Path) -> None:
    report = AuditReport.model_validate_json((fixtures_dir / "reports/config_only_report.json").read_text())
    tracer = RecordingTracer()
    export_report(report, tracer=tracer)
    assert _events(tracer.spans[0]) == {"MCP-CH-REMOTE-ENDPOINT": 1}
    servers = [span for span in tracer.spans if span.name == "mcp_audit.server"]
    assert all(span.attributes["mcp_audit.connection.state"] == "skipped" for span in servers)


def test_optional_dependency_error_is_explicit(report: AuditReport, monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def import_without_otel(
        name: str,
        globals: Mapping[str, object] | None = None,
        locals: Mapping[str, object] | None = None,
        fromlist: Sequence[str] = (),
        level: int = 0,
    ) -> ModuleType:
        if name.startswith("opentelemetry"):
            raise ModuleNotFoundError("fixture missing optional dependency")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_otel)
    tracer = RecordingTracer()
    with pytest.raises(RuntimeError, match=r"mcp-audits\[otel\]"):
        export_report(report, tracer=tracer)
    assert not tracer.spans


def test_tracer_errors_propagate_without_recording_report_or_exception(
    report: AuditReport, monkeypatch: pytest.MonkeyPatch
) -> None:
    tracer = RecordingTracer()

    def fail(key: str, value: AttributeValue) -> None:
        raise RuntimeError("fixture tracer failure")

    monkeypatch.setattr(RecordingSpan, "set_attribute", lambda self, key, value: fail(key, value))
    with pytest.raises(RuntimeError, match="fixture tracer failure"):
        export_report(report, tracer=tracer)
    assert len(tracer.spans) == 1 and tracer.spans[0].ended
    assert tracer.spans[0].events == []
