"""Synthetic redaction gaps promoted to passing, cross-renderer regressions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import cast

import pytest
from rich.console import Console

from mcp_audit.connector import _redact_sse_log_text
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import (
    AuditReport,
    AuthorizationFetch,
    AuthorizationProbeObservation,
    InjectionFinding,
    InjectionSeverity,
    ProvenanceFinding,
    ProvenanceKind,
    ProvenanceSeverity,
    ScanWarning,
    ServerAudit,
    ToolInfo,
)
from mcp_audit.pinning import PinStore
from mcp_audit.redaction import redact_data, redact_text, redact_url, redacted_excerpt
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

CORPUS = cast(
    list[dict[str, object]],
    json.loads((Path(__file__).parents[1] / "fixtures/redaction/structural.json").read_text()),
)


def _report(case: dict[str, object]) -> AuditReport:
    source, kind = case["source"], case["kind"]
    server = make_server_config(name="synthetic-server", env_keys=["API_TOKEN"])
    server.headers_keys = ["X-Key"]
    tool = ToolInfo(name="synthetic-tool")
    probe: AuthorizationProbeObservation | None = None
    provenance: list[ProvenanceFinding] = []
    if kind == "text":
        assert isinstance(source, str)
        tool.name = tool.description = source
    elif kind == "args":
        assert isinstance(source, list) and all(isinstance(item, str) for item in source)
        server.args = cast(list[str], source)
    elif kind in {"schema", "meta"}:
        assert isinstance(source, dict)
        if kind == "schema":
            tool.input_schema = tool.output_schema = source
        else:
            tool.meta = source
    elif kind == "url":
        assert isinstance(source, str)
        server.url = source
        tool.meta = {"endpoint": source}
        probe = AuthorizationProbeObservation(
            metadata_fetches=[AuthorizationFetch(url=source, reason="synthetic")], warnings=[source]
        )
        provenance = [
            ProvenanceFinding(
                kind=ProvenanceKind.URL,
                severity=ProvenanceSeverity.HIGH,
                server_name=server.name,
                summary=f"Endpoint: {source}",
                baseline=source,
                current=source,
            )
        ]
    else:
        raise AssertionError(f"Unsupported corpus kind: {kind}")
    finding = InjectionFinding(
        tool_name=tool.name,
        severity=InjectionSeverity.HIGH,
        pattern_name="synthetic-pattern",
        matched_text=tool.description or "synthetic evidence",
        matched_span=(0, len(tool.description or "synthetic evidence")),
        description=tool.description or "synthetic finding",
    )
    return AuditReport(
        scan_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        hostname="synthetic-host",
        os_platform="synthetic-os",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=0,
        audits=[
            ServerAudit(
                server=server,
                tools=[tool],
                injection_findings=[finding],
                connection_status="connected",
                authorization_probe=probe,
                provenance_findings=provenance,
            )
        ],
        scan_duration_seconds=0,
        warnings=[ScanWarning(code="synthetic_url", message=f"Endpoint: {source}", check="connection")]
        if kind == "url"
        else [],
    )


@pytest.mark.redteam
@pytest.mark.parametrize("case", CORPUS, ids=[str(case["id"]) for case in CORPUS])
@pytest.mark.parametrize("identifiers", [False, True])
def test_structural_redaction_corpus(case: dict[str, object], tmp_path: Path, identifiers: bool) -> None:
    report = _report(case)
    original = report.model_dump(mode="json")
    safe = report.redacted(identifiers=identifiers)
    audit = safe.audits[0]
    kind = case["kind"]
    if kind == "text":
        assert audit.tools[0].name == audit.tools[0].description == case["expected"]
        assert redact_text(cast(str, case["source"])) == case["expected"]
        assert audit.injection_findings[0].matched_span is None
    else:
        assert audit.injection_findings[0].matched_span == report.audits[0].injection_findings[0].matched_span
    if kind == "args":
        assert audit.server.args == case["expected"]
    elif kind == "schema":
        assert audit.tools[0].input_schema == audit.tools[0].output_schema == case["expected"]
    elif kind == "meta":
        assert audit.tools[0].meta == case["expected"]
    elif kind == "url":
        assert audit.server.url == case["expected"]
        assert (
            audit.provenance_findings[0].baseline == audit.provenance_findings[0].current == case["expected"]
        )
        assert audit.authorization_probe is not None
        assert audit.authorization_probe.metadata_fetches[0].url == case["expected"]
    assert audit.server.env_keys == ["API_TOKEN"]
    assert audit.server.headers_keys == ["X-Key"]
    assert safe.schema_version == report.schema_version
    assert safe.model_dump(mode="json").keys() == original.keys()
    assert safe.redacted(identifiers=identifiers).model_dump() == safe.model_dump()
    assert report.model_dump(mode="json") == original

    terminal = StringIO()
    generator = ReportGenerator(Console(file=terminal, width=200, color_system=None))
    # Pass raw input to each renderer, proving its public entry point is safe.
    generator.render_terminal(report, verbose=True)
    generator.render_json(report, tmp_path / "report.json")
    outputs = [
        safe.model_dump_json(),
        terminal.getvalue(),
        (tmp_path / "report.json").read_text(),
        HtmlReportGenerator().generate(report),
        json.dumps(SarifGenerator().generate(report)),
    ]
    pin_file = tmp_path / "pins.yaml"
    # Pin identities intentionally remain raw; exercise the saved metadata with
    # an ordinary identity so this sweep checks the reportable snapshot fields.
    pin_tool = report.audits[0].tools[0].model_copy(update={"name": "synthetic-tool"})
    PinStore(pin_file).pin_server(report.audits[0].server.name, [pin_tool], report.audits[0].server)
    store = PinStore(pin_file)
    snapshot = store.baseline_config(report.audits[0].server.name)
    assert snapshot is not None
    if kind == "args":
        assert snapshot["args"] == audit.server.args
    elif kind == "url":
        assert snapshot["url"] == audit.server.url
    elif kind == "schema":
        assert (
            store.baseline_tools(report.audits[0].server.name)[0].input_schema == audit.tools[0].input_schema
        )
    outputs.append(pin_file.read_text())
    forbidden = case["forbidden"]
    assert isinstance(forbidden, list)
    for output in outputs:
        for secret in forbidden:
            assert isinstance(secret, str)
            assert secret not in output


def test_metadata_lists_are_not_argv_and_env_maps_have_no_values() -> None:
    # Only key names and an absent value are supplied for the synthetic env map.
    assert redact_data({"env": {"API_TOKEN": None}}) == {"env": {"API_TOKEN": "<redacted>"}}
    assert redact_data({"items": ["--token", "ordinary label"]}) == {"items": ["--token", "ordinary label"]}


@pytest.mark.parametrize(
    "char",
    ["\uff02", "\uff0f", "\uff20", "\uff1a", "\uff1d", "\u00a8", "\u2024", "\ufe6b", "\uff03", "\uff1f"],
)
@pytest.mark.parametrize("position", ["assignment", "flag", "header", "userinfo"])
@pytest.mark.parametrize("obfuscated_label", [False, True])
def test_delimiter_changes_never_publish_secret_substrings(
    char: str, position: str, obfuscated_label: bool
) -> None:
    secret = f"v7KpQ9d2M{char}Z8nR4t6Vc"
    sources = {
        "assignment": f"password={secret}",
        "flag": f"--password {secret}",
        "header": f"Authorization: Bearer {secret}",
        "userinfo": f"https://user:{secret}@fixture.example/mcp",
    }
    source = sources[position]
    if obfuscated_label:
        source = (
            source.replace("password", "ｐａｓｓｗｏｒｄ")
            .replace("Authorization", "Ａｕｔｈｏｒｉｚａｔｉｏｎ")
            .replace("Bearer", "Ｂｅａｒｅｒ")
        )
    report = _report({"source": source, "kind": "url" if position == "userinfo" else "text"})
    report.warnings = [ScanWarning(code="fixture", message=source, check="connection")]
    safe = report.redacted()
    terminal = StringIO()
    ReportGenerator(Console(file=terminal, width=200, color_system=None)).render_terminal(
        report, verbose=True
    )
    outputs = [
        safe.model_dump_json(),
        terminal.getvalue(),
        HtmlReportGenerator().generate(report),
        json.dumps(SarifGenerator().generate(report)),
    ]
    # Every longer substring contains a six-character substring. Test both raw
    # halves independently so introduced delimiters cannot conceal a leaked tail.
    for output in outputs:
        for offset in range(len(secret) - 5):
            assert secret[offset : offset + 6] not in output
    assert safe.redacted().model_dump() == safe.model_dump()
    if position == "userinfo":
        assert redact_url(source) == safe.audits[0].server.url == "<redacted>"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("ｐａｓｓｗｏｒｄ=fixture-secret ordinary Ｆ／＠", "ｐａｓｓｗｏｒｄ=<redacted> ordinary Ｆ／＠"),
        ("pass\u200bword=fixture-secret", "pass\u200bword=<redacted>"),
        ("pass\x1b[31mword=fixture-secret", "pass\x1b[31mword=<redacted>"),
        ("Bearer plantedfirst\u200bplantedsecond-secret", "Bearer <redacted>"),
        ('password="prefix\x1b\\"suffix-secret"', "password=<redacted>"),
        # Cross-character NFKC composition has no per-codepoint map: withhold.
        ("ｐａｓｓｗｏｒｄ=fixture-secret e\u0301", "<redacted>"),
    ],
    ids=[
        "raw-label-context",
        "zero-width-label",
        "control-label",
        "union-spans",
        "removed-escape",
        "composition",
    ],
)
def test_normalization_only_detects_and_raw_coverage_survives(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert redact_text(expected) == expected


def test_inline_argv_keeps_raw_obfuscated_flag_spelling() -> None:
    assert redact_data(['--ｐａｓｓｗｏｒｄ=fixture-secret"tail']) == ["--ｐａｓｓｗｏｒｄ=<redacted>"]


@pytest.mark.parametrize(
    "url",
    [
        "ｈｔｔｐｓ://user:fixture-secret@fixture.example/mcp",
        "https：／／user:fixture-secret@fixture.example/mcp",
        "https://user:fixture-secret@Ｆixture.example/mcp",
    ],
    ids=["scheme", "scheme-delimiters", "authority"],
)
def test_compatibility_url_boundaries_are_withheld(url: str) -> None:
    assert redact_url(url) == "<redacted>"
    assert redact_text(url) == "<redacted>"


def test_redacted_assignment_before_colon_is_stable() -> None:
    text = 'password="fixture-secret": ordinary context'
    expected = "password=<redacted>: ordinary context"
    assert redact_text(text) == redact_text(expected) == expected


@pytest.mark.parametrize("control", ["\x1b[31m", "\x9b31m", "\x00", "\x08"])
def test_control_bearing_stderr_lines_are_withheld(control: str) -> None:
    text = f"plain context\npass{control}word=control-secret\ntoken=plain-secret"
    assert _redact_sse_log_text(text) == (
        "plain context\n<terminal-formatted line withheld>\ntoken=<redacted>"
    )
    assert redacted_excerpt(text, 0, len(text)) == "[metadata excerpt withheld]"
