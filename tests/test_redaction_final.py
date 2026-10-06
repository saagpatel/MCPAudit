"""Final-round synthetic redaction cases through text, report JSON and saved pins."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_audit.models import AuditReport, ServerAudit, ToolInfo
from mcp_audit.pinning import PinStore
from mcp_audit.redaction import redact_data, redact_text
from mcp_audit.report import ReportGenerator
from tests.conftest import make_server_config

_CASES = json.loads((Path(__file__).parent / "fixtures/redaction/final-round.json").read_text())


@pytest.mark.parametrize("case", _CASES, ids=[f"case-{i}" for i in range(len(_CASES))])
@pytest.mark.parametrize("identifiers", [False, True])
def test_final_round_text_report_and_pin(case: dict[str, object], tmp_path: Path, identifiers: bool) -> None:
    text, expected = case["text"], case["redacted"]
    assert isinstance(text, str) and isinstance(expected, str)
    args = case.get("args", [text])
    expected_args = case.get("redacted_args", [expected])
    assert isinstance(args, list)
    assert redact_text(text) == expected
    assert redact_text(expected) == expected
    assert redact_data(args) == expected_args
    config = make_server_config(
        args=args,
        url=text if text.startswith(("https://", "postgresql://", "mysql://", "redis://")) else None,
    )
    tool = ToolInfo(
        name="fixture-tool",
        description=text,
        input_schema={"type": "object", "properties": {"value": {"type": "string", "description": text}}},
    )
    report = AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="synthetic-host",
        os_platform="synthetic-os",
        servers_discovered=1,
        servers_connected=1,
        servers_failed=0,
        total_tools=1,
        high_risk_servers=0,
        audits=[ServerAudit(server=config, tools=[tool], connection_status="connected")],
        scan_duration_seconds=0.0,
    )
    report_file = tmp_path / "report.json"
    ReportGenerator().render_json(report.redacted(identifiers=identifiers), report_file)
    output = json.loads(report_file.read_text())
    audit = output["audits"][0]
    assert audit["server"]["args"] == expected_args
    assert audit["tools"][0]["description"] == expected
    assert audit["tools"][0]["input_schema"]["properties"]["value"]["description"] == expected
    assert report.audits[0].tools[0].description == text

    pin_file = tmp_path / "pins.yaml"
    store = PinStore(pin_file)
    store.pin_server(config.name, [tool], config)
    reloaded = PinStore(pin_file)
    baseline = reloaded.baseline_tools(config.name)[0]
    snapshot = reloaded.baseline_config(config.name)
    assert snapshot is not None
    assert baseline.description == expected
    assert baseline.input_schema == audit["tools"][0]["input_schema"]
    assert snapshot["args"] == expected_args
    if config.url is not None:
        assert snapshot["url"] == audit["server"]["url"] == expected
    assert reloaded.check_drift(config.name, [tool]) == []
