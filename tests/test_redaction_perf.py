"""Equivalence checks for report-local redaction optimizations."""

from collections import Counter
from functools import lru_cache
from io import StringIO
from pathlib import Path
from random import Random
from unittest.mock import patch

import pytest
from pydantic import BaseModel
from rich.console import Console

from mcp_audit import redaction
from mcp_audit.checkup import generate_card
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ServerConfig
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config
from tests.redteam.test_redaction_corpus import CORPUS, _report


def test_ascii_argv_fast_path_matches_full_path() -> None:
    rng = Random(2110)
    alphabet = "".join(chr(code) for code in range(32, 127)) + "=:@//" * 8
    fragments = [
        "token",
        "tokens",
        "tokenizer",
        "api",
        "key",
        "auth",
        "author",
        "sig",
        "session-name",
        "Bearer",
        "Basic",
        "ghp_",
        "sk-",
        "eyJ",
        "password",
        "private-key",
        "https://",
    ]
    argv_lists: list[list[object]] = [
        ["-I", "-S", "/fixture/hostile_server.py", "normal"],
        ["--password", "ordinary", "--port", "8000"],
        ["--token", "", "--format=token", "--root", "/fixture"],
    ]
    for _ in range(2000):
        argv: list[object] = []
        for _ in range(rng.randrange(1, 9)):
            value = "".join(rng.choices(alphabet, k=rng.randrange(0, 80)))
            if rng.randrange(2):
                index = rng.randrange(len(value) + 1)
                value = value[:index] + rng.choice(fragments) + value[index:]
            if rng.randrange(4) == 0:
                value = "--" + rng.choice(fragments) + rng.choice(["", "=", ":"]) + value
            argv.append(value)
        argv_lists.append(argv)
    argv_lists.extend(case["source"] for case in CORPUS if isinstance(case["source"], list))
    fast = [redaction.redact_argv(argv) for argv in argv_lists]
    texts = [item for argv in argv_lists for item in argv if isinstance(item, str)]
    fast_text = [redaction.redact_text(text) for text in texts]
    pointers = ["/mcpServers/" + text.replace("~", "~0").replace("/", "~1") for text in texts[:2000]]
    pointers.extend(["/mcpServers/https:~1~1user:synthetic@fixture.invalid", "/mcpServers/--password=x"])
    fast_pointers = [redaction._redact_config_pointer(pointer) for pointer in pointers]
    with patch.object(redaction, "_argv_safe_ascii", return_value=False):
        full = [redaction.redact_argv(argv) for argv in argv_lists]
        full_text = [redaction.redact_text(text) for text in texts]
        full_pointers = [redaction._redact_config_pointer(pointer) for pointer in pointers]
    assert fast == full
    assert fast_text == full_text
    assert fast_pointers == full_pointers


def test_ascii_argv_bypasses_readings_after_pairing() -> None:
    args: list[object] = ["-I", "-S", "/fixture/hostile_server.py", "normal"]
    with patch.object(redaction, "_argv_readings", side_effect=AssertionError("unexpected readings")):
        assert redaction.redact_argv(args) == args
    assert redaction.redact_argv(["--password", *args]) == ["--password", "<redacted>", *args[1:]]
    for value in ("\x00", "\x7f", "\x1b[0m", "ｔｏｋｅｎ", "café", "--auth", "Bearer abc", "https://a"):
        assert not redaction._argv_safe_ascii(value)


def test_report_argv_cache_is_local_and_returns_independent_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    class Fleet(BaseModel):
        servers: list[ServerConfig]

    argv = ["--password", "synthetic-value", "--root", "/fixture"]
    fleet = Fleet(servers=[make_server_config(name=f"fixture-{i}", args=argv) for i in range(10)])
    calls: Counter[tuple[object, ...]] = Counter()
    original = redaction.redact_argv

    def counted(value: list[object]) -> list[object]:
        calls[tuple(value)] += 1
        return original(value)

    monkeypatch.setattr(redaction, "redact_argv", counted)
    first = redaction.redact_model(fleet)
    assert calls[tuple(argv)] == 1
    assert redaction.redact_model(fleet) == first
    assert calls[tuple(argv)] == 2
    servers = first["servers"]
    assert isinstance(servers, list)
    assert isinstance(servers[0], dict) and isinstance(servers[1], dict)
    assert servers[0]["args"] is not servers[1]["args"]
    assert fleet.servers[0].args == argv


@pytest.mark.parametrize("case", CORPUS, ids=[str(case["id"]) for case in CORPUS])
def test_report_caches_match_uncached_pass(case: dict[str, object]) -> None:
    report = _report(case)
    cached = redaction.redact_model(report)
    with patch.object(redaction, "lru_cache", side_effect=lambda **kwargs: lru_cache(maxsize=0)):
        assert redaction.redact_model(report) == cached
    assert redaction._REPORT_REDACTOR.get() is None


def _surfaces(report: AuditReport) -> list[str]:
    terminal, json_output = StringIO(), StringIO()
    renderer = ReportGenerator(Console(file=terminal, width=200, color_system=None))
    renderer._render_redacted_terminal(report, verbose=True)
    renderer._stream_redacted_json(report, json_output)
    return [
        report.model_dump_json(),
        terminal.getvalue(),
        json_output.getvalue(),
        HtmlReportGenerator()._generate_redacted(report),
        str(SarifGenerator()._generate_redacted(report)),
        generate_card(report, names=True),
    ]


def _type_tree(value: object) -> object:
    if isinstance(value, BaseModel):
        return (
            type(value),
            value.model_fields_set,
            {name: _type_tree(getattr(value, name)) for name in type(value).model_fields},
        )
    if isinstance(value, (list, tuple)):
        return type(value), [_type_tree(item) for item in value]
    if isinstance(value, dict):
        return {key: _type_tree(item) for key, item in value.items()}
    return type(value)


def test_empty_audit_copy_matches_serialized_surfaces() -> None:
    report = _report({"source": ["-I", "-S", "normal"], "kind": "args"})
    report.audits[0].tools = []
    report.audits[0].injection_findings = []
    report.audits[0].connection_status = "skipped"
    report.total_tools = report.servers_connected = 0
    safe = report.redacted()
    reference = AuditReport.model_validate(redaction.redact_model(report))
    assert _surfaces(safe) == _surfaces(reference)
    assert safe.model_dump(exclude_unset=True) == reference.model_dump(exclude_unset=True)
    assert safe.audits[0].model_fields_set == reference.audits[0].model_fields_set
    for name in type(report.audits[0]).model_fields:
        original = getattr(report.audits[0], name)
        if isinstance(original, list):
            assert getattr(safe.audits[0], name) is not original


@pytest.mark.parametrize("identifiers", [False, True])
@pytest.mark.parametrize("config_only", [False, True])
@pytest.mark.parametrize("case", [None, *CORPUS], ids=["sample", *[str(c["id"]) for c in CORPUS]])
def test_typed_copy_matches_validated_golden_surfaces(
    case: dict[str, object] | None, identifiers: bool, config_only: bool
) -> None:
    report = (
        _report(case)
        if case is not None
        else AuditReport.model_validate_json(
            Path("tests/fixtures/reports/sample_audit_report.json").read_text()
        )
    )
    if config_only:
        for audit in report.audits:
            audit.tools = []
            audit.prompts = []
            audit.resources = []
        report.total_tools = 0
    before = report.model_dump_json()
    safe = report.redacted(identifiers=identifiers)

    original = redaction.redact_model

    def serialized(model: BaseModel, *, _typed: bool = False) -> dict[str, object]:
        return original(model)

    with patch.object(redaction, "redact_model", side_effect=serialized):
        reference = report.redacted(identifiers=identifiers)
    assert _type_tree(safe) == _type_tree(reference)
    assert safe.model_dump(mode="json") == reference.model_dump(mode="json")
    assert safe.model_dump(exclude_unset=True) == reference.model_dump(exclude_unset=True)
    assert _surfaces(safe) == _surfaces(reference)
    assert report.model_dump_json() == before
    assert safe.audits[0] is not report.audits[0]
    assert safe.audits[0].server is not report.audits[0].server
