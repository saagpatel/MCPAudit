"""Operation-count regressions for fleet parsing, scoring and report redaction."""

import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Literal, SupportsIndex

import json5
import pytest
from pydantic import BaseModel

from mcp_audit import analyzer, engine, normalize, redaction
from mcp_audit.agent_text import agent_visible_text
from mcp_audit.discovery import _config, _entry
from mcp_audit.discovery.base import ConfigParseError
from mcp_audit.models import ClientType, ServerConfig, ToolInfo
from mcp_audit.rules.patterns import PERMISSION_PATTERNS
from tests.conftest import make_tool
from tests.fixtures.escape_dense import MIB, escape_dense_field


@pytest.mark.parametrize("separated", [False, True], ids=["adjacent", "spaced"])
def test_escape_dense_redaction_work_is_linear(monkeypatch: pytest.MonkeyPatch, separated: bool) -> None:
    work = 0
    text_edits, choices = redaction._text_edits, redaction._sequence_choices
    normalize_text = normalize.normalize_text

    def counted_edits(
        value: str, *, raw: bool = True, labels: frozenset[int] | None = None
    ) -> Iterator[tuple[int, int, str]]:
        nonlocal work
        work += len(value)
        return text_edits(value, raw=raw, labels=labels)

    def counted_choices(value: str, start: int, end: int) -> tuple[tuple[redaction._Choice, ...], bool]:
        nonlocal work
        result, complete = choices(value, start, end)
        work += end - start + sum(len(text) for text, _, _ in result)
        return result, complete

    def counted_normalize(value: str) -> str:
        nonlocal work
        work += len(value)
        return normalize_text(value)

    monkeypatch.setattr(redaction, "_text_edits", counted_edits)
    monkeypatch.setattr(redaction, "_sequence_choices", counted_choices)
    monkeypatch.setattr(redaction, "normalize_text", counted_normalize)
    for size in (MIB // 16, MIB // 4, MIB):
        field = escape_dense_field(size, separated=separated)
        assert len(field.encode("utf-8")) == size
        assert all(sequence in field for sequence in ("\x1b[31m", "\x1b]note\x07", "\x1b:"))
        work = 0
        assert redaction.redact_text(field) == ("context <redacted>" if separated else "<redacted>")
        # Count scanned detection/normalization characters and copied reading
        # choices, rather than elapsed time. A 16x input cannot do quadratic work.
        assert work <= 40 * size + (1 << 20), (size, work)


@pytest.mark.parametrize("literal", [False, True])
def test_ascii_redaction_view_does_not_normalize_codepoints(
    monkeypatch: pytest.MonkeyPatch, literal: bool
) -> None:
    def unexpected_normalize(value: str) -> str:
        pytest.fail("ASCII view normalization is the identity")

    monkeypatch.setattr(redaction, "normalize_text", unexpected_normalize)
    field = "a\x1b[31mb\x1b]note\x07\x1b:c"
    text, origins = redaction._normalized_view(field, literal=literal)
    assert text == ("a31mbnote:c" if literal else "abc")
    assert origins is not None
    assert "".join(field[start:end] for start, end in origins) == text


@pytest.mark.parametrize("size", [0, 1, 4, redaction._MAX_SUFFIX, redaction._MAX_SUFFIX + 1])
def test_escape_suffix_choices_do_not_copy_the_full_payload_twice(size: int) -> None:
    visits = 0

    class CountedText(str):
        def __getitem__(self, key: SupportsIndex | slice) -> str:
            nonlocal visits
            result = super().__getitem__(key)
            visits += len(result)
            return result

    field = CountedText("\x1b]" + "a" * size + "\x07")
    choices, complete = redaction._sequence_choices(field, 0, len(field))
    suffix = min(size, redaction._MAX_SUFFIX)
    assert visits == suffix * (suffix + 1) // 2 + (size if size > suffix else 0)
    assert complete == (size <= redaction._MAX_SUFFIX)
    assert choices[-1][0] == "a" * size


def test_ascii_normalization_does_not_visit_codepoints(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_visit(char: str) -> None:
        pytest.fail("ASCII normalization must not classify individual codepoints")

    monkeypatch.setattr(normalize, "invisible_class", unexpected_visit)
    text = "".join(chr(i) for i in range(128)) * 100
    assert normalize.normalize_text(text) == text


def test_jsonc_standard_json_does_not_use_python_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_parse(*args: object, **kwargs: object) -> None:
        pytest.fail("Standard JSON must not pass through the JSON5 parser")

    monkeypatch.setattr(json5, "loads", unexpected_parse)
    fixture = Path(__file__).parent / "fixtures/claude_desktop_config.json"
    issues: list[ConfigParseError] = []
    assert _config.decode_config(
        fixture.read_text(), "fixture", ClientType.CLAUDE_DESKTOP, issues, jsonc=True
    )
    assert issues == []


def test_jsonc_fallback_counts_duplicate_keys_only_once() -> None:
    issues: list[ConfigParseError] = []
    data = _config.decode_config(
        '{"nested": {"name": 1, "name": 2}, /* comment */ "tail": 3}',
        "fixture",
        ClientType.CLAUDE_DESKTOP,
        issues,
        jsonc=True,
    )
    assert data == {"nested": {"name": 2}, "tail": 3}
    assert len(issues) == 1
    assert "1 duplicate object key(s)" in str(issues[0])


@pytest.mark.parametrize("project", [False, True])
def test_server_map_classifies_shared_path_once(monkeypatch: pytest.MonkeyPatch, project: bool) -> None:
    calls = 0

    def classify(path: Path) -> bool:
        nonlocal calls
        calls += 1
        return project

    monkeypatch.setattr(_entry, "is_project_config", classify)
    servers = _entry.parse_server_map(
        {f"fixture-{i}": {"command": "fixture"} for i in range(100)},
        "synthetic-config.json",
        ClientType.CLAUDE_CODE,
    )
    assert calls == 1
    assert len(servers) == 100
    assert {server.scope for server in servers} == {"project" if project else "workstation"}


def test_explicit_config_tags_validated_models_without_copying(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "synthetic-config.json"
    config.write_text(json.dumps({"mcpServers": {"fixture/name": {"command": "fixture"}}}))

    def unexpected_copy(*args: object, **kwargs: object) -> None:
        pytest.fail("Freshly parsed models need no copies for source and pointer tags")

    monkeypatch.setattr(ServerConfig, "model_copy", unexpected_copy)
    [server] = engine._parse_extra_config(config)
    assert server.config_source == "explicit file; parsed as Claude-style config"
    assert server.config_pointer == "/mcpServers/fixture~1name"


def test_keyword_scoring_does_not_revisit_unmatched_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    class CountScores(dict[str, int]):
        calls = 0

        def __getitem__(self, key: str) -> int:
            self.calls += 1
            return super().__getitem__(key)

    scores = CountScores(analyzer._STRENGTH_SCORES)
    monkeypatch.setattr(analyzer, "_STRENGTH_SCORES", scores)
    analyzer._category_rules.cache_clear()
    try:
        engine = analyzer.PermissionAnalyzer()
        for category in PERMISSION_PATTERNS:
            analyzer._category_rules(category)
        scores.calls = 0
        for size in (10, 100):
            findings = engine.analyze_server([make_tool(f"status_{i}", description="") for i in range(size)])
            assert findings == []
            assert scores.calls == 0
        findings = engine.analyze_tool(make_tool("read_file", description="read_file"))
        assert findings[0].evidence == ["read_file", "read"]
        assert scores.calls == 0
    finally:
        analyzer._category_rules.cache_clear()


def test_empty_tool_analysis_does_not_allocate_keyword_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_cache(*args: object, **kwargs: object) -> None:
        pytest.fail("Empty tool metadata needs no keyword cache")

    engine = analyzer.PermissionAnalyzer()
    monkeypatch.setattr(analyzer, "lru_cache", unexpected_cache)
    assert engine.analyze_server([]) == []
    assert engine.analyze_server([], agent_texts=[]) == []


def test_empty_tool_analysis_still_rejects_mismatched_texts() -> None:
    text = agent_visible_text(make_tool("fixture"))
    with pytest.raises(ValueError, match="zip"):
        analyzer.PermissionAnalyzer().analyze_server([], agent_texts=[text])


def test_report_redaction_reuses_short_fields_only_within_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Metadata(BaseModel):
        tools: list[ToolInfo]

    calls: Counter[str] = Counter()
    original = redaction._redact_text

    def counted(value: str) -> str:
        calls[value] += 1
        return original(value)

    monkeypatch.setattr(redaction, "_redact_text", counted)
    fixture = Path(__file__).parent / "fixtures/redaction/final-round.json"
    case = json.loads(fixture.read_text())[0]
    text, expected = case["text"], case["redacted"]
    model = Metadata(tools=[make_tool(f"tool_{i}", description=text) for i in range(100)])
    first = redaction.redact_model(model)
    tools = first["tools"]
    assert isinstance(tools, list)
    assert all(isinstance(tool, dict) and tool["description"] == expected for tool in tools)
    assert calls[text] == 1
    assert redaction._REPORT_REDACTOR.get() is None
    assert redaction.redact_model(model) == first
    assert calls[text] == 2
    assert model.tools[0].description == text


def test_report_redaction_clears_cache_on_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class Metadata(BaseModel):
        description: str

    def failure(value: str) -> str:
        raise ValueError("synthetic redactor failure")

    monkeypatch.setattr(redaction, "_redact_text", failure)
    with pytest.raises(ValueError, match="synthetic redactor failure"):
        redaction.redact_model(Metadata(description="fixture"))
    assert redaction._REPORT_REDACTOR.get() is None


def test_report_redaction_reuses_serialized_containers(monkeypatch: pytest.MonkeyPatch) -> None:
    class Metadata(BaseModel):
        tools: list[ToolInfo]

    original = Metadata.model_dump
    serialized: list[dict[str, object]] = []

    def dumped(self: Metadata, *, mode: Literal["json"]) -> dict[str, object]:
        data = original(self, mode=mode)
        serialized.append(data)
        return data

    monkeypatch.setattr(Metadata, "model_dump", dumped)
    model = Metadata(
        tools=[
            make_tool(
                f"tool_{i}",
                description="Bearer synthetic-secret",
                input_schema={"properties": {"api_key": {"default": "synthetic-secret"}}},
            )
            for i in range(10)
        ]
    )
    before = json.dumps(original(model, mode="json"), sort_keys=True)
    result = redaction.redact_model(model)
    assert len(serialized) == 1
    assert result is serialized[0]
    assert model.tools[0].description == "Bearer synthetic-secret"
    assert json.dumps(original(model, mode="json"), sort_keys=True) == before


def test_report_redaction_does_not_cache_large_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    class Metadata(BaseModel):
        descriptions: list[str]

    calls = 0
    original = redaction._redact_text

    def counted(value: str) -> str:
        nonlocal calls
        calls += 1
        return original(value)

    monkeypatch.setattr(redaction, "_redact_text", counted)
    text = "x" * 1025
    assert redaction.redact_model(Metadata(descriptions=[text, text])) == {"descriptions": [text, text]}
    assert calls == 2


def test_report_redaction_cache_evicts_unique_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    class Metadata(BaseModel):
        descriptions: list[str]

    calls: Counter[str] = Counter()

    def counted(value: str) -> str:
        calls[value] += 1
        return value

    monkeypatch.setattr(redaction, "_redact_text", counted)
    values = ["rare", *[f"unique_{index}" for index in range(5000)], "rare"]
    assert redaction.redact_model(Metadata(descriptions=values)) == {"descriptions": values}
    assert calls["rare"] == 2
