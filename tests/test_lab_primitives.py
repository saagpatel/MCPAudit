"""Acceptance tests for shared offline lab mechanics and unchanged canonical bytes."""

from __future__ import annotations

import hashlib
import importlib
import os
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from mcp_audit.agent_ui_scanner import scan_agent_ui_path
from mcp_audit.cache_contract_scanner import scan_cache_path
from mcp_audit.canonical import canonical_json_bytes, compact_json_bytes
from mcp_audit.lab_primitives import read_bounded_descriptor, strict_json_loads, validate_json_nesting
from mcp_audit.oauth_transcript_scanner import scan_oauth_transcript_path
from mcp_audit.result_parcel_scanner import scan_scenario_path as scan_parcel_path
from mcp_audit.session_resume_lab import SessionResumeInputError, load_scenario_path, run_builtin_suite
from mcp_audit.task_time_machine import load_scenario_path as load_task_path
from mcp_audit.task_time_machine import scan_scenario_path as scan_task_path
from mcp_audit.task_time_machine_models import TaskScenario

FIXTURES = Path(__file__).parent / "fixtures"
SERIALIZERS = [
    ("agent_ui", True, True),
    ("authorization_posture", False, True),
    ("cache_contract", False, False),
    ("oauth_transcript", True, True),
    ("result_parcel", False, False),
    ("session_resume", False, False),
    ("task_time_machine", False, False),
]


@pytest.mark.parametrize(("size", "budget"), [(0, 0), (4, 4), (5, 4), (100_000, 4), (100_000, 100_000)])
def test_descriptor_read_is_bounded_and_leaves_ownership_with_caller(
    tmp_path: Path, size: int, budget: int
) -> None:
    path = tmp_path / "synthetic.bin"
    path.write_bytes(b"x" * size)
    descriptor = os.open(path, os.O_RDONLY)
    try:
        assert read_bounded_descriptor(descriptor, budget) == b"x" * min(size, budget + 1)
        assert os.lseek(descriptor, 0, os.SEEK_CUR) == min(size, budget + 1)
        assert os.fstat(descriptor).st_size == size
    finally:
        os.close(descriptor)


def test_task_loader_handles_short_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    original_read = os.read

    def short_read(descriptor: int, size: int) -> bytes:
        return original_read(descriptor, min(7, size))

    monkeypatch.setattr(os, "read", short_read)
    scenario = load_task_path(FIXTURES / "task_time_machine/happy-path.json")
    assert isinstance(scenario, TaskScenario)
    assert scenario.scenario_id == "happy-path"


def test_read_errors_propagate_and_invalid_budgets_do_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied_read(descriptor: int, size: int) -> bytes:
        raise OSError("synthetic read failure")

    monkeypatch.setattr(os, "read", denied_read)
    with pytest.raises(ValueError, match="non-negative"):
        read_bounded_descriptor(-1, -1)
    with pytest.raises(OSError, match="synthetic read failure"):
        read_bounded_descriptor(-1, 4)


@pytest.mark.parametrize(
    "raw",
    [b'{"outer":{"key":1,"key":2}}', b"NaN", b"Infinity", b"-Infinity", b"\xff", b"{", b"{} {}"],
)
def test_strict_json_rejects_ambiguous_or_malformed_input(raw: bytes) -> None:
    with pytest.raises(ValueError):
        strict_json_loads(raw)


def test_strict_json_accepts_standard_values_without_coercion() -> None:
    assert strict_json_loads(b'{"x":[true,null,1,1.25,"text"]}') == {"x": [True, None, 1, 1.25, "text"]}


def test_duplicate_hook_does_not_reflect_input_keys() -> None:
    raw = b'{"synthetic-private-marker":1,"synthetic-private-marker":2}'
    with pytest.raises(ValueError) as error:
        strict_json_loads(raw)
    assert "synthetic-private-marker" not in "".join(traceback.format_exception(error.value))


def test_nesting_budget_ignores_escaped_string_delimiters() -> None:
    raw = b'{"text":"[ { \\" ] }", "nested":[]}'
    validate_json_nesting(raw, 2, ValueError)
    with pytest.raises(ValueError, match="exceeds 1 levels"):
        validate_json_nesting(raw, 1, ValueError)


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_session_resume_rejects_nonstandard_constants_at_json_boundary(
    tmp_path: Path, constant: bytes
) -> None:
    path = tmp_path / "scenario.json"
    path.write_bytes(b'{"unexpected":' + constant + b"}")
    with pytest.raises(SessionResumeInputError, match="not valid bounded JSON"):
        load_scenario_path(path)


class _AliasFixture(BaseModel):
    label: str = Field(alias="wire_label")
    values: list[object] = Field(alias="wire_values")


class _ConfiguredAliasFixture(_AliasFixture):
    model_config = ConfigDict(serialize_by_alias=True)


@pytest.mark.parametrize(("module_name", "by_alias", "allow_nan"), SERIALIZERS)
def test_lab_serializers_preserve_exact_model_bytes_and_number_policy(
    module_name: str, by_alias: bool, allow_nan: bool
) -> None:
    module = importlib.import_module(f"mcp_audit.{module_name}_models")
    serializer: Callable[[BaseModel | dict[str, object] | list[object]], bytes] = module.canonical_json_bytes
    model = _AliasFixture(wire_label="café", wire_values=[None, True, 1.25, {"z": 2, "a": "line\n"}])
    expected = (
        '{"wire_label":"café","wire_values":[null,true,1.25,{"a":"line\\n","z":2}]}\n'
        if by_alias
        else '{"label":"café","values":[null,true,1.25,{"a":"line\\n","z":2}]}\n'
    ).encode("utf-8")
    assert serializer(model) == expected
    configured = _ConfiguredAliasFixture(wire_label="café", wire_values=[])
    assert serializer(configured) == '{"wire_label":"café","wire_values":[]}\n'.encode()
    assert serializer({"z": "café", "a": [True, None]}) == '{"a":[true,null],"z":"café"}\n'.encode()
    assert serializer([True, None]) == b"[true,null]\n"
    if allow_nan:
        assert serializer({"number": float("nan")}) == b'{"number":NaN}\n'
    else:
        with pytest.raises(ValueError):
            serializer({"number": float("nan")})


def test_tool_pin_legacy_and_current_canonical_bytes_are_unchanged() -> None:
    value = {"z": "café", "a": [True, None]}
    assert compact_json_bytes(value) == '{"a":[true,null],"z":"café"}'.encode()
    assert canonical_json_bytes(value) == '{"a":[true,null],"z":"café"}\n'.encode()
    assert canonical_json_bytes(value, legacy=True) == '{"a": [true, null], "z": "café"}'.encode()


# These digests were captured with the pre-extraction serializers. They bind
# fixture-backed reports, including their input digests and canonical formatting.
@pytest.mark.parametrize(
    ("module_name", "scanner", "fixture", "expected"),
    [
        (
            "agent_ui",
            scan_agent_ui_path,
            "agent_ui/mcpui001-authority-negative.json",
            "ad7f36838d946499a7132f79e658533e7d0317740d408e37ddc066af5bf3dbfa",
        ),
        (
            "cache_contract",
            scan_cache_path,
            "cache_contract/wrong-key-vulnerable.json",
            "fb4b39f4f951030f311459faddc7f166058ad3c2fd9fb0f7ea145a578ffba0ea",
        ),
        (
            "oauth_transcript",
            scan_oauth_transcript_path,
            "oauth_transcript/mcpoauth001-negative.json",
            "67b58c4b6025c7c334dd7abe1addf6e079431d690a0df59a54d5a3253528f05a",
        ),
        (
            "result_parcel",
            scan_parcel_path,
            "result_parcel/small-inline.json",
            "8f7507621e2c9f453ab7e1ac49154648b9570e5056b332c9ee35c78d7d24e103",
        ),
        (
            "task_time_machine",
            scan_task_path,
            "task_time_machine/happy-path.json",
            "c152fc3eac4ec943d7272db068f739e656b18680b18d571a4fb6686983bda02d",
        ),
    ],
)
def test_fixture_report_canonical_bytes_match_before_extraction(
    module_name: str, scanner: Callable[[Path], BaseModel], fixture: str, expected: str
) -> None:
    module = importlib.import_module(f"mcp_audit.{module_name}_models")
    serializer: Callable[[BaseModel], bytes] = module.canonical_json_bytes
    assert hashlib.sha256(serializer(scanner(FIXTURES / fixture))).hexdigest() == expected


def test_session_resume_suite_canonical_bytes_match_before_extraction() -> None:
    from mcp_audit.session_resume_lab import report_json_bytes

    assert hashlib.sha256(report_json_bytes(run_builtin_suite())).hexdigest() == (
        "840c0346443b6302c34329462d52d56c76d9ed7baf6faba5df131d66f0d34627"
    )
