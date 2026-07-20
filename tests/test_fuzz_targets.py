from __future__ import annotations

import sys
from types import SimpleNamespace

from pytest import MonkeyPatch

from fuzz.ssrf_schema_fuzzer import fuzz_one_input, main


def test_ssrf_schema_fuzzer_smoke_cases() -> None:
    cases = [
        b"",
        b"https://{host}/metadata",
        b'{"properties":{"targetUrl":{"type":"string","format":"uri"}}}',
        b'{"input_schema":{"properties":{"hostname":{"type":"string"}}},"description":"proxy request"}',
        b"\xff\xfe\x00not-json",
    ]

    for case in cases:
        fuzz_one_input(case)


def test_fuzzer_instruments_loaded_code_before_setup(monkeypatch: MonkeyPatch) -> None:
    calls: list[object] = []
    fake_atheris = SimpleNamespace(
        instrument_all=lambda: calls.append("instrument_all"),
        Setup=lambda argv, callback: calls.append(("setup", argv, callback)),
        Fuzz=lambda: calls.append("fuzz"),
    )
    monkeypatch.setitem(sys.modules, "atheris", fake_atheris)

    main()

    assert calls[0] == "instrument_all"
    assert calls[1] == ("setup", sys.argv, fuzz_one_input)
    assert calls[2] == "fuzz"
