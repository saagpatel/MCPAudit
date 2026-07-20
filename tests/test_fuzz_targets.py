from __future__ import annotations

from fuzz.ssrf_schema_fuzzer import fuzz_one_input


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
