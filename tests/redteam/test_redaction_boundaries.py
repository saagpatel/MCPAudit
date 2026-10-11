"""Property-style sweep: normalization-affecting characters never move a redaction boundary.

Every character class that normalization changes (controls and escape
sequences, compatibility delimiters, invisibles, escaped quotes) is embedded at
the start, middle and end of a synthetic credential in each structural
position. No six-character piece of the credential, nor a payload carried by a
stripped escape sequence, may reach any rendered surface or the pin snapshot.
"""

from __future__ import annotations

import json
import random
from collections.abc import Callable
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import cast

import pytest
from rich.console import Console

from mcp_audit.confighealth import _server_definition_summary
from mcp_audit.htmlreport import HtmlReportGenerator
from mcp_audit.models import AuditReport, ScanWarning, ServerAudit, ToolInfo, TransportType
from mcp_audit.pinning import PinStore
from mcp_audit.provenance import ProvenanceAnalyzer
from mcp_audit.redaction import redact_argv, redact_data, redact_text, redact_url, redacted_excerpt
from mcp_audit.report import ReportGenerator
from mcp_audit.sarif import SarifGenerator
from tests.conftest import make_server_config

LEFT, RIGHT = "v7KpQ9d2M", "Z8nR4t6Vc"
# Payload of a stripped OSC sequence: removed from detection text, never from output.
OSC_PAYLOAD = "Hx4Lq9WzT"

INSERTS = {
    "c0": "\x01",
    "bel": "\x07",
    "esc": "\x1b",
    "esc-st": "\x1b\\",
    "csi": "\x1b[31m",
    "csi-params": "\x1b[1;31m",
    "c1-csi": "\x9b31m",
    "osc": f"\x1b]0;{OSC_PAYLOAD}\x07",
    "osc-unterminated": f"\x1b]0;{OSC_PAYLOAD}",
    "fullwidth-quote": "\uff02",
    "fullwidth-slash": "\uff0f",
    "fullwidth-at": "\uff20",
    "fullwidth-colon": "\uff1a",
    "fullwidth-equals": "\uff1d",
    "diaeresis": "\u00a8",
    "one-dot-leader": "\u2024",
    "small-at": "\ufe6b",
    "fullwidth-hash": "\uff03",
    "fullwidth-question": "\uff1f",
    "zero-width-space": "\u200b",
    "zero-width-joiner": "\u200d",
    "word-joiner": "\u2060",
    "bom": "\ufeff",
    "escaped-double-quote": '\\"',
    "escaped-single-quote": "\\'",
    # Characters that end a free-text URL span or an unquoted token.
    "less-than": "<",
    "greater-than": ">",
    "double-quote": '"',
    "single-quote": "'",
    "backtick": "`",
}
_CLOSING = {"<": ">", "\uff02": "\uff02"}
PLACEMENTS = {
    "start": lambda insert: insert + LEFT + RIGHT,
    "middle": lambda insert: LEFT + insert + RIGHT,
    "end": lambda insert: LEFT + RIGHT + insert,
    "wrapped": lambda insert: insert + LEFT + RIGHT + _CLOSING.get(insert, insert),
}
POSITIONS = ("assignment", "flag-inline", "flag-separate", "header", "env", "userinfo", "query")


def _sources(position: str, secret: str) -> tuple[str, list[str], str | None]:
    """Free text, argv and URL field carrying the synthetic credential."""
    if position == "assignment":
        return f"config password={secret} ready", [f"password={secret}"], None
    if position == "flag-inline":
        return f"run --password={secret} --verbose", [f"--password={secret}", "--verbose"], None
    if position == "flag-separate":
        return f"run --password {secret} --verbose", ["--password", secret, "--verbose"], None
    if position == "header":
        return f"Authorization: Bearer {secret}", ["--header", f"Authorization: Bearer {secret}"], None
    if position == "env":
        return f"export API_TOKEN={secret} && run", [f"API_TOKEN={secret}"], None
    if position == "userinfo":
        url = f"https://user:{secret}@fixture.example/mcp"
    else:
        url = f"https://fixture.example/mcp?token={secret}"
    return f"Endpoint {url} ready", ["--url", url], url


def _report(text: str, args: list[str], url: str | None) -> AuditReport:
    server = make_server_config(
        name="synthetic-server",
        command="synthetic-fixture-server",
        args=args,
        url=url,
        transport=TransportType.STDIO if url is None else TransportType.HTTP,
    )
    tool = ToolInfo(
        name="synthetic-tool",
        description=text,
        input_schema={"type": "object", "properties": {"value": {"type": "string", "description": text}}},
        meta={"note": text},
    )
    # A pin of a different endpoint makes provenance copy the current URL.
    previous = make_server_config(name="synthetic-server", url="https://previous.example/mcp")
    provenance = (
        ProvenanceAnalyzer().analyze_server(server, PinStore(Path("unused"))._config_snapshot(previous))
        if url is not None
        else []
    )
    if url is not None:
        assert provenance, "URL drift must be reported against a different pinned endpoint"
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
                server=server, tools=[tool], connection_status="connected", provenance_findings=provenance
            )
        ],
        scan_duration_seconds=0,
        warnings=[ScanWarning(code="synthetic", message=text, check="connection")],
    )


def _forbidden(insert: str) -> list[str]:
    pieces = [LEFT, RIGHT, LEFT + RIGHT, *([OSC_PAYLOAD] if OSC_PAYLOAD in insert else [])]
    return sorted({piece[i : i + 6] for piece in pieces for i in range(len(piece) - 5)})


@pytest.mark.redteam
@pytest.mark.parametrize("position", POSITIONS)
@pytest.mark.parametrize("placement", list(PLACEMENTS))
@pytest.mark.parametrize("insert", list(INSERTS), ids=list(INSERTS))
def test_normalization_never_moves_a_redaction_boundary(
    insert: str, placement: str, position: str, tmp_path: Path
) -> None:
    secret = PLACEMENTS[placement](INSERTS[insert])
    text, args, url = _sources(position, secret)
    _assert_surfaces(text, args, url, _forbidden(INSERTS[insert]), tmp_path)


def _assert_surfaces(
    text: str, args: list[str], url: str | None, forbidden: list[str], tmp_path: Path
) -> None:
    """No forbidden piece on any surface; every structural path is idempotent."""
    report = _report(text, args, url)
    safe = report.redacted()

    terminal = StringIO()
    generator = ReportGenerator(Console(file=terminal, width=200, color_system=None))
    # Raw reports go to each public entry point, which must redact on its own.
    generator.render_terminal(report, verbose=True)
    generator.render_json(report, tmp_path / "report.json")
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(pin_file)
    snapshot = store._config_snapshot(report.audits[0].server)
    store.pin_server("synthetic-server", report.audits[0].tools, report.audits[0].server)
    outputs = {
        "model": safe.model_dump_json(),
        "json": (tmp_path / "report.json").read_text(),
        "terminal": terminal.getvalue(),
        "html": HtmlReportGenerator().generate(report),
        "sarif": json.dumps(SarifGenerator().generate(report)),
        "snapshot": json.dumps(snapshot),
        "pins": pin_file.read_text(),
        "excerpt": redacted_excerpt(text, 0, len(text), context_before=8, context_after=8),
        "definition": _server_definition_summary(report.audits[0].server),
    }
    for surface, output in outputs.items():
        for piece in forbidden:
            assert piece not in output, (surface, piece)

    # Redaction is idempotent on every structural path.
    assert safe.redacted().model_dump() == safe.model_dump()
    assert redact_text(redact_text(text)) == redact_text(text)
    once = redact_argv(cast(list[object], args))
    assert redact_argv(once) == once
    assert redact_data(once) == once
    if url is not None:
        assert redact_url(redact_url(url)) == redact_url(url)


# Escape sequences and controls placed right before a delimiter they may consume.
CONTROLS_BEFORE_DELIMITER = {
    "esc": "\x1b",
    "csi": "\x1b[",
    "c1-csi": "\x9b",
    "c1-osc": "\x9d",
    "osc": f"\x1b]0;{OSC_PAYLOAD}",
    "esc-esc": "\x1b\x1b",
}
_Source = Callable[[str, str], tuple[str, list[str], str | None]]
DELIMITER_SOURCES: dict[str, _Source] = {
    "assignment-equals": lambda c, v: (f"config password{c}={v} ready", [f"password{c}={v}"], None),
    "assignment-colon": lambda c, v: (f"config password{c}:{v} ready", [f"password{c}:{v}"], None),
    "flag-inline": lambda c, v: (f"run --password{c}={v} x", [f"--password{c}={v}", "x"], None),
    "quote": lambda c, v: (f'config password={c}"{v} {v}" ready', [f'password={c}"{v}"'], None),
    "header": lambda c, v: (f"Authorization{c}: Bearer {v}", [f"Authorization{c}: Bearer {v}"], None),
    "userinfo-at": lambda c, v: (
        f"Endpoint https://user:{v}{c}@fixture.example/mcp ready",
        ["--url", f"https://user:{v}{c}@fixture.example/mcp"],
        f"https://user:{v}{c}@fixture.example/mcp",
    ),
}


@pytest.mark.redteam
@pytest.mark.parametrize("source", list(DELIMITER_SOURCES))
@pytest.mark.parametrize("control", list(CONTROLS_BEFORE_DELIMITER))
def test_removed_bytes_never_hide_a_delimiter(control: str, source: str, tmp_path: Path) -> None:
    text, args, url = DELIMITER_SOURCES[source](CONTROLS_BEFORE_DELIMITER[control], LEFT + RIGHT)
    _assert_surfaces(text, args, url, _forbidden(OSC_PAYLOAD), tmp_path)


@pytest.mark.redteam
@pytest.mark.parametrize("space", [" ", "\t", "\u00a0", "  "], ids=["space", "tab", "nbsp", "two-spaces"])
@pytest.mark.parametrize("password", [LEFT + RIGHT, f"{LEFT}:{RIGHT}"], ids=["plain", "with-colon"])
def test_netloc_password_cut_from_its_at_sign_is_withheld(space: str, password: str, tmp_path: Path) -> None:
    url = f"https://user:{password}{space}@fixture.example/mcp"
    _assert_surfaces(f"Endpoint {url} ready", ["--url", url], url, _forbidden(""), tmp_path)


def test_inline_argv_cuts_after_raw_delimiter_through_leading_osc() -> None:
    value = f"--password=\x1b]0;{OSC_PAYLOAD}\x07ordinary-secret"
    assert redact_argv([value]) == ["--password=<redacted>"]
    assert redact_argv(redact_argv([value])) == ["--password=<redacted>"]


@pytest.mark.parametrize(
    "text, expected",
    [
        # A ';' inside the removed OSC is not a terminator; the value runs on.
        (f"password=\x1b]0;{OSC_PAYLOAD}\x07ordinary-secret tail", "password=<redacted> tail"),
        (f"password=\x1b[1;31m{OSC_PAYLOAD}\x1b[0m tail", "password=<redacted> tail"),
        # Removed bytes beside a value are replaced with it.
        ("password=\x1b[1mfixture-secret\x1b[0m tail", "password=<redacted> tail"),
        ('password="fixture-secret"\x1b[0m tail', "password=<redacted> tail"),
        ("Bearer \x1b[1mfixture-secret\x1b[0m", "Bearer <redacted>"),
        # Whitespace after a delimiter hides a removed sequence carrying ';':
        # the value extent is ambiguous, so the field is withheld.
        (f"password\uff1a\x1b]0;{OSC_PAYLOAD}\x07 tail", "<redacted>"),
        # A detected value that is empty only after control stripping.
        (f"--\uff50assword \x1b]0;{OSC_PAYLOAD}\x07, next", "--\uff50assword <redacted> next"),
        (f"password=\x1b]0;{OSC_PAYLOAD}", "password=<redacted>"),
    ],
    ids=[
        "leading-osc",
        "csi-params",
        "csi-around-value",
        "csi-after-quoted",
        "bearer-csi",
        "space-hidden-osc",
        "empty-flag-value",
        "unterminated-osc",
    ],
)
def test_removed_bytes_next_to_a_value_are_part_of_its_raw_span(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert redact_text(expected) == expected
    assert redacted_excerpt(text, 0, len(text)) in {expected, "[metadata excerpt withheld]"}


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [*_strings(key), *_strings(item)]]
    return []


_FIXTURES = Path(__file__).parents[1] / "fixtures/redaction"
_CORPUS = [
    *json.loads((_FIXTURES / "structural.json").read_text()),
    *json.loads((_FIXTURES / "final-round.json").read_text()),
]
_SWEEP = [
    _sources(position, PLACEMENTS[placement](insert))[0]
    for insert in INSERTS.values()
    for placement in PLACEMENTS
    for position in POSITIONS
]


def test_redaction_is_idempotent_over_the_whole_corpus() -> None:
    texts = sorted({*_strings(_CORPUS), *_SWEEP})
    assert len(texts) > len(_SWEEP)
    for text in texts:
        once = redact_text(text)
        assert redact_text(once) == once, text
        if "://" in text:
            url = redact_url(text)
            assert redact_url(url) == url, text
    for case in _CORPUS:
        for field in ("source", "args", "text"):
            if field in case:
                once_data = redact_data(case[field])
                assert redact_data(once_data) == once_data, case


@pytest.mark.parametrize(
    "text, expected",
    [
        # Unterminated quotes and escaped quotes never end a value early.
        ('password="fixture-secret tail', "password=<redacted>"),
        ('password=fixture\\"secret tail', "password=<redacted> tail"),
        ('password="fixture"secret tail', "password=<redacted> tail"),
        ('{"password":"fixture-secret"}', '{"password":<redacted>}'),
        # A terminator created by normalization leaves an empty value without a raw extent.
        ("pass\u200bword\uff1a\uff1a\u00a8fixture-secret", "<redacted>"),
        # A URL boundary that only normalization reveals is withheld.
        ("pass\u200bword\uff1a\uff0f\uff0ffixture-secret", "<redacted>"),
    ],
    ids=[
        "unterminated-quote",
        "escaped-quote",
        "quoted-then-unquoted",
        "json-closing-brace",
        "created-terminator",
        "created-url",
    ],
)
def test_raw_value_extent_is_complete(text: str, expected: str) -> None:
    assert redact_text(text) == expected
    assert redact_text(expected) == expected


def test_seeded_structural_fuzz_never_publishes_a_value_chunk() -> None:
    """Interleave value chunks with every insert under obfuscated labels."""
    rng = random.Random(20261011)
    inserts = list(INSERTS.values())
    labels = ["password", "\uff50assword", "pass\u200bword", "pass\x1b[31mword", "api_key", "--password"]
    delimiters = ["=", ":", "\uff1d", "\uff1a", ": ", '":"', '="', "='", "\x1b=", "\x1b:", "\x9b=", "\x1b[="]
    for _ in range(3000):
        chunks = ["".join(rng.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(6)) for _ in range(3)]
        value = "".join(
            "".join(rng.choice(inserts) for _ in range(rng.randint(0, 2))) + chunk for chunk in chunks
        )
        label, delimiter = rng.choice(labels), rng.choice(delimiters)
        prefix, suffix = rng.choice(["", "x ", "{"]), rng.choice(["", " tail", '"}'])
        text = prefix + label + delimiter + value + suffix
        outputs = [redact_text(text), redacted_excerpt(text, 0, len(text), context_after=len(text))]
        if label.startswith("--"):
            outputs.append(repr(redact_argv([text.removeprefix(prefix)])))
        for output in outputs:
            assert not any(chunk in output for chunk in chunks), (text, output)
        assert redact_text(outputs[0]) == outputs[0]


@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.test/path with spaces",
        " https://api.example.test/mcp ",
        "https://fixture.example/mcp?token=<opaque-secret>",
        "https://user:fixture-secret@fixture.example/mcp?mode=admin#fragment",
        "https://api.example.test/mcp",
    ],
)
def test_unchanged_url_has_no_drift_against_its_own_snapshot(url: str) -> None:
    server = make_server_config(name="synthetic-server", url=url, transport=TransportType.HTTP)
    snapshot = PinStore(Path("unused"))._config_snapshot(server)
    assert ProvenanceAnalyzer().analyze_server(server, snapshot) == []


@pytest.mark.parametrize("quote", ["<>", '""', "''", "``", "><"])
def test_truncated_url_never_splits_a_credential(quote: str) -> None:
    opening, closing = quote[0], quote[1]
    for url in (
        f"https://fixture.example/mcp?token={opening}opaque-secret{closing}",
        f"https://user:{opening}opaque-secret{closing}@fixture.example/mcp",
        f"https://fixture.example/mcp/token={opening}opaque-secret{closing}",
    ):
        for text in (url, f"Endpoint {url} ready"):
            redacted = redact_text(text)
            assert "opaque" not in redacted and "secret" not in redacted, (text, redacted)
            assert redact_text(redacted) == redacted
        assert redact_url(url) == "<redacted>" or "opaque" not in redact_url(url)
