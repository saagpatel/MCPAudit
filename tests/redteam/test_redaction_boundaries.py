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
import re
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


# Pairwise composition: every perturbation class meets every other one in URL
# userinfo, URL query and assignment positions, through every surface at once.
_CUT = ['"', "'", "<", ">", "`"]
_CONTROL_DELIMITERS = [
    control + delimiter
    for control in ("\x1b", "\x1b[", "\x9b", "\x1b]0;x")
    for delimiter in ("=", ":", "@", '"')
]
_COMPAT = [
    "\uff02",
    "\uff0f",
    "\uff20",
    "\uff1a",
    "\uff1d",
    "\u00a8",
    "\u2024",
    "\ufe6b",
    "\uff03",
    "\uff1f",
    "\u200b",
]
_PERTURBATIONS = ["", *_CUT, *_CONTROL_DELIMITERS, *_COMPAT]
_SPACES_BEFORE_AT = ["", " ", "\t", "\u00a0"]
# Renderers consume report.redacted(); render every surface for one batch per class.
_RENDERED = {"", '"', "\x1b=", "\uff02"}


def _composed_cases(first: str, rng: random.Random) -> list[tuple[str, list[str], str | None, list[str]]]:
    cases: list[tuple[str, list[str], str | None, list[str]]] = []
    for second in _PERTURBATIONS:
        for position in ("userinfo", "query", "assignment"):
            # Whitespace before '@' pairs with every first perturbation.
            for space in _SPACES_BEFORE_AT if position == "userinfo" and not second else [""]:
                chunks = [
                    "".join(rng.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(7)) for _ in range(3)
                ]
                value = chunks[0] + first + chunks[1] + second + chunks[2]
                if position == "assignment":
                    text, args, url = f"config password={value} ready", [f"password={value}"], None
                else:
                    url = (
                        f"https://user:{value}{space}@fixture.example/mcp"
                        if position == "userinfo"
                        else f"https://fixture.example/mcp?token={value}"
                    )
                    text, args = f"Endpoint {url} ready", ["--url", url]
                cases.append((text, args, url, [chunk[i : i + 6] for chunk in chunks for i in range(2)]))
    return cases


@pytest.mark.redteam
@pytest.mark.parametrize("first", _PERTURBATIONS, ids=[repr(item) for item in _PERTURBATIONS])
def test_composed_perturbations_never_publish_a_credential(first: str, tmp_path: Path) -> None:
    cases = _composed_cases(first, random.Random(f"compose:{first}"))
    reports = [_report(text, args, url) for text, args, url, _ in cases]
    for index, report in enumerate(reports):
        report.audits[0].server.name = f"synthetic-server-{index}"
    report = reports[0].model_copy(
        update={
            "audits": [audit for item in reports for audit in item.audits],
            "warnings": [warning for item in reports for warning in item.warnings],
        }
    )
    store = PinStore(tmp_path / "pins.yaml")
    outputs = [
        report.redacted().model_dump_json(),
        json.dumps([store._config_snapshot(audit.server) for audit in report.audits]),
        *(_server_definition_summary(audit.server) for audit in report.audits),
    ]
    if first in _RENDERED:
        terminal = StringIO()
        generator = ReportGenerator(Console(file=terminal, width=200, color_system=None))
        generator.render_terminal(report, verbose=True)
        generator.render_json(report, tmp_path / "report.json")
        outputs += [
            (tmp_path / "report.json").read_text(),
            terminal.getvalue(),
            HtmlReportGenerator().generate(report),
            json.dumps(SarifGenerator().generate(report)),
        ]
    for text, args, url, _ in cases:
        once = redact_text(text)
        assert redact_text(once) == once, text
        argv = redact_argv(cast(list[object], args))
        assert redact_argv(argv) == argv, args
        outputs += [once, repr(argv), redacted_excerpt(text, 0, len(text), context_after=len(text))]
        if url is not None:
            outputs.append(redact_url(url))
    published = "\n".join(outputs)
    pattern = re.compile("|".join(piece for _, _, _, pieces in cases for piece in pieces))
    assert pattern.search(published) is None, pattern.findall(published)[:5]


@pytest.mark.parametrize("cut", ['"', "'", "<", ">", "`"])
@pytest.mark.parametrize("password", ["planted{cut}tail-secret", "{cut}planted-tail-secret"])
@pytest.mark.parametrize("space", [" ", "\t", "\u00a0"], ids=["space", "tab", "nbsp"])
def test_authority_cut_before_spaced_at_is_withheld(
    cut: str, password: str, space: str, tmp_path: Path
) -> None:
    url = f"https://user:{password.format(cut=cut)}{space}@fixture.example/mcp"
    text = f"Endpoint {url} ready"
    assert "secret" not in redact_text(text) and "planted" not in redact_text(text)
    _assert_surfaces(text, ["--url", url], url, ["planted", "tail-secret"], tmp_path)


# Sequences whose final (or only following) byte detection removes with them.
CONSUMING_SEQUENCES = {"csi": "\x1b[", "c1-csi": "\x9b", "csi-params": "\x1b[1;2", "bare-esc": "\x1b"}


@pytest.mark.parametrize("sequence", list(CONSUMING_SEQUENCES.values()), ids=list(CONSUMING_SEQUENCES))
@pytest.mark.parametrize("label", ["password", "token", "secret", "api_key"])
@pytest.mark.parametrize("split", [0, 1, -1], ids=["first", "second", "last"])
def test_label_letter_consumed_by_an_escape_sequence_is_still_a_label(
    sequence: str, label: str, split: int, tmp_path: Path
) -> None:
    # The sequence ends on a letter of the label, so detection text drops it.
    raw = label[: split % len(label)] + sequence + label[split % len(label) :]
    secret = LEFT + RIGHT
    text = f"config {raw}={secret} ready"
    _assert_surfaces(text, [f"--{raw}", secret, f"--{raw}={secret}"], None, _forbidden(""), tmp_path)
    assert redact_argv([f"--{raw}", secret])[1] == "<redacted>"
    schema = redact_data({"properties": {raw: {"type": "string", "default": secret}}, raw: secret})
    assert secret not in json.dumps(schema)


@pytest.mark.parametrize(
    "space",
    [" ", "  ", "\t", "\u00a0", "\u2003", "\u3000"],
    ids=["space", "spaces", "tab", "nbsp", "em", "ideographic"],
)
@pytest.mark.parametrize("wrap", ["{}", '"{}"', "({})", "<{}>", "'{}'"])
def test_userinfo_cut_from_its_at_by_spaces_is_redacted(space: str, wrap: str, tmp_path: Path) -> None:
    url = f"https://{LEFT}{RIGHT}{space}@fixture.example/mcp"
    text = "Endpoint " + wrap.format(url) + " ready"
    assert (
        redact_text(text)
        == "Endpoint " + wrap.format(f"https://<redacted>{space}@fixture.example/mcp") + " ready"
    )
    _assert_surfaces(text, ["--url", url], url, _forbidden(""), tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "\x1b[31mERROR\x1b[0m: timeout=30 retries=3",
        "\x9b31mwarn\x9b0m count=5",
        "\x1b[1mtokens\x1b[0m: 5",
        "\x1b[1mtokenizer\x1b[0m=bpe",
        "\x1b[1mauthor\x1b[0m=fixture",
        "\x1b[32mok\x1b[0m session_name=demo",
        "\x1b]8;;https://example.test/docs\x07docs\x1b]8;;\x07 mode=fast",
        "email me @ host",
        "contact @fixture about it",
        "see https://example.test/docs @fixture",
    ],
)
def test_ordinary_colored_text_and_prose_are_not_redacted(text: str) -> None:
    assert redact_text(text) == text
    assert redact_argv(["\x1b[1m--verbose\x1b[0m", "on", "--color", "\x1b[31mred\x1b[0m"]) == [
        "\x1b[1m--verbose\x1b[0m",
        "on",
        "--color",
        "\x1b[31mred\x1b[0m",
    ]
    schema = {"properties": {"\x1b[1mtimeout\x1b[0m": {"type": "integer", "default": "30"}}}
    assert redact_data(schema) == schema


# Every CSI parameter and intermediate byte, open (the next byte is consumed as
# the final byte) and closed by 'm', with 7-bit and C1 introducers.
CSI_PARAMETER_SEQUENCES = [
    introducer + chr(byte) + final
    for introducer in ("\x1b[", "\x9b")
    for byte in range(0x20, 0x40)
    for final in ("", "m")
]
_SWEEP_SECRET = LEFT + RIGHT
_SWEEP_TEXTS = [
    "run --password {secret} now",
    "config api_key={secret} ready",
    "token: {secret}",
    "https://fixture.example/a/password={secret}/x",
    "https://fixture.example/mcp?q={secret}",
    "https://fixture.example/mcp#{secret}",
    "Endpoint https://{secret} @fixture.example/mcp",
]


def _inserted(text: str) -> list[str]:
    """``text`` with each CSI sequence inserted at every position before the secret."""
    cut = text.index("{secret}")
    prefix, suffix = text[:cut], text[cut:].format(secret=_SWEEP_SECRET)
    return [
        prefix[:index] + sequence + prefix[index:] + suffix
        for index in range(cut + 1)
        for sequence in CSI_PARAMETER_SEQUENCES
    ]


@pytest.mark.parametrize("template", _SWEEP_TEXTS)
def test_csi_parameter_bytes_never_hide_a_structural_decision_in_text(template: str) -> None:
    forbidden = re.compile("|".join(_forbidden("")))
    for text in _inserted(template):
        once = redact_text(text)
        assert forbidden.search(once) is None, text
        assert redact_text(once) == once, text


@pytest.mark.parametrize(
    "args",
    [["--password", "{secret}"], ["--api_key={secret}"], ["token:{secret}"]],
    ids=["flag", "inline", "colon"],
)
def test_csi_parameter_bytes_never_hide_a_structural_decision_in_argv(args: list[str]) -> None:
    forbidden = re.compile("|".join(_forbidden("")))
    store = PinStore(Path("unused"))
    label = args[0].replace("{secret}", "")
    for argument in _inserted(label + "{secret}"):
        argv = (
            [argument[: len(argument) - len(_SWEEP_SECRET)], _SWEEP_SECRET] if len(args) == 2 else [argument]
        )
        once = redact_argv(cast(list[object], argv))
        snapshot = store._config_snapshot(make_server_config(args=argv))
        assert forbidden.search(repr(once)) is None, argv
        assert forbidden.search(json.dumps(snapshot)) is None, argv
        assert redact_argv(once) == once, argv


@pytest.mark.parametrize("label", ["password", "--password", "api_key", "token"])
def test_csi_parameter_bytes_never_hide_a_schema_or_json_key(label: str) -> None:
    forbidden = re.compile("|".join(_forbidden("")))
    for index in range(len(label) + 1):
        for sequence in CSI_PARAMETER_SEQUENCES:
            key = label[:index] + sequence + label[index:]
            data = {"properties": {key: {"type": "string", "default": _SWEEP_SECRET}}, key: _SWEEP_SECRET}
            assert forbidden.search(repr(redact_data(data))) is None, key


# Enough single-letter colour runs to push a window past the reading limit.
_OVER_READING_CAP = "".join(f"\x1b[m{letter}" for letter in "abcdefghijkl")
_FULLWIDTH = {"=": "＝", ":": "：", "@": "＠", "/": "／", "?": "？", "#": "＃"}
_FULLWIDTH |= {"-": "－", '"': "＂", "'": "＇"}
# A structural character that only one escape sequence reading supplies (the
# OSC "last character" reading); {pad} pushes that token's window past the cap.
_HIDDEN_STRUCTURAL = {
    "=": ["password{pad}\x1b]x{char}\x07{secret}"],
    ":": ["token{pad}\x1b]x{char}\x07 {secret}"],
    "@": ["Endpoint https://{secret} \x1b]x{char}\x07f{pad}ixture.example/mcp"],
    "/": ["https:/\x1b]x{char}\x07fixture.example/mcp?token={secret}{pad}"],
    "?": ["https://fixture.example/mcp\x1b]x{char}\x07token={secret}{pad}"],
    "#": ["https://fixture.example/mcp\x1b]x{char}\x07{secret}{pad}"],
    "-": ["run \x1b]x{char}\x07password{pad} {secret}"],
    '"': ["password=\x1b]x{char}\x07{secret}{pad} tail{char}"],
    "'": ["password=\x1b]x{char}\x07{secret}{pad} tail{char}"],
}


@pytest.mark.parametrize("cap", ["under-cap", "over-cap"])
@pytest.mark.parametrize("width", ["ascii", "fullwidth"])
@pytest.mark.parametrize("structural", list(_HIDDEN_STRUCTURAL))
def test_structural_byte_from_an_escape_is_judged_after_normalization(
    structural: str, width: str, cap: str
) -> None:
    char = _FULLWIDTH[structural] if width == "fullwidth" else structural
    pad = _OVER_READING_CAP if cap == "over-cap" else ""
    forbidden = re.compile("|".join(_forbidden("")))
    for template in _HIDDEN_STRUCTURAL[structural]:
        text = template.format(char=char, secret=_SWEEP_SECRET, pad=pad)
        once = redact_text(text)
        assert forbidden.search(once) is None, text
        assert redact_text(once) == once, text
    if structural == "-":
        assert redact_argv([f"\x1b]x{char}\x07password{pad}", _SWEEP_SECRET])[1] == "<redacted>"


_DELIMITER_ESCAPES = {
    "osc-bel": "\x1b]x{delimiter}\x07",
    "osc-st": "\x1b]0;x{delimiter}\x1b\\",
    "osc-unterminated": "\x1b]x{delimiter}",
    "bare-esc": "\x1b{delimiter}",
    "csi": "\x1b[1{delimiter}",
    "c1-csi": "\x9b{delimiter}",
    "wrapped": "\x1b[1m\x1b]x{delimiter}\x07\x1b[0m",
}


@pytest.mark.parametrize("escape", list(_DELIMITER_ESCAPES.values()), ids=list(_DELIMITER_ESCAPES))
@pytest.mark.parametrize("delimiter", [":", "=", "：", "＝"])
def test_escaped_delimiter_standing_alone_between_label_and_value(escape: str, delimiter: str) -> None:
    forbidden = re.compile("|".join(_forbidden("")))
    for label in ("password", "token", "api_key"):
        for left in range(4):
            for right in range(4):
                for value in (_SWEEP_SECRET, f'"{_SWEEP_SECRET} more"', f"'a {_SWEEP_SECRET}'"):
                    text = (
                        f"x {label}{' ' * left}{escape.format(delimiter=delimiter)}{' ' * right}{value} tail"
                    )
                    once = redact_text(text)
                    assert forbidden.search(once) is None, text
                    assert redact_text(once) == once, text


@pytest.mark.parametrize(
    "opening",
    [
        "\x1b]x{quote}\x07",
        "\x1b]0;x{quote}\x1b\\",
        "\x1b{quote}",
        "\x1b[1m\x1b]x{quote}\x07\x1b[0m",
        "{quote}",
    ],
    ids=["osc-bel", "osc-st", "bare-esc", "wrapped", "retained"],
)
@pytest.mark.parametrize("quote", ['"', "'", "＂", "＇"])
@pytest.mark.parametrize("delimiter", ["\x1b]x=\x07 ", "\x1b]x:\x07 ", "= "])
def test_quote_opened_by_an_escape_or_normalization_withholds_the_quoted_value(
    opening: str, quote: str, delimiter: str
) -> None:
    forbidden = re.compile("|".join(_forbidden("")))
    for body in (f"first {_SWEEP_SECRET}", f"a b {_SWEEP_SECRET} c", f"x\\ {_SWEEP_SECRET}"):
        for tail in ("", " tail", ' tail "x"'):
            text = f"x password {delimiter}{opening.format(quote=quote)}{body}{quote}{tail}"
            once = redact_text(text)
            assert forbidden.search(once) is None, text
            assert redact_text(once) == once, text
