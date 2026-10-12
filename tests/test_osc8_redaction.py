"""OSC 8 URIs are typed fields; link text remains ordinary detection text."""

import pytest

from mcp_audit.redaction import redact_text, redact_url


@pytest.mark.parametrize("introducer", ["\x1b]", "\x9d"])
@pytest.mark.parametrize("terminator", ["\x07", "\x1b\\", "\x9c"])
def test_osc8_uses_typed_uri_rules(introducer: str, terminator: str) -> None:
    for uri in (
        "https://fixture-user:fixture-password@fixture.example/long/"
        + "path/" * 30
        + "?mode=fixture-query#fixture-fragment",
        'https://fixture.example/path?mode=quoted"fixture-query',
        "https://fixture.example/path#fragment<fixture-fragment",
        "https://fixture.example：fixture-password/path",
        "not-a-url",
    ):
        opening = f"{introducer}8;id=docs;{uri}{terminator}"
        closing = f"{introducer}8;;{terminator}"
        expected = f"{introducer}8;id=docs;{redact_url(uri)}{terminator}Read docs{closing}"
        assert redact_text(opening + "Read docs" + closing) == expected
        assert redact_text(expected) == expected


def test_osc8_framing_cannot_hide_a_split_secret_label_or_value() -> None:
    opening = "\x1b]8;;https://fixture.example/" + "path/" * 30 + "\x07"
    closing = "\x1b]8;;\x07"
    source = f"pass{opening}word=fixture-{closing}secret tail"
    expected = f"pass{opening}word=<redacted> tail"
    assert redact_text(source) == expected
    assert redact_text(expected) == expected


def test_osc8_parameters_receive_ordinary_credential_detection() -> None:
    source = "\x1b]8;password=fixture-parameter;https://fixture.example/docs\x07Docs\x1b]8;;\x07"
    expected = "\x1b]8;password=<redacted>;https://fixture.example/docs\x07Docs\x1b]8;;\x07"
    assert redact_text(source) == expected
    assert redact_text(expected) == expected


@pytest.mark.parametrize(
    "sequence",
    [
        "\x1b]0;" + "x" * 65 + "\x07",
        "\x9d0;" + "x" * 65 + "\x9c",
        "\x1b[" + "1;" * 33 + "m",
        "\x1b]8;;https://fixture.example/" + "x" * 65,  # Unterminated OSC 8.
        "\x1b]8;" + "x" * 65 + "\x07",  # Missing URI separator.
        "\x1b]8;;https://fixture.example/\t" + "x" * 65 + "\x07",
        "\x1b]0;\x1b]8;;https://fixture.example/" + "x" * 65 + "\x07",
    ],
)
def test_other_long_or_malformed_escapes_stay_withheld(sequence: str) -> None:
    assert redact_text(sequence + "label tail") == "<redacted>"
