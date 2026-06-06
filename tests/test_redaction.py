"""Tests for centralized output redaction."""

from mcp_audit.redaction import redact_data, redact_identifiers, redact_text


def test_redacts_secret_assignments() -> None:
    text = "failed with token=abc123 and api_key: sk-test"
    redacted = redact_text(text)
    assert "abc123" not in redacted
    assert "sk-test" not in redacted
    assert "token=<redacted>" in redacted


def test_redacts_bearer_tokens() -> None:
    redacted = redact_text("Authorization: Bearer abc.def.ghi")
    assert redacted == "Authorization: Bearer <redacted>"


def test_redacts_url_userinfo() -> None:
    redacted = redact_text("https://user:password@example.com/mcp")
    assert redacted == "https://<redacted>@example.com/mcp"


def test_redacts_nested_data() -> None:
    data = {"tools": [{"description": "password=super-secret"}]}
    redacted = redact_data(data)
    assert redacted["tools"][0]["description"] == "password=<redacted>"


def test_redact_identifiers_scrubs_hostname() -> None:
    data = {"hostname": "Ds-MacBook.local", "note": "scanned on Ds-MacBook.local"}
    out = redact_identifiers(data, hostname="Ds-MacBook.local")
    assert out["hostname"] == "<redacted-host>"
    assert out["note"] == "scanned on <redacted-host>"
    assert "Ds-MacBook.local" not in str(out)


def test_redact_identifiers_scrubs_unix_home_usernames() -> None:
    data = {
        "config_path": "/Users/alice/.claude.json",
        "command": "/home/bob/.local/bin/server",
    }
    out = redact_identifiers(data, hostname=None)
    assert out["config_path"] == "/Users/<redacted>/.claude.json"
    assert out["command"] == "/home/<redacted>/.local/bin/server"


def test_redact_identifiers_scrubs_windows_home_username() -> None:
    data = {"config_path": r"C:\Users\carol\AppData\mcp.json"}
    out = redact_identifiers(data, hostname=None)
    assert out["config_path"] == r"C:\Users\<redacted>\AppData\mcp.json"


def test_redact_identifiers_preserves_non_identifying_values() -> None:
    data = {
        "os_platform": "Darwin",
        "servers_discovered": 24,
        "finding_type": "package_runner_source_review",
    }
    out = redact_identifiers(data, hostname="some-host")
    assert out == data


def test_redact_identifiers_recurses_lists_and_dicts() -> None:
    data = {"audits": [{"server": {"config_path": "/Users/dave/x.json"}}]}
    out = redact_identifiers(data, hostname=None)
    assert out["audits"][0]["server"]["config_path"] == "/Users/<redacted>/x.json"
