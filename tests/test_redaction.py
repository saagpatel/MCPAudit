"""Tests for centralized output redaction."""

from mcp_audit.redaction import redact_data, redact_text


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
