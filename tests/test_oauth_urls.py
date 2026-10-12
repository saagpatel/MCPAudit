"""Shared OAuth URL and posture serialization behavior remains unchanged."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, Field

from mcp_audit import oauth_urls
from mcp_audit.authorization_posture_models import canonical_json_bytes


@pytest.mark.parametrize(
    "url",
    [
        "https://auth.fixture.test/tenant",
        "https://AUTH.fixture.test:8443/tenant?scope=read",
        "https://bücher.fixture.test/tenant",
    ],
)
def test_https_urls_preserve_input(url: str) -> None:
    assert oauth_urls.require_https_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        " https://auth.fixture.test",
        "https://auth.fixture.test/" + "a" * oauth_urls.MAX_URL_LENGTH,
        "http://auth.fixture.test",
        "https:///tenant",
        "https://user@auth.fixture.test",
        "https://auth.fixture.test/#fragment",
        "https://auth.fixture.test:invalid/",
        "https://auth.fixture.test:0/",
        "https://localhost./",
        "https://sub.localhost/",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://auth.fixture.test/\\path",
        "https://auth.fixture.test/%5Cpath",
        "https://auth.fixture.test/%00path",
        "https://auth.fixture.test/\npath",
    ],
)
def test_https_urls_reject_unsafe_input(url: str) -> None:
    with pytest.raises(ValueError):
        oauth_urls.require_https_url(url)


def test_https_query_policy() -> None:
    with pytest.raises(ValueError, match="query"):
        oauth_urls.require_https_url("https://auth.fixture.test/?scope=read", query_allowed=False)


@pytest.mark.parametrize(
    "resource,discovery,suffix",
    [
        ("/mcp/", "well-known-path", "/.well-known/oauth-protected-resource/mcp"),
        ("/mcp", "well-known-root", "/.well-known/oauth-protected-resource"),
        ("/", "well-known-root", "/.well-known/oauth-protected-resource"),
        ("/mcp", "www-authenticate", None),
    ],
)
def test_resource_metadata_locations(resource: str, discovery: str, suffix: str | None) -> None:
    result = oauth_urls.expected_resource_metadata_url("https://MCP.fixture.test:8443" + resource, discovery)
    assert result == ("https://mcp.fixture.test:8443" + suffix if suffix is not None else None)


@pytest.mark.parametrize(
    "path,discovery,suffix",
    [
        ("/", "rfc8414", "/.well-known/oauth-authorization-server"),
        ("/", "openid-connect", "/.well-known/openid-configuration"),
        ("/tenant/", "rfc8414-path-insertion", "/.well-known/oauth-authorization-server/tenant"),
        ("/tenant", "openid-connect-path-insertion", "/.well-known/openid-configuration/tenant"),
        ("/tenant", "openid-connect-path-append", "/tenant/.well-known/openid-configuration"),
    ],
)
def test_authorization_metadata_locations(path: str, discovery: str, suffix: str) -> None:
    assert oauth_urls.expected_authorization_metadata_url("https://AUTH.fixture.test" + path, discovery) == (
        "https://auth.fixture.test" + suffix
    )


def test_invalid_discovery_shapes_fail_closed() -> None:
    with pytest.raises(ValueError):
        oauth_urls.expected_resource_metadata_url("https://mcp.fixture.test/", "well-known-path")
    with pytest.raises(ValueError):
        oauth_urls.expected_authorization_metadata_url("https://auth.fixture.test/tenant", "rfc8414")
    with pytest.raises(ValueError):
        oauth_urls.expected_authorization_metadata_url("https://auth.fixture.test/", "rfc8414-path-insertion")


def test_canonical_posture_bytes_keep_model_and_number_policy() -> None:
    class Document(BaseModel):
        label: str = Field(serialization_alias="display_label")
        timestamp: datetime

    document = Document(label="café", timestamp=datetime(2026, 1, 1, tzinfo=UTC))
    expected = '{"label":"café","timestamp":"2026-01-01T00:00:00Z"}\n'.encode()
    assert oauth_urls.canonical_json_bytes(document) == expected
    assert canonical_json_bytes is oauth_urls.canonical_json_bytes
    assert oauth_urls.canonical_json_bytes({"z": [1], "a": "café"}) == '{"a":"café","z":[1]}\n'.encode()
    assert oauth_urls.canonical_json_bytes([float("nan")]) == b"[NaN]\n"
