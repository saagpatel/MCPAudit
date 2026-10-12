"""Shared authorization URL rules and JSON bytes, independent of lab contracts."""

from __future__ import annotations

import ipaddress
from typing import Final
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel

from mcp_audit.canonical import compact_json_bytes

MAX_URL_LENGTH: Final = 2_048
MAX_AUTHORIZATION_SERVERS: Final = 8
MAX_FETCHES: Final = 32


def require_https_url(value: str, *, query_allowed: bool = True) -> str:
    if not value or value != value.strip() or len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is empty, padded, or too long")
    if "\\" in value or any(ord(character) < 32 for character in value):
        raise ValueError("URL contains a forbidden character")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL authority is malformed") from exc
    if parsed.scheme.lower() != "https" or not hostname:
        raise ValueError("URL must use HTTPS and include a host")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("URL user information and fragments are forbidden")
    if not query_allowed and parsed.query:
        raise ValueError("URL query is forbidden")
    try:
        normalized_host = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("URL host is invalid") from exc
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError("localhost URL authorities are forbidden")
    try:
        ipaddress.ip_address(normalized_host)
    except ValueError:
        pass
    else:
        raise ValueError("IP-literal URL authorities are forbidden")
    decoded_path = unquote(parsed.path or "/")
    if "\\" in decoded_path or any(ord(character) < 32 for character in decoded_path):
        raise ValueError("URL path contains a forbidden character")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("URL port is outside the valid range")
    return value


def origin(value: str) -> str:
    parsed = urlsplit(value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def expected_resource_metadata_url(resource: str, discovery: str) -> str | None:
    if discovery == "www-authenticate":
        return None
    parsed = urlsplit(resource)
    base_origin = origin(resource)
    resource_path = parsed.path.rstrip("/")
    if discovery == "well-known-path" and resource_path:
        return f"{base_origin}/.well-known/oauth-protected-resource{resource_path}"
    if discovery == "well-known-root":
        return f"{base_origin}/.well-known/oauth-protected-resource"
    raise ValueError("protected-resource discovery does not match the resource path")


def expected_authorization_metadata_url(issuer: str, discovery: str) -> str:
    parsed = urlsplit(issuer)
    base_origin = origin(issuer)
    issuer_path = parsed.path.strip("/")
    if not issuer_path:
        if discovery == "rfc8414":
            return f"{base_origin}/.well-known/oauth-authorization-server"
        if discovery == "openid-connect":
            return f"{base_origin}/.well-known/openid-configuration"
        raise ValueError("authorization-server discovery does not match a root issuer")
    if discovery == "rfc8414-path-insertion":
        return f"{base_origin}/.well-known/oauth-authorization-server/{issuer_path}"
    if discovery == "openid-connect-path-insertion":
        return f"{base_origin}/.well-known/openid-configuration/{issuer_path}"
    if discovery == "openid-connect-path-append":
        return f"{base_origin}/{issuer_path}/.well-known/openid-configuration"
    raise ValueError("authorization-server discovery does not match an issuer path")


def canonical_json_bytes(value: object) -> bytes:
    """Retain authorization-posture model encoding and its terminal newline."""
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return compact_json_bytes(payload, allow_nan=True) + b"\n"
