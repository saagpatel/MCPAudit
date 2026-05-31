"""SSRF detection — flag tools/resources that may fetch caller-controlled targets.

This is a static, schema-derived signal. No network request is ever made and no
credential value is read. A finding means the *interface* lets a caller steer where
the server connects (the classic SSRF primitive: reaching internal services or cloud
metadata endpoints) — not that the server is exploitable.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from mcp_audit.models import (
    CapabilityTarget,
    ResourceInfo,
    SsrfFinding,
    SsrfSeverity,
    ToolInfo,
)

# Schemes where a caller-controlled host means the server reaches out over the network.
_REMOTE_SCHEMES = {"http", "https", "ws", "wss"}

# Param-name tokens that denote a URL/endpoint the server is expected to fetch.
_URL_TOKENS = {"url", "uri", "endpoint", "webhook", "callback", "href"}

# Property `format` values that mark a string as a URL.
_URL_FORMATS = {"uri", "url", "iri", "uri-reference", "uri-template"}

# Param-name tokens that denote a host/address target (weaker than a full URL).
_HOST_TOKENS = {"host", "hostname", "domain", "ip", "proxy", "upstream"}

# Verb roots (prefix match on word tokens) that signal a server-side fetch.
# Deliberately excludes weak/ambiguous roots like "http" and "request": they
# appear in most network tool descriptions and would inflate nearly every
# URL-param finding to HIGH. "webhook"/"callback" are URL tokens, not verbs.
_FETCH_VERB_ROOTS = (
    "fetch",
    "curl",
    "wget",
    "download",
    "proxy",
    "crawl",
    "scrape",
    "ping",
    "probe",
    "resolve",
    "retriev",
    "visit",
)

_WORD_RE = re.compile(r"[a-z0-9]+")
# camelCase / acronym boundaries, so "callbackUrl" and "targetURL" tokenize as
# {callback, url} / {target, url} instead of one merged token. MCP tool schemas
# are predominantly camelCase, so without this every camelCase URL param is missed.
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_ACRONYM_BOUNDARY = re.compile(r"([A-Z]+)([A-Z][a-z])")


def _word_tokens(text: str) -> list[str]:
    spaced = _ACRONYM_BOUNDARY.sub(r"\1_\2", _CAMEL_BOUNDARY.sub(r"\1_\2", text))
    return _WORD_RE.findall(spaced.lower())


def _tokens(text: str) -> list[str]:
    return _word_tokens(text)


def _key_tokens(key: str) -> set[str]:
    return set(_word_tokens(key))


def _is_url_param(key: str, prop: object) -> bool:
    if _key_tokens(key) & _URL_TOKENS:
        return True
    if isinstance(prop, dict):
        fmt = prop.get("format")
        if isinstance(fmt, str) and fmt.lower() in _URL_FORMATS:
            return True
    return False


def _is_host_param(key: str) -> bool:
    return bool(_key_tokens(key) & _HOST_TOKENS)


def _has_fetch_verb(*texts: str | None) -> bool:
    for text in texts:
        if not text:
            continue
        for token in _tokens(text):
            if any(token.startswith(root) for root in _FETCH_VERB_ROOTS):
                return True
    return False


class SsrfDetector:
    """Detects SSRF-prone capabilities from tool schemas and resource URIs."""

    def scan_tool(self, tool: ToolInfo) -> list[SsrfFinding]:
        """Return at most one SSRF finding for a single tool (highest applicable severity)."""
        if not isinstance(tool.input_schema, dict):
            return []
        props = tool.input_schema.get("properties")
        if not isinstance(props, dict):
            return []

        url_params = [str(k) for k in props if _is_url_param(str(k), props[k])]
        host_params = [str(k) for k in props if str(k) not in url_params and _is_host_param(str(k))]
        has_verb = _has_fetch_verb(tool.name, tool.description)

        if not url_params and not host_params:
            return []

        if url_params and has_verb:
            severity, pattern = SsrfSeverity.HIGH, "url_param_with_fetch_verb"
        elif url_params:
            severity, pattern = SsrfSeverity.MEDIUM, "url_param"
        elif host_params and has_verb:
            severity, pattern = SsrfSeverity.MEDIUM, "host_param_with_fetch_verb"
        else:
            severity, pattern = SsrfSeverity.LOW, "host_param"

        evidence = [f"URL-shaped parameter '{name}'" for name in url_params]
        evidence += [f"host/address parameter '{name}'" for name in host_params]
        if has_verb:
            evidence.append("server-side fetch verb in tool name or description")

        from mcp_audit.taxonomy import ssrf_metadata

        return [
            SsrfFinding(
                target_type=CapabilityTarget.TOOL,
                target_name=tool.name,
                severity=severity,
                pattern_name=pattern,
                evidence=evidence,
                description=ssrf_metadata(severity).description,
            )
        ]

    def scan_resource(self, resource: ResourceInfo) -> list[SsrfFinding]:
        """Return an SSRF finding for a remote resource URI with a caller-templated target."""
        uri = resource.uri
        try:
            parsed = urlparse(uri)
        except ValueError:
            # Malformed authority (e.g. bracketed non-IP host) — skip, never crash the scan.
            return []
        if parsed.scheme.lower() not in _REMOTE_SCHEMES:
            return []
        if "{" not in uri or "}" not in uri:
            return []

        # Strip any userinfo before checking the host authority, so a templated
        # credential (user:{password}@fixed-host) is not mistaken for a templated host.
        host_authority = parsed.netloc.rsplit("@", 1)[-1]
        if "{" in host_authority:
            severity, pattern = SsrfSeverity.HIGH, "remote_uri_host_template"
            evidence = [
                f"remote scheme '{parsed.scheme.lower()}'",
                f"caller-templated host authority '{parsed.netloc}'",
            ]
        elif "{" in parsed.path or "{" in parsed.query:
            severity, pattern = SsrfSeverity.LOW, "remote_uri_path_template"
            evidence = [
                f"remote scheme '{parsed.scheme.lower()}'",
                "caller-templated path on a fixed remote host",
            ]
        else:
            # Template variable is only in userinfo (e.g. a credential) — the
            # request destination is fixed, so this is not an SSRF signal.
            return []

        from mcp_audit.taxonomy import ssrf_metadata

        return [
            SsrfFinding(
                target_type=CapabilityTarget.RESOURCE,
                target_name=uri,
                severity=severity,
                pattern_name=pattern,
                evidence=evidence,
                description=ssrf_metadata(severity).description,
            )
        ]

    def scan_server(
        self,
        tools: list[ToolInfo],
        resources: list[ResourceInfo] | None = None,
    ) -> list[SsrfFinding]:
        """Return all SSRF findings across a server's tools and resources."""
        findings: list[SsrfFinding] = []
        for tool in tools:
            findings.extend(self.scan_tool(tool))
        for resource in resources or []:
            findings.extend(self.scan_resource(resource))
        return findings
