"""SSRF detection — flag tools/resources that may fetch caller-controlled targets.

This is a static, schema-derived signal. No network request is ever made and no
credential value is read. A finding means the *interface* lets a caller steer where
the server connects (the classic SSRF primitive: reaching internal services or cloud
metadata endpoints) — not that the server is exploitable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from mcp_audit.models import (
    CapabilityTarget,
    ResourceInfo,
    SsrfFinding,
    SsrfSeverity,
    ToolInfo,
)

# Schemes where a caller-controlled host means the server reaches out over the
# network — i.e. a templated host is a genuine SSRF target. Kept aligned with
# analyzer._REMOTE_RESOURCE_SCHEMES so a templated DB/cache/bucket/git host (which
# can point the server at an internal or attacker-controlled endpoint just as a
# URL can) is flagged, not just web/websocket URIs.
_REMOTE_SCHEMES = {
    "az",
    "azure",
    "git",
    "github",
    "gs",
    "http",
    "https",
    "mongodb",
    "mysql",
    "postgres",
    "postgresql",
    "redis",
    "s3",
    "ws",
    "wss",
}

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

# Input schemas are untrusted. These limits are deliberately well above normal
# MCP schemas while keeping traversal deterministic under schema amplification.
_MAX_SCHEMA_NODES = 2_048
_MAX_SCHEMA_DEPTH = 64
_MAX_SCHEMA_PROPERTIES = 4_096


@dataclass
class _SchemaWalkResult:
    properties: list[tuple[str, str, object]]
    incomplete_reasons: list[str]


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


def _resolve_local_ref(root: dict[str, object], ref: str) -> dict[str, object] | None:
    """Resolve one same-document JSON Pointer without loading external data."""
    if ref == "#":
        return root
    if not ref.startswith("#/"):
        return None
    current: object = root
    for raw_token in ref[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return None
    return current if isinstance(current, dict) else None


def _iter_schema_properties(schema: dict[str, object]) -> _SchemaWalkResult:
    """Return named properties from reachable, bounded JSON Schema branches.

    MCP tool inputs routinely nest request targets inside objects, arrays, and
    composition keywords. Definition registries are traversed only through a
    local ``$ref``, so unused definitions cannot manufacture findings. Cycles
    are stopped by branch ancestry and explicit node/depth/property budgets.
    Any unresolved reference or exhausted budget is returned to the caller as
    visible incomplete-analysis evidence.
    """
    found: list[tuple[str, str, object]] = []
    incomplete: set[str] = set()
    stack: list[tuple[dict[str, object], str, int, frozenset[int]]] = [
        (schema, "", 0, frozenset()),
    ]
    visited_nodes = 0
    property_count = 0

    while stack:
        if visited_nodes >= _MAX_SCHEMA_NODES:
            incomplete.add(f"node budget exceeded ({_MAX_SCHEMA_NODES})")
            break
        node, prefix, depth, ancestors = stack.pop()
        if depth > _MAX_SCHEMA_DEPTH:
            incomplete.add(f"depth budget exceeded ({_MAX_SCHEMA_DEPTH})")
            continue
        identity = id(node)
        if identity in ancestors:
            continue
        visited_nodes += 1
        branch = ancestors | {identity}

        ref = node.get("$ref")
        if isinstance(ref, str):
            resolved = _resolve_local_ref(schema, ref)
            if resolved is None:
                incomplete.add(f"unresolved or external reference: {ref}")
            else:
                stack.append((resolved, prefix, depth + 1, branch))

        for keyword in ("$dynamicRef", "$recursiveRef"):
            dynamic_ref = node.get(keyword)
            if isinstance(dynamic_ref, str):
                incomplete.add(f"unsupported dynamic reference {keyword}: {dynamic_ref}")

        properties = node.get("properties")
        if isinstance(properties, dict):
            nested: list[tuple[dict[str, object], str, int, frozenset[int]]] = []
            property_budget_exhausted = False
            for raw_name, property_schema in properties.items():
                if property_count >= _MAX_SCHEMA_PROPERTIES:
                    incomplete.add(
                        f"property budget exceeded ({_MAX_SCHEMA_PROPERTIES})",
                    )
                    property_budget_exhausted = True
                    break
                name = str(raw_name)
                path = f"{prefix}.{name}" if prefix else name
                found.append((path, name, property_schema))
                property_count += 1
                if isinstance(property_schema, dict):
                    nested.append((property_schema, path, depth + 1, branch))
            if property_budget_exhausted:
                break
            stack.extend(reversed(nested))

        for keyword, suffix in (
            ("additionalProperties", ".*"),
            ("contains", "[]"),
            ("unevaluatedItems", "[]"),
            ("unevaluatedProperties", ".*"),
        ):
            child = node.get(keyword)
            if isinstance(child, dict):
                stack.append((child, f"{prefix}{suffix}", depth + 1, branch))

        items = node.get("items")
        if isinstance(items, dict):
            stack.append((items, f"{prefix}[]", depth + 1, branch))
        elif isinstance(items, list):
            stack.extend(
                (child, f"{prefix}[{index}]", depth + 1, branch)
                for index, child in reversed(list(enumerate(items)))
                if isinstance(child, dict)
            )

        for keyword in ("allOf", "anyOf", "oneOf"):
            children = node.get(keyword)
            if isinstance(children, list):
                stack.extend(
                    (child, prefix, depth + 1, branch)
                    for child in reversed(children)
                    if isinstance(child, dict)
                )

        prefix_items = node.get("prefixItems")
        if isinstance(prefix_items, list):
            stack.extend(
                (child, f"{prefix}[{index}]", depth + 1, branch)
                for index, child in reversed(list(enumerate(prefix_items)))
                if isinstance(child, dict)
            )

        for keyword in ("dependentSchemas", "patternProperties"):
            children = node.get(keyword)
            if isinstance(children, dict):
                stack.extend(
                    (child, f"{prefix}.*", depth + 1, branch)
                    for child in reversed(list(children.values()))
                    if isinstance(child, dict)
                )

        for keyword in ("else", "if", "not", "then"):
            child = node.get(keyword)
            if isinstance(child, dict):
                stack.append((child, prefix, depth + 1, branch))

    return _SchemaWalkResult(found, sorted(incomplete))


class SsrfDetector:
    """Detects SSRF-prone capabilities from tool schemas and resource URIs."""

    def scan_tool(self, tool: ToolInfo) -> list[SsrfFinding]:
        """Return at most one SSRF finding for a single tool (highest applicable severity)."""
        if not isinstance(tool.input_schema, dict):
            return []

        walk = _iter_schema_properties(tool.input_schema)
        url_params = [path for path, name, schema in walk.properties if _is_url_param(name, schema)]
        host_params = [
            path for path, name, _schema in walk.properties if path not in url_params and _is_host_param(name)
        ]
        has_verb = _has_fetch_verb(tool.name, tool.description)

        if not url_params and not host_params:
            if not walk.incomplete_reasons:
                return []
            severity, pattern = (
                SsrfSeverity.MEDIUM,
                "schema_traversal_incomplete",
            )
        elif url_params and has_verb:
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
        evidence += [f"schema traversal incomplete: {reason}" for reason in walk.incomplete_reasons]

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


def parse_host_allowlist(raw: str | None) -> set[str]:
    """Parse a comma-separated host allowlist into a normalised lowercase set.

    Entries are hostnames (no scheme/port). Empty/whitespace entries are dropped.
    Returns an empty set for None/empty input (meaning: no allowlist, no effect).
    """
    if not raw:
        return set()
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def fixed_host_from_uri(uri: str) -> str | None:
    """Extract a fixed (non-templated) host from a URI string, or None.

    Returns None for a non-URI string (no ``://`` scheme separator), a malformed
    authority, or a caller-templated host authority (``{host}``) — a caller-steerable
    target is never allowlistable. Any userinfo is stripped before the host is read,
    and a trailing ``:port`` (or an IPv6 literal's brackets) is removed. The returned
    host is lowercased.

    Shared host-truth for both SSRF allowlisting and egress destination analysis, so
    the two detectors never disagree about what host a target resolves to.
    """
    if "://" not in uri:
        return None
    try:
        parsed = urlparse(uri)
    except ValueError:
        return None
    netloc = parsed.netloc.rsplit("@", 1)[-1]  # drop any userinfo
    if not netloc or "{" in netloc:
        return None  # templated / caller-controlled host — not allowlistable
    host = netloc
    if host.startswith("[") and "]" in host:  # IPv6 literal [::1]:port
        host = host[1 : host.index("]")]
    elif ":" in host:  # strip :port
        host = host.rsplit(":", 1)[0]
    return host.lower() or None


def _finding_fixed_host(finding: SsrfFinding) -> str | None:
    """Extract a fixed (non-templated) target host from an SSRF finding, or None.

    Only resource findings whose ``target_name`` is a URI with a concrete host
    authority yield a host. Tool findings (caller-controlled URL/host params) and
    findings whose host authority is itself templated (``{host}``) yield None — a
    caller-steerable target is never allowlistable, so it can never be suppressed.
    """
    return fixed_host_from_uri(finding.target_name)


def host_in_allowlist(host: str, allowlist: set[str]) -> bool:
    """True if ``host`` exactly matches an allowlist entry or is a subdomain of one."""
    host = host.lower()
    return any(host == entry or host.endswith("." + entry) for entry in allowlist)


def filter_allowlisted_ssrf(
    findings: list[SsrfFinding], allowlist: set[str]
) -> tuple[list[SsrfFinding], int]:
    """Suppress SSRF findings whose fixed target host is in the allowlist.

    Returns ``(kept_findings, suppressed_count)``. A finding is suppressed only
    when it has a concrete, non-templated target host that is allowlisted; findings
    with caller-controlled targets are always kept. An empty allowlist is a no-op.
    """
    if not allowlist:
        return list(findings), 0
    kept: list[SsrfFinding] = []
    suppressed = 0
    for finding in findings:
        host = _finding_fixed_host(finding)
        if host is not None and host_in_allowlist(host, allowlist):
            suppressed += 1
        else:
            kept.append(finding)
    return kept, suppressed
