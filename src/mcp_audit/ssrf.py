"""SSRF detection — flag tools/resources that may fetch caller-controlled targets.

This is a static, schema-derived signal. No network request is ever made and no
credential value is read. A finding means the *interface* lets a caller steer where
the server connects (the classic SSRF primitive: reaching internal services or cloud
metadata endpoints) — not that the server is exploitable.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator
from dataclasses import dataclass
from urllib.parse import urlparse

from mcp_audit.models import (
    CapabilityTarget,
    ResourceInfo,
    SsrfFinding,
    SsrfSeverity,
    ToolInfo,
)
from mcp_audit.normalize import invisible_class, normalize_text
from mcp_audit.redaction import redacted_excerpt
from mcp_audit.text_limits import bounded_text

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

# Input schemas are untrusted. These limits are deliberately well above normal
# MCP schemas while keeping traversal deterministic under schema amplification.
_MAX_SCHEMA_NODES = 2_048
_MAX_SCHEMA_DEPTH = 64
_MAX_SCHEMA_PROPERTIES = 4_096


@dataclass
class _SchemaWalkResult:
    properties: list[tuple[str, str, object]]
    incomplete_reasons: list[str]


def _split_words(text: str) -> list[str]:
    """Split words and camel/acronym boundaries in one linear pass."""
    spaced: list[str] = []
    for index, char in enumerate(text):
        if index:
            previous = text[index - 1]
            following = text[index + 1] if index + 1 < len(text) else ""
            camel_boundary = (previous.isascii() and (previous.islower() or previous.isdigit())) and (
                char.isascii() and char.isupper()
            )
            acronym_boundary = (
                previous.isascii()
                and previous.isupper()
                and char.isascii()
                and char.isupper()
                and following.isascii()
                and following.islower()
            )
            if camel_boundary or acronym_boundary:
                spaced.append("_")
        spaced.append(char)
    return _WORD_RE.findall("".join(spaced).lower())


_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9\x00]+")


def _word_tokens(text: str, vocabulary: Collection[str] = ()) -> list[str]:
    """Tokens of the raw text, then any new tokens of its normalized readings.

    Raw tokens treat any non-alphanumeric character, invisible ones included,
    as a word break, so ``target\u200burl`` yields ``url``. For non-ASCII text,
    NFKC compatibility forms and curated confusables are folded to ASCII and the
    folded text is read twice, with each invisible codepoint as a word break and
    as nothing (``u\u200brl`` yields ``url``).

    A word that contains an invisible codepoint is adversarial, so any
    ``vocabulary`` entry found as a substring of its folded, invisible-free,
    lowercased skeleton is also a token: ``target\u200bu\u200brlValue`` yields
    ``url`` and ``Please\u200bf\u200betchsomething`` yields ``fetch``. Clean
    words keep exact-token matching. Callers pass only words that raise a
    detection and keep the raw text for evidence.
    """
    raw = _split_words(text)
    if text.isascii():  # ASCII has no invisible or compatibility codepoints
        return raw
    # Mark invisibles with NUL (kept by normalize_text) before folding the rest.
    marked = normalize_text("".join("\x00" if invisible_class(char) else char for char in text))
    tokens = dict.fromkeys(raw)
    for reading in (marked.replace("\x00", " "), marked.replace("\x00", "")):
        tokens.update(dict.fromkeys(_split_words(reading)))
    if vocabulary:
        for chunk in _ALNUM_RUN_RE.findall(marked):
            if "\x00" in chunk:
                skeleton = chunk.replace("\x00", "").lower()
                tokens.update(dict.fromkeys(word for word in vocabulary if word in skeleton))
    return list(tokens)


# Words matched as substrings of obfuscated parameter names (see _word_tokens).
_PARAM_VOCABULARY = frozenset(_URL_TOKENS | _HOST_TOKENS)


def _tokens(text: str) -> list[str]:
    return _word_tokens(text, _FETCH_VERB_ROOTS)


def _key_tokens(key: str, vocabulary: Collection[str] = _PARAM_VOCABULARY) -> set[str]:
    return set(_word_tokens(key, vocabulary))


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
        for token in _tokens(bounded_text(text)):
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


_MAX_POINTER_CHARS = 4_096
# Child slots (including non-object values such as boolean schemas) examined
# across one index build. Bounds time and work on wide containers.
_MAX_POINTER_INDEX_SLOTS = 8 * _MAX_SCHEMA_NODES


def _schema_pointer_index(root: dict[str, object]) -> dict[int, str]:
    """Map schema objects inside ``root`` to their escaped JSON Pointers.

    Follows only schema-bearing keywords (never instance payloads such as
    ``examples`` or ``default``). Children are visited lazily, one slot at a
    time: non-object values are skipped before anything is built, the slot,
    node, depth and pointer-length budgets are checked before a child's
    pointer is constructed, and no per-node children list is materialised. A
    schema object outside the budget gets no pointer, which callers report as
    an unresolved reference.
    """
    # Imported here because schema_rules imports this module.
    from mcp_audit.schema_rules import (
        _SCHEMA_ARRAY_KEYWORDS,
        _SCHEMA_MAP_KEYWORDS,
        _SINGLE_SCHEMA_KEYWORDS,
    )

    def escape(token: object) -> str:
        return str(token).replace("~", "~0").replace("/", "~1")

    def child_slots(node: dict[str, object]) -> Iterator[tuple[str, object, object]]:
        """Yield (keyword, key or index or None, child) lazily."""
        for keyword in (*_SCHEMA_MAP_KEYWORDS, "$defs", "definitions"):
            members = node.get(keyword)
            if isinstance(members, dict):
                for key, child in members.items():
                    yield keyword, key, child
        for keyword in _SCHEMA_ARRAY_KEYWORDS:
            members = node.get(keyword)
            if isinstance(members, list):
                for position, child in enumerate(members):
                    yield keyword, position, child
        for keyword in _SINGLE_SCHEMA_KEYWORDS:
            yield keyword, None, node.get(keyword)
        items = node.get("items")
        if isinstance(items, list):
            for position, child in enumerate(items):
                yield "items", position, child

    index: dict[int, str] = {id(root): ""}
    stack: list[tuple[dict[str, object], str, int]] = [(root, "", 0)]
    slots = 0
    while stack:
        node, pointer, depth = stack.pop()
        if depth >= _MAX_SCHEMA_DEPTH:
            continue
        for keyword, key, child in child_slots(node):
            slots += 1
            if slots > _MAX_POINTER_INDEX_SLOTS:
                return index
            if not isinstance(child, dict) or id(child) in index:
                continue
            if len(index) >= _MAX_SCHEMA_NODES:
                return index
            suffix_length = len(keyword) + 1 + (len(str(key)) + 1 if key is not None else 0)
            if len(pointer) + suffix_length > _MAX_POINTER_CHARS:
                continue
            child_pointer = f"{pointer}/{keyword}" if key is None else f"{pointer}/{keyword}/{escape(key)}"
            if len(child_pointer) > _MAX_POINTER_CHARS:  # escaping can lengthen the key
                continue
            index[id(child)] = child_pointer
            stack.append((child, child_pointer, depth + 1))
    return index


def _iter_schema_properties(schema: dict[str, object], *, pointer_paths: bool = False) -> _SchemaWalkResult:
    """Return named properties from reachable, bounded JSON Schema branches.

    MCP tool inputs routinely nest request targets inside objects, arrays, and
    composition keywords. Definition registries are traversed only through a
    local ``$ref``, so unused definitions cannot manufacture findings. Cycles
    are stopped by branch ancestry and explicit node/depth/property budgets.
    Any unresolved reference or exhausted budget is returned to the caller as
    visible incomplete-analysis evidence.
    ``pointer_paths`` addresses the schema objects with JSON Pointers instead
    of the logical parameter paths used by SSRF findings.
    """
    found: list[tuple[str, str, object]] = []
    incomplete: set[str] = set()
    stack: list[tuple[dict[str, object], str, int, frozenset[int]]] = [
        (schema, "", 0, frozenset()),
    ]
    visited_nodes = 0
    property_count = 0
    anchor_cache: dict[int, dict[str, dict[str, object] | None] | None] = {}
    pointer_index: dict[int, str] | None = None

    def child_path(prefix: str, keyword: str, suffix: str, index: object | None = None) -> str:
        if pointer_paths:
            path = f"{prefix}/{keyword}"
            return f"{path}/{str(index).replace('~', '~0').replace('/', '~1')}" if index is not None else path
        return f"{prefix}{suffix}"

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
            ref_pointer = ref[1:]
            if resolved is None and ref.startswith("#"):
                # `$anchor` and percent-encoded pointers: resolve them the way the
                # schema metadata rules do, so both walkers reach the same nodes.
                # Imported here because schema_rules imports this module.
                from mcp_audit.schema_rules import local_reference_target

                target = local_reference_target(schema, ref, anchor_cache)
                # Field paths must address the target itself, so an anchor or an
                # encoded pointer yields the same path as the plain pointer form.
                # Paths are only built when the caller asked for pointer paths.
                if target is not None and not pointer_paths:
                    resolved = target
                elif target is not None:
                    if pointer_index is None:
                        pointer_index = _schema_pointer_index(schema)
                    target_pointer = pointer_index.get(id(target))
                    if target_pointer is not None:
                        resolved, ref_pointer = target, target_pointer
            if resolved is None:
                incomplete.add(f"unresolved or external reference: {ref}")
            else:
                stack.append((resolved, ref_pointer if pointer_paths else prefix, depth + 1, branch))

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
                path = (
                    child_path(prefix, "properties", "", name)
                    if pointer_paths
                    else f"{prefix}.{name}"
                    if prefix
                    else name
                )
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
                stack.append((child, child_path(prefix, keyword, suffix), depth + 1, branch))

        items = node.get("items")
        if isinstance(items, dict):
            stack.append((items, child_path(prefix, "items", "[]"), depth + 1, branch))
        elif isinstance(items, list):
            stack.extend(
                (child, child_path(prefix, "items", f"[{index}]", index), depth + 1, branch)
                for index, child in reversed(list(enumerate(items)))
                if isinstance(child, dict)
            )

        for keyword in ("allOf", "anyOf", "oneOf"):
            children = node.get(keyword)
            if isinstance(children, list):
                stack.extend(
                    (child, child_path(prefix, keyword, "", index), depth + 1, branch)
                    for index, child in reversed(list(enumerate(children)))
                    if isinstance(child, dict)
                )

        prefix_items = node.get("prefixItems")
        if isinstance(prefix_items, list):
            stack.extend(
                (child, child_path(prefix, "prefixItems", f"[{index}]", index), depth + 1, branch)
                for index, child in reversed(list(enumerate(prefix_items)))
                if isinstance(child, dict)
            )

        for keyword in ("dependentSchemas", "patternProperties"):
            children = node.get(keyword)
            if isinstance(children, dict):
                stack.extend(
                    (child, child_path(prefix, keyword, ".*", key), depth + 1, branch)
                    for key, child in reversed(list(children.items()))
                    if isinstance(child, dict)
                )

        for keyword in ("else", "if", "not", "then"):
            child = node.get(keyword)
            if isinstance(child, dict):
                stack.append((child, child_path(prefix, keyword, ""), depth + 1, branch))

    return _SchemaWalkResult(found, sorted(incomplete))


# RFC 3986 Appendix B: splits any string into scheme, authority, path, query and
# fragment without validating the parts. It always matches.
_URI_PARTS_RE = re.compile(r"^(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?$", re.DOTALL)


@dataclass(frozen=True)
class UriParts:
    """URI components for metadata analysis, as ``urlparse`` names them."""

    scheme: str
    netloc: str
    path: str
    query: str
    hostname: str


def split_uri(uri: str) -> UriParts:
    """Split a server-supplied URI, falling back when ``urlparse`` rejects it.

    ``urlparse`` raises ``ValueError`` for some authorities (Python 3.14 validates
    bracketed hosts such as ``[{host}]``). Resource URIs are untrusted metadata, so
    analysis must still see their parts instead of crashing or skipping them: the
    fallback splits by the RFC 3986 grammar and derives the host from the authority.
    """
    try:
        parsed = urlparse(uri)
        return UriParts(parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.hostname or "")
    except ValueError:
        match = _URI_PARTS_RE.match(uri)
        if match is None:  # unreachable: the Appendix B pattern matches every string
            return UriParts("", "", uri, "", "")
        scheme, netloc, path, query = (match.group(i) or "" for i in (1, 2, 3, 4))
        host = netloc.rsplit("@", 1)[-1]
        if host.startswith("["):
            host = host[1:].split("]", 1)[0]
        else:
            host = host.split(":", 1)[0]
        return UriParts(scheme, netloc, path, query, host.lower())


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

        evidence = [f"URL-shaped parameter '{redacted_excerpt(name, 0, len(name))}'" for name in url_params]
        evidence += [
            f"host/address parameter '{redacted_excerpt(name, 0, len(name))}'" for name in host_params
        ]
        if has_verb:
            evidence.append("server-side fetch verb in tool name or description")
        evidence += [
            f"schema traversal incomplete: {redacted_excerpt(reason, 0, len(reason))}"
            for reason in walk.incomplete_reasons
        ]

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
        # split_uri never raises: a malformed authority (e.g. a bracketed template
        # host) is still classified instead of being skipped.
        parsed = split_uri(uri)
        if parsed.scheme.lower() not in _REMOTE_SCHEMES:
            return []
        if "{" not in uri or "}" not in uri:
            return []

        # Strip any userinfo before checking the host authority, so a templated
        # credential (user:{password}@fixed-host) is not mistaken for a templated host.
        host_authority = parsed.netloc.rsplit("@", 1)[-1]
        if "{" in host_authority:
            severity, pattern = SsrfSeverity.HIGH, "remote_uri_host_template"
            safe_authority = split_uri(redacted_excerpt(uri, 0, len(uri))).netloc
            evidence = [
                f"remote scheme '{parsed.scheme.lower()}'",
                f"caller-templated host authority '{safe_authority}'",
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


# Authority-less shorthands whose destination host the scheme implies, as in the
# npm-style ``github:owner/repo``. Everything after the colon is a path on that host.
_IMPLIED_HOSTS = {"github": "github.com"}
# Characters urlparse removes anywhere in a URL before splitting it.
_URI_STRIPPED_CONTROLS = str.maketrans("", "", "\t\r\n")


def fixed_host_from_uri(uri: str) -> str | None:
    """Extract a fixed (non-templated) host from a URI string, or None.

    Returns None for a non-URI string (no ``://`` scheme separator), a malformed
    authority, or a caller-templated host authority (``{host}``) — a caller-steerable
    target is never allowlistable. Any userinfo is stripped before the host is read,
    and a trailing ``:port`` (or an IPv6 literal's brackets) is removed. The returned
    host is lowercased. An authority-less shorthand (``github:owner/{repo}``) resolves
    to the host its scheme implies, so a template there is a path template, as SSRF
    classifies it.

    Shared host-truth for both SSRF allowlisting and egress destination analysis, so
    the two detectors never disagree about what host a target resolves to.
    """
    # Only a clean shorthand gets the implied host. Read the scheme and authority with
    # the parser scan_resource uses, which drops embedded tab, CR and LF, so
    # "github:\n//{host}/x" has a (templated) authority; and refuse any "//" or backslash
    # that another parser could read as one. Anything else keeps the behavior below,
    # which never yields an allowlistable host for an authority-less URI.
    parts = split_uri(uri)
    implied = _IMPLIED_HOSTS.get(parts.scheme.lower())
    if implied is not None and not parts.netloc:
        cleaned = uri.translate(_URI_STRIPPED_CONTROLS)
        if "//" not in cleaned and "\\" not in cleaned:
            return implied
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
    A tool's ``target_name`` is its name, which never constrains where it connects,
    so a tool named ``github:fetch`` or ``https://trusted.example/fetch`` stays
    caller-controlled. Shared by SSRF allowlisting and egress.
    """
    if finding.target_type is not CapabilityTarget.RESOURCE:
        return None
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
