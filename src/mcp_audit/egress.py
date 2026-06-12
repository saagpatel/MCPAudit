"""Egress detection — flag *where* an MCP server may send data.

Where SSRF asks "can a caller steer where the server connects?", egress asks "is the
destination one we trust?". This is a static, schema/URI-derived signal: no network
request is ever made and no credential value is read.

The detector consumes already-computed SSRF findings and resource URIs as its source of
destination truth, and reuses ``ssrf.fixed_host_from_uri`` / ``ssrf.host_in_allowlist``
so SSRF and egress never disagree about what host a target resolves to. It does not
reimplement host parsing or allowlist matching.

It emits three kinds:
  * ``UNBOUNDED_EGRESS`` (HIGH) — a caller-controlled outbound target (URL/host param or
    a templated host authority); the destination is chosen at call time and cannot be
    allowlisted.
  * ``DESTINATION_OUTSIDE_ALLOWLIST`` (MEDIUM) — a fixed destination host not on the
    caller-supplied allowlist. An empty allowlist trusts nothing, so every fixed
    external destination is reported for review.
  * ``TRUSTED_DESTINATION_RESIDUAL`` (LOW/MEDIUM) — an *allowlisted* fixed host that is
    still not automatically safe: it is a multi-tenant, data-bearing API
    (``MULTI_TENANT_API_HOSTS``) or the server can attach caller-controlled credentials
    (a credential-shaped tool param, or a resource URI templating userinfo). This is the
    January 2026 Claude Cowork lesson — a trusted host is not a safe destination. MEDIUM
    when credentials are involved (the active redirect vector), LOW for the multi-tenant
    property alone; never HIGH.

Downgrade-not-suppress boundary: ``ssrf.filter_allowlisted_ssrf`` *removes* an SSRF
finding once its fixed host is allowlisted. Egress deliberately does the opposite for the
residual — an allowlisted multi-tenant/credential-bearing destination is kept as a
downgraded LOW/MEDIUM advisory rather than suppressed. The two are consistent: SSRF asks
whether the *caller* can steer the host (allowlisting removes that question), while egress
asks whether the *trusted* host is itself a safe place to send data (allowlisting does not
answer that). An allowlisted host with neither property produces nothing.
"""

from __future__ import annotations

from urllib.parse import urlparse

from mcp_audit.models import (
    CapabilityTarget,
    EgressFinding,
    EgressKind,
    EgressSeverity,
    ServerAudit,
)
from mcp_audit.ssrf import (
    _REMOTE_SCHEMES,
    _key_tokens,
    fixed_host_from_uri,
    host_in_allowlist,
)

# Curated, conservative default set of multi-tenant, data-bearing destinations. An
# allowlisted host matching one of these is trusted to *reach* but is shared
# infrastructure — data sent there can land in a different tenant/account. Lowercased
# and subdomain-matched via ``host_in_allowlist`` (so ``my-bucket.s3.amazonaws.com``
# matches ``amazonaws.com``). Operators extend this via ``--multi-tenant-hosts``.
MULTI_TENANT_API_HOSTS: set[str] = {
    "api.anthropic.com",
    "api.openai.com",
    "amazonaws.com",  # S3 and other AWS endpoints
    "storage.googleapis.com",  # Google Cloud Storage
    "blob.core.windows.net",  # Azure Blob Storage
    "hooks.slack.com",
    "discord.com",
    "webhook.site",
    "pastebin.com",
    "ngrok.io",
}

# Param-name *tokens* that denote a caller-controllable credential. Matched against the
# tokenized param name (camelCase/snake-aware, via ``ssrf._key_tokens``) so the match is
# exact-token, never substring: ``api_key``/``apiKey`` tokenize to include ``key`` and
# match; ``query`` tokenizes to ``{query}`` and does not. The multi-word ``api_key`` entry
# is kept for parity with the spec though ``key`` already covers it post-tokenization.
_CREDENTIAL_PARAM_TOKENS: set[str] = {
    "auth",
    "token",
    "key",
    "apikey",
    "api_key",
    "secret",
    "bearer",
    "credential",
}


def _is_remote_uri(uri: str) -> bool:
    """True if ``uri`` uses a network-reaching scheme (egress only audits these).

    Single source of the scheme gate, shared by destination enumeration and the
    credential-bearing signal so egress never derives signal from a resource it does
    not treat as an egress destination.
    """
    try:
        return urlparse(uri).scheme.lower() in _REMOTE_SCHEMES
    except ValueError:
        return False


def _uri_templates_userinfo(uri: str) -> bool:
    """True if ``uri`` templates the userinfo (credential) portion, e.g. ``u:{pw}@host``.

    A templated userinfo means the server attaches a caller-supplied credential to a
    request whose host is otherwise fixed — the credential-bearing signal for the
    trusted-destination residual. The host authority itself is ignored here.
    """
    if "://" not in uri:
        return False
    try:
        netloc = urlparse(uri).netloc
    except ValueError:
        return False
    if "@" not in netloc:
        return False
    userinfo = netloc.rsplit("@", 1)[0]
    return "{" in userinfo


class EgressDetector:
    """Detects outbound-destination risk from SSRF findings and resource URIs."""

    def __init__(self, allowlist: set[str], multi_tenant_hosts: set[str] | None = None) -> None:
        self.allowlist = allowlist
        # The curated default is always active; an operator-supplied set extends it.
        self.multi_tenant_hosts = MULTI_TENANT_API_HOSTS | (multi_tenant_hosts or set())

    def scan_server(self, audit: ServerAudit) -> list[EgressFinding]:
        """Return all egress findings for a server.

        Reads ``audit.ssrf_findings`` (caller-controlled targets + path-templated fixed
        hosts) and ``audit.resources`` (fixed remote hosts that never fire SSRF). SSRF
        must have run first; the audit pipeline guarantees this under ``--egress-check``.
        """
        findings: list[EgressFinding] = []
        seen_fixed: set[tuple[str, str]] = set()  # (target_name, host) — dedup fixed destinations
        # Server-level signal: can this server attach a caller-controlled credential to an
        # outbound request? Drives the MEDIUM residual on an allowlisted destination.
        credential_bearing = self._is_credential_bearing(audit)

        # 1. Caller-controlled (unbounded) targets and any fixed hosts the SSRF pass surfaced.
        for ssrf in audit.ssrf_findings:
            host = fixed_host_from_uri(ssrf.target_name)
            if host is None:
                findings.append(
                    EgressFinding(
                        target_type=ssrf.target_type,
                        target_name=ssrf.target_name,
                        severity=EgressSeverity.HIGH,
                        kind=EgressKind.UNBOUNDED_EGRESS,
                        destination_host=None,
                        evidence=[
                            f"caller-controlled outbound target '{ssrf.target_name}'",
                            "destination is chosen at call time and cannot be allowlisted",
                        ],
                    )
                )
            else:
                self._emit_fixed(
                    ssrf.target_type, ssrf.target_name, host, credential_bearing, seen_fixed, findings
                )

        # 2. Fixed remote destinations the SSRF pass cannot see (a concrete external host
        #    with no template is not an SSRF signal, but it is still a data-egress path).
        for resource in audit.resources:
            if not _is_remote_uri(resource.uri):
                continue
            host = fixed_host_from_uri(resource.uri)
            if host is not None:
                self._emit_fixed(
                    CapabilityTarget.RESOURCE,
                    resource.uri,
                    host,
                    credential_bearing,
                    seen_fixed,
                    findings,
                )

        return findings

    def _is_credential_bearing(self, audit: ServerAudit) -> bool:
        """True if the server can attach a caller-controlled credential to an outbound call.

        Two signals: a tool input param whose name tokenizes to a credential token
        (exact-token, not substring), or a resource URI that templates its userinfo.
        """
        for tool in audit.tools:
            schema = tool.input_schema
            if not isinstance(schema, dict):
                continue
            props = schema.get("properties")
            if not isinstance(props, dict):
                continue
            for key in props:
                if _key_tokens(str(key)) & _CREDENTIAL_PARAM_TOKENS:
                    return True
        return any(
            _uri_templates_userinfo(resource.uri)
            for resource in audit.resources
            if _is_remote_uri(resource.uri)
        )

    def _emit_fixed(
        self,
        target_type: CapabilityTarget,
        target_name: str,
        host: str,
        credential_bearing: bool,
        seen_fixed: set[tuple[str, str]],
        findings: list[EgressFinding],
    ) -> None:
        """Record a fixed destination once; classify it against the allowlist.

        Outside the allowlist → MEDIUM ``DESTINATION_OUTSIDE_ALLOWLIST``. Inside it →
        either nothing (genuinely trusted) or a downgraded ``TRUSTED_DESTINATION_RESIDUAL``
        when the host is multi-tenant or the server is credential-bearing.
        """
        key = (target_name, host)
        if key in seen_fixed:
            return
        seen_fixed.add(key)

        if not host_in_allowlist(host, self.allowlist):
            findings.append(
                EgressFinding(
                    target_type=target_type,
                    target_name=target_name,
                    severity=EgressSeverity.MEDIUM,
                    kind=EgressKind.DESTINATION_OUTSIDE_ALLOWLIST,
                    destination_host=host,
                    evidence=[
                        f"fixed destination host '{host}'",
                        "host is not on the egress allowlist",
                    ],
                )
            )
            return

        # Allowlisted: downgrade-not-suppress. A multi-tenant or credential-bearing
        # trusted host keeps a LOW/MEDIUM residual; a plain trusted host produces nothing.
        multi_tenant = host_in_allowlist(host, self.multi_tenant_hosts)
        if not (multi_tenant or credential_bearing):
            return
        evidence = [f"allowlisted destination host '{host}'"]
        if multi_tenant:
            evidence.append("host is a multi-tenant, data-bearing API (shared infrastructure)")
        if credential_bearing:
            evidence.append(
                "server can attach a caller-controlled credential (credential-shaped param "
                "or userinfo-templated resource URI)"
            )
        findings.append(
            EgressFinding(
                target_type=target_type,
                target_name=target_name,
                # MEDIUM when a credential can be attached (active redirect vector);
                # LOW for the multi-tenant-host property alone. Never HIGH.
                severity=EgressSeverity.MEDIUM if credential_bearing else EgressSeverity.LOW,
                kind=EgressKind.TRUSTED_DESTINATION_RESIDUAL,
                destination_host=host,
                evidence=evidence,
            )
        )
