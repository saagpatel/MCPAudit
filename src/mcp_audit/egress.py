"""Egress detection — flag *where* an MCP server may send data.

Where SSRF asks "can a caller steer where the server connects?", egress asks "is the
destination one we trust?". This is a static, schema/URI-derived signal: no network
request is ever made and no credential value is read.

The detector consumes already-computed SSRF findings and resource URIs as its source of
destination truth, and reuses ``ssrf.fixed_host_from_uri`` / ``ssrf.host_in_allowlist``
so SSRF and egress never disagree about what host a target resolves to. It does not
reimplement host parsing or allowlist matching.

Phase 0 emits two kinds:
  * ``UNBOUNDED_EGRESS`` (HIGH) — a caller-controlled outbound target (URL/host param or
    a templated host authority); the destination is chosen at call time and cannot be
    allowlisted.
  * ``DESTINATION_OUTSIDE_ALLOWLIST`` (MEDIUM) — a fixed destination host not on the
    caller-supplied allowlist. An empty allowlist trusts nothing, so every fixed
    external destination is reported for review.

A fixed destination whose host *is* on the allowlist produces nothing in Phase 0; the
trusted-destination residual (the Cowork lesson) is layered on in Phase 1.
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
from mcp_audit.ssrf import _REMOTE_SCHEMES, fixed_host_from_uri, host_in_allowlist


class EgressDetector:
    """Detects outbound-destination risk from SSRF findings and resource URIs."""

    def __init__(self, allowlist: set[str], multi_tenant_hosts: set[str] | None = None) -> None:
        self.allowlist = allowlist
        # Curated multi-tenant host set is consumed by the Phase 1 residual; accepted now
        # so the detector's construction contract is stable across phases.
        self.multi_tenant_hosts = multi_tenant_hosts or set()

    def scan_server(self, audit: ServerAudit) -> list[EgressFinding]:
        """Return all egress findings for a server.

        Reads ``audit.ssrf_findings`` (caller-controlled targets + path-templated fixed
        hosts) and ``audit.resources`` (fixed remote hosts that never fire SSRF). SSRF
        must have run first; the audit pipeline guarantees this under ``--egress-check``.
        """
        findings: list[EgressFinding] = []
        seen_fixed: set[tuple[str, str]] = set()  # (target_name, host) — dedup fixed destinations

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
                self._emit_fixed(ssrf.target_type, ssrf.target_name, host, seen_fixed, findings)

        # 2. Fixed remote destinations the SSRF pass cannot see (a concrete external host
        #    with no template is not an SSRF signal, but it is still a data-egress path).
        for resource in audit.resources:
            try:
                scheme = urlparse(resource.uri).scheme.lower()
            except ValueError:
                continue
            if scheme not in _REMOTE_SCHEMES:
                continue
            host = fixed_host_from_uri(resource.uri)
            if host is not None:
                self._emit_fixed(CapabilityTarget.RESOURCE, resource.uri, host, seen_fixed, findings)

        return findings

    def _emit_fixed(
        self,
        target_type: CapabilityTarget,
        target_name: str,
        host: str,
        seen_fixed: set[tuple[str, str]],
        findings: list[EgressFinding],
    ) -> None:
        """Record a fixed destination once; flag it when it is outside the allowlist."""
        key = (target_name, host)
        if key in seen_fixed:
            return
        seen_fixed.add(key)
        if host_in_allowlist(host, self.allowlist):
            return  # trusted in Phase 0; the residual is layered on in Phase 1
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
