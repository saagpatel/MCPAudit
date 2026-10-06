# Suppressing findings

MCPAudit does not provide a general finding-suppression file. Prefer narrowing
the audited config, adjusting a detector's documented allowlist, or expressing
an acceptance rule in a local policy so the reason stays reviewable.

## SSRF fixed-host allowlist

`--ssrf-allowlist` suppresses SSRF findings only when the detected target host
is fixed and appears in the allowlist. It never suppresses caller-controlled
fetch targets. Review the [SSRF detector guide](../SSRF-DETECTION.md) before
using an allowlist.

## Egress allowlist

`--egress-allowlist` records trusted destinations. An allowlisted multi-tenant
host can still produce a residual advisory; allowlisting does not make that
destination universally safe. See the [egress guide](../EGRESS-DETECTION.md).

## Policy decisions

Policies can allow named servers or set explicit risk and permission limits.
They do not erase findings from the report. Start with the [CI guide](ci.md)
and keep policy changes under normal code review.
