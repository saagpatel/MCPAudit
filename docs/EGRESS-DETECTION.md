# Egress Detection

`mcp-audit scan --egress-check` audits **where** an MCP server may send data. Where
SSRF asks "can a caller steer where the server connects?", egress asks "is the
destination one we trust?" — it flags outbound destinations outside a caller-supplied
allowlist, caller-controlled (unbounded) destinations, and the residual risk of an
allowlisted-but-multi-tenant destination.

This check is **static and schema/URI-derived**. It never issues a network request,
never connects to a flagged destination, and never reads a credential value. A finding
describes an *interface shape*, not a proven exfiltration: it tells you "this server can
send data to a destination you have not reviewed," not "this server leaked data."

Like SSRF and prompt-injection findings, egress findings are **additive and opt-in**.
They do not change `risk_score.composite`, they only appear when `--egress-check` is
passed, and they are gated in policy only through the dedicated `fail_on.egress` key.
`--egress-check` includes SSRF analysis (it is the substrate for the caller-controlled
signal), so an SSRF Warnings section appears alongside the Egress section.

## What it flags

The detector consumes the SSRF caller-controlled signal and walks resource URIs as its
source of destination truth, reusing the SSRF host primitives so the two detectors never
disagree about what host a target resolves to.

| Severity | Kind (`MCP04x`) | Condition |
|----------|-----------------|-----------|
| high | `unbounded_egress` (MCP041) | A caller-controlled outbound target — a URL/host tool param, or a templated host authority in a resource URI. The destination is chosen at call time and **cannot** be allowlisted. |
| medium | `destination_outside_allowlist` (MCP040) | A fixed destination host that is not on the configured egress allowlist. |
| medium / low | `trusted_destination_residual` (MCP042) | An *allowlisted* fixed host that is still not automatically safe (see below). |

An empty allowlist trusts nothing, so every fixed external destination is reported for
review. A fixed destination is deduplicated per `(target, host)`.

## The trusted-destination residual (the Cowork lesson)

Allowlisting a host answers "is the caller steering this?" — it does **not** answer "is
this trusted host a safe place to send data?" A multi-tenant, data-bearing API
(`api.anthropic.com`, S3/GCS/Azure blob, webhook/paste hosts) can receive data that lands
in a different tenant, and a tool that attaches a caller-controlled credential can have
its destination redirected by an attacker-supplied secret. This is the January 2026
Claude Cowork lesson: a trusted host is not a safe destination.

So an allowlisted fixed host still raises a `trusted_destination_residual` when:

- the host is in the curated `MULTI_TENANT_API_HOSTS` set (extend it with
  `--multi-tenant-hosts`), **or**
- the server is **credential-bearing** — a tool param whose name tokenizes to a
  credential token (`auth`, `token`, `key`, `apikey`, `secret`, `bearer`, `credential`;
  exact-token, not substring), or a resource URI that templates its userinfo.

Severity is **MEDIUM** when a credential can be attached (the active redirect vector) and
**LOW** for the multi-tenant property alone. The residual is never HIGH.

### Downgrade, not suppress

`ssrf.filter_allowlisted_ssrf` *removes* an SSRF finding once its fixed host is
allowlisted. Egress deliberately does the opposite: an allowlisted multi-tenant /
credential-bearing destination is **kept** as a downgraded LOW/MEDIUM advisory rather
than suppressed. An allowlisted host with neither property produces nothing.

## What it deliberately does not flag

To stay low-noise, the check only considers network-reaching schemes (the same set SSRF
treats as remote: `http(s)`, `ws(s)`, DB/cache/bucket/git schemes). A `file://` resource
or a non-remote scheme is not egress. A fixed local-only destination is still reported
under an empty allowlist by design — supply an allowlist (or `--egress-allowlist`) to
scope what counts as trusted.

## Output

Egress findings render in the terminal report (an **Egress / Outbound Destinations**
table), the HTML report (an **Egress** table), and SARIF (rule ids `MCP040`/`MCP041`/
`MCP042`, with `unbounded_egress` at `error`, `destination_outside_allowlist` at
`warning`, and `trusted_destination_residual` at `note`). Each finding carries the
destination host (or `caller-controlled` when unbounded), the kind, and the evidence.

## Configuration

```bash
# Flag everything outside the allowlist; api.anthropic.com is trusted but raises a residual.
mcp-audit scan --egress-check --egress-allowlist api.anthropic.com,internal.corp.example

# Extend the curated multi-tenant host set.
mcp-audit scan --egress-check --egress-allowlist data.partner.example --multi-tenant-hosts data.partner.example
```

A policy file can also supply `egress_allowlist` and `multi_tenant_hosts`; these merge
with the CLI flags to configure the detector.

## Policy gating

Egress is opt-in in policy. The broad `fail_on.severity` shortcut does **not** gate
egress, so existing policy files keep their behavior. To enforce it, add the dedicated
key (globally or per server):

```yaml
fail_on:
  egress: medium   # fail the scan on any medium-or-higher egress finding
egress_allowlist:
  - api.anthropic.com
servers:
  exfil-prone:
    fail_on:
      egress: low
```

See `examples/policies/egress.yaml` for a complete sample.
