# Provenance / Launch-Config Drift Detection

`--provenance-check` compares a server's **launch configuration** against the
snapshot captured in its pin baseline and flags supply-chain-relevant changes the
tool-schema drift check cannot see.

## Why This Matters

The tool schemas tell you what a server *claims* to do. The **launch command** —
`npx pkg@1.2.3`, the binary, its arguments, the HTTP endpoint, the credential
env-keys — is what actually *runs*. A server can keep byte-identical tool schemas
while:

- repointing a pinned version to a floating tag (`pkg@1.2.3` → `pkg@latest`),
- swapping the package or binary (typosquat, or `node` → a wrapper script),
- gaining a permission-broadening flag (`--no-sandbox`, `--dangerously-*`),
- changing its HTTP endpoint to an attacker-controlled host, or
- demanding a new credential key it was never trusted with.

Each is a classic rug-pull vector that schema-only checks miss. Provenance
detection is the launch-config layer of the over-time analysis (alongside
[escalation](ESCALATION-DETECTION.md)).

## How It Works

`mcp-audit pin` now snapshots each server's launch config — `command`, `args`,
`url`, `transport`, and env/header **key names only** (never values) — alongside
the tool schemas. On a later `mcp-audit scan --provenance-check`, the current
launch config is compared field-by-field against that snapshot and a finding is
produced only for a genuine delta. An unchanged launch config yields nothing.

`--provenance-check` **implies a pin comparison**. Run `mcp-audit pin` first. A
baseline pinned **before** this feature has no config snapshot, so its provenance
comparison is skipped until you re-pin; the scan prints a hint when no baseline
exists at all. (Drift output stays gated on `--pin-check`.)

> **Credential safety.** The credential surface is compared by KEY NAME only.
> Values are never read, stored, or displayed — consistent with the rest of
> mcp-audit. A MCP023 finding reports *that* a key name appeared/disappeared,
> never any secret.

## The Four Rule Kinds

### MCP020 — Command / transport (HIGH)

The `command`/binary or the `transport` changed (e.g. `npx` → `python`, or
`stdio` → `http`). The command is the supply-chain trust anchor; swapping it can
redirect the agent to an entirely different program.

### MCP021 — Arguments (MEDIUM / HIGH)

The launch `args` changed: a version float, a package swap, or a new flag.
**MEDIUM** by default; **HIGH** when a known-dangerous flag was gained. The
dangerous-flag signal set includes `--no-sandbox`, `--dangerously-*`,
`--allow-all`, `--allow-root`, `--disable-security`, `--disable-sandbox`,
`--unsafe`, `--no-verify`, `--insecure`, `--privileged`, `--trust-all`, and
`--skip-permissions`. The gained dangerous tokens are listed in the finding's
`gained_flags`.

### MCP022 — URL / endpoint (HIGH)

The HTTP `url` changed. A changed host or path can silently repoint the agent at
an attacker-controlled endpoint that proxies or replaces the legitimate service.

### MCP023 — Credential key-name set (MEDIUM)

The set of declared env/header **key names** changed. A server newly demanding a
credential key it did not previously reference may be trying to harvest a secret
it was not originally trusted with. Key names only — never values.

## Output

### JSON (`ServerAudit.provenance_findings`)

Provenance findings are per-server:

```json
"provenance_findings": [
  {
    "kind": "args",
    "severity": "high",
    "server_name": "repointed-server",
    "summary": "Launch arguments for 'repointed-server' changed since pin: ...",
    "baseline": "good-pkg@1.2.3",
    "current": "evil-pkg@latest --no-sandbox",
    "gained_flags": ["--no-sandbox"],
    "rule_id": "MCP021",
    "title": "Launch arguments changed since pin baseline",
    "remediation": "..."
  }
]
```

### SARIF

| Finding | Rule ID | Level |
|---------|---------|-------|
| Command / transport | MCP020 | error |
| Arguments | MCP021 | error (HIGH) / warning (MEDIUM) |
| URL / endpoint | MCP022 | error |
| Credential key-name set | MCP023 | warning |

All four carry the `provenance` category.

### Terminal / HTML report

A **Provenance / Launch-Config Drift** section lists rule ID, server, kind,
severity, and a one-line description of the change in both the terminal and the
`--html` report.

## Policy Gating

Add `fail_on.provenance: true` to fail CI on any provenance finding. Opt-in; not
covered by the broad `fail_on.severity` shortcut.

```yaml
fail_on:
  provenance: true
```

Pair with `--provenance-check` and an existing pin baseline. See
`examples/policies/provenance-aware-ci.yaml`.

## Recommended Workflow

```bash
# 1. Capture and review the baseline once (also snapshots the launch config).
mcp-audit pin

# 2. On every later audit / in CI, compare against the approved baseline.
mcp-audit scan --provenance-check --json mcp-audit.json --sarif mcp-audit.sarif \
  --policy examples/policies/provenance-aware-ci.yaml

# 3. When a launch-config change is intentional and trusted, re-review and re-pin.
mcp-audit pin --refresh <server> --apply
```

## MCP Server Tool

`mcp-audit serve` exposes a `get_provenance_findings` tool that runs a fresh scan
with `provenance_check=True` and returns findings as JSON. It requires a pin
baseline that includes a config snapshot.

## False-Positive Notes

- Findings are a pure delta vs the approved baseline; an unchanged launch config
  never fires. The most likely "false" positive is a *legitimate* upgrade you have
  not re-pinned yet — review it, then `pin --refresh`.
- Pin to explicit package versions rather than floating tags (`@latest`) so an
  intended upgrade is an explicit, reviewable event rather than silent drift.
- A baseline pinned before this feature produces no provenance findings until
  re-pinned — this is expected, not a miss.
