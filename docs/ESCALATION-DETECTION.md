# Capability-Escalation ("Rug Pull") Detection

`--escalation-check` compares each tool against its operator-blessed **pin
baseline** and flags security-significant changes over time — the MCP
supply-chain "rug pull": a previously-trusted server that ships an update quietly
broadening its capability surface or mutating its description to carry
agent-targeting instructions.

## Why This Matters

Per-scan analysis answers "what can this server do *right now*?" It cannot catch a
server that was benign when you approved it and turned dangerous in a later
update. Because MCP servers are often `npx`/`uvx`-launched packages that update
out from under you, capability change-over-time is a distinct and important
threat surface. Escalation detection is the **temporal** layer on top of the
per-server and fleet-wide checks.

## How It Works

`mcp-audit pin` captures a baseline snapshot (tool description + input schema)
that the operator has reviewed and approved. On a later
`mcp-audit scan --escalation-check`, for every tool present in **both** the
baseline and the current scan, mcp-audit:

1. Re-derives the tool's capability set from the **pinned** description/schema and
   from the **current** description/schema using the same permission inference
   used everywhere else.
2. Computes the **delta** — capabilities present now but not at pin time.
3. Re-runs the prompt-injection scanner on both descriptions and computes the
   **injection-pattern delta**.

A finding is produced **only** for a genuine gain. A tool that matches its
baseline produces nothing, so findings stay scoped to reviewed baseline deltas.
No new inference is performed, no network request is made, and no credential
value is ever read.

`--escalation-check` **implies a pin comparison**: it reuses the pin store as the
baseline. Run `mcp-audit pin` first. If no baseline exists, the scan prints a
hint and produces no escalation findings. (Drift output stays gated on
`--pin-check` — `--escalation-check` alone emits only escalation findings.)

## The Two Rule Kinds

### MCP018 — Capability escalation

A pinned tool **gained** a dangerous permission category it did not hold when
pinned.

| Gained category | Severity |
|---|---|
| `exfiltration`, `shell_execution`, `destructive` | **HIGH** |
| `file_write`, `network` | **MEDIUM** |

**Note on annotation defaults.** A reconstructed baseline tool has no annotations,
so MCP annotation defaults (`destructive_hint`/`open_world_hint` default true)
give it `destructive` + `network` at *declared* confidence. Because the baseline
therefore already carries those two categories, they can never be reported as
*gained* — which neatly prevents annotation-default flapping. In practice the
live escalation signals are **`file_write`** (MEDIUM) and
**`shell_execution`/`exfiltration`** (HIGH), all derived from the tool's
description/schema content rather than annotation defaults.

### MCP019 — Description-injection escalation

A pinned tool's description **gained** one or more prompt-injection patterns
(e.g. `ignore_instructions`, `system_override`, `hidden_directive`) that were
absent from the approved baseline. A benign tool description mutating to carry
agent-targeting instructions is a strong compromise signal. Always **HIGH**.

## Output

### JSON (`ServerAudit.escalation_findings`)

Escalation findings are per-server, stored on each `ServerAudit`:

```json
"escalation_findings": [
  {
    "kind": "capability",
    "severity": "high",
    "server_name": "rugpull-server",
    "tool_name": "read_doc",
    "gained_categories": ["shell_execution"],
    "gained_patterns": [],
    "description": "...",
    "rule_id": "MCP018",
    "title": "Capability escalation since pin baseline",
    "remediation": "..."
  }
]
```

### SARIF

| Finding | Rule ID | Level |
|---------|---------|-------|
| Capability escalation | MCP018 | error (HIGH) / warning (MEDIUM) |
| Description-injection escalation | MCP019 | error |

Both rules carry the `capability_escalation` category.

### Terminal Report

When `--escalation-check` finds escalations, a **Capability Escalation (vs pin
baseline)** section prints rule ID, server, tool, kind, severity, the gained
categories/patterns, and remediation.

## Policy Gating

Add `fail_on.escalation: true` to fail CI on any escalation finding. This gate is
opt-in and is **not** covered by the broad `fail_on.severity` shortcut.

```yaml
fail_on:
  escalation: true
```

Pair it with `--escalation-check`; without the flag (and without a pin baseline)
no escalation findings are produced, so the gate has nothing to trip on. See
`examples/policies/escalation-aware-ci.yaml` for a complete example.

## Recommended Workflow

```bash
# 1. Capture and review the baseline once (connects to capture real schemas).
mcp-audit pin

# 2. On every later audit / in CI, compare against the approved baseline.
mcp-audit scan --escalation-check --json mcp-audit.json --sarif mcp-audit.sarif \
  --policy examples/policies/escalation-aware-ci.yaml

# 3. When an escalation is intentional and trusted, re-review and refresh the pin.
mcp-audit pin --refresh <server> --apply
```

## MCP Server Tool

The MCP server exposed by `mcp-audit serve` includes a `get_escalation_findings`
tool that runs a fresh scan with `escalation_check=True` and returns findings as
JSON. It requires an existing pin baseline.

## False-Positive Notes

- **Findings are a pure delta vs the approved baseline.** An unchanged tool never
  fires. The most likely "false" positive is a *legitimate* capability addition you
  simply have not re-approved yet — review it, then `pin --refresh`.
- **`destructive`/`network` are never reported as gained** (see the annotation-default
  note above), so benign description tweaks do not flap those categories.
- **A removed or brand-new tool is not an escalation.** New tools are reported by
  drift (`--pin-check`, status NEW); removed tools cannot escalate.
