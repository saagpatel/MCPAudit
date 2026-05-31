# Lethal Trifecta / Toxic Flow Detection

`mcp-audit scan --trifecta-check` detects the canonical agent-exfiltration attack
surface — the **lethal trifecta** — by checking whether the permission capabilities
already inferred by the scanner cover all three legs of the classic toxic-flow
attack pattern.

This check is **static and permission-inference-derived**. It never issues a
network request, never reads a credential value, and never modifies any config
file. A finding describes an *attack-surface shape*, not a proven exploit: it
tells you "this server (or combination of servers) assembles the full capability
set an attacker would exploit," not "this server is actively exfiltrating data."

Like SSRF findings, trifecta findings are **additive and opt-in**. They do not
change `risk_score.composite`, they only appear when `--trifecta-check` is passed,
and they are gated in policy only through the dedicated `fail_on.trifecta` key.


## The Three Legs

| Leg | Capability | PermissionCategory |
|-----|------------|-------------------|
| 1 | Sensitive data access | `file_read` |
| 2 | Untrusted-content exposure | `network` |
| 3 | Exfiltration or outbound action | `exfiltration` OR `shell_execution` OR `file_write` |

**Leg 3 is satisfied by any one of exfiltration, shell_execution, or file_write.**
`destructive` alone does NOT satisfy leg 3.

A "leg is present" for a server if that server has at least one
`PermissionFinding` or `CapabilityFinding` in the leg's category (any confidence
level counts, including LOW/inferred).


## Two Finding Tiers

### Per-server (MCP013 — HIGH)

A single server whose tools cover all three legs simultaneously. This is the
high-confidence case: a malicious or compromised tool description can instruct an
AI agent to read sensitive files (leg 1), fetch attacker-controlled content (leg 2),
and transmit the data out (leg 3) — entirely within a single server.

One finding is emitted per such server. The finding records which tool(s) satisfy
each leg so the operator can reason about the attack surface.

### Fleet-level (MCP014 — MEDIUM, advisory)

Fires when the **union** of legs across all audited servers equals {1, 2, 3} AND
no single server already holds all three legs. This is the distributed-exposure
case: in a compromised multi-server agent session, legs from different servers can
combine across server boundaries to achieve the same exfiltration outcome.

The fleet finding is **non-redundant** with per-server: if any single server
already fires MCP013, the fleet finding is suppressed entirely (it would be
redundant and lower-priority information).

The fleet finding records which server contributes which leg (minimal covering
set of all contributing tool names).


## Output

### JSON (`ServerAudit.trifecta_findings`)

Per-server findings are stored in `audits[n].trifecta_findings`:

```json
"trifecta_findings": [
  {
    "severity": "high",
    "is_fleet": false,
    "leg1_contributors": [["file-srv", "read_files"]],
    "leg2_contributors": [["file-srv", "fetch_url"]],
    "leg3_contributors": [["file-srv", "send_webhook"]],
    "description": "...",
    "rule_id": "MCP013",
    "title": "Lethal trifecta: single-server toxic flow",
    "remediation": "..."
  }
]
```

### JSON (`AuditReport.fleet_trifecta_findings`)

Fleet findings are stored at the report top level in `fleet_trifecta_findings`:

```json
"fleet_trifecta_findings": [
  {
    "severity": "medium",
    "is_fleet": true,
    "leg1_contributors": [["reader-srv", "read_files"]],
    "leg2_contributors": [["net-srv", "fetch_url"]],
    "leg3_contributors": [["exfil-srv", "send_data"]],
    "description": "...",
    "rule_id": "MCP014",
    "title": "Lethal trifecta: fleet-level toxic flow (advisory)",
    "remediation": "..."
  }
]
```

### SARIF

- `MCP013` — per-server lethal trifecta (level: `error`)
- `MCP014` — fleet-level lethal trifecta advisory (level: `warning`)

Each SARIF result's `properties` includes `is_fleet`, `leg1_contributors`,
`leg2_contributors`, `leg3_contributors`, `severity`, and `target_type`.


## Policy Gating

```yaml
# policy.yaml
fail_on:
  trifecta: true  # Gate on any trifecta finding (per-server or fleet)
```

`fail_on.trifecta` is opt-in and distinct from `fail_on.severity`. The broad
`fail_on.severity` shortcut does **not** cover trifecta findings, so existing
policy files keep their previous behavior unchanged.


## False-Positive Notes

- The check is based on *inferred* permission capabilities. A server flagged as
  having `file_read` + `network` + `exfiltration` may not actually use all three
  in the same agent session — the finding reflects potential, not confirmed
  activity.
- Fleet findings (MCP014) are advisory: the legs exist across the fleet but may
  not be reachable in a single session if servers are used in isolation.
- A server that scores high on individual capability dimensions but operates in a
  sandboxed environment may not present a real exfiltration risk.
- Use these findings as a prompt to audit the server's tools individually, not as
  definitive proof of malicious behaviour.


## Example

```bash
# Detect lethal-trifecta attack surface, write JSON + SARIF, gate in CI
mcp-audit scan --trifecta-check --json audit.json --sarif audit.sarif --policy policy.yaml
```
