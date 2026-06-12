# Lethal Trifecta / Toxic Flow Detection

`mcp-audit scan --trifecta-check` detects the canonical agent-exfiltration attack
surface — the **lethal trifecta** — by checking whether the capabilities across a
server (or fleet) cover all three legs of the classic toxic-flow attack pattern.

This check is **static and inference-derived**. It never issues a network request,
never reads a credential value, and never modifies any config file. A finding
describes an *attack-surface shape*, not a proven exploit: it tells you "this server
(or combination of servers) assembles the full capability set an attacker would
exploit," not "this server is actively exfiltrating data."

Like SSRF findings, trifecta findings are **additive and opt-in**. They do not
change `risk_score.composite`, they only appear when `--trifecta-check` is passed,
and they are gated in policy only through the dedicated `fail_on.trifecta` key.


## The Three Legs

| Leg | Signal | How it is detected |
|-----|--------|--------------------|
| 1 | Sensitive data access | `PermissionCategory.FILE_READ` in `permissions` or `capability_findings` |
| 2 | Untrusted-content ingestion | A tool/resource flagged by the SSRF detector (caller-controlled remote fetch), **OR** a tool whose name or description carries a fetch verb (`fetch`, `download`, `scrape`, `crawl`, `curl`, `wget`, `retriev`, `visit`, …) |
| 3 | Exfiltration capability | `PermissionCategory.EXFILTRATION` in `permissions` or `capability_findings` |

### Why Leg 2 is ingestion-based, not the NETWORK category

The original design used `PermissionCategory.NETWORK` for Leg 2. Live-probing
against 21 real-world server fixtures showed this caused 18/21 servers to fire
the per-server trifecta — a useless 86% false-positive rate — and never let the
fleet-level pass trigger. `NETWORK` is near-universal: almost every MCP server
contacts some external service (package registry, search API, LLM endpoint),
making it an entirely non-discriminating signal.

Leg 2 is now **untrusted-content ingestion**: the server actively pulls in content
from a caller-controlled or external source it does not fully trust. The SSRF
detector already identifies exactly this pattern (caller-controlled fetch target),
and fetch-verb tool names are a lightweight complement. This change calibrated the
detector to 3/21 per-server hits (aws_s3, email, playwright) — servers that
genuinely combine file-read reach with remote-content ingestion and exfiltration.

### Why Leg 3 is exfiltration-only

The original design also accepted `SHELL_EXEC` and `FILE_WRITE` for Leg 3.
`SHELL_EXEC` is extremely common in developer tooling (build tools, git wrappers,
terminals) and `FILE_WRITE` is almost as common. Neither inherently enables
exfiltration — a shell or file-write tool can operate entirely locally.
`EXFILTRATION` is the specific inferred capability that means the server combines
local data access with an outbound transfer, making it the precise signal for Leg 3.


## Two Finding Tiers

### Per-server (MCP013 — HIGH)

A single server whose tools cover all three legs simultaneously. One finding is
emitted per such server. The finding records which tool(s) satisfy each leg.

### Fleet-level (MCP014 — MEDIUM, advisory)

Fires when the **union** of legs across all audited servers equals {1, 2, 3} AND
no single server already holds all three legs. This is the distributed-exposure
case: in a compromised multi-server agent session, legs from different servers can
combine to achieve the same exfiltration outcome.

The fleet finding is **non-redundant**: suppressed entirely when any per-server
finding fires. The fleet finding records which server contributes which leg.


## Output

### JSON (`ServerAudit.trifecta_findings`)

Per-server findings are stored in `audits[n].trifecta_findings`:

```json
"trifecta_findings": [
  {
    "severity": "high",
    "is_fleet": false,
    "leg1_contributors": [["file-srv", "read_sensitive_files"]],
    "leg2_contributors": [["file-srv", "fetch_remote_content"]],
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
    "leg1_contributors": [["filesystem-srv", "read_files"]],
    "leg2_contributors": [["fetch-srv", "fetch_remote"]],
    "leg3_contributors": [["slack-srv", "post_message"]],
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

- The check is based on inferred permission capabilities and heuristic ingestion
  signals. A server flagged as having `file_read` + ingestion + `exfiltration` may
  not actually use all three in the same agent session.
- Fleet findings (MCP014) are advisory: the legs exist across the fleet but may
  not be reachable in a single session if servers are used in isolation.
- A tool name containing a fetch verb triggers Leg 2 heuristically. If a tool
  named `fetch_config` only reads a local config file (not remote content), the
  Leg 2 signal is a false positive. Inspect the tool's actual implementation.
- Use these findings as a prompt to audit server tools individually, not as
  definitive proof of malicious behaviour.


## Example

```bash
# Detect lethal-trifecta attack surface, write JSON + SARIF, gate in CI
mcp-audit scan --trifecta-check --json audit.json --sarif audit.sarif --policy policy.yaml
```

## Rule of Two Posture

Every fired trifecta finding (per-server and fleet) carries an advisory
`rule_of_two` posture, after Meta's October 2025 *Rule of Two* framing: an agent
should hold at most two of {untrusted input, sensitive data access, external
communication}. Dropping any **one** leg breaks the trifecta — so the posture
names which leg to drop and how.

The posture is purely advisory: it **never changes when the trifecta fires**, only
enriches the finding. It is computed by a deterministic, pure heuristic (no I/O):

1. **Prefer dropping Leg 3 (exfiltration)** whenever Leg 3 has at least one
   contributing tool. Removing the outbound channel breaks the trifecta with the
   least loss of read/ingest utility, and it is enforceable today via the egress
   detector — the Leg 3 action reads *"restrict outbound destinations via
   `--egress-check` allowlist, or remove tool(s) …"*.
2. **Otherwise drop the leg with the fewest contributing tools** (tie-break: lower
   leg number) — fewest tools removed = least functionality lost.

The posture records:

| Field | Meaning |
|-------|---------|
| `legs_present` | the legs (subset of `[1, 2, 3]`) that have contributing tools |
| `recommended_drop` | the single leg to remove (`1` \| `2` \| `3`) |
| `action` | the concrete remediation for the recommended drop, naming the affected tool(s) |
| `affected_tools` | the deduplicated tool names tied to the dropped leg |
| `alternatives` | `(leg, action)` for the other present legs, so the operator can pick a different trade-off |

It renders as a compact line in the terminal report (a **Rule of Two** column on
the trifecta tables), in the HTML report, and in SARIF (appended to the result
message plus a structured `rule_of_two` property carrying the recommendation).
