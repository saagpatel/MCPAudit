# Cross-Server Tool-Name Shadowing Detection

`--shadow-check` detects when two or more different configured MCP servers
expose tools with colliding or confusable names — so an AI agent could be
tricked into routing a call to the wrong (possibly malicious) server.

## Why This Matters

MCP agents route tool calls by name.  If a malicious server registers a tool
with the same name as a trusted one, the agent may call the attacker-controlled
tool instead.  This is particularly dangerous when the legitimate tool has
elevated capabilities (file access, shell execution) and the attacker's tool is
designed to exfiltrate its arguments.

## Why Fleet-Level Only

Tool names are unique within a single server by the MCP specification.
Collisions are inherently cross-server — there is nothing to detect within one
server's own tool list.  `shadowing_findings` therefore lives at the top level
of `AuditReport`, not on each `ServerAudit`.

## The Three Tiers

### MCP015 — Exact (HIGH)

Two or more servers expose the **identical** tool name (e.g. both have
`search`).  This is the strongest signal: a legitimate server is directly
shadowed by an attacker-controlled one.

The **first-configured** server in the collision set is presumed legitimate;
later servers are flagged as suspect shadowers.  This ordering follows the
config-file order as discovered by mcp-audit.

### MCP016 — Normalised (MEDIUM)

Names differ **only** by case and/or separator characters (`_`, `-`,
whitespace) but normalise to the same token.

Examples that all normalise to `readfile`:
- `read_file`
- `readFile`
- `read-file`
- `Read File`

Only fires when the canonical normalised form is **not already an exact match**
for any pair — no double-reporting.

Normalisation: lowercase + strip `[_\-\s]+`.

### MCP017 — Homoglyph (HIGH)

A tool name on one server contains **non-ASCII confusable characters** whose
ASCII "skeleton" matches another server's tool name.

Example: `deletе` with a Cyrillic `е` (U+0435) vs. `delete` with ASCII `e`.
The bytes differ so an exact or normalised check passes, but the characters
look identical in most fonts.

The confusable map is small and curated (Cyrillic + Greek lookalikes most
commonly used in phishing and toolname spoofing demos).  No external dependency
is added.  Only fires when at least one name in the collision set contains a
non-ASCII character — two ASCII names that normalise the same are reported as
MCP016, not MCP017.

## Zero Collisions in the 21-Server Corpus

Across 21 real-world server fixtures, there are **zero** exact or normalised
collisions.  Legitimate servers namespace their tools (`slack_*`, `github_*`,
`filesystem_*`).  Exact-match HIGH findings should be uncommon in normal
namespaced server fleets.

Fuzzy edit-distance matching is deliberately excluded so findings stay scoped to
concrete cross-server name collisions.  A typo-similar name on two servers is a
software quality issue, not a security signal.

## Output

### JSON (`AuditReport.shadowing_findings`)

Fleet-level findings are stored at the report top level in `shadowing_findings`:

```json
"shadowing_findings": [
  {
    "kind": "exact",
    "severity": "high",
    "name": "search",
    "collisions": [
      ["legitimate-server", "search"],
      ["malicious-server", "search"]
    ],
    "description": "...",
    "rule_id": "MCP015",
    "title": "Exact tool-name collision across servers",
    "remediation": "..."
  }
]
```

Each finding reports the canonical/colliding name and all `(server_name,
tool_name)` pairs.  The first pair is the presumed-legitimate server; later
pairs are the suspect shadowers.

### SARIF

| Finding | Rule ID | Level |
|---------|---------|-------|
| Exact collision | MCP015 | error |
| Normalised collision | MCP016 | warning |
| Homoglyph collision | MCP017 | error |

### Terminal Report

When `--shadow-check` finds collisions, a **Tool-Name Shadowing** section is
printed after the SSRF and trifecta sections, showing rule ID, kind, severity,
canonical name, colliding `server/tool` pairs, and remediation.

## Policy Gating

Add `fail_on.shadowing: true` to your policy YAML to fail CI on any shadowing
finding.  This gate is opt-in and is **not** covered by the broad
`fail_on.severity` shortcut — existing policy files keep their previous
behavior.

```yaml
fail_on:
  shadowing: true
```

Pair it with `--shadow-check` on the scan command; without the flag, no
shadowing findings are produced so the gate has nothing to trip on.

See `examples/policies/shadowing-aware-ci.yaml` for a complete example.

## MCP Server Tool

The MCP server exposed by `mcp-audit serve` includes a `get_shadowing_findings`
tool that runs a fresh scan with `shadow_check=True` and returns findings as
JSON.

## False-Positive Notes

- **Normalised (MCP016)** is the most likely false-positive tier.  Teams that
  use different naming conventions (`snake_case` in one server,
  `camelCase` in another) for unrelated tools may see collisions.  Review the
  canonical names — if the underlying tools do different things the finding is
  informational.
- **Exact (MCP015)** findings are designed to stay low-noise because the
  detector avoids fuzzy matching and reports only concrete cross-server
  collisions.  Identical tool names on separate servers usually indicate a
  naming conflict or deliberate shadowing.
- **Homoglyph (MCP017)** is a deliberate spoofing indicator.  An accidental
  non-ASCII character in a tool name is rare; if it appears in the same slot as
  an ASCII name on another server, treat it as suspicious.
- **Cross-client scope.** The check compares tool names across the entire
  configured fleet, including servers registered in *different* MCP clients
  (Claude Desktop, Cursor, VS Code, …).  Because an agent only loads one
  client's servers at a time, a collision between servers in two different
  clients is not a live misrouting risk — review the `collisions` entries and
  dismiss cross-client pairs that never share a single agent's toolset.  (A
  server configured in two clients under the *same* name does not fire, since
  the collision set then has only one distinct server.)

## Example

```bash
# Detect tool-name shadowing across all configured MCP servers
mcp-audit scan --shadow-check

# Export JSON + SARIF and gate CI
mcp-audit scan --shadow-check --json mcp-audit.json --sarif mcp-audit.sarif \
  --policy examples/policies/shadowing-aware-ci.yaml
```
