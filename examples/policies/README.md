# Policy Pack

These starter policies are intended to be copied and edited. They are examples,
not a universal security baseline.

| Policy | Audience | Default posture |
|--------|----------|-----------------|
| `local-review.yaml` | Solo workstation exploration | Light gate for high severity, injection, and high config-health findings. |
| `balanced-team-ci.yaml` | Team CI adoption | Blocks high permission findings, medium injection and config-health findings, drift, and unpinned reviewed servers. |
| `reviewed-local-workstation.yaml` | Reviewed developer machines | Requires pins for known local servers and blocks high-risk tool behavior. |
| `approved-servers-ci.yaml` | Reviewed server allowlists | Allows only named servers and requires selected pin baselines. |
| `ci-strict.yaml` | Strict reviewed CI | Fails on medium-or-higher findings, drift, and denied destructive behavior. |
| `browser-automation-ci.yaml` | Browser automation MCP servers | Allows expected browser network behavior while blocking shell/destructive behavior. |
| `ssrf-aware-ci.yaml` | Teams gating SSRF-prone servers | Adds an opt-in `fail_on.ssrf` gate (global high, per-server medium) on top of the usual permission/injection bars. Requires `--ssrf-check`. |
| `trifecta-aware-ci.yaml` | Teams gating lethal-trifecta servers | Adds an opt-in `fail_on.trifecta` gate for per-server (HIGH/MCP013) and fleet-level advisory (MEDIUM/MCP014) findings. Requires `--trifecta-check`. |
| `shadowing-aware-ci.yaml` | Teams gating tool-name shadowing | Adds an opt-in `fail_on.shadowing` gate for exact (MCP015), normalised (MCP016), and homoglyph (MCP017) cross-server tool-name collisions. Requires `--shadow-check`. |
| `escalation-aware-ci.yaml` | Teams gating capability rug-pulls vs a pin baseline | Adds an opt-in `fail_on.escalation` gate for capability gains (MCP018) and description-injection gains (MCP019) since the approved pin. Requires `--escalation-check` and an existing `mcp-audit pin` baseline. |
| `provenance-aware-ci.yaml` | Teams gating supply-chain / launch-config drift | Adds an opt-in `fail_on.provenance` gate for command/transport (MCP020), args/version + dangerous-flag (MCP021), URL/endpoint (MCP022), and credential-key-set (MCP023) changes vs the pin baseline. Requires `--provenance-check` and an existing `mcp-audit pin` baseline. |

## Selection Guide

Use `local-review.yaml` for an initial workstation pass:

```bash
mcp-audit scan --inject-check --json mcp-audit.json --policy examples/policies/local-review.yaml
```

Use `balanced-team-ci.yaml` when the team is still learning the server set:

```bash
mcp-audit scan --inject-check --pin-check --json mcp-audit.json --policy examples/policies/balanced-team-ci.yaml
```

Use `approved-servers-ci.yaml` or `ci-strict.yaml` after the allowed server set
and pin baselines are reviewed.

Use `ssrf-aware-ci.yaml` when you want to fail CI on SSRF-prone servers — tools
or resources whose interface lets a caller steer a server-side request target.
Run the scan with `--ssrf-check` so SSRF findings are produced:

```bash
mcp-audit scan --ssrf-check --json mcp-audit.json --policy examples/policies/ssrf-aware-ci.yaml
```

Use `trifecta-aware-ci.yaml` when you want to fail CI on servers (or fleets)
that assemble the lethal-trifecta attack surface. Run with `--trifecta-check`:

```bash
mcp-audit scan --trifecta-check --json mcp-audit.json --policy examples/policies/trifecta-aware-ci.yaml
```

Use `shadowing-aware-ci.yaml` when you want to fail CI if any two servers
expose colliding tool names (exact, case/separator-normalised, or homoglyph).
Run with `--shadow-check`:

```bash
mcp-audit scan --shadow-check --json mcp-audit.json --policy examples/policies/shadowing-aware-ci.yaml
```

Use `escalation-aware-ci.yaml` to fail CI when a previously-pinned tool gains a
dangerous capability or its description gains injection patterns (a "rug pull").
Capture a baseline once with `mcp-audit pin`, then run with `--escalation-check`:

```bash
mcp-audit pin
mcp-audit scan --escalation-check --json mcp-audit.json --policy examples/policies/escalation-aware-ci.yaml
```

Use `provenance-aware-ci.yaml` to fail CI when a server's launch configuration
drifts from its pinned baseline — a swapped binary, a floated package version, a
newly added dangerous flag, a changed endpoint, or a new credential key. Capture
a baseline once with `mcp-audit pin`, then run with `--provenance-check`:

```bash
mcp-audit pin
mcp-audit scan --provenance-check --json mcp-audit.json --policy examples/policies/provenance-aware-ci.yaml
```

## Scoring And Config-Health Note

These policies gate on concrete findings, pin coverage, drift, and tool
composite risk. They may also gate on structured config-health findings with
`fail_on.config_health`. They intentionally do not gate directly on
`non_tool_risk` yet. Treat `non_tool_risk` as a triage signal until more
real-world calibration data is available.
