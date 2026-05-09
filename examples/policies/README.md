# Policy Pack

These starter policies are intended to be copied and edited. They are examples,
not a universal security baseline.

| Policy | Audience | Default posture |
|--------|----------|-----------------|
| `local-review.yaml` | Solo workstation exploration | Light gate for high severity and injection findings. |
| `balanced-team-ci.yaml` | Team CI adoption | Blocks high permission findings, medium injection findings, drift, and unpinned reviewed servers. |
| `reviewed-local-workstation.yaml` | Reviewed developer machines | Requires pins for known local servers and blocks high-risk tool behavior. |
| `approved-servers-ci.yaml` | Reviewed server allowlists | Allows only named servers and requires selected pin baselines. |
| `ci-strict.yaml` | Strict reviewed CI | Fails on medium-or-higher findings, drift, and denied destructive behavior. |
| `browser-automation-ci.yaml` | Browser automation MCP servers | Allows expected browser network behavior while blocking shell/destructive behavior. |

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

## 1.1 Scoring Note

These policies gate on concrete findings, pin coverage, drift, and tool
composite risk. They intentionally do not gate directly on `non_tool_risk` yet.
Treat `non_tool_risk` as a triage signal until more real-world calibration data
is available.
