# mcp-audit

[![Python](https://img.shields.io/badge/Python-3776ab?style=flat-square&logo=python)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#) [![Claude Review](https://img.shields.io/badge/Claude_Review-enabled-7F5AF0?style=flat-square)](https://code.claude.com/docs/en/code-review)

> You're giving AI direct access to your computer. Do you actually know what you've installed?

`mcp-audit` gives you x-ray vision into every MCP server configured on your system: what it can do, how risky it is, whether its descriptions are hiding adversarial instructions, and whether it's changed since you last looked. It is local-first, needs no API key by default, and makes networked LLM analysis opt-in.

PyPI package: `mcp-permission-audit`. Installed command: `mcp-audit`.

## Features

- **Capability inventory** — catalogs server tools, prompts, and resources; tool, prompt, and resource capabilities are classified across six permission categories: `file_read`, `file_write`, `network`, `shell_execution`, `destructive`, `exfiltration`
- **Config-only inference** — `scan --skip-connect` infers conservative risks from declared commands, transports, credential key names, package runners, and remote URLs
- **Risk scoring** — composite 0–10 per server as a weighted sum of per-category max(weight × confidence), with a five-dimension breakdown (file access, network, shell, destructive, exfiltration)
- **Stable finding metadata** — permission and prompt-injection findings include stable rule IDs, severity, evidence, and suggested remediation so reports are easier to triage
- **Local policy gates** — `scan --policy policy.yaml` evaluates reports against local YAML rules and exits nonzero for CI enforcement
- **Report redaction** — terminal, JSON, and SARIF report paths share a redaction layer for likely credential values
- **Prompt injection detection** — `scan --inject-check` scans tool, prompt, and resource text for instruction-override patterns, hidden directives, fake role turns, and adversarial phrasing; pattern-based, no LLM required
- **Schema drift tracking** — `mcp-audit pin` connects to servers and snapshots current tool schemas; subsequent `scan --pin-check` flags added, removed, and changed tools with plain-language summaries, changed-field hints, suggested actions, and a dry-run refresh workflow for reviewed upgrades
- **Multi-client support** — reads configs from Claude Desktop, Claude Code, Cursor, VSCode, and Windsurf — plus any custom path via `--config`
- **Structured output** — Rich terminal report plus JSON and SARIF 2.1.0 export for ingestion by GitHub Advanced Security and SARIF-aware SAST pipelines
- **Documented output contract** — JSON, SARIF rule IDs, and policy exit codes are documented in `docs/OUTPUT-CONTRACT.md`
- **Watch mode** — `mcp-audit watch` re-scans on config file changes via `watchfiles` (optional extra: install with `mcp-permission-audit[watch]`)

## Quick Start

### Prerequisites
- Python 3.11+
- `uv` (recommended) or `pip`

### Installation
```bash
uvx --from mcp-permission-audit mcp-audit discover
# or install permanently:
uv tool install mcp-permission-audit
# with watch mode support:
uv tool install 'mcp-permission-audit[watch]'
```

### Usage
```bash
mcp-audit --version

# Discover configured MCP servers without connecting to them
mcp-audit discover

# Scan all configured MCP servers
mcp-audit scan

# Config-only scan that does not spawn or connect to servers
mcp-audit scan --skip-connect

# Filter to specific clients (comma-separated)
mcp-audit scan --clients claude_desktop,cursor

# Check tools, prompts, and resources for prompt-injection patterns
mcp-audit scan --inject-check

# Pin current tool schemas, then detect drift on later scans.
# Pinning connects to servers so it can capture real tool schemas.
mcp-audit pin
mcp-audit pin --status
mcp-audit pin --status --json
mcp-audit scan --pin-check

# Review expected drift for one server before refreshing its baseline.
mcp-audit pin --refresh github
mcp-audit pin --refresh github --json
mcp-audit pin --refresh github --apply

# Export JSON or SARIF 2.1.0
mcp-audit scan --json audit.json --sarif audit.sarif

# Fail CI on local policy violations
mcp-audit scan --policy policy.yaml

# Optional LLM-assisted classification (requires ANTHROPIC_API_KEY)
mcp-audit scan --llm-analysis

# Watch mode — re-scan on config change; use --skip-connect for config-only watching
mcp-audit watch
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.11+ |
| CLI | Click 8 |
| Output | Rich |
| MCP protocol | `mcp` SDK 1.27+ |
| Validation | Pydantic v2 |
| Config parsing | PyYAML + json5 |
| Watch mode | `watchfiles` (optional extra) |
| Optional LLM | Anthropic SDK |

## Architecture

The scanner enumerates MCP client config files, connects to each configured server, and calls `tools/list`, `prompts/list`, and `resources/list` over the MCP protocol when those capabilities are available. Stdio servers are started as subprocesses via `anyio`; HTTP/SSE servers are contacted at their configured URL. Returned tool schemas, prompt arguments, and resource URIs flow into the permission classifier (schema walker + regex ruleset over six permission categories) and the optional injection detector (pattern ruleset for instruction-override, role-switch, and hidden-directive phrasing). The risk scorer composes a per-category weighted sum clamped to 0–10 from tool findings; prompt and resource findings are reported separately for review and policy gates, and do not currently change the composite tool risk score. Reports render via Rich; JSON and SARIF 2.1.0 export are first-class. The pin store serializes SHA256 schema hashes plus reviewable tool snapshots to `~/.mcp-audit-pins.yaml` for actionable drift detection on subsequent `--pin-check` scans. Use `mcp-audit pin --refresh <server>` to preview expected drift for one reviewed server, then rerun with `--apply` to replace that server's pins.

### Local Policy Gates

Policies are local YAML files evaluated after a scan. A failing policy exits with code `2` after terminal, JSON, or SARIF output is written.

```yaml
fail_on:
  severity: high
  injection: medium
  capabilities: medium
  drift: true
require:
  pins:
    servers:
      - github
deny:
  permissions:
    - shell_execution
max_risk: 7
allow_servers:
  - github
servers:
  github:
    max_risk: 5
    deny:
      permissions:
        - shell_execution
```

See `examples/policies/` for starter policies. See `docs/PIN-MAINTENANCE.md`
for reviewed pin refresh and stale server cleanup workflows. See
`docs/PROMPT-RESOURCE-SCORING.md` for the current prompt/resource scoring
boundary.

## License

MIT
