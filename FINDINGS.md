# Field Scan: Official MCP Servers — June 2026

**Scanned:** 9 official servers from `@modelcontextprotocol/*` (npm) and `mcp-server-*` (PyPI)  
**Mode:** Config-only, no servers spawned (`--skip-connect`)  
**Tool:** `mcp-audit` v1.13.1  
**Duration:** 0.002 seconds  
**Config used:** [`examples/configs/popular-public-servers.json`](examples/configs/popular-public-servers.json)

---

## Risk summary

| Server | Composite Risk | Permission Surface | Package / Version |
|--------|---------------|--------------------|-------------------|
| `filesystem` | **1.05** | file_read, file_write, network | `@modelcontextprotocol/server-filesystem@2026.1.14` |
| `github` | **0.75** | network, file_read | `@modelcontextprotocol/server-github` ⚠️ **unpinned** |
| `everything` | 0.45 | network | `@modelcontextprotocol/server-everything@2026.1.26` |
| `memory` | 0.45 | network | `@modelcontextprotocol/server-memory@2026.1.26` |
| `sequential-thinking` | 0.45 | network | `@modelcontextprotocol/server-sequential-thinking@2025.12.18` |
| `git` | 0.45 | network | `mcp-server-git==2026.1.14` |
| `fetch` | 0.45 | network | `mcp-server-fetch==2025.4.7` |
| `time` | 0.45 | network | `mcp-server-time==2026.1.26` |
| `remote-example` | 0.45 | network | HTTP SSE remote |

**0 high-risk servers. 9 medium-severity config-health findings (all confirmed real).**

---

## What the scanner found

### Finding 1 — Every server uses a package runner (MCP001, medium × 8)

All 4 npm-based servers (`filesystem`, `everything`, `memory`, `sequential-thinking`, `github`) launch via `npx`. All 3 PyPI-based servers (`git`, `fetch`, `time`) launch via `uvx`. 

What this means: **the package is downloaded and executed on every server startup.** Your machine runs whatever is currently published under that name. If the package is compromised between your last run and now, you run the compromised code. This is a fundamental trust assumption in the current MCP ecosystem — all "install from the registry" servers share it.

```
mcp-audit says: pin package versions or container digests where possible,
and review the source before running connected scans.
```

### Finding 2 — `github` server is unpinned

`@modelcontextprotocol/server-github` has no version tag. Every time it starts, it downloads the latest published version. This is the highest supply-chain risk in the set: a rug pull on this package (capabilities silently added or changed) would not be caught without a pinned baseline. Run `mcp-audit pin --save` to establish a SHA256 schema baseline; `mcp-audit scan --pin-check` will flag any capability change on the next run.

### Finding 3 — `filesystem` is the highest-risk server (1.05)

The only server with both file_read and file_write capabilities plus network access. This is expected behavior — it's a filesystem server — but it means that any compromise of the `@modelcontextprotocol/server-filesystem` package has read+write access to the configured directories plus can make outbound network calls. The risk score reflects what the server *can do*, not that it's malicious.

---

## What this demonstrates

A 0.002-second config-only scan surfaced:
- The permission surface of every server your agent can reach
- Which servers use package runners (and what versions they pin)
- Which server carries unpinned dependency risk
- Composite risk scores for policy-gate decisions

A connected scan (add `--pin` to establish a baseline, then `--pin-check` on subsequent runs) would additionally show:
- The actual tool schemas (`tools/list`, `prompts/list`, `resources/list` enumeration)
- Capability-escalation ("rug pull") detection against the saved baseline
- Prompt injection fingerprints in tool descriptions
- SHA256 verification of the published package bytes

---

## How to reproduce

```shell
# Install
uv tool install mcp-permission-audit

# Run the same scan
mcp-audit scan \
  --config examples/configs/popular-public-servers.json \
  --config-only \
  --skip-connect \
  --json my-scan.json

# Or scan your own config
mcp-audit discover          # find all locally configured servers
mcp-audit scan              # full audit + risk scores
mcp-audit scan --policy policy.yaml  # enforce rules in CI (exits 2 on policy violation)
```

---

## Machine-readable output

- [`examples/configs/popular-public-servers.json`](examples/configs/popular-public-servers.json) — the config scanned
- JSON report: run the command above to generate `my-scan.json`

> **Note:** The JSON and SARIF outputs contain no credential values, hostnames, or private paths — `mcp-audit` reports env-var key names only, never values, and the `--config-only` mode spawns nothing.
