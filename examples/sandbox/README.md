# MCP Prompt-Injection Sandbox

This is a public-safe, synthetic sandbox for teaching MCP and tool-security
risks without exposing real workstation configs.

Open `index.html` through a local static server:

```bash
python3 -m http.server 8765 --directory examples/sandbox
```

Then visit `http://127.0.0.1:8765/`.

## What It Demonstrates

- Prompt injection in tool descriptions.
- Overbroad file and network access.
- Credential key-name exposure.
- Benign twins versus risky lookalikes.
- The boundary between config-only review and connected tool-schema review.

The sandbox uses only toy server names, toy paths under `/tmp`, documentation
hosts under `.example`, placeholder env values, and static tool metadata.

## Files

- `fixtures/synthetic-mcp-config.json`: a synthetic MCP client config designed
  for config-only scans.
- `fixtures/config-only-report.json`: a normalized MCPAudit config-only report
  generated from the synthetic config. It is static so websites and docs can
  embed a stable report without running the scanner.
- `fixtures/connected-tool-manifest.json`: synthetic connected-mode tool
  metadata for every benign/risky twin. The browser prefers this file and falls
  back to the embedded scenario metadata if it is absent.
- `scenarios.json`: the browser demo data model, including toy tool metadata,
  expected MCPAudit-style findings, source backing, and proof boundaries.
- `index.html`: a dependency-free static inspector that compares config shape,
  connected-style tool metadata, and findings.

## Config-Only Check

Run the real MCPAudit engine against the toy config:

```bash
uv run mcp-audit scan \
  --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only \
  --skip-connect
```

The config-only scan should infer review-worthy signals such as package runners,
remote endpoints, remote URL arguments, shell wrapper launch, credential-heavy
key-name sets, and known filesystem-server file access. It should not connect to
any configured endpoint, launch any toy server, or inspect tool descriptions.

To refresh the static report fixture after intentional scanner or fixture
changes, generate a fresh JSON report and normalize volatile fields:

```bash
uv run mcp-audit scan \
  --config examples/sandbox/fixtures/synthetic-mcp-config.json \
  --config-only \
  --skip-connect \
  --json /tmp/mcpaudit-sandbox-report.raw.json
```

Keep `scan_timestamp`, `hostname`, and `scan_duration_seconds` deterministic in
the checked-in fixture. The tests compare stable report semantics against a live
config-only scan.

## Proof Boundary

Config-only mode can reason about launch shape. It cannot prove a tool
description is malicious because it intentionally does not start a server. The
scenario fixture therefore includes static toy tool metadata to demonstrate what
a connected scan or a supplied manifest can inspect.

The connected tool manifest is deliberately separate from the config-only
report. That keeps the demo honest: launch-shape findings come from MCPAudit's
config-only engine, while prompt-injection and tool-name lessons come from
synthetic connected metadata.

Source backing:

- MCP Tools specification:
  <https://modelcontextprotocol.io/specification/2025-11-25/server/tools>
- MCP Security Best Practices:
  <https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices>
- NSA MCP Security guidance:
  <https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf>

## Public-Safety Contract

Do not replace these fixtures with real configs. Keep all examples synthetic:

- no real secrets or token-looking values
- no real home-directory paths or usernames
- no private hostnames, IP addresses, customer names, or internal service names
- no raw logs, message bodies, private transcripts, or credential-bearing config
