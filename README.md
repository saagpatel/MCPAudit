# mcp-audit

[![PyPI](https://img.shields.io/pypi/v/mcp-audit)](https://pypi.org/project/mcp-audit/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![CI](https://github.com/saagpatel/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/saagpatel/mcp-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**mcp-audit** scans every MCP server configured on your machine, connects to each one, enumerates its tools, and produces a risk-scored permission audit — fully local, no API keys required.

## What it does

mcp-audit discovers MCP server configurations across Claude Desktop, Claude Code, Cursor, VS Code, and Windsurf, then connects to each server and analyzes what it can do to your system:

- **Discovers** MCP server configurations from all local client config files
- **Connects** to each server and enumerates all exposed tools with annotations and input schemas
- **Infers** permission categories: file read/write, network access, shell execution, destructive operations, data exfiltration
- **Scores** each server on a 0–10 composite risk scale across five dimensions
- **Renders** a color-coded terminal report or machine-readable JSON/SARIF output
- **Supports** user override configs to manually classify findings

## Install

```bash
# Recommended: install as isolated tool
pipx install mcp-audit

# Or run without installing
uvx mcp-audit

# Or with pip
pip install mcp-audit

# With watch mode support
pip install 'mcp-audit[watch]'
```

## Quick start

```bash
# Full audit of all configured MCP servers
mcp-audit scan

# Fast mode — config inference only, no live connections
mcp-audit scan --skip-connect

# Write JSON report
mcp-audit scan --json report.json

# Write SARIF report (for GitHub Code Scanning)
mcp-audit scan --sarif findings.sarif

# Verbose: show per-tool findings
mcp-audit scan --verbose

# Re-scan whenever config files change
mcp-audit watch
```

Sample output:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  Scanned 4 servers across 2 clients. 1 high-risk. 0 failed. (1.24s)          │
└────────────────────────────────────────────────────────────────────────────────┘
 Server                   Client          Tools  Risk  Top Permissions     Status
 ──────────────────────────────────────────────────────────────────────────────────
 filesystem               claude_desktop  3      4.5   file_read, ...      connected
 github                   claude_desktop  12     3.0   network, ...        connected
 sequential-thinking      claude_code     1      0.0   —                   connected
 shell-exec-server        cursor          5      8.5   shell_execution,... connected
```

## Usage

```
mcp-audit [--debug] COMMAND [OPTIONS]

Commands:
  discover    List all configured MCP servers without connecting
  scan        Full audit: connect, enumerate, score, report
  watch       Re-scan on config file changes (requires mcp-audit[watch])

scan options:
  --json PATH              Write JSON report to PATH
  --sarif PATH             Write SARIF 2.1.0 report to PATH
  --skip-connect           Config inference only, no live connections
  --clients CSV            Filter by client:
                             claude_code, claude_desktop, cursor, vscode, windsurf
  --timeout SECS           Connection timeout per server (default: 10)
  --verbose                Show per-tool permission breakdown
  --config PATH            Scan a specific config file
  --override-config PATH   Override config YAML (default: ~/.mcp-audit.yaml)

watch options:
  Same as scan, plus:
  --sarif PATH             Write SARIF on each re-scan
```

## Override config

Create `~/.mcp-audit.yaml` to manually classify findings:

```yaml
overrides:
  # Mark a tool as definitely read-only
  - server: "filesystem"
    tool: "read_file"
    permissions:
      file_read: true
      file_write: false
    notes: "read_file only accesses /tmp — verified safe"

  # Suppress all network findings for a known-safe server
  - server: "sequential-thinking"
    tool: "*"
    permissions:
      network: false
      destructive: false
    notes: "Pure reasoning server, no external calls"

  # Force-flag a suspicious tool across all servers
  - server: "*"
    tool: "execute_shell"
    permissions:
      shell_execution: true
```

Override rules:
- `true` → add a MANUAL-confidence finding for that category (if not already present)
- `false` → remove all findings for that category from the tool
- `tool: "*"` → applies to all tools on the specified server
- `server: "*"` → applies across all servers
- Overrides are applied in order; later entries can override earlier ones

## SARIF / GitHub Security

Generate SARIF output and upload to GitHub Code Scanning to track MCP server risks in your security dashboard:

```bash
# Generate SARIF
mcp-audit scan --sarif mcp-findings.sarif
```

Add to `.github/workflows/security.yml`:

```yaml
- name: Run mcp-audit
  run: uvx mcp-audit scan --sarif mcp-findings.sarif --skip-connect

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-findings.sarif
```

Each finding maps to a SARIF rule (MCP001–MCP006):

| Rule ID | Category | Description |
|---------|----------|-------------|
| MCP001 | file_read | File system read access |
| MCP002 | file_write | File system write access |
| MCP003 | network | External network access |
| MCP004 | shell_execution | Shell command execution |
| MCP005 | destructive | Destructive operations |
| MCP006 | exfiltration | Data exfiltration capability |

Results with composite score ≥ 7.0 are reported as `error`; ≥ 3.0 or high-confidence findings as `warning`; others as `note`.

## Architecture

```
mcp_audit/
├── cli.py              CLI entrypoint (click)
├── models.py           Pydantic data models
├── discovery/          Config file parsers (5 clients)
│   ├── base.py         ConfigDiscoverer ABC
│   ├── claude_code.py
│   ├── claude_desktop.py
│   ├── cursor.py
│   ├── vscode.py
│   ├── windsurf.py
│   └── aggregator.py
├── connector.py        MCP server connection (anyio, stdio + HTTP)
├── analyzer.py         Permission inference (annotations + keyword heuristics)
├── scorer.py           Risk scoring (weighted multi-dimensional)
├── overrides.py        User override config loader and applier
├── report.py           Terminal (Rich) + JSON output
├── sarif.py            SARIF 2.1.0 output generator
├── watcher.py          Watch mode (watchfiles)
└── rules/
    ├── patterns.py     Keyword pattern dictionary
    └── weights.py      Category weights + confidence multipliers
```

Scan pipeline:

```
discover_all_configs()
    ↓
ServerConnector.connect()       [concurrent — anyio task group]
    ↓
PermissionAnalyzer.analyze_server()
    ↓
OverrideApplier.apply()         [user ~/.mcp-audit.yaml]
    ↓
RiskScorer.score_server()
    ↓
AuditReport
    ↓
ReportGenerator (terminal + JSON) + SarifGenerator (SARIF)
```

## Comparison with other tools

| Feature | mcp-audit | Invariant mcp-scan | Cisco/Snyk scanners |
|---------|-----------|-------------------|---------------------|
| Fully local / offline | ✓ | Partial | No (cloud API) |
| Connects to live servers | ✓ | ✓ | No |
| MCP annotation analysis | ✓ | Partial | No |
| Multi-dimensional risk score | ✓ | Single score | No |
| SARIF output | ✓ | No | Yes |
| User overrides | ✓ | No | No |
| Watch mode | ✓ | No | No |
| Prompt injection detection | No | Yes | Yes |
| Zero API keys required | ✓ | No | No |

mcp-audit focuses on **permission capability analysis** — what a server *can* do to your system. It does not detect prompt injection or malicious content in tool responses (different threat model).

## Contributing

```bash
# Dev setup
git clone https://github.com/saagpatel/mcp-audit
cd mcp-audit
uv sync --dev

# Run tests
uv run pytest tests/ -v

# Lint + format
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type check
uv run mypy src/ --strict
```

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/). All PRs must pass `ruff check`, `ruff format --check`, `mypy --strict`, and the full test suite on Python 3.11, 3.12, and 3.13.
