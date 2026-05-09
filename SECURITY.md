# Security Policy

MCPAudit is itself a security tool. This document covers two distinct concerns:

1. How to report vulnerabilities **in MCPAudit** (the auditor tool itself)
2. MCPAudit's **threat model** — what it does and does not protect against

---

## Reporting a vulnerability in MCPAudit

**Please do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/saagpatel/MCPAudit/security/advisories/new) to report privately. This allows coordinated disclosure before a fix is published.

Include in your report:

- A description of the vulnerability and its impact
- Steps to reproduce (config snippet, command invoked, observed vs. expected behavior)
- The MCPAudit version (`mcp-audit --version`) and Python version
- Whether the vulnerability requires a malicious MCP config to trigger, or if it can be triggered by a benign config

We aim to acknowledge reports within **72 hours** and provide an initial assessment within **7 days**.

---

## Threat model

Understanding what MCPAudit does and does not do is important for evaluating its security properties.

### What MCPAudit does

- Reads local MCP server configuration files (e.g., `claude_desktop_config.json`, Cursor/VS Code equivalents)
- During a standard `mcp-audit scan`, connects to configured MCP servers to enumerate declared tools and schemas
- For stdio servers, starts the configured server command with timeout guards; for HTTP/SSE servers, opens a client connection to the configured URL
- Scores permission risk and flags potential prompt injection patterns in tool names and descriptions
- Detects schema drift across capability declarations with `mcp-audit pin` and `scan --pin-check`
- Supports `--skip-connect` for config-only review when you do not want MCPAudit to spawn or connect to audited servers

### What MCPAudit does not do

- MCPAudit does not call audited MCP tools; it only enumerates tool metadata
- MCPAudit does not exfiltrate config data
- MCPAudit does not modify MCP configs during scans
- `mcp-audit serve --install` is an explicit setup command that writes an MCPAudit server entry to detected Claude config files
- MCPAudit does not transmit data to a third-party API unless optional LLM analysis is explicitly requested
- The `watch` mode monitors local config file changes using `watchfiles`; each re-scan follows the selected scan mode, so use `watch --skip-connect` for config-only watching

### Trust boundary

MCPAudit reads config files from your local filesystem. It trusts that the config files it reads are your own. A scenario where an attacker can write to your MCP config directory is outside MCPAudit's threat model — at that point, the attacker already has local file write access.

### Prompt injection in MCPAudit's own output

MCPAudit parses and displays content from MCP server configs and MCP server metadata, including tool descriptions that may be attacker-controlled. If a malicious MCP server is installed, its tool descriptions could contain content designed to manipulate AI assistants that consume MCPAudit's output. MCPAudit does not sanitize or escape tool description content before rendering it. Users should treat MCPAudit's output as untrusted data when piping it to AI systems.

### LLM mode (`--llm-analysis`)

When the optional `anthropic` dependency is installed and `--llm-analysis` is used, MCPAudit sends selected tool names, descriptions, and parameter names to the Anthropic API for permission classification. In this mode, content from audited MCP server configs is transmitted over the network to a third-party service. Do not use `--llm-analysis` if your MCP configs contain sensitive information (API keys in args, internal hostnames, etc.).

---

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.0 alpha (`1.0.0a5` and later) | Yes |
| Earlier alpha/pre-release builds | Security fixes only |
| < 0.3   | No |

---

## Acknowledgements

We appreciate responsible disclosure. Reporters of valid vulnerabilities will be credited in the release notes unless they prefer to remain anonymous.
