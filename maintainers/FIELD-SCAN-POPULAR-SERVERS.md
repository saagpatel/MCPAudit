# Field Scan: Popular Public MCP Servers (mcp-audit 1.12.0)

A solo validation pass that runs `mcp-audit` against a set of widely-used,
public, open-source MCP servers — to show what the scanner reports on real
software, and to confirm the networked registry/byte-verification checks
(`MCP025`, `MCP026`) work end-to-end against real published packages.

This is **solo evidence**, not an external field report. It reduces release
risk and gives a concrete reference point; it does not substitute for the two
external redacted reports tracked in issues
[#83](https://github.com/saagpatel/MCPAudit/issues/83) /
[#84](https://github.com/saagpatel/MCPAudit/issues/84). If you run MCP servers,
**please contribute a redacted config-only report** — see
[`EXTERNAL-FIELD-REPORT-REQUEST.md`](EXTERNAL-FIELD-REPORT-REQUEST.md).

## What was scanned

The publishable sample config
[`examples/configs/popular-public-servers.json`](../examples/configs/popular-public-servers.json)
lists only public, open-source servers — no credential values, private paths,
internal hostnames, or proprietary text:

- Official npm servers: `@modelcontextprotocol/server-filesystem`,
  `-server-everything`, `-server-memory`, `-server-sequential-thinking`,
  `-server-github`.
- Official PyPI servers: `mcp-server-git`, `mcp-server-fetch`,
  `mcp-server-time`.
- A placeholder `example.com` HTTP remote (to exercise the remote-endpoint
  diagnostic).

Versions were pinned to the releases current at 2026-06-02.

## Safety posture

- **Config-only baseline** (`--config-only --skip-connect`) spawns nothing and
  contacts nothing — it reasons purely from the config file.
- **Artifact verification** (`MCP025`/`MCP026`) is read-only: it downloads the
  *packages'* published bytes over HTTPS and hashes them in memory (never to
  disk, never executed), only from the npm/PyPI host allowlist.
- A separate **connected reference scan** does spawn the servers to read their
  real tool schemas. It was run only against these trusted, public reference
  implementations, whose schemas are themselves public. No connected output is
  stored; only the non-sensitive summary below is recorded.

## Results

### 1. Config-only baseline (no servers spawned)

9 server entries, 0 spawned, **9 config-health findings (all medium):** 8
package-runner source-review notices (every `npx`/`uvx` launch fetches and runs
remote code, so the source is worth a look) and 1 remote-endpoint declaration.
This is the honest, zero-risk view any user gets without running anything.

### 2. Byte-level artifact verification against real packages (`MCP025` + `MCP026`)

The shipped verification engine was run against the real published packages:

| Check | Result |
|-------|--------|
| Registry-published hash retrievable (`MCP025`) | **7 / 7** |
| Bytes downloaded and hashed (`MCP026`) | **7 / 7** |
| Downloaded bytes matched the registry-published hash | **7 / 7** |
| npm single-tarball handling | confirmed (1 file each) |
| PyPI multi-file handling (sdist + wheel) | confirmed (2 files each, every file matched its published sha256) |
| Floating-version ref (`server-github`, unpinned) | correctly skipped (both checks key by exact `package@version`) |

Every untampered official package verified clean — **zero false positives** —
which is exactly what you want: the check stays quiet on good software and is
reserved to fire only when the bytes actually disagree.

### 3. Connected reference scan (public servers, public schemas)

Connecting to the servers and reading their real tools: **7 / 9 connected, 64
tools enumerated.** (The two non-connecting entries failed for benign reasons —
a non-existent filesystem path argument and the `example.com` placeholder.)

Inferred risk scores tracked capability surface sensibly — higher score means a
broader, more powerful surface to sandbox, **not** that a server is malicious:

| Server | Risk | Why |
|--------|------|-----|
| `github` | 9.35 | 26 tools spanning repo read/write, issue/PR mutation, and network — the broadest surface. |
| `sequential-thinking` | 8.6 | one tool, but broadly-scoped reasoning/state capability. |
| `everything` | 8.0 | a deliberately maximal demo server: file read/write, network, and an SSRF-shaped fetch tool. |
| `git`, `memory` | 5.3 | repository / knowledge-graph mutation. |
| `time`, `fetch` | 3.8 / 3.5 | narrow, single-purpose. |

Two **SSRF findings** were raised — on `fetch` and `everything` — both of which
expose a caller-controllable fetch tool, so the flag matches their documented
behavior. **No prompt-injection findings** were raised on any of these clean
official servers, a useful low-false-positive signal.

## What this demonstrates

- The 1.12.0 public-package and config-only paths work against real, popular
  servers.
- `MCP025`/`MCP026` verify real npm and PyPI artifacts end-to-end, including
  PyPI's multi-file releases, with no false positives on good packages.
- Risk scoring and SSRF detection produce sensible, defensible output on
  real-world servers, and the injection detector does not cry wolf on clean
  ones.

## Reproduce it

```bash
# Safe, no-spawn baseline:
uvx --from mcp-permission-audit==1.12.0 mcp-audit \
  scan --config examples/configs/popular-public-servers.json --config-only --skip-connect

# Networked artifact verification against the real packages (read-only):
#   pin a setup with --download-artifacts, then `scan --download-artifacts`.
# See docs/PACKAGE-VERIFICATION.md.
```

## Help close the external-evidence gap

Two external redacted field reports are still required before a beta label. A
report is a few minutes of config-only output with secrets stripped — see
[`EXTERNAL-FIELD-REPORT-REQUEST.md`](EXTERNAL-FIELD-REPORT-REQUEST.md) and the
`field-report` issue template.
