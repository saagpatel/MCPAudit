# Launch-Artifact Integrity Detection (`--integrity-check`)

`mcp-audit scan --integrity-check` hashes the **on-disk artifact** a server
launches and flags drift against the pin baseline. It closes a gap left by the
schema (`--pin-check`) and provenance (`--provenance-check`) checks: those compare
tool schemas and the launch *config strings*, but the command string can stay
byte-identical while the file it points at is swapped underneath you.

`python /opt/mcp/server.py` is an unchanged command even if `server.py` was
rewritten overnight; `/usr/local/bin/mcp-server` can be replaced in place. The
integrity check catches exactly that.

## What it does

At pin time (`mcp-audit pin`), the baseline now records a SHA-256 for each
resolvable on-disk launch artifact:

- the **resolved command binary** (an absolute/relative path that exists, or a
  bare name resolved on `PATH` via `which`), and
- any **argument that is an existing local file** (e.g. a script path).

On a later `scan --integrity-check`, each pinned path is re-hashed and compared:

| Rule | Condition | Severity |
|------|-----------|----------|
| `MCP024` (artifact_drift) | the file's SHA-256 differs from the baseline | **HIGH** |
| `MCP024` (artifact_drift) | the pinned file is no longer present at its path | **MEDIUM** (often a relocation, still worth a look) |

Findings are a pure delta against the pinned hashes — an unchanged artifact
produces nothing.

## Scope and limits (v1)

- **Offline and deterministic.** Only bytes already on the local filesystem are
  hashed (capped at 64 MiB per file); no network request is ever made. This fits
  MCPAudit's local-first, no-API-key identity.
- **Package-runner launches hash the runner, not the package.** For `npx pkg@x`
  or `uvx pkg`, the resolved command is the runner (`npx`/`uvx`), so the check
  hashes that binary — useful if the runner itself is swapped, but it does **not**
  verify the remote package that the runner pulls. Verifying the resolved registry
  artifact (the tarball/wheel) is a separate, network-gated follow-up. Use
  `--provenance-check` (MCP021) to catch a floated/swapped package version in the
  meantime.
- **Implies a pin comparison.** `--integrity-check` needs a baseline that captured
  artifact hashes. Run `mcp-audit pin` first; baselines pinned before this feature
  existed are skipped until re-pinned.

## Credential safety

The integrity check reads and hashes launch *artifact* bytes (binaries/scripts).
It never reads MCP config credential values, and the pin baseline stores only the
artifact path and its SHA-256 — never file contents. This is consistent with the
rest of MCPAudit: env/header credentials are recorded by key name only.

## Usage

```bash
# Capture the approved baseline once (records artifact hashes).
mcp-audit pin

# Later, flag any on-disk launch-artifact drift.
mcp-audit scan --integrity-check

# Gate CI on it (opt-in; not covered by the broad fail_on.severity shortcut).
mcp-audit scan --integrity-check --json mcp-audit.json --policy examples/policies/integrity-aware-ci.yaml
```

A non-empty `MCP024` finding means a file the server launches changed since you
reviewed it. Confirm the change was an intended upgrade/rebuild from a trusted
source before refreshing the pin with `mcp-audit pin --refresh <server>`; treat an
unexpected change as a potential compromise and inspect the file before use.

## Relationship to the other over-time checks

| Check | Compares | Catches |
|-------|----------|---------|
| `--pin-check` | tool schemas | added/removed/changed tools |
| `--escalation-check` | inferred capabilities + injection patterns | a tool that *gained* a dangerous capability or injection text |
| `--provenance-check` | launch **config strings** (command, args, URL, cred key names) | a swapped command, floated version, new flag, changed endpoint |
| `--integrity-check` | on-disk artifact **bytes** | the launch command is unchanged but the file it runs was modified/replaced |

Run them together for full over-time coverage; each is opt-in and additive, and
none changes `risk_score.composite`.
