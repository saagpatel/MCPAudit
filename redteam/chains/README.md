# Two-server chains (checkout only)

This developer tool explores a cross-server boundary: one server's file-writing
operation may prepare an artifact that another server's operation executes.
MCPAudit's core reports describe individual configured servers and tool metadata;
this tool composes those declared capabilities into conditional chains. It never
connects to or launches MCP servers. Neither `redteam/` nor generated `build/`
output ships in the core wheel or sdist.

```sh
uv sync --all-packages --locked --dev
make chains
uv run python -m redteam.chains run \
  --config redteam/fixtures/servers/configs/git-plus-filesystem.json \
  --json build/redteam/chains/fixture-report.json \
  --md build/redteam/chains/fixture-report.md
```

JSON `mcpServers` configurations use MCPAudit's `api.parse_config`. Codex TOML
`[mcp_servers.NAME]` tables are adapted to the same parser. An optional
`--surfaces mapping.json` selects an adjacent name-to-surface-filename mapping;
each surface must be an adjacent JSON file, including after symlink resolution.
Environment values are discarded; reports include only environment key names.
Reports omit commands, arguments, URLs, paths, descriptions, schemas, and file
contents. Generated output belongs under `build/redteam/` and is not committed.

## Surfaces and labels

Surface precedence is explicit mapping, then an explicitly supplied `--pins DIR`,
then the shared catalog. The default pin store is never read. This adapter uses
`DIR/.mcp-audit-pins.yaml` and `DIR/trusted-keys.yaml` (the trust store's content
uses MCPAudit's JSON format). `DIR/signing-key.pem` is supplied as the bounded
signing-key location; verification does not read or create private keys or update
trust history. Bring existing pins and their public trust material into that
directory explicitly; this tool does not copy them or use ambient key paths.

Pins must pass `PinStore`'s normal baseline gate and match the full saved launch
identity: command, arguments, URL, transport, environment key names, and header
key names. Matching by server name alone never supplies tools. Pins are labeled
historical/unverified even when their signatures verify: they do not establish a
current live surface. Withheld same-name pins, unusable matching pins, conflicting
matching surfaces, or an unreadable selected store produce UNKNOWN rather than
silently falling back to the catalog. An unrelated pin with a different launch
identity does not replace a catalog surface. Catalog surfaces are unversioned,
unverified snapshots. Servers without usable metadata appear as UNKNOWN.

The labeler vocabulary includes `read`, `write`, `execute`, and `unknown`
capabilities, with `definite`, `conditional`, or `heuristic` confidence. Tags are
`writes_file`, `writes_git_config`, `writes_index`, `reads_file`, `runs_command`,
`triggers_git_filter`, `triggers_hook`, `fetches_url`, and `unknown`. Conditions
remain prerequisites; a label does not establish arbitrary path access or actual
execution. The public labeler and ranker determine the current rules.

## Templates and ranking

The explicit template registry contains `git-clean-filter` (write `.git/config`
and `.gitattributes`, then stage matching bait) and `git-hook` (write a hook,
then invoke a triggering Git operation). Only the clean-filter template has a
reproducer. Templates declare writer and executor tags, actions, trigger,
automaticity, and prerequisites. Register additional templates explicitly.

The ranker adds automaticity and path-overlap evidence, then subtracts steps,
prerequisites, and conditional labels. It returns the explanation with every
score and uses stable tie-breaking. Unknown scope is not proof of disjointness.
Multiple rows can represent different writer tools for the same server pair.
Rank is a review priority, not a probability, vulnerability verdict, or claim
that an installed server permits the operations.

## Sandboxed canary

`--reproduce` selects only the highest-ranked chain with a registered reproducer.
It demonstrates Git filter activation via the two servers' equivalent operations
on a fresh synthetic canary, **not an exploit against a live MCP server**.
`MOCKED` labels the equivalent server operations; the Git operation itself runs
only when the sandbox is available.

The reproducer creates a resolved private `mkdtemp` directory (0700) beneath
`build/redteam/chains/`. It initializes a fresh repository with empty templates
and hooks, rejects symlinks and Git indirection, includes, remotes, and submodules,
and verifies the repository toplevel, Git directory, and common directory before
writing artifacts. The fixed script creates one marker and passes stdin through
`/bin/cat`; fixtures and generated twin programs are never executed.

Every Git invocation, including init and inspection, uses absolute `/usr/bin/git`,
explicit `-C`, and macOS `/usr/bin/sandbox-exec`. Its environment is built from an
allowlist: HOME, XDG_CONFIG_HOME, and TMPDIR inside the canary; system/global Git
config and attributes disabled; prompts disabled; PATH fixed to `/usr/bin:/bin`.
Hooks, fsmonitor, external attributes, commit signing, and credential helpers are
disabled on each invocation. The profile denies network, denies writes outside
the canary (except `/dev/null` and `/dev/tty`), and allows execution only of Git,
its fixed Apple Git executable/libexec locations, `/bin/sh`, `/bin/cat`, and the
canary script. Each invocation has a ten-second limit; timeout kills its process
group. Containment is never replaced with an unsandboxed fallback.

Success requires no marker before staging, a marker afterwards, exit zero, and
the exact bait bytes in the index. Fresh negative controls omit filter config
or attributes and must produce no marker. A before/after snapshot requires the
marker to be the only new non-Git entry and all other non-Git entries unchanged.
Writes outside the canary are prevented by the sandbox policy; this is not a
scan of the host filesystem. The containment test additionally attempts a write
outside the canary and requires its rejection. Teardown verifies the exact
generated path and prefix before deleting it, then verifies absence.

Results are `REPRODUCED`, `NOT_REPRODUCED`, or `SKIPPED`, with exit codes, marker
and index evidence, control results, isolation checks, and teardown status.
Non-macOS hosts or missing sandbox-exec yield SKIPPED. The exact nested-sandbox
failure `sandbox_apply: Operation not permitted` yields SKIPPED with reason
`nested sandbox unavailable`; rerun outside that outer sandbox for live evidence.
CLI exit codes are 0 for a completed static run (including a skipped canary),
1 for NOT_REPRODUCED, and 2 for input/dependency errors.

## Explicit discovery

```sh
make chains-real SHADOW_MCP=path/to/shadow-mcp
# Opt in separately if the credential-bearing Claude Code config is intended:
uv run --with path/to/shadow-mcp python -m redteam.chains run \
  --discover --include-claude-code --reproduce
```

The optional shadow-mcp import is lazy. Without it, the command exits 2 with
`install shadow-mcp: uv run --with <path-to-shadow-mcp> ...`.
The adapter calls `discover_all(collectors=...)` with only ClaudeDesktop, Codex,
Dxt, and ProjectMcpJson collectors. It never falls back to default discovery,
`claude mcp list`, or a process collector. ClaudeCode is off by default because
its config file may carry credentials; `--include-claude-code` explicitly opts
into that collector. Discovery reads configuration metadata and does not connect.

The adapter accepts `discover_all` from the package facade or
`shadow_mcp.discovery`, and named collector factories (optionally suffixed
`Collector`) from `shadow_mcp.collectors` or the facade. It accepts a synchronous
or asynchronous server list or a result with `servers`; unsupported APIs fail
closed. Its allowlist and normalization are tested with offline stand-ins. The
head must verify compatibility with the selected shadow-mcp checkout and run real
discovery; this worker does not inspect real client configuration.

`make chains-real` writes `build/redteam/chains/real-report.json` and
`real-report.md`. Review reports before sharing. Scores and offline canary
evidence do not prove server version, runtime path permissions, policy bypass,
user interaction, or successful exploitation against an installed MCP server.
