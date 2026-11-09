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
Explicit metadata must match the mapped server name and launch identity, including
transport and environment key names. A mismatched explicit surface stays UNKNOWN;
pins and other sources cannot replace it. HTTP endpoints use the hardened core's
private routing-identity comparison; query values never appear in reports.
Environment values are discarded; reports include only environment key names.
Reports omit launch commands, arguments, tool descriptions, schemas, and file
contents. DXT roots are included with the home directory replaced by `~`.
Generated output belongs under `build/redteam/` and is not committed.

## Surfaces and labels

Surface precedence is explicit mapping, then an explicitly supplied `--pins DIR`,
DXT manifests, then the shared catalog. The default pin store is never read. This adapter uses
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
matching surfaces, missing expected entries, failed signatures, or an unreadable
selected store produce UNKNOWN rather than silently falling back to DXT or the
catalog. Persisted signing expectations detect deleted entries and missing pin
files. Redacted HTTP snapshots cannot establish equality for query values.
Duplicate discovery names resolve under their original names before display
disambiguation, preserving the same-name pin gate.
An unrelated verified pin with a different launch
identity does not replace a catalog surface. Catalog snapshots are unverified;
versioned entries require the exact configured package version. A mismatch stays
UNKNOWN with both versions in the reason. Servers without usable metadata appear
as UNKNOWN.

The local machine-room catalog is transcribed from the source commit recorded in
its provenance; only a `machine-room` command basename with `mcp` in its arguments
matches. The job-start registration is labeled `runs_command`.
`xcodebuildmcp@2.6.2` remains UNKNOWN: its tagged README links an unversioned tools
website, and no version-matched tool document was found at that tag.

`--dxt-dir DIR` selects a Claude Extensions directory. Discovery otherwise uses
shadow-mcp's `DiscoveryPaths.claude_extensions_dir`; collector provenance may
select one direct-child extension within that root. In particular, `source: dxt` with a
`location` naming `Claude Extensions/<id>/manifest.json` selects that exact manifest
only when the collected command and arguments exactly equal `server.mcp_config`.
Placeholders remain unexpanded: expanded arguments cannot establish identity.
The location must be a direct-child `manifest.json` of a direct-child extension
inside `Claude Extensions`; symlinks and ambiguous manifests are rejected.
If discovery supplies no extension root, a validated manifest location can supply
its enclosing `Claude Extensions` root. Explicit-config mode never discovers a
default DXT directory from the home directory.
Only `manifest.json` is read within each
extension. Without provenance, `${__dirname}` launches must match exactly one
manifest's command and arguments. Tools are declared name/description metadata;
schemas are not declared. For the allowed-directories placeholder, the only
retained settings key is `userConfig.allowed_directories` in the sibling
`Claude Extensions Settings/<id>.json`. Absent settings mean unknown roots.
Collector source counts and errors appear as discovery notes in both reports.

The labeler vocabulary includes `read`, `write`, `execute`, and `unknown`
capabilities, with `definite`, `conditional`, or `heuristic` confidence. Tags are
`writes_file`, `creates_directory`, `writes_git_config`, `writes_index`, `reads_file`, `runs_command`,
`runs_browser_script`, `runs_build`, `triggers_git_filter`, `triggers_hook`, `fetches_url`, and `unknown`. Conditions
remain prerequisites; a label does not establish arbitrary path access or actual
execution. The public labeler and ranker determine the current rules.

## Templates and ranking

The explicit template registry contains `git-clean-filter` (write `.git/config`
and `.gitattributes`, then stage matching bait), `git-hook` (write a hook,
then invoke a triggering Git operation), `write-then-run`, and `write-then-build`.
Build execution is conditional on building a project with writable build scripts
or Run Script phases. `runs_browser_script` runs script in a browser page, not on the host;
no current template uses it as an executor. Playwright also retains URL-fetching labels.
`create_directory` does not write file content; `move_file` can place an attacker-controlled
file at a path and is heuristically labeled `writes_file`.
The clean-filter and write-then-run templates have reproducers.
Templates declare writer and executor tags, actions, trigger,
automaticity, and prerequisites. Register additional templates explicitly.

The ranker adds automaticity and path-overlap evidence, then subtracts steps,
prerequisites, and conditional labels. It returns the explanation with every
score and uses stable tie-breaking. Unknown scope is not proof of disjointness.
Each writer/executor server pair and template has one ranked row, scored by its
best member. Reports retain the alternative tool pairs and show them in the Steps
column; JSON steps describe the selected best member.
Rank is a review priority, not a probability, vulnerability verdict, or claim
that an installed server permits the operations.

## Sandboxed canary

`--reproduce` selects the top-ranked chain when supported, otherwise the
highest-ranked chain with a registered reproducer. Reports identify the selected
rank, template, and reason. The Git canary demonstrates filter activation via equivalent operations
on a fresh synthetic canary, **not an exploit against a live MCP server**.
`MOCKED` labels the equivalent server operations; the Git operation itself runs
only when the sandbox is available.

The write-then-run canary writes a synthetic script into its private 0700
directory, then executes `/bin/sh <script>` as an operation-level stand-in for
the run tool. Its sandbox permits execution only of `/bin/sh`, its validated
`/bin/<shell>` selection (when present), and that script,
denies network, and denies writes outside the canary except the shared device
exceptions described below. The marker must be absent before and present after;
a fresh missing-script control must fail without a marker. Full snapshots check
that only the marker was added. Timeout kills the process group with bounded
cleanup; teardown is confirmed. Tests also require outside writes to fail.

The reproducer creates a resolved private `mkdtemp` directory (0700) beneath
`build/redteam/chains/`. It initializes a fresh repository with empty templates
and hooks, rejects symlinks and Git indirection, includes, remotes, and submodules,
and verifies the repository toplevel, Git directory, and common directory before
writing artifacts. The fixed script creates one marker and passes stdin through
`/bin/cat`; fixtures and generated twin programs are never executed.

Before entering the sandbox, the reproducer resolves Git once with
`/usr/bin/xcrun --find git` and obtains its helper directory with `git --exec-path`.
A non-shim `/usr/bin/git` is the fallback. Both paths must resolve beneath
`/Applications/Xcode.app/`, `/Library/Developer/CommandLineTools/`, `/usr/bin/`,
or `/opt/homebrew/`; unavailable or unapproved toolchains yield SKIPPED.
Every repository operation, including init and inspection, invokes that resolved
Git directly with explicit `-C` and macOS `/usr/bin/sandbox-exec`. Its environment
is built from an allowlist: HOME, XDG_CONFIG_HOME, and TMPDIR inside the canary; system/global Git
config and attributes disabled; prompts disabled; PATH fixed to `/usr/bin:/bin`.
Hooks, fsmonitor, external attributes, commit signing, and credential helpers are
disabled on each invocation. The profile denies network, denies writes outside
the canary (except `/dev/null` and `/dev/tty`), and allows execution only of Git,
its resolved helper subpath, `/bin/sh`, `/bin/cat`, and the canary script. xcrun
is never allowed inside the sandbox. Each invocation has a ten-second limit;
timeout kills its process group. Containment is never replaced with an
unsandboxed fallback.

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
CLI exit codes are 0 for completed analysis, 1 for incomplete analysis or
NOT_REPRODUCED, 2 for input/dependency/output errors, and 3 for a requested but
SKIPPED canary. `--allow-incomplete` permits success despite server parse errors
or collector errors; errors remain visible. `--allow-skip` permits success with a
SKIPPED canary. Neither flag permits a NOT_REPRODUCED result. Without
`--reproduce`, static analysis does not run a canary. Report paths must be distinct
from each other and every selected input, and outside pin and DXT metadata
directories; aliases and hard links to inputs are protected too.

## Explicit discovery

```sh
make chains-real SHADOW_MCP=path/to/shadow-mcp
# Opt in separately if the credential-bearing Claude Code config is intended:
PYTHONPATH=path/to/shadow-mcp/src uv run --locked python -m redteam.chains run \
  --discover --include-claude-code --reproduce
```

The optional shadow-mcp import is lazy. Without it, the command exits 2 with
`set PYTHONPATH=<path-to-shadow-mcp>/src and use uv run --locked ...`.
Discovery verifies that `mcp_audit` comes from this checkout's `src/`, avoiding
the older PyPI dependency that can shadow the local package.
The adapter calls `discover_all(collectors=...)` with only ClaudeDesktop, Codex,
Dxt, and ProjectMcpJson collectors. It never falls back to default discovery,
`claude mcp list`, or a process collector. ClaudeCode is off by default because
its config file may carry credentials; `--include-claude-code` explicitly opts
into that collector. Discovery reads configuration metadata and does not connect.

The adapter requires `DiscoveryPaths.default` in `shadow_mcp.config`,
`discover_all` in `shadow_mcp.collectors.base`, and the named collector classes
in their respective modules. The synchronous result must expose `servers`,
`source_counts`, and `errors`; incompatible APIs fail closed before any fallback.
Source counts and value-free collector errors appear in Markdown and JSON.
Any collector error makes analysis incomplete, even with zero discovered servers.
Tests use fake layouts and offline stand-ins; they do not establish compatibility
with an installed shadow-mcp checkout or inspect real client configuration.

`make chains-real` writes `build/redteam/chains/real-report.json` and
`real-report.md`. Review reports before sharing. Scores and offline canary
evidence do not prove server version, runtime path permissions, policy bypass,
user interaction, or successful exploitation against an installed MCP server.
