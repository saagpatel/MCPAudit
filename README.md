# mcp-audit

<!-- mcp-name: io.github.saagpatel/mcp-audit -->

[![PyPI](https://img.shields.io/pypi/v/mcp-audits?style=flat-square&logo=pypi&logoColor=white&label=PyPI)](https://pypi.org/project/mcp-audits/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-audits?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/mcp-audits/)
[![CI](https://img.shields.io/github/actions/workflow/status/saagpatel/MCPAudit/ci.yml?style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/saagpatel/MCPAudit/actions/workflows/ci.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/saagpatel/MCPAudit/codeql.yml?style=flat-square&logo=github&label=CodeQL)](https://github.com/saagpatel/MCPAudit/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

> **See what your AI tools' MCP servers can reach.**

MCPAudit reviews MCP server configuration and, when asked, lists the tools a
server exposes. It highlights declared capabilities, instruction-shaped text
heuristics, and changes from a saved pin so you can decide what to investigate.
Findings are review signals: a high score means broader capability exposure,
not that a server is malicious or unsafe.

> [!IMPORTANT]
> The package is `mcp-audits`; the command is `mcp-audit`.
> The default check is static. `check --connect` and legacy `scan` can start
> configured local programs or contact configured endpoints. Package
> verification, downloads, and LLM analysis are separate opt-in operations.
> MCPAudit does not edit configs, and reports environment variable key names,
> never their values. Review generated reports before sharing them.

## Try it

```sh
mcp-audit                              # static review of supported configs
mcp-audit check --config ./mcp.json    # review this file only; no connections
mcp-audit demo                         # see a bundled synthetic example
mcp-audit explain MCP007               # explain a finding offline; no config reads
```

Install with [uv](https://docs.astral.sh/uv/):

```sh
uv tool install mcp-audits
```

Or run without installing:

```sh
uvx --from mcp-audits mcp-audit demo
```

## What to do with a finding

Start with the suggested action and inspect the named capability or evidence.
For example, if a filesystem server can write broadly, restrict its configured
directory and review the report again. Pattern-based instruction checks can
miss reworded or obfuscated text and can also need human review. A clean report
is not a safety certificate.

```text
Review the server's configured access, narrow it if needed, then run the check again.
```

Use [Start here](docs/start-here.md) for a guided walkthrough and
[Reading results](docs/reading-results.md) to interpret scores, findings, and
coverage. [How it works](docs/how-it-works.md) explains the check boundary.

Each rule's meaning, possible consequences, manual fix and confidence limits are
in the [finding reference](docs/findings/index.md); `mcp-audit explain MCP013`
prints the same entry offline. Explicit `--config` sources are labeled
"explicit file; parsed as Claude-style config"; the parser identity does not
establish which client uses that file.

Static tool metadata checks also flag malformed MCP header annotations,
credential parameters mapped to headers, external schema references and
unexpected icon sources. These checks inspect served metadata without fetching
schemas or icons.

## Use in CI

MCPAudit can write SARIF and evaluate local policy files. Begin with
config-only CI, then enable connected checks only where the workflow should
start those servers. See the [CI guide](docs/guides/ci.md) and
[policy examples](examples/policies/README.md).

For a pinned release example, the composite Action can upload SARIF to GitHub
code scanning:

```yaml
- uses: saagpatel/MCPAudit@v2.8.1
```

The release checklist calls out Action references so maintainers can update
examples when a new public release is available. Review the action's permissions
and inputs before enabling it in a repository.

## Choose a review path

| Goal | Starting point | What it does |
| --- | --- | --- |
| Learn the output | `mcp-audit demo` | Uses bundled synthetic input |
| Review one file | `mcp-audit check --config FILE` | Static check of the selected config |
| Make a share card | `mcp-audit checkup --config FILE --card checkup.html` | Writes a local counts-only HTML Preview |
| See discovered sources | `mcp-audit inspect` | Lists identities and source status |
| Inspect one server | `mcp-audit check --connect --server ID` | Connects to one unambiguous identity |
| Automate a policy | `mcp-audit check --policy FILE` | Evaluates a local policy |

The `ID` for a connected check has the form `CLIENT:SCOPE:NAME`. Use the exact
identity shown by `inspect`; the command refuses ambiguous selections. A
connected check can start the configured local command or contact its endpoint.

`checkup` writes a local, counts-only share card with no names by default; see
the [checkup guide](docs/guides/checkup.md).

## Keep the evidence in context

Configuration-based findings describe declared access. A connected listing
adds the tool metadata the server provides, but does not prove what the server
will do later. Connected HTTP scans also send one credential-free
`server/discover` request and, on 401, review bounded public authorization
metadata. The probe never uses configuration header values and does not run
with `--skip-connect` or for project sources without connection opt-in.
These observations do not prove a completed OAuth flow. The optional canary is bounded and exercises only eligible
tools under its documented limits. See [How it works](docs/how-it-works.md)
for the boundary between those observations.

Reports can contain configuration shape, tool names, and evidence text. Secret
redaction is best-effort; do not share a report until you have reviewed it.
Configs are parsed in full, but environment variable values are discarded
during parsing and never reported; reports keep key names for context. The [output contract](docs/OUTPUT-CONTRACT.md) lists stable fields and
the limits of these outputs.

## Known issues

- Credential redaction is pattern-based: a quoted secret flag value containing
  an escaped quote can leak its suffix; a zero-width character inside a
  bearer/basic token can leave its tail. Secret-shaped schema property names
  are not redacted, and terminal output prints tool names without credential
  redaction (terminal controls are still sanitized). A structural redaction
  redesign is planned for 2.10. Review field reports before sharing.
- A fresh CI trust store has no rollback high-water mark until its first
  verification, so restoring a complete older signed pin file in a one-shot
  CI job is not detected. Persist the trust store. Deleting it removes trusted
  keys and signing expectations; expectations are keyed by server name across
  pin files.
- Static schema header checks do not follow every composition form. Unsupported
  or ambiguous cases report incomplete coverage rather than findings.
- Legacy v1 pins do not cover annotation-only changes, title, output schema,
  icons, or metadata. Review `pin --refresh` before upgrading to v2; current
  v2 pins cover these fields, including security-relevant annotation deltas.

## More documentation

The [documentation index](docs/README.md) links current guides and references.
The [sandbox walkthrough](docs/guides/sandbox.md) is safe to try without
connecting to a server. Experimental fixture-based work is grouped under
[labs](docs/labs/README.md); maintainer-only procedures are in
[`maintainers/`](maintainers/), with older 1.x material in [`archive/`](archive/).

## Learn more

- [Pinning and drift checks](docs/guides/pinning.md)
- [Trust packet walkthrough](docs/guides/trust-packet.md) and the
  [MCP trust packet](docs/MCP-TRUST-PACKET.md)
- [Adjusting permission findings](docs/guides/suppressing.md)
- [Sandbox walkthrough](docs/guides/sandbox.md) using the
  [`examples/sandbox/`](examples/sandbox/) fixtures
- [Output contract](docs/OUTPUT-CONTRACT.md)
- [Documentation index](docs/README.md)

Experimental, fixture-based tools are documented in [the labs](docs/labs).
Maintainer procedures and project history live in [`maintainers/`](maintainers/)
and [`archive/`](archive/).
