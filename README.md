# mcp-audit

<!-- mcp-name: io.github.saagpatel/mcp-audit -->

[![PyPI](https://img.shields.io/pypi/v/mcp-audits?label=PyPI)](https://pypi.org/project/mcp-audits/)
[![CI](https://img.shields.io/github/actions/workflow/status/saagpatel/MCPAudit/ci.yml?label=CI)](https://github.com/saagpatel/MCPAudit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Audit the MCP servers configured for your AI clients. `mcp-audit` inventories
declared capabilities, highlights risky access and configuration drift, and
can compare results over time with reviewed pins.

## Start safely

> **Read-only by default.** Config-only scans do not start configured servers
> or contact their endpoints. Reports show environment variable key names,
> never values. Connected scans, package verification, downloads, and LLM
> analysis have additional reach; opt into them deliberately.

1. Install the CLI:

   ```sh
   uv tool install mcp-audits
   ```

2. Scan the included synthetic config without discovering workstation configs:

   ```sh
   mcp-audit scan --config examples/sandbox/fixtures/synthetic-mcp-config.json \
     --config-only --skip-connect --override-config /dev/null
   ```

3. Explore the built-in offline protocol demo:

   ```sh
   mcp-audit session-resume list
   ```

The package is `mcp-audits`; the installed command is `mcp-audit`.

## What to read next

- [Start here](docs/start-here.md) for common tasks and the command map.
- [How it works](docs/how-it-works.md) for the scan flow and trust boundaries.
- [Reading results](docs/reading-results.md) for severity, warnings, and limits.
- [CI guide](docs/guides/ci.md) for SARIF and policy gates.
- [Pinning guide](docs/guides/pinning.md) for reviewed schema baselines.
- [Trust packet guide](docs/guides/trust-packet.md) for the offline ecosystem demo.
- [Suppressing guide](docs/guides/suppressing.md) for allowlists and policy choices.
- [Sandbox guide](docs/guides/sandbox.md) for the synthetic prompt-injection exercise.
- [Staged rollout](docs/GOLDEN-ROLLOUT.md) for moving from review to CI policy.
- [Labs](docs/labs/) for experimental offline analyzers and simulators.
- [Output contract](docs/OUTPUT-CONTRACT.md) for JSON, SARIF, and exit behavior.
- [Changelog](CHANGELOG.md) for release history; earlier planning material is in the [archive index](archive/README.md).
- [1.5 evidence intake](archive/1.5-evidence-intake.md) is retained for historical context.

## One small example

Run a local config-only check and save a machine-readable report:

```sh
mcp-audit scan --config ./mcp.json --config-only --skip-connect \
  --override-config /dev/null --json audit.json
```

To inspect a known config locally, use `--config PATH --config-only` and
`--skip-connect`. Add `--policy policy.yaml` to apply a local policy gate.
Connected checks and package verification are opt-in; see the [CI guide](docs/guides/ci.md).

## Choose a workflow

### Review declared access

Use an explicit config-only scan to review launch commands, transports,
credential key names, package runners, and declared endpoints. Configuration
findings help identify malformed or conflicting entries before connection.

### Inspect live schemas

When you intend to start a configured server or contact its endpoint, run a
connected scan deliberately. It can inspect available tools, prompts, and
resources for capability and injection patterns. The resulting report is
evidence from that run; it does not establish future behavior.

### Compare changes over time

Pinning saves a reviewed tool-schema baseline. Later scans can report schema
drift and related changes. Refreshes are explicit; see the [pinning guide](docs/guides/pinning.md).

### Export or gate results

JSON supports structured consumers, SARIF supports code-scanning workflows,
and HTML packages a report for review. A local policy can fail a scan after
reports are written; policy results do not remove detector findings.

### Learn with synthetic inputs

The [sandbox guide](docs/guides/sandbox.md) walks through a synthetic config.
The [offline labs](docs/labs/) cover additional supplied-input analyzers and
protocol simulators; their outputs do not prove live server behavior.

## GitHub Action

The composite action runs config-only by default and can upload SARIF:

```yaml
- uses: saagpatel/MCPAudit@v2.7.0
```

Use a reviewed version tag in workflows. Release maintainers check floating
`@v2` references with the release checklist before updating the major tag.

## Share a redacted field report

The config-only report command does not start configured servers or contact
their endpoints. `uvx` may contact the configured Python package index and may
reuse its tool cache:

```sh
uvx --from mcp-audits mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
```

See the [field report guide](docs/FIELD-REPORTS.md) before sharing; remove
credential values and proprietary tool or prompt text. See
[feedback to fixtures](docs/FEEDBACK-TO-FIXTURES.md) for safe regression reports.

## License

MIT
