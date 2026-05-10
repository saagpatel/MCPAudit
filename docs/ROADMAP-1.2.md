# MCPAudit 1.2 Roadmap

MCPAudit `1.2` focuses on adoption depth: make configuration health easier to
consume in CI and inventory systems without changing tool risk scoring.

## Goals

- Keep `risk_score.composite` stable.
- Make config-health diagnostics visible in terminal and JSON output.
- Preserve SARIF rule IDs and existing JSON fields.
- Keep connected scans opt-in for first-time rollout paths.

## Shipped In This Line

### Structured Config Health

Status: in progress.

`discover` and `scan` already show terminal config-health warnings. The next
step is additive JSON output through top-level `config_health_findings`, so
automation can parse duplicate names, missing stdio commands, deprecated SSE
transports, shell-wrapper launches, remote endpoints, remote URL arguments, and
credential-heavy configs.

Done when:

- JSON output includes stable finding metadata;
- output-contract fixtures and schema include the additive field;
- docs explain that config-health findings do not affect composite risk;
- release notes call out the additive output field.

## Candidate Follow-Ups

- Optional policy gates for config-health findings after users validate the
  signal.
- Consumer examples that summarize config-health findings.
- Additional config diagnostics for missing local binaries and conflicting
  project/global scopes, if fixture-backed examples justify them.

## Non-Goals

- Do not change tool scoring semantics in `1.2`.
- Do not make config-health warnings policy failures by default.
- Do not expose credential values; key names only.
