# MCPAudit 1.1 Roadmap

MCPAudit `1.0.0` keeps the stable output contract intentionally conservative.
The `1.1` line should add depth without changing existing scoring semantics.

## Goals

- Expand real-world server coverage before changing risk models.
- Keep `risk_score.composite` stable unless a future breaking release says
  otherwise.
- Add optional, additive fields for new risk signals.
- Turn user feedback into fixtures before changing analyzer behavior.

## Candidate Lanes

### Additive Non-Tool Risk

Status: shipped in `1.1.0`.

Introduced an optional `non_tool_risk` report field after calibration. This
field summarizes prompt and resource risk without changing
`risk_score.composite`.

Done when:

- prompt/resource fixtures cover common server families;
- JSON compatibility snapshots include the additive field;
- policy examples show how to gate on prompt/resource findings without relying
  on composite score changes.

Follow-up calibration should continue collecting false-positive and
false-negative examples before any policy default gates on `non_tool_risk`.

### Policy Packs

Add more policy profiles for common adoption shapes:

- solo workstation review;
- locked-down CI;
- reviewed local developer workstation;
- AI-assistant-heavy browser automation environments.

Done when each policy loads in tests and has a documented intended audience.

### Pin Maintenance UX

Keep pin writes explicit and server-scoped, but consider a dry-run stale-baseline
report for users with many reviewed servers.

Done when stale cleanup remains review-first and cannot silently delete multiple
baselines.

### Downstream Consumer Hardening

Add tests and examples for consumers that parse MCPAudit JSON/SARIF artifacts.

Done when example CI files parse cleanly and output-contract fixtures cover the
fields used by those examples.

## Non-Goals

- Do not change `risk_score.composite` semantics in a patch release.
- Do not make connected scans the only recommended path for first-time users.
- Do not add LLM-dependent default behavior.
