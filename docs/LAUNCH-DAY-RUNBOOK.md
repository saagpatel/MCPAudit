# Launch-Day Runbook

Use this on the day MCPAudit is posted publicly. It keeps the launch packet
share-safe, pre-beta, and aligned with the current evidence bar.

## Go / No-Go

Current status: **go for launch execution, not beta**.

Use one of these primary windows:

- Tuesday, June 9, 2026, 8:00-9:30am ET
- Wednesday, June 10, 2026, 8:00-9:30am ET

Do not post on Sunday, June 7, 2026 unless intentionally choosing to ignore the
documented launch window.

Before posting, confirm:

- `main` is clean and matches `origin/main`;
- CI, Self Audit, and CodeQL are green on the current `main` head;
- README hero assets render on GitHub:
  - `docs/assets/hero-scan.gif`
  - `docs/assets/mcp-audit-config-only-scan.png`
  - `docs/assets/ci-sarif.png`
- launch copy still avoids a beta claim;
- the field-report command includes `--redact`;
- the maintainer can submit and immediately comment from the chosen Hacker News
  account.

## Hacker News

Submit this URL:

```text
https://github.com/saagpatel/MCPAudit
```

Use this title:

```text
Show HN: mcp-audit – see what your MCP servers can actually touch
```

Paste the first comment from `launch-posts.md` within about 60 seconds of
submitting. Keep the first comment text-only and let the GitHub README carry the
visuals.

Stay present for the first 3-4 hours. Reply plainly to questions about:

- why the safe path uses `--skip-connect`;
- what `--redact` does and does not scrub;
- why higher risk means broader surface, not maliciousness;
- why solo evidence does not make the project beta-ready;
- how SARIF/code scanning and policy gates fit team adoption.

If security-sensitive false negatives, proprietary server metadata, or private
prompt/tool/schema text show up in a reply, route the reporter to `SECURITY.md`
instead of a public issue.

## Follow-On Channels

Stagger follow-on posts so each thread gets attention:

- r/mcp / r/LocalLLaMA: Thursday, June 11, 2026, 9:00am-12:00pm ET
- LinkedIn: Tuesday-Thursday morning, after the HN thread is stable

Use `launch-posts.md` for the r/mcp and LinkedIn drafts. Use
`docs/EXTERNAL-OUTREACH-MESSAGES.md` for shorter public posts rather than
trimming the Show HN comment by hand.

Use `docs/LAUNCH-RESPONSE-PLAYBOOK.md` for live reply snippets and first-day
triage.

## Field-Report Routing

The beta gate is two accepted external, redacted, config-only field reports.
Route contributors to:

- request packet: `docs/EXTERNAL-FIELD-REPORT-REQUEST.md`
- safe public example: `docs/FIELD-REPORTS.md#minimal-public-example`
- issue template:
  `https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md`

Canonical contributor command:

```bash
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
```

Maintainer acceptance checks:

1. The report was produced with `scan --skip-connect`.
2. No credential values, private paths, internal hosts, private URLs, customer
   names, workspace names, or proprietary prompt/resource/tool/schema text are
   public.
3. The reporter explicitly allows fixture conversion, or the report stays in
   private triage.
4. Any accepted public fixture gets a focused regression assertion.
5. Issues #83, #84, and #85 remain open until two accepted external reports are
   handled and the release decision is made.

## If HN Does Not Catch

If the HN post does not get traction after roughly 2 hours:

- keep answering substantive comments in the original thread;
- do not repost immediately;
- optionally email `hn@ycombinator.com` with a short second-chance note;
- use at most one later repost after a cooling-off period, with the supply-chain
  angle title from `launch-posts.md`.

More than one quick repost reads as spam. The durable objective is external
field-report evidence, not a vanity launch spike.
