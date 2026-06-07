# Launch Control Card

Use this as the single screen during the Hacker News launch window. It is a
thin operator card over the canonical launch docs:

- full timing and routing: `docs/LAUNCH-DAY-RUNBOOK.md`
- live reply snippets: `docs/LAUNCH-RESPONSE-PLAYBOOK.md`
- long-form channel copy: `launch-posts.md`

## Timing

Primary windows:

- Tuesday, June 9, 2026, 8:00-9:30am ET
- Wednesday, June 10, 2026, 8:00-9:30am ET

Sunday, June 7, 2026 is **not** the planned Hacker News launch window.

## Submit Fields

URL:

```text
https://github.com/saagpatel/MCPAudit
```

Title:

```text
Show HN: mcp-audit – see what your MCP servers can actually touch
```

First comment source:

```text
launch-posts.md -> "Body / first comment"
```

Field-report command that must appear in the first comment:

```bash
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
```

## Open Before Submit

- Hacker News submit page, logged in and able to comment:
  `https://news.ycombinator.com/submit`
  Confirm it shows the submit form, not a login prompt.
- GitHub repo README:
  `https://github.com/saagpatel/MCPAudit#readme`
- Field-report issue template:
  `https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md`
- `docs/LAUNCH-RESPONSE-PLAYBOOK.md`
- `docs/EXTERNAL-FIELD-REPORT-REQUEST.md`
- `docs/FIELD-REPORTS.md#minimal-public-example`
- `SECURITY.md`

## Final Go Check

- `main` matches `origin/main`.
- CI, Self Audit, and CodeQL are green on the current `main` head.
- `python scripts/launch_preflight.py` passes, including public README / asset
  URL checks plus PyPI / `uvx` package checks.
- README visuals render:
  - `docs/assets/hero-scan.gif`
  - `docs/assets/mcp-audit-config-only-scan.png`
  - `docs/assets/ci-sarif.png`
  - `docs/assets/policy-gate.gif`
  - `docs/assets/html-report.png`
- Launch copy does not claim beta.
- Public field-report command includes `--redact`.
- Maintainer has 3-4 hours free for replies.

## First 5 Minutes

1. Run `python scripts/launch_preflight.py --print-hn-copy`.
2. Submit the printed repo URL and title.
3. Paste the printed first comment within about 60 seconds.
4. Confirm the first comment's command blocks rendered correctly.
5. Keep the response playbook open.
6. Reply first to safety/redaction questions and field-report contributors.

## Do Not Do

- Do not call the project beta.
- Do not ask anyone to paste secrets, private paths, internal hostnames,
  private URLs, customer/workspace names, or proprietary prompt/tool/schema text.
- Do not handle security-sensitive false negatives in public comments; route
  those to `SECURITY.md`.
- Do not repost immediately if the thread stalls.

## Success Criteria

The launch succeeds if it produces qualified field-report leads, useful threat
model questions, or reproducible detector feedback. A front-page spike is nice,
but the durable goal is external evidence for #83, #84, and #85.
