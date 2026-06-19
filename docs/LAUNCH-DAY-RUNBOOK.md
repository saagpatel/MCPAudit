# Launch Day Runbook

Use this only after `docs/LAUNCH-CONTROL-CARD.md` is green. This runbook
coordinates the public post and first response window; it does not replace the
field-report and security disclosure docs.

## Go / No-Go

Go only when all of these are true:

- `main` matches `origin/main`.
- CI, Self Audit, and CodeQL are green on the current `main` head.
- `uv run pytest -q` passes locally.
- `uv run ruff check .` passes locally.
- `uv run python scripts/launch_preflight.py` passes.
- Public README, image, issue-template, PyPI, and `uvx` checks pass through the
  launch preflight.
- Launch copy does not claim beta.
- The field-report command uses both `--skip-connect` and `--redact`.
- The maintainer has 3-4 hours reserved for replies.

No-go if any of these are true:

- CI or local gates are failing.
- The field-report issue template is unavailable.
- Public assets referenced by the README do not render.
- The maintainer cannot reply quickly to safety, redaction, or false-negative
  questions.

## Submit

1. Run:

   ```bash
   uv run python scripts/launch_preflight.py --print-hn-copy
   ```

2. Submit the printed URL and title to Hacker News.
3. Paste the printed first comment within about 60 seconds.
4. Confirm command blocks render correctly.
5. Open:
   - `docs/LAUNCH-RESPONSE-PLAYBOOK.md`
   - `docs/EXTERNAL-FIELD-REPORT-REQUEST.md`
   - `docs/FIELD-REPORTS.md#minimal-public-example`
   - `SECURITY.md`

## First Four Hours

Prioritize:

1. Safety and redaction questions.
2. Field-report contributors.
3. Correctness or false-negative reports.
4. CI/SARIF/policy adoption questions.
5. General MCP threat-model discussion.

For field-report leads, point to:

```bash
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact
```

Ask contributors to review the file before posting and to state whether the
redacted shape may become a public regression fixture.

## Capture Afterward

Record:

- post URL and launch time;
- recurring questions;
- field-report leads and issue links;
- accepted fixture permissions;
- confusing docs or command wording;
- any detector false-positive or false-negative candidates.

Keep the project pre-beta until two external redacted reports are accepted and
the fixture-conversion decision is complete.
