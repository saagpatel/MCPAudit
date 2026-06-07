# Launch Response Playbook

Use this after the Show HN / Reddit / LinkedIn posts are live. Keep replies
plain, technical, and honest: MCPAudit is launch-ready, but still pre-beta until
two external redacted field reports are accepted.

## Reply Principles

- Answer the actual question first.
- Keep "risk" language precise: broad capability surface is not the same as
  malicious behavior.
- Keep the safe path crisp: `--skip-connect` means no server spawn and no
  network contact; `--redact` helps scrub shared artifacts.
- Never ask contributors to paste secrets, private paths, internal hostnames,
  private URLs, or proprietary prompt/tool/schema text.
- Route security-sensitive false negatives or proprietary metadata to
  `SECURITY.md`, not public issue comments.
- Do not claim beta, production hardening, broad false-positive rates, or
  enterprise readiness beyond the evidence already in the repo.

## First 60 Seconds

1. Submit the GitHub repo URL.
2. Paste the first comment from `launch-posts.md`.
3. Check the comment rendered with the command blocks intact.
4. Open the issue-template URL in a separate tab:
   `https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md`
5. Keep `docs/EXTERNAL-FIELD-REPORT-REQUEST.md` and
   `docs/FIELD-REPORTS.md#minimal-public-example` ready for contributor replies.

## Common Replies

### "Is this safe to run?"

```text
The safe first run is config-only:

uvx --from mcp-permission-audit mcp-audit scan --skip-connect

With --skip-connect it does not spawn MCP servers or contact remote endpoints; it
reasons from the local config. If you are sharing a report publicly, use:

mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Still review before posting: don't include secrets, private paths, internal hosts,
private URLs, or proprietary prompt/tool/schema text.
```

### "Does a high risk score mean the server is bad?"

```text
No. The score is surface-area guidance, not a malware verdict. A server that can
read repos, mutate issues, reach the network, or run shell should score higher
because it needs more review and sandboxing. Narrow tools like time/fetch should
score lower. The point is visibility and gating, not shaming specific servers.
```

### "Why not just rely on MCP client permissions?"

```text
Client permissions help, but they don't give the same inventory and drift story.
MCPAudit is meant to answer: what servers are configured, what can they plausibly
do, did their launch config or package bytes change, and can I gate that in CI?
It complements client controls rather than replacing them.
```

### "Why SARIF/code scanning?"

```text
For individual users, the terminal report is enough. For teams, SARIF is useful
because MCP config risk becomes reviewable in the same place as other code
security findings. The composite GitHub Action runs config-only by default and
can fail CI through local YAML policy.
```

### "Can I send you my report?"

```text
Yes, if it is redacted and config-only. Please use:

mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json --redact

Then open a field-report issue:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

Please include version, OS, clients, approximate server count, status counts,
finding types, whether a consumer parsed the report, and whether the redacted
shape may become a public fixture.
```

### "I think you missed a risky pattern."

```text
Thank you. If the example can be public, please open a minimal redacted issue
with the smallest config/report shape that reproduces it. If it involves private
server metadata, proprietary prompts/schemas, or a security-sensitive false
negative, please use the SECURITY.md private disclosure path instead.
```

### "Is this beta?"

```text
Not yet. The solo field scan proves the paths work end-to-end on my machine and
on popular public packages, but I am holding the beta label until two external,
redacted, config-only reports are accepted and turned into durable evidence.
```

## Triage During The First 4 Hours

Prioritize replies in this order:

1. Safety and redaction questions.
2. Field-report contributors.
3. Correctness or false-negative reports.
4. CI/SARIF/policy adoption questions.
5. General MCP threat-model discussion.

For every accepted field-report lead:

- point them to the issue template;
- remind them to use `--skip-connect` and `--redact`;
- ask for fixture permission explicitly;
- keep issues #83, #84, and #85 as the beta-evidence tracking path.

## If The Thread Gets Hostile

Stay boring and factual:

- acknowledge limitations;
- separate solo evidence from external evidence;
- correct misunderstandings once;
- avoid arguing about intent;
- invite reproducible examples and redacted fixtures.

Do not escalate tone. The launch goal is evidence collection and trust, not
winning every subthread.

## After The First Day

Capture:

- post URL and launch time;
- questions that kept recurring;
- field-report leads and issue links;
- any docs that confused readers;
- any detector or policy false-positive / false-negative candidates.

If no external reports land, keep the project pre-beta and use the best recurring
question as the next docs improvement lane.
