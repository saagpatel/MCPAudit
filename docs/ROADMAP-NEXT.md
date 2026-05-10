# MCPAudit Next Roadmap

MCPAudit `1.3.0` is published with structured config-health findings and
opt-in policy gates. The next line should deepen config-only confidence and
adoption examples without changing tool scoring semantics.

## 1. Config Health Depth

Status: in progress.

Add fixture-backed diagnostics only when they can be detected from local MCP
configuration without connecting to servers or reading credential values.

Shipped after `1.3.0`:

- missing local command paths for stdio servers;
- server names that conflict across global and project scopes.

Candidate follow-ups:

- package-runner source review for commands such as `npx`, `uvx`, and `docker`;
- conflicting client definitions when two clients point the same server name at
  meaningfully different commands or URLs;
- clearer remediation text for intentionally shadowed project-local servers.

## 2. Adoption Examples

Status: in progress.

Keep examples copy-pasteable and conservative. Examples should start with
`--skip-connect` when the goal is config-health review, then graduate to
connected scans only after the server set is understood.

Shipped after `1.3.0`:

- GitHub Actions config-health policy gate example;
- Python and Node JSON consumers that summarize config-health findings by
  severity per server.

Candidate follow-ups:

- dashboard-oriented JSON examples once downstream consumers appear;
- organization-specific policy profiles only when repeated user patterns justify
  them.

## 3. Pin Maintenance UX

Status: hold writes explicit.

Keep `pin --stale` read-only and keep cleanup server-scoped through
`pin --clear <server>`. Bulk stale cleanup remains intentionally out of scope
until users show a repeated need for it.

## 4. Prompt And Resource Scoring

Status: observe before changing scoring.

Prompt/resource findings stay visible, policy-gatable, and summarized through
`non_tool_risk`. Do not merge them into `risk_score.composite` until more
real-world fixtures prove a stable scoring model.

## Verification Bar

Before the next release, run:

```bash
uv run pytest
uv run ruff check
uv run mypy .
uv run ruff format --check
uv lock --check
git diff --check
uv run python tests/validation/validate_patterns.py
uv build --clear
```
