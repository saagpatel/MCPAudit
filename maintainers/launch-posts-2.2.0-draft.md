# MCPAudit Launch Posts: 2.2.0 (DRAFT)

> **Status: draft, pre-beta, not yet posted.** Supersedes the CLI-only
> `launch-posts.md` by adding the hosted zero-install page
> (`mcp-audit.saagarpatel.dev`) as the front door. Do not post until: (1)
> `mcp-audits` 2.2.0 is live on PyPI, (2) the page is deployed and resolves,
> (3) the two **external** redacted field reports have landed (issues #83/#84).
>
> **Honesty rules baked into this copy:**
> - The two writeups below are **first-party solo evidence** (real runs on a
>   synthetic config), clearly labeled, NOT external field reports, and NOT a
>   substitute for them.
> - No live-adoption claims.
> - CVE-2025-49596 is cited as ecosystem context only. It is an RCE in *MCP
>   Inspector* (a debugging tool), a **different layer** than config risk, so
>   the copy never implies mcp-audit would have caught it.

---

## Hacker News

### Title (primary)

```text
Show HN: Paste your MCP config, see what your AI agents can actually touch
```

### Title (variants, pick one)

```text
Show HN: mcp-audit, a local scanner for what your MCP servers can reach
Show HN: I built a config-only trust check for MCP servers (no install)
```

### Body / first comment

```text
Every MCP server you wire into Claude Desktop, Cursor, Windsurf, or Claude Code
gets real reach into your machine (files, shell, network, your tokens), and
there's almost no tooling to see that surface before you connect.

mcp-audit reads the MCP configs already on your machine and shows, per server,
what each one can actually touch: file/network/shell/destructive/exfiltration
surface, plus config-health flags (package-runner launches, remote endpoints,
credential-heavy entries, duplicate names).

Two ways to run it:

1. Zero-install, in your browser: https://mcp-audit.saagarpatel.dev
   Paste a config, get a config-only report. It runs the exact same engine in
   config-only mode, so it never launches a server and never makes a network
   request. The pasted config is parsed in memory for one request and is never
   stored or logged.

2. The CLI, for the deep checks the browser deliberately can't do:
   uvx --from mcp-audits mcp-audit scan
   A connected scan reads each server's real tool schemas and adds prompt-
   injection detection (in tool/prompt/resource text), SSRF, the lethal
   trifecta (read + untrusted-input + exfiltration in one fleet), schema-drift
   pinning, a policy gate, SARIF + a GitHub Action, and an egress check.

Why I built it: MCP security isn't hypothetical. CVE-2025-49596 (CVSS 9.4) was
a critical RCE in Anthropic's own MCP Inspector: a missing-auth localhost flaw
chained with a browser bug, fixed in 0.14.1. That's a different layer than what
mcp-audit checks (it audits what the servers you connect can reach, not the
debugger), but it's the same lesson: this ecosystem moved fast and the security
tooling is still catching up.

Design choices worth calling out:
- Config-only is a conservative preview by design. Without launching a server,
  only declared config is visible, so scores skew low, and the page says so
  loudly. A reassuring grade is NOT the headline; the findings list is.
- Risk != malicious. A higher score means a broader surface to review and
  sandbox, not "dangerous." A filesystem server scoring high is expected.
- Fully local. The CLI never phones home; the only optional network call is an
  opt-in package-byte verification against the npm/PyPI host allowlist.

Repo: https://github.com/saagpatel/MCPAudit
PyPI: https://pypi.org/project/mcp-audits/

It's pre-beta and I'd genuinely like the scrutiny: heuristics, false-positive
rates, how it treats servers without connecting. If you run MCP servers, a
redacted config-only field report is the most useful thing you could send:
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md
```

---

## Solo Evidence Writeup #1: "5 seconds, zero install" (the hosted page)

> First-party demo. Real `mcp-audit` output on a **synthetic** config that
> mirrors a realistic developer setup (filesystem + github + postgres + fetch +
> a shell-to-webhook bridge + an HTTP remote). No real machine data. Reproducible:
> paste the config below into https://mcp-audit.saagarpatel.dev or run
> `mcp-audit scan --config <file> --config-only --skip-connect`.

**The config (realistic, but synthetic):**

```json
{
  "mcpServers": {
    "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"] },
    "github":     { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "" } },
    "postgres":   { "command": "uvx", "args": ["postgres-mcp"], "env": { "DATABASE_URI": "" } },
    "fetch":      { "command": "uvx", "args": ["mcp-server-fetch"] },
    "automation": { "command": "bash", "args": ["-c", "npx -y @acme/agent-bridge --webhook https://hooks.acme.dev/in"] },
    "notion":     { "type": "http", "url": "https://mcp.notion.com/v1" }
  }
}
```

**What the config-only scan returns (verbatim, 6 servers, 0 high-risk):**

The conservative part first: config-only finds **0 high-risk** servers, because
without connecting it can only reason about declared config. That's the point,
and the report says so. What it *does* surface is the review surface and seven
config-health flags:

| Server | Config-only risk | Inferred surface |
|---|---|---|
| `automation` | 1.3 | network, **shell_execution** |
| `filesystem` | 1.0 | file_read, file_write, network |
| `github` | 0.8 | network, file_read |
| `postgres` | 0.4 | network |
| `fetch` | 0.4 | network |
| `notion` | 0.4 | network |

Seven config-health findings (all medium):
- `filesystem`, `github`, `postgres`, `fetch`: each launches through a package
  runner (`npx`/`uvx`); review the package or image source before connecting.
- `automation`: command/args include a remote URL; review the outbound target.
- `automation`: launches through a shell wrapper (`bash`); review args.
- `notion`: declares a remote endpoint; connected scans may contact the network.

**The takeaway the page leads with:** the `automation` server (a `bash -c` that
shells out to a remote webhook) is the thing to look at first. Not because it's
malicious, but because it's the broadest, least-inspectable surface in the fleet,
and it took five seconds and zero installs to spot it.

---

## Solo Evidence Writeup #2: "Config-only is the floor, not the ceiling" (the CLI moat)

> First-party. Honest framing of what the page deliberately does NOT do, and
> why the connected CLI scan is where the real depth lives.

The hosted page is intentionally shallow: it runs in **config-only** mode, so it
never launches your servers. That's a privacy and safety guarantee, but it has a
hard limit: the most dangerous MCP risks live in the **tool schemas**, and you
only see those after connecting. On the synthetic config above, a config-only
pass reports `total_tools: 0`, so the deep detectors have nothing to chew on yet.

That's exactly the line between the page and the CLI:

| Check | Hosted page (config-only) | CLI connected scan |
|---|---|---|
| Surface map (file/shell/network/exfil) | yes | yes |
| Config-health (runners, remotes, creds) | yes | yes |
| Prompt-injection in tool/prompt/resource text | no (no schemas) | **yes** |
| SSRF (caller-steerable destinations) | no | **yes** |
| Lethal trifecta across the fleet | no | **yes** |
| Schema-drift pinning (`--pin-check`) | no | **yes** |
| Egress destination audit | no | **yes** |
| Policy gate / SARIF / GitHub Action | no | **yes** |

mcp-audit is the only MCP scanner that covers SSRF + egress + the lethal
trifecta + schema drift together, the only one that emits SARIF and ships a
GitHub Action, and the only one that runs fully local. The browser page is the
front door; the CLI is the house.

```text
# graduate from the page to the full scan:
uvx --from mcp-audits mcp-audit scan --inject-check --ssrf-check --trifecta-check
# in CI, with a policy gate and SARIF for code scanning:
uses: saagpatel/MCPAudit@v2.2.0
```

> Not shown here as fabricated output: a connected scan against a deliberately
> hostile server (real injection/trifecta findings) is the strongest demo, but
> it requires spawning servers and is best captured as part of the external
> field-report lane rather than asserted in launch copy.

---

## The two EXTERNAL field reports (launch gate, NOT first-party)

These are tracked in issues [#83](https://github.com/saagpatel/MCPAudit/issues/83)
/ [#84](https://github.com/saagpatel/MCPAudit/issues/84) and must come from real
outside users running it on their own setups. The Show HN copy above stays
pre-beta until both land. Outreach below leads with the zero-install browser
hook (5 seconds, no commitment), then asks for the redacted CLI report as the
actual contribution. Builds on `docs/EXTERNAL-OUTREACH-MESSAGES.md`.

### Message 1: warm DM (someone you know who runs MCP servers)

```text
Built a thing you might find useful: paste your MCP config (Claude Desktop /
Cursor / Windsurf / Claude Code) at https://mcp-audit.saagarpatel.dev and it
shows what each server can actually touch (files, shell, network) plus what to
review before you connect. No install, nothing stored, runs in your browser.

If it surfaces anything interesting on your setup, the most helpful thing you
could do is drop a redacted report. One command, no server is launched and
nothing is contacted:

  uvx --from mcp-audits mcp-audit scan --skip-connect --json report.json --redact

then open an issue here: https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

--redact scrubs hostname, home-path usernames, and server names. Still glance
over it and strip anything private before posting. No worries if you only have
time for the browser version. Either way I'd love to hear what it flagged.
```

### Message 2: community post (MCP / AI-tooling Discord, Slack, forum)

```text
If you run MCP servers, you can now see their reach without installing anything:
https://mcp-audit.saagarpatel.dev to paste a config and get a config-only trust
report (file/shell/network/exfiltration surface + config-health flags). Runs
fully in-browser, never launches a server, never makes a network request,
stores nothing.

It is the hosted front door to mcp-audit (PyPI: mcp-audits), a local CLI that
adds the deeper connected checks: prompt-injection in tool descriptions, SSRF,
the lethal trifecta, schema drift, SARIF + a GitHub Action.

It is pre-beta and I want real scrutiny. If you can spare two minutes, a
redacted config-only report is the single most useful thing:

  uvx --from mcp-audits mcp-audit scan --skip-connect --json report.json --redact
  # then: https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md

False positives, heuristics, anything that looks wrong: all fair game.
```

### Message 3: maintainer follow-up (when someone bites)

```text
Thanks, this is exactly what helps. The useful signals are: version, OS, MCP
clients, approximate server count, status counts, config-health finding types,
whether a consumer parsed the JSON/SARIF, and whether the redacted shape is OK
to become a public test fixture. Anything sensitive stays out of the issue and
goes through SECURITY.md instead.
```

**Redaction boundaries (every message, non-negotiable).** Do not solicit or
accept: credential values; private paths or usernames; internal hostnames or
private URLs; customer / workspace names; proprietary prompt / tool / resource
/ schema text. Security-sensitive false negatives route to `SECURITY.md`.

---

## Honesty ledger: what this copy must NOT claim

- No live-user / adoption numbers until external reports exist.
- Do not imply mcp-audit would have caught CVE-2025-49596 (wrong layer).
- Do not present the config-only grade as a clean bill of health; it is a
  conservative floor, and the copy says so every time it appears.
- Solo evidence (#1, #2) is labeled solo; it does not stand in for the two
  external field reports.

CVE reference verified against multiple independent advisories (Tenable, Oligo,
Recorded Future, Qualys, Docker): CVSS 9.4, missing-auth localhost RCE in MCP
Inspector, fixed in 0.14.1, disclosed 2025-06-13.
