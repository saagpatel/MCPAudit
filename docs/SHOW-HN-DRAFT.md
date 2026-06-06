# Show HN / Blog Draft — Field Scan + Field-Report Recruitment

Purpose: recruit two external, redacted, config-only field reports
([#83](https://github.com/saagpatel/MCPAudit/issues/83) /
[#84](https://github.com/saagpatel/MCPAudit/issues/84)) by leading with the
solo field scan in
[`docs/FIELD-SCAN-POPULAR-SERVERS.md`](FIELD-SCAN-POPULAR-SERVERS.md).

Tone target: honest, technical, builder-to-builder. No marketing voice — HN
punishes it. Lead with results, state limitations plainly, end with the ask.

---

## A. Show HN submission

**Title** (≤ 80 chars, plain "Show HN:" format):

```
Show HN: MCPAudit – do you actually know what your MCP servers can access?
```

**URL to submit:**

```
https://github.com/saagpatel/MCPAudit
```

**First comment** (HN convention: author posts context as the first comment):

```text
I build a lot of MCP servers and wire them into Claude Desktop, Claude Code,
Cursor, and VSCode, and I kept wanting a quick answer to "what can the things
in my config actually do, and did the packages they launch change under me?"
So I wrote MCPAudit.

It's a Python CLI that reads the MCP server configs already on your machine
and reports on them. The default path is offline and read-only: it never
modifies a config file, and with --skip-connect it doesn't spawn or connect to
anything — it reasons purely from the config. It only reports env-var key
names, never values. A connected scan (opt-in) spawns the servers to read
their real tool schemas; networked package verification and LLM analysis are
both separate opt-in flags.

The ask, up front: before I put a "beta" label on this I want two external,
redacted, config-only field reports from setups that aren't mine. If you run
MCP servers, this is ~2 minutes and stays entirely on the safe path:

    python3 -m pip install --upgrade mcp-permission-audit
    mcp-audit --version
    mcp-audit scan --skip-connect --json mcp-audit-field-report.json

That command is config-only — no servers spawned, no network. Then open a
redacted report (the template prompts you for the safe fields):
https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md
Please strip credential values, private paths, internal hostnames, private
URLs, and proprietary prompt/tool/schema text — full checklist in the request
packet:
https://github.com/saagpatel/MCPAudit/blob/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md

What it checks: inferred permission/capability scope per server, prompt-
injection patterns in tool/prompt/resource text, SSRF-shaped tools (caller-
controllable server-side fetch), cross-server tool-name shadowing, the
"lethal trifecta" toxic-flow surface across a fleet, capability escalation and
launch-config drift vs a pinned baseline, on-disk artifact hash drift, and
byte-level package verification — it downloads the real npm/PyPI bytes, hashes
them in memory (never to disk, never executed), and checks them against the
registry's published hash and a pin-time baseline. Output is rich terminal,
JSON, SARIF 2.1.0, or self-contained HTML.

To show the verification path works on real software, I ran it against a set
of popular public servers — the official npm ones (server-filesystem,
-everything, -memory, -sequential-thinking, -github) and PyPI ones
(mcp-server-git, -fetch, -time). What it found:

- Byte verification: 7/7 packages had a retrievable published hash, 7/7
  downloaded and hashed, 7/7 matched. PyPI multi-file releases (sdist + wheel)
  each verified per-file. Zero false positives on clean packages — which is
  the point: the check stays quiet on good software and only fires when bytes
  actually disagree.
- Connected scan: 7/9 connected, 64 tools enumerated. Inferred risk tracked
  capability surface sensibly — github scored highest (26 tools spanning repo
  read/write, issue/PR mutation, network), the narrow ones (time, fetch)
  lowest. Higher score = broader surface to sandbox, NOT "malicious."
- Two SSRF findings (fetch, everything) — both genuinely expose a caller-
  controllable fetch tool, so the flag matches documented behavior. Zero
  prompt-injection findings on these clean official servers.

Full writeup with the numbers:
https://github.com/saagpatel/MCPAudit/blob/main/docs/FIELD-SCAN-POPULAR-SERVERS.md

That scan is solo evidence — it does not by itself make this beta-ready; the
two external reports above are what close that gap. Happy to answer anything
about the heuristics, the threat model, or why it's deliberately offline-first.
```

---

## B. Blog-post version (longer form)

### I pointed my MCP auditor at the most popular public servers. Here's what it found.

If you use Claude Desktop, Claude Code, Cursor, VSCode, or Windsurf, you
probably have a handful of MCP servers wired into your config right now. Each
one is a process that can be launched on your behalf, often via `npx` or `uvx`
— which means each launch fetches and runs remote code, and each server
exposes some set of tools with some amount of reach into your machine and your
network.

I wanted a fast, boring answer to two questions:

1. What can the servers in my config actually *do*?
2. Did the packages behind them change under me since I last looked?

So I built **MCPAudit** — a Python CLI that reads the MCP configs already on
your machine and tells you. It's deliberately offline-first and read-only by
default: it never edits a config, it reports env-var *key names* and never
their values, and its baseline mode (`--skip-connect`) doesn't spawn or
contact anything at all.

#### What it checks

- **Capability/permission inference** — a deterministic, rule-based read of how
  broad each server's surface is (file read/write, network, mutation), so you
  know what to sandbox.
- **Prompt-injection patterns** in tool, prompt, and resource text.
- **SSRF-shaped tools** — caller-controllable server-side fetch targets.
- **Cross-server tool-name shadowing** — exact, normalized, and homoglyph
  collisions where one server can impersonate another's tool.
- **Lethal-trifecta / toxic-flow** surface across the whole fleet.
- **Drift vs a pinned baseline** — capability escalation ("rug pull"),
  launch-config/provenance changes, and on-disk artifact hash drift.
- **Byte-level package verification** — it downloads the actual npm/PyPI bytes,
  hashes them in memory (never written to disk, never executed), and compares
  against both the registry's published hash and a pin-time baseline.

Output is rich terminal for humans, plus JSON, SARIF 2.1.0, and a
self-contained HTML report for CI and dashboards.

#### The field scan

Solo claims are cheap, so I ran the verification engine against real, popular,
public packages — the official npm servers (`server-filesystem`,
`-everything`, `-memory`, `-sequential-thinking`, `-github`) and PyPI servers
(`mcp-server-git`, `-fetch`, `-time`), pinned to their current releases.

**Byte-level verification (MCP025 + MCP026):**

| Check | Result |
|-------|--------|
| Published hash retrievable | 7 / 7 |
| Bytes downloaded and hashed | 7 / 7 |
| Downloaded bytes matched published hash | 7 / 7 |
| PyPI multi-file (sdist + wheel) per-file match | confirmed |
| Floating/unpinned version | correctly skipped |

Zero false positives on clean packages. That's the behavior you want from an
integrity check: silent on good software, loud only when the bytes actually
disagree.

**Connected reference scan** (7/9 connected, 64 tools enumerated):

| Server | Risk | Why |
|--------|------|-----|
| `github` | 9.35 | 26 tools — repo read/write, issue/PR mutation, network |
| `sequential-thinking` | 8.6 | one tool, broadly-scoped reasoning/state |
| `everything` | 8.0 | maximal demo server: file I/O, network, SSRF-shaped fetch |
| `git`, `memory` | 5.3 | repository / knowledge-graph mutation |
| `time`, `fetch` | 3.8 / 3.5 | narrow, single-purpose |

A higher score means a broader surface to sandbox, **not** that a server is
malicious. Two SSRF findings landed on `fetch` and `everything` — both
genuinely expose a caller-controllable fetch tool, so the flags match
documented behavior — and **no** prompt-injection findings fired on any of
these clean official servers. Low false-positive rate on known-good software
is exactly the signal I was after.

#### The honest part: I need external evidence

That whole scan is *solo* evidence. It's useful for local confidence, and it
proves the networked verification path works end-to-end — but it's all from my
machine, my configs, my reading of the output. Before MCPAudit wears a "beta"
label, I want **two external, redacted, config-only field reports** from setups
that aren't mine ([#83](https://github.com/saagpatel/MCPAudit/issues/83),
[#84](https://github.com/saagpatel/MCPAudit/issues/84)).

If you run MCP servers, contributing one is a couple of minutes and stays
entirely on the safe path:

```bash
python3 -m pip install --upgrade mcp-permission-audit
mcp-audit --version
mcp-audit scan --skip-connect --json mcp-audit-field-report.json
```

`--skip-connect` is config-only — it won't spawn servers or touch the network.
Then open a redacted report; the template prompts you for the safe fields
(version, OS, client mix, rough server count, finding types):

<https://github.com/saagpatel/MCPAudit/issues/new?template=field_report.md>

Please redact credential values, private paths, internal hostnames, private
URLs, customer/workspace names, and any proprietary prompt/tool/schema text.
The full redaction checklist and what to include is in the request packet:

<https://github.com/saagpatel/MCPAudit/blob/main/docs/EXTERNAL-FIELD-REPORT-REQUEST.md>

A report can become a small public regression fixture (with your permission),
which is the most useful thing of all: it turns "it worked on my machine" into
a test that keeps working on everyone's.

Repo: <https://github.com/saagpatel/MCPAudit>

---

## C. Posting notes

- **Submit the repo as the URL**, not a blog link — Show HN favors the thing
  itself. Drop the first comment immediately after submitting.
- **Time it** for a US-morning weekday (≈ 8–10am ET) for the best front-page
  window; avoid Fri/weekend.
- **Reuse, don't fork, the ask.** The install + report command and redaction
  list here are copied verbatim from
  [`EXTERNAL-OUTREACH-MESSAGES.md`](EXTERNAL-OUTREACH-MESSAGES.md) so every
  channel says the same thing. If the canonical ask changes, update there
  first, then re-sync this draft.
- **Stay in the thread.** Answer heuristic/threat-model questions plainly;
  acknowledge false-negative reports and point security-sensitive ones to the
  `SECURITY.md` private-disclosure path instead of a public issue.
- **Don't claim beta.** Solo + this scan do not close #83/#84; only two
  accepted external reports do. Keep that line honest in replies.
- **Ship `--redact` first.** A release including `scan --redact` (auto-scrubs
  hostname + home-path usernames from `--json`/`--sarif`/`--html`) is the
  friction-killer for contributors. It landed on `main` but is unreleased — before
  posting, cut a release, then append `--redact` to the field-report command here
  and in `EXTERNAL-OUTREACH-MESSAGES.md` / `EXTERNAL-FIELD-REPORT-REQUEST.md`. Don't
  reference it in the copy-paste ask until it's on the published package.
- **Shorter channels** (Reddit r/LocalLLaMA, Mastodon, X, Discord): use the
  "Public Post" block already in `EXTERNAL-OUTREACH-MESSAGES.md` rather than
  trimming this one — it's pre-redacted and pre-approved.
