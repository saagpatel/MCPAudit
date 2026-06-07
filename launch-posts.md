# Launch Posts — mcp-audit

Drafts for amplifying `mcp-audit` (PyPI: `mcp-permission-audit`) to platform and
security teams adopting MCP / AI agents. Tone: honest, builder-to-builder, results
first. Two channels below — a **Show HN / r/mcp** version and a **LinkedIn** version.

**Before posting, read the canon.** The field-report recruitment ask and the redaction
checklist are owned by [`docs/EXTERNAL-OUTREACH-MESSAGES.md`](docs/EXTERNAL-OUTREACH-MESSAGES.md)
and [`docs/SHOW-HN-DRAFT.md`](docs/SHOW-HN-DRAFT.md). If the canonical ask changes, update
there first, then re-sync these. The numbers cited below come from the solo field scan in
[`docs/FIELD-SCAN-POPULAR-SERVERS.md`](docs/FIELD-SCAN-POPULAR-SERVERS.md) — keep them
honest (solo evidence, not a beta claim).

---

## 1. Show HN / r/mcp

**Title** (≤ 80 chars):

```
Show HN: mcp-audit – see what your MCP servers can actually touch
```

For **r/mcp**, use the same body with this title instead:

```
I built an offline auditor for MCP servers — permissions, injection, supply-chain drift
```

**URL to submit:** `https://github.com/saagpatel/MCPAudit`

**Body / first comment:**

```text
If you run Claude Desktop, Claude Code, Cursor, VS Code, or Windsurf, you probably
have a handful of MCP servers wired into your config right now. Each one is a process
that can read your files, reach the network, or run shell on your behalf — and most
are launched from a remote npx/uvx package that can change underneath you between one
session and the next. I wanted a fast, boring answer to two questions:

  1. What can the servers in my config actually DO?
  2. Did the packages behind them change since I last looked?

So I built mcp-audit. It's a Python CLI that reads the MCP configs already on your
machine and reports on them. The safe first-run path is deliberately offline and
read-only: it never edits a config, it reports env-var KEY NAMES only (never values),
and with --skip-connect it doesn't spawn or contact anything — it reasons purely from
the config. Dropping --skip-connect gives you a connected scan that reads real tool
schemas; networked package verification and LLM analysis are separate opt-in flags.

Zero-install, config-only, in one line:

    uvx --from mcp-permission-audit mcp-audit scan --skip-connect

What it checks, with config-only coverage where possible and explicit connected modes
where schemas or live metadata are required:
  - Permission/capability inference per server (file read/write, network, shell,
    destructive, exfiltration) — so you know what to sandbox.
  - Prompt-injection patterns in tool / prompt / resource text.
  - SSRF-shaped tools — caller-controllable server-side fetch targets.
  - Cross-server tool-name shadowing (exact, normalized, and homoglyph collisions
    where one server can impersonate another's tool).
  - Lethal-trifecta / toxic-flow surface across the whole fleet.
  - Drift vs a pinned baseline: capability escalation ("rug pull"), launch-config /
    provenance changes, and on-disk artifact hash drift.
  - Byte-level package verification (opt-in, network): it downloads the actual
    npm/PyPI bytes, hashes them in memory — never to disk, never executed — and
    checks them against the registry's published hash AND a pin-time baseline.

Output is rich terminal, JSON, SARIF 2.1.0, or a self-contained HTML report. There's
a composite GitHub Action that writes SARIF straight to code scanning, a pre-commit
hook for repo-local .mcp.json, and local YAML policy gates that exit non-zero for CI.

For platform/security folks: the SARIF + policy path is the point. You can gate a
team's MCP config in CI the same way you gate dependencies — config-only by default,
fail the build on a shell-execution server or an unreviewed capability escalation.

Solo claims are cheap, so I ran the verification engine against popular public
servers — the official npm ones (server-filesystem, -everything, -memory,
-sequential-thinking, -github) and PyPI ones (mcp-server-git, -fetch, -time):
  - Byte verification: 7/7 packages had a retrievable published hash, 7/7 downloaded
    and hashed, 7/7 matched. Zero false positives on clean packages — exactly the
    behavior you want: silent on good software, loud only when bytes disagree.
  - Connected scan: 7/9 connected, 64 tools enumerated. github scored highest (26
    tools spanning repo read/write, issue/PR mutation, network); the narrow ones
    (time, fetch) lowest. Higher score = broader surface to sandbox, NOT "malicious."
  - Two SSRF findings (fetch, everything) — both genuinely expose a caller-
    controllable fetch tool. Zero prompt-injection findings on these clean servers.

Honest caveat: that's all SOLO evidence — my machine, my configs. It proves the
paths work end-to-end, but before I put a "beta" label on this I'm collecting two
external, redacted, config-only field reports from setups that aren't mine. If you
run MCP servers and want to contribute one, it's ~2 minutes on the safe path and the
README + docs/EXTERNAL-FIELD-REPORT-REQUEST.md walk you through redaction. The safe
public example shape is docs/FIELD-REPORTS.md#minimal-public-example.

Repo: https://github.com/saagpatel/MCPAudit
Field scan writeup: docs/FIELD-SCAN-POPULAR-SERVERS.md
Safe example shape: docs/FIELD-REPORTS.md#minimal-public-example

Happy to answer anything about the heuristics, the threat model, or why it's
deliberately offline-first.
```

**Posting notes:**
- Submit the **repo** as the URL (Show HN favors the thing itself); drop the body as the
  first comment immediately after.
- Time it for a US-morning weekday (~8–10am ET); avoid Fri/weekend.
- Stay in the thread. Answer heuristic/threat-model questions plainly; route security-
  sensitive false-negative reports to the `SECURITY.md` private-disclosure path, not a
  public issue.
- Don't claim beta. Solo evidence + this scan don't close the external-report gate.

---

## 2. LinkedIn

Audience: platform engineering and security leaders standing up MCP / AI-agent tooling
across a team or org. Slightly more adoption-framed, still honest. Skimmable.

```text
Your developers are installing AI agents faster than anyone is reviewing them.

Every MCP server wired into Claude, Cursor, or VS Code is a process with real reach:
it can read files, hit the network, or run shell commands on a developer's machine —
usually launched from a remote npm/PyPI package that can change between sessions.
That's a new local attack surface and a new software-supply-chain dependency, landing
in your fleet without a PR, a review, or an inventory.

I built mcp-audit to make that surface visible. It's a free, open-source (MIT) CLI
that reads the MCP configs already on a machine and reports what each server can do,
how risky it is, whether its tool descriptions hide adversarial instructions, and
whether the packages behind it changed since they were last approved.

What makes it safe to run on a real workstation:
 → Read-only by default. It never edits a config. It reports environment-variable
   KEY NAMES only — never their values.
 → A safe first-run config-only mode (--skip-connect) that doesn't spawn a server or
   touch the network at all. Connected scans, package verification, downloads, and
   LLM analysis make their extra reach explicit in the command.

What makes it useful for a platform/security team:
 → SARIF 2.1.0 output that uploads straight to GitHub code scanning.
 → Local YAML policy gates that fail CI on what you decide matters — a shell-execution
   server, an unreviewed capability escalation, a config-health problem.
 → Supply-chain checks: it pins a baseline, then flags capability "rug pulls," launch-
   config swaps, and on-disk / byte-level package drift against it.
 → A composite GitHub Action and a pre-commit hook, so you can gate MCP configs the
   same way you already gate dependencies.

Try it in 60 seconds, zero install, fully offline:

   uvx --from mcp-permission-audit mcp-audit scan --skip-connect

It's early and honest about it — I'm actively gathering external field reports before
calling it beta. But if your org is adopting MCP, the inventory-and-gate problem is
already here, and this is a free place to start.

Repo + docs: https://github.com/saagpatel/MCPAudit
Safe field-report example: https://github.com/saagpatel/MCPAudit/blob/main/docs/FIELD-REPORTS.md#minimal-public-example

#MCP #AIagents #PlatformEngineering #DevSecOps #SupplyChainSecurity #AppSec
```

**Posting notes:**
- LinkedIn favors a strong first line above the "…see more" fold — the opening hook is
  written for that.
- Pair with a short demo GIF (see `DEMO-ASSETS.md`) recorded against a **synthetic
  sandbox config**, never a real workstation.
- Keep the "early / honest / pre-beta" line in — it builds more trust with this audience
  than a polished pitch, and it matches the project's actual posture.

---

## 3. Title A/B + posting-time plan

The title is the entire top of the funnel, and HN's ranking is velocity-sensitive —
the first hour of upvotes-per-time decides whether you hit the front page. Pick one
title, lead with it, and hold the others as a documented second-chance fallback.

### Show HN title variants (HN caps titles at 80 chars; must start with `Show HN:`)

| # | Title | Chars | Angle |
|---|-------|-------|-------|
| **A** ⭐ | `Show HN: mcp-audit – see what your MCP servers can read, run, and reach` | 71 | Plain + concrete. "read, run, reach" maps to file/shell/network. HN-safe, no hype. |
| **B** | `Show HN: Do you actually know what your MCP servers can access?` | 63 | Curiosity gap; mirrors the README hook. Higher CTR, slightly riskier (HN can read rhetorical titles as clickbait). |
| C | `Show HN: Does your editor still run the MCP code you approved?` | 61 | Supply-chain / rug-pull angle. Best as a second-wave repost title if A/B stalls. |
| D | `Show HN: An offline auditor for the MCP servers in your editor` | 62 | Plainest, lowest-curiosity, maximally HN-safe fallback. |

**Recommendation:** lead with **A** (concrete, factual, names the tool — the form HN
rewards). Hold **B** as the A/B alternate if you get a second-chance window. **C** is
the title to use for a single legitimate repost later, since it sells a *different*
story (drift/supply-chain) and won't read as spamming the same post.

> Don't change the title mid-thread. "A/B" here means *across attempts*, not live —
> HN doesn't allow meaningful title edits after votes land.

### r/mcp title variants (no prefix; niche, friendly, technical is fine)

- ⭐ `I built an offline auditor for MCP servers — permissions, injection, supply-chain drift`
- `mcp-audit: see what every MCP server in your editor can actually do (offline, MIT)`
- `I pointed an auditor at the most popular public MCP servers — here's what it found` (results-led; link `docs/FIELD-SCAN-POPULAR-SERVERS.md` in the body)

### Posting-time plan (front-page window)

HN ranking rewards fast early velocity, so post when the most of your audience is awake
and you'll have a full business day for the post to mature.

- **Primary slot:** **Tuesday or Wednesday, 8:00–9:30am ET.** Catches US-East morning +
  US-West early risers + Europe afternoon, and leaves all day to climb.
- **Avoid:** Monday (crowded `/newest` queue, inbox-clearing), Friday afternoon →
  weekend (low traffic), and the **12–2pm ET** lunch lull.
- **Submit the repo URL** (not a blog link), then paste the prepared first comment
  within ~60 seconds — the body is what converts a click into an upvote.
- **Be present for 3–4 hours after posting.** Reply to every substantive question fast;
  early engagement velocity is most of the ranking signal.
- **Pre-flight checklist:** account can comment immediately (enough karma), first
  comment is copy-paste ready, README hero looks sharp (✓ done), and the demo GIF is
  embedded in the README (record via `DEMO-ASSETS.md` first if possible — a visible GIF
  lifts Show HN conversion noticeably).
- **If it doesn't catch in ~2 hours:** HN has a moderator "second-chance" pool — you can
  email `hn@ycombinator.com` with a one-line context note, or do **one** clean repost
  after a cooling-off period using title **C** (the supply-chain angle). One repost max;
  more reads as spam.

### Channel stagger (don't split your own attention)

You can only be in one thread at a time, and every channel needs live replies. Stagger
across the week instead of firing all three at once:

| Day | Channel | Title |
|-----|---------|-------|
| Tue/Wed AM | Hacker News | Show HN **A** |
| Thu (9am–12pm ET) | r/mcp (+ r/LocalLLaMA) | r/mcp ⭐ variant |
| Tue–Thu, your AM | LinkedIn | LinkedIn draft (§2) |

Keep the cross-channel ask identical (install + `--skip-connect` one-liner) so every
surface points at the same safe path; only the framing changes per audience.
