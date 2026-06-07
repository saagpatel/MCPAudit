# Demo Assets to Record — mcp-audit

A shot list for the GIFs and screenshots that would make the README and launch posts
land. **Nothing here is fabricated** — this is a recording plan; capture the real
output yourself before publishing.

## 🔒 Recording safety (read first — this is a security tool)

A live scan of your real machine can expose your installed MCP servers, file paths,
credential key names, and infra. **Do not record against your real config.** Record
every asset below against the repo's bundled public config so the demo is reproducible
and does not expose your workstation configs:

```bash
# Safe, public, in-repo target; no real workstation configs, no servers spawned
mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --skip-connect
```

- Use `--config examples/configs/popular-public-servers.json --config-only` for every
  shot so workstation-discovered configs never appear. Add `--skip-connect` unless the
  shot is explicitly a reviewed connected-scan demo.
- Before publishing any frame, scrub for: home paths (`/Users/...`, `/home/...`,
  `C:\Users\...`), hostnames, real server names, tokens/keys, and your shell prompt
  (set a neutral prompt like `PS1='$ '` or use a clean recording profile).
- For any connected/network shots, prefer `--redact` on file output and review the
  artifact before it leaves your machine. Connected scans may start package-runner
  commands from the sample config and contact configured HTTP endpoints.
- Suggested tools: [`asciinema`](https://asciinema.org/) + [`agg`](https://github.com/asciinema/agg)
  for crisp terminal GIFs (selectable text, small files), or `vhs` for scripted,
  repeatable captures. Target a readable terminal width (~100 cols) and font size.

---

## Priority 1 — the hero GIF (README top + LinkedIn)

**`hero-scan.gif`** — the 60-second "what can my servers touch" moment.
- Show typing: `mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --ssrf-check`
- Recording script: `docs/assets/hero.tape`.
- `--config ... --config-only` scopes the scan to **only** the bundled public config, so
  your real configs never appear. Leaving off `--skip-connect` makes this a connected
  demo: MCPAudit may start the curated public sample package commands to enumerate tool
  schemas (that's what fills the table and the SSRF section). The hero config intentionally
  uses a compact no-auth subset (`fetch`, `sequential-thinking`, `time`) and omits sample
  entries that need auth tokens, real local paths, or placeholder remote URLs.
  The recording redirects server startup stderr off-camera so package-runner noise does not
  obscure the real MCPAudit report.
  Review the captured output before publishing even though the input fixture is public.
- Capture the summary panel + the per-server risk table rendering (the colored Risk
  column is the payoff — red high-risk, yellow mid, green low) + the SSRF Warnings block.
- ~8–12 seconds. Loop-friendly. This is the single most important asset.
- If you'd rather keep the hero fully offline, swap in `--skip-connect` instead and
  record the config-only shape (status `skipped`, inferred risk, config-health findings)
  — and update the README sample to match so the two never drift.

## Priority 2 — the SARIF / CI story (security-team audience)

**`ci-sarif.png`** (or short GIF) — `mcp-audit` findings inside GitHub code scanning.
- Run the scan with `--skip-connect --sarif mcp-audit.sarif` against the public config, upload via the
  documented Action, and screenshot the **Security → Code scanning** alerts view showing
  `MCPxxx` rule IDs.
- Reinforces "gate MCP configs like dependencies." Pairs with the LinkedIn post.

**`policy-gate.gif`** — a CI policy gate failing on purpose.
- `mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --skip-connect --policy examples/policies/ci-strict.yaml`
- Show the terminal output + the non-zero exit (`echo $?` → `2`). Demonstrates the
  enforcement path in a few seconds.

## Priority 3 — flagship detector spotlights (r/mcp + docs)

**`ssrf-check.gif`** — `--ssrf-check` flagging a caller-controllable fetch tool.
- Use a reviewed connected scan with `--ssrf-check`; capture the **SSRF Warnings**
  section. Keep this separate from the zero-touch config-only recording path.

**`trifecta-check.gif`** — `--trifecta-check` lighting up the lethal-trifecta / toxic-flow
surface (per-server HIGH and/or fleet-level advisory).

**`shadow-check.gif`** — `--shadow-check` catching a cross-server tool-name collision
(use a config with two servers exposing the same tool name to force the finding).

**`drift-rugpull.gif`** — the supply-chain story, two-shot:
1. `mcp-audit pin` against a baseline config.
2. Swap a tool/capability in the config, then `mcp-audit scan --escalation-check` to show
   the "rug pull" finding vs the baseline. The most compelling narrative for the
   supply-chain angle — worth scripting with `vhs` for repeatability.

## Priority 4 — shareable artifacts (static, easy wins)

**`html-report.png`** — screenshot of the self-contained HTML report
(`mcp-audit scan --config ... --html report.html`, opened in a browser). Good for blog
embeds; the report is already redaction-aware.

**`terminal-static.png`** — a clean still of the risk table for the PyPI page (PyPI
renders the README but not animated GIFs reliably, so a static fallback helps).

Produced:
- `docs/assets/mcp-audit-config-only-scan.png` — static zero-touch preview generated
  from the bundled public config with `--config-only --skip-connect`.
- `docs/assets/hero-demo-config.json` — curated public connected-scan fixture for a
  hero GIF; it avoids workstation configs, auth-token servers, and real-path arguments.
- `docs/assets/hero.tape` — `vhs` script that records `docs/assets/hero-scan.gif`
  from the curated fixture.
- `docs/assets/hero-scan.gif` — connected scan GIF recorded from `docs/assets/hero.tape`
  against the curated public fixture.

---

## Notes for whoever records these

- Keep `examples/configs/popular-public-servers.json` as the zero-touch/static demo fixture.
  Use `docs/assets/hero-demo-config.json` only for the connected hero GIF, where the curated
  subset avoids auth-token, local-path, and placeholder-remote setup noise.
- If a detector needs a finding that the public config doesn't naturally produce
  (e.g. shadowing), add a tiny **synthetic** config under a scratch path with
  placeholder server names — never a real one — and note that it's illustrative.
- Store final assets under `docs/assets/` (or a `media/` dir) and reference them from
  the README with relative paths once recorded.
