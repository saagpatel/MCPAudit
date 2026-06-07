# Demo Assets to Record — mcp-audit

A shot list for the GIFs and screenshots that would make the README and launch posts
land. **Nothing here is fabricated** — this is a recording plan; capture the real
output yourself before publishing.

## 🔒 Recording safety (read first — this is a security tool)

A live scan of your real machine can expose your installed MCP servers, file paths,
credential key names, and infra. **Do not record against your real config.** Record
every asset below against the repo's bundled public config so the demo is reproducible
and leaks nothing:

```bash
# Safe, public, in-repo target — no real workstation data
mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --skip-connect
```

- Use `--config examples/configs/popular-public-servers.json --config-only` for every
  shot so only the public sample servers appear.
- Before publishing any frame, scrub for: home paths (`/Users/...`, `/home/...`,
  `C:\Users\...`), hostnames, real server names, tokens/keys, and your shell prompt
  (set a neutral prompt like `PS1='$ '` or use a clean recording profile).
- For any connected/network shots, prefer `--redact` on file output and review the
  artifact before it leaves your machine.
- Suggested tools: [`asciinema`](https://asciinema.org/) + [`agg`](https://github.com/asciinema/agg)
  for crisp terminal GIFs (selectable text, small files), or `vhs` for scripted,
  repeatable captures. Target a readable terminal width (~100 cols) and font size.

---

## Priority 1 — the hero GIF (README top + LinkedIn)

**`hero-scan.gif`** — the 60-second "what can my servers touch" moment. Matches the
README hero sample.
- Show typing: `uvx --from mcp-permission-audit mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --ssrf-check`
- `--config ... --config-only` scopes the scan to **only** the bundled public config, so
  your real configs never appear. Dropping `--skip-connect` lets it connect to those
  public sample servers and enumerate real tool schemas (that's what fills the table and
  the SSRF section). Still leaks nothing about your machine — the servers are public.
- Capture the summary panel + the per-server risk table rendering (the colored Risk
  column is the payoff — red high-risk, yellow mid, green low) + the SSRF Warnings block.
- ~8–12 seconds. Loop-friendly. This is the single most important asset.
- If you'd rather keep the hero fully offline, swap in `--skip-connect` instead and
  record the config-only shape (status `skipped`, inferred risk, config-health findings)
  — and update the README sample to match so the two never drift.

## Priority 2 — the SARIF / CI story (security-team audience)

**`ci-sarif.png`** (or short GIF) — `mcp-audit` findings inside GitHub code scanning.
- Run the scan with `--sarif mcp-audit.sarif` against the public config, upload via the
  documented Action, and screenshot the **Security → Code scanning** alerts view showing
  `MCPxxx` rule IDs.
- Reinforces "gate MCP configs like dependencies." Pairs with the LinkedIn post.

**`policy-gate.gif`** — a CI policy gate failing on purpose.
- `mcp-audit scan --config examples/configs/popular-public-servers.json --config-only --policy examples/policies/ci-strict.yaml`
- Show the terminal output + the non-zero exit (`echo $?` → `2`). Demonstrates the
  enforcement path in a few seconds.

## Priority 3 — flagship detector spotlights (r/mcp + docs)

**`ssrf-check.gif`** — `--ssrf-check` flagging a caller-controllable fetch tool.
- Add `--ssrf-check` to the base command; capture the **SSRF Warnings** section.

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

---

## Notes for whoever records these

- Keep the bundled `examples/configs/popular-public-servers.json` as the single demo
  fixture across all assets so the story is consistent and reproducible.
- If a detector needs a finding that the public config doesn't naturally produce
  (e.g. shadowing), add a tiny **synthetic** config under a scratch path with
  placeholder server names — never a real one — and note that it's illustrative.
- Store final assets under `docs/assets/` (or a `media/` dir) and reference them from
  the README with relative paths once recorded.
