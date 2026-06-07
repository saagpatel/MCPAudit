# hero.tape - MCPAudit hero GIF (records the README "60-second start" moment)
#
# Produces docs/assets/hero-scan.gif: a CONNECTED `--ssrf-check` scan against a
# curated PUBLIC demo config, rendering the summary panel, per-server risk table,
# and SSRF Warnings - the same shape as the README hero sample.
#
# HOW TO RECORD
#   1. Install vhs:      brew install vhs        (needs ffmpeg + ttyd)
#   2. Install the tool: uv tool install mcp-permission-audit
#   3. PRE-WARM off-camera so npx/uvx packages are cached and the GIF is clean:
#        time mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --ssrf-check
#   4. Record from the repo root so the relative paths resolve:
#        vhs docs/assets/hero.tape
#
# SAFETY
#   Scans ONLY docs/assets/hero-demo-config.json (public, no-auth servers). It
#   never reads your real MCP configs. Still eyeball the final GIF before posting.
#   The on-screen numbers are real output. If they drift from the README sample,
#   reconcile the README sample to match (DEMO-ASSETS.md notes this).

Output docs/assets/hero-scan.gif

Require mcp-audit

Set Shell        "bash"
Set FontSize     15
Set Width        1200
Set Height       820
Set Padding      24
Set Margin       16
Set BorderRadius 10
Set Theme        "Catppuccin Mocha"
Set WindowBar    Colorful
Set TypingSpeed  70ms

# Clean, minimal prompt and a pinned width so Rich renders consistently.
Hide
Type "export PS1='$ '" Enter
Type "export COLUMNS=118" Enter
Type "clear" Enter
Show

Sleep 700ms
Type "mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --ssrf-check"
Sleep 900ms
Enter

# Hold while the scan spawns public servers, enumerates tools, and renders.
# Tune this to the duration printed by the pre-warm run. Too short cuts off.
Sleep 9s

# Linger on the final frame so the loop reads cleanly.
Sleep 3s

# OFFLINE FALLBACK
# Prefer a fully offline, deterministic GIF with no servers spawned and no
# network? Swap the Type line above for:
#   Type "mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --skip-connect"
# It renders fast and identically every run, but shows status `skipped`, 0 tools,
# inferred-from-config risk, and config-health findings instead of the connected
# table plus SSRF block. If you ship this variant as the hero, update the README
# sample to match so the GIF and the docs never drift.
