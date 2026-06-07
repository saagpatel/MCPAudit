# hero.tape - MCPAudit hero GIF (records the README "60-second start" moment)
#
# Produces docs/assets/hero-scan.gif: a CONNECTED `--ssrf-check` scan against a
# curated PUBLIC demo config, rendering the summary panel, the per-server risk
# table, and the SSRF Warnings - the same story as the README hero.
#
# HOW TO RECORD
#   1. brew install vhs                       (pulls ttyd; needs ffmpeg)
#   2. uv tool install mcp-permission-audit
#   3. PRE-WARM off-camera so npx/uvx packages are cached and the GIF is fast:
#        mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --ssrf-check
#   4. Record from the repo root so the relative paths resolve:
#        vhs docs/assets/hero.tape
#
# SAFETY
#   Scans ONLY docs/assets/hero-demo-config.json (public, no-auth servers). It
#   never reads your real MCP configs. Numbers are REAL output - eyeball the GIF
#   before posting. COLUMNS=185 keeps the risk table tight (no permission wrap).

Output docs/assets/hero-scan.gif

Require mcp-audit

Set Shell        "bash"
Set FontSize     12
Set Width        1480
Set Height       1480
Set Padding      24
Set Margin       16
Set BorderRadius 10
Set Theme        "Catppuccin Mocha"
Set WindowBar    Colorful
Set TypingSpeed  60ms

# Hidden setup: clean prompt, pinned width, mute server stderr banners, and put
# the mise-managed npx/uvx + the mcp-audit tool on PATH so all servers connect.
Hide
Type "export PS1='$ '" Enter
Type 'export PATH=$HOME/.local/bin:$PATH; for d in $HOME/.local/share/mise/installs/*/*/bin; do PATH=$d:$PATH; done; export PATH' Enter
Type "export COLUMNS=185" Enter
Type "exec 2>/dev/null" Enter
Type "clear" Enter
Show

Sleep 600ms
Type "mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --ssrf-check"
Sleep 800ms
Enter

# Hold while the scan spawns the public servers, enumerates tools, and renders.
Sleep 5s

# Linger on the final frame so the loop reads cleanly.
Sleep 3s

# OFFLINE FALLBACK: for a fully offline, deterministic GIF (no servers spawned,
# no network), swap the Type line for:
#   Type "mcp-audit scan --config docs/assets/hero-demo-config.json --config-only --skip-connect"
# It renders identically every run but shows status `skipped`, 0 tools, and
# inferred-from-config risk instead of the connected table + SSRF block.
