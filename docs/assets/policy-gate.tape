# policy-gate.tape - MCPAudit CI policy gate demo
#
# Produces docs/assets/policy-gate.gif: a zero-touch scan against the public
# fixture with the strict example policy, showing Policy Gate Failed and the
# real process exit code (`2`).
#
# SAFETY
#   Uses --config examples/configs/popular-public-servers.json --config-only
#   --skip-connect, so no real workstation configs are read, no MCP servers are
#   spawned, and no network calls are made.

Output docs/assets/policy-gate.gif

Require mcp-audit

Set Shell        "bash"
Set FontSize     15
Set Width        1500
Set Height       1040
Set Padding      24
Set Margin       16
Set BorderRadius 10
Set Theme        "Catppuccin Mocha"
Set WindowBar    Colorful
Set TypingSpeed  48ms

Hide
Type "export PS1='$ '" Enter
Type "export COLUMNS=112" Enter
Type "clear" Enter
Show

Sleep 600ms
Type "bash docs/assets/policy-gate-demo.sh"
Sleep 800ms
Enter

Sleep 3s
