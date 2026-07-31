# Evidence Conservation evidence package candidate

This subtree contains only the `EVIDENCE_PACKAGE_ONLY` phase: the approved canonical specification,
three frozen path definitions, 21 opaque synthetic primary fixtures, 29 prerequisite record candidates,
schemas, deterministic generators, offline validators, focused tests, and admission outputs.

It does not invoke PortfolioCommandCenter, mcp-trust, BridgeDB consumer logic, MCPAudit scans, or any
primary pilot case. Every record remains `CANDIDATE`; independent review is explicitly pending. The
single known local admission failure is P1's unavailable exact pnpm 11.5.2 executable in the isolated
offline mirror, while the installed pnpm is 11.18.0.

Run the focused validator and tests with the existing local MCPAudit virtual environment only. Do not
install or update dependencies.
