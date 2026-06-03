# HANDOFF — MCPAudit

**Status:** Complete. All work merged + released. Working tree clean.
**Branch:** `main` @ `6875f88` (0 ahead / 0 behind origin). No stale branches.
**Latest on PyPI:** `1.11.0` (verified on simple index).

## Completed this session
- **1.9.0** — drop-in adoption: composite GitHub Action (`uses: saagpatel/MCPAudit@v1.11.0`),
  pre-commit hook (`.pre-commit-hooks.yaml`), repo-local `.mcp.json` discovery, self-audit
  dogfood. Fixed: empty scan now writes `--json`/`--sarif`/`--html` artifacts. (#107)
- **1.10.0** — unified `pin --refresh` (surfaces escalation + provenance deltas) +
  launch-artifact integrity `--integrity-check` / MCP024 (on-disk binary/script hash). (#108)
- **1.11.0** — registry package verification `--verify-artifacts` / MCP025 (network-gated
  npm/PyPI published-hash check), opt-in `--ssrf-allowlist`, per-server pin-staleness warnings. (#110)
- **Docs** — OUTPUT-CONTRACT rule-ID registry brought current through MCP025. (#109)

## In Progress / Blocked
- Nothing in progress. All PRs merged + tagged + released; working tree clean.
- BLOCKED (roadmap-gated, do NOT build without external field reports #83/#84/#85):
  composite-scoring (fold `non_tool_risk` into `risk_score.composite`) + default SSRF
  severity downgrade. Operator chose opt-in `--ssrf-allowlist` instead (shipped 1.11.0).

## Next Steps
- Next detection frontier: extend `--verify-artifacts` to **download-and-hash the resolved
  artifact** (truest verification) vs today's registry-published-hash compare.
- Otherwise maintenance: keep scanner + output contracts stable; gate behavior changes
  behind fixtures/sample-scan assertions.

## Key Decisions
- All detectors additive + opt-in; **never** touch `risk_score.composite`.
- `--verify-artifacts` is the only networked path besides `--llm-analysis`; offline-first by default.
- Registry verification keys by exact `package@version`; a version *float* is provenance's job (MCP021).
- SSRF allowlist suppresses only FIXED non-templated hosts — never caller-controlled targets.

## Key Files (session)
- New: `src/mcp_audit/{integrity,pkgverify}.py`, `action.yml`, `.pre-commit-hooks.yaml`,
  `.github/workflows/self-audit.yml`, `docs/{INTEGRITY,PACKAGE}-*.md`,
  `tests/test_{integrity,pkgverify,distribution}.py`.
- **Additive-detector wiring checklist** (touch all, then regen):
  `models.py` + `taxonomy.py` + `<detector>.py` + `cli.py` + `sarif.py` + `report.py` +
  `policy.py` + `server.py` + `htmlreport.py` + `pinning.py` → regen
  `output_contract_snapshot.json` + `audit-report.schema.json`.

## Verify bar
`uv run pytest` (540) ; `uv run mypy .` (whole tree — CI checks tests/) ; `uv run ruff check .` ;
`ruff format --check src/ tests/` ; `uv run python tests/validation/validate_patterns.py` ;
`uv lock --check` ; `uv build`. Release: tag `vX.Y.Z` → publish.yml OIDC → PyPI; verify simple
index BEFORE logging SHIPPED.
