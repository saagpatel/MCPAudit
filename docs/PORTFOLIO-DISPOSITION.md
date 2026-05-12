# MCPAudit (mcp-permission-audit) — Portfolio Disposition

**Status:** Release Frozen — Python CLI **already published to PyPI**
as `mcp-permission-audit` at **v1.5.5**, classified
"Development Status :: 5 - Production/Stable." Audits locally-
configured MCP servers for permission surface, adversarial
descriptions, and schema drift. **First member of a new PyPI
distribution cluster** — distinct from desktop signing, iOS App
Store, static-host, and self-hosted service clusters.

> Disposition uses strict `origin/main` verification.
> **Introduces the PyPI distribution cluster** as the fifth
> top-level disposition cluster.

---

## Verification posture

This repo has **only `origin`** (`saagpatel/MCPAudit`) — no
`legacy-origin` remote. Clean migration state. Local clone's `main`
is tracking `origin/main` correctly.

Specifically verified on `origin/main`:

- Tip: `1182db8` (HEAD)
- **Release cadence visible in commit log:**
  - `chore(release): prepare 1.4.0`
  - `chore(release): prepare 1.4.1`
  - `chore(release): prepare 1.4.2`
  - `chore(release): prepare 1.4.3`
  - Current `pyproject.toml` version: **1.5.5**
  - Gap between 1.4.3 and 1.5.5 implies the operator skipped
    intermediate releases or didn't tag them in the log grep
- Recent substantive commits:
  - `d636020` feat(pin): add reviewed stale cleanup
  - `832594a` feat(config): flag package runner definitions
  - `1d2697a` feat(config): deepen config health adoption
- **PyPI package identity (`pyproject.toml` on `origin/main`):**
  - `name = "mcp-permission-audit"`
  - `version = "1.5.5"`
  - `Development Status :: 5 - Production/Stable`
  - Author: `saagpatel <saagarpatel08@gmail.com>`
  - Topic classifiers: Security, Software Development :: Libraries
- Tree on `origin/main`:
  - `src/` (Python source)
  - `tests/`, `fixtures/` (test data)
  - `examples/`, `docs/`
  - Standard codex-os scaffolding
- Default branch: `main`

---

## Current state in one paragraph

`mcp-permission-audit` (CLI command: `mcp-audit`) is a Python CLI
that gives operators "x-ray vision into every MCP server configured
on your system: what it can do, how risky it is, whether its
descriptions are hiding adversarial instructions, and whether it's
changed since you last looked." Local-first, no API key by default,
networked LLM analysis opt-in. Subcommands include `discover` (no
connection), `scan` (configurable: skip-connect, inject-check,
pin-check, per-client filter), `pin` (capture/refresh tool schemas
for drift detection), `--json` and `--sarif 2.1.0` export. Published
to PyPI; production-stable per classifier. The operator's own
`mcp_audit` module name aligns with the CLI naming.

For full detail see `README.md` on `origin/main`.

---

## Why "Release Frozen (PyPI)" — NOT any other cluster

MCPAudit is a Python CLI published to PyPI:

- **Not desktop signing cluster** — no Tauri/Rust desktop binary
- **Not iOS App Store cluster** — Python, not Swift
- **Not static-host cluster** — CLI tool, not web app
- **Not self-hosted service cluster** — operator-invoked command,
  not long-running service

The release model is **PyPI versioned releases** with `pip install
mcp-permission-audit`. The operator has already shipped 1.4.0 →
1.4.3 → 1.5.5 with explicit `chore(release): prepare X.Y.Z` commits.

---

## Cluster taxonomy update

This row introduces the **fifth top-level disposition cluster**:

| Cluster | Count | Distribution |
|---|---|---|
| **Signing (Apple desktop)** | 22 | DMG via Apple Developer ID |
| **iOS App Store** | 1 | App Store Connect |
| **Static-host (web)** | 3 | Vercel / Netlify |
| **Self-hosted service** | 1 | launchd + nginx |
| **PyPI distribution (new)** | **1** | `pip install` from PyPI |

GithubRepoAuditor (next disposition this round) also has `feat(release):
PyPI publish workflow + shiv binary distribution` on canonical main,
so the cluster will likely grow to 2 within this round.

---

## Unblock trigger (operator)

This row is already shipped. No unblock needed in the standard sense
— there is no "credentials wired" gate, no "App Store review"
gate. The relevant ongoing operations are:

1. **PyPI release cadence.** The 1.4.x → 1.5.5 history shows steady
   shipping. Next release is whenever the operator has another
   batch of features to cut.
2. **PyPI account security.** PyPI is the distribution channel —
   operator should have 2FA + PyPI API tokens (not username/password)
   and trusted publishers / OIDC if using GitHub Actions release
   workflow.
3. **Security advisories surface.** Since this audits *other* MCP
   servers, a CVE or advisory in this tool's own dependency chain
   would be material. Worth a periodic `pip-audit` of its own deps.

No operator-only release-readiness work blocks v1.5.5 — that's
already on PyPI.

---

## Portfolio operating system instructions

| Aspect | Posture |
|---|---|
| Portfolio status | `Release Frozen (PyPI)` |
| Distribution channel | **PyPI** — `pip install mcp-permission-audit` → `mcp-audit` CLI |
| Current version | **1.5.5** (Production/Stable per classifier) |
| Review cadence | Suspend overdue counting — already shipping continuously |
| Resurface conditions | (a) Operator cuts a new release, (b) PyPI account compromised or token rotation needed, (c) security advisory in own deps, or (d) operator opens a v2.0 scope packet |
| Do **not** auto-add to signing cluster | Python CLI, not desktop binary |
| Do **not** auto-add to iOS App Store cluster | Python, not Swift |
| Do **not** auto-add to static-host cluster | CLI, not web app |
| Do **not** auto-add to self-hosted service cluster | Operator-invoked command, not daemon |
| **New cluster: PyPI distribution** | **First member.** GithubRepoAuditor likely joins this round; other Python packages in portfolio should batch here as they're audited. |
| Special concern | **PyPI account 2FA + API token rotation.** This is the operational risk for PyPI distribution. |
| Special concern | **Dogfood-adjacent.** This tool audits MCP servers in the operator's own MCP-running stack — if it ever broke its own audit, that's a category-bug. |

---

## Why this row founds the PyPI distribution cluster

Every prior cluster boundary was discovered via distribution shape:

- Apple desktop signing → DMG + notarization
- iOS App Store → App Store Connect + human review
- Static-host → Vercel / static SPA
- Self-hosted service → launchd + nginx

PyPI is similarly clean as a cluster boundary:

- Different release artifact (sdist + wheel, not binary)
- Different distribution channel (PyPI.org, not GitHub Releases)
- Different version semantics (semver enforced by PyPI conventions)
- Different acquisition flow for users (`pip install`, no signing
  trust dialog)
- Different security model (PyPI 2FA + tokens, not Apple Developer
  certificates)

No cluster member needs Apple credentials, App Store Review, Vercel
deployment, or nginx config — all are PyPI-specific releases.

---

## Reactivation procedure (for the next code session)

1. Verify `git branch -vv` shows `main` tracking `origin/main`.
   Already correct as of this disposition pass.
2. No stash created this pass — working tree was clean.
3. Re-run `uv sync && pytest` to confirm toolchain.
4. Check PyPI for `mcp-permission-audit` page is current.
5. Check `pip-audit` results for any new advisories in this tool's
   own dependency chain.

---

## Last known reference

| Field | Value |
|---|---|
| `origin/main` tip | `1182db8` (HEAD) |
| Last substantive commit | `d636020` feat(pin): add reviewed stale cleanup |
| Default branch | `main` |
| Build system | Python 3.11+ (uv-managed) + Click + Rich + pyproject.toml |
| Distribution | **PyPI** — `pip install mcp-permission-audit` |
| Current version | **1.5.5** (Production/Stable) |
| Release cadence visible | 1.4.0 → 1.4.1 → 1.4.2 → 1.4.3 → 1.5.5 |
| Export formats | JSON, SARIF 2.1.0 |
| Build verification status | Operator verifies via CI / PyPI release process |
| Blocker | **None for the shipped release.** Future releases are operator-cadence. |
| Migration state | **No `legacy-origin` remote** — clean |
| Distinguishing feature | **Already shipped to PyPI.** First PyPI distribution cluster member. |
