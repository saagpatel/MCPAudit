# Contributing to MCPAudit

Thank you for your interest in contributing. MCPAudit is a security tool — contributions that touch risk scoring, threat detection, or config parsing carry extra responsibility. Please read this guide before submitting a pull request.

## Security-sensitive contributions

If your change affects how MCPAudit detects or scores threats (prompt injection patterns, permission risk scoring, schema drift logic), follow the process in [SECURITY.md](SECURITY.md) before opening a public issue or PR. When in doubt, disclose privately first.

## Getting started

### Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) — used for all dependency and virtual environment management

### Setup

```bash
git clone https://github.com/saagpatel/MCPAudit.git
cd MCPAudit
uv sync --dev
```

### Running the tool locally

```bash
uv run mcp-audit --help
```

### Running tests

```bash
uv run pytest tests/ -v
```

To run a specific test file:

```bash
uv run pytest tests/test_scorer.py -v
```

### Linting and formatting

```bash
# Check for lint errors
uv run ruff check src/ tests/

# Auto-fix lint errors
uv run ruff check --fix src/ tests/

# Check formatting
uv run ruff format --check src/ tests/

# Apply formatting
uv run ruff format src/ tests/
```

### Type checking

```bash
uv run mypy src/ --strict
```

You can also use `make` if you prefer — see the [Makefile](Makefile) for all available targets.

## Submitting a pull request

1. **Fork** the repository and create a feature branch from `main`.
   - Branch naming: `feat/short-description`, `fix/short-description`, `chore/short-description`

2. **Make your changes**, keeping commits small and focused.
   - Follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`

3. **Add or update tests** for any changed behavior. The CI matrix runs against Python 3.11, 3.12, and 3.13 — keep compatibility in mind.

4. **Update CHANGELOG.md** under the `[Unreleased]` section.

5. **Run the full check suite** before pushing:
   ```bash
   make lint test
   ```

6. **Open the PR** against `main`. Fill in the pull request template — especially the security implications section.

## Automated Review

PRs to MCPAudit run through Claude Code's [ultrareview](https://code.claude.com/docs/en/ultrareview) — a multi-agent code review that posts inline findings on the PR. Findings are advisory; reviewers (human) make the final merge decision. The review is non-blocking and typically completes in 5–10 minutes.

## Code style

- Type hints on all public functions (mypy strict mode must pass)
- f-strings over `.format()` or `%`
- `pathlib.Path` over `os.path`
- No external analysis frameworks — keep dependencies minimal
- Line length: 110 characters (ruff enforced)

## Adding a new audit dimension

If you are adding a new check or risk dimension:

1. Add the detector logic under `src/mcp_audit/`
2. Add unit tests in `tests/`
3. Update the README with the new dimension in the audit dimensions table
4. Consider whether the new check changes existing risk scores — if so, note the scoring impact in the PR description

## Questions

Open a [discussion](https://github.com/saagpatel/MCPAudit/discussions) for design questions, or a [GitHub issue](https://github.com/saagpatel/MCPAudit/issues) for bugs and feature requests.
