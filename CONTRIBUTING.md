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

Run tests from a real Git checkout. A passing broad suite can contain expected
skips, so it verifies only the tests that ran. Use the smallest lane that proves
your change, then run the full suite before opening a pull request.

The current lane selections are:

| Lane | Command | Current expected result | Prerequisite and claim boundary |
| --- | --- | --- | --- |
| Portable behavior | `uv run pytest -p no:cacheprovider -q -m 'not skipif' --ignore=tests/test_repo_hygiene.py tests/` | 1,590 selected; 0 skipped on hosts with a nonzero `os.O_NONBLOCK` | Python 3.11–3.13, Git, a writable test root, and a nonzero `os.O_NONBLOCK` are required for the zero-skip result. Marker-declared host, service, and platform prerequisites are excluded; unmarked Git-dependent tests and two runtime capability guards remain selected. If `os.O_NONBLOCK` is missing, those two guards skip at runtime; a zero-valued constant is unsupported and has no zero-skip claim. |
| Proof Before Action pre-runtime rejection | `uv run pytest -p no:cacheprovider -q tests/test_proof_before_action.py::test_sensitive_repository_input_is_blocked_before_execution tests/test_proof_before_action.py::test_literal_config_secret_and_sensitive_argv_are_redacted_or_blocked` | 5 passed; 0 skipped | Does not need Docker. It proves only that sensitive inputs are rejected before runtime inspection. |
| Proof Before Action Docker execution | `uv run pytest -p no:cacheprovider -q -m skipif tests/test_proof_before_action.py tests/test_proof_attempt_evidence.py` | 24 passed when ready | Requires a reachable Docker daemon and the exact local `node:24-slim` image. Twenty-four skips mean the optional prerequisite is unavailable, not verified. Do not pull the image merely to turn a local result green. |
| ProofOS PostgreSQL | `uv run pytest -p no:cacheprovider -q -m skipif tests/test_proofos_postgres.py` | 6 passed when ready | Requires PostgreSQL 16 server binaries and a writable socket-capable temporary root. Six skips mean the optional prerequisite is unavailable. The tests manage only disposable local processes; they do not prove production database safety. |
| Repository hygiene | `uv run pytest -p no:cacheprovider -q tests/test_repo_hygiene.py` | 3 passed; 0 skipped | Requires a real Git checkout. Failure because `.git` is absent in a source archive is an invalid harness, not a repository defect. |
| Portable SafeForge | `uv run pytest -p no:cacheprovider -q -m 'not skipif' tests/test_safeforge.py tests/test_safeforge_consumer.py tests/test_safeforge_coordinator.py tests/test_safeforge_runtime.py` | 61 selected; 0 skipped | Proves portable models, consumer, coordinator, and pre-kernel runtime behavior. It does not prove macOS Seatbelt enforcement. |
| Full supported local suite | `uv run pytest -p no:cacheprovider -q tests/` | All collected tests complete; prerequisite skips are reported | Requires a real Git checkout. A zero exit does not verify Docker, PostgreSQL, Node, macOS, or another capability whose tests skipped. Use the named lane to claim that capability. |

The macOS SafeForge acceptance lane has a stricter host contract. On an arm64
macOS host with `/usr/bin/sandbox-exec`, use a unique direct `/private/tmp` root:

```bash
set -euo pipefail
test_root="$(mktemp -d /private/tmp/mcpaudit-safeforge.XXXXXX)"
cleanup() {
  case "$test_root" in
    /private/tmp/mcpaudit-safeforge.*)
      /usr/bin/find "$test_root" -depth -delete
      ;;
    *)
      return 1
      ;;
  esac
}
finish() {
  status=$?
  trap - EXIT HUP INT TERM
  cleanup_status=0
  cleanup || cleanup_status=$?
  if (( status != 0 )); then
    exit "$status"
  fi
  exit "$cleanup_status"
}
trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

uv run pytest -p no:cacheprovider -q --basetemp="$test_root/pytest" \
  tests/test_safeforge_runtime.py::test_supervisor_kills_hanging_shutdown_resistant_process_group \
  tests/test_safeforge_runtime.py::test_supervisor_enforces_process_count \
  tests/test_safeforge_runtime.py::test_supervisor_enforces_memory_and_disk \
  tests/test_safeforge_runtime.py::test_kernel_denies_artifact_root_escape_and_network \
  tests/test_safeforge_runtime.py::test_generated_code_profile_kernel_denies_child_processes
```

This lane is verified only by exactly 5 passes and 0 skips. The
[`macOS SafeForge` workflow](.github/workflows/macos-safeforge.yml) enforces
that collection and result guard mechanically. A non-macOS host is unsupported
for this lane; a temporary root beneath the user home is a host-policy mismatch.
The supported boundary and limits are documented in
[`docs/SAFEFORGE-RUNTIME-THREAT-MODEL.md`](docs/SAFEFORGE-RUNTIME-THREAT-MODEL.md).

For every lane, a missing named node, collection error, failure, error, or
unexpected skip is not a pass. Classify unavailable prerequisites separately;
do not add a skip or weaken an assertion to manufacture a green result. The
selection counts above are revision-bound and must be updated when tests are
intentionally added or removed.

The broad command remains useful for ordinary development:

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
   uv run pytest
   uv run ruff check
   uv run mypy src
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
