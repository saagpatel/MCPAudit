"""Keep the pinned GitHub Actions workflow lint check in CI."""

from __future__ import annotations

from pathlib import Path


def test_actionlint_runs_for_pull_requests_with_a_pinned_checksum() -> None:
    workflow = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
    triggers = workflow.split("\npermissions:", maxsplit=1)[0]
    actionlint_job = workflow.split("\n  link-check:", maxsplit=1)[0]

    assert "  pull_request:" in triggers
    assert "  actionlint:" in actionlint_job
    assert "ACTIONLINT_VERSION: 1.7.12" in actionlint_job
    assert "ACTIONLINT_SHA256: 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8" in (
        actionlint_job
    )
    assert "sha256sum --check" in actionlint_job
    assert '"$RUNNER_TEMP/actionlint/actionlint"' in actionlint_job
    assert "invalid-cache-mode.yml" in actionlint_job
    assert 'input "cache-mode" is not defined' in actionlint_job
