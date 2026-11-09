"""Canary containment checks; no MCP servers or inert fixture programs run."""

from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from redteam.chains import reproduce


def test_missing_sandbox_never_runs_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(reproduce, "SANDBOX_EXEC", tmp_path / "missing-sandbox")

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("Git must never run without sandbox-exec")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = reproduce.reproduce_git_clean_filter(parent=tmp_path)
    assert result.status == "SKIPPED"
    assert result.reason == "sandbox-exec is unavailable"
    assert result.steps == []
    assert list(tmp_path.iterdir()) == []


def test_non_macos_skips(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    result = reproduce.reproduce_git_clean_filter(parent=tmp_path)
    assert result.status == "SKIPPED"
    assert result.reason == "requires macOS sandbox-exec"
    assert not list(tmp_path.iterdir())


def test_nested_sandbox_refusal_is_skipped_and_torn_down(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    available = tmp_path / "sandbox-exec"
    available.touch()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(reproduce, "SANDBOX_EXEC", available)
    process = MagicMock()
    process.__enter__.return_value = process
    process.returncode = 71
    process.communicate.return_value = (b"", b"sandbox-exec: sandbox_apply: Operation not permitted\n")
    launch = MagicMock(return_value=process)
    monkeypatch.setattr(subprocess, "Popen", launch)
    parent = tmp_path / "canaries"
    result = reproduce.reproduce_git_clean_filter(parent=parent)
    assert result.status == "SKIPPED"
    assert result.reason == "nested sandbox unavailable"
    assert result.steps[0].exit_code == 71
    assert result.teardown_confirmed
    assert not list(parent.iterdir())
    command = launch.call_args.args[0]
    assert command[0] == str(available)
    assert command[3] == "/usr/bin/git"
    assert launch.call_args.kwargs["start_new_session"] is True


def test_timeout_kills_entire_process_group(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.pid = 123456
    process.returncode = -9
    process.communicate.side_effect = [subprocess.TimeoutExpired("sandboxed git", 0.01), (b"", b"")]
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    kill = MagicMock()
    monkeypatch.setattr("os.killpg", kill)
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="timed out"):
        reproduce._run_git(tmp_path, ["add", "--", "bait.txt"], "filter:git-add", result, 0.01)
    kill.assert_called_once_with(process.pid, 9)
    assert result.steps == [reproduce.ReproductionStep("filter:git-add", -9, timed_out=True)]


def test_environment_is_built_from_scratch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "filter.canary.clean")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "untrusted")
    monkeypatch.setenv("SECRET_SENTINEL", "private-value")
    env = reproduce.canary_environment(tmp_path)
    assert set(env) == {
        "HOME",
        "XDG_CONFIG_HOME",
        "TMPDIR",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_TERMINAL_PROMPT",
        "GIT_ATTR_NOSYSTEM",
        "PATH",
    }
    assert env["HOME"] == str(tmp_path / "home")
    assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"] == "/dev/null"


def test_profile_denies_network_write_and_unlisted_exec(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    profile = reproduce.sandbox_profile(root, root / "canary.sh")
    assert "(deny network*)" in profile
    assert "(deny file-write*)" in profile
    assert "(deny process-exec)" in profile
    assert '(literal "/bin/sh")' in profile
    assert '(literal "/bin/cat")' in profile
    assert '(subpath "/usr/bin")' not in profile
    with pytest.raises(ValueError):
        reproduce.sandbox_profile(root, root.parent / "outside-script")


def _require_sandbox(result: reproduce.ReproductionResult) -> None:
    if result.status == "SKIPPED":
        assert result.reason in {"sandbox-exec is unavailable", "nested sandbox unavailable"}
        if result.steps:
            assert result.teardown_confirmed
        pytest.skip(result.reason)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")
def test_canary_reproduces_with_negative_controls_and_teardown(tmp_path: Path) -> None:
    # Spaces exercise Git-config and shell quoting without running any fixtures.
    parent = tmp_path / "canary space"
    result = reproduce.reproduce_git_clean_filter(parent=parent)
    _require_sandbox(result)
    assert result.status == "REPRODUCED", result
    assert result.marker_before is False
    assert result.marker_after is True
    assert result.index_has_bait is True
    assert result.negative_controls == {"no-filter-config": True, "no-attributes": True}
    assert result.isolation_checks and all(result.isolation_checks.values())
    assert result.teardown_confirmed
    assert all(step.exit_code == 0 and not step.timed_out for step in result.steps)
    assert list(parent.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")
def test_sandbox_rejects_filter_write_outside_canary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    outside = tmp_path / "outside-marker"

    def forbidden_script(marker: Path) -> str:
        return f"#!/bin/sh\nset -eu\n: > {shlex.quote(str(outside))}\n/bin/cat\n"

    monkeypatch.setattr(reproduce, "_script", forbidden_script)
    result = reproduce.reproduce_git_clean_filter(parent=tmp_path / "canaries")
    _require_sandbox(result)
    assert result.status == "NOT_REPRODUCED"
    assert result.reason == "sandboxed Git failed at filter:git-add"
    assert any(step.name == "filter:git-add" and step.exit_code != 0 for step in result.steps)
    assert not outside.exists()
    assert result.teardown_confirmed
    assert not list((tmp_path / "canaries").iterdir())


@pytest.mark.parametrize("indirection", ["objects/info/alternates", "commondir", "modules"])
def test_repo_indirections_are_rejected(tmp_path: Path, indirection: str) -> None:
    git_dir = tmp_path / "repo" / ".git"
    path = git_dir / indirection
    path.parent.mkdir(parents=True)
    path.write_text("synthetic indirection", encoding="utf-8")
    with pytest.raises(reproduce._Failed, match="indirection"):
        reproduce._check_repo(tmp_path, reproduce.ReproductionResult("NOT_REPRODUCED"), 1)


def test_git_file_and_symlinks_are_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: elsewhere", encoding="utf-8")
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="private directory"):
        reproduce._check_repo(tmp_path, result, 1)
    (repo / ".git").unlink()
    (repo / ".git").mkdir()
    (repo / "redirect").symlink_to(repo, target_is_directory=True)
    with pytest.raises(reproduce._Failed, match="symlink"):
        reproduce._check_repo(tmp_path, result, 1)
