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
    git = tmp_path / "real-git"
    git.touch()
    helpers = tmp_path / "git-core"
    helpers.mkdir()
    monkeypatch.setattr(reproduce, "resolve_git_tool", lambda *, cwd: reproduce.GitTool(git, helpers))
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
    assert command[3] == str(git)
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
        reproduce._run_git(
            tmp_path,
            ["add", "--", "bait.txt"],
            "filter:git-add",
            result,
            0.01,
            reproduce.GitTool(tmp_path / "git", tmp_path / "git-core"),
        )
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
    git = root / "resolved git"
    helpers = root / "git core"
    profile = reproduce.sandbox_profile(root, root / "canary.sh", reproduce.GitTool(git, helpers))
    assert "(deny network*)" in profile
    assert "(deny file-write*)" in profile
    assert "(deny process-exec)" in profile
    assert '(literal "/bin/sh")' in profile
    assert '(literal "/bin/cat")' in profile
    assert f'(literal "{git}")' in profile
    assert f'(subpath "{helpers}")' in profile
    assert f'(literal "{root / "canary.sh"}")' in profile
    assert "xcrun" not in profile
    assert "/usr/bin/git" not in profile
    assert '(subpath "/usr/bin")' not in profile
    with pytest.raises(ValueError):
        reproduce.sandbox_profile(root, root.parent / "outside-script", reproduce.GitTool(git, helpers))


def test_resolves_and_validates_git_and_helper_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git = root / "toolchain" / "usr" / "bin" / "git"
    helpers = root / "toolchain" / "usr" / "libexec" / "git-core"
    git.parent.mkdir(parents=True)
    git.touch()
    git.chmod(0o755)
    helpers.mkdir(parents=True)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root / "toolchain",))
    calls: list[list[str]] = []

    def resolve(command: list[str], *, cwd: Path) -> str:
        calls.append(command)
        return str(git if command[-2:] == ["--find", "git"] else helpers)

    monkeypatch.setattr(reproduce, "_run_resolution_command", resolve)
    monkeypatch.setattr(reproduce, "XCRUN", git.parent / "xcrun")
    (git.parent / "xcrun").touch()
    (git.parent / "xcrun").chmod(0o755)
    resolved = reproduce.resolve_git_tool(cwd=root)
    assert resolved == reproduce.GitTool(git, helpers)
    assert calls == [[str(git.parent / "xcrun"), "--find", "git"], [str(git), "--exec-path"]]


def test_rejects_unapproved_or_relative_resolution_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    git = root / "outside" / "git"
    git.parent.mkdir()
    git.touch()
    git.chmod(0o755)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root / "approved",))
    monkeypatch.setattr(reproduce, "_run_resolution_command", lambda command, *, cwd: str(git))
    monkeypatch.setattr(reproduce, "XCRUN", tmp_path / "xcrun")
    (tmp_path / "xcrun").touch()
    (tmp_path / "xcrun").chmod(0o755)
    with pytest.raises(reproduce._Unavailable, match="outside approved"):
        reproduce.resolve_git_tool(cwd=root)
    with pytest.raises(reproduce._Unavailable, match="not absolute"):
        reproduce._allowed_real_path(Path("relative/git"))


def test_rejects_resolved_symlink_outside_approved_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    approved = root / "approved"
    approved.mkdir()
    outside = root / "outside-git"
    outside.touch()
    (approved / "git").symlink_to(outside)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (approved,))
    with pytest.raises(reproduce._Unavailable, match="outside approved"):
        reproduce._allowed_real_path(approved / "git")


def test_falls_back_to_approved_non_shim_git(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git = root / "usr" / "bin" / "git"
    helpers = root / "usr" / "libexec" / "git-core"
    git.parent.mkdir(parents=True)
    git.write_bytes(b"synthetic non-shim executable")
    git.chmod(0o755)
    helpers.mkdir(parents=True)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root,))
    monkeypatch.setattr(reproduce, "GIT_FALLBACK", git)
    monkeypatch.setattr(reproduce, "XCRUN", tmp_path / "missing-xcrun")
    calls: list[list[str]] = []

    def resolve(command: list[str], *, cwd: Path) -> str:
        calls.append(command)
        return str(helpers)

    monkeypatch.setattr(reproduce, "_run_resolution_command", resolve)
    assert reproduce.resolve_git_tool(cwd=root) == reproduce.GitTool(git, helpers)
    assert calls == [[str(git), "--exec-path"]]


def test_rejects_xcrun_shim_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git = root / "usr" / "bin" / "git"
    git.parent.mkdir(parents=True)
    git.write_bytes(b"\xfe\xed\xfa\xcf Mach-O xcrun shim")
    git.chmod(0o755)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root,))
    monkeypatch.setattr(reproduce, "GIT_FALLBACK", git)
    monkeypatch.setattr(reproduce, "XCRUN", tmp_path / "missing-xcrun")
    with pytest.raises(reproduce._Unavailable, match="no approved real Git"):
        reproduce.resolve_git_tool(cwd=root)


@pytest.mark.parametrize("exec_path", ["relative/git-core", "outside"])
def test_rejects_unapproved_or_relative_helper_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exec_path: str
) -> None:
    root = tmp_path.resolve()
    toolchain = root / "toolchain"
    git = toolchain / "usr" / "bin" / "git"
    git.parent.mkdir(parents=True)
    git.touch()
    git.chmod(0o755)
    if exec_path == "outside":
        invalid_path = root / "outside" / "git-core"
        invalid_path.mkdir(parents=True)
        exec_path = str(invalid_path)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (toolchain,))
    monkeypatch.setattr(reproduce, "GIT_FALLBACK", git)
    monkeypatch.setattr(reproduce, "XCRUN", tmp_path / "missing-xcrun")
    monkeypatch.setattr(reproduce, "_run_resolution_command", lambda command, *, cwd: exec_path)
    with pytest.raises(reproduce._Unavailable, match="not absolute|outside approved"):
        reproduce.resolve_git_tool(cwd=root)


def test_rejects_unavailable_fallback_executable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    git = root / "toolchain" / "usr" / "bin" / "git"
    git.parent.mkdir(parents=True)
    git.touch()
    git.chmod(0o644)
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root / "toolchain",))
    monkeypatch.setattr(reproduce, "GIT_FALLBACK", git)
    monkeypatch.setattr(reproduce, "XCRUN", tmp_path / "missing-xcrun")
    with pytest.raises(reproduce._Unavailable, match="no approved real Git"):
        reproduce.resolve_git_tool(cwd=root)


def test_exec_failure_is_not_misreported_as_nested_sandbox_skip(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.returncode = 71
    process.communicate.return_value = (b"", b"sandbox: deny process-exec: Operation not permitted\n")
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match=r"filter:git-add \(exit code 71\)"):
        reproduce._run_git(
            tmp_path,
            ["add", "--", "bait.txt"],
            "filter:git-add",
            result,
            1,
            reproduce.GitTool(tmp_path / "git", tmp_path / "git-core"),
        )
    assert result.steps == [reproduce.ReproductionStep("filter:git-add", 71)]


@pytest.mark.parametrize(
    "exit_code,stderr",
    [
        (0, b"sandbox-exec: sandbox_apply: Operation not permitted\n"),
        (128, b"sandbox-exec: sandbox_apply: Operation not permitted\n"),
        (71, b"git: sandbox_apply: Operation not permitted\n"),
        (71, b"sandbox-exec: execvp: Operation not permitted\n"),
        (71, b"sandbox-exec: sandbox_apply: Operation not permitted\nother failure\n"),
    ],
)
def test_only_nested_apply_diagnostic_can_skip(exit_code: int, stderr: bytes) -> None:
    assert not reproduce._is_nested_apply_failure(exit_code, stderr)


def _require_sandbox(result: reproduce.ReproductionResult) -> None:
    if result.status == "SKIPPED":
        assert result.reason == "nested sandbox unavailable"
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
    git_add_step = next(step for step in result.steps if step.name == "filter:git-add")
    assert git_add_step.exit_code is not None and git_add_step.exit_code != 0
    assert result.reason == f"sandboxed Git failed at filter:git-add (exit code {git_add_step.exit_code})"
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
        reproduce._check_repo(
            tmp_path,
            reproduce.ReproductionResult("NOT_REPRODUCED"),
            1,
            reproduce.GitTool(tmp_path / "git", tmp_path / "git-core"),
        )


def test_git_file_and_symlinks_are_rejected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: elsewhere", encoding="utf-8")
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="private directory"):
        reproduce._check_repo(
            tmp_path,
            result,
            1,
            reproduce.GitTool(tmp_path / "git", tmp_path / "git-core"),
        )
    (repo / ".git").unlink()
    (repo / ".git").mkdir()
    (repo / "redirect").symlink_to(repo, target_is_directory=True)
    with pytest.raises(reproduce._Failed, match="symlink"):
        reproduce._check_repo(
            tmp_path,
            result,
            1,
            reproduce.GitTool(tmp_path / "git", tmp_path / "git-core"),
        )
