"""Canary containment checks; no MCP servers or inert fixture programs run."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from redteam.chains import reproduce
from redteam.chains.reproduce.containment import PrivateCanary, prepare_parent


@pytest.fixture
def mock_git_tool(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> reproduce.GitTool:
    """Inert toolchain paths for mocked process tests; never executed."""
    executable = tmp_path / "git"
    executable.touch()
    helpers = tmp_path / "git-core"
    helpers.mkdir()
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (tmp_path,))
    return reproduce.GitTool(executable, helpers)


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


def test_write_then_run_non_macos_skips(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    result = reproduce.reproduce_write_then_run(parent=tmp_path)
    assert result.status == "SKIPPED"
    assert result.reason == "requires macOS sandbox-exec"
    assert not list(tmp_path.iterdir())


def test_write_then_run_profile_is_narrow(tmp_path: Path) -> None:
    root = (tmp_path / "canary space").resolve()
    script = root / "canary.sh"
    profile = reproduce.write_then_run.sandbox_profile(root, script)
    assert "(deny network*)" in profile
    assert "(deny file-write*)" in profile
    assert "(deny file-read-data)" in profile
    assert "(deny process-exec)" in profile
    assert '(literal "/bin/sh")' in profile
    assert f'(literal "{script}")' in profile
    assert "process-exec (subpath" not in profile


def test_write_then_run_completes_both_controls_with_mocked_processes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox-exec"
    sandbox.touch()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(reproduce.write_then_run, "SANDBOX_EXEC", sandbox)
    variants: list[str] = []

    def selected_shell() -> Path:
        variants.append("resolved")
        return Path("/bin/bash")

    monkeypatch.setattr(reproduce.write_then_run, "resolve_sh_variant", selected_shell)
    launches: list[list[str]] = []

    def fake_popen(command: list[str], **kwargs: object) -> MagicMock:
        launches.append(command)
        descriptors = kwargs["pass_fds"]
        assert isinstance(descriptors, tuple)
        assert os.fstat(descriptors[0]).st_ino
        assert kwargs["cwd"] is None
        assert callable(kwargs["preexec_fn"])
        canary_root = next((tmp_path / "canaries").iterdir())
        script = canary_root / command[-1]
        profile = (script.parent / "sandbox.sb").read_text()
        assert '(literal "/bin/bash")' in profile
        assert "process-exec (subpath" not in profile
        process = MagicMock()
        process.__enter__.return_value = process
        process.communicate.return_value = (b"", b"")
        if script.is_file():
            process.returncode = 0
            marker_line = next(line for line in script.read_text().splitlines() if line.startswith(": > "))
            marker = shlex.split(marker_line)[2]
            (canary_root / marker).touch()
        else:
            process.returncode = 2
            process.communicate.return_value = (b"", os.fsencode(script) + b": No such file or directory\n")
        return process

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    parent = tmp_path / "canaries"
    result = reproduce.reproduce_write_then_run(parent=parent)

    assert result.status == "REPRODUCED", result
    assert result.marker_before is False and result.marker_after is True
    assert result.negative_controls == {"no-script-written": True}
    assert result.isolation_checks == {
        "positive:only-marker-added": True,
        "positive:teardown": True,
        "no-script-written:unchanged": True,
        "no-script-written:teardown": True,
    }
    assert [step.exit_code for step in result.steps] == [0, 0, 0, 2]
    assert all(not step.timed_out for step in result.steps)
    assert len(launches) == 2
    assert variants == ["resolved"] * 3
    assert all(command[0] == str(sandbox) for command in launches)
    assert list(parent.iterdir()) == []


def test_write_then_run_unapproved_shell_skips_without_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    sandbox = tmp_path / "sandbox-exec"
    sandbox.touch()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(reproduce.write_then_run, "SANDBOX_EXEC", sandbox)
    select = tmp_path / "sh"
    select.symlink_to(sandbox)
    monkeypatch.setattr(reproduce, "SH_SELECT", select)
    launch = MagicMock()
    monkeypatch.setattr(subprocess, "Popen", launch)
    parent = tmp_path / "canaries"
    result = reproduce.reproduce_write_then_run(parent=parent)
    assert result.status == "SKIPPED"
    assert result.reason == "sh variant is outside approved paths"
    assert result.steps == []
    launch.assert_not_called()
    assert list(parent.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")
def test_write_then_run_canary_and_missing_script_control(tmp_path: Path) -> None:
    parent = tmp_path / "canary space"
    result = reproduce.reproduce_write_then_run(parent=parent)
    _require_sandbox(result)
    assert result.status == "REPRODUCED", result
    assert result.marker_before is False
    assert result.marker_after is True
    assert result.negative_controls == {"no-script-written": True}
    assert result.isolation_checks and all(result.isolation_checks.values())
    assert result.teardown_confirmed
    assert result.steps[0].exit_code == 0 and not result.steps[0].timed_out
    assert result.steps[1].exit_code == 0 and not result.steps[1].timed_out
    assert result.steps[2].exit_code == 0 and not result.steps[2].timed_out
    assert result.steps[3].exit_code != 0 and not result.steps[3].timed_out
    assert list(parent.iterdir()) == []


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")
def test_write_then_run_sandbox_rejects_outside_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    outside = tmp_path / "outside marker"

    def forbidden_payload(marker: Path) -> str:
        return f"set -eu\n: > {shlex.quote(str(outside))}\n"

    monkeypatch.setattr(reproduce.write_then_run, "_payload", forbidden_payload)
    parent = tmp_path / "canaries"
    result = reproduce.reproduce_write_then_run(parent=parent)
    _require_sandbox(result)
    assert result.status == "NOT_REPRODUCED"
    assert result.reason == "written script did not create marker"
    assert not outside.exists()
    assert result.teardown_confirmed
    assert list(parent.iterdir()) == []


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
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (tmp_path,))
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


def test_timeout_kills_entire_process_group(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mock_git_tool: reproduce.GitTool
) -> None:
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
            mock_git_tool,
        )
    kill.assert_called_once_with(process.pid, 9)
    assert result.steps == [reproduce.ReproductionStep("filter:git-add", -9, timed_out=True)]


def test_write_then_run_timeout_bounds_drain_after_leader_exit(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.pid = 123456
    process.returncode = 0
    process.poll.return_value = 0
    process.communicate.side_effect = [
        subprocess.TimeoutExpired("sandbox", 0.01),
        subprocess.TimeoutExpired("sandbox", 1.0),
    ]
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    kill_group = MagicMock()
    monkeypatch.setattr("os.killpg", kill_group)
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="timed out at run:/bin/sh"):
        reproduce.write_then_run._run_script(tmp_path, tmp_path / "canary.sh", "run:/bin/sh", result, 0.01)
    kill_group.assert_called_once_with(process.pid, 9)
    assert process.communicate.call_args_list[1].kwargs == {
        "timeout": reproduce.write_then_run.PROCESS_CLEANUP_TIMEOUT
    }
    process.kill.assert_not_called()
    process.stdout.close.assert_called_once()
    process.stderr.close.assert_called_once()
    process.wait.assert_called_once_with(timeout=reproduce.write_then_run.PROCESS_CLEANUP_TIMEOUT)
    assert result.steps == [reproduce.ReproductionStep("run:/bin/sh", 0, timed_out=True)]


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
        "LC_ALL",
    }
    assert env["HOME"] == str(tmp_path / "home")
    assert env["GIT_CONFIG_GLOBAL"] == env["GIT_CONFIG_SYSTEM"] == "/dev/null"


def test_profile_denies_network_write_and_unlisted_exec(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path.resolve()
    git = root / "resolved git"
    helpers = root / "git-core"
    git.touch()
    helpers.mkdir()
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root,))
    profile = reproduce.sandbox_profile(root, root / "canary.sh", reproduce.GitTool(git, helpers))
    assert "(deny network*)" in profile
    assert "(deny file-write*)" in profile
    assert "(deny file-read-data)" in profile
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


@pytest.mark.parametrize("target", ["/usr/local/bin/bash", "relative/bash"])
def test_rejects_unapproved_sh_variant(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str) -> None:
    select = tmp_path / "sh"
    select.touch()
    monkeypatch.setattr(reproduce, "SH_SELECT", select)
    monkeypatch.setattr(os.path, "realpath", lambda path: target)
    with pytest.raises(reproduce._Unavailable, match="sh variant is outside approved paths"):
        reproduce.resolve_sh_variant()


def test_resolves_sh_variant_into_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path.resolve()
    select = root / "sh"
    select.touch()
    monkeypatch.setattr(reproduce, "SH_SELECT", select)
    with monkeypatch.context() as patch:
        patch.setattr(os.path, "realpath", lambda path: "/bin/bash")
        variant = reproduce.resolve_sh_variant()
    assert variant == Path("/bin/bash")
    (root / "git").touch()
    (root / "git-core").mkdir()
    monkeypatch.setattr(reproduce, "GIT_ROOTS", (root,))
    profile = reproduce.sandbox_profile(
        root, root / "canary.sh", reproduce.GitTool(root / "git", root / "git-core"), variant
    )
    assert '(literal "/bin/bash")' in profile
    assert "/usr/bin/xcrun" not in profile


def test_missing_sh_select_adds_no_variant(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(reproduce, "SH_SELECT", tmp_path / "missing")
    assert reproduce.resolve_sh_variant() is None


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
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mock_git_tool: reproduce.GitTool
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
            mock_git_tool,
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
    assert result.steps[0].exit_code == 0 and not result.steps[0].timed_out
    # Both negative controls still stage the bait and verify its exact index bytes;
    # their contract is absence of a marker, not a failed Git operation.
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


def test_parent_links_are_rejected_before_creating_any_directories(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        prepare_parent(tmp_path / "linked" / "must-not-be-created")
    assert list(outside.iterdir()) == []


def test_replacement_directory_is_preserved_during_teardown(tmp_path: Path) -> None:
    canary = PrivateCanary(tmp_path, reproduce.PREFIX)
    original = canary.root
    moved = tmp_path / "moved-canary"
    original.rename(moved)
    original.mkdir(mode=0o700)
    (original / "preserve").write_text("replacement")
    with pytest.raises(reproduce._Failed, match="identity changed"):
        canary.teardown()
    assert (original / "preserve").read_text() == "replacement"
    assert moved.is_dir()


def test_teardown_must_delete_original_not_rename_it(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    canary = PrivateCanary(tmp_path, reproduce.PREFIX)
    original = canary.root
    moved = tmp_path / "moved-canary"

    def rename_instead(path: str, *, dir_fd: int) -> None:
        os.rename(path, moved.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)

    replacement = MagicMock(side_effect=rename_instead)
    monkeypatch.setattr(os, "rmdir", replacement)
    with pytest.raises(reproduce._Failed, match="did not remove the original"):
        canary.teardown()
    assert not original.exists()
    assert moved.is_dir()


def test_teardown_never_empties_a_replacement_after_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    canary = PrivateCanary(tmp_path, reproduce.PREFIX)
    original = canary.root
    moved = tmp_path / "moved"
    verify = canary.verify
    replaced = False

    def swap_after_check() -> None:
        nonlocal replaced
        verify()
        if not replaced:
            replaced = True
            original.rename(moved)
            original.mkdir(mode=0o700)
            (original / "preserve").write_text("replacement")

    monkeypatch.setattr(canary, "verify", swap_after_check)
    with pytest.raises(reproduce._Failed, match="identity changed"):
        canary.teardown()
    assert (original / "preserve").read_text() == "replacement"


def test_failed_open_after_creation_removes_only_empty_canary(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original_open = os.open

    def fail_canary_open(
        path: str | Path, flags: int, mode: int = 0o777, *, dir_fd: int | None = None
    ) -> int:
        if str(path).startswith(reproduce.PREFIX):
            raise PermissionError("simulated restrictive umask")
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_canary_open)
    with pytest.raises(PermissionError):
        PrivateCanary(tmp_path, reproduce.PREFIX)
    assert list(tmp_path.iterdir()) == []


def test_linked_canary_entries_never_read_or_overwrite_target(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    canary = PrivateCanary(tmp_path, reproduce.PREFIX)
    try:
        (canary.root / "link").symlink_to(outside)
        with pytest.raises(OSError):
            canary.write("link", b"overwrite")
        with pytest.raises(OSError):
            canary.snapshot()
        (canary.root / "link").unlink()
        os.link(outside, canary.root / "hardlink")
        with pytest.raises(reproduce._Failed, match="private regular file"):
            canary.write("hardlink", b"overwrite")
        with pytest.raises(reproduce._Failed, match="non-private"):
            canary.snapshot()
        assert outside.read_bytes() == b"preserve"
    finally:
        canary.teardown()


@pytest.mark.parametrize("exit_code,stderr", [(1, b"permission denied"), (2, b"syntax error"), (0, b"")])
def test_negative_control_requires_the_missing_script_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_code: int, stderr: bytes
) -> None:
    process = MagicMock()
    process.returncode = exit_code
    process.communicate.return_value = (b"", stderr)
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="missing-script failure"):
        reproduce.write_then_run._run_script(
            tmp_path, tmp_path / "canary.sh", "negative", result, 1, missing_script=True
        )


def test_git_marker_must_be_created_by_add_not_inspection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mock_git_tool: reproduce.GitTool
) -> None:
    inspected = False

    def fake_git(
        root: Path,
        args: list[str],
        name: str,
        result: reproduce.ReproductionResult,
        timeout: float,
        git_tool: reproduce.GitTool,
        *,
        canary: PrivateCanary | None = None,
    ) -> str:
        nonlocal inspected
        if args[-1] == ".":
            (root / "repo/.git").mkdir()
            (root / "repo/.git/config").write_text("")
        if name.endswith(":verify-index"):
            inspected = True
            (root / "marker").touch()
            return "Synthetic canary bait.\n"
        return ""

    monkeypatch.setattr(reproduce, "_run_git", fake_git)
    monkeypatch.setattr(reproduce, "_check_repo", lambda *args, **kwargs: None)
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="did not create marker"):
        reproduce._case(tmp_path, "filter", result, 1, mock_git_tool, None)
    assert result.marker_after is False
    assert not inspected
    assert result.teardown_confirmed


def test_git_timeout_cleanup_is_bounded_even_when_process_cannot_be_reaped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mock_git_tool: reproduce.GitTool
) -> None:
    process = MagicMock()
    process.pid = 123456
    process.poll.return_value = None
    process.communicate.side_effect = subprocess.TimeoutExpired("sandbox", 0.01)
    process.wait.side_effect = subprocess.TimeoutExpired("sandbox", 1)
    monkeypatch.setattr(subprocess, "Popen", MagicMock(return_value=process))
    kill_group = MagicMock()
    monkeypatch.setattr(os, "killpg", kill_group)
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    with pytest.raises(reproduce._Failed, match="could not be reaped"):
        reproduce._run_git(tmp_path, ["add"], "add", result, 0.01, mock_git_tool)
    kill_group.assert_called_once_with(process.pid, 9)
    process.kill.assert_called_once()
    process.wait.assert_called_once_with(timeout=reproduce.PROCESS_CLEANUP_TIMEOUT)
    assert result.steps[0].timed_out
    process.__exit__.assert_not_called()


def test_profile_rejects_broad_helpers_and_unapproved_shell(
    tmp_path: Path, mock_git_tool: reproduce.GitTool
) -> None:
    with pytest.raises(reproduce._Failed, match="narrow toolchain"):
        reproduce.sandbox_profile(
            tmp_path, tmp_path / "canary.sh", reproduce.GitTool(mock_git_tool.executable, tmp_path)
        )
    with pytest.raises(ValueError, match="shell variant"):
        reproduce.write_then_run.sandbox_profile(tmp_path, tmp_path / "canary.sh", Path("/bin/other"))


def test_profile_quotes_paths_as_single_literals(tmp_path: Path) -> None:
    import json

    root = tmp_path / 'canary ") (allow network*) ("'
    profile = reproduce.write_then_run.sandbox_profile(root, root / "canary.sh")
    assert f"(subpath {json.dumps(str(root))})" in profile
    assert f"(literal {json.dumps(str(root / 'canary.sh'))})" in profile


@pytest.mark.skipif(sys.platform != "darwin", reason="requires macOS sandbox-exec")
def test_sandbox_rejects_reading_outside_canary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    outside = tmp_path / "outside-data"
    outside.write_text("synthetic outside data\n")

    def read_before_marker(marker: Path) -> str:
        return (
            f"set -eu\nif IFS= read -r value < {shlex.quote(str(outside))}; then\n"
            f": > {shlex.quote(str(marker))}\nfi\n"
        )

    monkeypatch.setattr(reproduce.write_then_run, "_payload", read_before_marker)
    result = reproduce.reproduce_write_then_run(parent=tmp_path / "canaries")
    _require_sandbox(result)
    assert result.status == "NOT_REPRODUCED"
    assert result.marker_after is False
    assert result.teardown_confirmed


def test_launch_pins_cwd_and_rejects_directory_swap(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from functools import partial

    canary = PrivateCanary(tmp_path, reproduce.PREFIX)
    original_inode = os.fstat(canary.fd).st_ino
    moved = tmp_path / "moved"

    def swapped_launch(command: list[str], **kwargs: object) -> MagicMock:
        assert kwargs["cwd"] is None
        hook = kwargs["preexec_fn"]
        assert isinstance(hook, partial)
        assert hook.func is os.fchdir
        assert hook.args == (canary.fd,)
        assert kwargs["pass_fds"] == (canary.fd,)
        assert command[1] == "-p" and command[-1] == "canary.sh"
        canary.root.rename(moved)
        canary.root.mkdir(mode=0o700)
        (canary.root / "preserve").write_text("replacement")
        assert os.fstat(canary.fd).st_ino == original_inode
        process = MagicMock()
        process.returncode = 0
        process.communicate.return_value = (b"", b"")
        return process

    monkeypatch.setattr(subprocess, "Popen", swapped_launch)
    result = reproduce.ReproductionResult("NOT_REPRODUCED")
    reproduce.write_then_run._run_script(
        canary.root, canary.root / "canary.sh", "positive", result, 1, canary=canary
    )
    with pytest.raises(reproduce._Failed, match="identity changed"):
        canary.teardown()
    assert (canary.root / "preserve").read_text() == "replacement"


def test_toolchain_resolution_timeout_kills_children(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    process = MagicMock()
    process.pid = 123456
    process.communicate.side_effect = [subprocess.TimeoutExpired("toolchain", 10), (b"", b"")]
    launch = MagicMock(return_value=process)
    monkeypatch.setattr(subprocess, "Popen", launch)
    kill_group = MagicMock()
    monkeypatch.setattr(os, "killpg", kill_group)
    with pytest.raises(reproduce._Unavailable, match="timed out"):
        reproduce._run_resolution_command(["synthetic-git", "--exec-path"], cwd=tmp_path)
    assert launch.call_args.kwargs["start_new_session"] is True
    kill_group.assert_called_once_with(process.pid, 9)
    assert process.communicate.call_args_list[1].kwargs == {"timeout": reproduce.PROCESS_CLEANUP_TIMEOUT}
    process.__exit__.assert_not_called()
