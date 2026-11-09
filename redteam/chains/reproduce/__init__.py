"""Operation-level Git canary. No fixture or MCP server is ever executed.

Toolchain resolution runs outside the sandbox. Every repository operation,
including initialization and inspection, is sandboxed; the only executable
payload is our fixed marker-and-cat script in a fresh repo.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Literal

from redteam.chains.reproduce.containment import CanaryFailure, PrivateCanary, prepare_parent

_Failed = CanaryFailure

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
XCRUN = Path("/usr/bin/xcrun")
GIT_FALLBACK = Path("/usr/bin/git")
SH_SELECT = Path("/private/var/select/sh")
GIT_ROOTS = (
    Path("/Applications/Xcode.app"),
    Path("/Library/Developer/CommandLineTools"),
    Path("/usr/bin"),
    Path("/opt/homebrew"),
)
PREFIX = "mcpaudit-chain-canary-"
PROCESS_CLEANUP_TIMEOUT = 1.0
DEMONSTRATION = (
    "Git filter activation via equivalent filesystem writes and git add operations on a canary; "
    "not an exploit against a live MCP server."
)
Control = Literal["filter", "no-filter-config", "no-attributes"]


@dataclass(frozen=True)
class ReproductionStep:
    name: str
    exit_code: int | None
    timed_out: bool = False


@dataclass
class ReproductionResult:
    status: Literal["REPRODUCED", "NOT_REPRODUCED", "SKIPPED"]
    reason: str | None = None
    demonstration: str = DEMONSTRATION
    steps: list[ReproductionStep] = field(default_factory=list)
    marker_before: bool | None = None
    marker_after: bool | None = None
    index_has_bait: bool | None = None
    negative_controls: dict[str, bool] = field(default_factory=dict)
    isolation_checks: dict[str, bool] = field(default_factory=dict)
    teardown_confirmed: bool = False


class _Unavailable(Exception):
    pass


@dataclass(frozen=True)
class GitTool:
    executable: Path
    exec_path: Path


def _allowed_real_path(path: Path) -> Path:
    """Resolve and constrain a toolchain path before allowing it in the sandbox."""
    if not path.is_absolute():
        raise _Unavailable("Git toolchain path is not absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise _Unavailable("Git toolchain path is unavailable") from exc
    if not resolved.is_absolute() or not any(
        resolved == root or root in resolved.parents for root in GIT_ROOTS
    ):
        raise _Unavailable("Git toolchain path is outside approved locations")
    return resolved


def _is_xcrun_shim(path: Path) -> bool:
    """Reject a fallback executable that would try to launch xcrun in the sandbox."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise _Unavailable("Git fallback is unavailable") from exc
    macho_magics = (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    )
    is_macho = data[:4] in macho_magics
    is_script = data.startswith(b"#!")
    return (is_macho or is_script) and re.search(rb"\bxcrun\b", data) is not None


def _run_resolution_command(command: list[str], *, cwd: Path) -> str:
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            try:
                stdout, _ = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _reap_timed_out(process)
                raise _Unavailable("Git toolchain resolution timed out") from None
        finally:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
    except (OSError, subprocess.SubprocessError) as exc:
        raise _Unavailable("Git toolchain could not be resolved") from exc
    if process.returncode != 0:
        raise _Unavailable("Git toolchain could not be resolved")
    return stdout.decode("utf-8", errors="strict").strip()


def resolve_git_tool(*, cwd: Path) -> GitTool:
    """Resolve the real Git executable and its helper directory outside sandbox-exec."""
    executable_text = ""
    if XCRUN.is_file() and os.access(XCRUN, os.X_OK):
        executable_text = _run_resolution_command([str(XCRUN), "--find", "git"], cwd=cwd)
    if executable_text:
        executable = _allowed_real_path(Path(executable_text))
    else:
        fallback = _allowed_real_path(GIT_FALLBACK)
        if not os.access(fallback, os.X_OK) or _is_xcrun_shim(fallback):
            raise _Unavailable("no approved real Git executable is available")
        executable = fallback
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise _Unavailable("resolved Git executable is unavailable")
    exec_text = _run_resolution_command([str(executable), "--exec-path"], cwd=cwd)
    exec_path = _allowed_real_path(Path(exec_text))
    if not exec_path.is_dir() or exec_path.name != "git-core":
        raise _Unavailable("Git helper directory is unavailable")
    return GitTool(executable, exec_path)


def resolve_sh_variant() -> Path | None:
    """Resolve the macOS sh selection without admitting arbitrary executables."""
    if not SH_SELECT.exists():
        return None
    variant = Path(os.path.realpath(SH_SELECT))
    if (
        not variant.is_absolute()
        or variant.parent != Path("/bin")
        or variant.name
        not in {
            "bash",
            "dash",
            "zsh",
            "sh",
        }
    ):
        raise _Unavailable("sh variant is outside approved paths")
    return variant


def sandbox_profile(root: Path, script: Path, git_tool: GitTool, sh_variant: Path | None = None) -> str:
    """Constrain writes, network, and execution; leave default reads enabled.

    Git and its helper directory are resolved and validated before entering
    the sandbox. JSON string escaping is also valid for Seatbelt literals.
    Reads are outside this canary's threat model: Git, shells, and dyld need
    system runtime files beyond a fixed allow-list to start reliably.
    """
    validate_profile_paths(root, script, sh_variant)
    if (
        _allowed_real_path(git_tool.executable) != git_tool.executable
        or _allowed_real_path(git_tool.exec_path) != git_tool.exec_path
        or git_tool.exec_path.name != "git-core"
        or not git_tool.executable.is_file()
        or not git_tool.exec_path.is_dir()
    ):
        raise _Failed("sandbox Git paths are not a resolved narrow toolchain")
    quote = json.dumps
    variant_literal = f"(literal {quote(str(sh_variant))}) " if sh_variant is not None else ""
    return (
        "(version 1)\n(allow default)\n"
        "(deny network*)\n(deny file-write*)\n"
        f"(allow file-write* (subpath {quote(str(root))}) "
        '(literal "/dev/null") (literal "/dev/tty"))\n'
        "(deny process-exec)\n"
        f"(allow process-exec (literal {quote(str(git_tool.executable))}) "
        f"(subpath {quote(str(git_tool.exec_path))}) "
        '(literal "/bin/sh") '
        f"{variant_literal}"
        f'(literal "/bin/cat") (literal {quote(str(script))}))\n'
    )


def validate_profile_paths(root: Path, script: Path, sh_variant: Path | None) -> None:
    if (
        not root.is_absolute()
        or root == Path("/")
        or root.resolve() != root
        or script.parent != root
        or script.name != "canary.sh"
        or script.is_symlink()
    ):
        raise ValueError("sandbox paths must be resolved private canary paths")
    if sh_variant is not None and (
        sh_variant.parent != Path("/bin") or sh_variant.name not in {"bash", "dash", "zsh", "sh"}
    ):
        raise ValueError("sandbox shell variant is outside approved paths")


def canary_environment(root: Path) -> dict[str, str]:
    """Never inherit Git knobs, credentials, shell startup settings, or HOME."""
    return {
        "HOME": str(root / "home"),
        "XDG_CONFIG_HOME": str(root / "xdg"),
        "TMPDIR": str(root / "tmp"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ATTR_NOSYSTEM": "1",
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
    }


def _run_git(
    root: Path,
    args: list[str],
    name: str,
    result: ReproductionResult,
    timeout: float,
    git_tool: GitTool,
    *,
    canary: PrivateCanary | None = None,
) -> str:
    if canary is not None:
        canary.verify()
    command = [
        str(SANDBOX_EXEC),
        "-p",
        sandbox_profile(root, root / "canary.sh", git_tool, resolve_sh_variant()),
        str(git_tool.executable),
        "-C",
        "repo" if canary is not None else str(root / "repo"),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "credential.helper=",
        *args,
    ]
    process = subprocess.Popen(
        command,
        cwd=root if canary is None else None,
        preexec_fn=partial(os.fchdir, canary.fd) if canary is not None else None,
        pass_fds=(canary.fd,) if canary is not None else (),
        env=canary_environment(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        umask=0o077,
    )
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the group, including a filter retaining the stdout pipe.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The process group already exited.
            try:
                _reap_timed_out(process)
            finally:
                result.steps.append(ReproductionStep(name, process.returncode, timed_out=True))
            raise _Failed(f"sandboxed Git timed out at {name} (exit code {process.returncode})") from None
    finally:
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
    result.steps.append(ReproductionStep(name, process.returncode))
    if _is_nested_apply_failure(process.returncode, stderr):
        raise _Unavailable("nested sandbox unavailable")
    if process.returncode != 0:
        raise _Failed(f"sandboxed Git failed at {name} (exit code {process.returncode})")
    return stdout.decode("utf-8", errors="strict")


def _reap_timed_out(process: subprocess.Popen[bytes]) -> None:
    """Bound cleanup even if an escaped child retains an output pipe."""
    try:
        process.communicate(timeout=PROCESS_CLEANUP_TIMEOUT)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            process.kill()
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()
        try:
            process.wait(timeout=PROCESS_CLEANUP_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise _Failed("timed out and sandbox process could not be reaped") from None


def _is_nested_apply_failure(returncode: int | None, stderr: bytes) -> bool:
    """Match sandbox-exec's own apply EPERM diagnostic, never ordinary denials."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return returncode == 71 and lines == [b"sandbox-exec: sandbox_apply: Operation not permitted"]


def _check_repo(
    root: Path,
    result: ReproductionResult,
    timeout: float,
    git_tool: GitTool,
    *,
    canary: PrivateCanary | None = None,
) -> None:
    repo = root / "repo"
    git_dir = repo / ".git"
    if not git_dir.is_dir() or git_dir.is_symlink():
        raise _Failed("canary .git is not a private directory")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise _Failed("symlink in canary")
    for relative in ("objects/info/alternates", "objects/info/http-alternates", "commondir", "modules"):
        if (git_dir / relative).exists():
            raise _Failed("unexpected Git indirection in canary")
    if (repo / ".gitmodules").exists():
        raise _Failed("unexpected submodules in canary")
    config = _run_git(
        root,
        ["config", "--local", "--name-only", "--list"],
        "verify-config",
        result,
        timeout,
        git_tool,
        canary=canary,
    )
    allowed = {
        "core.repositoryformatversion",
        "core.filemode",
        "core.bare",
        "core.logallrefupdates",
        "core.ignorecase",
        "core.precomposeunicode",
    }
    if set(config.splitlines()) - allowed:
        raise _Failed("unexpected Git config (includes/remotes are forbidden)")
    for option, expected in (
        ("--show-toplevel", repo),
        ("--absolute-git-dir", git_dir),
        ("--git-common-dir", git_dir),
    ):
        actual = _run_git(
            root, ["rev-parse", option], f"verify-{option[2:]}", result, timeout, git_tool, canary=canary
        )
        candidate = Path(actual.strip())
        if not candidate.is_absolute():
            candidate = repo / candidate
        if candidate.resolve() != expected:
            raise _Failed("Git repository paths escaped the canary")


def _script(marker: Path) -> str:
    return f"#!/bin/sh\nset -eu\n: > {shlex.quote(str(marker))}\n/bin/cat\n"


def _case(
    parent: Path,
    control: Control,
    result: ReproductionResult,
    timeout: float,
    git_tool: GitTool,
    sh_variant: Path | None,
) -> None:
    canary = PrivateCanary(parent, PREFIX)
    root = canary.root
    try:
        # Private permissions are checked rather than assumed from the umask.
        if root.is_symlink() or root.resolve() != root or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise _Failed("temporary canary path is not private and resolved")
        for directory in ("repo", "home", "xdg", "tmp", "empty-template", "empty-hooks"):
            canary.mkdir(directory)
        script = root / "canary.sh"
        canary.write("sandbox.sb", sandbox_profile(root, script, git_tool, sh_variant).encode())
        _run_git(
            root,
            [
                "-c",
                f"core.hooksPath={root / 'empty-hooks'}",
                "init",
                f"--template={root / 'empty-template'}",
                ".",
            ],
            f"{control}:init",
            result,
            timeout,
            git_tool,
            canary=canary,
        )
        _check_repo(root, result, timeout, git_tool, canary=canary)
        canary.verify()
        result.isolation_checks[f"{control}:private-repo"] = True
        # Equivalent filesystem-server operations: literal synthetic writes only.
        canary.write("canary.sh", _script(Path("../marker")).encode())
        canary.mkdir("repo/.git/hooks")
        if control != "no-filter-config":
            # Relative paths keep the filter anchored to Git's pinned worktree.
            clean = "/bin/sh ../canary.sh"
            canary.write(
                "repo/.git/config",
                (
                    "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                    f'[filter "canary"]\n\tclean = {json.dumps(clean)}\n\trequired = true\n'
                ).encode(),
            )
        if control != "no-attributes":
            canary.write("repo/.gitattributes", b"bait.txt filter=canary\n")
        bait = b"Synthetic canary bait.\n"
        canary.write("repo/bait.txt", bait)
        result.steps.append(ReproductionStep(f"{control}:filesystem-writes", 0))
        before = canary.snapshot(exclude_git=True)
        marker_before = "marker" in before
        if control == "filter":
            result.marker_before = marker_before
        if marker_before:
            raise _Failed("marker already existed before git add")
        _run_git(
            root,
            ["add", "--", "bait.txt"],
            f"{control}:git-add",
            result,
            timeout,
            git_tool,
            canary=canary,
        )
        after_add = canary.snapshot(exclude_git=True)
        marker_after = after_add.get("marker", "").endswith(
            ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        if control == "filter":
            result.marker_after = marker_after
        if control == "filter" and not marker_after:
            raise _Failed("clean filter did not create marker")
        indexed = _run_git(
            root, ["show", ":bait.txt"], f"{control}:verify-index", result, timeout, git_tool, canary=canary
        )
        correct_blob = indexed == bait.decode()
        if control == "filter":
            result.index_has_bait = correct_blob
        after = canary.snapshot(exclude_git=True)
        expected = dict(before)
        if control == "filter" and marker_after:
            expected["marker"] = after["marker"]
        unchanged = after_add == after == expected
        result.isolation_checks[f"{control}:only-marker-added"] = unchanged
        if not unchanged or not correct_blob:
            raise _Failed("unexpected canary filesystem or index change")
        if control == "filter":
            if not marker_after:
                raise _Failed("clean filter did not create marker")
        else:
            result.negative_controls[control] = not marker_after
            if marker_after:
                raise _Failed("negative control created a marker")
    finally:
        # Never delete a caller-supplied repo, another canary, or a redirected path.
        result.teardown_confirmed = False
        result.isolation_checks[f"{control}:teardown"] = False
        canary.teardown()
        result.isolation_checks[f"{control}:teardown"] = True
        result.teardown_confirmed = True


def reproduce_git_clean_filter(*, parent: Path | None = None, timeout: float = 10.0) -> ReproductionResult:
    """Run positive and negative controls, or skip without executing unsandboxed.

    Generated files default to build/redteam/chains; all evidence omits absolute
    temporary paths, process output, and environment values.
    """
    result = ReproductionResult("NOT_REPRODUCED")
    if sys.platform != "darwin":
        result.status, result.reason = "SKIPPED", "requires macOS sandbox-exec"
        return result
    if not SANDBOX_EXEC.is_file():
        result.status, result.reason = "SKIPPED", "sandbox-exec is unavailable"
        return result
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be positive and at most 60 seconds per Git invocation")
    base = parent if parent is not None else Path("build/redteam/chains")
    try:
        base = prepare_parent(base)
        git_tool = resolve_git_tool(cwd=base)
        sh_variant = resolve_sh_variant()
        for control in ("filter", "no-filter-config", "no-attributes"):
            _case(base, control, result, timeout, git_tool, sh_variant)
        result.status = "REPRODUCED"
    except _Unavailable as exc:
        result.status, result.reason = "SKIPPED", str(exc)
    except _Failed as exc:
        result.reason = str(exc)
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        result.reason = f"canary operation failed ({type(exc).__name__})"
    return result


from redteam.chains.reproduce import write_then_run as write_then_run  # noqa: E402

reproduce_write_then_run = write_then_run.reproduce_write_then_run
