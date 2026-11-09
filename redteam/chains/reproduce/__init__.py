"""Operation-level Git canary. No fixture or MCP server is ever executed.

Toolchain resolution runs outside the sandbox. Every repository operation,
including initialization and inspection, is sandboxed; the only executable
payload is our fixed marker-and-cat script in a fresh repo.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

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


class _Failed(Exception):
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
        completed = subprocess.run(
            command,
            cwd=cwd,
            env={"PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _Unavailable("Git toolchain could not be resolved") from exc
    if completed.returncode != 0:
        raise _Unavailable("Git toolchain could not be resolved")
    return completed.stdout.strip()


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
    if not exec_path.is_dir():
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
    """A deny-write/network/exec policy with narrowly scoped exceptions.

    Git and its helper directory are resolved and validated before entering
    the sandbox. JSON string escaping is also valid for Seatbelt literals.
    """
    if not root.is_absolute() or root.resolve() != root or script.parent != root:
        raise ValueError("sandbox paths must be resolved private canary paths")
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
    }


def _run_git(
    root: Path,
    args: list[str],
    name: str,
    result: ReproductionResult,
    timeout: float,
    git_tool: GitTool,
) -> str:
    command = [
        str(SANDBOX_EXEC),
        "-f",
        str(root / "sandbox.sb"),
        str(git_tool.executable),
        "-C",
        str(root / "repo"),
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
    with subprocess.Popen(
        command,
        cwd=root,
        env=canary_environment(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the group, including a filter retaining the stdout pipe.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass  # The process group already exited.
            process.communicate()
            result.steps.append(ReproductionStep(name, process.returncode, timed_out=True))
            raise _Failed(f"sandboxed Git timed out at {name} (exit code {process.returncode})") from None
    result.steps.append(ReproductionStep(name, process.returncode))
    if _is_nested_apply_failure(process.returncode, stderr):
        raise _Unavailable("nested sandbox unavailable")
    if process.returncode != 0:
        raise _Failed(f"sandboxed Git failed at {name} (exit code {process.returncode})")
    return stdout.decode("utf-8", errors="strict")


def _is_nested_apply_failure(returncode: int | None, stderr: bytes) -> bool:
    """Match sandbox-exec's own apply EPERM diagnostic, never ordinary denials."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return returncode == 71 and lines == [b"sandbox-exec: sandbox_apply: Operation not permitted"]


def _check_repo(root: Path, result: ReproductionResult, timeout: float, git_tool: GitTool) -> None:
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
        root, ["config", "--local", "--name-only", "--list"], "verify-config", result, timeout, git_tool
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
        actual = _run_git(root, ["rev-parse", option], f"verify-{option[2:]}", result, timeout, git_tool)
        candidate = Path(actual.strip())
        if not candidate.is_absolute():
            candidate = repo / candidate
        if candidate.resolve() != expected:
            raise _Failed("Git repository paths escaped the canary")


def _non_git_snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts[:2] == ("repo", ".git"):
            continue
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (path.is_dir() or path.is_file()):
            raise _Failed("unexpected non-regular canary entry")
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "directory"
        snapshot[str(relative)] = f"{stat.S_IMODE(info.st_mode)}:{digest}"
    return snapshot


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
    root = Path(tempfile.mkdtemp(prefix=PREFIX, dir=parent))
    try:
        # mkdtemp's 0700 is required, not merely assumed from the current umask.
        if root.is_symlink() or root.resolve() != root or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise _Failed("temporary canary path is not private and resolved")
        for directory in ("repo", "home", "xdg", "tmp", "empty-template", "empty-hooks"):
            (root / directory).mkdir(mode=0o700)
        script = root / "canary.sh"
        marker = root / "marker"
        (root / "sandbox.sb").write_text(
            sandbox_profile(root, script, git_tool, sh_variant), encoding="utf-8"
        )
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
        )
        _check_repo(root, result, timeout, git_tool)
        result.isolation_checks[f"{control}:private-repo"] = True
        # Equivalent filesystem-server operations: literal synthetic writes only.
        script.write_text(_script(marker), encoding="utf-8")
        repo = root / "repo"
        (repo / ".git" / "hooks").mkdir(mode=0o700)
        if control != "no-filter-config":
            # Git parses double quoted config values, then the shell parses the
            # resulting command. Escape at both layers, including spaces in cwd.
            clean = f"/bin/sh {shlex.quote(str(script))}"
            (repo / ".git" / "config").write_text(
                "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                f'[filter "canary"]\n\tclean = {json.dumps(clean)}\n\trequired = true\n',
                encoding="utf-8",
            )
        if control != "no-attributes":
            (repo / ".gitattributes").write_text("bait.txt filter=canary\n", encoding="utf-8")
        bait = b"Synthetic canary bait.\n"
        (repo / "bait.txt").write_bytes(bait)
        result.steps.append(ReproductionStep(f"{control}:filesystem-writes", 0))
        before = _non_git_snapshot(root)
        marker_before = marker.exists()
        if control == "filter":
            result.marker_before = marker_before
        if marker_before:
            raise _Failed("marker already existed before git add")
        _run_git(root, ["add", "--", "bait.txt"], f"{control}:git-add", result, timeout, git_tool)
        marker_after = marker.is_file() and not marker.is_symlink()
        if control == "filter":
            result.marker_after = marker_after
        indexed = _run_git(root, ["show", ":bait.txt"], f"{control}:verify-index", result, timeout, git_tool)
        correct_blob = indexed == bait.decode()
        if control == "filter":
            result.index_has_bait = correct_blob
        after = _non_git_snapshot(root)
        expected = dict(before)
        if control == "filter" and marker_after:
            expected["marker"] = after["marker"]
        unchanged = after == expected
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
        if (
            root.parent != parent
            or not root.name.startswith(PREFIX)
            or root.is_symlink()
            or root.resolve() != root
        ):
            result.teardown_confirmed = False
            raise _Failed("refusing teardown of an unverified canary path")
        shutil.rmtree(root)
        gone = not root.exists()
        result.isolation_checks[f"{control}:teardown"] = gone
        result.teardown_confirmed = gone
        if not gone:
            raise _Failed("canary teardown did not complete")


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
        base.mkdir(parents=True, exist_ok=True)
        if base.is_symlink() or base.absolute() != base.resolve():
            raise _Failed("canary parent must not contain symlinks")
        base = base.resolve()
        git_tool = resolve_git_tool(cwd=base)
        sh_variant = resolve_sh_variant()
        for control in ("filter", "no-filter-config", "no-attributes"):
            _case(base, control, result, timeout, git_tool, sh_variant)
        result.status = "REPRODUCED"
    except _Unavailable as exc:
        result.status, result.reason = "SKIPPED", str(exc)
    except _Failed as exc:
        result.reason = str(exc)
    except (OSError, UnicodeError) as exc:
        result.reason = f"canary operation failed ({type(exc).__name__})"
    return result
