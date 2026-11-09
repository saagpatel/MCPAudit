"""Sandboxed write-then-run canary using a synthetic shell script only."""

from __future__ import annotations

import json
import os
import shlex
import signal
import stat
import subprocess
import sys
from functools import partial
from pathlib import Path

from redteam.chains.reproduce import (
    PREFIX,
    ReproductionResult,
    ReproductionStep,
    _Failed,
    _is_nested_apply_failure,
    _Unavailable,
    canary_environment,
    resolve_sh_variant,
    validate_profile_paths,
)
from redteam.chains.reproduce.containment import PrivateCanary, prepare_parent

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
PROCESS_CLEANUP_TIMEOUT = 1.0
DEMONSTRATION = (
    "Filesystem write followed by /bin/sh execution of a synthetic canary script; "
    "the run step is an operation-level stand-in, not a live MCP call."
)


def sandbox_profile(root: Path, script: Path, sh_variant: Path | None = None) -> str:
    """Constrain writes, network, and execution to the shell and canary script.

    Reads remain at allow default: shells and dyld need system runtime files
    beyond a fixed allow-list. Reads are outside this canary's threat model.
    """
    validate_profile_paths(root, script, sh_variant)
    quote = json.dumps
    variant_literal = f"(literal {quote(str(sh_variant))}) " if sh_variant is not None else ""
    return (
        "(version 1)\n(allow default)\n"
        "(deny network*)\n(deny file-write*)\n"
        f"(allow file-write* (subpath {quote(str(root))}) "
        '(literal "/dev/null") (literal "/dev/tty"))\n'
        "(deny process-exec)\n"
        f'(allow process-exec (literal "/bin/sh") {variant_literal}(literal {quote(str(script))}))\n'
    )


def _payload(marker: Path) -> str:
    return f"set -eu\n: > {shlex.quote(str(marker))}\n"


def _run_script(
    root: Path,
    script: Path,
    name: str,
    result: ReproductionResult,
    timeout: float,
    *,
    missing_script: bool = False,
    canary: PrivateCanary | None = None,
) -> int:
    if canary is not None:
        canary.verify()
    command = [
        str(SANDBOX_EXEC),
        "-p",
        sandbox_profile(root, script, resolve_sh_variant()),
        "/bin/sh",
        script.name if canary is not None else str(script),
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
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
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
            finally:
                result.steps.append(ReproductionStep(name, process.returncode, timed_out=True))
            raise _Failed(f"sandboxed script timed out at {name}") from None
    finally:
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
    result.steps.append(ReproductionStep(name, process.returncode))
    if _is_nested_apply_failure(process.returncode, stderr):
        raise _Unavailable("nested sandbox unavailable")
    if missing_script and not (
        process.returncode == 2
        and os.fsencode(script.name if canary is not None else script) in stderr
        and b"No such file or directory" in stderr
    ):
        raise _Failed("negative control did not establish a missing-script failure")
    return process.returncode


def _case(
    parent: Path,
    result: ReproductionResult,
    timeout: float,
    sh_variant: Path | None,
    *,
    write_script: bool,
) -> None:
    control = "positive" if write_script else "no-script-written"
    canary = PrivateCanary(parent, PREFIX)
    root = canary.root
    try:
        if root.is_symlink() or root.resolve() != root or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise _Failed("temporary canary path is not private and resolved")
        for directory in ("home", "xdg", "tmp"):
            canary.mkdir(directory)
        script = root / "canary.sh"
        canary.write("sandbox.sb", sandbox_profile(root, script, sh_variant).encode())
        marker_before = "marker" in canary.snapshot()
        if marker_before:
            raise _Failed("marker already existed before script run")
        if write_script:
            canary.write("canary.sh", _payload(Path("marker")).encode())
            result.steps.append(ReproductionStep("filesystem-write", 0))
            if not script.is_file() or script.is_symlink():
                raise _Failed("written canary script is not a regular file")
        else:
            result.steps.append(ReproductionStep("negative:no-script-written", 0))
        before = canary.snapshot()
        exit_code = _run_script(
            root, script, "run:/bin/sh", result, timeout, missing_script=not write_script, canary=canary
        )
        after_snapshot = canary.snapshot()
        after = after_snapshot.get("marker", "").endswith(
            ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        if write_script:
            expected = dict(before)
            if after:
                expected["marker"] = after_snapshot["marker"]
            only_marker_added = after and after_snapshot == expected
            result.isolation_checks[f"{control}:only-marker-added"] = only_marker_added
            result.marker_before, result.marker_after = marker_before, after
            if exit_code != 0 or not after:
                raise _Failed("written script did not create marker")
            if not only_marker_added:
                raise _Failed("script changed unexpected canary files")
        else:
            result.isolation_checks[f"{control}:unchanged"] = after_snapshot == before
            result.negative_controls["no-script-written"] = not after and exit_code != 0
            if after_snapshot != before:
                raise _Failed("negative control changed canary files")
            if after or exit_code == 0:
                raise _Failed("negative control unexpectedly ran")
    finally:
        result.teardown_confirmed = False
        result.isolation_checks[f"{control}:teardown"] = False
        canary.teardown()
        result.isolation_checks[f"{control}:teardown"] = True
        result.teardown_confirmed = True


def reproduce_write_then_run(*, parent: Path | None = None, timeout: float = 10.0) -> ReproductionResult:
    """Run a write-then-run canary with a missing-script negative control."""
    result = ReproductionResult("NOT_REPRODUCED", demonstration=DEMONSTRATION)
    if sys.platform != "darwin":
        result.status, result.reason = "SKIPPED", "requires macOS sandbox-exec"
        return result
    if not SANDBOX_EXEC.is_file():
        result.status, result.reason = "SKIPPED", "sandbox-exec is unavailable"
        return result
    if not 0 < timeout <= 60:
        raise ValueError("timeout must be positive and at most 60 seconds")
    base = parent if parent is not None else Path("build/redteam/chains")
    try:
        base = prepare_parent(base)
        sh_variant = resolve_sh_variant()
        _case(base, result, timeout, sh_variant, write_script=True)
        _case(base, result, timeout, sh_variant, write_script=False)
        result.status = "REPRODUCED"
    except _Unavailable as exc:
        result.status, result.reason = "SKIPPED", str(exc)
    except _Failed as exc:
        result.reason = str(exc)
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        result.reason = f"canary operation failed ({type(exc).__name__})"
    return result
