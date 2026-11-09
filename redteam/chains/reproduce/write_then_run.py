"""Sandboxed write-then-run canary using a synthetic shell script only."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
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
)

SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
PROCESS_CLEANUP_TIMEOUT = 1.0
DEMONSTRATION = (
    "Filesystem write followed by /bin/sh execution of a synthetic canary script; "
    "the run step is an operation-level stand-in, not a live MCP call."
)


def sandbox_profile(root: Path, script: Path, sh_variant: Path | None = None) -> str:
    """Allow only the shell and this canary script to execute."""
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
        f'(allow process-exec (literal "/bin/sh") {variant_literal}(literal {quote(str(script))}))\n'
    )


def _payload(marker: Path) -> str:
    return f"set -eu\n: > {shlex.quote(str(marker))}\n"


def _snapshot(root: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise _Failed("unexpected canary entry")
        value = "directory" if stat.S_ISDIR(info.st_mode) else hashlib.sha256(path.read_bytes()).hexdigest()
        snapshot[str(path.relative_to(root))] = f"{stat.S_IMODE(info.st_mode)}:{value}"
    return snapshot


def _run_script(root: Path, script: Path, name: str, result: ReproductionResult, timeout: float) -> int:
    command = [str(SANDBOX_EXEC), "-f", str(root / "sandbox.sb"), "/bin/sh", str(script)]
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
            result.steps.append(ReproductionStep(name, process.returncode, timed_out=True))
            raise _Failed(f"sandboxed script timed out at {name}") from None
    result.steps.append(ReproductionStep(name, process.returncode))
    if _is_nested_apply_failure(process.returncode, stderr):
        raise _Unavailable("nested sandbox unavailable")
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
    root = Path(tempfile.mkdtemp(prefix=PREFIX, dir=parent))
    try:
        if root.is_symlink() or root.resolve() != root or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise _Failed("temporary canary path is not private and resolved")
        for directory in ("home", "xdg", "tmp"):
            (root / directory).mkdir(mode=0o700)
        script = root / "canary.sh"
        marker = root / "marker"
        (root / "sandbox.sb").write_text(sandbox_profile(root, script, sh_variant), encoding="utf-8")
        marker_before = marker.exists()
        if marker_before:
            raise _Failed("marker already existed before script run")
        if write_script:
            script.write_text(_payload(marker), encoding="utf-8")
            script.chmod(0o600)
            result.steps.append(ReproductionStep("filesystem-write", 0))
            if not script.is_file() or script.is_symlink():
                raise _Failed("written canary script is not a regular file")
        else:
            result.steps.append(ReproductionStep("negative:no-script-written", 0))
        before = _snapshot(root)
        exit_code = _run_script(root, script, "run:/bin/sh", result, timeout)
        after = marker.is_file() and not marker.is_symlink()
        after_snapshot = _snapshot(root)
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
        base.mkdir(parents=True, exist_ok=True)
        if base.is_symlink() or base.absolute() != base.resolve():
            raise _Failed("canary parent must not contain symlinks")
        base = base.resolve()
        sh_variant = resolve_sh_variant()
        _case(base, result, timeout, sh_variant, write_script=True)
        _case(base, result, timeout, sh_variant, write_script=False)
        result.status = "REPRODUCED"
    except _Unavailable as exc:
        result.status, result.reason = "SKIPPED", str(exc)
    except _Failed as exc:
        result.reason = str(exc)
    except (OSError, UnicodeError) as exc:
        result.reason = f"canary operation failed ({type(exc).__name__})"
    return result
