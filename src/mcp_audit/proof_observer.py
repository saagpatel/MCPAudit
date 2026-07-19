"""Disposable command observation with no host mounts or forwarded secrets."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from mcp_audit.proof_models import (
    CommandEvidence,
    CommandRuntimeProfile,
    DatabaseChange,
    FileChange,
    IsolationEvidence,
    NetworkEvidence,
    Observation,
    SubjectSnapshotEvidence,
    SurfaceObservation,
    canonical_json_bytes,
    sha256_bytes,
)

_FileSnapshot = dict[str, tuple[str, str | None, bool | None]]

_IGNORED_NAMES = {
    ".DS_Store",
    ".coverage",
    ".git",
    ".mypy_cache",
    ".nox",
    ".serena",
    ".tox",
    ".venv",
    "htmlcov",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
}
_SENSITIVE_INPUT_NAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
_SENSITIVE_ARGUMENT = re.compile(
    r"(?i)(?:^|[-_])(api[-_]?key|auth|authorization|cookie|credential|password|"
    r"private[-_]?key|secret|token)(?:$|[-_=])"
)
_SENSITIVE_VALUE = re.compile(
    r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/=-]+|"
    r"://[^/@\s]+:[^/@\s]+@|"
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_LITERAL_CREDENTIAL_VALUE = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+|"
    r"://[^/@\s]+:[^/@\s]+@|"
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)
_SENSITIVE_HEADER_ASSIGNMENT = re.compile(
    r"(?i)(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*[\"']?([^\"'\r\n]+)"
)
_HOME_PATH = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s\"']+(?:/[^\s\"']*)?")
_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|auth|authorization|cookie|credential|password|"
    r"private[_-]?key|secret|token)(?:$|[_-])"
)
_TEXT_SECRET_ASSIGNMENT = re.compile(
    r"(?im)^\s*([A-Za-z0-9._-]*(?:api[_-]?key|auth|authorization|cookie|credential|"
    r"password|private[_-]?key|secret|token)[A-Za-z0-9._-]*)\s*[:=]\s*"
    r"[\"']?([^\"'#\r\n]+)"
)
_SAFE_DATABASE_NAME = re.compile(r"(?i)(?:fixture|sample|seed|synthetic|test)")
_PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:\$\{?[A-Z0-9_]+\}?|\$\{\{\s*(?:env|secrets|vars)\.[A-Z0-9_.-]+\s*\}\}|"
    r"<[^>]+>|changeme|dummy|example|fixture|"
    r"placeholder|redacted|sample|synthetic|test)$"
)
_DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_REPO_CONFIG_NAMES = {".mcp.json", "server.json"}
_TEXT_CONFIG_SUFFIXES = {".cfg", ".conf", ".ini", ".properties", ".toml", ".yaml", ".yml"}
_MAX_FILES = 10_000
_MAX_INPUT_BYTES = 512 * 1024 * 1024
_MAX_ARCHIVE_BYTES = _MAX_INPUT_BYTES + 32 * 1024 * 1024
_MAX_OUTPUT_BYTES = 256 * 1024
_MAX_TEXT_FILE_BYTES = 16 * 1024 * 1024
_RUNTIME_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_WRAPPER = r"""
set -eu
cp -R --preserve=mode --no-preserve=ownership /pba-input/. /workspace/
chmod -R a+rwX /workspace
cat /proc/net/snmp > /pba/network.before
cat /proc/net/snmp6 > /pba/network6.before
ulimit -f 512
set +e
timeout --signal=TERM --kill-after=1 "${PBA_TIMEOUT_SECONDS}s" \
    setpriv --reuid=65534 --regid=65534 --clear-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    -- /bin/sh -c '
        cat /proc/self/status >&3 || exit 125
        exec 3>&-
        exec "$@"
    ' proof-before-action-command "$@" \
    3> /pba/command.status > /pba/stdout 2> /pba/stderr
rc=$?
set -e
chmod 0400 /pba/command.status
if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    touch /pba/timed-out
fi
quiescent=false
for _sweep in 1 2 3 4 5; do
    kill -KILL -1 2>/dev/null || true
    sleep 0.05
    active=false
    for status in /proc/[0-9]*/task/[0-9]*/status; do
        task=${status%/status}
        tid=${task##*/}
        [ "$tid" = "$$" ] && continue
        if [ ! -r "$status" ]; then
            active=true
            continue
        fi
        state=
        while read -r key value _rest; do
            if [ "$key" = "State:" ]; then
                state=$value
                break
            fi
        done < "$status" || active=true
        if [ -z "$state" ]; then
            active=true
            continue
        fi
        case "$state" in
            Z|X|x) ;;
            *) active=true ;;
        esac
    done
    if [ "$active" = false ]; then
        quiescent=true
        break
    fi
done
if [ "$quiescent" = false ]; then
    exit 3
fi
cat /proc/net/snmp > /pba/network.after
cat /proc/net/snmp6 > /pba/network6.after
printf '%s\n' "$rc" > /pba/exit-code
touch /pba/complete
tar -C / -cf - workspace pba
"""


class ObservationBlocked(RuntimeError):
    """The command was not run because the disposable boundary could not be proven."""


def observe_command(
    repo: Path,
    command: list[str],
    *,
    image: str,
    expected_image_id: str | None = None,
    timeout_seconds: int = 45,
) -> Observation:
    if not command:
        raise ObservationBlocked("a command is required after --")
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise ObservationBlocked("timeout must be between 1 and 600 seconds")
    root = Path(tempfile.mkdtemp(prefix="proof-before-action-"))
    staged = root / "staged"
    collected_root = root / "collected"
    collected = collected_root / "workspace"
    evidence = collected_root / "pba"
    staged.mkdir(mode=0o700)
    collected_root.mkdir(mode=0o700)
    container_id: str | None = None
    staging_container_id: str | None = None
    runtime_image: str | None = None
    try:
        subject_root = repo.resolve()
        _stage_repository(subject_root, staged)
        before_files = _file_snapshot(staged)
        subject_snapshot = _subject_snapshot_evidence(subject_root, staged, before_files)
        before_databases = _database_snapshot(staged)
        _make_disposable_writable(staged)
        image_id = _local_image_id(image)
        _verify_expected_image_id(image_id, expected_image_id)
        _require_image_tools(image_id)
        name = "pba-" + secrets.token_hex(8)
        runtime_image = name + "-input"
        stage_create = _run(
            [
                "docker",
                "create",
                "--name",
                name + "-stage",
                "--network",
                "none",
                "--entrypoint",
                "/bin/true",
                image_id,
            ],
            timeout=20,
        )
        if stage_create.returncode != 0:
            raise ObservationBlocked(
                "input staging container creation failed: " + _safe_error(stage_create.stderr)
            )
        staging_container_id = stage_create.stdout.decode().strip()
        copied = _run(
            ["docker", "cp", str(staged) + "/.", f"{staging_container_id}:/pba-input"],
            timeout=60,
        )
        if copied.returncode != 0:
            raise ObservationBlocked("staged input copy failed: " + _safe_error(copied.stderr))
        committed = _run(
            ["docker", "commit", staging_container_id, runtime_image],
            timeout=60,
        )
        if committed.returncode != 0:
            raise ObservationBlocked(
                "content-addressed staging image failed: " + _safe_error(committed.stderr)
            )
        committed_image_id = committed.stdout.decode().strip()
        if not committed_image_id.startswith("sha256:"):
            raise ObservationBlocked("content-addressed staging image did not return an immutable ID")
        if error := _cleanup_docker_resource(["docker", "rm", "-f", staging_container_id], timeout=20):
            raise ObservationBlocked("staging container cleanup could not be confirmed: " + error)
        staging_container_id = None
        create = _run(
            [
                "docker",
                "create",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "KILL",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SETPCAP",
                "--cap-add",
                "SETUID",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "128",
                "--memory",
                "512m",
                "--cpus",
                "1",
                "--log-driver",
                "none",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777",
                "--tmpfs",
                "/workspace:rw,exec,nosuid,nodev,size=536870912,mode=0777",
                "--tmpfs",
                "/pba:rw,noexec,nosuid,nodev,size=8388608,mode=0700",
                "--workdir",
                "/workspace",
                "--user",
                "0:0",
                "--env",
                "HOME=/nonexistent",
                "--env",
                "LANG=C.UTF-8",
                "--env",
                f"PATH={_RUNTIME_PATH}",
                "--env",
                f"PBA_TIMEOUT_SECONDS={timeout_seconds}",
                "--entrypoint",
                "/bin/sh",
                committed_image_id,
                "-c",
                _WRAPPER,
                "proof-before-action-wrapper",
                *command,
            ],
            timeout=20,
        )
        if create.returncode != 0:
            raise ObservationBlocked("container creation failed: " + _safe_error(create.stderr))
        container_id = create.stdout.decode().strip()
        inspect = _inspect_container(container_id)
        isolation = _isolation_evidence(image, image_id, inspect)
        archive_path = root / "observation.tar"
        attached = _run_bounded_archive(
            ["docker", "start", "--attach", container_id],
            archive_path,
            timeout=timeout_seconds + 75,
        )
        if attached.returncode != 0:
            raise ObservationBlocked(
                f"observer wrapper failed with exit code {attached.returncode} "
                "before completing evidence collection: " + _safe_error(attached.stderr)
            )
        _extract_observation_archive(archive_path, collected_root)
        if not (evidence / "complete").is_file():
            raise ObservationBlocked("observer wrapper exited before completing evidence collection")
        command_runtime_profile = _read_command_runtime_profile(evidence / "command.status")
        isolation = isolation.model_copy(update={"command_runtime_profile": command_runtime_profile})
        timed_out = (evidence / "timed-out").is_file()
        exit_code = _read_exit_code(evidence / "exit-code")
        if timed_out:
            exit_code = None

        after_files = _file_snapshot(collected)
        after_databases = _database_snapshot(collected)
        file_changes = _diff_files(before_files, after_files)
        database_changes = _diff_databases(before_databases, after_databases)
        database_paths = {item.path for item in database_changes}
        non_database_file_changes = [item for item in file_changes if item.path not in database_paths]
        network = _network_evidence(
            evidence / "network.before",
            evidence / "network.after",
            evidence / "network6.before",
            evidence / "network6.after",
            timed_out=timed_out,
        )
        stdout = _read_bounded(evidence / "stdout")
        stderr = _read_bounded(evidence / "stderr")
        filesystem = SurfaceObservation(
            attempted=True if non_database_file_changes else None,
            decision="allowed" if non_database_file_changes else "unknown",
            outcome="succeeded" if non_database_file_changes else "unknown",
            persisted="changed" if non_database_file_changes else "unchanged",
            mechanism="complete before/after hash inventory of the disposable workspace",
            complete=False,
            limitations=[
                "Persisted regular-file state is completely compared, but transient "
                "create-delete or write-restore attempts are not observable without syscall tracing."
            ],
        )
        database = SurfaceObservation(
            attempted=True if database_changes else None,
            decision="allowed" if database_changes else "unknown",
            outcome="succeeded" if database_changes else "unknown",
            persisted="changed" if database_changes else "unchanged",
            mechanism="SQLite schema, row-count, and row-digest comparison plus file hashes",
            complete=False,
            limitations=[
                "Only copied SQLite files receive semantic inspection; other databases "
                "remain file-level evidence.",
                "Persisted SQLite state is compared unless reported unreadable, but transient "
                "transactions that leave no SQLite or journal delta are not observable.",
            ],
        )
        recorded_argv, recorded_argv_sha256 = _command_argv_evidence(command)
        return Observation(
            subject_snapshot=subject_snapshot,
            isolation=isolation,
            command=CommandEvidence(
                argv=recorded_argv,
                argv_sha256=recorded_argv_sha256,
                executable=Path(command[0]).name,
                exit_code=exit_code,
                timed_out=timed_out,
                stdout_sha256=sha256_bytes(stdout),
                stderr_sha256=sha256_bytes(stderr),
                stdout_bytes=len(stdout),
                stderr_bytes=len(stderr),
            ),
            filesystem=filesystem,
            file_changes=file_changes,
            database=database,
            database_changes=database_changes,
            network=network,
            limitations=[
                "The Linux guest cannot represent macOS Keychain, TCC, XPC, Apple Events, "
                "GUI, device, or kernel effects.",
                "The container boundary is defense in depth, not proof against container, "
                "VM, or hypervisor escape.",
                "Raw command output is hashed and omitted to reduce credential and private-payload exposure.",
                "Command arguments use best-effort credential redaction; argv and output "
                "hashes can still reveal low-entropy secrets by guessing.",
                "Link or special-file output stops collection rather than being silently omitted.",
                "Nested child-process identities and short-lived process effects are not completely traced.",
            ],
        )
    finally:
        cleanup_errors: list[str] = []
        if container_id:
            if error := _cleanup_docker_resource(["docker", "rm", "-f", container_id], timeout=20):
                cleanup_errors.append(error)
        if staging_container_id:
            if error := _cleanup_docker_resource(["docker", "rm", "-f", staging_container_id], timeout=20):
                cleanup_errors.append(error)
        if runtime_image:
            if error := _cleanup_docker_resource(["docker", "image", "rm", "-f", runtime_image], timeout=30):
                cleanup_errors.append(error)
        if error := _cleanup_local_root(root):
            cleanup_errors.append(error)
        if cleanup_errors and sys.exc_info()[0] is None:
            raise ObservationBlocked("disposable Docker cleanup could not be confirmed: " + cleanup_errors[0])


def _stage_repository(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ObservationBlocked("repository path is not a directory")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ObservationBlocked("platform cannot securely open repository inputs without following links")
    file_count = 0
    total_bytes = 0
    expected_directories = {"."}
    traversed_directories: set[str] = set()
    for directory, directory_names, file_names, directory_fd in os.fwalk(
        source,
        topdown=True,
        onerror=_raise_repository_walk_error,
        follow_symlinks=False,
    ):
        relative_directory = Path(directory).relative_to(source)
        traversed_directories.add(relative_directory.as_posix())
        retained_directories: list[str] = []
        for name in sorted(directory_names):
            relative = relative_directory / name
            if not repository_input_is_in_scope(relative):
                continue
            try:
                mode = os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
            except OSError as exc:
                raise ObservationBlocked(
                    f"repository input directory could not be inspected: {relative.as_posix()}"
                ) from exc
            if not stat.S_ISDIR(mode):
                raise ObservationBlocked(f"input contains a symlink: {relative.as_posix()}")
            retained_directories.append(name)
            expected_directories.add(relative.as_posix())
            (destination / relative).mkdir(parents=True, exist_ok=True)
        directory_names[:] = retained_directories

        for name in sorted(file_names):
            relative = relative_directory / name
            if not repository_input_is_in_scope(relative):
                continue
            if name.lower() in _SENSITIVE_INPUT_NAMES:
                raise ObservationBlocked(
                    f"repository contains a sensitive file that will not be copied: {relative.as_posix()}"
                )
            flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK
            try:
                descriptor = os.open(name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise ObservationBlocked(
                    f"input contains a symlink or unreadable file: {relative.as_posix()}"
                ) from exc
            try:
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise ObservationBlocked(f"unsupported input file type: {relative.as_posix()}")
                file_count += 1
                if file_count > _MAX_FILES or opened.st_size > _MAX_INPUT_BYTES - total_bytes:
                    raise ObservationBlocked("repository exceeds the staging file-count or byte limit")
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with os.fdopen(descriptor, "rb") as source_file:
                    descriptor = -1
                    copied_bytes = _copy_open_repository_file(
                        source_file,
                        target,
                        max_bytes=_MAX_INPUT_BYTES - total_bytes,
                    )
                os.chmod(target, 0o755 if opened.st_mode & 0o111 else 0o644)
                total_bytes += copied_bytes
                _validate_staged_input(target, relative)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
    if traversed_directories != expected_directories:
        raise ObservationBlocked("repository input tree changed or could not be traversed completely")


def _raise_repository_walk_error(error: OSError) -> None:
    raise ObservationBlocked("repository input tree changed or could not be traversed completely") from error


def repository_input_is_in_scope(relative: Path) -> bool:
    """Return whether the observer copies this repository-relative path."""
    return not any(part in _IGNORED_NAMES for part in relative.parts)


def _copy_open_repository_file(
    source: Any,
    target: Path,
    *,
    max_bytes: int,
) -> int:
    copied = 0
    with target.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            copied += len(chunk)
            if copied > max_bytes:
                raise ObservationBlocked("repository exceeds the staging file-count or byte limit")
            output.write(chunk)
    return copied


def _subject_snapshot_evidence(
    source: Path,
    staged: Path,
    staged_tree: _FileSnapshot,
) -> SubjectSnapshotEvidence:
    from mcp_audit.proof_trust import discover_repo_mcp

    dependencies, diagnostics = discover_repo_mcp(staged)
    staged_tree_sha256 = sha256_bytes(canonical_json_bytes(staged_tree))
    commit: str | None = None
    dirty: bool | None = None
    try:
        commit = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        prefix = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--show-prefix"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        object_format = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--show-object-format"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        tree_command = ["git", "-C", str(source), "ls-tree", "-r", "-z", commit]
        if prefix:
            tree_command.extend(["--", prefix])
        tree = subprocess.run(
            tree_command,
            check=True,
            capture_output=True,
            timeout=5,
        ).stdout
        committed_tree: _FileSnapshot = {}
        for record in tree.split(b"\0"):
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            repository_path = os.fsdecode(raw_path)
            relative = repository_path[len(prefix) :] if prefix else repository_path
            if repository_input_is_in_scope(Path(relative)):
                kind = "file" if object_type == "blob" and mode in {"100644", "100755"} else "other"
                executable = mode == "100755" if kind == "file" else None
                committed_tree[relative] = (
                    kind,
                    object_id if kind == "file" else None,
                    executable,
                )
                parent = Path(relative).parent
                while parent != Path("."):
                    committed_tree[parent.as_posix()] = ("directory", None, None)
                    parent = parent.parent
        dirty = set(staged_tree) != set(committed_tree) or any(
            staged_tree[path][0] != committed_tree[path][0] or staged_tree[path][2] != committed_tree[path][2]
            for path in set(staged_tree) & set(committed_tree)
        )
        if not dirty:
            for relative, (kind, expected_object_id, _executable) in committed_tree.items():
                if kind != "file":
                    continue
                value = (staged / relative).read_bytes()
                header = f"blob {len(value)}\0".encode()
                actual_object_id = hashlib.new(object_format, header + value).hexdigest()
                if expected_object_id != actual_object_id:
                    dirty = True
                    break
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        dirty = None
    return SubjectSnapshotEvidence(
        repository_commit=commit,
        repository_dirty=dirty,
        staged_tree_sha256=staged_tree_sha256,
        dependencies=dependencies,
        diagnostics=diagnostics,
    )


def _make_disposable_writable(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_dir():
            mode = 0o777
        else:
            mode = 0o777 if path.stat().st_mode & 0o111 else 0o666
        os.chmod(path, mode)
    os.chmod(root, 0o777)


def _redact_argv(argv: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for value in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        if "=" in value and _SENSITIVE_ARGUMENT.search(value.split("=", 1)[0]):
            redacted.append(value.split("=", 1)[0] + "=<redacted>")
            continue
        if _SENSITIVE_VALUE.search(value):
            redacted.append("<redacted>")
            continue
        redacted.append(_HOME_PATH.sub(_home_path_replacement, value))
        if _SENSITIVE_ARGUMENT.search(value):
            redact_next = True
    return redacted


def _home_path_replacement(match: re.Match[str]) -> str:
    parts = match.group(0).split("/", 3)
    return "$HOME" + ("/" + parts[3] if len(parts) == 4 else "")


def _command_argv_evidence(argv: list[str]) -> tuple[list[str], str]:
    redacted = _redact_argv(argv)
    return redacted, sha256_bytes(canonical_json_bytes(redacted))


def _validate_staged_input(path: Path, relative: Path) -> None:
    if path.suffix.lower() in _DATABASE_SUFFIXES:
        with path.open("rb") as database:
            header = database.read(16)
        if not _SAFE_DATABASE_NAME.search(path.name) or header != b"SQLite format 3\0":
            raise ObservationBlocked(
                "database input must be an explicitly named synthetic SQLite fixture: " + relative.as_posix()
            )
        return
    if path.stat().st_size > _MAX_TEXT_FILE_BYTES:
        raise ObservationBlocked(f"binary or oversized text input will not be copied: {relative.as_posix()}")
    value = path.read_bytes()
    if b"\0" in value:
        raise ObservationBlocked(f"binary or oversized text input will not be copied: {relative.as_posix()}")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ObservationBlocked(f"non-UTF-8 input will not be copied: {relative.as_posix()}") from exc
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        raise ObservationBlocked(
            f"repository input appears to contain private key material: {relative.as_posix()}"
        )
    if _contains_literal_credential_material(text):
        raise ObservationBlocked(
            f"repository input appears to contain credential material: {relative.as_posix()}"
        )
    if path.suffix.lower() == ".json" or path.name in _REPO_CONFIG_NAMES:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = None
        if payload is not None and _json_contains_literal_secret(payload):
            raise ObservationBlocked(f"repository JSON contains a literal credential: {relative.as_posix()}")
    if path.suffix.lower() in _TEXT_CONFIG_SUFFIXES:
        for match in _TEXT_SECRET_ASSIGNMENT.finditer(text):
            key, match_value = match.groups()
            if not _SENSITIVE_KEY.search(key):
                continue
            normalized_key = key.lower()
            normalized_value = match_value.strip().lower()
            if normalized_key == "id-token" and normalized_value in {"none", "read", "write"}:
                continue
            if normalized_key == "persist-credentials" and normalized_value == "false":
                continue
            if not _is_placeholder(match_value):
                raise ObservationBlocked(
                    f"repository text contains a literal credential assignment: {relative.as_posix()}"
                )


def _contains_literal_credential_material(text: str) -> bool:
    if _LITERAL_CREDENTIAL_VALUE.search(text):
        return True
    for match in _SENSITIVE_HEADER_ASSIGNMENT.finditer(text):
        value = match.group(1).strip().rstrip("\\").strip().strip("\"'")
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        if not _is_placeholder(value):
            return True
    return False


def _json_contains_literal_secret(value: Any) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            if key_text in {"env", "headers"} and isinstance(nested, dict):
                if any(_literal_secret_value(item) for item in nested.values()):
                    return True
            if _SENSITIVE_KEY.search(key_text) and _literal_secret_value(nested):
                return True
            if key_text == "args" and isinstance(nested, list):
                args = [str(item) for item in nested]
                if _redact_argv(args) != args:
                    return True
            if _json_contains_literal_secret(nested):
                return True
    elif isinstance(value, list):
        return any(_json_contains_literal_secret(item) for item in value)
    return False


def _literal_secret_value(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and not _is_placeholder(value)
    return value is not None


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().strip("\"'")
    return bool(_PLACEHOLDER_VALUE.fullmatch(normalized))


def _local_image_id(image: str) -> str:
    result = _run(["docker", "image", "inspect", "--format", "{{.Id}}", image], timeout=20)
    if result.returncode != 0:
        raise ObservationBlocked(
            "the image must already exist locally; Proof Before Action never pulls code or images"
        )
    return result.stdout.decode().strip()


def _verify_expected_image_id(resolved: str, expected: str | None) -> None:
    if expected is None:
        raise ObservationBlocked(
            "an independently sourced --expect-image-id is required before image-provided "
            "observer tools can run"
        )
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected):
        raise ObservationBlocked("--expect-image-id must be an exact sha256 image ID")
    if resolved != expected:
        raise ObservationBlocked(
            f"resolved image ID {resolved!r} does not match independently supplied "
            f"--expect-image-id {expected!r}"
        )


def _require_image_tools(image: str) -> None:
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            "/bin/sh",
            "--env",
            f"PATH={_RUNTIME_PATH}",
            image,
            "-c",
            "test -r /proc/net/snmp && test -r /proc/net/snmp6 && command -v tar >/dev/null "
            "&& command -v cp >/dev/null && command -v timeout >/dev/null "
            "&& command -v setpriv >/dev/null",
        ],
        timeout=20,
    )
    if result.returncode != 0:
        raise ObservationBlocked(
            "local image lacks the required sh, cp, tar, timeout, setpriv, or procfs observer"
        )


def _extract_observation_archive(value: Path, destination: Path) -> None:
    file_count = 0
    total_bytes = 0
    try:
        with tarfile.open(value, mode="r:") as archive:
            for member in archive:
                relative = PurePosixPath(member.name)
                parts = tuple(part for part in relative.parts if part != ".")
                if (
                    relative.is_absolute()
                    or ".." in parts
                    or not parts
                    or parts[0] not in {"workspace", "pba"}
                ):
                    raise ObservationBlocked("runtime evidence archive contains an unsafe path")
                target = destination.joinpath(*parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    file_count += 1
                    total_bytes += member.size
                    if file_count > _MAX_FILES or total_bytes > _MAX_INPUT_BYTES:
                        raise ObservationBlocked("runtime evidence exceeds the file-count or byte limit")
                    source_file = archive.extractfile(member)
                    if source_file is None:
                        raise ObservationBlocked("runtime evidence file could not be read")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("wb") as output:
                        shutil.copyfileobj(source_file, output)
                    os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
                else:
                    raise ObservationBlocked(
                        "runtime evidence contains a link or special file; collection stopped"
                    )
    except tarfile.TarError as exc:
        raise ObservationBlocked("runtime evidence archive is invalid") from exc


def _read_command_runtime_profile(path: Path) -> CommandRuntimeProfile:
    try:
        fields: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition(":")
            if separator:
                fields[key] = value.strip()
        uids = tuple(int(item) for item in fields["Uid"].split())
        gids = tuple(int(item) for item in fields["Gid"].split())
        groups = [int(item) for item in fields["Groups"].split()]
        capability_fields = {
            key: int(fields[key], 16) for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
        }
        no_new_privileges = int(fields["NoNewPrivs"])
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        raise ObservationBlocked("tested command runtime profile was unavailable or malformed") from exc
    expected_identity = (65534, 65534, 65534, 65534)
    if (
        uids != expected_identity
        or gids != expected_identity
        or groups
        or any(capability_fields.values())
        or no_new_privileges != 1
    ):
        raise ObservationBlocked(
            "tested command runtime profile did not match the required unprivileged identity"
        )
    return CommandRuntimeProfile(
        uids=(65534, 65534, 65534, 65534),
        gids=(65534, 65534, 65534, 65534),
        supplementary_groups=groups,
        capabilities_inheritable=0,
        capabilities_permitted=0,
        capabilities_effective=0,
        capabilities_bounding=0,
        capabilities_ambient=0,
        no_new_privileges=True,
    )


def _inspect_container(container_id: str) -> dict[str, Any]:
    result = _run(["docker", "inspect", container_id], timeout=20)
    if result.returncode != 0:
        raise ObservationBlocked("container isolation readback failed")
    payload = json.loads(result.stdout)
    return cast(dict[str, Any], payload[0])


def _isolation_evidence(image: str, image_id: str, inspect: dict[str, Any]) -> IsolationEvidence:
    host = inspect.get("HostConfig", {})
    mounts = inspect.get("Mounts", [])
    network = str(host.get("NetworkMode", "unknown"))
    cap_drop = {str(item).upper() for item in host.get("CapDrop", [])}
    cap_add = {str(item).upper().removeprefix("CAP_") for item in host.get("CapAdd", [])}
    security = [str(item) for item in host.get("SecurityOpt", [])]
    root_read_only = bool(host.get("ReadonlyRootfs"))
    runtime_user = str(inspect.get("Config", {}).get("User", ""))
    no_new_privileges = any("no-new-privileges" in item for item in security)
    log_driver = str(host.get("LogConfig", {}).get("Type", ""))
    pids_limit = host.get("PidsLimit")
    memory_bytes = host.get("Memory")
    nano_cpus = host.get("NanoCpus")
    tmpfs = {str(key): str(value) for key, value in host.get("Tmpfs", {}).items()}
    expected_tmpfs = {
        "/pba": "rw,noexec,nosuid,nodev,size=8388608,mode=0700",
        "/tmp": "rw,noexec,nosuid,nodev,size=67108864,mode=1777",
        "/workspace": "rw,exec,nosuid,nodev,size=536870912,mode=0777",
    }
    tmpfs_paths = sorted(tmpfs)
    if (
        network != "none"
        or "ALL" not in cap_drop
        or not root_read_only
        or mounts
        or cap_add != {"KILL", "SETGID", "SETPCAP", "SETUID"}
        or runtime_user != "0:0"
        or not no_new_privileges
        or log_driver != "none"
        or pids_limit != 128
        or memory_bytes != 536870912
        or nano_cpus != 1000000000
        or tmpfs != expected_tmpfs
    ):
        raise ObservationBlocked(
            "container isolation readback did not match the required fail-closed profile"
        )
    return IsolationEvidence(
        image_reference=image,
        image_id=image_id,
        runtime_user="65534:65534",
        container_network_mode=network,
        log_driver="none",
        root_filesystem_read_only=root_read_only,
        capabilities_dropped=True,
        no_new_privileges=no_new_privileges,
        pids_limit=128,
        memory_bytes=536870912,
        nano_cpus=1000000000,
        tmpfs_paths=tmpfs_paths,
        host_mounts=[],
        secrets_forwarded=[],
        containment="partial",
        limitations=[
            "The fixed PID 1 observer retains only KILL, SETGID, SETPCAP, and SETUID "
            "so it can protect evidence, empty the command capability bounding set, "
            "enforce the unprivileged command identity, and terminate descendants.",
            "The tested command runs as 65534:65534 with an empty capability bounding set.",
            "The container has no host mounts or forwarded sockets, but the Docker engine "
            "and any VM or hypervisor layer are outside the observed boundary.",
            "A container escape, or VM escape when a VM is present, could reach a broader "
            "host-adjacent surface; hostile-kernel isolation is not proven.",
            "Loopback remains available inside the isolated network namespace.",
        ],
        observer_user="0:0",
        observer_capabilities=["KILL", "SETGID", "SETPCAP", "SETUID"],
    )


def _file_snapshot(root: Path) -> _FileSnapshot:
    snapshot: _FileSnapshot = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            snapshot[relative] = ("symlink", None, None)
        elif stat.S_ISDIR(mode):
            snapshot[relative] = ("directory", None, None)
        elif stat.S_ISREG(mode):
            snapshot[relative] = ("file", _sha256_file(path), bool(mode & 0o111))
        else:
            snapshot[relative] = ("other", None, None)
    return snapshot


def _diff_files(
    before: _FileSnapshot,
    after: _FileSnapshot,
) -> list[FileChange]:
    changes: list[FileChange] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        change: Literal["added", "modified", "deleted", "type_changed"]
        if old is None:
            change = "added"
        elif new is None:
            change = "deleted"
        elif old[0] != new[0]:
            change = "type_changed"
        else:
            change = "modified"
        changes.append(
            FileChange(
                path=path,
                change=change,
                before_sha256=old[1] if old else None,
                after_sha256=new[1] if new else None,
            )
        )
    return changes


def _database_snapshot(root: Path) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _DATABASE_SUFFIXES:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            values[relative] = _sqlite_semantic_snapshot(path)
        except (OSError, sqlite3.Error, ValueError) as exc:
            values[relative] = {
                "file_sha256": _sha256_file(path),
                "error": type(exc).__name__,
            }
    return values


def _sqlite_semantic_snapshot(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        table_values: dict[str, dict[str, Any]] = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            count = int(connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0])
            if count > 10_000:
                raise ValueError("SQLite table exceeds the semantic row cap")
            rows = connection.execute(f"SELECT * FROM {quoted} ORDER BY rowid").fetchall()
            normalized = [[_sqlite_value(item) for item in row] for row in rows]
            table_values[table] = {
                "rows": count,
                "sha256": sha256_bytes(canonical_json_bytes(normalized)),
            }
        schema = [
            list(row)
            for row in connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            )
        ]
        return {
            "file_sha256": _sha256_file(path),
            "schema_sha256": sha256_bytes(canonical_json_bytes(schema)),
            "tables": table_values,
        }
    finally:
        connection.close()


def _sqlite_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int)):
        return value
    if isinstance(value, float):
        return {"float_text": repr(value)}
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    return {"value_sha256": hashlib.sha256(repr(value).encode()).hexdigest()}


def _diff_databases(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[DatabaseChange]:
    changes: list[DatabaseChange] = []
    for path in sorted(set(before) | set(after)):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        change: Literal["added", "modified", "deleted", "unreadable"]
        if old is None:
            change = "added"
        elif new is None:
            change = "deleted"
        elif "error" in old or "error" in new:
            change = "unreadable"
        else:
            change = "modified"
        old_tables = old.get("tables", {}) if old else {}
        new_tables = new.get("tables", {}) if new else {}
        changed_tables = sorted(
            table
            for table in set(old_tables) | set(new_tables)
            if old_tables.get(table) != new_tables.get(table)
        )
        changes.append(
            DatabaseChange(
                path=path,
                change=change,
                before_sha256=old.get("file_sha256") if old else None,
                after_sha256=new.get("file_sha256") if new else None,
                changed_tables=changed_tables,
                limitations=["SQLite semantic inspection failed."] if change == "unreadable" else [],
            )
        )
    return changes


def _network_evidence(
    before: Path,
    after: Path,
    before6: Path,
    after6: Path,
    *,
    timed_out: bool,
) -> NetworkEvidence:
    if (
        timed_out
        or not before.is_file()
        or not after.is_file()
        or not before6.is_file()
        or not after6.is_file()
    ):
        return NetworkEvidence(
            surface=SurfaceObservation(
                attempted=None,
                decision="unknown",
                outcome="unknown",
                persisted="unknown",
                mechanism="Linux network namespace counters",
                complete=False,
                limitations=["Network counters were unavailable because the run did not exit normally."],
            )
        )
    old = _parse_snmp(before)
    new = _parse_snmp(after)
    old6 = _parse_snmp6(before6)
    new6 = _parse_snmp6(after6)
    ipv4_keys = (
        ("Tcp", "ActiveOpens"),
        ("Tcp", "PassiveOpens"),
        ("Tcp", "AttemptFails"),
        ("Udp", "OutDatagrams"),
        ("Ip", "OutRequests"),
    )
    ipv6_keys = ("Ip6OutRequests", "Udp6OutDatagrams")
    if any(
        field not in old.get(protocol, {}) or field not in new.get(protocol, {})
        for protocol, field in ipv4_keys
    ) or any(field not in old6 or field not in new6 for field in ipv6_keys):
        return NetworkEvidence(
            surface=SurfaceObservation(
                attempted=None,
                decision="unknown",
                outcome="unknown",
                persisted="unknown",
                mechanism="Linux IPv4 and IPv6 network namespace counters",
                complete=False,
                limitations=["Required IPv4 or IPv6 network counters were unavailable."],
            )
        )
    if any(new[protocol][field] < old[protocol][field] for protocol, field in ipv4_keys) or any(
        new6[field] < old6[field] for field in ipv6_keys
    ):
        return NetworkEvidence(
            surface=SurfaceObservation(
                attempted=None,
                decision="unknown",
                outcome="unknown",
                persisted="unknown",
                mechanism="Linux IPv4 and IPv6 network namespace counters",
                complete=False,
                limitations=["A required network counter regressed or wrapped during observation."],
            )
        )
    deltas = {
        f"{protocol}.{field}": new[protocol][field] - old[protocol][field] for protocol, field in ipv4_keys
    }
    deltas["Ip6.OutRequests"] = new6["Ip6OutRequests"] - old6["Ip6OutRequests"]
    deltas["Udp6.OutDatagrams"] = new6["Udp6OutDatagrams"] - old6["Udp6OutDatagrams"]
    attempted = any(value > 0 for value in deltas.values())
    failed = deltas["Tcp.AttemptFails"] > 0
    return NetworkEvidence(
        surface=SurfaceObservation(
            attempted=attempted,
            decision="blocked" if failed else "unknown" if attempted else "not_applicable",
            outcome="failed" if failed else "unknown" if attempted else "not_applicable",
            persisted="unchanged",
            mechanism=(
                "per-container /proc/net/snmp and /proc/net/snmp6 counter deltas "
                "under Docker network mode none"
            ),
            complete=False,
            limitations=[
                "IPv4/IPv6 IP and UDP counters plus family-agnostic Linux TCP counters "
                "identify activity but not the requested destination.",
                "Unix-domain socket activity, including abstract sockets, is not observed.",
                "Docker network mode none proves no ordinary external interface, not "
                "resistance to container escape.",
            ],
        ),
        counters=deltas,
    )


def _parse_snmp(path: Path) -> dict[str, dict[str, int]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    result: dict[str, dict[str, int]] = {}
    for index in range(0, len(lines) - 1, 2):
        headers = lines[index].split()
        values = lines[index + 1].split()
        if not headers or not values or headers[0] != values[0]:
            continue
        result[headers[0].rstrip(":")] = {
            key: int(value) for key, value in zip(headers[1:], values[1:], strict=False)
        }
    return result


def _parse_snmp6(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            result[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return result


def _read_exit_code(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as value:
            return value.read(_MAX_OUTPUT_BYTES)
    except OSError:
        return b""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as value:
        while chunk := value.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _run(argv: list[str], *, timeout: int) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")},
        )
    except subprocess.TimeoutExpired as exc:
        raise ObservationBlocked(f"Docker command timed out after {timeout} seconds") from exc


def _run_bounded_archive(
    argv: list[str],
    output: Path,
    *,
    timeout: int,
    max_bytes: int = _MAX_ARCHIVE_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")},
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise ObservationBlocked("Docker archive command pipes were unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout
    written = 0
    stderr = bytearray()
    try:
        with output.open("xb") as archive:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ObservationBlocked(f"Docker command timed out after {timeout} seconds")
                for key, _events in selector.select(min(remaining, 0.25)):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stdout":
                        if written + len(chunk) > max_bytes:
                            raise ObservationBlocked("runtime evidence archive exceeded the host byte limit")
                        archive.write(chunk)
                        written += len(chunk)
                    elif len(stderr) < _MAX_OUTPUT_BYTES:
                        stderr.extend(chunk[: _MAX_OUTPUT_BYTES - len(stderr)])
        returncode = process.wait(timeout=max(deadline - time.monotonic(), 0.001))
        return subprocess.CompletedProcess(argv, returncode, b"", bytes(stderr))
    except subprocess.TimeoutExpired as exc:
        raise ObservationBlocked(f"Docker command timed out after {timeout} seconds") from exc
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()


def _cleanup_docker_resource(argv: list[str], *, timeout: int) -> str | None:
    try:
        result = _run(argv, timeout=timeout)
    except (OSError, ObservationBlocked) as exc:
        return str(exc)
    if result.returncode != 0:
        return f"Docker cleanup command failed with exit code {result.returncode}"
    return None


def _cleanup_local_root(root: Path) -> str | None:
    shutil.rmtree(root, ignore_errors=True)
    if root.exists():
        return "local temporary evidence root still exists after cleanup"
    return None


def _safe_error(value: bytes) -> str:
    text = value[:4096].decode("utf-8", errors="replace")
    return text.replace(str(Path.home()), "$HOME")
