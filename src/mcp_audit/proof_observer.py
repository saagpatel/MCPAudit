"""Disposable command observation with no host mounts or forwarded secrets."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from mcp_audit.proof_models import (
    CommandEvidence,
    DatabaseChange,
    FileChange,
    IsolationEvidence,
    NetworkEvidence,
    Observation,
    SurfaceObservation,
    canonical_json_bytes,
    sha256_bytes,
)

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
_MAX_OUTPUT_BYTES = 256 * 1024
_MAX_TEXT_FILE_BYTES = 16 * 1024 * 1024
_WRAPPER = r"""
set -eu
cp -R /pba-input/. /workspace/
cat /proc/net/snmp > /pba/network.before
ulimit -f 512
set +e
"$@" > /pba/stdout 2> /pba/stderr
rc=$?
set -e
cat /proc/net/snmp > /pba/network.after
printf '%s\n' "$rc" > /pba/exit-code
touch /pba/complete
sleep 600
"""


class ObservationBlocked(RuntimeError):
    """The command was not run because the disposable boundary could not be proven."""


def observe_command(
    repo: Path,
    command: list[str],
    *,
    image: str,
    timeout_seconds: int = 45,
) -> Observation:
    if not command:
        raise ObservationBlocked("a command is required after --")
    if timeout_seconds < 1 or timeout_seconds > 600:
        raise ObservationBlocked("timeout must be between 1 and 600 seconds")
    root = Path(tempfile.mkdtemp(prefix="proof-before-action-"))
    staged = root / "staged"
    collected = root / "collected"
    evidence = root / "evidence"
    staged.mkdir(mode=0o700)
    collected.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    container_id: str | None = None
    staging_container_id: str | None = None
    runtime_image: str | None = None
    try:
        _stage_repository(repo.resolve(), staged)
        before_files = _file_snapshot(staged)
        before_databases = _database_snapshot(staged)
        _make_disposable_writable(staged)
        image_id = _local_image_id(image)
        _require_image_tools(image)
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
                image,
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
        _run(["docker", "rm", "-f", staging_container_id], timeout=20)
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
                "/workspace:rw,nosuid,nodev,size=536870912,mode=0777",
                "--tmpfs",
                "/pba:rw,noexec,nosuid,nodev,size=8388608,mode=0777",
                "--workdir",
                "/workspace",
                "--user",
                "65534:65534",
                "--env",
                "HOME=/nonexistent",
                "--env",
                "LANG=C.UTF-8",
                "--entrypoint",
                "/bin/sh",
                runtime_image,
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
        started = _run(["docker", "start", container_id], timeout=20)
        if started.returncode != 0:
            raise ObservationBlocked("container start failed: " + _safe_error(started.stderr))

        timed_out = not _wait_for_completion(container_id, timeout_seconds)
        if timed_out:
            _run(["docker", "kill", container_id], timeout=10)
        if not timed_out:
            _collect_tree(container_id, "/workspace", collected, timeout=60)
            _collect_tree(container_id, "/pba", evidence, timeout=20)
            _run(["docker", "kill", container_id], timeout=10)
        exit_code = _read_exit_code(evidence / "exit-code")
        if timed_out:
            exit_code = None

        after_files = before_files if timed_out else _file_snapshot(collected)
        after_databases = before_databases if timed_out else _database_snapshot(collected)
        file_changes = _diff_files(before_files, after_files)
        database_changes = _diff_databases(before_databases, after_databases)
        network = _network_evidence(
            evidence / "network.before",
            evidence / "network.after",
            timed_out=timed_out,
        )
        stdout = _read_bounded(evidence / "stdout")
        stderr = _read_bounded(evidence / "stderr")
        filesystem = SurfaceObservation(
            attempted=True if file_changes else None,
            decision="allowed" if file_changes else "unknown",
            outcome="succeeded" if file_changes else "unknown",
            persisted="changed" if file_changes else "unchanged",
            mechanism="complete before/after hash inventory of the disposable workspace",
            complete=True,
            limitations=[
                "Transient create-delete or write-restore attempts are not observable "
                "without syscall tracing."
            ],
        )
        database = SurfaceObservation(
            attempted=True if database_changes else None,
            decision="allowed" if database_changes else "unknown",
            outcome="succeeded" if database_changes else "unknown",
            persisted="changed" if database_changes else "unchanged",
            mechanism="SQLite schema, row-count, and row-digest comparison plus file hashes",
            complete=not any(change.change == "unreadable" for change in database_changes),
            limitations=[
                "Only copied SQLite files receive semantic inspection; other databases "
                "remain file-level evidence.",
                "Transient transactions that leave no SQLite or journal delta are not observable.",
            ],
        )
        recorded_argv, recorded_argv_sha256 = _command_argv_evidence(command)
        return Observation(
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
        if container_id:
            _run(["docker", "rm", "-f", container_id], timeout=20)
        if staging_container_id:
            _run(["docker", "rm", "-f", staging_container_id], timeout=20)
        if runtime_image:
            _run(["docker", "image", "rm", "-f", runtime_image], timeout=30)
        shutil.rmtree(root, ignore_errors=True)


def _stage_repository(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise ObservationBlocked("repository path is not a directory")
    file_count = 0
    total_bytes = 0
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if any(part in _IGNORED_NAMES for part in relative.parts):
            continue
        if path.is_symlink():
            raise ObservationBlocked(f"input contains a symlink: {relative.as_posix()}")
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        if not path.is_file():
            raise ObservationBlocked(f"unsupported input file type: {relative.as_posix()}")
        if path.name.lower() in _SENSITIVE_INPUT_NAMES:
            raise ObservationBlocked(
                f"repository contains a sensitive file that will not be copied: {relative.as_posix()}"
            )
        file_count += 1
        total_bytes += path.stat().st_size
        if file_count > _MAX_FILES or total_bytes > _MAX_INPUT_BYTES:
            raise ObservationBlocked("repository exceeds the staging file-count or byte limit")
        _validate_staged_input(path, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def _make_disposable_writable(root: Path) -> None:
    for path in root.rglob("*"):
        os.chmod(path, 0o777 if path.is_dir() else 0o666)
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
    if _SENSITIVE_VALUE.search(text):
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
            image,
            "-c",
            "test -r /proc/net/snmp && command -v tar >/dev/null",
        ],
        timeout=20,
    )
    if result.returncode != 0:
        raise ObservationBlocked("local image lacks the required sh, tar, or procfs observer")


def _wait_for_completion(container_id: str, timeout_seconds: int) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        marker = _run(
            ["docker", "exec", container_id, "test", "-f", "/pba/complete"],
            timeout=5,
        )
        if marker.returncode == 0:
            return True
        state = _run(
            ["docker", "inspect", "--format", "{{.State.Running}}", container_id],
            timeout=5,
        )
        if state.returncode != 0 or state.stdout.decode().strip() != "true":
            logs = _run(["docker", "logs", container_id], timeout=10)
            raise ObservationBlocked(
                "observer wrapper exited before evidence collection: "
                + _safe_error(logs.stderr or logs.stdout)
            )
        time.sleep(0.1)
    return False


def _collect_tree(container_id: str, source: str, destination: Path, *, timeout: int) -> None:
    archived = _run(
        ["docker", "exec", container_id, "tar", "-C", source, "-cf", "-", "."],
        timeout=timeout,
    )
    if archived.returncode != 0:
        raise ObservationBlocked("runtime evidence collection failed: " + _safe_error(archived.stderr))
    file_count = 0
    total_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archived.stdout), mode="r:") as archive:
            for member in archive:
                relative = PurePosixPath(member.name)
                parts = tuple(part for part in relative.parts if part != ".")
                if relative.is_absolute() or ".." in parts:
                    raise ObservationBlocked("runtime evidence archive contains an unsafe path")
                if not parts:
                    continue
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
                else:
                    raise ObservationBlocked(
                        "runtime evidence contains a link or special file; collection stopped"
                    )
    except tarfile.TarError as exc:
        raise ObservationBlocked("runtime evidence archive is invalid") from exc


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
    security = [str(item) for item in host.get("SecurityOpt", [])]
    root_read_only = bool(host.get("ReadonlyRootfs"))
    runtime_user = str(inspect.get("Config", {}).get("User", ""))
    no_new_privileges = any("no-new-privileges" in item for item in security)
    log_driver = str(host.get("LogConfig", {}).get("Type", ""))
    pids_limit = host.get("PidsLimit")
    memory_bytes = host.get("Memory")
    nano_cpus = host.get("NanoCpus")
    tmpfs_paths = sorted(str(item) for item in host.get("Tmpfs", {}))
    if (
        network != "none"
        or "ALL" not in cap_drop
        or not root_read_only
        or mounts
        or runtime_user != "65534:65534"
        or not no_new_privileges
        or log_driver != "none"
        or pids_limit != 128
        or memory_bytes != 536870912
        or nano_cpus != 1000000000
        or tmpfs_paths != ["/pba", "/tmp", "/workspace"]
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
            "The container has no host mounts or forwarded sockets, but it runs inside "
            "a networked Colima VM.",
            "A container or VM escape could reach a broader host-adjacent surface; "
            "hostile-kernel isolation is not proven.",
            "Loopback remains available inside the isolated network namespace.",
        ],
    )


def _file_snapshot(root: Path) -> dict[str, tuple[str, str | None]]:
    snapshot: dict[str, tuple[str, str | None]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            snapshot[relative] = ("symlink", None)
        elif stat.S_ISDIR(mode):
            snapshot[relative] = ("directory", None)
        elif stat.S_ISREG(mode):
            snapshot[relative] = ("file", _sha256_file(path))
        else:
            snapshot[relative] = ("other", None)
    return snapshot


def _diff_files(
    before: dict[str, tuple[str, str | None]],
    after: dict[str, tuple[str, str | None]],
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


def _network_evidence(before: Path, after: Path, *, timed_out: bool) -> NetworkEvidence:
    if timed_out or not before.is_file() or not after.is_file():
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
    keys = (
        ("Tcp", "ActiveOpens"),
        ("Tcp", "PassiveOpens"),
        ("Tcp", "AttemptFails"),
        ("Udp", "OutDatagrams"),
        ("Ip", "OutRequests"),
    )
    deltas = {
        f"{protocol}.{field}": max(
            0, new.get(protocol, {}).get(field, 0) - old.get(protocol, {}).get(field, 0)
        )
        for protocol, field in keys
    }
    attempted = any(value > 0 for value in deltas.values())
    failed = deltas["Tcp.AttemptFails"] > 0
    return NetworkEvidence(
        surface=SurfaceObservation(
            attempted=attempted,
            decision="blocked" if failed else "unknown" if attempted else "not_applicable",
            outcome="failed" if failed else "unknown" if attempted else "not_applicable",
            persisted="unchanged",
            mechanism="per-container /proc/net/snmp counter delta under Docker network mode none",
            complete=True,
            limitations=[
                "Counters identify common IP/TCP/UDP activity but not the requested "
                "destination or every socket family.",
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
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        timeout=timeout,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")},
    )


def _safe_error(value: bytes) -> str:
    text = value[:4096].decode("utf-8", errors="replace")
    return text.replace(str(Path.home()), "$HOME")
