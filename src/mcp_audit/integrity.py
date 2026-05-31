"""Launch-artifact integrity detector.

Provenance (MCP020–MCP023) compares the launch *config strings* — command, args,
URL, credential key names — against the pin baseline. But the command string can
stay byte-identical while the file it resolves to is swapped underneath you:
``python /opt/server.py`` is unchanged even if ``server.py`` was rewritten, and a
``/usr/local/bin/mcp-server`` binary can be replaced in place. This detector
closes that gap by hashing the actual on-disk artifact.

  MCP024 (ARTIFACT_DRIFT) — the SHA-256 of a pinned on-disk artifact changed
                            (HIGH), or the pinned file is gone from its path
                            (MEDIUM — often a relocation, still worth a look).

Scope (v1): offline and deterministic — it only hashes bytes already on the local
filesystem (the resolved command binary + local script-path arguments) and never
makes a network request. Package-runner launches (``npx pkg@x`` / ``uvx pkg``)
therefore hash the *runner* binary, not the remote package; verifying the resolved
registry artifact is a separate, network-gated follow-up.

Opt-in behind ``--integrity-check`` (which implies a pin comparison). Baselines
pinned before artifact hashes were captured return ``None`` and are skipped.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path

from mcp_audit.models import (
    IntegrityFinding,
    IntegrityKind,
    IntegritySeverity,
    ServerConfig,
)

logger = logging.getLogger(__name__)

# Cap per-file hashing so a pathological arg pointing at a huge file can't stall a
# scan. Real launch artifacts (binaries, scripts) are far below this.
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024  # 64 MiB
_CHUNK = 65536


def hash_file(path: Path) -> str | None:
    """Return the SHA-256 hex digest of a file, or None if it cannot be read.

    Bounded work: a fast ``stat()`` pre-check rejects oversize files, and the read
    loop also enforces the cap with a running counter so a file that grows after
    the stat (or a pipe/streaming source) cannot make hashing run unbounded. Only
    file bytes are read; nothing is written and no network is touched. The
    ``is_file``/``stat``/``open`` sequence is inherently TOCTOU — a symlink swapped
    mid-call could point ``open`` at a different target — but that needs write
    access to the artifact's directory, and ``_resolve_command`` canonicalises with
    ``.resolve()``; an unexpected swap surfaces as a normal hash-mismatch finding.
    """
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_ARTIFACT_BYTES:
            logger.debug("Skipping oversize artifact %s", path)
            return None
        total = 0
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK), b""):
                total += len(chunk)
                if total > _MAX_ARTIFACT_BYTES:
                    logger.debug("Artifact %s exceeded size cap mid-read", path)
                    return None
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        logger.debug("Could not hash artifact %s", path)
        return None


def _is_sensitive_path(path: Path) -> bool:
    """True if ``path`` lives under a known credential directory.

    Such files (SSH keys, cloud creds) can legitimately appear as launch args
    (e.g. ``--token-file ~/.aws/credentials``), but even their SHA-256 should not
    land in the pin store or an exported JSON/SARIF report. Mirrors the credential
    directories the workstation treats as never-readable.
    """
    home = Path.home()
    sensitive_dirs = (
        home / ".ssh",
        home / ".aws",
        home / ".gnupg",
        home / ".op",
        home / ".config" / "gcloud",
    )
    return any(path == d or d in path.parents for d in sensitive_dirs)


def _resolve_command(command: str) -> Path | None:
    """Resolve a launch command to an on-disk file path, or None.

    An absolute/relative path that exists is used directly; a bare name is looked
    up on PATH via ``shutil.which``.
    """
    candidate = Path(command).expanduser()
    if candidate.is_file():
        return candidate.resolve()
    found = shutil.which(command)
    return Path(found).resolve() if found else None


def resolve_artifact_paths(server_config: ServerConfig) -> list[Path]:
    """Return the on-disk artifact paths for a server's launch config.

    Includes the resolved command binary and any argument that is an existing
    local file (e.g. a script path). Order-preserving and de-duplicated.
    """
    paths: list[Path] = []
    seen: set[Path] = set()

    def _add(path: Path | None) -> None:
        if path is not None and path not in seen and not _is_sensitive_path(path):
            seen.add(path)
            paths.append(path)

    if server_config.command:
        _add(_resolve_command(server_config.command))
    for arg in server_config.args:
        candidate = Path(arg).expanduser()
        if candidate.is_file():
            _add(candidate.resolve())
    return paths


def resolve_artifact_hashes(server_config: ServerConfig) -> dict[str, str]:
    """Map each resolvable on-disk launch artifact to its SHA-256.

    Keyed by absolute path string. Artifacts that cannot be read/hashed are
    omitted. Used at pin time to snapshot the baseline and at scan time is mirrored
    by re-hashing the pinned paths.
    """
    result: dict[str, str] = {}
    for path in resolve_artifact_paths(server_config):
        digest = hash_file(path)
        if digest is not None:
            result[str(path)] = digest
    return result


class IntegrityAnalyzer:
    """Detects on-disk launch-artifact drift against a pin baseline snapshot."""

    def analyze_server(
        self,
        server_name: str,
        baseline_artifacts: dict[str, str] | None,
    ) -> list[IntegrityFinding]:
        """Return integrity findings for one server.

        ``baseline_artifacts`` is the pinned ``{path: sha256}`` map (from
        ``PinStore.baseline_artifacts``); ``None`` or empty means no comparison is
        possible (unpinned, or pinned before artifact hashes existed) and yields
        ``[]``. Each pinned path is re-hashed now and compared: a differing digest
        is HIGH, a missing file is MEDIUM.
        """
        if not baseline_artifacts:
            return []

        findings: list[IntegrityFinding] = []
        for path_str, baseline_hash in sorted(baseline_artifacts.items()):
            current_hash = hash_file(Path(path_str))
            if current_hash == baseline_hash:
                continue
            if current_hash is None:
                findings.append(
                    IntegrityFinding(
                        kind=IntegrityKind.ARTIFACT_DRIFT,
                        severity=IntegritySeverity.MEDIUM,
                        server_name=server_name,
                        artifact_path=path_str,
                        baseline_hash=baseline_hash,
                        current_hash=None,
                        summary=(
                            f"Pinned launch artifact for '{server_name}' is missing: "
                            f"{path_str} (was present at pin time). Often a relocation, but "
                            "confirm the server still launches the reviewed file."
                        ),
                    )
                )
            else:
                findings.append(
                    IntegrityFinding(
                        kind=IntegrityKind.ARTIFACT_DRIFT,
                        severity=IntegritySeverity.HIGH,
                        server_name=server_name,
                        artifact_path=path_str,
                        baseline_hash=baseline_hash,
                        current_hash=current_hash,
                        summary=(
                            f"Launch artifact for '{server_name}' changed since pin: {path_str} "
                            f"(SHA-256 {baseline_hash[:12]}…→{current_hash[:12]}…). The command "
                            "string is unchanged but the file it runs was modified."
                        ),
                    )
                )
        return findings
