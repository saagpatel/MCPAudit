"""Tool pinning — SHA256 schema snapshots and drift detection."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models import DriftFinding, DriftStatus, ServerConfig, ToolInfo

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: mutations run best-effort unlocked
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

DEFAULT_PIN_PATH = Path.home() / ".mcp-audit-pins.yaml"

# The pin file is user-editable; bound what we are willing to parse so a
# corrupted or hostile file cannot exhaust memory. Real baselines are a few KB.
_MAX_PIN_FILE_BYTES = 10 * 1024 * 1024


class PinFileError(Exception):
    """The pin file exists but cannot be parsed.

    Raised only on the mutation path: writing through an unreadable baseline
    would replace a file the user may be able to repair with a fresh one,
    silently destroying every pinned server. Read paths degrade to empty
    with a warning instead.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"cannot parse pin file {path}: {reason}")


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects aliases — blocks billion-laughs expansion.

    Trade-off: a hand-edited pin file using a legitimate anchor/alias is also
    rejected. That is acceptable ONLY because mutations refuse to touch an
    unparseable file (see :class:`PinFileError`) rather than wiping it.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.events.AliasEvent):  # type: ignore[no-untyped-call]
            raise yaml.YAMLError("YAML aliases are not supported in the pin file")
        return super().compose_node(parent, index)


class _NoAliasSafeDumper(yaml.SafeDumper):
    """SafeDumper that never emits anchors, so our own files always reload."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive advisory lock for a read-modify-write of ``path``.

    Serializes concurrent ``mcp-audit pin`` processes so one run's baseline
    cannot be erased by another's stale in-memory copy (lost update). On
    platforms without ``fcntl`` the lock is a no-op and mutations remain
    last-writer-wins. Caveat: ``flock`` may be silently non-serializing on
    NFS-mounted home directories.
    """
    if fcntl is None:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(".yaml.lock")
    with open(lock_path, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@dataclass(frozen=True)
class ServerPinStatus:
    """Review summary for one server in the pin baseline."""

    server_name: str
    tool_count: int
    oldest_pinned_at: datetime | None
    newest_pinned_at: datetime | None


@dataclass(frozen=True)
class StalePinStatus(ServerPinStatus):
    """Review summary for a pinned server that is not currently configured."""

    reason: str = "server not found in discovered MCP client configs"
    remediation: str = "If intentionally removed, run `mcp-audit pin --clear <server>`."


class PinStore:
    """Stores SHA256 hashes of MCP tool schemas and detects drift between scans."""

    def __init__(self, path: Path = DEFAULT_PIN_PATH) -> None:
        self._path = path
        self._data: dict[str, Any] = self._load()

    @property
    def path(self) -> Path:
        """Return the backing pin file path."""
        return self._path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_hash(self, tool: ToolInfo) -> str:
        """Return 'sha256:<hex>' hash of the tool's canonical schema."""
        payload = json.dumps(
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        digest = hashlib.sha256(payload.encode()).hexdigest()
        return f"sha256:{digest}"

    def pin_server(
        self,
        server_name: str,
        tools: list[ToolInfo],
        server_config: ServerConfig | None = None,
        package_hashes: dict[str, str] | None = None,
        artifact_hashes: dict[str, str] | None = None,
    ) -> None:
        """Upsert pin entries for all tools on a server. Writes atomically.

        When ``server_config`` is provided, its launch fields (command, args, url,
        transport, and env/header KEY NAMES — never values) are snapshotted so the
        provenance detector can compare them on later scans.
        """
        now = datetime.now(UTC).isoformat()
        with _file_lock(self._path):
            # Re-read under the lock: another process may have written pins
            # since this store loaded, and mutating a stale copy would erase them.
            self._data = self._load(strict=True)
            if "servers" not in self._data:
                self._data["servers"] = {}
            server_entry: dict[str, Any] = self._data["servers"].setdefault(server_name, {"tools": {}})
            tool_entries: dict[str, Any] = server_entry.setdefault("tools", {})
            for tool in tools:
                tool_entries[tool.name] = {
                    "hash": self.compute_hash(tool),
                    "pinned_at": now,
                    "snapshot": self._tool_snapshot(tool),
                }
            if server_config is not None:
                snapshot = self._config_snapshot(server_config)
                prior = server_entry.get("config_snapshot")
                prior_snapshot = prior if isinstance(prior, dict) else {}
                if package_hashes:
                    # Registry-published package hashes (npm/PyPI) captured under
                    # --verify-artifacts; values are hashes only, never package bytes.
                    snapshot["package_hashes"] = dict(package_hashes)
                elif isinstance(prior_snapshot.get("package_hashes"), dict):
                    # Preserve a previously-captured registry baseline when this pin
                    # call did not supply one (e.g. a schema-only `pin --refresh`), so
                    # it isn't silently wiped by an unrelated refresh.
                    snapshot["package_hashes"] = prior_snapshot["package_hashes"]
                if artifact_hashes:
                    # Byte-level registry artifact hashes (sha256 over the served npm/PyPI
                    # bytes) captured under --download-artifacts; hashes only, never bytes.
                    # NOTE: stored under "registry_artifact_hashes" — distinct from
                    # "artifact_hashes", which _config_snapshot already owns for the MCP024
                    # on-disk launch-artifact baseline ({path: sha256}). The two namespaces
                    # must never share a key.
                    snapshot["registry_artifact_hashes"] = dict(artifact_hashes)
                elif isinstance(prior_snapshot.get("registry_artifact_hashes"), dict):
                    snapshot["registry_artifact_hashes"] = prior_snapshot["registry_artifact_hashes"]
                server_entry["config_snapshot"] = snapshot
            self._data["pinned_at"] = now
            self._write()

    def check_drift(self, server_name: str, tools: list[ToolInfo]) -> list[DriftFinding]:
        """Compare current tool hashes against stored pins. Returns drift findings."""
        servers: dict[str, Any] = self._data.get("servers", {})
        server_entry: dict[str, Any] = servers.get(server_name, {})
        pinned_tools: dict[str, Any] = server_entry.get("tools", {})

        findings: list[DriftFinding] = []
        current_names = {t.name for t in tools}
        pinned_names = set(pinned_tools.keys())

        # NEW: in current scan but not pinned
        for tool in tools:
            if tool.name not in pinned_names:
                findings.append(
                    DriftFinding(
                        server_name=server_name,
                        tool_name=tool.name,
                        status=DriftStatus.NEW,
                        stored_hash=None,
                        current_hash=self.compute_hash(tool),
                        pinned_at=None,
                        summary="Tool is present now but was not in the pin baseline.",
                        details=self._new_tool_details(tool),
                        remediation="Review the tool capability and run `mcp-audit pin` after approval.",
                    )
                )
            else:
                # CHANGED: hash mismatch
                pin_entry: dict[str, Any] = pinned_tools[tool.name]
                stored_hash: str = pin_entry.get("hash", "")
                current_hash = self.compute_hash(tool)
                if stored_hash != current_hash:
                    pinned_at = self._parse_datetime(pin_entry.get("pinned_at"))
                    findings.append(
                        DriftFinding(
                            server_name=server_name,
                            tool_name=tool.name,
                            status=DriftStatus.CHANGED,
                            stored_hash=stored_hash,
                            current_hash=current_hash,
                            pinned_at=pinned_at,
                            summary="Pinned tool metadata changed since the baseline.",
                            details=self._changed_tool_details(pin_entry, tool),
                            remediation=(
                                "Review the changed tool metadata before refreshing the pin baseline."
                            ),
                        )
                    )

        # REMOVED: in pins but not in current scan
        for tool_name in pinned_names - current_names:
            pin_entry = pinned_tools[tool_name]
            stored_hash = pin_entry.get("hash", "")
            pinned_at = self._parse_datetime(pin_entry.get("pinned_at"))
            findings.append(
                DriftFinding(
                    server_name=server_name,
                    tool_name=tool_name,
                    status=DriftStatus.REMOVED,
                    stored_hash=stored_hash,
                    current_hash=None,
                    pinned_at=pinned_at,
                    summary="Pinned tool is no longer exposed by the server.",
                    details=["tool missing from current scan"],
                    remediation="Confirm the removal is expected, then remove or refresh the stale pin.",
                )
            )

        return findings

    def remove_server(self, server_name: str) -> None:
        """Remove all pins for a server. No-op if server not pinned."""
        with _file_lock(self._path):
            self._data = self._load(strict=True)
            servers: dict[str, Any] = self._data.get("servers", {})
            if server_name in servers:
                del servers[server_name]
                self._write()

    def pinned_servers(self) -> list[str]:
        """Return list of server names that have pins."""
        return list(self._data.get("servers", {}).keys())

    def tool_count(self, server_name: str) -> int:
        """Return number of pinned tools for a server."""
        servers: dict[str, Any] = self._data.get("servers", {})
        return len(servers.get(server_name, {}).get("tools", {}))

    def baseline_tools(self, server_name: str) -> list[ToolInfo]:
        """Reconstruct pinned tools as ``ToolInfo`` from stored snapshots.

        Returns the description + input_schema captured at pin time so callers can
        re-derive the baseline capability/injection surface (used by the
        escalation detector). Annotations are not snapshotted, so reconstructed
        tools carry ``annotations=None``. Empty list if the server is not pinned.
        """
        servers: dict[str, Any] = self._data.get("servers", {})
        pinned_tools: dict[str, Any] = servers.get(server_name, {}).get("tools", {})
        tools: list[ToolInfo] = []
        for name, entry in pinned_tools.items():
            snapshot: dict[str, Any] = entry.get("snapshot", {})
            tools.append(
                ToolInfo(
                    name=name,
                    description=snapshot.get("description"),
                    input_schema=snapshot.get("input_schema"),
                )
            )
        return tools

    def baseline_config(self, server_name: str) -> dict[str, Any] | None:
        """Return the pinned launch-config snapshot for a server, or None.

        None when the server is unpinned OR was pinned before config snapshots
        existed (older baselines) — callers must treat None as "no provenance
        comparison possible" and skip silently.
        """
        servers: dict[str, Any] = self._data.get("servers", {})
        snapshot = servers.get(server_name, {}).get("config_snapshot")
        return snapshot if isinstance(snapshot, dict) else None

    def baseline_artifacts(self, server_name: str) -> dict[str, str] | None:
        """Return the pinned launch-artifact ``{path: sha256}`` map, or None.

        None when the server is unpinned, has no config snapshot, or was pinned
        before artifact hashes were captured (older baselines) — callers treat
        None as "no integrity comparison possible" and skip silently.
        """
        snapshot = self.baseline_config(server_name)
        if snapshot is None:
            return None
        hashes = snapshot.get("artifact_hashes")
        if not isinstance(hashes, dict):
            return None
        return {str(path): str(digest) for path, digest in hashes.items()}

    def baseline_package_hashes(self, server_name: str) -> dict[str, str] | None:
        """Return the pinned registry package ``{ref_key: hash}`` map, or None.

        None when unpinned, no config snapshot, or pinned without
        ``--verify-artifacts`` (no package hashes captured) — callers skip silently.
        """
        snapshot = self.baseline_config(server_name)
        if snapshot is None:
            return None
        hashes = snapshot.get("package_hashes")
        if not isinstance(hashes, dict):
            return None
        return {str(key): str(digest) for key, digest in hashes.items()}

    def baseline_artifact_hashes(self, server_name: str) -> dict[str, str] | None:
        """Return the pinned byte-level registry artifact ``{ref_key: sha256}`` map, or None.

        None when unpinned, no config snapshot, or pinned without
        ``--download-artifacts`` (no artifact byte-hashes captured) — callers skip
        silently. Read from ``registry_artifact_hashes``, which is kept distinct from
        ``artifact_hashes`` (the MCP024 on-disk launch-artifact baseline, keyed by
        filesystem path) and ``package_hashes`` (the MCP025 registry-metadata baseline).
        """
        snapshot = self.baseline_config(server_name)
        if snapshot is None:
            return None
        hashes = snapshot.get("registry_artifact_hashes")
        if not isinstance(hashes, dict):
            return None
        return {str(key): str(digest) for key, digest in hashes.items()}

    def status(self) -> list[ServerPinStatus]:
        """Return review summaries for all pinned servers."""
        servers: dict[str, Any] = self._data.get("servers", {})
        statuses: list[ServerPinStatus] = []
        for server_name in sorted(servers):
            server_entry = servers.get(server_name, {})
            if not isinstance(server_entry, dict):
                continue
            tools = server_entry.get("tools", {})
            if not isinstance(tools, dict):
                continue
            pinned_times = [
                parsed
                for entry in tools.values()
                if isinstance(entry, dict)
                for parsed in [self._parse_datetime(entry.get("pinned_at"))]
                if parsed is not None
            ]
            statuses.append(
                ServerPinStatus(
                    server_name=server_name,
                    tool_count=len(tools),
                    oldest_pinned_at=min(pinned_times) if pinned_times else None,
                    newest_pinned_at=max(pinned_times) if pinned_times else None,
                )
            )
        return statuses

    def stale_baselines(self, discovered_server_names: set[str]) -> list[StalePinStatus]:
        """Return pinned servers that are not present in discovered MCP client configs."""
        stale: list[StalePinStatus] = []
        for status in self.status():
            if status.server_name in discovered_server_names:
                continue
            stale.append(
                StalePinStatus(
                    server_name=status.server_name,
                    tool_count=status.tool_count,
                    oldest_pinned_at=status.oldest_pinned_at,
                    newest_pinned_at=status.newest_pinned_at,
                )
            )
        return stale

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self, *, strict: bool = False) -> dict[str, Any]:
        """Parse the pin file.

        ``strict=False`` (read paths): parse failures degrade to ``{}`` with a
        warning — a broken baseline should not block a scan. ``strict=True``
        (mutation paths): parse failures raise :class:`PinFileError`, because
        writing through them would wipe a possibly-repairable baseline.
        """
        if not self._path.exists():
            return {}
        try:
            # Bounded read (not stat-then-read): the file cannot grow past the
            # cap between a size check and the read.
            with open(self._path, "rb") as handle:
                data = handle.read(_MAX_PIN_FILE_BYTES + 1)
            if len(data) > _MAX_PIN_FILE_BYTES:
                raise yaml.YAMLError(f"pin file exceeds {_MAX_PIN_FILE_BYTES} bytes")
            raw: Any = yaml.load(data.decode("utf-8"), Loader=_NoAliasSafeLoader)  # noqa: S506 - loader subclasses SafeLoader
            return dict(raw) if isinstance(raw, dict) else {}
        except Exception as exc:
            if strict:
                raise PinFileError(str(self._path), f"{type(exc).__name__}: {exc}") from exc
            logger.warning(
                "Failed to parse pin file %s (%s) — treating as empty for reading; "
                "pin mutations will refuse to overwrite it",
                self._path,
                exc,
            )
            return {}

    def _write(self) -> None:
        """Write pin data atomically (tmp file → rename)."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".yaml.tmp")
        tmp.write_text(
            yaml.dump(
                self._data,
                Dumper=_NoAliasSafeDumper,
                default_flow_style=False,
                allow_unicode=True,
            )
        )
        tmp.rename(self._path)

    def _parse_datetime(self, value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _tool_snapshot(self, tool: ToolInfo) -> dict[str, Any]:
        """Return the reviewable tool fields stored alongside the pin hash."""
        return {
            "description": tool.description,
            "input_schema": tool.input_schema,
        }

    def _config_snapshot(self, server_config: ServerConfig) -> dict[str, Any]:
        """Return the launch-config fields stored for provenance comparison.

        Credential surface is recorded by KEY NAME only (env_keys / headers_keys);
        no value is ever read or stored. Key lists are sorted for stable diffing.
        Also captures SHA-256 hashes of the resolved on-disk launch artifacts
        (command binary + local script args) for the integrity detector — hashes
        only, never file contents.
        """
        from mcp_audit.integrity import resolve_artifact_hashes

        return {
            "command": server_config.command,
            "args": list(server_config.args),
            "url": server_config.url,
            "transport": server_config.transport.value,
            "env_keys": sorted(server_config.env_keys),
            "headers_keys": sorted(server_config.headers_keys),
            "artifact_hashes": resolve_artifact_hashes(server_config),
        }

    def _new_tool_details(self, tool: ToolInfo) -> list[str]:
        details = ["not previously pinned"]
        if tool.description:
            details.append("description present")
        if tool.input_schema:
            details.append("input schema present")
        return details

    def _changed_tool_details(self, pin_entry: dict[str, Any], tool: ToolInfo) -> list[str]:
        previous = pin_entry.get("snapshot")
        current = self._tool_snapshot(tool)

        if not isinstance(previous, dict):
            return ["pin hash changed; previous schema snapshot unavailable"]

        details: list[str] = []
        if previous.get("description") != current["description"]:
            details.append("description changed")
        if previous.get("input_schema") != current["input_schema"]:
            details.append("input schema changed")
        if not details:
            details.append("tool metadata changed")
        return details
