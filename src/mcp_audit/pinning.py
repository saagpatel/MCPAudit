"""Tool pinning — SHA256 schema snapshots and drift detection."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.canonical import canonical_json_bytes
from mcp_audit.models import (
    DriftFinding,
    DriftStatus,
    ScanWarning,
    ServerConfig,
    SurfaceFieldChange,
    ToolInfo,
)
from mcp_audit.redaction import redact_data, redact_text
from mcp_audit.terminal_text import TerminalSafeLogFilter

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: mutations run best-effort unlocked
    fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())

DEFAULT_PIN_PATH = Path.home() / ".mcp-audit-pins.yaml"

# The pin file is user-editable; bound what we are willing to parse so a
# corrupted or hostile file cannot exhaust memory. Real baselines are a few KB.
_MAX_PIN_FILE_BYTES = 10 * 1024 * 1024
TOOL_SURFACE_SCHEMA = "mcpaudit.tool-surface.v2"


def canonical_tool_surface(tool: ToolInfo) -> dict[str, object]:
    """Return the v2 tool form, preserving schemas and filling hint defaults."""
    annotations = tool.annotations
    hints: dict[str, object] = {}
    for wire_name, field, default in (
        ("readOnlyHint", "read_only_hint", False),
        ("destructiveHint", "destructive_hint", True),
        ("idempotentHint", "idempotent_hint", False),
        ("openWorldHint", "open_world_hint", True),
    ):
        value = getattr(annotations, field) if annotations is not None else None
        hints[wire_name] = default if value is None else value
    if annotations is not None and annotations.title:
        hints["title"] = annotations.title
    surface: dict[str, object] = {
        "name": tool.name,
        "inputSchema": tool.input_schema,
        "annotations": hints,
    }
    for key, optional in (
        ("title", tool.title),
        ("description", tool.description),
        ("outputSchema", tool.output_schema),
        ("icons", tool.icons),
        ("meta", tool.meta),
    ):
        if optional is not None and optional != "" and optional != [] and optional != {}:
            surface[key] = optional
    if tool.icons:
        surface["icons"] = [
            {
                key: value
                for key, value in icon.items()
                if key not in {"mimeType", "sizes", "theme"}
                or (value is not None and value != "" and value != [])
            }
            for icon in tool.icons
        ]
    return surface


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


def _describe_parse_error(exc: Exception) -> str:
    """Sanitized, secret-safe description of a pin file parse failure.

    ``str(exc)`` on a YAML parser error renders a snippet of the offending
    source line (``Mark.get_snippet``), which can echo a pasted secret back
    into ``ScanWarning.message`` — a value that flows into scan JSON/MCP
    responses. Report only the exception class and, when the parser
    supplies one, its line/column — never the parser's rendered message.
    """
    name = type(exc).__name__
    mark = getattr(exc, "problem_mark", None)
    if mark is not None:
        return f"{name} at line {mark.line + 1}, column {mark.column + 1}"
    return name


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
        self._read_error: str | None = None
        self._data: dict[str, Any] = self._load()

    @property
    def path(self) -> Path:
        """Return the backing pin file path."""
        return self._path

    @property
    def read_error(self) -> str | None:
        """Parse failure from the last non-strict load, or ``None``.

        Set when the pin file exists but could not be parsed, so callers can
        tell a corrupted baseline (scarier: possibly wiped or tampered) apart
        from a genuinely absent one — both otherwise look like
        ``pinned_servers() == []``.
        """
        return self._read_error

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_hash(self, tool: ToolInfo) -> str:
        """Return 'sha256:<hex>' hash of the tool's canonical schema."""
        return surface_hash(canonical_tool_surface(tool))

    def legacy_tool_names(self, server_name: str) -> set[str]:
        """Tools whose pins predate annotation coverage, including mixed files."""
        entries = self._data.get("servers", {}).get(server_name, {}).get("tools", {})
        return {name for name, entry in entries.items() if entry.get("pin_schema", 1) == 1}

    def schema_warnings(self, server_name: str) -> list[ScanWarning]:
        """Expose reduced legacy coverage without changing or re-hashing pins."""
        if not self.legacy_tool_names(server_name):
            return []
        return [
            ScanWarning(
                code="pin_schema_outdated",
                message=(
                    f"{server_name} has schema v1 pins; annotations, title, outputSchema, icons "
                    "and meta are not covered. Run "
                    f"`mcp-audit pin --refresh {server_name} --apply` after review."
                ),
                check="pin_check",
                servers=[server_name],
            )
        ]

    def uncovered_field_rows(self, server_name: str, tools: list[ToolInfo]) -> list[dict[str, str]]:
        """Refresh review rows for fields absent from the old hash contract."""
        legacy = self.legacy_tool_names(server_name)
        return [
            {"tool_name": tool.name, "field": field, "summary": "not previously covered"}
            for tool in tools
            if tool.name in legacy
            for field in ("annotations", "title", "outputSchema", "icons", "meta")
        ]

    def pin_server(
        self,
        server_name: str,
        tools: list[ToolInfo],
        server_config: ServerConfig | None = None,
        package_hashes: dict[str, str] | None = None,
        artifact_hashes: dict[str, str] | None = None,
        *,
        redact_args: bool = True,
    ) -> None:
        """Upsert pin entries for all tools on a server. Writes atomically.

        When ``server_config`` is provided, its launch fields (command, args, url,
        transport, and env/header KEY NAMES — never values) are snapshotted so the
        provenance detector can compare them on later scans. Arguments are
        credential-redacted unless ``redact_args=False``; URLs are always redacted.
        """
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("Cannot pin duplicate tool names.")
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
                    "pin_schema": 2,
                    "canonical_form": TOOL_SURFACE_SCHEMA,
                    "hash": self.compute_hash(tool),
                    "pinned_at": now,
                    "snapshot": self._tool_snapshot(tool),
                }
            if server_config is not None:
                snapshot = self._config_snapshot(server_config, redact_args=redact_args)
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
            self._data["pin_schema"] = 2
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
                snapshot = pin_entry.get("snapshot")
                current_hash = (
                    _legacy_tool_hash(
                        tool,
                        empty_input_as_none=not isinstance(snapshot, dict)
                        or snapshot.get("input_schema") is None,
                    )
                    if pin_entry.get("pin_schema", 1) == 1
                    else self.compute_hash(tool)
                )
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

        Restores all covered fields, including annotations. Legacy snapshots
        retain absent fields as None. Empty list if the server is not pinned.
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
                    annotations=snapshot.get("annotations"),
                    title=snapshot.get("title"),
                    output_schema=snapshot.get("output_schema"),
                    icons=snapshot.get("icons"),
                    meta=snapshot.get("meta"),
                )
            )
        return tools

    def canary_baseline(
        self, server_name: str, *, warnings: list[ScanWarning] | None = None
    ) -> dict[str, dict[str, object]] | None:
        """Use complete v2 pins; warn and fall back when their snapshots are corrupt."""
        if server_name not in self.pinned_servers() or self.legacy_tool_names(server_name):
            return None
        entries = self._data["servers"][server_name].get("tools", {})
        if any(entry.get("pin_schema") != 2 for entry in entries.values()):
            return None
        required_fields = ToolInfo.model_fields.keys() - {"name"}
        tools: dict[str, object] = {}
        try:
            for name, entry in entries.items():
                snapshot: object = entry.get("snapshot")
                if not isinstance(snapshot, dict) or not required_fields <= snapshot.keys():
                    raise ValueError("Incomplete v2 tool snapshot")
                tool = ToolInfo.model_validate({**snapshot, "name": name}, strict=True)
                surface = canonical_tool_surface(tool)
                canonical_json_bytes(surface)
                tools[name] = surface
        except (TypeError, ValueError):
            # Validation errors can include snapshot values; never render them.
            if warnings is not None:
                warnings.append(
                    ScanWarning(
                        code="pin_baseline_corrupted",
                        message=(
                            "--canary-check: saved v2 tool snapshots are invalid or incomplete; "
                            "using an in-session baseline only."
                        ),
                        check="canary_check",
                        servers=[server_name],
                    )
                )
            return None
        return {"tools": tools}

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
            self._read_error = None
            return {}
        try:
            # Bounded read (not stat-then-read): the file cannot grow past the
            # cap between a size check and the read.
            with open(self._path, "rb") as handle:
                data = handle.read(_MAX_PIN_FILE_BYTES + 1)
            if len(data) > _MAX_PIN_FILE_BYTES:
                raise yaml.YAMLError(f"pin file exceeds {_MAX_PIN_FILE_BYTES} bytes")
            raw: Any = yaml.load(data.decode("utf-8"), Loader=_NoAliasSafeLoader)  # noqa: S506 - loader subclasses SafeLoader
            self._read_error = None
            return dict(raw) if isinstance(raw, dict) else {}
        except Exception as exc:
            if strict:
                raise PinFileError(str(self._path), f"{type(exc).__name__}: {exc}") from exc
            self._read_error = _describe_parse_error(exc)
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
            "description": redact_data(tool.description),
            "input_schema": redact_data(tool.input_schema),
            "annotations": redact_data(tool.annotations.model_dump() if tool.annotations else None),
            "title": redact_data(tool.title),
            "output_schema": redact_data(tool.output_schema),
            "icons": redact_data(tool.icons),
            "meta": redact_data(tool.meta),
        }

    def _config_snapshot(self, server_config: ServerConfig, *, redact_args: bool = True) -> dict[str, Any]:
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
            "args": redact_data(server_config.args) if redact_args else list(server_config.args),
            "url": redact_text(server_config.url) if server_config.url is not None else None,
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

        previous = redact_data(previous)
        if pin_entry.get("pin_schema", 1) == 1 and previous.get("input_schema") is None:
            if current["input_schema"] == {}:
                current["input_schema"] = None
        details: list[str] = []
        if previous.get("description") != current["description"]:
            details.append("description changed")
        if previous.get("input_schema") != current["input_schema"]:
            details.append("input schema changed")
        if pin_entry.get("pin_schema", 1) == 2:
            for field in ("annotations", "title", "output_schema", "icons", "meta"):
                if previous.get(field) != current[field]:
                    details.append(f"{field} changed")
        if not details:
            details.append("tool metadata changed")
        return details


def surface_hash(value: object) -> str:
    """Hash a session surface using the pin store's canonical SHA256 convention."""
    if isinstance(value, ToolInfo):
        value = canonical_tool_surface(value)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _legacy_tool_hash(tool: ToolInfo, *, empty_input_as_none: bool) -> str:
    # The v1 connector converted served {} schemas to None. Retain that shape
    # for those snapshots while preserving explicitly stored empty schemas.
    schema = None if empty_input_as_none and tool.input_schema == {} else tool.input_schema
    value = {"name": tool.name, "description": tool.description, "inputSchema": schema}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value, legacy=True)).hexdigest()


def surface_field_diff(before: object, after: object, path: str = "") -> list[SurfaceFieldChange]:
    """Diff nested fields without copying raw metadata or result values to reports."""
    if before == after:
        return []
    if isinstance(before, dict) and isinstance(after, dict):
        changes: list[SurfaceFieldChange] = []
        for key in sorted(before.keys() | after.keys()):
            pointer = path + "/" + str(key).replace("~", "~0").replace("/", "~1")
            if key not in before:
                changes.append(SurfaceFieldChange(path=pointer, after_hash=surface_hash(after[key])))
            elif key not in after:
                changes.append(SurfaceFieldChange(path=pointer, before_hash=surface_hash(before[key])))
            else:
                changes.extend(surface_field_diff(before[key], after[key], pointer))
        return changes
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        return [
            change
            for i, (old, new) in enumerate(zip(before, after, strict=True))
            for change in surface_field_diff(old, new, f"{path}/{i}")
        ]
    return [SurfaceFieldChange(path=path, before_hash=surface_hash(before), after_hash=surface_hash(after))]
