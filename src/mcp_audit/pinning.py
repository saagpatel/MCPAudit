"""Tool pinning — SHA256 schema snapshots and drift detection."""

from __future__ import annotations

import hashlib
import logging
import os
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
    PinVerification,
    PinVerificationState,
    ProtocolObservation,
    ScanWarning,
    ServerConfig,
    SurfaceFieldChange,
    ToolInfo,
)
from mcp_audit.redaction import redact_data, redact_url
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
PIN_MANIFEST_SCHEMA = "mcpaudit.pin-manifest.v1"
# Reserved key in a canary pin baseline: legacy v1 tool names whose live
# surface is not covered by the signed v2 rows and is excluded from comparison.
CANARY_UNCOVERED_TOOLS_KEY = "uncovered_legacy_tools"
# Refresh review summary for each field of a v1 tool row: nothing was compared.
UNCOVERED_V1_FIELD_SUMMARY = "not compared; schema v1 row reviewed as new"
_V1_UNCOVERED_FIELDS = ("description", "inputSchema", "annotations", "title", "outputSchema", "icons", "meta")


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
    """Stores SHA256 hashes of MCP tool schemas and detects drift between scans.

    ``record_verification=False`` checks existing rollback history without
    persisting new signing expectations or timestamps during verification.
    Explicit pin mutations remain writes regardless of this option.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        signing_key: Path | None = None,
        unsigned: bool = False,
        trusted_keys_path: Path | None = None,
        record_verification: bool = True,
    ) -> None:
        from mcp_audit.pin_signing import DEFAULT_SIGNING_KEY_PATH, DEFAULT_TRUSTED_KEYS_PATH

        # Resolved per call so callers and tests that select the default
        # location never bind a stale import-time path.
        self._path = path if path is not None else DEFAULT_PIN_PATH
        environment_key = os.environ.get("MCP_AUDIT_PIN_KEY")
        self._explicit_key = signing_key is not None or environment_key is not None
        self._signing_key = signing_key or (
            Path(environment_key) if environment_key else DEFAULT_SIGNING_KEY_PATH
        )
        self._unsigned = unsigned
        self._trusted_keys_path = trusted_keys_path or DEFAULT_TRUSTED_KEYS_PATH
        self._record_verification = record_verification
        self._verification: dict[str, PinVerification | None] = {}
        self._verification_messages: dict[str, str] = {}
        self._rollback_warnings: dict[str, list[tuple[str, str]]] = {}
        self._keys_trusted_cache: bool | None = None
        self._entry_results: dict[str, PinVerification | None] = {}
        self._manifest_cache: tuple[str, dict[str, str]] | None = None
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

    def verification(self, server_name: str) -> PinVerification | None:
        """Verify an entry before exposing any saved baseline to a consumer.

        Entry-level verification, then the document manifest while trusted keys
        exist or the manifest carries a signature. Deleted, renamed, or spliced-in
        signed entries and a missing or invalid manifest are ``tampered_entry``;
        an entry's untrusted-signer diagnosis is retained when no key is usable.
        """
        if server_name in self._verification:
            return self._verification[server_name]
        result = self._entry_verification(server_name)
        violation = self._manifest_violation(server_name)
        if violation is not None and not (
            result is not None
            and result.state == PinVerificationState.UNTRUSTED_SIGNER
            and not self._keys_trusted()
        ):
            result = PinVerification(state=PinVerificationState.TAMPERED_ENTRY)
            self._verification_messages[server_name] = violation
            self._rollback_warnings.pop(server_name, None)
        self._verification[server_name] = result
        return result

    def _entry_verification(self, server_name: str) -> PinVerification | None:
        """Verify one server entry on its own (signature, expectation, keys)."""
        from mcp_audit.pin_signing import (
            PinSigningError,
            has_active_trusted_key,
            is_pinned_at_rollback,
            record_signed_pin,
            signature_required,
            verify_document,
        )

        if server_name in self._entry_results:
            return self._entry_results[server_name]
        servers = self._data.get("servers", {})
        if server_name not in servers:
            # A deleted, renamed, or never-written entry (including an empty,
            # missing, or unparseable pin file) must not erase a signing
            # expectation that lives outside the editable pin file.
            try:
                expected_signed = signature_required(server_name, self._trusted_keys_path)
            except PinSigningError:
                expected_signed = True
            if not expected_signed:
                self._entry_results[server_name] = None
                return None
            result = PinVerification(state=PinVerificationState.TAMPERED_ENTRY)
            self._entry_results[server_name] = result
            self._verification_messages[server_name] = (
                f"Pin for {server_name} fails signature verification; the signed baseline required by "
                "your trusted signing expectations is missing from the pin file, or that expectation "
                "is unavailable. Restore the pin file from backup, or run "
                f"`mcp-audit pin --clear {server_name}` and re-review the server before pinning again."
            )
            return result
        entry = servers[server_name]
        if not isinstance(entry, dict):
            result = PinVerification(state=PinVerificationState.TAMPERED_ENTRY)
            self._entry_results[server_name] = result
            self._verification_messages[server_name] = (
                f"Pin for {server_name} fails signature verification; the saved server entry is invalid. "
                "Restore it from backup or re-review the server and re-pin."
            )
            return result
        missing_required_signature = False
        unsigned_under_trusted_keys = False
        if "signature" not in entry:
            try:
                missing_required_signature = signature_required(server_name, self._trusted_keys_path)
                # Public-key-only CI has no per-server expectation on first use:
                # once any key is trusted, an unsigned v2 entry is a stripped
                # signature, not a legacy pin. Genuine v1 entries only warn
                # (and are withheld from comparison).
                if not missing_required_signature and not _is_legacy_entry(entry):
                    unsigned_under_trusted_keys = has_active_trusted_key(self._trusted_keys_path)
            except PinSigningError:
                missing_required_signature = True
            missing_required_signature |= any(
                field in entry for field in ("signer", "surface_sha256", "canonical_bytes_len")
            )
        if missing_required_signature or unsigned_under_trusted_keys:
            result = PinVerification(state=PinVerificationState.TAMPERED_ENTRY)
            self._verification_messages[server_name] = (
                f"Pin for {server_name} fails signature verification; a required signature is missing "
                "or its trusted signing expectation is unavailable. Restore the baseline from backup."
                if missing_required_signature
                else f"Pin for {server_name} fails signature verification; the v2 baseline is unsigned "
                "but trusted pin keys exist, so its signature was removed or never written. Restore a "
                f"signed baseline, or review `mcp-audit pin --refresh {server_name}` for unsigned migration."
            )
        elif "signature" not in entry and self.legacy_tool_names(server_name):
            result = PinVerification(state=PinVerificationState.SCHEMA_OUTDATED)
        else:
            try:
                verified = verify_document(
                    self._server_document(server_name, entry) if "signature" in entry else {},
                    entry if "signature" in entry else None,
                    self._trusted_keys_path,
                    server_name=server_name,
                )
            except (ValueError, TypeError, KeyError, AttributeError):
                result = PinVerification(state=PinVerificationState.TAMPERED_ENTRY)
                self._verification_messages[server_name] = (
                    f"Pin for {server_name} fails signature verification; "
                    "the baseline was modified after signing. Do not refresh from this file; "
                    "restore it from backup or re-review the server and re-pin."
                )
            else:
                result = PinVerification(state=PinVerificationState(verified.state), kid=verified.kid)
                if verified.message:
                    self._verification_messages[server_name] = verified.message
                if verified.state in {"verified", "retired_key"}:
                    timestamp = entry.get("pinned_at")
                    if isinstance(timestamp, str):
                        # Decide rollback from a read before any write, so a failed
                        # trust-store update can never turn a rollback into a clean verify.
                        warnings = self._rollback_warnings.setdefault(server_name, [])
                        try:
                            if is_pinned_at_rollback(server_name, timestamp, self._trusted_keys_path):
                                warnings.append(
                                    (
                                        "pin_rolled_back",
                                        f"Pin for {server_name} is older than the last verified baseline.",
                                    )
                                )
                        except (PinSigningError, OSError, ValueError):
                            warnings.append(
                                (
                                    "pin_rollback_tracking_unavailable",
                                    (
                                        "Pin rollback state could not be read; "
                                        "rollback detection was not established."
                                    ),
                                )
                            )
                        if self._record_verification:
                            try:
                                record_signed_pin(server_name, timestamp, self._trusted_keys_path)
                            except (PinSigningError, OSError, ValueError):
                                warnings.append(
                                    (
                                        "pin_rollback_tracking_unavailable",
                                        "Pin rollback tracking could not be updated.",
                                    )
                                )
                        if not warnings:
                            del self._rollback_warnings[server_name]
        self._entry_results[server_name] = result
        return result

    def baseline_trusted(self, server_name: str) -> bool:
        """Unsigned and v1 pins are not MCP027 failures; failed signatures are."""
        result = self.verification(server_name)
        return result is None or result.state not in {
            PinVerificationState.UNTRUSTED_SIGNER,
            PinVerificationState.BAD_SIGNATURE,
            PinVerificationState.TAMPERED_ENTRY,
        }

    def _entry_trusted(self, server_name: str) -> bool:
        result = self._entry_verification(server_name)
        return result is None or result.state not in {
            PinVerificationState.UNTRUSTED_SIGNER,
            PinVerificationState.BAD_SIGNATURE,
            PinVerificationState.TAMPERED_ENTRY,
        }

    def _manifest(self) -> tuple[str, dict[str, str]]:
        """Return ("absent" | "invalid" | "valid", signed server digests)."""
        from mcp_audit.pin_signing import verify_document

        if self._manifest_cache is None:
            raw = self._data.get("manifest")
            if raw is None:
                self._manifest_cache = ("absent", {})
            else:
                state = "invalid"
                listed: dict[str, str] = {}
                if (
                    isinstance(raw, dict)
                    and raw.get("schema") == PIN_MANIFEST_SCHEMA
                    and isinstance(raw.get("servers"), dict)
                    and all(isinstance(k, str) and isinstance(v, str) for k, v in raw["servers"].items())
                    and ("sequence" not in raw or (type(raw["sequence"]) is int and raw["sequence"] > 0))
                ):
                    document = {"schema": PIN_MANIFEST_SCHEMA, "servers": raw["servers"]}
                    if "sequence" in raw:
                        document["sequence"] = raw["sequence"]
                    try:
                        verified = verify_document(
                            document, raw, self._trusted_keys_path, server_name="<pin manifest>"
                        )
                    except (ValueError, TypeError, KeyError, AttributeError):
                        verified = None
                    if verified is not None and verified.state in {"verified", "retired_key"}:
                        state, listed = "valid", dict(raw["servers"])
                self._manifest_cache = (state, listed)
        return self._manifest_cache

    def verified_manifest_sequence(self) -> int | None:
        """Return the authenticated sequence, never an unverified claimed value.

        Pre-sequence manifests remain verifiable but cannot satisfy a CI minimum.
        """
        if self._manifest()[0] != "valid":
            return None
        raw = self._data.get("manifest")
        sequence = raw.get("sequence") if isinstance(raw, dict) else None
        return sequence if type(sequence) is int else None

    def _manifest_violation(self, server_name: str) -> str | None:
        """Why the signed manifest makes this server untrusted, or None."""
        raw = self._data.get("manifest")
        signed_manifest = isinstance(raw, dict) and "signature" in raw
        if not self._keys_trusted() and not signed_manifest:
            return None  # Unsigned workflows: the manifest is optional.
        state, listed = self._manifest()
        entry = self._data.get("servers", {}).get(server_name)
        legacy = isinstance(entry, dict) and "signature" not in entry and _is_legacy_entry(entry)
        if state != "valid":
            if legacy and (not signed_manifest or self._keys_trusted()):
                return None  # D8: genuine v1 warns (and is withheld), never MCP027.
            if state == "absent":
                return (
                    f"Pin for {server_name} fails signature verification; trusted pin keys exist but the "
                    "pin file has no signed manifest, so deleted or renamed signed entries cannot be "
                    "detected. Restore the pin file from backup, or sign a manifest with "
                    "`mcp-audit pin rotate-key --resign` after review."
                )
            return (
                f"Pin for {server_name} fails signature verification; the pin file's signed manifest "
                "is invalid or signed by an untrusted key. Restore the pin file from backup."
            )
        digest = listed.get(server_name)
        if digest is not None:
            if not isinstance(entry, dict):
                return (
                    f"Pin for {server_name} fails signature verification; the signed manifest lists it "
                    "but its entry is missing (deleted or renamed). Restore the pin file from backup, or "
                    f"run `mcp-audit pin --clear {server_name}` and re-review before pinning again."
                )
            if entry.get("surface_sha256") != digest:
                return (
                    f"Pin for {server_name} fails signature verification; its entry does not match the "
                    "signed manifest. Restore the pin file from backup."
                )
        elif isinstance(entry, dict) and "signature" in entry:
            return (
                f"Pin for {server_name} fails signature verification; the entry is signed but not listed "
                f"in the signed manifest (spliced in). Run `mcp-audit pin --clear {server_name}` and "
                "re-review before pinning again."
            )
        return None

    def _write_trusted(self, server_name: str) -> bool:
        """Writers check entries individually until a manifest exists, so first use and
        migration can create one; afterwards the manifest-aware verdict applies."""
        if self._keys_trusted() and self._manifest()[0] == "absent":
            return self._entry_trusted(server_name)
        return self.baseline_trusted(server_name)

    def _check_manifest_writable(self, *, removing: str | None = None) -> None:
        from mcp_audit.pin_signing import PinSigningError

        if not self._keys_trusted() and "manifest" not in self._data:
            return
        state, listed = self._manifest()
        if "manifest" in self._data and state != "valid":
            raise PinSigningError(
                "Cannot write through a pin file whose signed manifest fails verification; "
                "restore it from backup."
            )
        missing = sorted(set(listed) - set(self.pinned_servers()) - {removing})
        if missing:
            raise PinSigningError(
                "Signed pin entries listed in the manifest are missing: "
                f"{', '.join(missing)}. Restore them from backup, or run `mcp-audit pin --clear NAME` "
                "for each after review, before writing."
            )

    def _sign_manifest(self) -> None:
        """Sign the set of signed entries (with their digests) into the pin file."""
        from mcp_audit.pin_signing import PinSigningError, sign_document

        servers: dict[str, Any] = self._data.get("servers", {})
        signed = {
            name: entry["surface_sha256"]
            for name, entry in sorted(servers.items())
            if isinstance(entry, dict)
            and "signature" in entry
            and isinstance(entry.get("surface_sha256"), str)
        }
        if "manifest" in self._data and self._manifest()[0] != "valid":
            raise PinSigningError(
                "Cannot advance an unverified pin manifest sequence; restore it from backup."
            )
        sequence = self.verified_manifest_sequence() or 0
        document = {"schema": PIN_MANIFEST_SCHEMA, "servers": signed, "sequence": sequence + 1}
        self._data["manifest"] = {**document, **sign_document(document, self._signing_key)}
        self._manifest_cache = None

    def _reset_verification(self) -> None:
        self._verification.clear()
        self._verification_messages.clear()
        self._rollback_warnings.clear()
        self._entry_results.clear()
        self._manifest_cache = None

    def baseline_usable(self, server_name: str) -> bool:
        """Whether saved data may serve as a comparison baseline.

        Stricter than :meth:`baseline_trusted`: a genuine legacy v1 entry still
        only warns (never MCP027), but it is never compared, whether or not
        trusted keys exist. An unsigned mixed entry (``schema_outdated`` too)
        stays usable for its v2 rows.
        """
        if not self.baseline_trusted(server_name):
            return False
        return not self.v1_baseline(server_name)

    def legacy_entry(self, server_name: str) -> bool:
        """A genuine v1 entry (v1 tool pins, no v2 marker): 3.0 never compares it.

        Only an explicit ``pin --refresh SERVER --apply`` replaces it; reads never
        rewrite the pin file.
        """
        entry: object = self._data.get("servers", {}).get(server_name)
        return isinstance(entry, dict) and _is_legacy_entry(entry)

    def v1_baseline(self, server_name: str) -> bool:
        """An entry with v1 tool rows and no v2 rows: nothing comparable is saved.

        Covers a genuine v1 entry and one that carries an entry-level v2 marker
        (``pin_schema: 2`` or ``protocol``) over v1-only tool rows; neither may
        serve as a baseline or satisfy ``require.pins``.
        """
        if self.legacy_entry(server_name):
            return True
        legacy = self.legacy_tool_names(server_name)
        return bool(legacy) and not self._v2_tool_names(server_name)

    def unsigned_v2_migration_allowed(self, server_name: str) -> bool:
        """Allow explicit refresh review of v2 pins that were never required to be signed.

        This is not a scan trust verdict. Signing remnants, a signing expectation,
        or a manifest binding the entry keep the ordinary integrity gate closed.
        """
        from mcp_audit.pin_signing import signature_required

        entry: object = self._data.get("servers", {}).get(server_name)
        if not self._keys_trusted() or not isinstance(entry, dict) or entry.get("pin_schema") != 2:
            return False
        signing_fields = {"signature", "signer", "surface_sha256", "canonical_bytes_len"}
        if signing_fields.intersection(entry) or signature_required(server_name, self._trusted_keys_path):
            return False
        tools = entry.get("tools")
        if not isinstance(tools, dict) or not all(
            isinstance(name, str)
            and isinstance(row, dict)
            and row.get("pin_schema") == 2
            and row.get("canonical_form") == TOOL_SURFACE_SCHEMA
            and isinstance(row.get("hash"), str)
            and isinstance(row.get("snapshot"), dict)
            for name, row in tools.items()
        ):
            return False
        if not _unsigned_v2_shapes_valid(entry):
            return False
        state, listed = self._manifest()
        if state == "invalid" or server_name in listed:
            return False
        if state == "absent" and any(
            isinstance(saved, dict) and signing_fields.intersection(saved)
            for saved in self._data.get("servers", {}).values()
        ):
            return False
        return True

    def _review_gate(self, server_name: str, review_unsigned_v2: bool = False) -> bool:
        if review_unsigned_v2 and self.unsigned_v2_migration_allowed(server_name):
            return True
        return self.baseline_usable(server_name)

    def _keys_trusted(self) -> bool:
        from mcp_audit.pin_signing import PinSigningError, has_active_trusted_key

        if self._keys_trusted_cache is None:
            try:
                self._keys_trusted_cache = has_active_trusted_key(self._trusted_keys_path)
            except PinSigningError:
                self._keys_trusted_cache = True
        return self._keys_trusted_cache

    def verification_message(self, server_name: str) -> str:
        self.verification(server_name)
        return self._verification_messages.get(server_name, "")

    def verification_warnings(self, server_name: str) -> list[ScanWarning]:
        result = self.verification(server_name)
        warnings: list[ScanWarning] = []
        if result is not None and result.state in {
            PinVerificationState.UNSIGNED,
            PinVerificationState.RETIRED_KEY,
        }:
            warnings.append(
                ScanWarning(
                    code="pin_unsigned"
                    if result.state == PinVerificationState.UNSIGNED
                    else "pin_signed_by_retired_key",
                    message=self.verification_message(server_name),
                    check="pin_check",
                    servers=[server_name],
                )
            )
        for code, message in self._rollback_warnings.get(server_name, []):
            warnings.append(ScanWarning(code=code, message=message, check="pin_check", servers=[server_name]))
        return warnings

    def signing_status(self, server_name: str) -> dict[str, object]:
        from mcp_audit.pin_signing import PinSigningError, key_id, load_trusted_keys

        entry = self._data.get("servers", {}).get(server_name, {})
        signature = entry.get("signature", {})
        signer = entry.get("signer", {})
        trusted_public_key = None
        verified = self.verification(server_name)
        if verified is not None and verified.state in {
            PinVerificationState.VERIFIED,
            PinVerificationState.RETIRED_KEY,
        }:
            try:
                record = load_trusted_keys(self._trusted_keys_path).get(verified.kid or "", {})
                public_key = record.get("public_key")
                if isinstance(public_key, str) and key_id(bytes.fromhex(public_key)) == verified.kid:
                    trusted_public_key = public_key
            except (PinSigningError, ValueError):
                trusted_public_key = None
        return {
            "schema": entry.get("pin_schema", 1 if self.legacy_tool_names(server_name) else 2),
            "signed": bool(signature),
            "kid": signature.get("kid") if isinstance(signature, dict) else None,
            "public_key": signer.get("public_key") if isinstance(signer, dict) else None,
            "trusted_public_key": trusted_public_key,
            # Additive: verification evidence, unlike the entry-derived fields above.
            "verification": str(verified.state) if verified is not None else None,
            "baseline_usable": self.baseline_usable(server_name),
        }

    def _server_document(self, server_name: str, entry: dict[str, Any]) -> dict[str, object]:
        """Cover the normalized surface and all stored comparison metadata."""
        config = entry.get("config_snapshot", {})
        config_without_artifacts = {key: value for key, value in config.items() if key != "artifact_hashes"}
        tools = [
            canonical_tool_surface(ToolInfo(name=name, **snapshot["snapshot"]))
            for name, snapshot in sorted(entry.get("tools", {}).items())
        ]
        return {
            "schema": TOOL_SURFACE_SCHEMA,
            "server": {
                "name": server_name,
                "config_sha256": hashlib.sha256(canonical_json_bytes(config_without_artifacts)).hexdigest(),
            },
            "protocol": entry.get("protocol", {"negotiated_version": None, "era": "unknown"}),
            "pinned_at": entry.get("pinned_at"),
            "tools": tools,
            # Hashes and redacted snapshots both participate: redaction must not
            # make an edited stored hash or launch-artifact baseline trustworthy.
            "pin_metadata": {
                key: value
                for key, value in entry.items()
                if key not in {"signature", "signer", "surface_sha256", "canonical_bytes_len"}
            },
        }

    def _sign_entry(self, server_name: str, entry: dict[str, Any]) -> bool:
        """Sign ``entry`` in memory; return whether it now carries a signature.

        The trust-store expectation is deliberately NOT written here. Callers
        record it via :meth:`_record_signed` only after the pin file write
        succeeds, so a failed write leaves both the old baseline and the old
        expectation intact.
        """
        from mcp_audit.pin_signing import sign_document, signature_required

        was_signed = "signature" in entry
        for key in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
            entry.pop(key, None)
        if self._unsigned:
            return False
        if (
            was_signed
            or self._explicit_key
            or self._signing_key.exists()
            or signature_required(server_name, self._trusted_keys_path)
        ):
            entry.update(sign_document(self._server_document(server_name, entry), self._signing_key))
            return True
        return False

    def _record_signed(self, server_names: list[str]) -> None:
        """After a successful signed write, persist the signing expectation and
        advance the rollback high-water mark to each entry's ``pinned_at``."""
        from mcp_audit.pin_signing import record_signed_pin

        servers: dict[str, Any] = self._data.get("servers", {})
        for server_name in server_names:
            entry = servers.get(server_name, {})
            pinned_at = entry.get("pinned_at") if isinstance(entry, dict) else None
            record_signed_pin(server_name, pinned_at, self._trusted_keys_path)

    def rotate_key(self, grace_days: int = 30) -> str:
        """Reverify all signed entries before key replacement and re-signing."""
        from mcp_audit.pin_signing import PinSigningError, rotate_key

        if self._unsigned:
            raise PinSigningError("Key rotation requires signing; omit --unsigned.")
        with _file_lock(self._path):
            self._data = self._load(strict=True)
            self._check_manifest_writable()
            for server in self.pinned_servers():
                if not self._write_trusted(server):
                    raise PinSigningError(
                        "Cannot rotate keys through an untrusted pin baseline; restore or re-review it first."
                    )
                if _resigned_by_rotation(self._data["servers"][server]):
                    # Preflight unsigned entries too, before changing key material.
                    try:
                        canonical_json_bytes(self._server_document(server, self._data["servers"][server]))
                    except (ValueError, TypeError, KeyError, AttributeError) as exc:
                        raise PinSigningError(
                            "Cannot rotate keys through an invalid v2 pin baseline."
                        ) from exc
            generated = rotate_key(
                self._signing_key.parent, self._trusted_keys_path, self._signing_key, grace_days=grace_days
            )
            self._signing_key = generated.private_key_path
            signed: list[str] = []
            for server, entry in self._data.get("servers", {}).items():
                # Signed and mixed v1/v2 entries must move to the new key before the
                # old one retires; a genuine v1 entry is never rewritten here.
                if _resigned_by_rotation(entry) and self._sign_entry(server, entry):
                    signed.append(server)
            self._sign_manifest()
            self._write()
            self._record_signed(signed)
            self._reset_verification()
            return generated.public_key

    def resign(self) -> str:
        """Re-sign reviewed v2 entries with the existing active key."""
        from mcp_audit.pin_signing import PinSigningError, sign_document

        if self._unsigned:
            raise PinSigningError("Re-signing requires signing; omit --unsigned.")
        with _file_lock(self._path):
            self._data = self._load(strict=True)
            self._check_manifest_writable()
            for server in self.pinned_servers():
                if not self._write_trusted(server):
                    raise PinSigningError(
                        "Cannot re-sign an untrusted pin baseline; restore or re-review it first."
                    )
            # Validate the active key even when only v1 entries exist.
            metadata = sign_document({}, self._signing_key)
            signer = metadata["signer"]
            assert isinstance(signer, dict) and isinstance(signer["public_key"], str)
            signed: list[str] = []
            for server, entry in self._data.get("servers", {}).items():
                if _resigned_by_rotation(entry) and self._sign_entry(server, entry):
                    signed.append(server)
            self._sign_manifest()
            self._write()
            self._record_signed(signed)
            self._reset_verification()
            return signer["public_key"]

    def compute_hash(self, tool: ToolInfo) -> str:
        """Return 'sha256:<hex>' hash of the tool's canonical schema."""
        return surface_hash(canonical_tool_surface(tool))

    def legacy_tool_names(self, server_name: str) -> set[str]:
        """Tools whose pins predate annotation coverage, including mixed files."""
        return self._tool_names_with_schema(server_name, 1)

    def _v2_tool_names(self, server_name: str) -> set[str]:
        return self._tool_names_with_schema(server_name, 2)

    def _tool_names_with_schema(self, server_name: str, schema: int) -> set[str]:
        server = self._data.get("servers", {}).get(server_name, {})
        if not isinstance(server, dict):
            return set()
        entries = server.get("tools", {})
        if not isinstance(entries, dict):
            return set()
        return {
            name
            for name, entry in entries.items()
            if isinstance(entry, dict) and entry.get("pin_schema", 1) == schema
        }

    def schema_warnings(self, server_name: str) -> list[ScanWarning]:
        """Name the uncovered v1 tool rows without changing or re-hashing pins."""
        legacy = self.legacy_tool_names(server_name)
        if not legacy or not self.baseline_trusted(server_name):
            # A rejected entry gets only tampered/withheld guidance, never refresh advice.
            return []
        scope = (
            "is a schema v1 pin baseline, which is not compared"
            if self.v1_baseline(server_name)
            else "has schema v1 tool pins, which are not compared and count as uncovered"
        )
        return [
            ScanWarning(
                code="pin_schema_outdated",
                message=(
                    f"{server_name} {scope}: {', '.join(sorted(legacy))}. Run "
                    f"`mcp-audit pin --refresh {server_name}` to review the current tool surface, "
                    f"then `mcp-audit pin --refresh {server_name} --apply`."
                ),
                check="pin_check",
                servers=[server_name],
            )
        ]

    def uncovered_field_rows(self, server_name: str, tools: list[ToolInfo]) -> list[dict[str, str]]:
        """Refresh review rows for every field of a tool whose saved row is v1.

        No field of a v1 row is compared (3.0 does not hash v1), so the whole
        current surface, description and inputSchema included, is reviewed as new.
        """
        legacy = self.legacy_tool_names(server_name)
        return [
            {"tool_name": tool.name, "field": field, "summary": UNCOVERED_V1_FIELD_SUMMARY}
            for tool in tools
            if tool.name in legacy
            for field in _V1_UNCOVERED_FIELDS
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
        protocol: ProtocolObservation | None = None,
        migrate_unsigned_v2: bool = False,
    ) -> None:
        """Upsert pin entries for all tools on a server. Writes atomically.

        When ``server_config`` is provided, its launch fields (command, args, url,
        transport, and env/header KEY NAMES — never values) are snapshotted so the
        provenance detector can compare them on later scans. Arguments are
        credential-redacted unless ``redact_args=False``; URLs are always redacted.
        """
        if len({tool.name for tool in tools}) != len(tools):
            raise ValueError("Cannot pin duplicate tool names.")
        from mcp_audit.pin_signing import PinSigningError, signature_required, verify_document

        now = datetime.now(UTC).isoformat()
        with _file_lock(self._path):
            # Re-read under the lock: another process may have written pins
            # since this store loaded, and mutating a stale copy would erase them.
            self._data = self._load(strict=True)
            self._check_manifest_writable()
            if migrate_unsigned_v2 and not self.unsigned_v2_migration_allowed(server_name):
                raise PinSigningError("Unsigned v2 migration is no longer eligible; review the pin again.")
            if not migrate_unsigned_v2 and not self._write_trusted(server_name):
                raise PinSigningError(
                    "Cannot pin through an untrusted pin baseline; restore it or explicitly clear "
                    "the server's pin and re-review before pinning again."
                )
            if "servers" not in self._data:
                self._data["servers"] = {}
            if not self.baseline_usable(server_name):
                # Never carry a withheld (v1 or unauthenticated) entry into the new baseline.
                self._data["servers"][server_name] = {"tools": {}}
            server_entry: dict[str, Any] = self._data["servers"].setdefault(server_name, {"tools": {}})
            tool_entries: dict[str, Any] = server_entry.setdefault("tools", {})
            for name in self.legacy_tool_names(server_name):
                # Retained v1 rows of a mixed entry are never compared; a reviewed
                # write drops them rather than carrying uncovered rows forward.
                del tool_entries[name]
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
            server_entry["pin_schema"] = 2
            server_entry["pinned_at"] = now
            server_entry["protocol"] = (
                {"negotiated_version": protocol.negotiated_version, "era": protocol.era}
                if protocol
                else {"negotiated_version": None, "era": "unknown"}
            )
            signed = self._sign_entry(server_name, server_entry)
            if migrate_unsigned_v2 and (
                not signed
                or verify_document(
                    self._server_document(server_name, server_entry),
                    server_entry,
                    self._trusted_keys_path,
                    server_name=server_name,
                ).state
                != "verified"
            ):
                raise PinSigningError(
                    "Unsigned v2 migration requires a trusted signing key. Run `mcp-audit pin keygen` "
                    "or select a trusted key with --signing-key; omit --unsigned, then refresh --apply."
                )
            if not signed:
                from mcp_audit.pin_signing import PinSigningError, has_active_trusted_key

                if has_active_trusted_key(self._trusted_keys_path) or signature_required(
                    server_name, self._trusted_keys_path
                ):
                    # The entry would read back as tampered (MCP027); refuse it.
                    raise PinSigningError(
                        "Trusted pin keys exist, so unsigned v2 pins fail verification. Sign with "
                        "your key (`--signing-key` or `mcp-audit pin keygen`), or remove the trusted "
                        "keys before writing unsigned pins."
                    )
            if signed:
                self._sign_manifest()
            self._reset_verification()
            self._data["pinned_at"] = now
            self._data["pin_schema"] = 2
            self._write()
            if signed:
                self._record_signed([server_name])

    def new_pin_review(self, server_name: str, tools: list[ToolInfo]) -> list[DriftFinding]:
        """Every current tool as ``NEW``: the review shown before a first pin.

        ``pin --refresh`` uses this for a genuine v1 entry, whose baseline is
        never compared, so the operator reviews the full current surface.
        """
        return [self._new_finding(server_name, tool) for tool in tools]

    def check_drift(
        self,
        server_name: str,
        tools: list[ToolInfo],
        *,
        review_unsigned_v2: bool = False,
    ) -> list[DriftFinding]:
        """Compare current tool hashes against stored pins. Returns drift findings.

        A withheld baseline (failed verification or a genuine v1 entry) yields
        no findings. In a mixed entry the v1 rows are uncovered: their tools are
        excluded from NEW, CHANGED and REMOVED, and ``pin_schema_outdated``
        names them. ``review_unsigned_v2`` permits eligible unsigned v2 migration
        review only; it never allows known signed-integrity failures.
        """
        if not self._review_gate(server_name, review_unsigned_v2):
            return []
        servers: dict[str, Any] = self._data.get("servers", {})
        server_entry: dict[str, Any] = servers.get(server_name, {})
        pinned_tools: dict[str, Any] = server_entry.get("tools", {})
        legacy = self.legacy_tool_names(server_name)

        findings: list[DriftFinding] = []
        current_names = {t.name for t in tools} - legacy
        pinned_names = set(pinned_tools.keys()) - legacy

        for tool in tools:
            if tool.name in legacy:
                continue
            if tool.name not in pinned_names:
                # NEW: in current scan but not pinned
                findings.append(self._new_finding(server_name, tool))
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
        """Remove all pins for a server and forget its signing expectation.

        An explicit clear is the authorized recovery path for a signed baseline
        that was deleted or damaged. The separate expectation is dropped only
        after the pin file write succeeds (or when no entry remains to write),
        so a failed write never leaves an entry without its expectation.
        """
        from mcp_audit.pin_signing import PinSigningError, forget_server

        with _file_lock(self._path):
            self._data = self._load(strict=True)
            self._check_manifest_writable(removing=server_name)
            servers: dict[str, Any] = self._data.get("servers", {})
            removed = servers.pop(server_name, None)
            listed = server_name in self._manifest()[1]
            was_signed = isinstance(removed, dict) and "signature" in removed
            if "manifest" in self._data and (was_signed or listed):
                try:
                    self._sign_manifest()
                except PinSigningError as exc:
                    raise PinSigningError(
                        "Clearing a signed pin re-signs the pin manifest; a signing key is required."
                    ) from exc
            if removed is not None or listed:
                self._write()
            self._reset_verification()
            forget_server(server_name, self._trusted_keys_path)

    def pinned_servers(self) -> list[str]:
        """Return list of server names that have pins."""
        return list(self._data.get("servers", {}).keys())

    def tool_count(self, server_name: str) -> int:
        """Return the number of comparable (v2) pinned tools for a server."""
        if not self.baseline_usable(server_name):
            # A withheld baseline (failed verification, v1) must not satisfy require.pins.
            return 0
        return len(self._v2_tool_names(server_name))

    def baseline_tools(self, server_name: str, *, review_unsigned_v2: bool = False) -> list[ToolInfo]:
        """Reconstruct pinned tools as ``ToolInfo`` from stored snapshots.

        Restores all covered fields, including annotations. Uncovered v1 rows of
        a mixed entry retain absent fields as None. Empty list if the server is
        not pinned or its baseline is withheld.
        """
        if not self._review_gate(server_name, review_unsigned_v2):
            return []
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
        """Use the v2 pin rows; warn and fall back when their snapshots are corrupt.

        A genuine v1 entry is withheld. A mixed entry (trusted v2 rows plus
        retained v1 rows) still compares its v2 rows. Legacy tool names are
        listed under :data:`CANARY_UNCOVERED_TOOLS_KEY` so the first-listing
        comparison excludes them instead of reporting them as new;
        ``pin_schema_outdated`` already names them as uncovered.
        """
        if not self.baseline_usable(server_name):
            return None
        if server_name not in self.pinned_servers():
            return None
        legacy = self.legacy_tool_names(server_name)
        entries = {
            name: entry
            for name, entry in self._data["servers"][server_name].get("tools", {}).items()
            if name not in legacy
        }
        if not entries or any(entry.get("pin_schema") != 2 for entry in entries.values()):
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
        baseline: dict[str, dict[str, object]] = {"tools": tools}
        if legacy:
            baseline[CANARY_UNCOVERED_TOOLS_KEY] = {name: True for name in sorted(legacy)}
        return baseline

    def baseline_config(self, server_name: str, *, review_unsigned_v2: bool = False) -> dict[str, Any] | None:
        """Return the pinned launch-config snapshot for a server, or None.

        None when the server is unpinned OR was pinned before config snapshots
        existed (older baselines) — callers must treat None as "no provenance
        comparison possible" and skip silently.
        """
        if not self._review_gate(server_name, review_unsigned_v2):
            return None
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
        self._reset_verification()
        self._keys_trusted_cache = None
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
            if isinstance(raw, dict) and "servers" in raw and not isinstance(raw["servers"], dict):
                raise yaml.YAMLError("pin servers must be a mapping")
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
                self._read_error,  # sanitized: str(exc) can echo a source line containing a secret
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
            "url": redact_url(server_config.url) if server_config.url is not None else None,
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

    def _new_finding(self, server_name: str, tool: ToolInfo) -> DriftFinding:
        return DriftFinding(
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

    def _changed_tool_details(self, pin_entry: dict[str, Any], tool: ToolInfo) -> list[str]:
        previous = pin_entry.get("snapshot")
        current = self._tool_snapshot(tool)

        if not isinstance(previous, dict):
            return ["pin hash changed; previous schema snapshot unavailable"]

        previous = redact_data(previous)
        details: list[str] = []
        if previous.get("description") != current["description"]:
            details.append("description changed")
        if previous.get("input_schema") != current["input_schema"]:
            details.append("input schema changed")
        for field in ("annotations", "title", "output_schema", "icons", "meta"):
            if previous.get(field) != current[field]:
                details.append(f"{field} changed")
        if not details:
            details.append("tool metadata changed")
        return details


def _resigned_by_rotation(entry: object) -> bool:
    """Rotation/re-signing covers signed and v2 (including mixed) entries.

    A genuine v1 entry is never hashed or rewritten by 3.0 except through an
    explicit refresh, so it is left as-is (and stays withheld).
    """
    return isinstance(entry, dict) and ("signature" in entry or not _is_legacy_entry(entry))


def _is_legacy_entry(entry: dict[str, Any]) -> bool:
    """A genuine v1 entry: v1 tool pins and no marker only v2 writers produce."""
    tools = entry.get("tools", {})
    if not isinstance(tools, dict) or entry.get("pin_schema") == 2 or "protocol" in entry:
        return False
    tool_entries = [tool for tool in tools.values() if isinstance(tool, dict)]
    return bool(tool_entries) and all(
        tool.get("pin_schema", 1) == 1 and "canonical_form" not in tool for tool in tool_entries
    )


def surface_hash(value: object) -> str:
    """Hash a session surface using the pin store's canonical SHA256 convention."""
    if isinstance(value, ToolInfo):
        value = canonical_tool_surface(value)
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


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


_SNAPSHOT_STR_LISTS = ("args", "env_keys", "headers_keys")


def _unsigned_v2_shapes_valid(entry: dict[str, Any]) -> bool:
    """Unauthenticated rows must rebuild cleanly before a guided migration may use them."""
    from pydantic import ValidationError

    for name, row in entry["tools"].items():
        snapshot: dict[str, Any] = row["snapshot"]
        try:
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
        except (ValidationError, TypeError, ValueError):
            return False
    config: object = entry.get("config_snapshot")
    if config is None:
        return True
    if not isinstance(config, dict):
        return False
    if not all(isinstance(config.get(key), (str, type(None))) for key in ("command", "url")):
        return False
    if not isinstance(config.get("transport"), str):
        return False
    if not all(
        isinstance(config.get(key), list) and all(isinstance(v, str) for v in config[key])
        for key in _SNAPSHOT_STR_LISTS
    ):
        return False
    hashes: object = config.get("artifact_hashes", {})
    return isinstance(hashes, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in hashes.items()
    )
