"""Ed25519 signing and local trust storage for v2 tool-surface pins."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from mcp_audit.canonical import canonical_json_bytes

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: trust-store updates are best-effort unlocked
    fcntl = None  # type: ignore[assignment]

VerificationState = Literal[
    "verified",
    "unsigned",
    "untrusted_signer",
    "bad_signature",
    "tampered_entry",
    "retired_key",
]

DEFAULT_KEY_DIR = Path.home() / ".mcp-audit" / "keys"
DEFAULT_TRUSTED_KEYS_PATH = Path.home() / ".mcp-audit" / "trusted-pin-keys.json"
DEFAULT_SIGNING_KEY_PATH = DEFAULT_KEY_DIR / "pin-signing.key"
_KEY_MODE_MESSAGE = "Signing key {path} must be mode 0600 and owned by you."
_MAX_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_TRUSTED_KEYS_BYTES = 10 * 1024 * 1024
_KID_PATTERN = re.compile(r"[0-9a-f]{16}\Z")


class PinSigningError(ValueError):
    """Raised when pin signing material cannot be safely read or written."""


@dataclass(frozen=True)
class GeneratedKey:
    """Metadata returned after creating a signing key pair."""

    kid: str
    private_key_path: Path
    public_key_path: Path
    public_key: str


@dataclass(frozen=True)
class VerificationResult:
    """Signature status and the signer id, when one was present."""

    state: VerificationState
    kid: str | None
    message: str | None = None


def key_id(public_key: bytes) -> str:
    """Return the stable identifier for raw Ed25519 public-key bytes."""
    if len(public_key) != 32:
        raise ValueError("Ed25519 public keys must contain exactly 32 bytes")
    return hashlib.sha256(public_key).hexdigest()[:16]


def generate_keypair(
    key_dir: Path = DEFAULT_KEY_DIR,
    trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH,
) -> GeneratedKey:
    """Create a PKCS8 private key and raw-hex public key with restrictive modes."""
    generated = _create_keypair(key_dir)
    try:
        trust_key(generated.public_key, trusted_keys_path)
    except PinSigningError:
        generated.private_key_path.unlink(missing_ok=True)
        generated.public_key_path.unlink(missing_ok=True)
        raise
    return generated


def load_private_key(path: Path = DEFAULT_SIGNING_KEY_PATH) -> Ed25519PrivateKey:
    """Read a private key only when it is a user-owned, mode-0600 regular file."""
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PinSigningError(_KEY_MODE_MESSAGE.format(path=path)) from exc
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        current_uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != current_uid
        ):
            raise PinSigningError(_KEY_MODE_MESSAGE.format(path=path))
        private_bytes = handle.read(_MAX_PRIVATE_KEY_BYTES + 1)
    if len(private_bytes) > _MAX_PRIVATE_KEY_BYTES:
        raise PinSigningError(f"Signing key {path} could not be read.")
    try:
        key = serialization.load_pem_private_key(private_bytes, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise PinSigningError(f"Signing key {path} could not be read.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise PinSigningError(f"Signing key {path} is not an Ed25519 private key.")
    return key


def sign_document(
    document: Mapping[str, object], private_key_path: Path = DEFAULT_SIGNING_KEY_PATH
) -> dict[str, object]:
    """Sign a canonical server document and return its pin entry metadata."""
    try:
        payload = canonical_json_bytes(dict(document))
    except (TypeError, ValueError) as exc:
        raise PinSigningError("Server document cannot be serialized as canonical JSON.") from exc
    private_key = load_private_key(private_key_path)
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = key_id(public_bytes)
    return {
        "surface_sha256": hashlib.sha256(payload).hexdigest(),
        "canonical_bytes_len": len(payload),
        "signature": {
            "alg": "ed25519",
            "kid": kid,
            "sig": base64.b64encode(private_key.sign(payload)).decode("ascii"),
        },
        "signer": {"kid": kid, "public_key": public_bytes.hex()},
    }


def verify_document(
    document: Mapping[str, object],
    signature_record: Mapping[str, object] | None,
    trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH,
    *,
    server_name: str = "<server>",
    grace_days: int = 30,
    now: datetime | None = None,
) -> VerificationResult:
    """Verify a canonical document using only the separate trusted-key store."""
    if grace_days < 0:
        raise ValueError("grace_days must be non-negative")
    if now is not None and now.tzinfo is None:
        raise ValueError("now must include a timezone")
    if signature_record is None:
        return VerificationResult(
            "unsigned",
            None,
            (
                f"Pin for {server_name} is unsigned. Run `mcp-audit pin keygen` then "
                f"`pin --refresh {server_name} --apply` to sign it."
            ),
        )

    signature = signature_record.get("signature")
    if not isinstance(signature, Mapping):
        return VerificationResult("tampered_entry", None, _integrity_message(server_name))
    kid_value = signature.get("kid")
    if not isinstance(kid_value, str) or _KID_PATTERN.fullmatch(kid_value) is None:
        return VerificationResult("tampered_entry", None, _integrity_message(server_name))
    kid = kid_value
    try:
        payload = canonical_json_bytes(dict(document))
    except (TypeError, ValueError):
        return VerificationResult("tampered_entry", kid, _integrity_message(server_name))
    digest = hashlib.sha256(payload).hexdigest()
    if signature_record.get("surface_sha256") != digest or signature_record.get("canonical_bytes_len") != len(
        payload
    ):
        return VerificationResult("tampered_entry", kid, _integrity_message(server_name))
    if signature.get("alg") != "ed25519" or kid is None:
        return VerificationResult("tampered_entry", kid, _integrity_message(server_name))

    try:
        keys = load_trusted_keys(trusted_keys_path)
    except PinSigningError:
        return VerificationResult(
            "untrusted_signer",
            kid,
            f"Pin for {server_name} cannot be verified because trusted keys are unavailable.",
        )
    record = keys.get(kid)
    if record is None:
        message = (
            f"Pin for {server_name} is signed by key {kid} which is not in your trusted keys. "
            "If you rotated keys, run `pin trust-key --add`. Otherwise treat the pin file as replaced."
        )
        return VerificationResult("untrusted_signer", kid, message)
    try:
        public_key_hex = record.get("public_key")
        if not isinstance(public_key_hex, str):
            return VerificationResult("untrusted_signer", kid)
        public_bytes = bytes.fromhex(public_key_hex)
        if key_id(public_bytes) != kid:
            return VerificationResult(
                "untrusted_signer", kid, f"Pin for {server_name} is signed by an invalid trusted key {kid}."
            )
        raw_signature = base64.b64decode(str(signature.get("sig", "")), validate=True)
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(raw_signature, payload)
    except (ValueError, InvalidSignature, KeyError, TypeError):
        return VerificationResult("bad_signature", kid, _integrity_message(server_name))

    retired_at = record.get("retired_at")
    if isinstance(retired_at, str):
        try:
            retired_time = _parse_timestamp(retired_at)
        except ValueError:
            return VerificationResult(
                "untrusted_signer", kid, f"Pin for {server_name} is signed by an invalid retired key {kid}."
            )
        current = now or datetime.now(UTC)
        retired_grace_days = record.get("grace_days")
        if not isinstance(retired_grace_days, int) or isinstance(retired_grace_days, bool):
            retired_grace_days = grace_days
        if current > retired_time + timedelta(days=retired_grace_days):
            message = (
                f"Pin for {server_name} is signed by key {kid} which is not in your trusted keys. "
                "If you rotated keys, run `pin trust-key --add`. Otherwise treat the pin file as replaced."
            )
            return VerificationResult("untrusted_signer", kid, message)
        return VerificationResult(
            "retired_key",
            kid,
            (
                f"Pin for {server_name} was signed by a retired key ({kid}); re-sign with "
                f"`pin rotate-key --resign` before "
                f"{(retired_time + timedelta(days=retired_grace_days)).date().isoformat()}."
            ),
        )
    return VerificationResult("verified", kid)


def load_trusted_keys(path: Path = DEFAULT_TRUSTED_KEYS_PATH) -> dict[str, dict[str, object]]:
    """Load trusted public keys; never consult public keys embedded in pins."""
    value = _read_trust_json(path)
    if value is None:
        return {}
    raw_keys = _extract_trusted_keys(value)
    result: dict[str, dict[str, object]] = {}
    for kid, raw in raw_keys.items():
        if not isinstance(kid, str):
            continue
        if isinstance(raw, str):
            result[kid] = {"public_key": raw, "retired_at": None}
        elif isinstance(raw, dict) and isinstance(raw.get("public_key"), str):
            retired_at = raw.get("retired_at")
            normalized: dict[str, object] = {
                "public_key": raw["public_key"],
                "retired_at": retired_at if isinstance(retired_at, str) else None,
            }
            grace_days = raw.get("grace_days")
            if isinstance(grace_days, int) and not isinstance(grace_days, bool) and grace_days >= 0:
                normalized["grace_days"] = grace_days
            result[kid] = normalized
    return result


def trust_key(public_key: bytes | str, trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH) -> str:
    """Add a public key to the trust anchor store and return its kid."""
    raw = bytes.fromhex(public_key) if isinstance(public_key, str) else public_key
    kid = key_id(raw)
    try:
        Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as exc:
        raise PinSigningError("Trusted key is not a valid Ed25519 public key.") from exc
    with _trusted_store_lock(trusted_keys_path):
        data = _read_trust_data(trusted_keys_path)
        keys = data.setdefault("keys", {})
        if not isinstance(keys, dict):
            raise PinSigningError("Trusted pin keys have an invalid format.")
        keys[kid] = {"public_key": raw.hex(), "retired_at": None}
        _write_json(trusted_keys_path, data)
    return kid


def rotate_key(
    key_dir: Path = DEFAULT_KEY_DIR,
    trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH,
    old_private_key_path: Path = DEFAULT_SIGNING_KEY_PATH,
    *,
    grace_days: int = 30,
    now: datetime | None = None,
) -> GeneratedKey:
    """Generate a replacement key and start the old key's grace period."""
    if grace_days < 0:
        raise ValueError("grace_days must be non-negative")
    if now is not None and now.tzinfo is None:
        raise ValueError("now must include a timezone")
    with _trusted_store_lock(trusted_keys_path):
        old_private = load_private_key(old_private_key_path)
        old_public = old_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        old_kid = key_id(old_public)
        if old_private_key_path.parent != key_dir:
            raise PinSigningError("Current signing key must be inside the rotation key directory.")
        _ensure_private_directory(key_dir)
        private_path = old_private_key_path
        public_path = old_private_key_path.with_suffix(".pub")
        try:
            public_key_file = public_path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise PinSigningError("Current public key could not be read; refusing to rotate.") from exc
        if public_key_file != old_public.hex():
            raise PinSigningError("Current public key does not match the signing key; refusing to rotate.")
        data = _read_trust_data(trusted_keys_path)
        keys = data.setdefault("keys", {})
        if not isinstance(keys, dict) or old_kid not in keys:
            raise PinSigningError("Current signing key is not in the trusted key store.")
        staging_dir = Path(tempfile.mkdtemp(prefix=".pin-key-rotation-", dir=key_dir))
        os.chmod(staging_dir, 0o700)
        try:
            staged = _create_keypair(staging_dir)
            archived_private = private_path.with_name(f"{private_path.stem}.{old_kid}{private_path.suffix}")
            archived_public = public_path.with_name(f"{public_path.stem}.{old_kid}{public_path.suffix}")
            if archived_private.exists() or archived_public.exists():
                raise PinSigningError("Retired signing key archive already exists; refusing to replace it.")
            moved_private = moved_public = installed_private = installed_public = False
            try:
                os.replace(private_path, archived_private)
                moved_private = True
                os.replace(public_path, archived_public)
                moved_public = True
                os.replace(staged.private_key_path, private_path)
                installed_private = True
                os.replace(staged.public_key_path, public_path)
                installed_public = True
                keys[old_kid] = {
                    "public_key": old_public.hex(),
                    "retired_at": _timestamp(now),
                    "grace_days": grace_days,
                }
                keys[staged.kid] = {"public_key": staged.public_key, "retired_at": None}
                _write_json(trusted_keys_path, data)
            except Exception:
                if installed_public and public_path.exists():
                    os.replace(public_path, staged.public_key_path)
                if installed_private and private_path.exists():
                    os.replace(private_path, staged.private_key_path)
                if moved_public and archived_public.exists():
                    os.replace(archived_public, public_path)
                if moved_private and archived_private.exists():
                    os.replace(archived_private, private_path)
                raise
            return GeneratedKey(staged.kid, private_path, public_path, staged.public_key)
        finally:
            shutil.rmtree(staging_dir)


def check_and_record_pinned_at(
    server_name: str,
    pinned_at: str,
    trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH,
) -> bool:
    """Record the newest verified pin time; return whether this pin is a rollback."""
    try:
        incoming = _parse_timestamp(pinned_at)
    except ValueError as exc:
        raise PinSigningError("Pin timestamp is invalid.") from exc
    with _trusted_store_lock(trusted_keys_path):
        data = _read_trust_data(trusted_keys_path)
        servers = data.setdefault("servers", {})
        if not isinstance(servers, dict):
            raise PinSigningError("Trusted pin keys have an invalid format.")
        server = servers.setdefault(server_name, {})
        if not isinstance(server, dict):
            raise PinSigningError("Trusted pin keys have an invalid format.")
        server["signature_required"] = True
        previous = server.get("last_seen_pinned_at")
        rolled_back = False
        if isinstance(previous, str):
            try:
                rolled_back = incoming < _parse_timestamp(previous)
            except ValueError as exc:
                raise PinSigningError("Trusted pin rollback state is invalid.") from exc
        if not rolled_back:
            server["last_seen_pinned_at"] = _timestamp(incoming)
        _write_json(trusted_keys_path, data)
        return rolled_back


def signature_required(server_name: str, trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH) -> bool:
    """Read the signing expectation independently of editable pin contents."""
    data = _read_trust_data(trusted_keys_path)
    servers = data.get("servers", {})
    if not isinstance(servers, dict):
        raise PinSigningError("Trusted pin signing state has an invalid format.")
    server = servers.get(server_name, {})
    if not isinstance(server, dict):
        raise PinSigningError("Trusted pin signing state has an invalid format.")
    required = server.get("signature_required")
    if "signature_required" in server:
        if not isinstance(required, bool):
            raise PinSigningError("Trusted pin signing state has an invalid format.")
        return required
    # Migrate existing verified-baseline history without trusting pin metadata.
    return "last_seen_pinned_at" in server


def record_signature_requirement(
    server_name: str, required: bool, trusted_keys_path: Path = DEFAULT_TRUSTED_KEYS_PATH
) -> None:
    """Persist signing or a successfully written explicit downgrade."""
    with _trusted_store_lock(trusted_keys_path):
        data = _read_trust_data(trusted_keys_path)
        servers = data.setdefault("servers", {})
        if not isinstance(servers, dict):
            raise PinSigningError("Trusted pin signing state has an invalid format.")
        server = servers.setdefault(server_name, {})
        if not isinstance(server, dict):
            raise PinSigningError("Trusted pin signing state has an invalid format.")
        server["signature_required"] = required
        _write_json(trusted_keys_path, data)


def _create_keypair(key_dir: Path) -> GeneratedKey:
    _ensure_private_directory(key_dir)
    private_path = key_dir / "pin-signing.key"
    public_path = key_dir / "pin-signing.pub"
    if private_path.exists() or public_path.exists():
        raise PinSigningError("Signing key already exists; refusing to replace it.")
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    _write_new_file(private_path, private_bytes, 0o600)
    try:
        _write_new_file(public_path, public_bytes.hex().encode("ascii") + b"\n", 0o644)
    except OSError:
        private_path.unlink(missing_ok=True)
        raise
    return GeneratedKey(key_id(public_bytes), private_path, public_path, public_bytes.hex())


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.getuid()
    ):
        raise PinSigningError(f"Signing key directory {path} must be mode 0700 and owned by you.")


def _write_new_file(path: Path, value: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def _read_trust_data(path: Path) -> dict[str, object]:
    value = _read_trust_json(path)
    if value is None:
        return {"keys": {}, "servers": {}}
    if "keys" not in value:
        flat_keys = _extract_trusted_keys(value)
        wrapped_keys = {
            kid: {"public_key": public_key, "retired_at": None} for kid, public_key in flat_keys.items()
        }
        value = {"keys": wrapped_keys, "servers": {}}
    elif not isinstance(value.get("keys"), dict):
        raise PinSigningError("Trusted pin keys have an invalid format.")
    value.setdefault("keys", {})
    value.setdefault("servers", {})
    return value


def _extract_trusted_keys(value: dict[str, object]) -> dict[str, object]:
    """Read either the flat public-only CI format or the wrapped local format."""
    raw_keys = value.get("keys")
    if raw_keys is None and "keys" not in value:
        raw_keys = value
    if not isinstance(raw_keys, dict):
        raise PinSigningError("Trusted pin keys have an invalid format.")
    if raw_keys is value:
        if any(
            not isinstance(kid, str) or _KID_PATTERN.fullmatch(kid) is None or not isinstance(public_key, str)
            for kid, public_key in raw_keys.items()
        ):
            raise PinSigningError("Trusted pin keys have an invalid format.")
    return raw_keys


def _read_trust_json(path: Path) -> dict[str, object] | None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PinSigningError("Trusted pin keys could not be read.") from exc
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        current_uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or bool(stat.S_IMODE(metadata.st_mode) & 0o022)
            or metadata.st_uid != current_uid
        ):
            raise PinSigningError("Trusted pin keys must be owned by you and not group/world writable.")
        raw = handle.read(_MAX_TRUSTED_KEYS_BYTES + 1)
    if len(raw) > _MAX_TRUSTED_KEYS_BYTES:
        raise PinSigningError("Trusted pin keys exceed the 10 MiB size limit.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PinSigningError("Trusted pin keys could not be read.") from exc
    if not isinstance(value, dict):
        raise PinSigningError("Trusted pin keys have an invalid format.")
    return value


@contextmanager
def _trusted_store_lock(path: Path) -> Iterator[None]:
    """Serialize trust-store read/modify/write operations across local processes."""
    if fcntl is None:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise PinSigningError("Trusted pin keys could not be locked for update.") from exc
    try:
        metadata = os.fstat(descriptor)
        current_uid = getattr(os, "getuid", lambda: metadata.st_uid)()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != current_uid
        ):
            raise PinSigningError("Trusted pin key lock must be mode 0600 and owned by you.")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        Path(temporary).unlink(missing_ok=True)
        raise PinSigningError("Trusted pin keys could not be written.") from exc


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must have a timezone")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _integrity_message(server_name: str) -> str:
    return (
        f"Pin for {server_name} fails signature verification; the baseline was modified after signing. "
        "Do not refresh from this file; restore it from backup or re-review the server and re-pin."
    )
