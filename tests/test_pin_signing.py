"""Tests for signed v2 tool-surface pins and their local trust anchor."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import mcp_audit.pin_signing as pin_signing
from mcp_audit.pin_signing import (
    PinSigningError,
    check_and_record_pinned_at,
    generate_keypair,
    key_id,
    record_signature_requirement,
    rotate_key,
    sign_document,
    signature_required,
    trust_key,
    verify_document,
)


@pytest.fixture
def signing_paths(tmp_path: Path) -> tuple[Path, Path]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o700)
    trusted = tmp_path / "trusted-pin-keys.json"
    return key_dir, trusted


def sample_document() -> dict[str, object]:
    return {
        "schema": "mcpaudit.tool-surface.v2",
        "server": {"name": "fixture-server", "config_sha256": "a" * 64},
        "protocol": {"negotiated_version": "2026-07-28", "era": "modern"},
        "tools": [
            {
                "name": "read_fixture",
                "title": "Read fixture",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            }
        ],
    }


def test_signed_expectation_is_separate_and_explicitly_downgradable(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted.json"
    assert not signature_required("legacy", trusted)
    record_signature_requirement("fixture", True, trusted)
    assert signature_required("fixture", trusted)
    assert not signature_required("legacy", trusted)
    record_signature_requirement("fixture", False, trusted)
    assert not signature_required("fixture", trusted)


def test_verified_history_requires_signatures_until_explicit_downgrade(tmp_path: Path) -> None:
    trusted = tmp_path / "trusted.json"
    trusted.write_text(
        json.dumps({"keys": {}, "servers": {"fixture": {"last_seen_pinned_at": "2026-01-01T00:00:00Z"}}})
    )
    assert signature_required("fixture", trusted)
    record_signature_requirement("fixture", False, trusted)
    assert not signature_required("fixture", trusted)
    assert json.loads(trusted.read_text())["servers"]["fixture"]["last_seen_pinned_at"]


@pytest.mark.parametrize("state", ["unreadable", "invalid"])
def test_signing_expectation_fails_closed_on_invalid_trust_state(tmp_path: Path, state: str) -> None:
    trusted = tmp_path / "trusted.json"
    trusted.write_text(
        "{"
        if state == "unreadable"
        else json.dumps({"keys": {}, "servers": {"fixture": {"signature_required": "false"}}})
    )
    with pytest.raises(PinSigningError):
        signature_required("fixture", trusted)


def test_keygen_sign_and_verify_round_trip(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    assert key_dir.stat().st_mode & 0o777 == 0o700
    assert generated.private_key_path.stat().st_mode & 0o777 == 0o600
    assert generated.public_key_path.read_text().strip() == generated.public_key
    record = sign_document(sample_document(), generated.private_key_path)

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "verified"
    assert result.kid == generated.kid == key_id(bytes.fromhex(generated.public_key))
    assert result.message is None


@pytest.mark.parametrize(
    "change",
    [
        lambda doc: doc.update(schema="mcpaudit.tool-surface.v3"),
        lambda doc: doc["server"].update(name="changed-server"),
        lambda doc: doc["protocol"].update(era="legacy"),
        lambda doc: doc["tools"][0].update(title="Changed title"),
        lambda doc: doc["tools"][0]["annotations"].update(readOnlyHint=False),
    ],
)
def test_changed_signed_fields_fail_verification(signing_paths: tuple[Path, Path], change: object) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    original = sample_document()
    record = sign_document(original, generated.private_key_path)
    changed = sample_document()
    change(changed)  # type: ignore[operator]

    result = verify_document(changed, record, trusted, server_name="fixture-server")

    assert result.state == "tampered_entry"
    assert result.message is not None and "fails signature verification" in result.message


def test_untrusted_kid_is_rejected_even_with_matching_embedded_public_key(
    signing_paths: tuple[Path, Path], tmp_path: Path
) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    other = generate_keypair(tmp_path / "other-keys", tmp_path / "other-trusted.json")
    record = sign_document(sample_document(), generated.private_key_path)
    record["signature"]["kid"] = other.kid  # type: ignore[index]
    record["signer"] = {"kid": other.kid, "public_key": other.public_key}

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "untrusted_signer"
    assert result.kid == other.kid
    assert "not in your trusted keys" in (result.message or "")


def test_retired_key_is_accepted_during_grace_then_rejected(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    trust = json.loads(trusted.read_text())
    trust["keys"][generated.kid]["retired_at"] = "2026-01-01T00:00:00Z"
    trusted.write_text(json.dumps(trust))

    inside = verify_document(
        sample_document(),
        record,
        trusted,
        server_name="fixture-server",
        now=datetime(2026, 1, 20, tzinfo=UTC),
    )
    past = verify_document(
        sample_document(), record, trusted, server_name="fixture-server", now=datetime(2026, 2, 2, tzinfo=UTC)
    )

    assert inside.state == "retired_key"
    assert inside.message is not None and "re-sign" in inside.message
    assert past.state == "untrusted_signer"


def test_invalid_signature_bytes_are_reported_as_bad_signature(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    signature_record = cast(dict[str, object], record["signature"])
    signature_bytes = bytearray(base64.b64decode(cast(str, signature_record["sig"])))
    signature_bytes[0] ^= 1
    signature_record["sig"] = base64.b64encode(signature_bytes).decode("ascii")

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "bad_signature"


def test_signing_refuses_wrong_key_mode(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    os.chmod(generated.private_key_path, 0o644)

    with pytest.raises(PinSigningError, match="mode 0600 and owned by you"):
        sign_document(sample_document(), generated.private_key_path)


def test_public_key_only_ci_verification_needs_no_private_key(
    signing_paths: tuple[Path, Path], tmp_path: Path
) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    generated.private_key_path.unlink()

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "verified"


def test_read_only_public_trust_store_supports_ci_verification(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    os.chmod(trusted, 0o644)
    generated.private_key_path.unlink()

    result = verify_document(sample_document(), record, trusted)

    assert result.state == "verified"


def test_flat_public_only_trust_store_supports_ci_and_migrates_on_write(
    signing_paths: tuple[Path, Path], tmp_path: Path
) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    wrapped = json.loads(trusted.read_text())
    trusted.write_text(json.dumps({generated.kid: generated.public_key}))
    os.chmod(trusted, 0o644)
    generated.private_key_path.unlink()

    result = verify_document(sample_document(), record, trusted)
    assert result.state == "verified"

    second = generate_keypair(tmp_path / "second-keys", tmp_path / "second-trust.json")
    trust_key(second.public_key, trusted)
    migrated = json.loads(trusted.read_text())

    assert set(migrated["keys"]) == {generated.kid, second.kid}
    assert migrated["keys"][generated.kid]["public_key"] == wrapped["keys"][generated.kid]["public_key"]
    assert migrated["servers"] == {}


def test_malformed_kid_is_not_copied_into_verification_message(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    signature_record = cast(dict[str, object], record["signature"])
    signature_record["kid"] = "kid\nforged warning"

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "tampered_entry"
    assert result.kid is None
    assert "forged warning" not in (result.message or "")


def test_unreadable_trusted_store_is_reported_as_untrusted(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), generated.private_key_path)
    trusted.write_text("not valid json")

    result = verify_document(sample_document(), record, trusted, server_name="fixture-server")

    assert result.state == "untrusted_signer"
    assert result.message == "Pin for fixture-server cannot be verified because trusted keys are unavailable."


def test_rotation_keeps_old_key_for_grace_and_trusts_new_key(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    old = generate_keypair(key_dir, trusted)

    new = rotate_key(
        key_dir,
        trusted,
        old.private_key_path,
        grace_days=7,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    trust = json.loads(trusted.read_text())

    assert new.kid != old.kid
    assert trust["keys"][old.kid]["retired_at"] == "2026-01-01T00:00:00Z"
    assert trust["keys"][old.kid]["grace_days"] == 7
    assert trust["keys"][new.kid]["retired_at"] is None
    assert (key_dir / f"pin-signing.{old.kid}.key").exists()
    assert (key_dir / f"pin-signing.{old.kid}.key").stat().st_mode & 0o777 == 0o600


def test_rotation_uses_custom_signing_key_and_preserves_canonical_pair(
    signing_paths: tuple[Path, Path],
) -> None:
    key_dir, trusted = signing_paths
    canonical = generate_keypair(key_dir, trusted)
    canonical_private = canonical.private_key_path.read_bytes()
    canonical_public = canonical.public_key_path.read_bytes()
    custom_private = key_dir / "ci-review-key.pem"
    custom_public = custom_private.with_suffix(".pub")
    custom_private.write_bytes(canonical_private)
    custom_public.write_bytes(canonical_public)
    os.chmod(custom_private, 0o600)
    os.chmod(custom_public, 0o644)

    rotated = rotate_key(key_dir, trusted, custom_private)

    assert rotated.private_key_path == custom_private
    assert rotated.public_key_path == custom_public
    assert custom_public.read_text().strip() == rotated.public_key
    assert canonical.private_key_path.read_bytes() == canonical_private
    assert canonical.public_key_path.read_bytes() == canonical_public
    assert (key_dir / f"ci-review-key.{canonical.kid}.pem").read_bytes() == canonical_private


def test_rotation_persisted_grace_days_controls_verification(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    old = generate_keypair(key_dir, trusted)
    record = sign_document(sample_document(), old.private_key_path)
    rotate_key(
        key_dir,
        trusted,
        old.private_key_path,
        grace_days=2,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    inside = verify_document(sample_document(), record, trusted, now=datetime(2026, 1, 3, tzinfo=UTC))
    past = verify_document(sample_document(), record, trusted, now=datetime(2026, 1, 4, tzinfo=UTC))

    assert inside.state == "retired_key"
    assert past.state == "untrusted_signer"


def test_negative_grace_period_is_rejected(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    old = generate_keypair(key_dir, trusted)

    with pytest.raises(ValueError, match="grace_days must be non-negative"):
        rotate_key(key_dir, trusted, old.private_key_path, grace_days=-1)


def test_failed_trust_store_write_rolls_back_key_rotation(
    signing_paths: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    key_dir, trusted = signing_paths
    old = generate_keypair(key_dir, trusted)

    def fail_write(path: Path, value: object) -> None:
        raise PinSigningError("injected trust-store write failure")

    monkeypatch.setattr(pin_signing, "_write_json", fail_write)
    with pytest.raises(PinSigningError, match="injected trust-store write failure"):
        rotate_key(key_dir, trusted, old.private_key_path)

    assert old.private_key_path.exists()
    assert (key_dir / "pin-signing.pub").read_text().strip() == old.public_key
    assert not list(key_dir.glob("pin-signing.*.key"))
    assert sign_document(sample_document(), old.private_key_path)["signature"]


def test_private_key_symlink_is_rejected(signing_paths: tuple[Path, Path]) -> None:
    key_dir, trusted = signing_paths
    generated = generate_keypair(key_dir, trusted)
    symlink_path = key_dir / "linked.key"
    symlink_path.symlink_to(generated.private_key_path)

    with pytest.raises(PinSigningError, match="mode 0600 and owned by you"):
        sign_document(sample_document(), symlink_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are unavailable")
@pytest.mark.parametrize("target", ["private", "trusted"])
def test_fifo_key_paths_fail_without_blocking(tmp_path: Path, target: str) -> None:
    fifo = tmp_path / f"{target}.fifo"
    os.mkfifo(fifo, 0o600)
    if target == "private":
        script = """\
import sys
from pathlib import Path
from mcp_audit.pin_signing import PinSigningError, load_private_key
try:
    load_private_key(Path(sys.argv[1]))
except PinSigningError:
    pass
else:
    raise SystemExit(1)
"""
    else:
        script = """\
import sys
from pathlib import Path
from mcp_audit.pin_signing import PinSigningError, load_trusted_keys
try:
    load_trusted_keys(Path(sys.argv[1]))
except PinSigningError:
    pass
else:
    raise SystemExit(1)
"""

    result = subprocess.run(
        [sys.executable, "-c", script, str(fifo)],
        capture_output=True,
        check=False,
        timeout=3,
    )

    assert result.returncode == 0


def test_rollback_state_tracks_highest_seen_pin_timestamp(signing_paths: tuple[Path, Path]) -> None:
    _, trusted = signing_paths

    assert not check_and_record_pinned_at("fixture-server", "2026-01-02T00:00:00Z", trusted)
    assert check_and_record_pinned_at("fixture-server", "2026-01-01T00:00:00Z", trusted)
    assert not check_and_record_pinned_at("fixture-server", "2026-01-03T00:00:00Z", trusted)

    data = json.loads(trusted.read_text())
    assert data["servers"]["fixture-server"]["last_seen_pinned_at"] == "2026-01-03T00:00:00Z"


def test_rollback_state_preserves_microseconds(signing_paths: tuple[Path, Path]) -> None:
    _, trusted = signing_paths

    assert not check_and_record_pinned_at("fixture-server", "2026-01-02T00:00:00.900000Z", trusted)
    assert check_and_record_pinned_at("fixture-server", "2026-01-02T00:00:00.100000Z", trusted)

    data = json.loads(trusted.read_text())
    assert data["servers"]["fixture-server"]["last_seen_pinned_at"] == "2026-01-02T00:00:00.900000Z"


def test_unsigned_v2_is_reported_with_remediation(signing_paths: tuple[Path, Path]) -> None:
    _, trusted = signing_paths

    result = verify_document(sample_document(), None, trusted, server_name="fixture-server")

    assert result.state == "unsigned"
    assert result.message == (
        "Pin for fixture-server is unsigned. Run `mcp-audit pin keygen`, then "
        "`pin --clear fixture-server` and `pin --server fixture-server` after review to sign it."
    )
