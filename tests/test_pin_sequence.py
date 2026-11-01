"""Signed manifest sequence and deleted-trust acceptance, using synthetic fixtures."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

import anyio
import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import cli, pin_signing, pinning
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, PinVerificationState, ToolInfo
from mcp_audit.pin_signing import GeneratedKey, PinSigningError, generate_keypair, sign_document, trust_key
from mcp_audit.pinning import PinStore
from mcp_audit.policy import PolicyConfig, evaluate_policy, load_policy
from tests.conftest import make_server_config


@pytest.fixture
def signed_pins(tmp_path: Path) -> tuple[PinStore, GeneratedKey, Path]:
    trust = pin_signing.DEFAULT_TRUSTED_KEYS_PATH
    key = generate_keypair(tmp_path / "keys", trust)
    store = PinStore(tmp_path / "pins.yaml", signing_key=key.private_key_path)
    tool = ToolInfo.model_validate_json((Path("tests/fixtures/pinning/tool-v2.json")).read_text())
    store.pin_server("fixture", [tool], make_server_config(name="fixture"))
    return store, key, trust


def empty_report() -> AuditReport:
    return AuditReport(
        scan_timestamp=datetime.now(UTC),
        hostname="fixture-host",
        os_platform="fixture-os",
        servers_discovered=0,
        servers_connected=0,
        servers_failed=0,
        total_tools=0,
        high_risk_servers=0,
        audits=[],
        scan_duration_seconds=0,
    )


def test_sequence_advances_on_each_signed_write_under_lock(
    signed_pins: tuple[PinStore, GeneratedKey, Path],
) -> None:
    store, key, _ = signed_pins
    stale = PinStore(store.path, signing_key=key.private_key_path)
    assert store.verified_manifest_sequence() == 1
    store.pin_server("fixture", [ToolInfo(name="second", input_schema={})])
    assert store.verified_manifest_sequence() == 2
    stale.resign()
    assert stale.verified_manifest_sequence() == 3
    stale.rotate_key()
    assert stale.verified_manifest_sequence() == 4
    stale.remove_server("fixture")
    assert stale.pinned_servers() == []
    assert stale.verified_manifest_sequence() == 5


def test_failed_write_does_not_consume_persisted_sequence(
    signed_pins: tuple[PinStore, GeneratedKey, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _, _ = signed_pins
    original = store.path.read_bytes()
    with monkeypatch.context() as patch:

        def fail_write() -> None:
            raise OSError("injected fixture write failure")

        patch.setattr(store, "_write", fail_write)
        with pytest.raises(OSError, match="fixture write failure"):
            store.resign()
    assert store.path.read_bytes() == original
    store.resign()
    assert store.verified_manifest_sequence() == 2


@pytest.mark.parametrize("sequence", [None, 2, True, 0, -1, "1"])
def test_sequence_is_authenticated_and_validated(
    signed_pins: tuple[PinStore, GeneratedKey, Path], sequence: object
) -> None:
    store, _, _ = signed_pins
    data = yaml.safe_load(store.path.read_text())
    if sequence is None:
        data["manifest"].pop("sequence")
    else:
        data["manifest"]["sequence"] = sequence
    store.path.write_text(yaml.safe_dump(data))
    reader = PinStore(store.path)
    assert reader.verified_manifest_sequence() is None
    assert not reader.baseline_usable("fixture")
    assert not evaluate_policy(empty_report(), PolicyConfig(pin_min_sequence=1), reader).passed


def test_pre_sequence_manifest_compatibility_and_migration(
    signed_pins: tuple[PinStore, GeneratedKey, Path],
) -> None:
    store, key, _ = signed_pins
    data = yaml.safe_load(store.path.read_text())
    document = {"schema": data["manifest"]["schema"], "servers": data["manifest"]["servers"]}
    data["manifest"] = {**document, **sign_document(document, key.private_key_path)}
    store.path.write_text(yaml.safe_dump(data))
    reader = PinStore(store.path, signing_key=key.private_key_path)
    assert reader.baseline_usable("fixture")
    assert reader.verified_manifest_sequence() is None
    assert not evaluate_policy(empty_report(), PolicyConfig(pin_min_sequence=1), reader).passed
    reader.resign()
    assert reader.verified_manifest_sequence() == 1


def test_minimum_rejects_rollback_with_fresh_public_only_trust(
    signed_pins: tuple[PinStore, GeneratedKey, Path], tmp_path: Path
) -> None:
    store, key, _ = signed_pins
    older = store.path.read_bytes()
    store.resign()
    newer = store.path.read_bytes()
    fresh_trust = tmp_path / "ci-trust.json"
    trust_key(key.public_key, fresh_trust)
    assert not json.loads(fresh_trust.read_text()).get("servers")
    policy = PolicyConfig(pin_min_sequence=2)
    assert evaluate_policy(empty_report(), policy, PinStore(store.path, trusted_keys_path=fresh_trust)).passed
    store.path.write_bytes(older)
    result = evaluate_policy(empty_report(), policy, PinStore(store.path, trusted_keys_path=fresh_trust))
    assert not result.passed
    assert result.violations[0].rule == "require.pin_min_sequence"
    store.path.write_bytes(newer)
    assert evaluate_policy(empty_report(), policy, PinStore(store.path, trusted_keys_path=fresh_trust)).passed


@pytest.mark.parametrize("entry_state", ["intact", "deleted", "legacy"])
def test_deleted_trust_store_is_mcp027_and_withholds_baselines(
    signed_pins: tuple[PinStore, GeneratedKey, Path], entry_state: str
) -> None:
    store, _, trust = signed_pins
    data = yaml.safe_load(store.path.read_text())
    if entry_state == "deleted":
        data["servers"] = {}
    elif entry_state == "legacy":
        data["servers"]["fixture"] = {"tools": {"old": {"hash": "sha256:" + "0" * 64}}}
    store.path.write_text(yaml.safe_dump(data))
    trust.unlink()
    report = anyio.run(
        partial(
            run_scan,
            ScanOptions(skip_connect=True, pin_check=True, pin_file=store.path),
            servers=[make_server_config(name="fixture")],
        )
    )
    audit = report.audits[0]
    assert audit.pin_integrity_findings[0].rule_id == "MCP027"
    assert audit.pin_integrity_findings[0].state == (
        PinVerificationState.UNTRUSTED_SIGNER
        if entry_state == "intact"
        else PinVerificationState.TAMPERED_ENTRY
    )
    assert not audit.drift_findings
    reader = PinStore(store.path)
    assert not reader.baseline_usable("fixture")
    assert not reader.baseline_tools("fixture")
    assert not evaluate_policy(report, PolicyConfig(fail_on_pin_integrity=True), reader).passed
    assert not evaluate_policy(report, PolicyConfig(pin_min_sequence=1), reader).passed
    assert not trust.exists()


@pytest.mark.parametrize("value", ["true", "0", "-1", "1.5", "'1'", "null", "[]"])
def test_policy_minimum_requires_positive_integer(tmp_path: Path, value: str) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"require:\n  pin_min_sequence: {value}\n")
    with pytest.raises(ValueError, match="positive integer"):
        load_policy(policy)


@pytest.mark.parametrize("command", ["check", "check"])
@pytest.mark.parametrize(
    "minimum,policy_minimum,expected", [(1, None, 0), (2, None, 2), (1, 2, 2), (None, 1, 0)]
)
def test_cli_sequence_gate_selects_pin_file_and_never_weakens_policy(
    signed_pins: tuple[PinStore, GeneratedKey, Path],
    tmp_path: Path,
    command: str,
    minimum: int | None,
    policy_minimum: int | None,
    expected: int,
) -> None:
    store, _, _ = signed_pins
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {}}')
    args = [command, "--config", str(config), "--override-config", "/dev/null", "--pin-file", str(store.path)]
    if command == "check":
        args += ["--config-only", "--skip-connect"]
    if minimum is not None:
        args += ["--pin-min-sequence", str(minimum)]
    if policy_minimum is not None:
        policy = tmp_path / "policy.yaml"
        policy.write_text(f"require:\n  pin_min_sequence: {policy_minimum}\n")
        args += ["--policy", str(policy)]
    result = CliRunner().invoke(cli.main, args)
    assert result.exit_code == expected, result.output
    if expected == 2:
        assert "sequence" in result.output


@pytest.mark.parametrize("state", ["missing", "unsigned", "untrusted"])
def test_minimum_cannot_pass_without_trusted_signed_manifest(
    signed_pins: tuple[PinStore, GeneratedKey, Path], state: str
) -> None:
    store, _, trust = signed_pins
    if state == "missing":
        store.path.unlink()
    elif state == "unsigned":
        data = yaml.safe_load(store.path.read_text())
        data.pop("manifest")
        store.path.write_text(yaml.safe_dump(data))
    else:
        trust.unlink()
    assert not evaluate_policy(empty_report(), PolicyConfig(pin_min_sequence=1), PinStore(store.path)).passed


def test_policy_minimum_uses_default_store(
    signed_pins: tuple[PinStore, GeneratedKey, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _, _ = signed_pins
    monkeypatch.setattr(pinning, "DEFAULT_PIN_PATH", store.path)
    assert evaluate_policy(empty_report(), PolicyConfig(pin_min_sequence=1)).passed


@pytest.mark.parametrize(
    "manifest_state,write", [("unsigned", "pin"), ("unsigned", "resign"), ("signed-empty", "resign")]
)
def test_writers_cannot_authenticate_a_sequence_after_trust_store_deletion(
    signed_pins: tuple[PinStore, GeneratedKey, Path],
    tmp_path: Path,
    write: str,
    manifest_state: str,
) -> None:
    store, key, trust = signed_pins
    assert store.verified_manifest_sequence() == 1
    ci_trust = tmp_path / "ci-trust.json"
    trust_key(key.public_key, ci_trust)
    data = yaml.safe_load(store.path.read_text())
    if manifest_state == "unsigned":
        data["manifest"] = {"schema": pinning.PIN_MANIFEST_SCHEMA, "sequence": 11, "servers": {}}
        entry = data["servers"]["fixture"]
        for field in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
            entry.pop(field)
        for tool in entry["tools"].values():
            tool["snapshot"]["description"] = "unreviewed replacement"
    else:
        document = {
            "schema": pinning.PIN_MANIFEST_SCHEMA,
            "sequence": 11,
            "servers": data["manifest"]["servers"],
        }
        data["manifest"] = {**document, **sign_document(document, key.private_key_path)}
        data["servers"] = {}
    store.path.write_text(yaml.safe_dump(data))
    trust.unlink()
    before = store.path.read_bytes()
    key_before = key.private_key_path.read_bytes()

    if write == "pin":
        # Reuse an instance that previously cached trusted verification.
        with pytest.raises(PinSigningError, match="signed manifest fails verification"):
            store.pin_server("fixture", [ToolInfo(name="replacement", input_schema={})])
    else:
        result = CliRunner().invoke(
            cli.main,
            [
                "pin",
                "--pin-file",
                str(store.path),
                "--signing-key",
                str(key.private_key_path),
                "rotate-key",
                "--resign",
            ],
        )
        assert result.exit_code == 1, result.output
        assert "signed manifest fails verification" in " ".join(result.output.split())

    assert store.path.read_bytes() == before
    assert key.private_key_path.read_bytes() == key_before
    assert not trust.exists()
    ci_reader = PinStore(store.path, trusted_keys_path=ci_trust)
    assert not evaluate_policy(empty_report(), PolicyConfig(pin_min_sequence=12), ci_reader).passed


def test_clear_preserves_signed_manifest_and_mcp027_after_trust_and_key_deletion(
    signed_pins: tuple[PinStore, GeneratedKey, Path], tmp_path: Path
) -> None:
    store, key, trust = signed_pins
    tool = ToolInfo.model_validate_json(Path("tests/fixtures/pinning/tool-v2.json").read_text())
    store.pin_server("payments", [tool])
    store.pin_server("docs", [tool])
    trust.unlink()
    key.private_key_path.unlink()
    before = store.path.read_bytes()

    result = CliRunner().invoke(cli.main, ["pin", "--pin-file", str(store.path), "--clear", "payments"])
    assert result.exit_code == 1, result.output
    assert "signed manifest fails verification" in " ".join(result.output.split())
    assert store.path.read_bytes() == before
    assert not trust.exists()

    data = yaml.safe_load(store.path.read_text())
    data["servers"]["docs"] = {"pin_schema": 2, "tools": {}}
    store.path.write_text(yaml.safe_dump(data))
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"docs": {"command": "fixture"}}}')
    report = tmp_path / "report.json"
    result = CliRunner().invoke(
        cli.main,
        [
            "check",
            "--config",
            str(config),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--pin-file",
            str(store.path),
            "--pin-check",
            "--output-json",
            str(report),
        ],
    )
    # The tampered baseline is withheld, so the requested pin check fails the run (P-2)
    # after the report is written.
    assert result.exit_code == 2, result.output
    audit = json.loads(report.read_text())["audits"][0]
    assert audit["pin_integrity_findings"][0]["rule_id"] == "MCP027"
    assert audit["pin_integrity_findings"][0]["severity"] == "high"
    assert not PinStore(store.path).baseline_usable("docs")
    assert not trust.exists()
