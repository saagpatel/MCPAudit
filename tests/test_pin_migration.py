"""Acceptance coverage for reviewed unsigned v2 to signed pin migration."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner, Result

from mcp_audit import cli, overrides, pin_cli, pin_signing
from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, ServerAudit, ToolAnnotations, ToolInfo
from mcp_audit.pinning import PinStore
from tests.conftest import make_server_config, make_tool


@pytest.fixture
def unsigned_v2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    pins = tmp_path / "pins.yaml"
    store = PinStore(pins, unsigned=True)
    store.pin_server(
        "fixture",
        [
            make_tool("status", annotations=ToolAnnotations(read_only_hint=True)),
            make_tool("removed"),
        ],
        make_server_config(name="fixture", command="old-fixture", args=[]),
        package_hashes={"npm:fixture@1.0.0": "old-registry-hash"},
        artifact_hashes={"npm:fixture@1.0.0": "old-byte-hash"},
    )
    store.pin_server("other", [make_tool("unrelated")])
    pin_signing.generate_keypair(
        pin_signing.DEFAULT_SIGNING_KEY_PATH.parent, pin_signing.DEFAULT_TRUSTED_KEYS_PATH
    )
    monkeypatch.setattr(overrides, "DEFAULT_OVERRIDE_PATH", tmp_path / "no-overrides.yaml")
    return pins


def _refresh(
    monkeypatch: pytest.MonkeyPatch,
    pins: Path,
    tools: list[ToolInfo],
    *extra: str,
    connection_status: str = "connected",
) -> Result:
    config = pins.parent / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "live-fixture"}}}')
    audit = ServerAudit(
        server=make_server_config(name="fixture", command="live-fixture", args=[], env_keys=["TOKEN"]),
        connection_status=connection_status,
        tools=tools,
    )

    async def fake_scan(options: ScanOptions, *args: object, **kwargs: object) -> AuditReport:
        assert options.config_only and options.extra_config == str(config)
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="fixture-host",
            os_platform="fixture-os",
            servers_discovered=1,
            servers_connected=int(connection_status == "connected"),
            servers_failed=int(connection_status != "connected"),
            total_tools=len(tools),
            high_risk_servers=0,
            audits=[audit],
            scan_duration_seconds=0.0,
        )

    monkeypatch.setattr(pin_cli, "run_scan", fake_scan)
    monkeypatch.setattr(pin_cli.console, "width", 240)
    return CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--refresh",
            "fixture",
            "--config",
            str(config),
            "--config-only",
            "--pin-file",
            str(pins),
            *extra,
        ],
    )


def _live_tools() -> list[ToolInfo]:
    return [
        make_tool("status", annotations=ToolAnnotations(read_only_hint=False)),
        make_tool("new"),
    ]


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("apply", [False, True])
def test_refresh_migrates_unsigned_v2_without_clear(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch, as_json: bool, apply: bool
) -> None:
    before = unsigned_v2.read_bytes()
    trust_before = pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes()
    other = yaml.safe_load(before)["servers"]["other"]
    store = PinStore(unsigned_v2)
    assert not store.baseline_usable("fixture")
    assert store.check_drift("fixture", _live_tools()) == []
    assert store.baseline_tools("fixture") == []
    assert store.baseline_config("fixture") is None

    args = (["--json"] if as_json else []) + (["--apply"] if apply else [])
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), *args)
    assert result.exit_code == 0, result.output
    if as_json:
        payload = json.loads(result.output)
        assert payload["applied"] is apply
        assert payload["error"] is None
        assert payload["baseline_verified"] is False
        assert "unsigned v2" in payload["baseline_note"]
        assert payload["drift_counts"] == {"new": 1, "changed": 1, "removed": 1}
        assert payload["escalation"] and payload["provenance"]
    else:
        assert "unverified unsigned v2 baseline" in result.output
        assert "1 new, 1 changed, 1 removed" in result.output
        assert "Capability escalation" in result.output
        assert "Launch-config / provenance drift" in result.output
        assert "No drift found" not in result.output

    if not apply:
        assert unsigned_v2.read_bytes() == before
        assert pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes() == trust_before
        assert "--apply" in result.output
        return

    data = yaml.safe_load(unsigned_v2.read_text())
    entry = data["servers"]["fixture"]
    assert set(entry["tools"]) == {"status", "new"}
    assert data["servers"]["other"] == other
    assert "package_hashes" not in entry["config_snapshot"]
    assert "registry_artifact_hashes" not in entry["config_snapshot"]
    assert entry["config_snapshot"]["command"] == "live-fixture"
    assert entry["config_snapshot"]["env_keys"] == ["TOKEN"]
    assert data["manifest"]["servers"] == {"fixture": entry["surface_sha256"]}
    reloaded = PinStore(unsigned_v2)
    verified = reloaded.verification("fixture")
    assert verified is not None and verified.state == "verified"
    assert reloaded.check_drift("fixture", _live_tools()) == []
    assert pin_signing.signature_required("fixture", pin_signing.DEFAULT_TRUSTED_KEYS_PATH)


def test_matching_unsigned_review_never_claims_verified_match(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = yaml.safe_load(unsigned_v2.read_text())
    data["servers"]["fixture"].pop("config_snapshot")
    unsigned_v2.write_text(yaml.safe_dump(data))
    tools = PinStore(unsigned_v2).baseline_tools("fixture", review_unsigned_v2=True)
    result = _refresh(monkeypatch, unsigned_v2, tools)
    assert result.exit_code == 0, result.output
    assert "could not be verified" in result.output
    assert "No drift found" not in result.output


def test_migration_preserves_an_existing_signed_peer(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PinStore(unsigned_v2)
    store.pin_server("other", [make_tool("unrelated")], migrate_unsigned_v2=True)
    signed_other = yaml.safe_load(unsigned_v2.read_text())["servers"]["other"]
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), "--apply")
    assert result.exit_code == 0, result.output
    assert yaml.safe_load(unsigned_v2.read_text())["servers"]["other"] == signed_other
    reloaded = PinStore(unsigned_v2)
    for name in ("fixture", "other"):
        verified = reloaded.verification(name)
        assert verified is not None and verified.state == "verified"


def test_manifest_binding_blocks_migration_even_with_fresh_trust_store(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    PinStore(unsigned_v2).pin_server("fixture", _live_tools(), migrate_unsigned_v2=True)
    data = yaml.safe_load(unsigned_v2.read_text())
    for field in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
        data["servers"]["fixture"].pop(field)
    unsigned_v2.write_text(yaml.safe_dump(data))
    trust = json.loads(pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_text())
    trust.pop("servers")
    pin_signing.DEFAULT_TRUSTED_KEYS_PATH.write_text(json.dumps(trust))
    before = unsigned_v2.read_bytes()
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), "--apply", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["applied"] is False and "fails signature verification" in payload["error"]
    assert unsigned_v2.read_bytes() == before


@pytest.mark.parametrize("refusal", ["expectation", "signer", "invalid_manifest", "signed_peer"])
def test_migration_keeps_integrity_failures_blocked(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch, refusal: str
) -> None:
    data = yaml.safe_load(unsigned_v2.read_text())
    if refusal == "expectation":
        pin_signing.record_signed_pin(
            "fixture", datetime.now(UTC).isoformat(), pin_signing.DEFAULT_TRUSTED_KEYS_PATH
        )
    elif refusal == "signer":
        data["servers"]["fixture"]["signer"] = {}
    elif refusal == "invalid_manifest":
        data["manifest"] = {}
    else:
        data["servers"]["other"]["signature"] = {}
    unsigned_v2.write_text(yaml.safe_dump(data))
    before = unsigned_v2.read_bytes()
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), "--apply", "--json")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["applied"] is False
    assert "fails signature verification" in payload["error"]
    assert unsigned_v2.read_bytes() == before


@pytest.mark.parametrize("key_mode", ["missing", "untrusted", "unsigned"])
def test_migration_requires_trusted_private_key(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch, key_mode: str
) -> None:
    args: list[str] = []
    if key_mode == "missing":
        pin_signing.DEFAULT_SIGNING_KEY_PATH.unlink()
    elif key_mode == "untrusted":
        key = pin_signing.generate_keypair(
            unsigned_v2.parent / "untrusted", unsigned_v2.parent / "other-trust.json"
        )
        args = ["--signing-key", str(key.private_key_path)]
    else:
        args = ["--unsigned"]
    before = unsigned_v2.read_bytes()
    trust_before = pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes()
    preview = _refresh(monkeypatch, unsigned_v2, _live_tools(), *args)
    assert preview.exit_code == 0, preview.output
    assert "trusted signing key" in preview.output
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), "--apply", *args)
    assert result.exit_code == 1, result.output
    assert "trusted signing key" in result.output
    assert unsigned_v2.read_bytes() == before
    assert pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes() == trust_before


def test_migration_requires_live_connection(unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    before = unsigned_v2.read_bytes()
    result = _refresh(monkeypatch, unsigned_v2, [], "--apply", "--json", connection_status="failed")
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["applied"] is False and payload["error"] == "connection failed"
    assert unsigned_v2.read_bytes() == before


def test_migration_rechecks_eligibility_under_write_lock(unsigned_v2: Path) -> None:
    store = PinStore(unsigned_v2)
    assert store.unsigned_v2_migration_allowed("fixture")
    pin_signing.record_signed_pin(
        "fixture", datetime.now(UTC).isoformat(), pin_signing.DEFAULT_TRUSTED_KEYS_PATH
    )
    before = unsigned_v2.read_bytes()
    with pytest.raises(pin_signing.PinSigningError, match="no longer eligible"):
        store.pin_server("fixture", _live_tools(), migrate_unsigned_v2=True)
    assert unsigned_v2.read_bytes() == before


def test_failed_migration_write_preserves_baseline_and_expectation(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = unsigned_v2.read_bytes()
    trust_before = pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes()
    store = PinStore(unsigned_v2)

    def fail_write() -> None:
        raise OSError("synthetic write failure")

    monkeypatch.setattr(store, "_write", fail_write)
    with pytest.raises(OSError, match="synthetic write failure"):
        store.pin_server("fixture", _live_tools(), migrate_unsigned_v2=True)
    assert unsigned_v2.read_bytes() == before
    assert pin_signing.DEFAULT_TRUSTED_KEYS_PATH.read_bytes() == trust_before


@pytest.mark.parametrize(
    "corrupt",
    ["annotations", "config_not_mapping", "config_args", "config_hashes"],
)
def test_malformed_unsigned_snapshot_is_not_migration_eligible(
    unsigned_v2: Path, monkeypatch: pytest.MonkeyPatch, corrupt: str
) -> None:
    data = yaml.safe_load(unsigned_v2.read_text())
    entry = data["servers"]["fixture"]
    if corrupt == "annotations":
        entry["tools"]["status"]["snapshot"]["annotations"] = "bad"
    elif corrupt == "config_not_mapping":
        entry["config_snapshot"] = ["bad"]
    elif corrupt == "config_args":
        entry["config_snapshot"]["args"] = "bad"
    else:
        entry["config_snapshot"]["artifact_hashes"] = {"path": 1}
    unsigned_v2.write_text(yaml.safe_dump(data))
    assert PinStore(unsigned_v2).unsigned_v2_migration_allowed("fixture") is False
    before = unsigned_v2.read_bytes()
    result = _refresh(monkeypatch, unsigned_v2, _live_tools(), "--apply", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["applied"] is False
    assert unsigned_v2.read_bytes() == before
