"""CLI coverage for signed pin key management and explicit config selection."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import cli, pin_signing
from mcp_audit.engine import ScanOptions
from mcp_audit.models import AuditReport, ServerAudit
from mcp_audit.pinning import PinStore
from tests.conftest import make_server_config, make_tool


def test_pin_keygen_creates_isolated_key_and_reports_public_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_dir = tmp_path / "keys"
    trusted_path = tmp_path / "trusted-keys.json"
    actual_generate = pin_signing.generate_keypair
    generated_keys: list[pin_signing.GeneratedKey] = []

    def generate_isolated() -> pin_signing.GeneratedKey:
        generated = actual_generate(key_dir=key_dir, trusted_keys_path=trusted_path)
        generated_keys.append(generated)
        return generated

    monkeypatch.setattr(pin_signing, "generate_keypair", generate_isolated)
    result = CliRunner().invoke(cli.main, ["pin", "keygen"])

    assert result.exit_code == 0, result.output
    generated = generated_keys[0]
    assert generated.private_key_path.stat().st_mode & 0o777 == 0o600
    assert f"Public key: {generated.public_key}" in result.output
    assert trusted_path.exists()


def test_pin_trust_key_uses_external_public_key_and_isolates_trust_store(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = pin_signing.generate_keypair(tmp_path / "source-keys", tmp_path / "source-trust.json")
    trusted_path = tmp_path / "target-trust.json"
    actual_trust = pin_signing.trust_key
    monkeypatch.setattr(
        pin_signing,
        "trust_key",
        lambda public_key: actual_trust(public_key, trusted_keys_path=trusted_path),
    )

    result = CliRunner().invoke(cli.main, ["pin", "trust-key", "--add", key.public_key])

    assert result.exit_code == 0, result.output
    assert key.kid in result.output
    contents = json.loads(trusted_path.read_text(encoding="utf-8"))
    assert contents["keys"][key.kid]["public_key"] == key.public_key


def test_pin_rotate_key_rotates_only_isolated_key_material(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_dir = tmp_path / "keys"
    trusted_path = tmp_path / "trusted-keys.json"
    old = pin_signing.generate_keypair(key_dir, trusted_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", old.private_key_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", trusted_path)

    pin_file = tmp_path / "pins.yaml"
    result = CliRunner().invoke(cli.main, ["pin", "--pin-file", str(pin_file), "rotate-key"])

    assert result.exit_code == 0, result.output
    assert "Public key: " in result.output
    keys = json.loads(trusted_path.read_text(encoding="utf-8"))["keys"]
    assert keys[old.kid]["retired_at"] is not None
    assert len(keys) == 2


def test_pin_config_only_forwards_explicit_config_without_discovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "fixture"}}}\n', encoding="utf-8")
    pin_file = tmp_path / "pins.yaml"
    captured: list[ScanOptions] = []
    audit = ServerAudit(
        server=make_server_config(name="fixture"),
        connection_status="connected",
        tools=[make_tool("example")],
    )

    async def fake_scan(options: ScanOptions, *args: object, **kwargs: object) -> AuditReport:
        captured.append(options)
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="test-host",
            os_platform="test-os",
            servers_discovered=1,
            servers_connected=1,
            servers_failed=0,
            total_tools=1,
            high_risk_servers=0,
            audits=[audit],
            scan_duration_seconds=0.0,
        )

    monkeypatch.setattr("mcp_audit.pin_cli.run_scan", fake_scan)

    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--config",
            str(config),
            "--config-only",
            "--unsigned",
            "--pin-file",
            str(pin_file),
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured[0].extra_config == str(config)
    assert captured[0].config_only is True
    assert PinStore(pin_file, unsigned=True).tool_count("fixture") == 1


def test_pin_stale_config_only_does_not_discover_workstation_configs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "fixture"}}}\n', encoding="utf-8")
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(pin_file, unsigned=True)
    store.pin_server("removed", [make_tool("example")])

    def unexpected_discovery(*args: object, **kwargs: object) -> list[object]:
        raise AssertionError("config-only stale review must not discover workstation configs")

    monkeypatch.setattr("mcp_audit.pin_cli.discover_all_configs", unexpected_discovery)
    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--stale",
            "--json",
            "--config",
            str(config),
            "--config-only",
            "--pin-file",
            str(pin_file),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["discovered_server_count"] == 1
    assert payload["stale_servers"][0]["name"] == "removed"


def test_pin_refresh_refuses_failed_signature_without_applying(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key_dir = tmp_path / "keys"
    trusted_path = tmp_path / "trusted-keys.json"
    key = pin_signing.generate_keypair(key_dir, trusted_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", key.private_key_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", trusted_path)
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(pin_file, signing_key=key.private_key_path, trusted_keys_path=trusted_path)
    store.pin_server("fixture", [make_tool("example", description="reviewed")])
    original = yaml.safe_load(pin_file.read_text(encoding="utf-8"))
    original["servers"]["fixture"]["tools"]["example"]["snapshot"]["description"] = "edited"
    pin_file.write_text(yaml.safe_dump(original), encoding="utf-8")
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "fixture"}}}\n', encoding="utf-8")
    audit = ServerAudit(
        server=make_server_config(name="fixture"),
        connection_status="connected",
        tools=[make_tool("example", description="new surface")],
    )

    async def fake_scan(options: ScanOptions, *args: object, **kwargs: object) -> AuditReport:
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="test-host",
            os_platform="test-os",
            servers_discovered=1,
            servers_connected=1,
            servers_failed=0,
            total_tools=1,
            high_risk_servers=0,
            audits=[audit],
            scan_duration_seconds=0.0,
        )

    monkeypatch.setattr("mcp_audit.pin_cli.run_scan", fake_scan)
    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--refresh",
            "fixture",
            "--apply",
            "--json",
            "--config",
            str(config),
            "--config-only",
            "--pin-file",
            str(pin_file),
            "--signing-key",
            str(key.private_key_path),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["applied"] is False
    assert "fails signature verification" in payload["error"]
    assert yaml.safe_load(pin_file.read_text(encoding="utf-8")) == original


def test_pin_rotate_key_resign_keeps_the_current_key(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key = pin_signing.generate_keypair(tmp_path / "keys", tmp_path / "trusted-keys.json")
    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", key.private_key_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", tmp_path / "trusted-keys.json")
    pin_file = tmp_path / "pins.yaml"
    store = PinStore(
        pin_file,
        signing_key=key.private_key_path,
        trusted_keys_path=tmp_path / "trusted-keys.json",
    )
    store.pin_server("fixture", [make_tool("example")])

    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--pin-file",
            str(pin_file),
            "--signing-key",
            str(key.private_key_path),
            "rotate-key",
            "--resign",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Re-signed pins with the current key" in result.output
    assert key.public_key in result.output
    assert (
        PinStore(pin_file, trusted_keys_path=tmp_path / "trusted-keys.json").signing_status("fixture")["kid"]
        == key.kid
    )
    assert len(json.loads((tmp_path / "trusted-keys.json").read_text())["keys"]) == 1


def test_pin_write_reports_wrong_mode_signing_key_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = pin_signing.generate_keypair(tmp_path / "keys", tmp_path / "trusted-keys.json")
    key.private_key_path.chmod(0o644)
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "fixture"}}}\n', encoding="utf-8")
    audit = ServerAudit(
        server=make_server_config(name="fixture"),
        connection_status="connected",
        tools=[make_tool("example")],
    )

    async def fake_scan(options: ScanOptions, *args: object, **kwargs: object) -> AuditReport:
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="test-host",
            os_platform="test-os",
            servers_discovered=1,
            servers_connected=1,
            servers_failed=0,
            total_tools=1,
            high_risk_servers=0,
            audits=[audit],
            scan_duration_seconds=0.0,
        )

    monkeypatch.setattr("mcp_audit.pin_cli.run_scan", fake_scan)
    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--config",
            str(config),
            "--config-only",
            "--pin-file",
            str(tmp_path / "pins.yaml"),
            "--signing-key",
            str(key.private_key_path),
        ],
    )

    assert result.exit_code == 1
    assert "must be mode 0600 and owned by you." in " ".join(result.output.split())
    assert "pin-signing.key" in result.output


@pytest.mark.parametrize("hash_field", ["package_hashes", "registry_artifact_hashes"])
def test_plain_pin_cannot_resign_hashes_from_failed_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, hash_field: str
) -> None:
    trust = tmp_path / "trusted.json"
    key = pin_signing.generate_keypair(tmp_path / "keys", trust)
    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", key.private_key_path)
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", trust)
    pin_file = tmp_path / "pins.yaml"
    config = make_server_config(name="fixture")
    tools = [make_tool("example", description="reviewed")]
    store = PinStore(pin_file, signing_key=key.private_key_path, trusted_keys_path=trust)
    store.pin_server(
        "fixture",
        tools,
        config,
        package_hashes={"npm:fixture": "sha256:good"},
        artifact_hashes={"npm:fixture": "sha256:good"},
    )
    assert store.baseline_trusted("fixture")
    data = yaml.safe_load(pin_file.read_text())
    data["servers"]["fixture"]["config_snapshot"][hash_field]["npm:fixture"] = "sha256:edited"
    data["servers"]["fixture"]["signature"]["sig"] = "invalid-signature"
    pin_file.write_text(yaml.safe_dump(data))
    before = pin_file.read_bytes()
    synthetic_config = tmp_path / "synthetic.json"
    synthetic_config.write_text('{"mcpServers": {"fixture": {"command": "fixture"}}}\n')

    async def fake_scan(options: ScanOptions, *args: object, **kwargs: object) -> AuditReport:
        assert options.config_only and options.extra_config == str(synthetic_config)
        return AuditReport(
            scan_timestamp=datetime.now(UTC),
            hostname="test-host",
            os_platform="test-os",
            servers_discovered=1,
            servers_connected=1,
            servers_failed=0,
            total_tools=1,
            high_risk_servers=0,
            scan_duration_seconds=0.0,
            audits=[ServerAudit(server=config, tools=tools, connection_status="connected")],
        )

    monkeypatch.setattr("mcp_audit.pin_cli.run_scan", fake_scan)
    result = CliRunner().invoke(
        cli.main,
        [
            "pin",
            "--server",
            "fixture",
            "--config",
            str(synthetic_config),
            "--config-only",
            "--pin-file",
            str(pin_file),
        ],
    )
    assert result.exit_code == 1
    assert "untrusted pin baseline" in " ".join(result.output.split())
    assert pin_file.read_bytes() == before
    # The library guard must reverify even when this instance cached success.
    with pytest.raises(pin_signing.PinSigningError, match="untrusted pin baseline"):
        store.pin_server("fixture", tools, config)
    assert pin_file.read_bytes() == before
