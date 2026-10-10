"""Signed pin integration against synthetic server surfaces only."""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import AsyncIterator
from functools import partial
from pathlib import Path
from types import ModuleType

import anyio
import pytest
import yaml
from click.testing import CliRunner

from mcp_audit import engine, pinning
from mcp_audit.connector import ServerConnector
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import PinVerificationState, ProtocolObservation, ServerAudit, ToolAnnotations, ToolInfo
from mcp_audit.overrides import OverrideConfig
from mcp_audit.pin_signing import PinSigningError, generate_keypair, sign_document
from mcp_audit.pinning import PinStore
from mcp_audit.report import ReportGenerator
from tests.conftest import make_server_config


@pytest.fixture
def signed_store(tmp_path: Path) -> PinStore:
    trust = tmp_path / "trusted.json"
    key = generate_keypair(tmp_path / "keys", trust)
    store = PinStore(tmp_path / "pins.yaml", signing_key=key.private_key_path, trusted_keys_path=trust)
    store.pin_server(
        "fixture",
        [
            ToolInfo(
                name="list_items",
                description="List items",
                title="Items",
                input_schema={"type": "object"},
                output_schema={"type": "array"},
                annotations=ToolAnnotations(read_only_hint=True, destructive_hint=False),
                icons=[{"src": "https://example.invalid/icon.png"}],
                meta={"version": "one"},
            )
        ],
        make_server_config(name="fixture"),
        protocol=ProtocolObservation(era="modern", negotiated_version="2026-07-28"),
    )
    return store


@pytest.mark.parametrize(
    "field",
    [
        "name",
        "description",
        "title",
        "input_schema",
        "output_schema",
        "annotations",
        "icons",
        "meta",
        "hash",
        "pinned_at",
        "protocol",
        "config_snapshot",
        "tool_set",
        "server_name",
        "canonical_bytes_len",
        "malformed_tool",
        "malformed_tools",
    ],
)
def test_signed_fields_cannot_be_edited(signed_store: PinStore, field: str) -> None:
    data = yaml.safe_load(signed_store.path.read_text())
    entry = data["servers"]["fixture"]
    tool = entry["tools"]["list_items"]
    if field == "name":
        entry["tools"]["list_itemx"] = entry["tools"].pop("list_items")
    elif field in {"description", "title", "input_schema", "output_schema", "annotations", "icons", "meta"}:
        snapshot = tool["snapshot"]
        if field in {"description", "title"}:
            snapshot[field] += "x"
        elif field == "annotations":
            snapshot[field]["read_only_hint"] = False
        elif field == "icons":
            snapshot[field][0]["src"] += "x"
        else:
            snapshot[field]["extra"] = "x"
    elif field == "hash":
        tool[field] = tool[field][:-1] + ("0" if tool[field][-1] != "0" else "1")
    elif field == "pinned_at":
        entry[field] = "2000-01-01T00:00:00+00:00"
    elif field == "protocol":
        entry[field]["era"] = "legacy"
    elif field == "config_snapshot":
        entry[field]["command"] += "x"
    elif field == "tool_set":
        entry["tools"].clear()
    elif field == "server_name":
        data["servers"]["fixturx"] = data["servers"].pop("fixture")
    elif field == "malformed_tool":
        entry["tools"]["list_items"] = None
    elif field == "malformed_tools":
        entry["tools"] = []
    else:
        entry[field] += 1
    signed_store.path.write_text(yaml.safe_dump(data))
    loaded = PinStore(signed_store.path, trusted_keys_path=signed_store._trusted_keys_path)
    name = "fixturx" if field == "server_name" else "fixture"
    result = loaded.verification(name)
    assert result is not None and result.state == PinVerificationState.TAMPERED_ENTRY
    assert loaded.check_drift(name, [ToolInfo(name="new_tool")]) == []
    assert loaded.baseline_tools(name) == []
    assert loaded.baseline_config(name) is None
    assert loaded.canary_baseline(name) is None


def test_public_key_only_verification_and_rollback(signed_store: PinStore) -> None:
    original = signed_store.path.read_text()
    old = yaml.safe_load(original)
    newer = copy.deepcopy(old)
    entry = newer["servers"]["fixture"]
    entry["pinned_at"] = "2099-01-01T00:00:00+00:00"
    signed_store._sign_entry("fixture", entry)
    signed_store.path.write_text(yaml.safe_dump(newer))
    trust = signed_store._trusted_keys_path
    verified = PinStore(signed_store.path, trusted_keys_path=trust).verification("fixture")
    assert verified is not None and verified.state == "verified"
    signed_store._signing_key.unlink()
    signed_store.path.write_text(original)
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    verified = loaded.verification("fixture")
    assert verified is not None and verified.state == "verified"
    assert [w.code for w in loaded.verification_warnings("fixture")] == ["pin_rolled_back"]


def test_rotation_resigns_and_refuses_corrupted_baseline(signed_store: PinStore) -> None:
    previous = signed_store.signing_status("fixture")["kid"]
    public = signed_store.rotate_key()
    assert len(public) == 64
    assert signed_store.signing_status("fixture")["kid"] != previous
    verified = signed_store.verification("fixture")
    assert verified is not None and verified.state == "verified"
    data = yaml.safe_load(signed_store.path.read_text())
    data["servers"]["fixture"]["tools"].clear()
    signed_store.path.write_text(yaml.safe_dump(data))
    key_before = signed_store._signing_key.read_bytes()
    with pytest.raises(PinSigningError, match="untrusted pin baseline"):
        signed_store.rotate_key()
    assert signed_store._signing_key.read_bytes() == key_before


@pytest.mark.parametrize("canary", [False, True])
def test_engine_surfaces_failed_verification_and_withholds_baseline(
    signed_store: PinStore,
    monkeypatch: pytest.MonkeyPatch,
    canary: bool,
) -> None:
    data = yaml.safe_load(signed_store.path.read_text())
    data["servers"]["fixture"]["tools"]["list_items"]["snapshot"]["title"] += "x"
    signed_store.path.write_text(yaml.safe_dump(data))
    trust = signed_store._trusted_keys_path
    captured: list[object] = []

    class LocalStore(PinStore):
        def __init__(self, path: Path = signed_store.path) -> None:
            super().__init__(path, trusted_keys_path=trust)

    class Connector:
        def __init__(self, timeout: int) -> None:
            self.scan_warnings: list[object] = []

        async def connect(self, server: object, **kwargs: object) -> ServerAudit:
            captured.append(kwargs.get("canary_baseline"))
            return ServerAudit(
                server=make_server_config(name="fixture"),
                connection_status="connected",
                tools=[ToolInfo(name="new_tool")],
            )

    monkeypatch.setattr(pinning, "PinStore", LocalStore)
    monkeypatch.setattr(engine, "ServerConnector", Connector)
    report = anyio.run(
        partial(
            run_scan,
            ScanOptions(pin_check=not canary, canary_check=canary, pin_file=signed_store.path),
            servers=[make_server_config(name="fixture")],
        )
    )
    audit = report.audits[0]
    assert audit.pin_verification is not None and audit.pin_verification.state == "tampered_entry"
    assert audit.pin_integrity_findings[0].rule_id == "MCP027"
    assert audit.drift_findings == []
    assert captured == [None]
    assert "pin_integrity_failed" in {w.code for w in report.warnings}
    if not canary:
        assert report.coverage["pin_check"].state == "not_run"


def test_unsigned_escape_hatch_and_v1_warning(signed_store: PinStore) -> None:
    unsigned = PinStore(
        signed_store.path,
        signing_key=signed_store._signing_key,
        unsigned=True,
        trusted_keys_path=signed_store._trusted_keys_path,
    )
    unsigned.pin_server("fixture", [ToolInfo(name="list_items")])
    verified = unsigned.verification("fixture")
    assert verified is not None and verified.state == "unsigned"
    assert unsigned.verification_warnings("fixture")[0].code == "pin_unsigned"
    data = yaml.safe_load(signed_store.path.read_text())
    entry = data["servers"]["fixture"]
    entry["tools"]["list_items"].pop("pin_schema")
    signed_store.path.write_text(yaml.safe_dump(data))
    legacy = PinStore(signed_store.path, trusted_keys_path=signed_store._trusted_keys_path)
    verified = legacy.verification("fixture")
    assert verified is not None and verified.state == "schema_outdated"
    assert legacy.baseline_trusted("fixture")
    assert legacy.schema_warnings("fixture")[0].code == "pin_schema_outdated"


def test_pin_write_records_signing_requirement_before_first_verification(signed_store: PinStore) -> None:
    trust = json.loads(signed_store._trusted_keys_path.read_text())
    assert trust["servers"]["fixture"] == {"signature_required": True}
    data = yaml.safe_load(signed_store.path.read_text())
    entry = data["servers"]["fixture"]
    for field in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
        entry.pop(field)
    signed_store.path.write_text(yaml.safe_dump(data))
    loaded = PinStore(signed_store.path, trusted_keys_path=signed_store._trusted_keys_path)
    assert not loaded.baseline_trusted("fixture")


def test_failed_unsigned_write_keeps_signature_requirement(
    signed_store: PinStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.pin_signing import signature_required

    before = signed_store.path.read_bytes()
    trust = signed_store._trusted_keys_path
    unsigned = PinStore(signed_store.path, unsigned=True, trusted_keys_path=trust)

    def fail_write() -> None:
        raise OSError("Synthetic pin replacement failure")

    monkeypatch.setattr(unsigned, "_write", fail_write)
    with pytest.raises(OSError, match="Synthetic pin replacement failure"):
        unsigned.pin_server("fixture", [ToolInfo(name="list_items")])
    assert signed_store.path.read_bytes() == before
    assert signature_required("fixture", trust)
    data = yaml.safe_load(before)
    for field in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
        data["servers"]["fixture"].pop(field)
    signed_store.path.write_text(yaml.safe_dump(data))
    assert not PinStore(signed_store.path, trusted_keys_path=trust).baseline_trusted("fixture")


def test_missing_private_key_cannot_silently_downgrade_signed_pin(signed_store: PinStore) -> None:
    before = signed_store.path.read_bytes()
    signed_store._signing_key.unlink()
    ci_store = PinStore(signed_store.path, trusted_keys_path=signed_store._trusted_keys_path)
    with pytest.raises(PinSigningError, match="mode 0600"):
        ci_store.pin_server("fixture", [ToolInfo(name="list_items")])
    assert signed_store.path.read_bytes() == before


def test_status_prints_complete_copyable_public_key(
    signed_store: PinStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.cli import main

    monkeypatch.setattr("mcp_audit.pin_signing.DEFAULT_TRUSTED_KEYS_PATH", signed_store._trusted_keys_path)
    public_key = signed_store.signing_status("fixture")["trusted_public_key"]
    result = CliRunner().invoke(main, ["pin", "--pin-file", str(signed_store.path), "--status"])
    assert result.exit_code == 0
    assert f"Trusted public key for fixture (CI): {public_key}" in result.output


@pytest.mark.parametrize("strip_all", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_stripped_signature_is_untrusted_even_after_tool_schema_downgrade(
    signed_store: PinStore, strip_all: bool, legacy: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.policy import evaluate_policy, load_policy

    trust = signed_store._trusted_keys_path
    assert signed_store.baseline_trusted("fixture")
    data = yaml.safe_load(signed_store.path.read_text())
    entry = data["servers"]["fixture"]
    for field in (
        ("signature", "signer", "surface_sha256", "canonical_bytes_len") if strip_all else ("signature",)
    ):
        entry.pop(field)
    malicious = ToolInfo(name="list_items", description="Changed surface")
    entry["tools"]["list_items"]["hash"] = signed_store.compute_hash(malicious)
    entry["tools"]["list_items"]["snapshot"] = signed_store._tool_snapshot(malicious)
    if legacy:
        entry["tools"]["list_items"]["pin_schema"] = 1
    signed_store.path.write_text(yaml.safe_dump(data))

    class LocalStore(PinStore):
        def __init__(self, path: Path = signed_store.path) -> None:
            super().__init__(path, trusted_keys_path=trust)

    class Connector:
        def __init__(self, timeout: int) -> None:
            self.scan_warnings: list[object] = []

        async def connect(self, server: object) -> ServerAudit:
            return ServerAudit(
                server=make_server_config(name="fixture"),
                connection_status="connected",
                tools=[malicious],
            )

    monkeypatch.setattr(pinning, "PinStore", LocalStore)
    monkeypatch.setattr(engine, "ServerConnector", Connector)
    report = anyio.run(
        partial(
            run_scan,
            ScanOptions(pin_check=True, pin_file=signed_store.path),
            servers=[make_server_config(name="fixture")],
        )
    )
    loaded = LocalStore()
    assert not loaded.baseline_trusted("fixture")
    assert loaded.check_drift("fixture", [malicious]) == []
    assert loaded.baseline_tools("fixture") == []
    assert loaded.baseline_config("fixture") is None
    assert loaded.canary_baseline("fixture") is None
    assert report.audits[0].pin_verification is not None
    assert report.audits[0].pin_verification.state == "tampered_entry"
    assert report.audits[0].pin_integrity_findings[0].rule_id == "MCP027"
    assert "pin_unsigned" not in {w.code for w in report.warnings}
    policy_file = signed_store.path.parent / "policy.yaml"
    policy_file.write_text("fail_on:\n  pin_integrity: true\n")
    assert not evaluate_policy(report, load_policy(policy_file)).passed

    # A writer that verified before the edit must also re-read and refuse it.
    for mutation in (signed_store.rotate_key, signed_store.resign):
        with pytest.raises(PinSigningError, match="untrusted pin baseline"):
            mutation()
    with pytest.raises(PinSigningError, match="untrusted pin baseline"):
        signed_store.pin_server("fixture", [malicious])
    assert yaml.safe_load(signed_store.path.read_text()) == data


@pytest.mark.parametrize("replace_signature", [False, True])
def test_status_never_offers_embedded_attacker_key_for_ci(
    signed_store: PinStore, monkeypatch: pytest.MonkeyPatch, replace_signature: bool
) -> None:
    from mcp_audit.cli import main

    trust = signed_store._trusted_keys_path
    original_key = signed_store.signing_status("fixture")["trusted_public_key"]
    attacker = generate_keypair(signed_store.path.parent / "attacker-keys", trust.with_name("attacker.json"))
    data = yaml.safe_load(signed_store.path.read_text())
    entry = data["servers"]["fixture"]
    entry["signer"] = {"kid": attacker.kid, "public_key": attacker.public_key}
    if replace_signature:
        entry["tools"]["list_items"]["snapshot"]["description"] = "Changed surface"
        entry.update(
            sign_document(signed_store._server_document("fixture", entry), attacker.private_key_path)
        )
    signed_store.path.write_text(yaml.safe_dump(data))
    monkeypatch.setattr("mcp_audit.pin_signing.DEFAULT_TRUSTED_KEYS_PATH", trust)
    result = CliRunner().invoke(main, ["pin", "--pin-file", str(signed_store.path), "--status"])
    assert result.exit_code == 0
    assert attacker.public_key not in result.output
    if replace_signature:
        assert "(CI):" not in result.output
    else:
        assert f"(CI): {original_key}" in result.output
    result = CliRunner().invoke(main, ["pin", "--pin-file", str(signed_store.path), "--status", "--json"])
    status = json.loads(result.output)["servers"][0]
    assert status["public_key"] == attacker.public_key  # Existing field remains untrusted entry metadata.
    assert status["trusted_public_key"] == (None if replace_signature else original_key)


@pytest.mark.anyio
async def test_serve_check_server_verifies_saved_pin(
    signed_store: PinStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import overrides, server

    config = make_server_config(name="fixture")
    signed_store._signing_key.unlink()
    monkeypatch.setattr(server, "discover_all_configs", lambda *args: [config])
    monkeypatch.setattr(pinning, "PinStore", lambda: signed_store)
    monkeypatch.setattr(overrides, "load_override_config", lambda *args: OverrideConfig())

    async def connect(self: object, target: object) -> ServerAudit:
        return ServerAudit(
            server=config, connection_status="connected", tools=signed_store.baseline_tools("fixture")
        )

    monkeypatch.setattr(ServerConnector, "connect", connect)
    result = await server._build_mcp_server().call_tool("check_server", {"name": "fixture"})
    payload = json.loads(result.structured_content["result"])
    assert payload["pin_verification"]["state"] == "verified"
    assert payload["drift_findings"] == []


@pytest.mark.anyio
async def test_watch_reverifies_on_every_rescan(
    signed_store: PinStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import overrides, watcher

    config = make_server_config(name="fixture")
    trust = signed_store._trusted_keys_path
    listed_tools = signed_store.baseline_tools("fixture")
    captured: list[ServerAudit] = []

    class LocalStore(PinStore):
        def __init__(self) -> None:
            super().__init__(signed_store.path, trusted_keys_path=trust)

    async def connect(self: object, target: object) -> ServerAudit:
        return ServerAudit(server=config, connection_status="connected", tools=listed_tools)

    async def changes(*paths: str) -> AsyncIterator[set[tuple[int, str]]]:
        data = yaml.safe_load(signed_store.path.read_text())
        data["servers"]["fixture"]["tools"]["list_items"]["snapshot"]["title"] += "x"
        signed_store.path.write_text(yaml.safe_dump(data))
        yield {(2, paths[0])}

    def render(self: object, report: object, **kwargs: object) -> None:
        from mcp_audit.models import AuditReport

        assert isinstance(report, AuditReport)
        captured.append(report.audits[0])

    watchfiles = ModuleType("watchfiles")
    monkeypatch.setattr(watchfiles, "awatch", changes, raising=False)
    monkeypatch.setitem(sys.modules, "watchfiles", watchfiles)
    monkeypatch.setattr(engine, "discover_all_configs", lambda *args: [config])
    monkeypatch.setattr(pinning, "PinStore", LocalStore)
    monkeypatch.setattr(overrides, "load_override_config", lambda *args: OverrideConfig())
    monkeypatch.setattr(ServerConnector, "connect", connect)
    monkeypatch.setattr(watcher, "_get_watch_paths", lambda: [signed_store.path.parent / "config.json"])
    monkeypatch.setattr(ReportGenerator, "render_terminal", render)
    await watcher._watch_loop(None, None, False, None, 10, False, None, None)
    assert [audit.pin_verification.state for audit in captured if audit.pin_verification] == [
        "verified",
        "tampered_entry",
    ]
    assert captured[1].pin_integrity_findings[0].rule_id == "MCP027"
    assert captured[1].drift_findings == []
