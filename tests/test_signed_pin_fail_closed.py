"""Fail-closed regressions: an expected-signed pin can never silently pass.

For any server the separate trust store expects to be signed, a missing,
unsigned, invalid, or untrusted entry must yield HIGH MCP027, withhold every
saved baseline, fail ``require.pins`` and baseline-dependent gates, and never
be reported as a legacy pin. Synthetic surfaces and tmp paths only.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from functools import partial
from pathlib import Path

import anyio
import pytest
import yaml

from mcp_audit import engine, pinning
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, PinVerificationState, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.pin_signing import PinSigningError, generate_keypair, signature_required
from mcp_audit.pinning import PinStore
from mcp_audit.policy import evaluate_policy, load_policy
from tests.conftest import make_server_config

TOOL = ToolInfo(name="list_items", description="List items", input_schema={"type": "object"})


@pytest.fixture
def trust(tmp_path: Path) -> Path:
    return tmp_path / "trusted.json"


@pytest.fixture
def key_path(tmp_path: Path, trust: Path) -> Path:
    return generate_keypair(tmp_path / "keys", trust).private_key_path


@pytest.fixture
def script(tmp_path: Path) -> Path:
    path = tmp_path / "server.py"
    path.write_text("print('synthetic fixture server')\n")
    return path


@pytest.fixture
def config(script: Path) -> ServerConfig:
    return make_server_config(name="fixture", command=None, args=[str(script)])


@pytest.fixture
def signed_store(tmp_path: Path, trust: Path, key_path: Path, config: ServerConfig) -> PinStore:
    store = PinStore(tmp_path / "pins.yaml", signing_key=key_path, trusted_keys_path=trust)
    store.pin_server("fixture", [TOOL], config)
    assert signature_required("fixture", trust)
    assert store.baseline_artifacts("fixture")
    return store


def _scan(
    monkeypatch: pytest.MonkeyPatch,
    pin_file: Path,
    trust: Path,
    config: ServerConfig,
    tools: list[ToolInfo],
    **options: object,
) -> AuditReport:
    class LocalStore(PinStore):
        def __init__(self, path: Path = pin_file) -> None:
            super().__init__(path, trusted_keys_path=trust)

    class Connector:
        def __init__(self, timeout: float, **transport_options: object) -> None:
            self.scan_warnings: list[object] = []

        async def connect(self, server: object, **kwargs: object) -> ServerAudit:
            return ServerAudit(server=config, connection_status="connected", tools=tools)

        def skip_connect_audit(self, server: object) -> ServerAudit:
            return ServerAudit(server=config, connection_status="skipped")

    monkeypatch.setattr(pinning, "PinStore", LocalStore)
    monkeypatch.setattr(engine, "ServerConnector", Connector)
    return anyio.run(
        partial(run_scan, ScanOptions(pin_file=pin_file, **options), servers=[config])  # type: ignore[arg-type]
    )


def _policy(tmp_path: Path, body: str) -> object:
    path = tmp_path / "policy.yaml"
    path.write_text(body)
    return load_policy(path)


def _edit(path: Path, mutate: Callable[[dict[str, object]], object]) -> None:
    data = yaml.safe_load(path.read_text())
    mutate(data)
    path.write_text(yaml.safe_dump(data))


def _rename(name: str) -> Callable[[dict[str, object]], object]:
    def mutate(data: dict[str, object]) -> None:
        servers = data["servers"]
        assert isinstance(servers, dict)
        servers[name] = servers.pop("fixture")

    return mutate


def _legacy_substitute(data: dict[str, object]) -> None:
    servers = data["servers"]
    assert isinstance(servers, dict)
    servers["fixture"] = {
        "tools": {"list_items": {"hash": "sha256:" + "0" * 64, "pinned_at": "2020-01-01T00:00:00+00:00"}}
    }


def _servers(data: dict[str, object]) -> dict[str, dict[str, object]]:
    servers = data["servers"]
    assert isinstance(servers, dict)
    return servers


def _edited(mutate: Callable[[dict[str, object]], object]) -> Callable[[Path], Path]:
    def attack(pins: Path) -> Path:
        _edit(pins, mutate)
        return pins

    return attack


def _written(text: str) -> Callable[[Path], Path]:
    def attack(pins: Path) -> Path:
        pins.write_text(text)
        return pins

    return attack


def _deleted(pins: Path) -> Path:
    pins.unlink()
    return pins


def _strip_signature(data: dict[str, object]) -> None:
    entry = _servers(data)["fixture"]
    for key in ("signature", "signer"):
        entry.pop(key)


# Each case returns the pin file the scan should use after the attack.
ATTACKS: dict[str, Callable[[Path], Path]] = {
    "entry_deleted": _edited(lambda d: _servers(d).pop("fixture")),
    "entry_renamed": _edited(_rename("fixture-old")),
    "entry_case_variant": _edited(_rename("Fixture")),
    "entry_whitespace_variant": _edited(_rename("fixture ")),
    "servers_emptied": _edited(lambda d: d.update(servers={})),
    "file_emptied": _written(""),
    "file_deleted": _deleted,
    "file_unparseable": _written("servers: [unterminated\n"),
    "pin_file_elsewhere": lambda pins: pins.with_name("other-pins.yaml"),
    "legacy_v1_substituted": _edited(_legacy_substitute),
    "signature_stripped": _edited(_strip_signature),
}


@pytest.mark.parametrize("attack", sorted(ATTACKS))
def test_expected_signed_server_never_escapes_mcp027(
    signed_store: PinStore,
    trust: Path,
    config: ServerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    pin_file = ATTACKS[attack](signed_store.path)
    loaded = PinStore(pin_file, trusted_keys_path=trust)
    verification = loaded.verification("fixture")
    assert verification is not None and verification.state == PinVerificationState.TAMPERED_ENTRY
    assert not loaded.baseline_trusted("fixture")
    assert loaded.tool_count("fixture") == 0
    assert loaded.check_drift("fixture", [TOOL]) == []
    assert loaded.baseline_tools("fixture") == []

    report = _scan(monkeypatch, pin_file, trust, config, [TOOL], pin_check=True)
    audit = report.audits[0]
    assert audit.pin_verification is not None and audit.pin_verification.state == "tampered_entry"
    assert [f.rule_id for f in audit.pin_integrity_findings] == ["MCP027"]
    assert audit.pin_integrity_findings[0].severity == "high"
    assert "pin_integrity_failed" in {w.code for w in report.warnings}
    # A rejected entry gets tampered/withheld guidance only, never legacy refresh advice.
    assert loaded.schema_warnings("fixture") == []
    assert "pin_schema_outdated" not in {w.code for w in report.warnings}

    policy = _policy(tmp_path, "fail_on:\n  pin_integrity: true\nrequire:\n  pins:\n    servers: [fixture]\n")
    result = evaluate_policy(report, policy, pin_store=loaded)  # type: ignore[arg-type]
    assert not result.passed
    assert {"fail_on.pin_integrity", "require.pins"} <= {v.rule for v in result.violations}


def test_unexpected_unpinned_server_is_still_unaffected(trust: Path, tmp_path: Path) -> None:
    store = PinStore(tmp_path / "pins.yaml", trusted_keys_path=trust)
    assert store.verification("never-pinned") is None
    assert store.baseline_trusted("never-pinned")


def test_broken_signature_fails_require_pins_and_drift_gate(
    signed_store: PinStore,
    trust: Path,
    config: ServerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def flip(data: dict[str, object]) -> None:
        signature = data["servers"]["fixture"]["signature"]  # type: ignore[index]
        raw = bytearray(base64.b64decode(signature["sig"]))
        raw[0] ^= 1
        signature["sig"] = base64.b64encode(bytes(raw)).decode()

    _edit(signed_store.path, flip)
    changed = TOOL.model_copy(update={"description": "Changed live surface"})
    report = _scan(monkeypatch, signed_store.path, trust, config, [changed], pin_check=True)
    audit = report.audits[0]
    assert audit.pin_verification is not None and audit.pin_verification.state == "bad_signature"
    assert audit.drift_findings == []

    # The ci-strict shape: drift + require.pins, without fail_on.pin_integrity.
    policy = _policy(tmp_path, "fail_on:\n  drift: true\nrequire:\n  pins:\n    servers: [fixture]\n")
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    result = evaluate_policy(report, policy, pin_store=loaded)  # type: ignore[arg-type]
    assert not result.passed
    rules = {v.rule for v in result.violations}
    assert {"require.pins", "fail_on.drift"} <= rules
    assert all(v.severity == "high" for v in result.violations if v.rule in {"require.pins", "fail_on.drift"})


def test_withheld_artifact_baseline_is_not_reported_as_legacy(
    signed_store: PinStore,
    trust: Path,
    config: ServerConfig,
    script: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def corrupt(data: dict[str, object]) -> None:
        data["servers"]["fixture"]["signature"]["sig"] = base64.b64encode(b"\0" * 64).decode()  # type: ignore[index]

    _edit(signed_store.path, corrupt)
    script.write_text("print('substituted')\n")
    report = _scan(
        monkeypatch,
        signed_store.path,
        trust,
        config,
        [TOOL],
        skip_connect=True,
        integrity_check=True,
        provenance_check=True,
    )
    codes = {(w.code, w.check) for w in report.warnings}
    assert ("pin_baseline_withheld", "integrity_check") in codes
    assert ("pin_baseline_withheld", "provenance_check") in codes
    assert "pin_baseline_stale" not in {code for code, _ in codes}
    assert report.audits[0].pin_integrity_findings[0].rule_id == "MCP027"
    withheld = next(w for w in report.warnings if w.code == "pin_baseline_withheld")
    assert withheld.servers == ["fixture"]
    assert "Re-pin with" not in withheld.message

    policy = load_policy(Path("examples/policies/integrity-aware-ci.yaml"))
    result = evaluate_policy(report, policy)
    assert not result.passed
    assert "fail_on.integrity" in {v.rule for v in result.violations}
    assert "fail_on.pin_integrity" in {v.rule for v in result.violations}


@pytest.mark.parametrize(
    "policy_name", ["ci-strict.yaml", "balanced-team-ci.yaml", "integrity-aware-ci.yaml"]
)
def test_example_ci_policies_gate_pin_integrity(policy_name: str) -> None:
    assert load_policy(Path("examples/policies") / policy_name).fail_on_pin_integrity


def _skipped_report(config: ServerConfig) -> AuditReport:
    """A report whose scan never verified pins (no pin-based check ran)."""
    return AuditReport.model_validate(
        {
            "scan_timestamp": "2026-01-01T00:00:00+00:00",
            "hostname": "synthetic",
            "os_platform": "synthetic",
            "servers_discovered": 1,
            "servers_connected": 0,
            "servers_failed": 0,
            "total_tools": 0,
            "high_risk_servers": 0,
            "audits": [ServerAudit(server=config, connection_status="skipped")],
            "scan_duration_seconds": 0,
        }
    )


def test_policy_verifies_pin_store_when_scan_did_not(
    signed_store: PinStore, trust: Path, config: ServerConfig, tmp_path: Path
) -> None:
    _edit(signed_store.path, lambda d: _servers(d).pop("fixture"))
    report = _skipped_report(config)
    policy = _policy(tmp_path, "fail_on:\n  pin_integrity: true\n")
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    result = evaluate_policy(report, policy, pin_store=loaded)  # type: ignore[arg-type]
    assert [v.rule for v in result.violations] == ["fail_on.pin_integrity"]


def _fail_write() -> None:
    raise OSError("Synthetic pin replacement failure")


def _unsigned_pins_and_untrusted_key(tmp_path: Path, trust: Path) -> tuple[Path, Path]:
    """Unsigned v2 pins plus a signing key whose public key this trust store lacks."""
    pins = tmp_path / "pins.yaml"
    PinStore(pins, unsigned=True, trusted_keys_path=trust).pin_server("fixture", [TOOL])
    key = generate_keypair(tmp_path / "keys", tmp_path / "staging-trust.json").private_key_path
    return pins, key


@pytest.mark.parametrize("operation", ["pin_server", "resign"])
def test_failed_signed_upgrade_keeps_old_expectation(
    tmp_path: Path, trust: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    pins, key = _unsigned_pins_and_untrusted_key(tmp_path, trust)
    before = pins.read_bytes()
    signer = PinStore(pins, signing_key=key, trusted_keys_path=trust)
    monkeypatch.setattr(signer, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        if operation == "pin_server":
            signer.pin_server("fixture", [TOOL])
        else:
            signer.resign()
    assert pins.read_bytes() == before
    assert not signature_required("fixture", trust)
    reopened = PinStore(pins, trusted_keys_path=trust).verification("fixture")
    assert reopened is not None and reopened.state == "unsigned"


@pytest.mark.parametrize("operation", ["pin_server", "rotate_key"])
def test_failed_signed_rewrite_keeps_trust_state(
    signed_store: PinStore, trust: Path, key_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    pins_before = signed_store.path.read_bytes()
    servers_before = json.loads(trust.read_text())["servers"]
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    monkeypatch.setattr(store, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        if operation == "pin_server":
            store.pin_server("fixture", [TOOL])
        else:
            store.rotate_key()
    assert signed_store.path.read_bytes() == pins_before
    # Neither the expectation nor the rollback high-water mark moved.
    assert json.loads(trust.read_text())["servers"] == servers_before


def test_successful_resign_records_expectation_after_write(tmp_path: Path, trust: Path) -> None:
    from mcp_audit.pin_signing import trust_key

    pins, key = _unsigned_pins_and_untrusted_key(tmp_path, trust)
    PinStore(pins, signing_key=key, trusted_keys_path=trust).resign()
    assert signature_required("fixture", trust)
    pinned_at = yaml.safe_load(pins.read_text())["servers"]["fixture"]["pinned_at"]
    assert json.loads(trust.read_text())["servers"]["fixture"]["last_seen_pinned_at"] == pinned_at.replace(
        "+00:00", "Z"
    )
    trust_key(key.with_suffix(".pub").read_text().strip(), trust)
    assert PinStore(pins, trusted_keys_path=trust).verification("fixture").state == "verified"  # type: ignore[union-attr]


def test_explicit_clear_is_the_recovery_path_for_a_deleted_entry(
    signed_store: PinStore, trust: Path, key_path: Path
) -> None:
    _edit(signed_store.path, lambda d: _servers(d).pop("fixture"))
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    with pytest.raises(PinSigningError, match="untrusted pin baseline|listed in the manifest are missing"):
        store.pin_server("fixture", [TOOL])
    store.remove_server("fixture")
    assert not signature_required("fixture", trust)
    assert "fixture" not in json.loads(trust.read_text())["servers"]
    store.pin_server("fixture", [TOOL])
    assert signature_required("fixture", trust)
    assert PinStore(signed_store.path, trusted_keys_path=trust).verification("fixture").state == "verified"  # type: ignore[union-attr]


def test_failed_clear_write_keeps_expectation(
    signed_store: PinStore, trust: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PinStore(signed_store.path, trusted_keys_path=trust)
    monkeypatch.setattr(store, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        store.remove_server("fixture")
    assert signature_required("fixture", trust)


def test_policy_opens_default_store_for_pin_integrity_gate(
    signed_store: PinStore, trust: Path, config: ServerConfig, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import pin_signing

    _edit(signed_store.path, lambda d: _servers(d).pop("fixture"))
    monkeypatch.setattr(pinning, "DEFAULT_PIN_PATH", signed_store.path)
    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", trust)
    report = _skipped_report(config)
    result = evaluate_policy(report, _policy(tmp_path, "fail_on:\n  pin_integrity: true\n"))  # type: ignore[arg-type]
    assert [v.rule for v in result.violations] == ["fail_on.pin_integrity"]


# --- Public-key-only CI: a fresh trust store holds only the trusted public key.


@pytest.fixture
def ci_trust(tmp_path: Path, key_path: Path) -> Path:
    from mcp_audit.pin_signing import trust_key

    path = tmp_path / "ci-trust.json"
    trust_key(key_path.with_suffix(".pub").read_text().strip(), path)
    assert not signature_required("fixture", path)
    return path


def test_public_key_only_ci_rejects_fully_stripped_signature(
    signed_store: PinStore,
    ci_trust: Path,
    config: ServerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malicious = TOOL.model_copy(update={"description": "Attacker surface"})

    def strip(data: dict[str, object]) -> None:
        entry = _servers(data)["fixture"]
        for key in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
            entry.pop(key)
        tool = entry["tools"]["list_items"]  # type: ignore[index]
        tool["hash"] = signed_store.compute_hash(malicious)
        tool["snapshot"] = signed_store._tool_snapshot(malicious)

    _edit(signed_store.path, strip)
    # One-shot CI: no earlier verification ever recorded a per-server expectation.
    assert not signature_required("fixture", ci_trust)
    loaded = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    assert loaded.verification("fixture").state == "tampered_entry"  # type: ignore[union-attr]
    assert not loaded.baseline_trusted("fixture")
    report = _scan(monkeypatch, signed_store.path, ci_trust, config, [malicious], pin_check=True)
    assert [f.rule_id for f in report.audits[0].pin_integrity_findings] == ["MCP027"]
    assert "pin_unsigned" not in {w.code for w in report.warnings}
    policy = _policy(tmp_path, "fail_on:\n  pin_integrity: true\n")
    assert not evaluate_policy(report, policy).passed  # type: ignore[arg-type]


def test_public_key_only_ci_still_warns_for_genuine_v1(signed_store: PinStore, ci_trust: Path) -> None:
    # A genuine legacy file predates signing: no signed entries and no manifest.
    def legacy_file(data: dict[str, object]) -> None:
        _legacy_substitute(data)
        data.pop("manifest")

    _edit(signed_store.path, legacy_file)
    loaded = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    assert loaded.verification("fixture").state == "schema_outdated"  # type: ignore[union-attr]
    assert loaded.baseline_trusted("fixture")
    assert [w.code for w in loaded.schema_warnings("fixture")] == ["pin_schema_outdated"]


def test_v1_markers_cannot_launder_a_stripped_v2_entry(signed_store: PinStore, ci_trust: Path) -> None:
    def downgrade(data: dict[str, object]) -> None:
        entry = _servers(data)["fixture"]
        for key in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
            entry.pop(key)
        for tool in entry["tools"].values():  # type: ignore[attr-defined]
            tool["pin_schema"] = 1

    _edit(signed_store.path, downgrade)
    loaded = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    assert loaded.verification("fixture").state == "tampered_entry"  # type: ignore[union-attr]
    assert loaded.schema_warnings("fixture") == []


def test_unsigned_v2_still_warns_without_trusted_keys(tmp_path: Path) -> None:
    trust = tmp_path / "empty-trust.json"
    store = PinStore(tmp_path / "pins.yaml", unsigned=True, trusted_keys_path=trust)
    store.pin_server("fixture", [TOOL])
    assert store.verification("fixture").state == "unsigned"  # type: ignore[union-attr]
    assert store.baseline_trusted("fixture")


def test_keys_retired_past_grace_do_not_require_signatures(
    tmp_path: Path, trust: Path, key_path: Path
) -> None:
    from datetime import UTC, datetime, timedelta

    from mcp_audit.pin_signing import has_active_trusted_key

    data = json.loads(trust.read_text())
    (record,) = data["keys"].values()
    record["retired_at"] = "2020-01-01T00:00:00Z"
    record["grace_days"] = 30
    trust.write_text(json.dumps(data))
    assert not has_active_trusted_key(trust)
    assert has_active_trusted_key(trust, now=datetime(2020, 1, 15, tzinfo=UTC))
    assert not has_active_trusted_key(trust, now=datetime(2020, 1, 1, tzinfo=UTC) + timedelta(days=31))


@pytest.mark.parametrize("unsigned", [False, True])
def test_unsigned_writes_are_refused_while_keys_are_trusted(
    tmp_path: Path, ci_trust: Path, unsigned: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import pin_signing

    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", tmp_path / "ci-host" / "pin-signing.key")
    pins = tmp_path / "ci-pins.yaml"
    # A CI host holds only the public key; the default private key path is absent.
    store = PinStore(pins, unsigned=unsigned, trusted_keys_path=ci_trust)
    with pytest.raises(PinSigningError, match="Trusted pin keys exist"):
        store.pin_server("fixture", [TOOL])
    assert not pins.exists()


# --- Rollback: the high-water mark advances on every successful signed write.


def test_restoring_an_older_signed_pin_after_repin_warns(
    signed_store: PinStore, trust: Path, key_path: Path, monkeypatch: pytest.MonkeyPatch, config: ServerConfig
) -> None:
    older = signed_store.path.read_bytes()
    first = yaml.safe_load(older)["servers"]["fixture"]["pinned_at"]
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    store.pin_server("fixture", [TOOL.model_copy(update={"description": "Tighter surface"})], config)
    second = yaml.safe_load(signed_store.path.read_text())["servers"]["fixture"]["pinned_at"]
    assert second > first
    assert json.loads(trust.read_text())["servers"]["fixture"]["last_seen_pinned_at"] == second.replace(
        "+00:00", "Z"
    )
    # No scan verified the newer pin; restoring the older file must still be noticed.
    signed_store.path.write_bytes(older)
    restored = PinStore(signed_store.path, trusted_keys_path=trust)
    assert restored.verification("fixture").state == "verified"  # type: ignore[union-attr]
    assert "pin_rolled_back" in {w.code for w in restored.verification_warnings("fixture")}
    report = _scan(monkeypatch, signed_store.path, trust, config, [TOOL], pin_check=True)
    assert "pin_rolled_back" in {w.code for w in report.warnings}


def test_failed_signed_write_does_not_advance_high_water(
    signed_store: PinStore, trust: Path, key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = json.loads(trust.read_text())["servers"]["fixture"]["last_seen_pinned_at"]
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    monkeypatch.setattr(store, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        store.pin_server("fixture", [TOOL])
    assert json.loads(trust.read_text())["servers"]["fixture"]["last_seen_pinned_at"] == before
    reopened = PinStore(signed_store.path, trusted_keys_path=trust)
    assert reopened.verification("fixture").state == "verified"  # type: ignore[union-attr]
    assert reopened.verification_warnings("fixture") == []


# --- Retired-key grace values never crash verification.


@pytest.mark.parametrize(
    ("retired_at", "grace_days"),
    [
        ("2026-01-01T00:00:00Z", 3_000_000),
        ("2026-01-01T00:00:00Z", -1),
        ("2026-01-01T00:00:00Z", "30"),
        ("9999-12-31T00:00:00Z", 30),
    ],
)
def test_invalid_retired_key_grace_fails_closed_without_crashing(
    signed_store: PinStore,
    trust: Path,
    config: ServerConfig,
    monkeypatch: pytest.MonkeyPatch,
    retired_at: str,
    grace_days: object,
) -> None:
    data = json.loads(trust.read_text())
    (record,) = data["keys"].values()
    record["retired_at"] = retired_at
    record["grace_days"] = grace_days
    trust.write_text(json.dumps(data))
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    verification = loaded.verification("fixture")
    assert verification is not None and verification.state == "untrusted_signer"
    assert "grace period is invalid" in loaded.verification_message("fixture")
    report = _scan(monkeypatch, signed_store.path, trust, config, [TOOL], pin_check=True)
    assert [f.rule_id for f in report.audits[0].pin_integrity_findings] == ["MCP027"]


def test_rotation_refuses_unbounded_grace_before_touching_keys(
    signed_store: PinStore, key_path: Path
) -> None:
    from mcp_audit.pin_signing import MAX_GRACE_DAYS

    key_before = key_path.read_bytes()
    with pytest.raises(ValueError, match="grace_days must be at most"):
        signed_store.rotate_key(grace_days=MAX_GRACE_DAYS + 1)
    assert key_path.read_bytes() == key_before


# --- Round 4: mixed baselines through rotation, v1 rewrites in CI, rollback on write failure.


def _resign_manifest(store: PinStore, data: dict[str, object], key_path: Path) -> None:
    """Re-sign the document manifest after a test re-signs an entry by hand."""
    forger = PinStore(store.path, signing_key=key_path, trusted_keys_path=store._trusted_keys_path)
    forger._data = data
    forger._sign_manifest()


def _signed_mixed_entry(signed_store: PinStore, key_path: Path, server: str = "fixture") -> None:
    """A signed server entry holding one v2 row and one retained legacy v1 row."""
    from mcp_audit.pin_signing import sign_document

    def mix(data: dict[str, object]) -> None:
        entry = _servers(data)[server]
        for key in ("signature", "signer", "surface_sha256", "canonical_bytes_len"):
            entry.pop(key)
        entry["tools"]["legacy_tool"] = {  # type: ignore[index]
            "hash": "sha256:" + "1" * 64,
            "pinned_at": "2020-01-01T00:00:00+00:00",
            "snapshot": {"description": "Legacy", "input_schema": None},
        }
        entry.update(sign_document(signed_store._server_document(server, entry), key_path))
        _resign_manifest(signed_store, data, key_path)

    _edit(signed_store.path, mix)
    loaded = PinStore(signed_store.path, trusted_keys_path=signed_store._trusted_keys_path)
    assert loaded.legacy_tool_names(server) == {"legacy_tool"}
    assert loaded.verification(server).state == "verified"  # type: ignore[union-attr]


def test_signed_mixed_entry_survives_rotation_past_grace(
    signed_store: PinStore, trust: Path, key_path: Path
) -> None:
    _signed_mixed_entry(signed_store, key_path)
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    store.rotate_key(grace_days=0)  # the old key is past grace immediately
    entry = yaml.safe_load(signed_store.path.read_text())["servers"]["fixture"]
    assert entry["tools"]["legacy_tool"]["hash"] == "sha256:" + "1" * 64
    assert entry["tools"]["legacy_tool"].get("pin_schema", 1) == 1
    reopened = PinStore(signed_store.path, trusted_keys_path=trust)
    assert reopened.verification("fixture").state == "verified"  # type: ignore[union-attr]


def test_resign_moves_signed_mixed_entry_to_the_active_key(
    signed_store: PinStore, trust: Path, key_path: Path, tmp_path: Path
) -> None:
    from mcp_audit.pin_signing import trust_key

    _signed_mixed_entry(signed_store, key_path)
    old_kid = yaml.safe_load(signed_store.path.read_text())["servers"]["fixture"]["signature"]["kid"]
    replacement = generate_keypair(tmp_path / "replacement-keys", tmp_path / "replacement-trust.json")
    trust_key(replacement.public_key, trust)
    PinStore(signed_store.path, signing_key=replacement.private_key_path, trusted_keys_path=trust).resign()
    entry = yaml.safe_load(signed_store.path.read_text())["servers"]["fixture"]
    assert entry["signature"]["kid"] == replacement.kid != old_kid
    assert entry["tools"]["legacy_tool"]["hash"] == "sha256:" + "1" * 64


@pytest.mark.parametrize("strip_manifest", [True, False])
def test_public_key_only_ci_withholds_a_v1_rewrite_without_mcp027(
    signed_store: PinStore,
    ci_trust: Path,
    config: ServerConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    strip_manifest: bool,
) -> None:
    malicious = TOOL.model_copy(update={"description": "Attacker surface"})

    def rewrite(data: dict[str, object]) -> None:
        _servers(data)["fixture"] = {
            "tools": {
                "list_items": {
                    "hash": signed_store.compute_hash(malicious),
                    "pinned_at": "2020-01-01T00:00:00+00:00",
                }
            }
        }
        if strip_manifest:
            data.pop("manifest")

    _edit(signed_store.path, rewrite)
    assert not signature_required("fixture", ci_trust)
    loaded = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    if not strip_manifest:
        # The signed manifest lists the server: a v1 rewrite is a downgrade (MCP027).
        assert loaded.verification("fixture").state == "tampered_entry"  # type: ignore[union-attr]
        assert "does not match the signed manifest" in loaded.verification_message("fixture")
        report = _scan(monkeypatch, signed_store.path, ci_trust, config, [malicious], pin_check=True)
        assert [f.rule_id for f in report.audits[0].pin_integrity_findings] == ["MCP027"]
        return
    assert loaded.verification("fixture").state == "schema_outdated"  # type: ignore[union-attr]
    assert loaded.baseline_trusted("fixture")  # D8: v1 warns, never MCP027
    assert not loaded.baseline_usable("fixture")
    assert loaded.check_drift("fixture", [TOOL]) == []
    assert loaded.baseline_tools("fixture") == []
    assert loaded.canary_baseline("fixture") is None
    assert loaded.tool_count("fixture") == 0

    report = _scan(monkeypatch, signed_store.path, ci_trust, config, [malicious], pin_check=True)
    audit = report.audits[0]
    assert audit.pin_integrity_findings == []
    codes = {(w.code, w.check) for w in report.warnings}
    assert ("pin_schema_outdated", "pin_check") in codes
    assert ("pin_baseline_withheld", "pin_check") in codes
    policy = _policy(tmp_path, "fail_on:\n  drift: true\nrequire:\n  pins:\n    servers: [fixture]\n")
    result = evaluate_policy(report, policy, pin_store=loaded)  # type: ignore[arg-type]
    assert not result.passed
    assert {"require.pins", "fail_on.drift"} <= {v.rule for v in result.violations}


def test_v1_entry_with_recorded_high_water_is_a_downgrade(tmp_path: Path) -> None:
    trust = tmp_path / "history-only-trust.json"
    trust.write_text(
        json.dumps({"keys": {}, "servers": {"fixture": {"last_seen_pinned_at": "2026-01-01T00:00:00Z"}}})
    )
    trust.chmod(0o600)
    pins = tmp_path / "pins.yaml"
    pins.write_text(yaml.safe_dump({"servers": {}}))
    _edit(pins, _legacy_substitute)
    loaded = PinStore(pins, trusted_keys_path=trust)
    assert loaded.verification("fixture").state == "tampered_entry"  # type: ignore[union-attr]
    assert loaded.schema_warnings("fixture") == []


def test_genuine_v1_without_keys_is_unchanged(tmp_path: Path) -> None:
    pins = tmp_path / "pins.yaml"
    pins.write_text(yaml.safe_dump({"servers": {}}))
    _edit(pins, _legacy_substitute)
    loaded = PinStore(pins, trusted_keys_path=tmp_path / "no-trust.json")
    assert loaded.verification("fixture").state == "schema_outdated"  # type: ignore[union-attr]
    assert loaded.baseline_usable("fixture")
    assert loaded.tool_count("fixture") == 1
    assert [f.status.value for f in loaded.check_drift("fixture", [TOOL])] == ["changed"]
    assert [w.code for w in loaded.schema_warnings("fixture")] == ["pin_schema_outdated"]


@pytest.mark.parametrize("failure", [OSError, PinSigningError])
def test_rollback_is_reported_when_the_trust_store_write_fails(
    signed_store: PinStore,
    trust: Path,
    config: ServerConfig,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[Exception],
) -> None:
    from mcp_audit import pin_signing

    data = json.loads(trust.read_text())
    data["servers"]["fixture"]["last_seen_pinned_at"] = "2099-01-01T00:00:00Z"
    trust.write_text(json.dumps(data))

    def fail_write(path: Path, value: object) -> None:
        raise failure("Synthetic trust-store write failure")

    monkeypatch.setattr(pin_signing, "_write_json", fail_write)
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    assert loaded.verification("fixture").state == "verified"  # type: ignore[union-attr]
    codes = [w.code for w in loaded.verification_warnings("fixture")]
    assert "pin_rolled_back" in codes
    assert "pin_rollback_tracking_unavailable" in codes
    report = _scan(monkeypatch, signed_store.path, trust, config, [TOOL], pin_check=True)
    assert "pin_rolled_back" in {w.code for w in report.warnings}


# --- Refresh review must never present a withheld or untrusted baseline as a clean match.


def _refresh_cli(
    monkeypatch: pytest.MonkeyPatch, pin_file: Path, tools: list[ToolInfo], *extra: str
) -> tuple[int, str]:
    from click.testing import CliRunner

    from mcp_audit import cli, pin_cli

    audit = ServerAudit(server=make_server_config(name="fixture"), connection_status="connected", tools=tools)
    report = _skipped_report(audit.server).model_copy(update={"audits": [audit]})

    async def fake_run_scan(*args: object, **kwargs: object) -> AuditReport:
        return report

    monkeypatch.setattr(pin_cli, "run_scan", fake_run_scan)
    result = CliRunner().invoke(
        cli.main, ["pin", "--refresh", "fixture", "--pin-file", str(pin_file), *extra]
    )
    return result.exit_code, result.output


@pytest.fixture
def legacy_pin_with_trusted_key(tmp_path: Path) -> Path:
    """A genuine v1 pin for tool ``status`` while the default trust store holds a key."""
    from mcp_audit import pin_signing

    generate_keypair(pin_signing.DEFAULT_SIGNING_KEY_PATH.parent, pin_signing.DEFAULT_TRUSTED_KEYS_PATH)
    pins = tmp_path / "legacy-pins.yaml"
    pins.write_text(
        yaml.safe_dump(
            {
                "servers": {
                    "fixture": {
                        "tools": {
                            "status": {
                                "hash": "sha256:" + "2" * 64,
                                "pinned_at": "2020-01-01T00:00:00+00:00",
                                "snapshot": {"description": "Status", "input_schema": None},
                            }
                        }
                    }
                }
            }
        )
    )
    store = PinStore(pins)
    assert store.unverified_legacy_baseline("fixture")
    return pins


def test_refresh_reviews_withheld_legacy_baseline_instead_of_clean_match(
    legacy_pin_with_trusted_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = [ToolInfo(name="status_v2", description="Status v2")]
    code, output = _refresh_cli(monkeypatch, legacy_pin_with_trusted_key, live)
    assert code == 0, output
    assert "No drift found" not in output
    assert "unverified legacy (v1) baseline" in output
    assert "1 new, 0 changed, 1 removed" in output

    code, output = _refresh_cli(monkeypatch, legacy_pin_with_trusted_key, live, "--json")
    payload = json.loads(output)
    assert payload["drift_counts"]["new"] == 1 and payload["drift_counts"]["removed"] == 1
    assert payload["baseline_verified"] is False
    assert "unverified legacy" in payload["baseline_note"]
    # Scan semantics are unchanged: the baseline is still withheld there.
    assert PinStore(legacy_pin_with_trusted_key).check_drift("fixture", live) == []


def test_refresh_never_claims_a_match_against_an_unverified_baseline(
    legacy_pin_with_trusted_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = PinStore(legacy_pin_with_trusted_key)
    status = ToolInfo(name="status", description="Status")
    _edit(
        legacy_pin_with_trusted_key,
        lambda d: _servers(d)["fixture"]["tools"]["status"].update(  # type: ignore[index]
            hash=store.check_drift("fixture", [status], review_unverified_legacy=True)[0].current_hash
        ),
    )
    assert (
        PinStore(legacy_pin_with_trusted_key).check_drift("fixture", [status], review_unverified_legacy=True)
        == []
    )
    code, output = _refresh_cli(monkeypatch, legacy_pin_with_trusted_key, [status])
    assert code == 0, output
    assert "No drift found" not in output
    assert "could not be verified" in output


def test_refresh_apply_replaces_legacy_rows_with_signed_live_surface(
    legacy_pin_with_trusted_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    live = [ToolInfo(name="status_v2", description="Status v2")]
    code, output = _refresh_cli(monkeypatch, legacy_pin_with_trusted_key, live, "--apply")
    assert code == 0, output
    store = PinStore(legacy_pin_with_trusted_key)
    assert store.verification("fixture").state == "verified"  # type: ignore[union-attr]
    assert set(yaml.safe_load(legacy_pin_with_trusted_key.read_text())["servers"]["fixture"]["tools"]) == {
        "status_v2"
    }


def test_refresh_of_tampered_baseline_is_still_refused(
    signed_store: PinStore, trust: Path, key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import pin_signing

    monkeypatch.setattr(pin_signing, "DEFAULT_TRUSTED_KEYS_PATH", trust)
    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", key_path)
    _edit(
        signed_store.path,
        lambda d: _servers(d)["fixture"]["tools"]["list_items"].update(  # type: ignore[index]
            hash="sha256:" + "3" * 64
        ),
    )
    before = signed_store.path.read_bytes()
    code, output = _refresh_cli(monkeypatch, signed_store.path, [TOOL], "--apply")
    assert "No drift found" not in output
    assert "fails signature verification" in output
    assert signed_store.path.read_bytes() == before
    code, output = _refresh_cli(monkeypatch, signed_store.path, [TOOL], "--json", "--apply")
    payload = json.loads(output)
    assert payload["applied"] is False and "fails signature verification" in payload["error"]
    assert signed_store.path.read_bytes() == before


def test_status_reports_verification_and_withheld_baselines(
    legacy_pin_with_trusted_key: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from click.testing import CliRunner

    from mcp_audit import cli, pin_cli

    result = CliRunner().invoke(
        cli.main, ["pin", "--status", "--json", "--pin-file", str(legacy_pin_with_trusted_key)]
    )
    server = json.loads(result.output)["servers"][0]
    assert server["verification"] == "schema_outdated"
    assert server["baseline_usable"] is False
    monkeypatch.setattr(pin_cli.console, "width", 240)
    result = CliRunner().invoke(cli.main, ["pin", "--status", "--pin-file", str(legacy_pin_with_trusted_key)])
    assert "schema_outdated (withheld)" in result.output


# --- Signed document manifest: deleted, renamed, or spliced signed entries in keys-only CI.


def _manifest_attack_rename(pins: Path) -> str:
    _edit(pins, _rename("fixture-old"))
    return "fixture"


def _manifest_attack_empty(pins: Path) -> str:
    _edit(pins, lambda d: d.update(servers={}))
    return "fixture"


def _manifest_attack_delete_manifest(pins: Path) -> str:
    _edit(pins, lambda d: d.pop("manifest"))
    return "fixture"


def _manifest_attack_splice(pins: Path) -> str:
    """Copy a validly signed entry for another server from a different pin file."""
    other = PinStore(
        pins.with_name("other-pins.yaml"),
        signing_key=pins.parent / "keys" / "pin-signing.key",
        trusted_keys_path=pins.parent / "trusted.json",
    )
    other.pin_server("other", [TOOL])
    spliced = yaml.safe_load(other.path.read_text())["servers"]["other"]
    _edit(pins, lambda d: _servers(d).update(other=spliced))
    return "other"


@pytest.mark.parametrize(
    "attack",
    [
        _manifest_attack_rename,
        _manifest_attack_empty,
        _manifest_attack_delete_manifest,
        _manifest_attack_splice,
    ],
    ids=["renamed", "servers_emptied", "manifest_deleted", "spliced_entry"],
)
def test_keys_only_ci_detects_manifest_attacks(
    signed_store: PinStore,
    ci_trust: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: Callable[[Path], str],
) -> None:
    assert "manifest" in yaml.safe_load(signed_store.path.read_text())
    target = attack(signed_store.path)
    assert not signature_required(target, ci_trust)  # keys-only: no per-server expectation
    loaded = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    assert loaded.verification(target).state == "tampered_entry"  # type: ignore[union-attr]
    config = make_server_config(name=target, command=None, args=[str(tmp_path / "server.py")])
    report = _scan(
        monkeypatch, signed_store.path, ci_trust, config, [TOOL], skip_connect=True, integrity_check=True
    )
    assert [f.rule_id for f in report.audits[0].pin_integrity_findings] == ["MCP027"]
    result = evaluate_policy(report, load_policy(Path("examples/policies/integrity-aware-ci.yaml")))
    assert not result.passed
    assert "fail_on.pin_integrity" in {v.rule for v in result.violations}


def test_manifest_lists_signed_entries_with_digests(signed_store: PinStore, ci_trust: Path) -> None:
    data = yaml.safe_load(signed_store.path.read_text())
    assert data["manifest"]["servers"] == {"fixture": data["servers"]["fixture"]["surface_sha256"]}
    assert PinStore(signed_store.path, trusted_keys_path=ci_trust).verification("fixture").state == "verified"  # type: ignore[union-attr]
    unpinned = PinStore(signed_store.path, trusted_keys_path=ci_trust)
    assert unpinned.verification("never-pinned") is None


def test_clear_re_signs_the_manifest_without_the_server(
    signed_store: PinStore, ci_trust: Path, key_path: Path, trust: Path
) -> None:
    PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust).remove_server("fixture")
    data = yaml.safe_load(signed_store.path.read_text())
    assert data["manifest"]["servers"] == {}
    assert PinStore(signed_store.path, trusted_keys_path=ci_trust).verification("fixture") is None


def test_clear_without_a_signing_key_is_refused_while_keys_are_trusted(
    signed_store: PinStore, ci_trust: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit import pin_signing

    monkeypatch.setattr(pin_signing, "DEFAULT_SIGNING_KEY_PATH", tmp_path / "ci-host" / "pin-signing.key")
    before = signed_store.path.read_bytes()
    with pytest.raises(PinSigningError, match="signing key is required"):
        PinStore(signed_store.path, trusted_keys_path=ci_trust).remove_server("fixture")
    assert signed_store.path.read_bytes() == before


def test_writes_refuse_a_manifest_listing_a_deleted_entry(
    signed_store: PinStore, trust: Path, key_path: Path
) -> None:
    _edit(signed_store.path, lambda d: _servers(d).pop("fixture"))
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    for write in (lambda: store.pin_server("another", [TOOL]), store.resign):
        with pytest.raises(PinSigningError, match="listed in the manifest are missing: fixture"):
            write()


def test_manifest_is_ignored_without_trusted_keys(tmp_path: Path) -> None:
    store = PinStore(tmp_path / "pins.yaml", unsigned=True, trusted_keys_path=tmp_path / "no-trust.json")
    store.pin_server("fixture", [TOOL])
    assert "manifest" not in yaml.safe_load(store.path.read_text())
    reopened = PinStore(store.path, trusted_keys_path=tmp_path / "no-trust.json").verification("fixture")
    assert reopened is not None and reopened.state == "unsigned"


# --- Canary: a trusted mixed baseline still compares its signed v2 rows.


def test_mixed_entry_canary_baseline_uses_v2_rows(
    signed_store: PinStore, trust: Path, key_path: Path
) -> None:
    from mcp_audit.pinning import CANARY_UNCOVERED_TOOLS_KEY

    _signed_mixed_entry(signed_store, key_path)
    PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust).rotate_key(grace_days=0)
    loaded = PinStore(signed_store.path, trusted_keys_path=trust)
    assert loaded.verification("fixture").state == "verified"  # type: ignore[union-attr]
    baseline = loaded.canary_baseline("fixture")
    assert baseline is not None
    assert set(baseline["tools"]) == {"list_items"}
    assert set(baseline[CANARY_UNCOVERED_TOOLS_KEY]) == {"legacy_tool"}


@pytest.mark.anyio
async def test_canary_detects_changed_v2_row_of_rotated_mixed_entry(
    tmp_path: Path, trust: Path, key_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from mcp_audit.connector import ServerConnector

    fixture = str(Path(__file__).parent / "fixtures" / "identity_canary_server.py")
    pins = tmp_path / "canary-pins.yaml"
    trace = tmp_path / "events.jsonl"
    config = make_server_config(command=sys.executable, args=[fixture, "stable", str(trace)])
    store = PinStore(pins, signing_key=key_path, trusted_keys_path=trust)
    listed = await ServerConnector(timeout=15).connect(config)
    assert listed.connection_status == "connected"
    store.pin_server(config.name, listed.tools)
    _signed_mixed_entry(store, key_path, server=config.name)
    PinStore(pins, signing_key=key_path, trusted_keys_path=trust).rotate_key(grace_days=0)
    monkeypatch.setattr(pinning, "PinStore", lambda *args, **kwargs: PinStore(pins, trusted_keys_path=trust))
    config.args[1] = "flipped"
    report = await run_scan(ScanOptions(canary_check=True, timeout=15), servers=[config])
    audit = report.audits[0]
    assert audit.pin_verification is not None and audit.pin_verification.state == "verified"
    assert audit.canary is not None and audit.canary.baseline_source == "pin"
    pinned = [f for f in audit.drift_findings if f.after_call == 0]
    assert pinned and all(f.tool_name != "legacy_tool" for f in pinned)
    assert any(f.field_changes and f.field_changes[0].path == "/description" for f in pinned)
