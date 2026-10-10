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


def test_failed_signed_upgrade_keeps_old_expectation(
    tmp_path: Path, trust: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pins = tmp_path / "pins.yaml"
    PinStore(pins, unsigned=True, trusted_keys_path=trust).pin_server("fixture", [TOOL])
    before = pins.read_bytes()
    key = generate_keypair(tmp_path / "keys", trust).private_key_path
    signer = PinStore(pins, signing_key=key, trusted_keys_path=trust)
    monkeypatch.setattr(signer, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        signer.pin_server("fixture", [TOOL])
    assert pins.read_bytes() == before
    assert not signature_required("fixture", trust)
    reopened = PinStore(pins, trusted_keys_path=trust).verification("fixture")
    assert reopened is not None and reopened.state == "unsigned"


@pytest.mark.parametrize("operation", ["resign", "rotate_key"])
def test_failed_resign_or_rotation_keeps_old_expectation(
    tmp_path: Path, trust: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    pins = tmp_path / "pins.yaml"
    PinStore(pins, unsigned=True, trusted_keys_path=trust).pin_server("fixture", [TOOL])
    before = pins.read_bytes()
    key = generate_keypair(tmp_path / "keys", trust).private_key_path
    signer = PinStore(pins, signing_key=key, trusted_keys_path=trust)
    monkeypatch.setattr(signer, "_write", _fail_write)
    with pytest.raises(OSError, match="Synthetic"):
        getattr(signer, operation)()
    assert pins.read_bytes() == before
    assert not signature_required("fixture", trust)
    reopened = PinStore(pins, trusted_keys_path=trust).verification("fixture")
    assert reopened is not None and reopened.state == "unsigned"


def test_successful_resign_records_expectation_after_write(tmp_path: Path, trust: Path) -> None:
    pins = tmp_path / "pins.yaml"
    PinStore(pins, unsigned=True, trusted_keys_path=trust).pin_server("fixture", [TOOL])
    key = generate_keypair(tmp_path / "keys", trust).private_key_path
    PinStore(pins, signing_key=key, trusted_keys_path=trust).resign()
    assert signature_required("fixture", trust)
    assert PinStore(pins, trusted_keys_path=trust).verification("fixture").state == "verified"  # type: ignore[union-attr]


def test_explicit_clear_is_the_recovery_path_for_a_deleted_entry(
    signed_store: PinStore, trust: Path, key_path: Path
) -> None:
    _edit(signed_store.path, lambda d: _servers(d).pop("fixture"))
    store = PinStore(signed_store.path, signing_key=key_path, trusted_keys_path=trust)
    with pytest.raises(PinSigningError, match="untrusted pin baseline"):
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
