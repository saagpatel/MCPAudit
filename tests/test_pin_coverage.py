"""Pin coverage and opt-in failure contracts on synthetic legacy baselines."""

from __future__ import annotations

import json
from functools import partial
from pathlib import Path

import anyio
import pytest
from click.testing import CliRunner

from mcp_audit import engine, pinning, scan_cli
from mcp_audit.cli import main
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.models import AuditReport, ServerAudit, ServerConfig, ToolInfo
from mcp_audit.pin_signing import generate_keypair
from mcp_audit.pinning import PinStore
from mcp_audit.policy import PolicyConfig, evaluate_policy, load_policy
from tests.conftest import make_server_config

FIXTURES = Path(__file__).parent / "fixtures" / "pinning"


@pytest.fixture
def legacy_store(tmp_path: Path) -> PinStore:
    path = tmp_path / "pins.yaml"
    path.write_bytes((FIXTURES / "legacy-v1.yaml").read_bytes())
    return PinStore(path)


def _scan_fixture(
    monkeypatch: pytest.MonkeyPatch,
    store: PinStore,
    *,
    skip_connect: bool = False,
    pin_check: bool = True,
    provenance_check: bool = False,
    mixed_fleet: bool = False,
) -> AuditReport:
    class Connector:
        def __init__(self, timeout: float, **transport_options: object) -> None:
            self.scan_warnings: list[object] = []

        async def connect(self, server: ServerConfig, **kwargs: object) -> ServerAudit:
            return ServerAudit(server=server, connection_status="connected", tools=[ToolInfo(name="status")])

        def skip_connect_audit(self, server: ServerConfig) -> ServerAudit:
            return ServerAudit(server=server, connection_status="skipped")

    monkeypatch.setattr(pinning, "PinStore", lambda path=None: store)
    monkeypatch.setattr(engine, "ServerConnector", Connector)
    servers = [make_server_config(name="fixture")]
    if mixed_fleet:
        servers.append(make_server_config(name="peer"))
    return anyio.run(
        partial(
            run_scan,
            ScanOptions(
                pin_file=store.path,
                skip_connect=skip_connect,
                pin_check=pin_check,
                provenance_check=provenance_check,
            ),
            servers=servers,
        )
    )


@pytest.mark.parametrize("skip_connect", [False, True])
@pytest.mark.parametrize("mixed_fleet", [False, True])
def test_withheld_pin_coverage_and_policy(
    legacy_store: PinStore,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    skip_connect: bool,
    mixed_fleet: bool,
) -> None:
    key = generate_keypair(tmp_path / "keys", tmp_path / "trusted-pin-keys.json")
    if mixed_fleet:
        writer = PinStore(legacy_store.path, signing_key=key.private_key_path)
        writer.pin_server("peer", [ToolInfo(name="status")])
    store = PinStore(legacy_store.path)
    before = store.path.read_bytes()
    report = _scan_fixture(monkeypatch, store, skip_connect=skip_connect, mixed_fleet=mixed_fleet)
    coverage = report.model_dump(mode="json")["coverage"]["pin_check"]
    assert coverage["state"] == "partial"
    assert "pin_baseline_withheld" in coverage["reason"]
    assert report.schema_version == 1
    assert report.audits[0].drift_findings == []
    warning = next(w for w in report.warnings if w.code == "pin_baseline_withheld")
    assert warning.check == "pin_check" and warning.servers == ["fixture"]
    assert "mcp-audit pin --refresh SERVER" in warning.message
    assert evaluate_policy(report, PolicyConfig()).passed
    assert evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=False)).passed
    result = evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=True))
    assert not result.passed
    (violation,) = result.violations
    assert violation.rule == "fail_on.pin_baseline_withheld"
    assert violation.server_name == "fixture" and violation.audit_index == 0
    assert violation.severity == "high"
    assert "mcp-audit pin --refresh fixture" in violation.message
    assert store.path.read_bytes() == before


def test_keyless_v1_is_withheld_and_warns(legacy_store: PinStore, monkeypatch: pytest.MonkeyPatch) -> None:
    # 3.0: a genuine v1 baseline is never compared, even without trusted keys.
    assert not legacy_store._keys_trusted()
    assert legacy_store.legacy_entry("fixture") and not legacy_store.baseline_usable("fixture")
    before = legacy_store.path.read_bytes()
    report = _scan_fixture(monkeypatch, legacy_store)
    assert report.audits[0].drift_findings == []
    assert report.audits[0].pin_integrity_findings == []
    assert report.coverage["pin_check"].state == "partial"
    assert report.coverage["pin_check"].reason == "pin_baseline_withheld"
    withheld = next(w for w in report.warnings if w.code == "pin_baseline_withheld")
    assert withheld.check == "pin_check" and withheld.servers == ["fixture"]
    assert "schema v1 pin, which is never compared" in withheld.message
    assert "mcp-audit pin --refresh SERVER" in withheld.message
    assert "3.0 will" not in withheld.message
    warning = next(w for w in report.warnings if w.code == "pin_schema_outdated")
    assert "is not compared: status" in warning.message
    assert "mcp-audit pin --refresh fixture --apply" in warning.message
    assert not evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=True)).passed
    assert legacy_store.path.read_bytes() == before


def test_other_withheld_checks_do_not_trigger_pin_gate(
    legacy_store: PinStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    generate_keypair(tmp_path / "keys", tmp_path / "trusted-pin-keys.json")
    report = _scan_fixture(monkeypatch, legacy_store, pin_check=False, provenance_check=True)
    assert any(w.code == "pin_baseline_withheld" for w in report.warnings)
    assert report.coverage["pin_check"].state == "not_requested"
    assert evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=True)).passed


def test_scan_wide_withheld_warning_triggers_pin_gate(
    legacy_store: PinStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    generate_keypair(tmp_path / "keys", tmp_path / "trusted-pin-keys.json")
    report = _scan_fixture(monkeypatch, legacy_store)
    warning = next(w for w in report.warnings if w.code == "pin_baseline_withheld")
    warning.servers = []  # The output contract defines this as the whole scan.
    result = evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=True))
    assert not result.passed
    assert [v.server_name for v in result.violations] == ["fixture"]


def test_missing_pin_is_not_a_withheld_baseline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report = _scan_fixture(monkeypatch, PinStore(tmp_path / "absent.yaml"))
    assert report.coverage["pin_check"].state == "not_run"
    assert not any(w.code == "pin_baseline_withheld" for w in report.warnings)
    assert evaluate_policy(report, PolicyConfig(fail_on_pin_baseline_withheld=True)).passed


@pytest.mark.parametrize("value", ["true", "false"])
def test_pin_withheld_policy_loads_boolean(tmp_path: Path, value: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(f"fail_on:\n  pin_baseline_withheld: {value}\n")
    assert load_policy(path).fail_on_pin_baseline_withheld is (value == "true")
    path.write_text("{}\n")
    assert not load_policy(path).fail_on_pin_baseline_withheld


@pytest.mark.parametrize("value", ['"true"', "1", "null", "[]"])
def test_pin_withheld_policy_rejects_non_boolean(tmp_path: Path, value: str) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(f"fail_on:\n  pin_baseline_withheld: {value}\n")
    with pytest.raises(ValueError, match=r"fail_on\.pin_baseline_withheld must be a boolean"):
        load_policy(path)


@pytest.mark.parametrize("enabled", [False, True])
def test_pin_withheld_policy_cli_writes_report_before_exit(
    legacy_store: PinStore, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, enabled: bool
) -> None:
    generate_keypair(tmp_path / "keys", tmp_path / "trusted-pin-keys.json")
    report = _scan_fixture(monkeypatch, legacy_store, skip_connect=True)

    async def fake_scan(options: ScanOptions, **kwargs: object) -> AuditReport:
        assert options.config_only and options.skip_connect and options.pin_check
        return report

    monkeypatch.setattr(scan_cli, "run_scan", fake_scan)
    config = tmp_path / "synthetic.json"
    config.write_text('{"mcpServers": {"fixture": {"command": "synthetic"}}}')
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"fail_on:\n  pin_baseline_withheld: {str(enabled).lower()}\n")
    output = tmp_path / "report.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--config",
            str(config),
            "--config-only",
            "--skip-connect",
            "--override-config",
            "/dev/null",
            "--pin-check",
            "--pin-file",
            str(legacy_store.path),
            "--policy",
            str(policy),
            "--json",
            str(output),
        ],
    )
    assert result.exit_code == (2 if enabled else 0), result.output
    payload = json.loads(output.read_text())
    assert payload["coverage"]["pin_check"]["state"] == "partial"
    assert payload["policy_result"]["passed"] is (not enabled)
    if enabled:
        assert payload["policy_result"]["violations"][0]["rule"] == "fail_on.pin_baseline_withheld"
