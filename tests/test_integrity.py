"""Unit tests for the IntegrityAnalyzer (on-disk launch-artifact hash drift).

Covers:
  - hash_file / resolve_artifact_hashes over real temp files
  - No baseline / empty baseline (None) -> no findings
  - Unchanged artifact -> no findings
  - Changed bytes -> MCP024 HIGH
  - Missing artifact -> MCP024 MEDIUM
  - Finding model fields / JSON serialisation

Behaviours are exercised against real files on disk. Exclusion regressions
also guard hashing calls to prove protected files are never read.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from mcp_audit import integrity, pinning
from mcp_audit.engine import ScanOptions, run_scan
from mcp_audit.integrity import (
    _MAX_ARTIFACT_BYTES,
    IntegrityAnalyzer,
    hash_file,
    resolve_artifact_hashes,
)
from mcp_audit.models import (
    ClientType,
    IntegrityKind,
    IntegritySeverity,
    ScanWarning,
    ServerConfig,
    TransportType,
)
from mcp_audit.pinning import PinStore
from tests.conftest import make_server_config, make_tool

_analyzer = IntegrityAnalyzer()


@pytest.mark.anyio
@pytest.mark.parametrize("via_path", [False, True], ids=["absolute-command", "path-lookup"])
async def test_pinned_command_rewrite_is_high_in_run_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, via_path: bool
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    binary = tmp_path / "fixture-server"
    before = b"#!/bin/sh\nexit 0\n"
    after = b"#!/bin/sh\nexit 1\n"
    binary.write_bytes(before)
    binary.chmod(0o700)
    if via_path:
        monkeypatch.setenv("PATH", str(tmp_path))
    config = make_server_config(name="fixture", command=binary.name if via_path else str(binary))
    # PinStore's default path is bound at import time; redirect the engine's
    # factory as well as HOME before any store is opened. No command is launched.
    pin_file = tmp_path / "pins.yaml"
    monkeypatch.setattr(pinning, "PinStore", lambda: PinStore(path=pin_file))
    store = PinStore(path=pin_file)
    store.pin_server(config.name, [make_tool("status")], config)
    path = str(binary.resolve())
    assert store.baseline_artifacts(config.name) == {path: hashlib.sha256(before).hexdigest()}
    clean = await run_scan(ScanOptions(skip_connect=True, integrity_check=True), servers=[config])
    assert not clean.audits[0].integrity_findings
    assert [warning.code for warning in clean.warnings] == ["pin_unsigned"]

    binary.write_bytes(after)
    report = await run_scan(ScanOptions(skip_connect=True, integrity_check=True), servers=[config])
    assert [warning.code for warning in report.warnings] == ["pin_unsigned"]
    findings = report.audits[0].integrity_findings
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "MCP024" and finding.severity == IntegritySeverity.HIGH
    assert finding.artifact_path == path and path in finding.summary
    assert finding.baseline_hash == hashlib.sha256(before).hexdigest()
    assert finding.current_hash == hashlib.sha256(after).hexdigest()


@pytest.mark.anyio
@pytest.mark.parametrize("include_safe", [False, True], ids=["excluded-only", "mixed-baseline"])
@pytest.mark.parametrize(
    "path_kind",
    ["gh", "dotfile", "alias-to-gh", "sensitive-alias-to-public", "missing-gh", "unresolvable"],
)
async def test_existing_pin_exclusions_never_hash_or_export_protected_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path_kind: str, include_safe: bool
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    visible = home / "server.py"
    visible.write_bytes(b"synthetic current artifact")
    protected = home / ".config" / "gh" / "hosts.yml"
    protected.parent.mkdir(parents=True)
    protected.write_bytes(b"synthetic protected fixture")
    pinned_path = protected
    if path_kind == "dotfile":
        pinned_path = home / ".fixture-token"
        pinned_path.write_bytes(b"synthetic protected fixture")
    elif path_kind == "alias-to-gh":
        pinned_path = home / "alias"
        pinned_path.symlink_to(protected)
    elif path_kind == "sensitive-alias-to-public":
        pinned_path = protected.parent / "alias"
        pinned_path.symlink_to(visible)
    elif path_kind == "missing-gh":
        pinned_path = protected.parent / "missing.yml"
    elif path_kind == "unresolvable":
        pinned_path = home / "unresolvable"
        original_resolve = Path.resolve

        def resolve(path: Path, strict: bool = False) -> Path:
            if path == pinned_path:
                raise OSError("synthetic resolution failure")
            return original_resolve(path, strict=strict)

        monkeypatch.setattr(Path, "resolve", resolve)

    protected_baseline_hash = "a" * 64
    baseline = {str(pinned_path): protected_baseline_hash}
    if include_safe:
        baseline[str(visible)] = hashlib.sha256(b"synthetic old artifact").hexdigest()
    # Model an older on-disk pin captured before these paths were excluded.
    pin_file = tmp_path / "pins.yaml"
    pin_file.write_text(
        yaml.safe_dump(
            {"servers": {"fixture": {"tools": {}, "config_snapshot": {"artifact_hashes": baseline}}}}
        ),
        encoding="utf-8",
    )
    saved_pin = pin_file.read_bytes()
    store = PinStore(path=pin_file)
    monkeypatch.setattr(pinning, "PinStore", lambda: PinStore(path=pin_file))
    calls: list[Path] = []

    def guarded_hash(path: Path) -> str | None:
        assert include_safe and path == visible.resolve()
        calls.append(path)
        return hash_file(path)

    monkeypatch.setattr(integrity, "hash_file", guarded_hash)
    warnings: list[ScanWarning] = []
    findings = _analyzer.analyze_server("fixture", store.baseline_artifacts("fixture"), warnings=warnings)
    assert len(findings) == int(include_safe)
    assert len(warnings) == 1
    config = make_server_config(name="fixture", command="synthetic-command-not-on-path")
    report = await run_scan(ScanOptions(skip_connect=True, integrity_check=True), servers=[config])
    assert report.audits[0].integrity_findings == findings
    if include_safe:
        assert findings[0].artifact_path == str(visible)
        assert findings[0].severity == IntegritySeverity.HIGH
    assert calls == [visible.resolve()] * (2 * int(include_safe))
    assert [warning for warning in report.warnings if warning.check == "integrity_check"] == warnings
    assert [warning for warning in report.warnings if warning.check != "integrity_check"] == [
        ScanWarning(
            code="pin_unsigned",
            message=(
                "Pin for fixture is unsigned. Run `mcp-audit pin keygen`, then "
                "`pin --clear fixture` and `pin --server fixture` after review to sign it."
            ),
            check="pin_check",
            servers=["fixture"],
        )
    ]
    warning = warnings[0]
    assert warning.code == "integrity_comparison_incomplete"
    assert warning.check == "integrity_check" and warning.servers == ["fixture"]
    assert ("0 sensitive" if path_kind == "unresolvable" else "1 sensitive") in warning.message
    assert ("1 pinned path(s)" if path_kind == "unresolvable" else "0 pinned path(s)") in warning.message
    assert report.coverage["integrity_check"].state == "partial"
    assert report.coverage["integrity_check"].reason == warning.code
    exported = report.model_dump_json()
    assert str(pinned_path) not in exported
    assert protected_baseline_hash not in exported
    assert hashlib.sha256(b"synthetic protected fixture").hexdigest() not in exported
    assert pin_file.read_bytes() == saved_pin


def test_artifact_size_cap_exact_boundary(tmp_path: Path) -> None:
    # Shipped cap is 64 MiB; use literal boundaries to catch constant drift too.
    assert _MAX_ARTIFACT_BYTES == 67_108_864
    artifact = tmp_path / "boundary"
    with artifact.open("wb") as handle:
        handle.truncate(67_108_864)
    assert hash_file(artifact) == hashlib.sha256(bytes(67_108_864)).hexdigest()
    with artifact.open("ab") as handle:
        handle.write(b"x")
    assert artifact.stat().st_size == 67_108_865
    assert hash_file(artifact) is None


def _cfg(**kw: Any) -> ServerConfig:
    base: dict[str, Any] = dict(
        name="srv",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )
    base.update(kw)
    return ServerConfig(**base)


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------


class TestHashing:
    def test_hash_file_returns_stable_digest(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("print('v1')\n", encoding="utf-8")
        first = hash_file(f)
        assert first is not None and len(first) == 64
        assert hash_file(f) == first  # deterministic

    def test_hash_file_missing_returns_none(self, tmp_path: Path) -> None:
        assert hash_file(tmp_path / "nope.py") is None

    def test_resolve_artifact_hashes_includes_local_script_arg(self, tmp_path: Path) -> None:
        script = tmp_path / "server.py"
        script.write_text("print('hi')\n", encoding="utf-8")
        cfg = _cfg(command="python", args=[str(script)])
        hashes = resolve_artifact_hashes(cfg)
        # The local script path is captured; bare 'python' may or may not resolve
        # on PATH in CI, so only assert the script we control.
        assert str(script.resolve()) in hashes

    def test_size_cap_returns_none_mid_read(self, tmp_path: Path, monkeypatch: Any) -> None:
        import mcp_audit.integrity as integrity_mod

        monkeypatch.setattr(integrity_mod, "_MAX_ARTIFACT_BYTES", 8)
        oversize = tmp_path / "big"
        oversize.write_text("0123456789", encoding="utf-8")  # 10 bytes > cap
        assert hash_file(oversize) is None

    def test_sensitive_path_args_are_not_hashed(self, tmp_path: Path, monkeypatch: Any) -> None:
        # A credential file passed as a launch arg must never have even its digest
        # captured into the pin store / reports.
        monkeypatch.setenv("HOME", str(tmp_path))
        ssh_dir = tmp_path / ".ssh"
        ssh_dir.mkdir()
        key = ssh_dir / "id_ed25519"
        key.write_text("PRIVATE-KEY-BYTES", encoding="utf-8")
        cfg = _cfg(command="cat", args=[str(key)])
        hashes = resolve_artifact_hashes(cfg)
        assert str(key.resolve()) not in hashes
        assert all(".ssh" not in path for path in hashes)

    def test_home_dotfiles_and_github_credentials_are_not_hashed(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        monkeypatch.setenv("HOME", str(tmp_path))
        visible = tmp_path / "server.py"
        env_file = tmp_path / ".env"
        gh_credentials = tmp_path / ".config" / "gh" / "hosts.yml"
        for path in (visible, env_file, gh_credentials):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic fixture", encoding="utf-8")
        config = _cfg(
            command="mcp-audit-test-command-not-on-path",
            args=[str(visible), str(env_file), str(gh_credentials)],
        )

        assert resolve_artifact_hashes(config) == {str(visible.resolve()): hash_file(visible)}


# ---------------------------------------------------------------------------
# No comparison possible
# ---------------------------------------------------------------------------


class TestNoBaseline:
    def test_none_baseline_produces_no_findings(self) -> None:
        assert _analyzer.analyze_server("srv", None) == []

    def test_empty_baseline_produces_no_findings(self) -> None:
        assert _analyzer.analyze_server("srv", {}) == []


# ---------------------------------------------------------------------------
# Drift detection (MCP024)
# ---------------------------------------------------------------------------


class TestDrift:
    def test_unchanged_artifact_produces_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_text("alpha", encoding="utf-8")
        baseline = {str(f): hash_file(f)}
        assert _analyzer.analyze_server("srv", baseline) == []  # type: ignore[arg-type]

    def test_changed_bytes_is_high_mcp024(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_text("alpha", encoding="utf-8")
        baseline = {str(f): hash_file(f)}
        f.write_text("BETA-rewritten", encoding="utf-8")  # swap the artifact

        findings = _analyzer.analyze_server("srv", baseline)  # type: ignore[arg-type]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.kind == IntegrityKind.ARTIFACT_DRIFT
        assert finding.severity == IntegritySeverity.HIGH
        assert finding.rule_id == "MCP024"
        assert finding.artifact_path == str(f)
        assert finding.current_hash is not None
        assert finding.current_hash != finding.baseline_hash

    def test_missing_artifact_is_medium(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_text("alpha", encoding="utf-8")
        baseline = {str(f): hash_file(f)}
        f.unlink()  # pinned artifact vanished

        findings = _analyzer.analyze_server("srv", baseline)  # type: ignore[arg-type]
        assert len(findings) == 1
        finding = findings[0]
        assert finding.severity == IntegritySeverity.MEDIUM
        assert finding.current_hash is None


# ---------------------------------------------------------------------------
# Model / serialisation
# ---------------------------------------------------------------------------


class TestFindingModel:
    def test_finding_has_title_summary_remediation(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_text("a", encoding="utf-8")
        baseline = {str(f): hash_file(f)}
        f.write_text("b", encoding="utf-8")
        finding = _analyzer.analyze_server("srv", baseline)[0]  # type: ignore[arg-type]
        assert finding.title
        assert finding.summary
        assert finding.remediation
        assert finding.description == finding.summary

    def test_serialises_to_json(self, tmp_path: Path) -> None:
        f = tmp_path / "bin"
        f.write_text("a", encoding="utf-8")
        baseline = {str(f): hash_file(f)}
        f.write_text("b", encoding="utf-8")
        finding = _analyzer.analyze_server("srv", baseline)[0]  # type: ignore[arg-type]
        data = json.loads(finding.model_dump_json())
        assert data["kind"] == "artifact_drift"
        assert data["severity"] == "high"
        assert data["rule_id"] == "MCP024"
        assert "baseline_hash" in data and "current_hash" in data
