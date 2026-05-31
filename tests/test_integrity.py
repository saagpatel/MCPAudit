"""Unit tests for the IntegrityAnalyzer (on-disk launch-artifact hash drift).

Covers:
  - hash_file / resolve_artifact_hashes over real temp files
  - No baseline / empty baseline (None) -> no findings
  - Unchanged artifact -> no findings
  - Changed bytes -> MCP024 HIGH
  - Missing artifact -> MCP024 MEDIUM
  - Finding model fields / JSON serialisation

Behaviours are exercised against real files on disk (no mocking of hashing),
mirroring how the detector runs at scan time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_audit.integrity import (
    IntegrityAnalyzer,
    hash_file,
    resolve_artifact_hashes,
)
from mcp_audit.models import (
    ClientType,
    IntegrityKind,
    IntegritySeverity,
    ServerConfig,
    TransportType,
)

_analyzer = IntegrityAnalyzer()


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
