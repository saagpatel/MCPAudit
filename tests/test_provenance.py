"""Unit tests for the ProvenanceAnalyzer (launch-config / supply-chain drift).

Covers:
  - No change vs baseline → no findings
  - Command/transport swap → MCP020 HIGH
  - Argument version float → MCP021 MEDIUM
  - Dangerous flag gained → MCP021 HIGH with gained_flags
  - URL/endpoint change → MCP022 HIGH
  - Credential key-name set change → MCP023 MEDIUM (key names only)
  - Missing/old baseline (None) → no findings
  - Finding model fields / JSON serialisation

Baseline snapshots are built by hand to match PinStore._config_snapshot's shape,
so the analyzer is exercised independently of the pin store. Behaviours were
live-probed before being asserted here.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_audit.models import (
    ClientType,
    ProvenanceKind,
    ProvenanceSeverity,
    ServerConfig,
    TransportType,
)
from mcp_audit.provenance import ProvenanceAnalyzer

_analyzer = ProvenanceAnalyzer()


def _cfg(**kw: Any) -> ServerConfig:
    base: dict[str, Any] = dict(
        name="srv",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/config.json",
        transport=TransportType.STDIO,
    )
    base.update(kw)
    return ServerConfig(**base)


def _snap(cfg: ServerConfig) -> dict[str, Any]:
    return {
        "command": cfg.command,
        "args": list(cfg.args),
        "url": cfg.url,
        "transport": cfg.transport.value,
        "env_keys": sorted(cfg.env_keys),
        "headers_keys": sorted(cfg.headers_keys),
    }


# ---------------------------------------------------------------------------
# No drift
# ---------------------------------------------------------------------------


class TestNoDrift:
    def test_identical_config_produces_no_findings(self) -> None:
        cfg = _cfg(command="npx", args=["pkg@1.2.3"])
        assert _analyzer.analyze_server(cfg, _snap(cfg)) == []

    def test_missing_baseline_produces_no_findings(self) -> None:
        cfg = _cfg(command="npx", args=["pkg@1.2.3"])
        assert _analyzer.analyze_server(cfg, None) == []

    def test_empty_baseline_dict_produces_no_findings(self) -> None:
        cfg = _cfg(command="npx", args=["pkg@1.2.3"])
        assert _analyzer.analyze_server(cfg, {}) == []


# ---------------------------------------------------------------------------
# Command / transport (MCP020)
# ---------------------------------------------------------------------------


class TestCommand:
    def test_binary_swap_is_high_mcp020(self) -> None:
        base = _snap(_cfg(command="npx", args=["pkg@1.2.3"]))
        findings = _analyzer.analyze_server(_cfg(command="python", args=["pkg@1.2.3"]), base)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ProvenanceKind.COMMAND
        assert f.severity == ProvenanceSeverity.HIGH
        assert f.rule_id == "MCP020"

    def test_transport_switch_flags_command(self) -> None:
        base = _snap(_cfg(command="npx", args=["p"], transport=TransportType.STDIO))
        cur = _cfg(command="npx", args=["p"], transport=TransportType.HTTP, url="http://x")
        kinds = {f.kind for f in _analyzer.analyze_server(cur, base)}
        assert ProvenanceKind.COMMAND in kinds


# ---------------------------------------------------------------------------
# Arguments (MCP021)
# ---------------------------------------------------------------------------


class TestArgs:
    def test_version_float_is_medium_mcp021(self) -> None:
        base = _snap(_cfg(command="npx", args=["pkg@1.2.3"]))
        findings = _analyzer.analyze_server(_cfg(command="npx", args=["pkg@latest"]), base)
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ProvenanceKind.ARGS
        assert f.severity == ProvenanceSeverity.MEDIUM
        assert f.rule_id == "MCP021"
        assert f.gained_flags == []

    def test_dangerous_flag_gained_is_high_with_flag_listed(self) -> None:
        base = _snap(_cfg(command="npx", args=["pkg@1.2.3"]))
        cur = _cfg(command="npx", args=["pkg@1.2.3", "--no-sandbox"])
        findings = [f for f in _analyzer.analyze_server(cur, base) if f.kind == ProvenanceKind.ARGS]
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == ProvenanceSeverity.HIGH
        assert "--no-sandbox" in f.gained_flags

    def test_dangerously_skip_permissions_flag_detected(self) -> None:
        base = _snap(_cfg(command="claude", args=["mcp"]))
        cur = _cfg(command="claude", args=["mcp", "--dangerously-skip-permissions"])
        findings = [f for f in _analyzer.analyze_server(cur, base) if f.kind == ProvenanceKind.ARGS]
        assert findings[0].severity == ProvenanceSeverity.HIGH
        assert findings[0].gained_flags == ["--dangerously-skip-permissions"]


# ---------------------------------------------------------------------------
# URL (MCP022)
# ---------------------------------------------------------------------------


class TestUrl:
    def test_endpoint_change_is_high_mcp022(self) -> None:
        base = _snap(_cfg(command=None, transport=TransportType.HTTP, url="https://api.good.com"))
        cur = _cfg(command=None, transport=TransportType.HTTP, url="https://api.evil.com")
        findings = [f for f in _analyzer.analyze_server(cur, base) if f.kind == ProvenanceKind.URL]
        assert len(findings) == 1
        assert findings[0].severity == ProvenanceSeverity.HIGH
        assert findings[0].rule_id == "MCP022"


# ---------------------------------------------------------------------------
# Credentials (MCP023) — KEY NAMES ONLY
# ---------------------------------------------------------------------------


class TestCredentials:
    def test_added_credential_key_is_medium_mcp023(self) -> None:
        base = _snap(_cfg(command="npx", args=["p"], env_keys=["API_KEY"]))
        cur = _cfg(command="npx", args=["p"], env_keys=["API_KEY", "AWS_SECRET_ACCESS_KEY"])
        findings = [f for f in _analyzer.analyze_server(cur, base) if f.kind == ProvenanceKind.CREDENTIALS]
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == ProvenanceSeverity.MEDIUM
        assert f.rule_id == "MCP023"
        # The new key NAME appears; no value is ever present.
        assert "AWS_SECRET_ACCESS_KEY" in f.current

    def test_header_key_change_also_flagged(self) -> None:
        base = _snap(_cfg(command="npx", args=["p"], headers_keys=["Authorization"]))
        cur = _cfg(command="npx", args=["p"], headers_keys=["Authorization", "X-Api-Key"])
        kinds = {f.kind for f in _analyzer.analyze_server(cur, base)}
        assert ProvenanceKind.CREDENTIALS in kinds


# ---------------------------------------------------------------------------
# Model / serialisation
# ---------------------------------------------------------------------------


class TestFindingModel:
    def test_finding_has_title_summary_remediation(self) -> None:
        base = _snap(_cfg(command="npx", args=["p"]))
        findings = _analyzer.analyze_server(_cfg(command="deno", args=["p"]), base)
        f = findings[0]
        assert f.title
        assert f.summary
        assert f.remediation
        assert f.description == f.summary

    def test_serialises_to_json(self) -> None:
        base = _snap(_cfg(command="npx", args=["p"]))
        findings = _analyzer.analyze_server(_cfg(command="deno", args=["p"]), base)
        data = json.loads(findings[0].model_dump_json())
        assert data["kind"] == "command"
        assert data["severity"] == "high"
        assert data["rule_id"] == "MCP020"
        assert "baseline" in data and "current" in data
