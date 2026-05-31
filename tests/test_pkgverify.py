"""Unit tests for registry package verification (MCP025).

The registry is never contacted: a fake fetch function is injected into
PackageVerifier, and the resolver is exercised on hand-built ServerConfigs.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_audit.models import (
    ClientType,
    PackageVerifyKind,
    PackageVerifySeverity,
    ServerConfig,
    TransportType,
)
from mcp_audit.pkgverify import PackageRef, PackageVerifier, resolve_package_refs


def _cfg(command: str | None, args: list[str]) -> ServerConfig:
    return ServerConfig(
        name="srv",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/c.json",
        command=command,
        args=args,
        transport=TransportType.STDIO,
    )


class TestResolver:
    def test_npx_name_version(self) -> None:
        refs = resolve_package_refs(_cfg("npx", ["-y", "server-fs@1.2.3"]))
        assert refs == [PackageRef("npm", "server-fs", "1.2.3")]

    def test_npx_scoped_name_version(self) -> None:
        refs = resolve_package_refs(_cfg("npx", ["@modelcontextprotocol/server-filesystem@0.5.0"]))
        assert refs == [PackageRef("npm", "@modelcontextprotocol/server-filesystem", "0.5.0")]

    def test_npx_unversioned(self) -> None:
        refs = resolve_package_refs(_cfg("npx", ["-y", "some-server"]))
        assert refs == [PackageRef("npm", "some-server", None)]

    def test_npx_package_flag(self) -> None:
        refs = resolve_package_refs(_cfg("npx", ["--package", "pkg@2.0.0", "-c", "run"]))
        assert refs == [PackageRef("npm", "pkg", "2.0.0")]

    def test_uvx_pinned(self) -> None:
        refs = resolve_package_refs(_cfg("uvx", ["mcp-server-git==1.4.0"]))
        assert refs == [PackageRef("pypi", "mcp-server-git", "1.4.0")]

    def test_uvx_from_flag_and_unpinned_constraint(self) -> None:
        refs = resolve_package_refs(_cfg("uvx", ["--from", "tool>=1.0", "run"]))
        assert refs == [PackageRef("pypi", "tool", None)]

    def test_non_runner_command_yields_nothing(self) -> None:
        assert resolve_package_refs(_cfg("python", ["server.py"])) == []
        assert resolve_package_refs(_cfg(None, [])) == []


class TestVerifier:
    def _verifier(self, table: dict[str, str | None]) -> PackageVerifier:
        def fake_fetch(ref: PackageRef) -> str | None:
            return table.get(ref.key())

        return PackageVerifier(fetch=fake_fetch)

    def test_capture_returns_hashes_for_versioned_refs(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": "sha512-AAA"})
        assert v.capture(cfg) == {"npm:pkg:1.0.0": "sha512-AAA"}

    def test_capture_skips_unversioned(self) -> None:
        cfg = _cfg("npx", ["pkg"])
        v = self._verifier({"npm:pkg:None": "x"})
        assert v.capture(cfg) == {}

    def test_no_baseline_no_findings(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        assert self._verifier({}).analyze_server("srv", cfg, None) == []

    def test_unchanged_hash_no_findings(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": "sha512-SAME"})
        assert v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "sha512-SAME"}) == []

    def test_changed_hash_is_high_mcp025(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": "sha512-NEW"})
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "sha512-OLD"})
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == PackageVerifyKind.REGISTRY_DRIFT
        assert f.severity == PackageVerifySeverity.HIGH
        assert f.rule_id == "MCP025"
        assert f.package == "pkg" and f.version == "1.0.0"

    def test_unfetchable_is_medium(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": None})  # fetch fails
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "sha512-OLD"})
        assert len(findings) == 1
        assert findings[0].severity == PackageVerifySeverity.MEDIUM
        assert findings[0].current_hash is None

    def test_version_float_is_deferred_to_provenance(self) -> None:
        # Baseline pinned 1.0.0 but the config now launches 2.0.0 — the pinned
        # version isn't present in the current refs, so MCP025 stays silent
        # (provenance MCP021 owns the float).
        cfg = _cfg("npx", ["pkg@2.0.0"])
        v = self._verifier({"npm:pkg:2.0.0": "sha512-X"})
        assert v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "sha512-OLD"}) == []

    def test_serialises_to_json(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": "sha512-NEW"})
        finding = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "sha512-OLD"})[0]
        data: dict[str, Any] = json.loads(finding.model_dump_json())
        assert data["rule_id"] == "MCP025"
        assert data["ecosystem"] == "npm"
        assert data["description"] == finding.summary
