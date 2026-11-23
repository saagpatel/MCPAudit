"""Unit tests for registry package verification (MCP025).

The registry is never contacted: a fake fetch function is injected into
PackageVerifier, and the resolver is exercised on hand-built ServerConfigs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from mcp_audit.models import (
    ClientType,
    PackageVerifyKind,
    PackageVerifySeverity,
    ServerConfig,
    TransportType,
)
from mcp_audit.pkgverify import (
    ArtifactVerifier,
    PackageRef,
    PackageVerifier,
    resolve_package_refs,
    verification_coverage,
)


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


@pytest.mark.parametrize(
    "command,args,expected",
    [
        # uv run: the command or script is local; only --with requirements come from PyPI.
        ("uv", ["run", "--with", "pkg==1.0", "server.py"], [("pkg", "1.0")]),
        ("uv", ["run", "server.py"], []),
        ("uv", ["run", "--with", "fastmcp", "fastmcp", "run", "server.py"], [("fastmcp", None)]),
        (
            "uv",
            ["run", "--directory", "/x", "--with=a==1,b[cli]==2", "main.py", "--with", "c==3"],
            [("a", "1"), ("b", "2")],
        ),
        # uvx / uv tool run: the package plus --with; uv's pkg@version spelling is exact.
        ("uv", ["tool", "run", "mcp-server-git==1.4.0"], [("mcp-server-git", "1.4.0")]),
        ("uvx", ["pkg@0.6.2"], [("pkg", "0.6.2")]),
        ("uvx", ["pkg@latest"], [("pkg", None)]),
        ("uvx", ["--from", "tool==1.0", "tool-cli"], [("tool", "1.0")]),
        ("uvx", ["-p", "3.12", "--with", "dep==2", "pkg==1"], [("pkg", "1"), ("dep", "2")]),
        ("uvx", ["--python=3.12", "mcp[cli]==1.2.0"], [("mcp", "1.2.0")]),
        ("uvx", ["--with", "pkg==1", "pkg==1"], [("pkg", "1")]),  # each ref once
        ("uvx", ["-w", "dep==2", "pkg==1"], [("pkg", "1"), ("dep", "2")]),  # -w is --with
        ("uv", ["run", "-w", "dep==2", "main.py"], [("dep", "2")]),
        ("uv", ["run", "--with", "pkg[a,b]==1.0", "main.py"], [("pkg", "1.0")]),  # commas in extras
        (
            "uv",
            ["run", "--with", 'a==1,pkg[x,y]==2; python_version in "3.12,3.13",c==3', "main.py"],
            [("a", "1"), ("pkg", "2"), ("c", "3")],
        ),
        # npm: only exec/x launch a registry package.
        ("npm", ["exec", "--", "pkg@1.0.0"], [("pkg", "1.0.0")]),
        ("npm", ["x", "-y", "--package", "pkg@1.0.0", "--", "cmd"], [("pkg", "1.0.0")]),
        ("npm", ["--package", "pkg@1.2.3", "exec", "cmd"], [("pkg", "1.2.3")]),  # options before exec
        ("npm", ["--package=pkg@1.2.3", "exec", "cmd"], [("pkg", "1.2.3")]),
        # npm reads options anywhere until "--"; npx stops at the first positional.
        ("npm", ["exec", "tool-cli", "--package=tool@1.0.0"], [("tool", "1.0.0")]),
        ("npx", ["tool-cli", "--package=tool@1.0.0"], [("tool-cli", None)]),
        ("npm", ["exec", "--", "pkg@1.0.0", "--package=x@9.9.9"], [("pkg", "1.0.0")]),
        # Every --package is installed.
        (
            "npx",
            ["--package=tool-a@1.0.0", "--package=tool-b@2.0.0", "cmd"],
            [("tool-a", "1.0.0"), ("tool-b", "2.0.0")],
        ),
        (
            "npm",
            ["exec", "--package", "a@1.0.0", "--package=b@2.0.0", "--", "cmd"],
            [("a", "1.0.0"), ("b", "2.0.0")],
        ),
        # In npm, -p is the boolean --parseable, not a package.
        ("npm", ["exec", "-p", "--", "tool@1.0.0"], [("tool", "1.0.0")]),
        ("npm", ["-p", "exec", "tool@1.0.0"], [("tool", "1.0.0")]),
        # PyPI direct references are sources, not registry packages.
        ("uvx", ["--from", "tool @ https://user:secret@example.invalid/tool.whl", "tool"], []),
        ("uvx", ["tool@https://user:secret@example.invalid/tool.whl"], []),
        (
            "uv",
            ["run", "--with", "dep @ git+https://tok@github.com/o/r.git", "--with", "ok==1", "main.py"],
            [("ok", "1")],
        ),
        ("pipx", ["run", "--spec", "git+https://tok@github.com/o/r.git", "cmd"], []),
        ("uvx", ["./local/pkg"], []),
        ("npm", ["run", "build"], []),
        ("npm", ["start"], []),
        # pipx run: --spec or the first positional; other subcommands launch nothing.
        ("pipx", ["run", "--spec", "pkg==1.0", "cmd"], [("pkg", "1.0")]),
        ("pipx", ["run", "--python", "3.12", "pkg==1.0"], [("pkg", "1.0")]),
        ("pipx", ["run", "--with", "dep==2", "--cooldown", "7", "pkg==1.0"], [("pkg", "1.0"), ("dep", "2")]),
        ("uvx", ["-C", "k=v", "-P", "dep", "pkg==1"], [("pkg", "1")]),  # value options from uv's help
        ("npm", ["exec", "--loglevel", "warn", "--", "pkg@1.0.0"], [("pkg", "1.0.0")]),
        ("pipx", ["install", "pkg"], []),
    ],
    ids=lambda value: (
        " ".join(value) if isinstance(value, list) and all(isinstance(v, str) for v in value) else None
    ),
)
def test_runner_grammar_resolves_only_registry_packages(
    command: str, args: list[str], expected: list[tuple[str, str | None]]
) -> None:
    assert [(ref.name, ref.version) for ref in resolve_package_refs(_cfg(command, args))] == expected


@pytest.mark.parametrize(
    "ref,exact",
    [
        (PackageRef("npm", "pkg", "1.2.3"), True),
        (PackageRef("npm", "pkg", "v1.2.3-beta.1"), True),
        (PackageRef("npm", "pkg", "latest"), False),
        (PackageRef("npm", "pkg", "^1.2.0"), False),
        (PackageRef("pypi", "pkg", "0.6.2"), True),
        (PackageRef("pypi", "pkg", "1.0.*"), False),
        (PackageRef("pypi", "pkg", None), False),
        (PackageRef("pypi", "pkg", "2!1.0rc1.post2.dev3+abc.1"), True),
        # Never registry-shaped, so never fetched.
        (PackageRef("pypi", "tool ", "https://user:secret@example.invalid/tool.whl"), False),
        (PackageRef("pypi", "pkg", "1.0/../../x"), False),
        (PackageRef("npm", "git+https://user:tok", "1.0.0"), False),
    ],
)
def test_is_exact(ref: PackageRef, exact: bool) -> None:
    assert ref.is_exact is exact


@pytest.mark.parametrize("spec", ["pkg@latest", "pkg@^1.2.0", "pkg@1.x"])
def test_moving_npm_versions_are_not_captured(spec: str) -> None:
    # Check time verifies exact versions only, so a baseline for a dist-tag or range
    # would sit in the pin store unchecked forever.
    fetched: list[str] = []

    def fake_fetch(ref: PackageRef) -> str | None:
        fetched.append(ref.key())
        return "sha512-x"

    assert PackageVerifier(fetch=fake_fetch).capture(_cfg("npx", ["-y", spec])) == {}
    assert fetched == []


def test_uvx_at_version_is_captured_and_verified() -> None:
    cfg = _cfg("uvx", ["pkg@0.6.2"])
    table = {"pypi:pkg:0.6.2": "sha256-a"}
    verifier = PackageVerifier(fetch=lambda ref: table.get(ref.key()))
    baseline = verifier.capture(cfg)
    assert baseline == {"pypi:pkg:0.6.2": "sha256-a"}
    table["pypi:pkg:0.6.2"] = "sha256-b"
    findings = verifier.analyze_server("srv", cfg, baseline)
    assert [(f.kind, f.severity, f.package, f.version) for f in findings] == [
        (PackageVerifyKind.REGISTRY_DRIFT, PackageVerifySeverity.HIGH, "pkg", "0.6.2")
    ]


@pytest.mark.parametrize(
    "command,args,count",
    [
        ("uvx", ["-w", "dep==2", "pkg==1"], 2),
        ("npm", ["--package", "pkg@1.2.3", "exec", "cmd"], 1),
        ("npx", ["--package=tool-a@1.0.0", "--package=tool-b@2.0.0", "cmd"], 2),
        ("npm", ["exec", "tool-cli", "--package=tool@1.0.0"], 1),
    ],
    ids=["uvx -w", "npm --package before exec", "npx repeated --package", "npm --package after command"],
)
def test_every_launched_package_is_captured_verified_and_covered(
    command: str, args: list[str], count: int
) -> None:
    cfg = _cfg(command, args)
    table = {ref.key(): f"hash-{ref.name}" for ref in resolve_package_refs(cfg)}
    verifier = PackageVerifier(fetch=lambda ref: table.get(ref.key()))
    baseline = verifier.capture(cfg)
    assert len(baseline) == count and baseline == table
    verified: set[str] = set()
    assert verifier.analyze_server("srv", cfg, baseline, verified) == []
    assert verification_coverage(cfg, baseline, verified).state == "complete"
    last = sorted(table)[-1]
    table[last] = "changed"
    drift = verifier.analyze_server("srv", cfg, baseline)
    assert [(f.kind, f.severity) for f in drift] == [
        (PackageVerifyKind.REGISTRY_DRIFT, PackageVerifySeverity.HIGH)
    ]


@pytest.mark.parametrize(
    "command,args",
    [
        ("uvx", ["--from", "tool @ https://user:secret@example.invalid/tool.whl", "tool"]),
        ("uvx", ["tool@https://user:secret@example.invalid/tool.whl"]),
        ("uv", ["run", "--with", "dep @ git+https://user:secret@github.com/o/r.git", "main.py"]),
        ("pipx", ["run", "--spec", "git+https://user:secret@github.com/o/r.git", "cmd"]),
        ("npx", ["-y", "git+https://user:secret@github.com/o/r.git"]),
    ],
    ids=["uvx --from direct url", "uvx name@url", "uv run --with vcs", "pipx --spec vcs", "npx git url"],
)
def test_source_specs_are_never_sent_to_a_registry(command: str, args: list[str]) -> None:
    fetched: list[str] = []

    def fetch_hash(ref: PackageRef) -> str | None:
        fetched.append(ref.key())
        return "h"

    def fetch_artifact(ref: PackageRef) -> None:
        fetched.append(ref.key())

    cfg = _cfg(command, args)
    PackageVerifier(fetch=fetch_hash).capture(cfg)
    ArtifactVerifier(fetch=fetch_artifact).capture(cfg)
    assert fetched == []


def test_uv_run_with_requirement_is_verified_not_the_script() -> None:
    cfg = _cfg("uv", ["run", "--with", "pkg==1.0", "server.py"])
    baseline = PackageVerifier(fetch=lambda ref: "sha256-a").capture(cfg)
    assert baseline == {"pypi:pkg:1.0": "sha256-a"}


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
