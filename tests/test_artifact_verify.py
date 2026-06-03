"""Unit tests for byte-level artifact verification (MCP026, --download-artifacts).

The network is never contacted: a fake ``fetch_artifact`` callable is injected
into ArtifactVerifier, and the download-host allowlist / size-cap helpers are
exercised directly. MCP026 deepens MCP025: instead of comparing the registry's
*published* hash across time, it downloads the actual bytes, hashes them, and
checks them against both the registry's published hash and the pinned byte-hash.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from mcp_audit.models import (
    ArtifactVerifyKind,
    ArtifactVerifySeverity,
    ClientType,
    ServerConfig,
    TransportType,
)
from mcp_audit.pkgverify import (
    ArtifactResult,
    ArtifactVerifier,
    PackageRef,
    RegistryClient,
    is_allowed_artifact_url,
    stream_sha256,
)


def _npm_consistent(integrity: str | None, digests: dict[str, str]) -> bool | None:
    dist: dict[str, object] = {}
    if integrity is not None:
        dist["integrity"] = integrity
    return RegistryClient._npm_consistent(dist, digests)


def _sri(algo: str, hex_digest: str) -> str:
    import base64

    return f"{algo}-" + base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _cfg(command: str | None, args: list[str]) -> ServerConfig:
    return ServerConfig(
        name="srv",
        client=ClientType.CLAUDE_CODE,
        config_path="/tmp/c.json",
        command=command,
        args=args,
        transport=TransportType.STDIO,
    )


class TestDownloadHostAllowlist:
    def test_known_registry_cdn_hosts_allowed(self) -> None:
        assert is_allowed_artifact_url("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")
        assert is_allowed_artifact_url("https://files.pythonhosted.org/packages/ab/cd/x.whl")
        assert is_allowed_artifact_url("https://pypi.org/pypi/x/1.0.0/json")

    def test_non_allowlisted_host_rejected(self) -> None:
        # A compromised metadata response must not redirect the downloader at an
        # internal address or an attacker-controlled host (SSRF guard).
        assert not is_allowed_artifact_url("https://169.254.169.254/latest/meta-data/")
        assert not is_allowed_artifact_url("https://evil.example.com/pkg.tgz")
        assert not is_allowed_artifact_url("http://registry.npmjs.org/pkg.tgz")  # http downgrade

    def test_lookalike_host_rejected(self) -> None:
        assert not is_allowed_artifact_url("https://registry.npmjs.org.evil.com/pkg.tgz")


class TestNpmConsistency:
    # sha256 of b"x"*1 etc. — exact values don't matter, only that hex round-trips.
    SHA512 = "a" * 128
    SHA256 = "b" * 64
    SHA384 = "c" * 96

    def test_matches_sha512_integrity(self) -> None:
        digests = {"sha512": self.SHA512, "sha256": self.SHA256, "sha384": self.SHA384, "sha1": "d" * 40}
        assert _npm_consistent(_sri("sha512", self.SHA512), digests) is True

    def test_matches_non_sha512_integrity(self) -> None:
        # Registry published only a sha256 SRI — must verify against that, not assume sha512.
        digests = {"sha512": self.SHA512, "sha256": self.SHA256, "sha384": self.SHA384, "sha1": "d" * 40}
        assert _npm_consistent(_sri("sha256", self.SHA256), digests) is True

    def test_multi_algo_integrity_matches_any(self) -> None:
        digests = {"sha512": self.SHA512, "sha256": self.SHA256, "sha384": self.SHA384, "sha1": "d" * 40}
        integrity = f"{_sri('sha384', self.SHA384)} {_sri('sha512', self.SHA512)}"
        assert _npm_consistent(integrity, digests) is True

    def test_real_mismatch_is_false(self) -> None:
        digests = {"sha512": self.SHA512, "sha256": self.SHA256, "sha384": self.SHA384, "sha1": "d" * 40}
        assert _npm_consistent(_sri("sha512", "e" * 128), digests) is False

    def test_unknown_algorithm_only_is_unverifiable_not_false(self) -> None:
        # Integrity uses an algorithm we did not compute → None (UNVERIFIED), never a
        # false PUBLISHED_MISMATCH on authentic bytes.
        digests = {"sha512": self.SHA512, "sha256": self.SHA256, "sha384": self.SHA384, "sha1": "d" * 40}
        assert _npm_consistent("sha3-512-" + "f" * 86, digests) is None


class TestRedirectAllowlist:
    def test_redirect_to_disallowed_host_raises(self) -> None:
        # A redirect hop to a non-allowlisted host must be rejected before it is
        # followed, so urllib never connects to e.g. the cloud metadata endpoint.
        from mcp_audit.pkgverify import _AllowlistRedirectHandler

        handler = _AllowlistRedirectHandler()
        req = urllib.request.Request("https://registry.npmjs.org/x")
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(
                req,
                io.BytesIO(b""),
                302,
                "Found",
                http.client.HTTPMessage(),
                "https://169.254.169.254/latest/meta-data/",
            )


class TestPypiFileCap:
    def test_too_many_files_skipped_without_downloading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from mcp_audit import pkgverify

        client = RegistryClient()
        many = {
            "urls": [
                {"url": f"https://files.pythonhosted.org/{i}.whl", "digests": {"sha256": "a" * 64}}
                for i in range(pkgverify._MAX_ARTIFACT_FILES + 1)
            ]
        }
        monkeypatch.setattr(client, "_get_json", lambda url: many)
        downloaded: list[str] = []

        def _fake_download(url: str, algos: tuple[str, ...]) -> dict[str, str]:
            downloaded.append(url)
            return {"sha256": "a" * 64}

        monkeypatch.setattr(pkgverify, "_download_digests", _fake_download)
        assert client._pypi_artifact("x", "1.0.0") is None
        assert downloaded == []  # short-circuited before any byte transfer


class TestStreamSha256:
    def test_hashes_full_stream(self) -> None:
        payload = b"hello world" * 1000
        digest, ok = stream_sha256(io.BytesIO(payload), cap=10 * 1024 * 1024)
        assert ok is True
        assert digest == hashlib.sha256(payload).hexdigest()

    def test_returns_not_ok_when_cap_exceeded(self) -> None:
        payload = b"x" * 5000
        digest, ok = stream_sha256(io.BytesIO(payload), cap=1024)
        assert ok is False
        assert digest is None


class TestArtifactVerifier:
    def _verifier(self, table: dict[str, ArtifactResult | None]) -> ArtifactVerifier:
        def fake_fetch(ref: PackageRef) -> ArtifactResult | None:
            return table.get(ref.key())

        return ArtifactVerifier(fetch=fake_fetch)

    # --- capture -----------------------------------------------------------
    def test_capture_stores_sha256_for_consistent_bytes(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("sha256hex", True)})
        cap = v.capture(cfg)
        assert cap.hashes == {"npm:pkg:1.0.0": "sha256hex"}
        assert cap.warnings == []

    def test_capture_refuses_inconsistent_bytes_and_warns(self) -> None:
        # Bytes the registry served did not match its own published hash: never
        # baseline poisoned bytes; surface a warning instead.
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("sha256hex", False)})
        cap = v.capture(cfg)
        assert cap.hashes == {}
        assert len(cap.warnings) == 1
        assert "pkg@1.0.0" in cap.warnings[0]

    def test_capture_warns_when_unverifiable(self) -> None:
        cfg = _cfg("uvx", ["mcp-server-git==1.4.0"])
        v = self._verifier({"pypi:mcp-server-git:1.4.0": None})
        cap = v.capture(cfg)
        assert cap.hashes == {}
        assert len(cap.warnings) == 1

    def test_capture_skips_unversioned(self) -> None:
        cfg = _cfg("npx", ["pkg"])
        v = self._verifier({"npm:pkg:None": ArtifactResult("x", True)})
        assert v.capture(cfg).hashes == {}

    # --- analyze_server ----------------------------------------------------
    def test_no_baseline_no_findings(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        assert self._verifier({}).analyze_server("srv", cfg, None) == []
        assert self._verifier({}).analyze_server("srv", cfg, {}) == []

    def test_stable_bytes_no_findings(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("SAME", True)})
        assert v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "SAME"}) == []

    def test_published_mismatch_is_high(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("WHATEVER", False)})
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"})
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ArtifactVerifyKind.PUBLISHED_MISMATCH
        assert f.severity == ArtifactVerifySeverity.HIGH
        assert f.rule_id == "MCP026"
        assert f.package == "pkg" and f.version == "1.0.0"

    def test_baseline_mismatch_is_high(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("NEWBYTES", True)})
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"})
        assert len(findings) == 1
        f = findings[0]
        assert f.kind == ArtifactVerifyKind.BASELINE_MISMATCH
        assert f.severity == ArtifactVerifySeverity.HIGH
        assert f.current_hash == "NEWBYTES"
        assert f.baseline_hash == "PINNED"

    def test_unverifiable_is_medium(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": None})
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"})
        assert len(findings) == 1
        assert findings[0].kind == ArtifactVerifyKind.UNVERIFIED
        assert findings[0].severity == ArtifactVerifySeverity.MEDIUM
        assert findings[0].current_hash is None

    def test_published_mismatch_takes_precedence_over_baseline(self) -> None:
        # Inconsistent-right-now is the headline even if bytes also differ from pin.
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("NEWBYTES", False)})
        findings = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"})
        assert len(findings) == 1
        assert findings[0].kind == ArtifactVerifyKind.PUBLISHED_MISMATCH

    def test_version_float_is_deferred_to_provenance(self) -> None:
        cfg = _cfg("npx", ["pkg@2.0.0"])
        v = self._verifier({"npm:pkg:2.0.0": ArtifactResult("X", True)})
        assert v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"}) == []

    def test_serialises_to_json(self) -> None:
        cfg = _cfg("npx", ["pkg@1.0.0"])
        v = self._verifier({"npm:pkg:1.0.0": ArtifactResult("NEWBYTES", True)})
        finding = v.analyze_server("srv", cfg, {"npm:pkg:1.0.0": "PINNED"})[0]
        data: dict[str, Any] = json.loads(finding.model_dump_json())
        assert data["rule_id"] == "MCP026"
        assert data["ecosystem"] == "npm"
        assert data["description"] == finding.summary
