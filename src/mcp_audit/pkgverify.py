"""Registry package verification — network-gated supply-chain check (MCP025).

The on-disk integrity check (MCP024) hashes local bytes, but for package-runner
launches (``npx pkg@1.2.3`` / ``uvx pkg``) the meaningful artifact is the remote
package, not the runner binary. This module resolves the package spec from a
server's launch config and compares the *registry-published* hash for the exact
``package@version`` against the hash captured at pin time.

  MCP025 (REGISTRY_DRIFT) — the registry's published hash for a pinned version
                            changed (HIGH; a registry must never serve different
                            bytes for the same version), or could not be
                            re-fetched to verify (MEDIUM).

Network-gated: the registry is contacted ONLY when the operator passes
``--verify-artifacts`` (to scan, and to ``pin`` to capture the baseline). A
version *float* (different version than pinned) is provenance's job (MCP021), not
this check — it keys by exact ``package@version``. The fetch function is injectable
so the offline test suite never touches the network.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

from mcp_audit.models import (
    PackageVerifyFinding,
    PackageVerifyKind,
    PackageVerifySeverity,
    ServerConfig,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_USER_AGENT = "mcp-audit (+https://github.com/saagpatel/MCPAudit)"

# Runner commands by ecosystem. The package spec is parsed from the args.
_NPM_RUNNERS = {"npx", "npm"}
_PYPI_RUNNERS = {"uvx", "pipx", "uv"}

# npx/npm/pipx/uv flags that consume the NEXT token as a value (so it isn't the
# package spec). "--package"/"-p"/"--from" point AT the package, handled separately.
_VALUE_FLAGS = {"-c", "--call", "-w", "--workspace"}


@dataclass(frozen=True)
class PackageRef:
    """A resolved package reference: ecosystem + name + exact version (or None)."""

    ecosystem: str  # "npm" | "pypi"
    name: str
    version: str | None

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}"


def _split_npm_spec(spec: str) -> tuple[str, str | None]:
    """Split an npm spec into (name, version). Handles @scope/name@version."""
    if spec.startswith("@"):
        # @scope/name[@version] — the version '@' is the one after the slash.
        if "/" not in spec:
            return spec, None
        scope, rest = spec.split("/", 1)
        if "@" in rest:
            name, version = rest.split("@", 1)
            return f"{scope}/{name}", version or None
        return spec, None
    if "@" in spec:
        name, version = spec.split("@", 1)
        return name, version or None
    return spec, None


def _split_pypi_spec(spec: str) -> tuple[str, str | None]:
    """Split a PyPI spec into (name, version). Only '==' yields an exact version."""
    if "==" in spec:
        name, version = spec.split("==", 1)
        return name.strip(), version.strip() or None
    # Non-pinned constraints (>=, ~=, bare) have no exact version to verify.
    for sep in ("<", ">", "~", "!", "="):
        if sep in spec:
            return spec.split(sep, 1)[0].strip(), None
    return spec.strip(), None


def _first_package_token(args: list[str], from_flags: set[str]) -> str | None:
    """Return the launch arg that names the package, or None.

    Honours ``--from``/``--package``/``-p`` (next token is the package); otherwise
    the first non-flag, non-subcommand token.
    """
    skip_subcommands = {"exec", "run", "tool", "x", "--"}
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in from_flags:
            return args[i + 1] if i + 1 < len(args) else None
        if arg.startswith("--") and "=" in arg and arg.split("=", 1)[0] in from_flags:
            return arg.split("=", 1)[1] or None
        if arg in _VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("-") or arg in skip_subcommands:
            i += 1
            continue
        return arg
    return None


def resolve_package_refs(server_config: ServerConfig) -> list[PackageRef]:
    """Resolve package references from a server's launch command + args.

    Best-effort: returns an empty list when the launch isn't a recognised package
    runner or the spec can't be parsed (never invents a ref). At most one ref per
    server today (the launched package).
    """
    command = (server_config.command or "").rsplit("/", 1)[-1].lower()
    args = [str(a) for a in server_config.args]

    if command in _NPM_RUNNERS:
        token = _first_package_token(args, {"--package", "-p"})
        if token:
            name, version = _split_npm_spec(token)
            return [PackageRef("npm", name, version)]
    elif command in _PYPI_RUNNERS:
        token = _first_package_token(args, {"--from"})
        if token:
            name, version = _split_pypi_spec(token)
            return [PackageRef("pypi", name, version)]
    return []


class RegistryClient:
    """Fetches registry-published hashes for npm / PyPI packages over HTTPS."""

    def _get_json(self, url: str) -> dict[str, object] | None:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (https only)
                data = json.loads(resp.read().decode("utf-8"))
                return data if isinstance(data, dict) else None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            logger.debug("Registry fetch failed: %s", url)
            return None

    def _npm_hash(self, name: str, version: str) -> str | None:
        # Keep '@' and '/' literal for scoped names (@scope/name); fully encode the
        # version so '?'/'#'/'..' in a malformed spec can't reshape the URL.
        url = f"https://registry.npmjs.org/{quote(name, safe='@/')}/{quote(version, safe='')}"
        data = self._get_json(url)
        dist = data.get("dist") if data else None
        if isinstance(dist, dict):
            value = dist.get("integrity") or dist.get("shasum")
            return str(value) if value else None
        return None

    def _pypi_hash(self, name: str, version: str) -> str | None:
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
        data = self._get_json(url)
        urls = data.get("urls") if data else None
        if not isinstance(urls, list):
            return None
        digests = sorted(
            str(u["digests"]["sha256"])
            for u in urls
            if isinstance(u, dict) and isinstance(u.get("digests"), dict) and u["digests"].get("sha256")
        )
        # Combine all distribution-file hashes so any file change is detected.
        return ",".join(digests) or None

    def fetch_hash(self, ref: PackageRef) -> str | None:
        """Return the registry-published hash for an exact package@version, or None."""
        if ref.version is None:
            return None
        if ref.ecosystem == "npm":
            return self._npm_hash(ref.name, ref.version)
        if ref.ecosystem == "pypi":
            return self._pypi_hash(ref.name, ref.version)
        return None


# A fetch callable: PackageRef -> published hash string (or None). Injectable.
FetchHash = Callable[[PackageRef], str | None]


class PackageVerifier:
    """Captures and compares registry-published package hashes vs the pin baseline."""

    def __init__(self, fetch: FetchHash | None = None) -> None:
        self._fetch: FetchHash = fetch or RegistryClient().fetch_hash

    def capture(self, server_config: ServerConfig) -> dict[str, str]:
        """Pin-time: fetch registry hashes for the server's pinned packages.

        Returns ``{ref_key: hash}`` for every exact-version package we could fetch.
        Unpinned versions and fetch failures are omitted (nothing to baseline).
        """
        captured: dict[str, str] = {}
        for ref in resolve_package_refs(server_config):
            if ref.version is None:
                continue
            digest = self._fetch(ref)
            if digest:
                captured[ref.key()] = digest
        return captured

    def analyze_server(
        self,
        server_name: str,
        server_config: ServerConfig,
        baseline_hashes: dict[str, str] | None,
    ) -> list[PackageVerifyFinding]:
        """Compare current registry hashes against the pinned baseline for one server."""
        if not baseline_hashes:
            return []

        refs_by_key = {r.key(): r for r in resolve_package_refs(server_config) if r.version}
        findings: list[PackageVerifyFinding] = []
        for key, baseline_hash in sorted(baseline_hashes.items()):
            ref = refs_by_key.get(key)
            if ref is None:
                # Version floated or package removed since pin — provenance (MCP021)
                # owns that signal; this check only verifies the exact pinned version.
                continue
            assert ref.version is not None  # keyed refs always carry a version
            current = self._fetch(ref)
            if current is None:
                findings.append(
                    PackageVerifyFinding(
                        kind=PackageVerifyKind.REGISTRY_DRIFT,
                        severity=PackageVerifySeverity.MEDIUM,
                        server_name=server_name,
                        ecosystem=ref.ecosystem,
                        package=ref.name,
                        version=ref.version,
                        baseline_hash=baseline_hash,
                        current_hash=None,
                        summary=(
                            f"Could not verify {ref.ecosystem} package '{ref.name}@{ref.version}' "
                            f"for '{server_name}' — registry unreachable or version withdrawn."
                        ),
                    )
                )
            elif current != baseline_hash:
                findings.append(
                    PackageVerifyFinding(
                        kind=PackageVerifyKind.REGISTRY_DRIFT,
                        severity=PackageVerifySeverity.HIGH,
                        server_name=server_name,
                        ecosystem=ref.ecosystem,
                        package=ref.name,
                        version=ref.version,
                        baseline_hash=baseline_hash,
                        current_hash=current,
                        summary=(
                            f"Registry-published hash for {ref.ecosystem} package "
                            f"'{ref.name}@{ref.version}' changed since pin — a registry must never "
                            "serve different bytes for the same version (republish/tampering)."
                        ),
                    )
                )
        return findings
