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

This module also hosts the deeper byte-level check (``ArtifactVerifier`` /
``--download-artifacts``), which downloads the actual bytes the registry serves,
hashes them, and compares against both the registry's own published hash and a
byte-hash captured at pin time:

  MCP026 (ARTIFACT_TAMPER) — served bytes don't match the registry's published
                             hash (PUBLISHED_MISMATCH, HIGH); a file pinned at
                             baseline now serves different bytes or is gone
                             (BASELINE_MISMATCH, HIGH) while a newly-added file on
                             the frozen version is an advisory (BASELINE_MISMATCH,
                             MEDIUM); UNVERIFIED (MEDIUM) when bytes can't be
                             fetched/hashed. Per-distribution-file, so a late wheel
                             upload isn't mistaken for tampering.

Network-gated: the registry is contacted ONLY when the operator passes
``--verify-artifacts`` / ``--download-artifacts`` (to scan, and to ``pin`` to
capture the baseline). A version *float* (different version than pinned) is
provenance's job (MCP021), not these checks — they key by exact
``package@version``. The fetch functions are injectable so the offline test suite
never touches the network. Artifact downloads stream through bounded hashers
(size + file-count caps), never to disk, and only to an allowlist of registry/CDN
hosts (re-validated on every redirect hop) as an SSRF guard.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import IO
from urllib.parse import quote, urlsplit

from mcp_audit.models import (
    ArtifactVerifyFinding,
    ArtifactVerifyKind,
    ArtifactVerifySeverity,
    CheckCoverage,
    PackageVerifyFinding,
    PackageVerifyKind,
    PackageVerifySeverity,
    ServerConfig,
)
from mcp_audit.terminal_text import TerminalSafeLogFilter

logger = logging.getLogger(__name__)
logger.addFilter(TerminalSafeLogFilter())

_TIMEOUT = 10
_USER_AGENT = "mcp-audit (+https://github.com/saagpatel/MCPAudit)"

# Byte-level download (MCP026) tunables. Downloads are heavier than metadata
# fetches, so they get a longer timeout and a hard size cap to bound memory and
# refuse a malicious/oversized artifact instead of streaming it forever.
_DOWNLOAD_TIMEOUT = 30
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
# Registry metadata JSON is a few KB (npm version doc) to a few MB (PyPI /json
# for old packages with many releases) — bound it far below artifact size.
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_CHUNK = 1 << 16
# A package@version with more distribution files than this is treated as unverifiable
# rather than downloaded, bounding total transfer against a metadata response that lists
# many large files (download-amplification DoS). Real releases stay well under this.
_MAX_ARTIFACT_FILES = 24

# Hosts a resolved artifact download may target. The download URL comes from
# registry *metadata*, so a poisoned metadata response could otherwise redirect
# the fetch at an internal address (SSRF). Restrict to known registry/CDN hosts.
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"registry.npmjs.org", "files.pythonhosted.org", "pypi.org"})

# Value flags per runner: options whose NEXT token is a value, so that token is
# neither the package nor the launched command. Unknown options are treated as
# boolean switches. Flags that name the package itself are listed separately.
# npm takes any config as "--key value"; these are the common value-taking ones.
_NPM_VALUE_FLAGS = {
    "-c",
    "--call",
    "-w",
    "--workspace",
    "--registry",
    "--cache",
    "--prefix",
    "--userconfig",
    "--loglevel",
    "--node-options",
    "--script-shell",
}
_NPM_PACKAGE_FLAGS = {"--package", "-p"}
_UV_VALUE_FLAGS = {
    "--with",
    "-w",  # short for --with
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--default-index",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--constraints",
    "-c",
    "--overrides",
    "--build-constraints",
    "-b",
    "--directory",
    "--project",
    "--env-file",
    "--config-file",
    "--cache-dir",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--exclude-newer",
    "--link-mode",
    "--python-platform",
    "--color",
    "--allow-insecure-host",
    "--extra",
    "--group",
    "--only-group",
    "--no-group",
    "--package",
    "--from",
    # Checked against `uv help tool run` and `uv help run` (uv 0.13.9).
    "--config-setting",
    "-C",
    "--config-settings-package",
    "--exclude-newer-package",
    "--fork-strategy",
    "--no-binary-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-editable-package",
    "--no-extra",
    "--no-sources-package",
    "--prerelease-package",
    "--refresh-package",
    "--reinstall-package",
    "--upgrade-group",
    "--upgrade-package",
    "-P",
}
# Checked against `pipx run --help` (pipx 1.18).
_PIPX_VALUE_FLAGS = {
    "--python",
    "--python-args",
    "--pip-args",
    "--index-url",
    "--spec",
    "--with",
    "--fetch-python",
    "--cooldown",
    "--backend",
}

_NPM_EXACT_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?")
# Registry-shaped names and versions. Anything else (a URL, a VCS or file source, a
# path) is never sent to a registry, so a credential inside it can never leave.
# npm names and scopes: URL-safe characters with one scope slash; a leading "_" is legal
# for existing packages (@scope/_pkg), a leading "." never is.
_NPM_NAME = re.compile(r"(?:@[a-z0-9~_-][a-z0-9._~-]*/)?[a-z0-9~_-][a-z0-9._~-]*", re.IGNORECASE)
_PYPI_NAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", re.IGNORECASE)
# PEP 440's VERSION_PATTERN (its leading "v", epoch, pre, post, dev and local label),
# e.g. 1.4.0, v1.2.3, 2!1.0rc1, 1.0.post2.dev3+abc.1.
_PYPI_EXACT_VERSION = re.compile(
    r"v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*"
    r"(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?[0-9]*)?"
    r"(?:-[0-9]+|[-_.]?(?:post|rev|r)[-_.]?[0-9]*)?"
    r"(?:[-_.]?dev[-_.]?[0-9]*)?"
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PackageRef:
    """A resolved package reference: ecosystem + name + exact version (or None)."""

    ecosystem: str  # "npm" | "pypi"
    name: str
    version: str | None

    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}:{self.version}"

    @property
    def is_exact(self) -> bool:
        """True when ``version`` names one immutable release a registry can be asked for.

        npm: a semver version (not a dist-tag such as ``latest`` or a range such as
        ``^1.2.0``). PyPI: a PEP 440 version (no ``*``; a leading ``v`` is fine). The name must be
        registry-shaped too. Only exact refs are captured at pin time and verified at
        check time, so nothing else is ever sent to a registry.
        """
        if not self.version:
            return False
        if self.ecosystem == "npm":
            return (
                _NPM_NAME.fullmatch(self.name) is not None
                and _NPM_EXACT_VERSION.fullmatch(self.version) is not None
            )
        return (
            _PYPI_NAME.fullmatch(self.name) is not None
            and _PYPI_EXACT_VERSION.fullmatch(self.version) is not None
        )


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


# One registry requirement, matched whole (an allowlist, not a blocklist): a name,
# optional extras, then optional version specifiers or uv's "@version", then an optional
# environment marker made only of plain characters. A URL, path or VCS source, or any
# fragment of one, cannot match, so it never becomes a package or reaches a registry.
_REQ_VERSIONISH = r"[A-Za-z0-9.*+!_-]+"
_REQ_SPECIFIER = rf"(?:===|==|!=|~=|>=|<=|>|<) ?{_REQ_VERSIONISH}"
# Matched against text whose whitespace runs are collapsed to single spaces, so each
# " ?" is at most one character and the match stays linear.
_PYPI_REQUIREMENT = re.compile(
    rf"(?P<name>{_PYPI_NAME.pattern}) ?"
    r"(?:\[ ?[A-Za-z0-9._-]+(?: ?, ?[A-Za-z0-9._-]+)* ?\] ?)?"
    rf"(?:(?P<specs>{_REQ_SPECIFIER}(?: ?, ?{_REQ_SPECIFIER})*) ?|@(?P<at>{_REQ_VERSIONISH}))?"
    r"(?:;[A-Za-z0-9_ .,<>=!~\"'()]*)?",
    re.IGNORECASE,
)
# Real requirements are short; longer text is never a registry requirement.
_MAX_REQUIREMENT_LENGTH = 512


def _pypi_ref(spec: str, *, at_version: bool = False) -> PackageRef | None:
    """A PyPI ref for one registry requirement, or None for anything else.

    Only a single ``==`` specifier holding a PEP 440 version pins a release
    (``pkg==2!1.0`` included); other specifiers (``>=1``, ``==1,<2``) give an unpinned
    ref. With ``at_version`` (uv's ``pkg@1.2.3`` spelling) the part after ``@`` is the
    version, and ``@latest`` pins nothing. A source URL, path or VCS requirement, or
    any string that is not one plain requirement, gives None.
    """
    if len(spec) > _MAX_REQUIREMENT_LENGTH:
        return None
    match = _PYPI_REQUIREMENT.fullmatch(" ".join(spec.split()))
    if match is None or (match.group("at") is not None and not at_version):
        return None
    version: str | None = None
    if match.group("at") is not None:
        version = None if match.group("at").lower() == "latest" else match.group("at")
    elif match.group("specs"):
        single = re.fullmatch(r"== ?(\S+)", match.group("specs").strip())
        if single is not None and _PYPI_EXACT_VERSION.fullmatch(single.group(1)):
            version = single.group(1)
    return PackageRef("pypi", match.group("name"), version)


@dataclass
class _ParsedArgs:
    """Options a runner consumed before its first positional, and that positional."""

    values: dict[str, list[str]] = field(default_factory=dict)
    positional: str | None = None
    rest: list[str] = field(default_factory=list)


def _parse_runner_args(args: list[str], value_flags: set[str]) -> _ParsedArgs:
    """Read options up to the first positional; everything after it belongs to it.

    ``--flag value`` and ``--flag=value`` are recorded under ``--flag`` when it is a
    value flag. ``--`` ends the options, so the next token is the positional.
    """
    parsed = _ParsedArgs()
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            if i + 1 < len(args):
                parsed.positional, parsed.rest = args[i + 1], args[i + 2 :]
            return parsed
        if arg.startswith("-") and "=" in arg and arg.split("=", 1)[0] in value_flags:
            flag, value = arg.split("=", 1)
            parsed.values.setdefault(flag, []).append(value)
            i += 1
            continue
        if arg in value_flags:
            if i + 1 < len(args):
                parsed.values.setdefault(arg, []).append(args[i + 1])
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        parsed.positional, parsed.rest = arg, args[i + 1 :]
        return parsed
    return parsed


def _split_requirements(value: str) -> list[str]:
    """Split a comma-separated requirement list, keeping commas inside extras or quotes.

    ``a==1,pkg[x,y]==2; python_version in "3.12,3.13"`` is two requirements.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    quote: str | None = None
    for char in value:
        if quote is not None:
            quote = None if char == quote else quote
        elif char in "\"'":
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _with_refs(parsed: _ParsedArgs, *, uv: bool = True) -> list[PackageRef]:
    """Registry packages installed alongside the command (``--with``, uv's ``-w``).

    uv takes a comma-separated list (``--with a==1,b``) and its ``pkg@1.0`` spelling;
    pipx takes one requirement per ``--with``. Unless every item of a value is one
    plain registry requirement, the whole value is dropped, so no piece of a URL (such
    as a query string after a comma) can ever be read as a package.
    """
    refs: list[PackageRef] = []
    for value in [*parsed.values.get("--with", []), *parsed.values.get("-w", [])]:
        items = [_pypi_ref(item, at_version=uv) for item in (_split_requirements(value) if uv else [value])]
        if items and all(item is not None for item in items):
            refs.extend(item for item in items if item is not None)
    return refs


def _npm_spec_refs(specs: list[str]) -> list[PackageRef]:
    return [PackageRef("npm", *_split_npm_spec(spec)) for spec in specs if spec]


def _npx_refs(args: list[str]) -> list[PackageRef]:
    """``npx``: options end at the first positional. Every ``--package``/``-p`` is a
    package; without one, the first positional is."""
    parsed = _parse_runner_args(args, _NPM_VALUE_FLAGS | _NPM_PACKAGE_FLAGS)
    named = [value for flag in ("--package", "-p") for value in parsed.values.get(flag, [])]
    return _npm_spec_refs(named or [parsed.positional or ""])


def _npm_refs(args: list[str]) -> list[PackageRef]:
    """``npm``: options are read anywhere until ``--`` (unlike npx), and ``-p`` is the
    boolean ``--parseable``, not a package. Only ``exec``/``x`` launch a package: every
    ``--package``, or else the command."""
    packages: list[str] = []
    positionals: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positionals.extend(args[i + 1 :])
            break
        flag, has_value, value = arg.partition("=")
        if arg.startswith("-") and has_value and flag == "--package":
            packages.append(value)
            i += 1
        elif arg == "--package":
            packages.extend(args[i + 1 : i + 2])
            i += 2
        elif arg.startswith("-") and has_value and flag in _NPM_VALUE_FLAGS:
            i += 1
        elif arg in _NPM_VALUE_FLAGS:
            i += 2
        elif arg.startswith("-"):
            i += 1
        else:
            positionals.append(arg)
            i += 1
    if not positionals or positionals[0] not in {"exec", "x"}:
        return []
    return _npm_spec_refs(packages or positionals[1:2])


def _uv_tool_run_refs(args: list[str]) -> list[PackageRef]:
    """``uvx`` / ``uv tool run``: the package (``--from`` or the command) plus ``--with``."""
    parsed = _parse_runner_args(args, _UV_VALUE_FLAGS)
    source = parsed.values.get("--from", [None])[0] or parsed.positional
    ref = _pypi_ref(source, at_version=True) if source else None
    return ([ref] if ref else []) + _with_refs(parsed)


def resolve_package_refs(server_config: ServerConfig) -> list[PackageRef]:
    """Resolve the registry packages a server's launch installs and runs, each once.

    See ``_resolve_package_refs`` for the per-runner grammar.
    """
    return list(dict.fromkeys(_resolve_package_refs(server_config)))


def _resolve_package_refs(server_config: ServerConfig) -> list[PackageRef]:
    """Resolve the registry packages a server's launch installs and runs.

    Best-effort: returns an empty list when the launch isn't a recognised package
    runner or the spec can't be parsed (never invents a ref). Per runner:

    - ``npx``: every ``--package``/``-p``, or else the first positional.
    - ``npm exec``/``npm x``: every ``--package`` (npm reads options anywhere until
      ``--``; its ``-p`` is ``--parseable``), or else the command. Other ``npm``
      subcommands (``npm run build``) launch no registry package.
    - ``uvx`` and ``uv tool run``: the package (``--from`` or the command; ``pkg==1.0``
      and uv's ``pkg@1.0``) plus each ``--with`` requirement.
    - ``uv run``: only ``--with`` requirements; the command or script is local.
    - ``pipx run``: the package (``--spec`` or the first positional) plus ``--with``.

    PyPI direct references (``tool @ https://host/tool.whl``, VCS, paths) are not
    registry packages and resolve to nothing.
    """
    command = (server_config.command or "").rsplit("/", 1)[-1].lower()
    args = [str(a) for a in server_config.args]

    if command == "npx":
        return _npx_refs(args)
    if command == "npm":
        return _npm_refs(args)
    if command == "uvx":
        return _uv_tool_run_refs(args)
    if command == "uv":
        parsed = _parse_runner_args(args, _UV_VALUE_FLAGS)
        if parsed.positional == "tool" and parsed.rest[:1] == ["run"]:
            return _uv_tool_run_refs(parsed.rest[1:])
        if parsed.positional == "run":
            return _with_refs(_parse_runner_args(parsed.rest, _UV_VALUE_FLAGS))
        return []
    if command == "pipx":
        parsed = _parse_runner_args(args, _PIPX_VALUE_FLAGS)
        if parsed.positional != "run":
            return []
        run = _parse_runner_args(parsed.rest, _PIPX_VALUE_FLAGS)
        spec = run.values.get("--spec", [None])[0] or run.positional
        ref = _pypi_ref(spec) if spec else None
        return ([ref] if ref else []) + _with_refs(run, uv=False)
    return []


def _iter_pinned_refs(
    server_config: ServerConfig, baseline_hashes: dict[str, str], *, artifact: bool = False
) -> Iterator[tuple[PackageRef, str]]:
    """Yield ``(ref, baseline_hash)`` for each baseline entry whose exact pinned ref
    still resolves from the current launch config, in deterministic sorted-key order.

    Shared by the MCP025 (metadata) and MCP026 (byte-level) verifiers. A baseline key
    whose ref no longer resolves (version floated / package removed) is skipped — that
    is provenance's signal (MCP021), not a verification finding here. Yielded refs
    always carry a version.
    """
    refs_by_key = {ref.key(): ref for ref in resolve_package_refs(server_config) if ref.is_exact}
    for key, baseline_hash in sorted(baseline_hashes.items()):
        ref = refs_by_key.get(key)
        usable = bool(baseline_hash)
        if artifact:
            files = _parse_files(baseline_hash)
            usable = bool(files) and all(files.values())
        if ref is not None and usable:
            yield ref, baseline_hash


def verification_coverage(
    server_config: ServerConfig,
    baseline_hashes: dict[str, str] | None,
    verified_refs: set[str],
    *,
    artifact: bool = False,
) -> CheckCoverage:
    """Account for current, applicable and actually fetched package references."""
    refs = resolve_package_refs(server_config)
    applicable = {
        ref.key() for ref, _ in _iter_pinned_refs(server_config, baseline_hashes or {}, artifact=artifact)
    }
    if not applicable:
        return CheckCoverage(state="not_run", reason="no current package reference has a usable baseline")
    if not refs or len(applicable) != len(refs) or verified_refs != applicable:
        return CheckCoverage(state="partial", reason="package references not fully verified")
    return CheckCoverage(state="complete", reason="all current package references verified")


class RegistryClient:
    """Fetches registry-published hashes for npm / PyPI packages over HTTPS.

    Holds a per-instance cache of fetched metadata JSON keyed by URL. Sharing one
    client between the MCP025 metadata verifier and the MCP026 byte verifier means a
    package's registry JSON (which carries both the published hash and the artifact
    download URL) is fetched once per scan instead of once per check. The cache lives
    only as long as the client, so a fresh client per scan keeps results current.
    """

    def __init__(self) -> None:
        self._json_cache: dict[str, dict[str, object]] = {}
        # analyze_server runs per-server under anyio.to_thread concurrently, all sharing
        # this client; guard the cache so concurrent workers can't race on the dict.
        self._cache_lock = threading.Lock()

    def _get_json(self, url: str) -> dict[str, object] | None:
        with self._cache_lock:
            cached = self._json_cache.get(url)
        if cached is not None:
            return cached
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310 (https only)
                # Bounded read: a hostile response must not exhaust memory.
                raw = resp.read(_MAX_METADATA_BYTES + 1)
                if len(raw) > _MAX_METADATA_BYTES:
                    logger.debug("Registry metadata response exceeded cap: %s", url)
                    result = None
                else:
                    data = json.loads(raw.decode("utf-8"))
                    result = data if isinstance(data, dict) else None
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            logger.debug("Registry fetch failed: %s", url)
            result = None
        # Cache successes only — a transient failure must not become sticky and get
        # served to the other check (verify/download) for the rest of the scan.
        if result is not None:
            with self._cache_lock:
                self._json_cache.setdefault(url, result)
        return result

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

    def _npm_artifact(self, name: str, version: str) -> ArtifactResult | None:
        url = f"https://registry.npmjs.org/{quote(name, safe='@/')}/{quote(version, safe='')}"
        data = self._get_json(url)
        dist = data.get("dist") if data else None
        if not isinstance(dist, dict):
            return None
        tarball = dist.get("tarball")
        if not isinstance(tarball, str):
            return None
        # sha256 is our stable baseline; the SRI algos (256/384/512) verify the
        # registry's own integrity claim, sha1 covers the legacy `shasum` field.
        digests = _download_digests(tarball, ("sha256", "sha384", "sha512", "sha1"))
        if digests is None:
            return None
        consistent = self._npm_consistent(dist, digests)
        if consistent is None:
            return None  # no integrity/shasum we can verify against — nothing to compare
        filename = tarball.rsplit("/", 1)[-1] or "tarball"
        return ArtifactResult(files={filename: digests["sha256"]}, published_consistent=consistent)

    @staticmethod
    def _npm_consistent(dist: dict[str, object], digests: dict[str, str]) -> bool | None:
        """Whether the downloaded bytes match npm's published integrity/shasum, or None.

        ``dist.integrity`` is an SRI string (``<algo>-<base64>`` tokens, possibly
        multiple, whitespace-separated). Compare against whichever algorithm the
        registry actually published rather than assuming sha512: decode each token and
        compare raw digest bytes. Returns None (unverifiable) when integrity is present
        but uses only algorithms we did not compute — never a false mismatch.
        """
        integrity = dist.get("integrity")
        if isinstance(integrity, str) and integrity:
            checkable = False
            for token in integrity.split():
                algo, _, b64 = token.partition("-")
                hex_digest = digests.get(algo)
                if not hex_digest or not b64:
                    continue  # algorithm we didn't compute, or malformed token
                try:
                    published_raw = base64.b64decode(b64, validate=True)
                except ValueError:
                    continue
                checkable = True
                if published_raw == bytes.fromhex(hex_digest):
                    return True
            return False if checkable else None
        shasum = dist.get("shasum")
        if isinstance(shasum, str) and shasum:
            return digests["sha1"] == shasum.lower()
        return None

    def _pypi_artifact(self, name: str, version: str) -> ArtifactResult | None:
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
        data = self._get_json(url)
        urls = data.get("urls") if data else None
        if not isinstance(urls, list):
            return None
        files = [
            u
            for u in urls
            if isinstance(u, dict)
            and isinstance(u.get("url"), str)
            and isinstance(u.get("digests"), dict)
            and u["digests"].get("sha256")
        ]
        if not files:
            return None
        if len(files) > _MAX_ARTIFACT_FILES:
            # Bound total transfer against metadata listing an implausible file count.
            logger.debug("PyPI %s==%s lists %d files (> cap); skipping", name, version, len(files))
            return None
        computed: dict[str, str] = {}
        consistent = True
        for u in files:
            file_url = str(u["url"])
            digests = _download_digests(file_url, ("sha256",))
            if digests is None:
                return None  # any distribution file unfetchable -> ref is unverifiable
            filename = str(u.get("filename") or file_url.rsplit("/", 1)[-1])
            computed[filename] = digests["sha256"]
            if digests["sha256"] != str(u["digests"]["sha256"]).lower():
                consistent = False
        # Keyed by filename so the baseline compare can tell a changed pinned file
        # (tamper) from a newly-added one (a late wheel upload — advisory, not tamper).
        return ArtifactResult(files=computed, published_consistent=consistent)

    def fetch_artifact(self, ref: PackageRef) -> ArtifactResult | None:
        """Download + hash the bytes for an exact package@version, or None on failure."""
        if ref.version is None:
            return None
        if ref.ecosystem == "npm":
            return self._npm_artifact(ref.name, ref.version)
        if ref.ecosystem == "pypi":
            return self._pypi_artifact(ref.name, ref.version)
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
        Unpinned or moving versions (``latest``, ``^1.2.0``) and fetch failures are
        omitted: check time only verifies exact refs, so a baseline for anything else
        would never be checked.
        """
        captured: dict[str, str] = {}
        for ref in resolve_package_refs(server_config):
            if not ref.is_exact:
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
        verified_refs: set[str] | None = None,
    ) -> list[PackageVerifyFinding]:
        """Compare current registry hashes against the pinned baseline for one server."""
        if not baseline_hashes:
            return []

        findings: list[PackageVerifyFinding] = []
        for ref, baseline_hash in _iter_pinned_refs(server_config, baseline_hashes):
            assert ref.version is not None  # keyed refs always carry a version
            current = self._fetch(ref)
            if current and verified_refs is not None:
                verified_refs.add(ref.key())
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


# --- Byte-level artifact verification (MCP026, --download-artifacts) ---------


def is_allowed_artifact_url(url: str) -> bool:
    """True only for an HTTPS URL whose host is a known registry/CDN host.

    The download URL is taken from registry metadata; gating it here stops a
    poisoned metadata response from pointing the downloader at an internal or
    attacker-controlled host.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.scheme == "https" and parsed.hostname in _ALLOWED_DOWNLOAD_HOSTS


def _stream_digests(
    fileobj: IO[bytes], algos: tuple[str, ...], cap: int
) -> tuple[dict[str, str] | None, bool]:
    """Stream ``fileobj`` through one hasher per algo, never holding the whole file.

    Returns ``(hex_digests, True)`` on success, or ``(None, False)`` once more than
    ``cap`` bytes have been read (oversized/unbounded artifact — refuse it).
    """
    hashers = {a: hashlib.new(a) for a in algos}
    total = 0
    while True:
        chunk = fileobj.read(_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            return None, False
        for h in hashers.values():
            h.update(chunk)
    return {a: h.hexdigest() for a, h in hashers.items()}, True


def stream_sha256(fileobj: IO[bytes], cap: int) -> tuple[str | None, bool]:
    """Stream ``fileobj`` and return ``(sha256_hex, True)``, or ``(None, False)`` if capped."""
    digests, ok = _stream_digests(fileobj, ("sha256",), cap)
    if not ok or digests is None:
        return None, False
    return digests["sha256"], True


@dataclass(frozen=True)
class ArtifactResult:
    """Outcome of downloading and hashing a package@version's bytes.

    ``files`` maps each distribution filename to the sha256 we computed over its
    served bytes — one entry for npm's single tarball, N for PyPI's wheels/sdist.
    Keying by filename (rather than a flat composite) lets the baseline compare
    distinguish a *changed* pinned file (tamper, HIGH) from a *newly added* one (a
    legitimately late-uploaded wheel, advisory) — a flat set can't tell them apart
    and could be evaded by a drop-and-re-add. ``published_consistent`` is whether
    every served file matched the registry's own published hash for that version.
    """

    files: dict[str, str]
    published_consistent: bool


def _serialize_files(files: dict[str, str]) -> str:
    """Canonical ``name=sha256;name=sha256`` form (sorted) for storing a byte baseline."""
    return ";".join(f"{name}={digest}" for name, digest in sorted(files.items()))


def _parse_files(serialized: str) -> dict[str, str]:
    """Parse a ``_serialize_files`` baseline string back into ``{filename: sha256}``."""
    parsed: dict[str, str] = {}
    for part in serialized.split(";"):
        name, sep, digest = part.partition("=")
        if sep and name:
            parsed[name] = digest
    return parsed


@dataclass(frozen=True)
class ArtifactCapture:
    """Result of a pin-time capture pass: storable hashes plus operator warnings."""

    hashes: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


# A download-and-hash callable: PackageRef -> ArtifactResult (or None when the
# bytes could not be fetched/hashed). Injectable so tests never touch the network.
FetchArtifact = Callable[[PackageRef], "ArtifactResult | None"]


class _AllowlistRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject a redirect whose target host is not allowlisted, before it is followed.

    urllib follows 3xx automatically, so validating only the final URL would still let
    an allowlisted URL launder a request through an internal host (e.g. a metadata/CDN
    response that 302s to 169.254.169.254). Re-validating each hop here stops the
    connection to a disallowed host from ever being made (SSRF guard).
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not is_allowed_artifact_url(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "redirect to non-allowlisted host blocked", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_ARTIFACT_OPENER = urllib.request.build_opener(_AllowlistRedirectHandler)


def _download_digests(url: str, algos: tuple[str, ...]) -> dict[str, str] | None:
    """Download an allowlisted HTTPS artifact and return its hex digests, or None.

    None on any failure: non-allowlisted host (initial, any redirect hop, or final),
    network error, truncated response, or the size cap being exceeded. Bytes are
    streamed, never written to disk and never held whole in memory.
    """
    if not is_allowed_artifact_url(url):
        return None
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with _ARTIFACT_OPENER.open(req, timeout=_DOWNLOAD_TIMEOUT) as resp:  # noqa: S310 (https + host allowlisted)
            if not is_allowed_artifact_url(resp.geturl()):
                logger.debug("Artifact final URL left allowlist: %s -> %s", url, resp.geturl())
                return None
            digests, ok = _stream_digests(resp, algos, _MAX_ARTIFACT_BYTES)
            return digests if ok else None
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, ValueError, OSError):
        logger.debug("Artifact download failed: %s", url)
        return None


class ArtifactVerifier:
    """Downloads pinned package artifacts, hashes the bytes, and compares them.

    Two checks beyond MCP025's metadata compare: the served bytes must match the
    registry's *own* published hash (``PUBLISHED_MISMATCH``) and the byte-hash
    captured at pin time (``BASELINE_MISMATCH``). The download function is
    injectable so the offline test suite never touches the network.
    """

    def __init__(self, fetch: FetchArtifact | None = None) -> None:
        self._fetch: FetchArtifact = fetch or RegistryClient().fetch_artifact

    def capture(self, server_config: ServerConfig) -> ArtifactCapture:
        """Pin-time: download + hash the server's pinned artifacts for a byte baseline.

        Stores a sha256 only for bytes that matched the registry's published hash;
        bytes that did not are refused (never baseline poisoned bytes) and surfaced
        as a warning, as are artifacts that could not be downloaded.
        """
        capture = ArtifactCapture()
        for ref in resolve_package_refs(server_config):
            if not ref.is_exact:  # check time verifies exact refs only
                continue
            label = f"{ref.name}@{ref.version}"
            result = self._fetch(ref)
            if result is None:
                capture.warnings.append(
                    f"Could not download {ref.ecosystem} artifact '{label}' to capture a byte-hash "
                    "baseline — registry unreachable, version withdrawn, artifact too large, or "
                    "download host not allowlisted."
                )
            elif not result.published_consistent:
                capture.warnings.append(
                    f"Refused to baseline {ref.ecosystem} artifact '{label}': served bytes did not "
                    "match the registry-published hash (possible tampering). Investigate before pinning."
                )
            else:
                capture.hashes[ref.key()] = _serialize_files(result.files)
        return capture

    def analyze_server(
        self,
        server_name: str,
        server_config: ServerConfig,
        baseline_hashes: dict[str, str] | None,
        verified_refs: set[str] | None = None,
    ) -> list[ArtifactVerifyFinding]:
        """Download + hash current bytes and compare against the pinned byte baseline."""
        if not baseline_hashes:
            return []

        findings: list[ArtifactVerifyFinding] = []
        for ref, baseline_hash in _iter_pinned_refs(server_config, baseline_hashes, artifact=True):
            assert ref.version is not None  # keyed refs always carry a version
            result = self._fetch(ref)
            if (
                result is not None
                and result.files
                and all(result.files.values())
                and verified_refs is not None
            ):
                verified_refs.add(ref.key())
            if result is None:
                findings.append(
                    ArtifactVerifyFinding(
                        kind=ArtifactVerifyKind.UNVERIFIED,
                        severity=ArtifactVerifySeverity.MEDIUM,
                        server_name=server_name,
                        ecosystem=ref.ecosystem,
                        package=ref.name,
                        version=ref.version,
                        baseline_hash=baseline_hash,
                        current_hash=None,
                        summary=(
                            f"Could not download/hash {ref.ecosystem} artifact "
                            f"'{ref.name}@{ref.version}' for '{server_name}' — registry unreachable, "
                            "version withdrawn, artifact too large, or download host not allowlisted."
                        ),
                    )
                )
            elif not result.published_consistent:
                findings.append(
                    ArtifactVerifyFinding(
                        kind=ArtifactVerifyKind.PUBLISHED_MISMATCH,
                        severity=ArtifactVerifySeverity.HIGH,
                        server_name=server_name,
                        ecosystem=ref.ecosystem,
                        package=ref.name,
                        version=ref.version,
                        baseline_hash=baseline_hash,
                        current_hash=_serialize_files(result.files),
                        summary=(
                            f"Downloaded bytes for {ref.ecosystem} artifact "
                            f"'{ref.name}@{ref.version}' do not match the registry-published hash — "
                            "a CDN/mirror/man-in-the-middle is serving bytes inconsistent with the "
                            "registry's own integrity metadata."
                        ),
                    )
                )
            else:
                baseline_files = _parse_files(baseline_hash)
                current_files = result.files
                changed = sorted(
                    fn for fn, h in baseline_files.items() if fn in current_files and current_files[fn] != h
                )
                removed = sorted(fn for fn in baseline_files if fn not in current_files)
                added = sorted(fn for fn in current_files if fn not in baseline_files)
                current_serial = _serialize_files(current_files)
                if changed or removed:
                    # A file pinned at baseline now serves different bytes, or is gone:
                    # republish-in-place / tampering. HIGH.
                    detail = ", ".join(changed + [f"{fn} (removed)" for fn in removed])
                    findings.append(
                        ArtifactVerifyFinding(
                            kind=ArtifactVerifyKind.BASELINE_MISMATCH,
                            severity=ArtifactVerifySeverity.HIGH,
                            server_name=server_name,
                            ecosystem=ref.ecosystem,
                            package=ref.name,
                            version=ref.version,
                            baseline_hash=baseline_hash,
                            current_hash=current_serial,
                            summary=(
                                f"A file pinned at baseline for {ref.ecosystem} artifact "
                                f"'{ref.name}@{ref.version}' no longer serves the same bytes "
                                f"({detail}) — republish-in-place / tampering; a registry must never "
                                "serve different bytes for the same fixed version."
                            ),
                        )
                    )
                elif added:
                    # New distribution file(s) on an already-pinned version. Legitimate
                    # late wheel uploads happen, but a new artifact on a frozen version is
                    # still worth a look — advisory MEDIUM, not a HIGH tamper alarm.
                    findings.append(
                        ArtifactVerifyFinding(
                            kind=ArtifactVerifyKind.BASELINE_MISMATCH,
                            severity=ArtifactVerifySeverity.MEDIUM,
                            server_name=server_name,
                            ecosystem=ref.ecosystem,
                            package=ref.name,
                            version=ref.version,
                            baseline_hash=baseline_hash,
                            current_hash=current_serial,
                            summary=(
                                f"New distribution file(s) appeared on pinned {ref.ecosystem} version "
                                f"'{ref.name}@{ref.version}' since baseline ({', '.join(added)}) — no "
                                "pinned file changed bytes; verify the addition is expected and re-pin."
                            ),
                        )
                    )
        return findings
