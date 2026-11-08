"""Resolve a target to its published metadata and check server.json and its namespace.

Targets are an official MCP Registry name, an npm or PyPI package, or a remote
URL. Resolution only reads public registry metadata over HTTPS; it never reads
local configuration.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import quote, urlsplit

from mcp_audit.redaction import redact_text
from mcp_audit.trust.models import Check, CheckStatus, EnvVar, PackageRef, RemoteRef, Resolution, TargetKind

DEFAULT_REGISTRY_URL = "https://registry.modelcontextprotocol.io"
NPM_URL = "https://registry.npmjs.org"
PYPI_URL = "https://pypi.org"
USER_AGENT = "mcp-audit-trust (+https://github.com/saagpatel/MCPAudit)"
FETCH_TIMEOUT = 15.0
MAX_METADATA_BYTES = 8 * 1024 * 1024
SYNTHETIC_VALUE = "mcpaudit-synthetic"
LAUNCH_PLACEHOLDER = "<set-me>"

_SERVER_NAME = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_EXACT_PYPI = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[a-z0-9.]+)?$")
_STATUS_CHECK: dict[str, CheckStatus] = {"active": "pass", "deprecated": "warn", "deleted": "fail"}
_PYPI_MARKER = re.compile(r"mcp-name:\s*([A-Za-z0-9.-]+/[A-Za-z0-9._-]+)")
_PLACEHOLDER = re.compile(r"\{[^{}]*\}")


class TargetError(ValueError):
    """The target string cannot be parsed into a supported kind."""


class FetchError(Exception):
    def __init__(self, url: str, status: int | None, reason: str) -> None:
        super().__init__(f"{reason} ({url})")
        self.url, self.status, self.reason = url, status, reason


Fetcher = Callable[[str], Any]


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    name: str
    version: str | None = None


def parse_target(raw: str) -> Target:
    """Parse `registry:NAME[@V]`, `npm:PKG[@V]`, `pypi:PKG[==V]`, or an https:// URL.

    Unprefixed values are accepted when unambiguous: URLs, `@scope/pkg` (npm),
    and reverse-DNS `namespace/name` (registry).
    """
    value = raw.strip()
    if not value:
        raise TargetError("Target is empty.")
    prefix, sep, rest = value.partition(":")
    if value.startswith(("https://", "http://")):
        return _url_target(value)
    if sep and prefix in {"registry", "npm", "pypi"}:
        kind, value = cast(TargetKind, prefix), rest
    elif value.startswith("@"):
        kind = "npm"
    elif _SERVER_NAME.match(value.split("@", 1)[0]) and "." in value.split("/", 1)[0]:
        kind = "registry"
    else:
        raise TargetError(
            f"Cannot tell what {raw!r} is. Use registry:NAME, npm:PACKAGE, pypi:PACKAGE, or an https:// URL."
        )
    if kind == "registry":
        name, _, version = value.partition("@")
        if not _SERVER_NAME.match(name):
            raise TargetError(f"{name!r} is not a registry server name (namespace/name).")
        return Target("registry", name, _version(version))
    if kind == "npm":
        scoped = value.startswith("@")
        head, at, version = value[1:].partition("@") if scoped else value.partition("@")
        name = ("@" + head) if scoped else head
        if not _NPM_NAME.match(name):
            raise TargetError(f"{name!r} is not a valid npm package name.")
        return Target("npm", name, _version(version) if at else None)
    name, _, version = value.partition("==")
    if "==" not in value:
        name, _, version = value.partition("@")
    if not _PYPI_NAME.match(name):
        raise TargetError(f"{name!r} is not a valid PyPI project name.")
    return Target("pypi", name, _version(version))


def validate_package(package: PackageRef) -> None:
    """Refuse identifiers that npm or pip would read as URLs, paths, or option flags."""
    pattern = _NPM_NAME if package.registry_type == "npm" else _PYPI_NAME
    if not pattern.match(package.identifier):
        raise TargetError(
            f"Package identifier {package.identifier!r} is not a plain {package.registry_type} name."
        )
    if package.version is not None and not _VERSION.match(package.version):
        raise TargetError(f"Package version {package.version!r} is not an exact version.")


def _version(value: str) -> str | None:
    if not value:
        return None
    if not _VERSION.match(value):
        raise TargetError(f"{value!r} is not an exact version.")
    return value


def _url_target(value: str) -> Target:
    parts = urlsplit(value)
    if parts.username or parts.password:
        raise TargetError("Remote URLs must not carry credentials.")
    if parts.scheme != "https" and parts.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise TargetError("Remote URLs must use https:// (http:// is accepted for loopback only).")
    if parts.query or parts.fragment:
        raise TargetError("Remote URLs must not carry a query or fragment; they can hold credentials.")
    if not parts.hostname:
        raise TargetError("Remote URL has no host.")
    return Target("url", value)


class _AllowlistRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts: frozenset[str]) -> None:
        self.hosts = hosts

    def redirect_request(
        self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> urllib.request.Request | None:
        parts = urlsplit(newurl)
        if parts.scheme != "https" or parts.hostname not in self.hosts:
            raise FetchError(newurl, code, "redirect left the allowed metadata hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_fetcher(allowed_hosts: frozenset[str]) -> Fetcher:
    """Bounded HTTPS JSON reads from an explicit host allowlist."""
    opener = urllib.request.build_opener(_AllowlistRedirects(allowed_hosts))

    def fetch(url: str) -> Any:
        parts = urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in allowed_hosts:
            raise FetchError(url, None, "host is not an allowed metadata host")
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            with opener.open(request, timeout=FETCH_TIMEOUT) as response:
                raw = response.read(MAX_METADATA_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise FetchError(url, exc.code, f"HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise FetchError(url, None, type(exc).__name__) from None
        if len(raw) > MAX_METADATA_BYTES:
            raise FetchError(url, None, "response exceeded the metadata size cap")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise FetchError(url, None, "response was not JSON") from None

    return fetch


def default_fetcher(registry_url: str = DEFAULT_REGISTRY_URL) -> Fetcher:
    hosts = {urlsplit(registry_url).hostname or "", "registry.npmjs.org", "pypi.org"}
    return https_fetcher(frozenset(h for h in hosts if h))


def _str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _prose(value: object, limit: int = 600) -> str | None:
    """Published free text, redacted and bounded before it reaches a card."""
    text = _str(value)
    return redact_text(text)[:limit] if text else None


def _dict(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return list(value) if isinstance(value, list) else []


class Resolver:
    def __init__(self, fetch: Fetcher, registry_url: str = DEFAULT_REGISTRY_URL) -> None:
        self.fetch = fetch
        self.registry_url = registry_url.rstrip("/")

    def resolve(self, raw: str) -> Resolution:
        target = parse_target(raw)
        resolution = Resolution(input=raw, kind=target.kind)
        if target.kind == "registry":
            entry = self._registry_entry(resolution, target.name, target.version)
            if entry is not None:
                self._apply_server_json(resolution, entry)
                self._check_package(resolution)
        elif target.kind in {"npm", "pypi"}:
            self._from_package(resolution, target)
        else:
            resolution.remote = RemoteRef(type="streamable-http", url=target.name)
            self._from_url(resolution, target.name)
        return resolution

    # Registry ------------------------------------------------------------------

    def _registry_entry(
        self, resolution: Resolution, name: str, version: str | None, *, claimed: bool = False
    ) -> dict[str, Any] | None:
        path = f"{quote(name, safe='')}/versions/{quote(version or 'latest', safe='')}"
        url = f"{self.registry_url}/v0.1/servers/{path}"
        try:
            payload = _dict(self.fetch(url))
        except FetchError as exc:
            if exc.status == 404:
                resolution.registry_listed = False
                resolution.checks.append(
                    Check(
                        id="registry.listed",
                        status="warn" if claimed else "fail",
                        summary=(
                            f"The package claims registry name {name}, which the MCP Registry does not list."
                            if claimed
                            else f"{name} is not in the MCP Registry."
                        ),
                    )
                )
            else:
                resolution.checks.append(
                    Check(
                        id="registry.listed",
                        status="unknown",
                        summary=f"Registry lookup failed: {exc.reason}.",
                    )
                )
            return None
        server = _dict(payload.get("server")) or payload
        meta = _dict(_dict(payload.get("_meta")).get("io.modelcontextprotocol.registry/official"))
        resolution.registry_listed = True
        status = _str(meta.get("status")) or "unknown"
        resolution.registry_status = status
        resolution.checks.append(
            Check(id="registry.listed", status="pass", summary=f"Listed in the MCP Registry as {name}.")
        )
        resolution.checks.append(
            Check(
                id="registry.status",
                status=_STATUS_CHECK.get(status, "unknown"),
                summary=f"Registry status is {status}.",
            )
        )
        if version is None and meta.get("isLatest") is False:
            resolution.checks.append(
                Check(id="registry.latest", status="warn", summary="Registry does not mark this as latest.")
            )
        return server

    def _apply_server_json(self, resolution: Resolution, server: dict[str, Any]) -> None:
        name = _str(server.get("name"))
        resolution.server_name = name
        resolution.server_version = _str(server.get("version"))
        resolution.title = _prose(server.get("title"), 200)
        resolution.description = _prose(server.get("description"))
        resolution.repository_url = _str(_dict(server.get("repository")).get("url"))
        resolution.checks.extend(schema_checks(server))
        packages = [p for p in (_package(raw) for raw in _list(server.get("packages"))) if p is not None]
        remotes = [r for r in (_remote(raw) for raw in _list(server.get("remotes"))) if r is not None]
        if resolution.kind in {"npm", "pypi"} and resolution.package is not None:
            mine = resolution.package
            listed = next(
                (
                    p
                    for p in packages
                    if p.registry_type == mine.registry_type
                    and _same_package(mine.registry_type, p.identifier, mine.identifier)
                ),
                None,
            )
            resolution.checks.append(
                Check(
                    id="registry.lists_package",
                    status="pass" if listed else "fail",
                    summary=(
                        f"{name} lists {mine.registry_type} package {mine.identifier}."
                        if listed
                        else f"{name} does not list {mine.registry_type} package {mine.identifier}; "
                        "the package claims a registry identity it is not part of."
                    ),
                )
            )
            if listed is not None:
                mine.transport, mine.runtime_hint = listed.transport, listed.runtime_hint
                mine.env, mine.arguments = listed.env, listed.arguments
                mine.launch_arguments = listed.launch_arguments
        elif resolution.kind == "registry":
            runnable = [p for p in packages if p.registry_type in {"npm", "pypi"} and p.transport == "stdio"]
            resolution.package = runnable[0] if runnable else packages[0] if packages else None
            if resolution.package is None and remotes:
                resolution.remote = next((r for r in remotes if r.type == "streamable-http"), remotes[0])
        if name:
            resolution.checks.extend(namespace_checks(name, resolution.repository_url, remotes))

    # Packages ------------------------------------------------------------------

    def _from_package(self, resolution: Resolution, target: Target) -> None:
        if target.kind == "npm":
            data = self._npm_version(resolution, target.name, target.version)
            if data is None:
                return
            resolution.package = PackageRef(
                registry_type="npm",
                identifier=target.name,
                version=_str(data.get("version")),
                transport="stdio",
                install_scripts=npm_install_scripts(data),
            )
            marker = _str(data.get("mcpName"))
            resolution.description = _prose(data.get("description"))
            resolution.repository_url = _npm_repository(data)
        else:
            info = self._pypi_info(resolution, target.name, target.version)
            if info is None:
                return
            resolution.package = PackageRef(
                registry_type="pypi",
                identifier=_str(info.get("name")) or target.name,
                version=_str(info.get("version")),
                transport="stdio",
            )
            found = _PYPI_MARKER.search(_str(info.get("description")) or "")
            marker = found.group(1) if found else None
            resolution.description = _prose(info.get("summary"))
            urls = _dict(info.get("project_urls"))
            resolution.repository_url = _str(urls.get("Source")) or _str(urls.get("Repository"))
        if marker is None:
            resolution.registry_listed = None
            resolution.checks.append(
                Check(
                    id="registry.identity",
                    status="info",
                    summary="Package declares no MCP Registry name, so publisher identity is unverified.",
                )
            )
            return
        resolution.checks.append(
            Check(id="registry.identity", status="pass", summary=f"Package declares registry name {marker}.")
        )
        entry = self._registry_entry(resolution, marker, None, claimed=True)
        if entry is not None:
            self._apply_server_json(resolution, entry)
        resolution.server_name = resolution.server_name or marker
        self._check_package(resolution, fetched=True)

    def _npm_version(self, resolution: Resolution, name: str, version: str | None) -> dict[str, Any] | None:
        url = f"{NPM_URL}/{quote(name, safe='@/')}/{quote(version or 'latest', safe='')}"
        try:
            return _dict(self.fetch(url))
        except FetchError as exc:
            resolution.checks.append(
                Check(
                    id="package.exists",
                    status="fail" if exc.status == 404 else "unknown",
                    summary=f"npm {name}@{version or 'latest'}: {exc.reason}.",
                )
            )
            return None

    def _pypi_info(self, resolution: Resolution, name: str, version: str | None) -> dict[str, Any] | None:
        path = f"{quote(name, safe='')}/{quote(version, safe='')}" if version else quote(name, safe="")
        try:
            return _dict(_dict(self.fetch(f"{PYPI_URL}/pypi/{path}/json")).get("info"))
        except FetchError as exc:
            resolution.checks.append(
                Check(
                    id="package.exists",
                    status="fail" if exc.status == 404 else "unknown",
                    summary=f"PyPI {name} {version or 'latest'}: {exc.reason}.",
                )
            )
            return None

    def _check_package(self, resolution: Resolution, *, fetched: bool = False) -> None:
        """Confirm the listed package exists and points back at the registry name."""
        package = resolution.package
        if package is None:
            if resolution.remote is None:
                resolution.checks.append(
                    Check(
                        id="package.runnable",
                        status="fail",
                        summary="server.json lists no package or remote.",
                    )
                )
            return
        if package.registry_type not in {"npm", "pypi"}:
            resolution.checks.append(
                Check(
                    id="package.runnable",
                    status="unknown",
                    summary=f"{package.registry_type} packages are not run in this milestone.",
                )
            )
            return
        if not is_exact_version(package.registry_type, package.version):
            resolution.checks.append(
                Check(
                    id="package.version",
                    status="warn",
                    summary=f"Package version {package.version or '(none)'} is not pinned exactly.",
                )
            )
        if fetched:
            return
        if package.registry_type == "npm":
            data = self._npm_version(resolution, package.identifier, package.version)
            marker = _str(data.get("mcpName")) if data else None
            if data is not None:
                package.install_scripts = npm_install_scripts(data)
        else:
            info = self._pypi_info(resolution, package.identifier, package.version)
            found = _PYPI_MARKER.search(_str(info.get("description")) or "") if info else None
            marker = found.group(1) if found else None
            data = info
        if data is None:
            return
        concrete = _str(data.get("version"))
        if concrete and concrete != package.version:
            # A tag or partial version resolves to one release; outputs name that one.
            package.version = concrete
        resolution.checks.append(
            Check(
                id="package.exists",
                status="pass",
                summary=f"{package.registry_type} {package.identifier} {package.version} exists.",
            )
        )
        expected = resolution.server_name
        where = "package.json mcpName" if package.registry_type == "npm" else "PyPI description mcp-name"
        resolution.checks.append(
            Check(
                id="namespace.package_ownership",
                status="pass" if marker == expected else "fail",
                summary=(
                    f"{where} matches {expected}."
                    if marker == expected
                    else f"{where} is {marker or 'missing'}, expected {expected}; "
                    "the package does not confirm this registry entry."
                ),
            )
        )

    # Remote URLs ---------------------------------------------------------------

    def _from_url(self, resolution: Resolution, url: str) -> None:
        host = urlsplit(url).hostname or ""
        labels = host.split(".")
        resolution.checks.append(
            Check(
                id="remote.https",
                status="pass" if url.startswith("https://") else "warn",
                summary="Remote uses HTTPS."
                if url.startswith("https://")
                else "Remote is plain HTTP (loopback).",
            )
        )
        if len(labels) < 2:
            return
        namespace = ".".join(reversed(labels[-2:]))
        search = (
            f"{self.registry_url}/v0.1/servers?search={quote(namespace, safe='')}&limit=50&version=latest"
        )
        try:
            payload = _dict(self.fetch(search))
        except FetchError as exc:
            resolution.checks.append(
                Check(
                    id="registry.listed", status="unknown", summary=f"Registry search failed: {exc.reason}."
                )
            )
            return
        wanted = _normal_url(url)
        outsiders: list[str] = []
        for entry in _list(payload.get("servers")):
            server = _dict(_dict(entry).get("server"))
            remotes = [r for r in (_remote(raw) for raw in _list(server.get("remotes"))) if r is not None]
            if not any(_normal_url(r.url) == wanted for r in remotes):
                continue
            if not namespace_covers(_str(server.get("name")) or "", host):
                # Anyone can list any URL; only an entry whose verified namespace owns the
                # host speaks for it.
                outsiders.append(_str(server.get("name")) or "?")
                continue
            resolution.registry_listed = True
            resolution.checks.append(
                Check(
                    id="registry.listed",
                    status="pass",
                    summary=f"Registry entry {server.get('name')} lists this remote.",
                )
            )
            self._apply_server_json(resolution, server)
            # Enrich with registry metadata, but always connect to the URL the user gave.
            listed = next(r for r in remotes if _normal_url(r.url) == wanted)
            resolution.remote = RemoteRef(type=listed.type, url=url)
            return
        resolution.registry_listed = False
        resolution.checks.append(
            Check(
                id="registry.listed",
                status="warn" if outsiders else "info",
                summary=(
                    "Registry entries outside the host's namespace list this remote: "
                    + ", ".join(outsiders[:3])
                    + "."
                    if outsiders
                    else f"No registry entry under {namespace} lists this remote."
                ),
            )
        )


def namespace_covers(name: str, host: str) -> bool:
    """Whether a reverse-DNS registry namespace owns this host (io.github.* never does)."""
    namespace = name.split("/", 1)[0].lower()
    if not namespace or namespace.startswith("io.github."):
        return False
    domain = ".".join(reversed(namespace.split(".")))
    host = host.lower()
    return host == domain or host.endswith("." + domain)


def _same_package(kind: str, left: str, right: str) -> bool:
    if kind == "pypi":
        return re.sub(r"[-_.]+", "-", left).lower() == re.sub(r"[-_.]+", "-", right).lower()
    return left.lower() == right.lower()


def is_exact_version(kind: str, version: str | None) -> bool:
    pattern = _EXACT_NPM if kind == "npm" else _EXACT_PYPI
    return version is not None and pattern.match(version) is not None


def _normal_url(url: str) -> str:
    """Endpoint identity: scheme, credentials, host, effective port, path and query all count."""
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    userinfo = f"{parts.username or ''}:{parts.password or ''}@" if parts.username or parts.password else ""
    query = f"?{parts.query}" if parts.query else ""
    return (
        f"{parts.scheme}://{userinfo}{(parts.hostname or '').lower()}:{port}{parts.path.rstrip('/')}{query}"
    )


def _package(raw: object) -> PackageRef | None:
    data = _dict(raw)
    identifier = _str(data.get("identifier"))
    if identifier is None:
        return None
    kind = _str(data.get("registryType")) or "other"
    env = [
        EnvVar(
            name=str(e["name"]),
            required=e.get("isRequired") is True,
            secret=e.get("isSecret") is True,
            has_default=e.get("default") is not None or e.get("value") is not None,
            description=_str(e.get("description")),
        )
        for e in map(_dict, _list(data.get("environmentVariables")))
        if _str(e.get("name"))
    ]
    return PackageRef(
        registry_type=cast(Any, kind if kind in {"npm", "pypi", "oci"} else "other"),
        identifier=identifier,
        version=_str(data.get("version")),
        transport=_str(_dict(data.get("transport")).get("type")),
        runtime_hint=_str(data.get("runtimeHint")),
        env=env,
        arguments=synthetic_arguments(_list(data.get("packageArguments"))),
        launch_arguments=synthetic_arguments(_list(data.get("packageArguments")), LAUNCH_PLACEHOLDER),
    )


def synthetic_arguments(arguments: list[Any], fill: str = SYNTHETIC_VALUE) -> list[str]:
    """Build argv from declared package arguments; placeholders and required gaps get `fill`."""
    argv: list[str] = []
    for arg in map(_dict, arguments):
        value = _str(arg.get("value")) or _str(arg.get("default"))
        if value is None and arg.get("isRequired") is not True:
            continue
        value = _PLACEHOLDER.sub(fill, value) if value else fill
        if arg.get("type") == "named":
            flag = _str(arg.get("name"))
            if flag is None:
                continue
            argv.append(flag)
        argv.append(value)
    return argv


def _remote(raw: object) -> RemoteRef | None:
    data = _dict(raw)
    url = _str(data.get("url"))
    return RemoteRef(type=_str(data.get("type")) or "streamable-http", url=url) if url else None


def npm_install_scripts(data: dict[str, Any]) -> list[str]:
    scripts = _dict(data.get("scripts"))
    return sorted(k for k in ("preinstall", "install", "postinstall") if _str(scripts.get(k)))


def _npm_repository(data: dict[str, Any]) -> str | None:
    repo = data.get("repository")
    if isinstance(repo, str):
        return repo
    return _str(_dict(repo).get("url"))


def schema_checks(server: dict[str, Any]) -> list[Check]:
    """Minimal structural checks on server.json; the registry validates the rest at publish."""
    problems: list[str] = []
    name = _str(server.get("name"))
    if name is None or not _SERVER_NAME.match(name):
        problems.append("name is not namespace/name")
    if not _str(server.get("description")):
        problems.append("description is missing")
    version = _str(server.get("version"))
    if version is None or not _VERSION.match(version):
        problems.append("version is missing or not exact")
    for raw in _list(server.get("packages")):
        package = _dict(raw)
        if not _str(package.get("identifier")) or not _str(_dict(package.get("transport")).get("type")):
            problems.append("a package lacks identifier or transport")
    for raw in _list(server.get("remotes")):
        url = _str(_dict(raw).get("url")) or ""
        if not url.startswith("https://"):
            problems.append("a remote URL is not https")
    if not _list(server.get("packages")) and not _list(server.get("remotes")):
        problems.append("no packages or remotes")
    if problems:
        return [
            Check(id="server_json.shape", status="warn", summary="server.json: " + "; ".join(problems) + ".")
        ]
    return [Check(id="server_json.shape", status="pass", summary="server.json has the expected shape.")]


def namespace_checks(name: str, repository_url: str | None, remotes: list[RemoteRef]) -> list[Check]:
    """Compare the namespace's claimed owner with the repository and remote hosts.

    The registry authenticates the namespace at publish time (GitHub login for
    io.github.*, DNS or HTTP proof for reverse-DNS names). Repository URLs and
    remote hosts are free text, so a mismatch is a claim to review.
    """
    namespace = name.split("/", 1)[0].lower()
    checks: list[Check] = []
    if namespace.startswith("io.github."):
        owner = namespace.removeprefix("io.github.")
        repo = urlsplit(repository_url or "")
        repo_owner = repo.path.strip("/").split("/", 1)[0].lower() if repo.hostname == "github.com" else None
        if repository_url is None:
            checks.append(
                Check(id="namespace.repository", status="warn", summary="No repository URL declared.")
            )
        elif repo_owner == owner:
            checks.append(
                Check(
                    id="namespace.repository",
                    status="pass",
                    summary=f"Repository owner matches GitHub namespace {owner}.",
                )
            )
        else:
            checks.append(
                Check(
                    id="namespace.repository",
                    status="warn",
                    summary=f"Namespace owner {owner} does not match repository {repository_url}.",
                )
            )
        domain = None
    else:
        domain = ".".join(reversed(namespace.split(".")))
    for remote in remotes:
        host = (urlsplit(remote.url).hostname or "").lower()
        if domain is None:
            continue
        ok = host == domain or host.endswith("." + domain)
        checks.append(
            Check(
                id="namespace.remote_host",
                status="pass" if ok else "warn",
                summary=(
                    f"Remote host {host} is under namespace domain {domain}."
                    if ok
                    else f"Remote host {host} is outside namespace domain {domain}."
                ),
            )
        )
    return checks
