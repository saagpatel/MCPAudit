"""Trust Before Connect resolver: target parsing, registry, npm and PyPI checks.

Everything here is synthetic: fake registry payloads served by FakeFetch.
"""

from __future__ import annotations

from typing import Any

import pytest

from mcp_audit.trust.models import PackageRef, RemoteRef, Resolution
from mcp_audit.trust.resolve import (
    FetchError,
    Resolver,
    TargetError,
    namespace_checks,
    parse_target,
    synthetic_arguments,
    validate_package,
)

REGISTRY = "https://registry.example.test"


NAME = "io.github.example-owner/notes"


def server_json(**overrides: Any) -> dict[str, Any]:
    server: dict[str, Any] = {
        "name": NAME,
        "description": "Synthetic notes server.",
        "version": "1.2.3",
        "repository": {"url": "https://github.com/example-owner/notes", "source": "github"},
        "packages": [
            {
                "registryType": "npm",
                "identifier": "@example-owner/notes-mcp",
                "version": "1.2.3",
                "transport": {"type": "stdio"},
                "environmentVariables": [
                    {"name": "NOTES_TOKEN", "isRequired": True, "isSecret": True},
                    {"name": "NOTES_DIR", "default": "~/.notes"},
                ],
                "packageArguments": [{"type": "named", "name": "--root", "isRequired": True}],
            }
        ],
    }
    server.update(overrides)
    return server


class FakeFetch:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.seen: list[str] = []

    def __call__(self, url: str) -> Any:
        self.seen.append(url)
        for prefix, value in self.routes.items():
            if url.startswith(prefix):
                if isinstance(value, int):
                    raise FetchError(url, value, f"HTTP {value}")
                return value
        raise FetchError(url, 404, "HTTP 404")


def registry_routes(server: dict[str, Any], mcp_name: str | None = NAME) -> dict[str, Any]:
    npm = {"name": "@example-owner/notes-mcp", "version": "1.2.3", "bin": {"notes-mcp": "cli.js"}}
    if mcp_name:
        npm["mcpName"] = mcp_name
    meta = {"io.modelcontextprotocol.registry/official": {"status": "active", "isLatest": True}}
    return {
        f"{REGISTRY}/v0.1/servers/io.github.example-owner%2Fnotes/versions/": {
            "server": server,
            "_meta": meta,
        },
        "https://registry.npmjs.org/@example-owner/notes-mcp/": npm,
    }


def statuses(resolution: Resolution) -> dict[str, str]:
    return {check.id: check.status for check in resolution.checks}


@pytest.mark.parametrize(
    ("raw", "kind", "name", "version"),
    [
        ("io.github.owner/server", "registry", "io.github.owner/server", None),
        ("registry:com.example/srv@2.0.0", "registry", "com.example/srv", "2.0.0"),
        ("npm:left-pad", "npm", "left-pad", None),
        ("@scope/pkg@1.0.0", "npm", "@scope/pkg", "1.0.0"),
        ("pypi:mcp-thing==0.4.1", "pypi", "mcp-thing", "0.4.1"),
        ("https://mcp.example.com/mcp", "url", "https://mcp.example.com/mcp", None),
        ("http://127.0.0.1:8080/mcp", "url", "http://127.0.0.1:8080/mcp", None),
    ],
)
def test_parse_target(raw: str, kind: str, name: str, version: str | None) -> None:
    target = parse_target(raw)
    assert (target.kind, target.name, target.version) == (kind, name, version)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "left-pad",
        "http://mcp.example.com/mcp",
        "https://user:secret@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?token=abc",
        "npm:../evil",
        "pypi:pkg==>=1.0",
        "npm:pkg@^1.0.0",
    ],
)
def test_parse_target_rejects(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)


@pytest.mark.parametrize(
    "package",
    [
        PackageRef(registry_type="npm", identifier="git+https://evil.example/x.git"),
        PackageRef(registry_type="npm", identifier="file:../x"),
        PackageRef(registry_type="pypi", identifier="--index-url=https://evil.example"),
        PackageRef(registry_type="npm", identifier="ok", version="latest || rm -rf"),
    ],
)
def test_validate_package_rejects_non_names(package: PackageRef) -> None:
    with pytest.raises(TargetError):
        validate_package(package)


def test_registry_resolution_passes_namespace_and_ownership() -> None:
    resolution = Resolver(FakeFetch(registry_routes(server_json())), REGISTRY).resolve(NAME)
    assert resolution.registry_listed is True
    assert resolution.package is not None
    assert resolution.package.identifier == "@example-owner/notes-mcp"
    assert resolution.package.arguments == ["--root", "mcpaudit-synthetic"]
    assert [e.name for e in resolution.package.env if e.required] == ["NOTES_TOKEN"]
    assert statuses(resolution) == {
        "registry.listed": "pass",
        "registry.status": "pass",
        "server_json.shape": "pass",
        "namespace.repository": "pass",
        "package.exists": "pass",
        "namespace.package_ownership": "pass",
    }


def test_registry_resolution_flags_missing_ownership_marker() -> None:
    routes = registry_routes(server_json(), mcp_name=None)
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve(NAME)
    assert statuses(resolution)["namespace.package_ownership"] == "fail"


def test_repository_owner_mismatch_is_a_warning() -> None:
    server = server_json(repository={"url": "https://github.com/someone-else/notes"})
    resolution = Resolver(FakeFetch(registry_routes(server)), REGISTRY).resolve(NAME)
    assert statuses(resolution)["namespace.repository"] == "warn"


def test_unlisted_registry_name_fails() -> None:
    resolution = Resolver(FakeFetch({}), REGISTRY).resolve("io.github.nobody/missing")
    assert resolution.registry_listed is False
    assert statuses(resolution) == {"registry.listed": "fail"}


def test_npm_package_claiming_unlisted_name_warns() -> None:
    routes = {
        "https://registry.npmjs.org/claimer/": {"name": "claimer", "version": "0.1.0", "mcpName": NAME},
    }
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("npm:claimer")
    assert statuses(resolution)["registry.listed"] == "warn"
    assert resolution.package is not None and resolution.package.version == "0.1.0"


def test_npm_package_not_listed_in_its_claimed_entry_fails() -> None:
    routes = registry_routes(server_json())
    routes["https://registry.npmjs.org/impostor/"] = {"name": "impostor", "version": "9.0.0", "mcpName": NAME}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("npm:impostor")
    assert statuses(resolution)["registry.lists_package"] == "fail"


def test_npm_install_scripts_are_recorded() -> None:
    routes = registry_routes(server_json())
    routes["https://registry.npmjs.org/@example-owner/notes-mcp/"] |= {
        "scripts": {"postinstall": "node setup.js", "test": "x", "prepare": "tsc"}
    }
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve(NAME)
    assert resolution.package is not None and resolution.package.install_scripts == ["postinstall"]


def test_pypi_marker_in_description() -> None:
    routes = {
        "https://pypi.org/pypi/notes-py/json": {
            "info": {
                "name": "notes-py",
                "version": "0.2.0",
                "summary": "Synthetic.",
                "description": "Readme\n<!-- mcp-name: io.github.example-owner/notes -->",
            }
        }
    }
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("pypi:notes-py")
    assert statuses(resolution)["registry.identity"] == "pass"
    assert resolution.server_name == NAME


def test_remote_url_found_through_registry_search() -> None:
    server = {
        "name": "com.example/remote",
        "description": "Synthetic remote.",
        "version": "1.0.0",
        "remotes": [{"type": "streamable-http", "url": "https://mcp.example.com/mcp"}],
    }
    routes = {f"{REGISTRY}/v0.1/servers?search=com.example": {"servers": [{"server": server}]}}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is True
    assert resolution.server_name == "com.example/remote"
    assert statuses(resolution)["namespace.remote_host"] == "pass"


def test_reverse_dns_remote_outside_domain_warns() -> None:

    checks = namespace_checks(
        "com.example/x", None, [RemoteRef(type="streamable-http", url="https://evil.test/mcp")]
    )
    assert [c.status for c in checks] == ["warn"]


def test_synthetic_arguments_fill_placeholders() -> None:
    argv = synthetic_arguments(
        [
            {"type": "positional", "value": "serve"},
            {"type": "named", "name": "--db", "value": "{dir}/db.sqlite"},
            {"type": "named", "name": "--optional"},
        ]
    )
    assert argv == ["serve", "--db", "mcpaudit-synthetic/db.sqlite"]


def test_pypi_listing_normalizes_names() -> None:
    server = server_json(
        packages=[
            {
                "registryType": "pypi",
                "identifier": "notes-py",
                "version": "0.2.0",
                "transport": {"type": "stdio"},
            }
        ]
    )
    routes = registry_routes(server)
    routes["https://pypi.org/pypi/notes_py/json"] = {
        "info": {"name": "Notes_Py", "version": "0.2.0", "description": f"<!-- mcp-name: {NAME} -->"}
    }
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("pypi:notes_py")
    assert statuses(resolution)["registry.lists_package"] == "pass"


def test_mutable_registry_version_resolves_to_concrete_release() -> None:
    server = server_json()
    server["packages"][0]["version"] = "latest"
    resolution = Resolver(FakeFetch(registry_routes(server)), REGISTRY).resolve(NAME)
    assert statuses(resolution)["package.version"] == "warn"
    assert resolution.package is not None and resolution.package.version == "1.2.3"


@pytest.mark.parametrize(
    "listed",
    [
        "https://mcp.example.com:9999/mcp",
        "https://user:secret@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?token=abc",
    ],
)
def test_registry_remote_must_match_the_exact_endpoint(listed: str) -> None:
    server = {
        "name": "com.example/remote",
        "description": "x",
        "version": "1.0.0",
        "remotes": [{"url": listed}],
    }
    routes = {f"{REGISTRY}/v0.1/servers?search=com.example": {"servers": [{"server": server}]}}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is False
    assert resolution.remote is not None and resolution.remote.url == "https://mcp.example.com/mcp"


def test_registry_match_keeps_the_user_supplied_url() -> None:
    server = {
        "name": "com.example/remote",
        "description": "x",
        "version": "1.0.0",
        "remotes": [{"type": "sse", "url": "https://mcp.example.com:443/mcp"}],
    }
    routes = {f"{REGISTRY}/v0.1/servers?search=com.example": {"servers": [{"server": server}]}}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is True
    assert resolution.remote is not None and resolution.remote.url == "https://mcp.example.com/mcp"


def test_remote_listed_only_by_an_outside_namespace_is_not_claimed() -> None:
    server = {
        "name": "io.github.someone/com.example-lookalike",
        "description": "x",
        "version": "1.0.0",
        "remotes": [{"url": "https://mcp.example.com/mcp"}],
    }
    routes = {f"{REGISTRY}/v0.1/servers?search=com.example": {"servers": [{"server": server}]}}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is False and resolution.server_name is None
    assert statuses(resolution)["registry.listed"] == "warn"


# PR split review fixes --------------------------------------------------------------


def remote_server(url: str, name: str = "com.example/remote") -> dict[str, Any]:
    return {"name": name, "description": "x", "version": "1.0.0", "remotes": [{"url": url}]}


def search_routes(*entries: dict[str, Any], cursor: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"servers": list(entries)}
    if cursor:
        payload["metadata"] = {"nextCursor": cursor}
    return {f"{REGISTRY}/v0.1/servers?search=com.example": payload}


@pytest.mark.parametrize(
    "raw", ["https://mcp.example.com:abc/mcp", "https://mcp.example.com:99999/mcp", "https://[x/"]
)
def test_malformed_url_target_is_a_target_error(raw: str) -> None:
    with pytest.raises(TargetError):
        parse_target(raw)


def test_malformed_remotes_in_search_results_are_skipped() -> None:
    entries = [
        {"server": remote_server("https://mcp.example.com:{port}/mcp")},
        {"server": remote_server("https://[broken/mcp")},
        {"server": remote_server("https://mcp.example.com/mcp")},
    ]
    resolution = Resolver(FakeFetch(search_routes(*entries)), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is True
    assert statuses(resolution)["namespace.remote_host"] == "pass"


@pytest.mark.parametrize(
    ("status", "expected"),
    [("active", "pass"), ("deprecated", "warn"), ("deleted", "fail"), (None, "unknown"), ("odd", "unknown")],
)
def test_url_match_applies_the_registry_status(status: str | None, expected: str) -> None:
    entry: dict[str, Any] = {"server": remote_server("https://mcp.example.com/mcp")}
    if status:
        entry["_meta"] = {"io.modelcontextprotocol.registry/official": {"status": status}}
    resolution = Resolver(FakeFetch(search_routes(entry)), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert statuses(resolution)["registry.status"] == expected


@pytest.mark.parametrize(
    "listed",
    ["https://mcp.example.com/mcp/", "https://mcp.example.com/mcp//", "https://mcp.example.com:0/mcp"],
)
def test_endpoint_identity_keeps_paths_and_explicit_ports(listed: str) -> None:
    routes = search_routes({"server": remote_server(listed)})
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert resolution.registry_listed is False


def test_search_follows_pages_and_reports_exhaustion_as_unknown() -> None:
    class Paged(FakeFetch):
        def __call__(self, url: str) -> Any:
            self.seen.append(url)
            page = len(self.seen)
            if page == 2:
                return {"servers": [{"server": remote_server("https://mcp.example.com/mcp")}]}
            return {"servers": [], "metadata": {"nextCursor": f"c{page}"}}

    found = Resolver(Paged({}), REGISTRY).resolve("https://mcp.example.com/mcp")
    assert found.registry_listed is True

    class Endless(FakeFetch):
        def __call__(self, url: str) -> Any:
            self.seen.append(url)
            return {"servers": [], "metadata": {"nextCursor": "more"}}

    fetch = Endless({})
    lost = Resolver(fetch, REGISTRY).resolve("https://mcp.example.com/mcp")
    assert len(fetch.seen) == 3 and lost.registry_listed is None
    assert statuses(lost)["registry.listed"] == "unknown"


def test_ownership_needs_a_marker_and_a_name() -> None:
    server = server_json()
    del server["name"]
    resolution = Resolver(FakeFetch(registry_routes(server, mcp_name=None)), REGISTRY).resolve(NAME)
    checks = statuses(resolution)
    assert checks["registry.name"] == "fail" and checks["namespace.package_ownership"] == "fail"
    assert resolution.server_name == NAME


def test_registry_returning_another_name_fails() -> None:
    routes = registry_routes(server_json(name="io.github.example-owner/other"))
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve(NAME)
    assert statuses(resolution)["registry.name"] == "fail"


# Follow-up hardening (issue #394) ----------------------------------------------------


@pytest.mark.parametrize(
    "package",
    [
        PackageRef(registry_type="npm", identifier="pkg\n"),
        PackageRef(registry_type="pypi", identifier="pkg", version="1.0.0\n"),
    ],
)
def test_validate_package_rejects_trailing_newlines(package: PackageRef) -> None:
    with pytest.raises(TargetError):
        validate_package(package)


def test_truncated_http_response_becomes_a_fetch_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client
    import urllib.request

    from mcp_audit.trust.resolve import https_fetcher

    class Opener:
        def open(self, *args: object, **kwargs: object) -> object:
            raise http.client.IncompleteRead(b"partial")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: Opener())
    fetch = https_fetcher(frozenset({"registry.example.test"}))
    with pytest.raises(FetchError):
        fetch("https://registry.example.test/v0.1/servers")


def test_malformed_repository_url_is_a_warning() -> None:
    checks = namespace_checks("io.github.owner/server", "https://[broken/repo", [])
    assert [(c.id, c.status) for c in checks] == [("namespace.repository", "warn")]


def test_package_target_refuses_a_registry_answer_for_another_name() -> None:
    routes = registry_routes(server_json(name="io.github.example-owner/other"))
    routes["https://registry.npmjs.org/claimer/"] = {"name": "claimer", "version": "1.0.0", "mcpName": NAME}
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("npm:claimer")
    assert statuses(resolution)["registry.name"] == "fail"
    assert resolution.description is None or "Synthetic notes" not in resolution.description
