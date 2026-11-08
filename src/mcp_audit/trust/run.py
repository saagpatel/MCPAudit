"""Orchestrate one Trust Before Connect run: resolve, observe, judge."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import anyio

from mcp_audit.models import ToolInfo
from mcp_audit.trust.models import Check, Observation, PackageRef, Phase, Resolution, TrustPin, VerdictCard
from mcp_audit.trust.resolve import SYNTHETIC_VALUE, Resolver
from mcp_audit.trust.sandbox import Sandbox, SandboxConfig, SandboxError
from mcp_audit.trust.session import ExercisePlan, observe_remote, observe_stdio
from mcp_audit.trust.verdict import build_card, build_pin, compare_pin

SINKHOLE_POLICY = (
    "sinkhole: DNS is answered with placeholder addresses and every TCP connection and UDP datagram "
    "is captured inside the sandbox; nothing leaves it"
)
CONTAINER_LIMITS = (
    "File reads are not recorded; writes are measured against the freshly installed image.",
    "Writes to tmpfs mounts such as /dev/shm are not visible.",
    "Only tools declared read-only (or named with --safe-tool) were called, with synthetic inputs; "
    "every other tool's behaviour is unobserved.",
    "Effects are attributed to the phase in which they appeared; background activity can land in a "
    "neighbouring phase.",
    "One short session was observed; delayed or conditional behaviour may not have triggered.",
    "Rewrites of files already changed in an earlier phase are detected by size and modification time "
    "while the server runs; a rewrite that keeps both, or one during shutdown, is not seen.",
    "Non-DNS UDP is counted without its destination.",
)
REMOTE_LIMITS = (
    "Remote server: observed from outside only. Its file writes and outbound connections happen on "
    "infrastructure MCPAudit cannot see.",
    "Remote tools were listed but never called.",
    "A remote URL taken from registry metadata is contacted only through connections vetted to public "
    "addresses at connect time.",
)


@dataclass(frozen=True)
class TrustOptions:
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    plan: ExercisePlan = field(default_factory=ExercisePlan)
    previous_pin: TrustPin | None = None


@dataclass
class TrustResult:
    card: VerdictCard
    pin: TrustPin | None


def synthetic_env(package: PackageRef) -> dict[str, str]:
    """Required variables get inert placeholders; optional ones stay unset so defaults apply."""
    return {
        var.name: f"{SYNTHETIC_VALUE}-not-a-secret" if var.secret else SYNTHETIC_VALUE
        for var in package.env
        if var.required
    }


async def observe_container(
    package: PackageRef, options: TrustOptions, checks: list[Check] | None = None
) -> tuple[Observation, list[ToolInfo], list[str] | None]:
    observation = Observation(mode="container", status="failed", network_policy=SINKHOLE_POLICY)
    env = synthetic_env(package)
    observation.synthetic_env = sorted(env)
    tools: list[ToolInfo] = []
    command: list[str] | None = None
    install = (
        "Install ran in a separate container with unrestricted network access (to fetch the package), "
        "with install scripts and source builds "
        + ("enabled." if options.sandbox.allow_install_scripts else "disabled.")
    )
    async with Sandbox(options.sandbox) as sandbox:
        observation.runtime = sandbox.runtime
        try:
            prepared = await sandbox.prepare(package)
            command = prepared.command
            if prepared.version and prepared.version != package.version:
                # Every output names the version that was actually observed.
                if checks is not None and package.version is not None:
                    checks.append(
                        Check(
                            id="package.version",
                            status="warn",
                            summary=f"Declared version {package.version} installed as {prepared.version}; "
                            "outputs use the installed version.",
                        )
                    )
                package.version = prepared.version
            observation.image = prepared.base_image + (
                f" ({prepared.base_digest})" if prepared.base_digest else ""
            )
            await sandbox.start_sink()
        except SandboxError as exc:
            observation.error = str(exc)
            observation.limits = [install]
            return observation, tools, command

        async def attest() -> None:
            observation.sandbox = await sandbox.attest()

        params = sandbox.server_parameters(prepared, package.arguments, env)
        tools = await observe_stdio(params, sandbox.snapshot, options.plan, observation, attest)
        observation.limits = [install, *CONTAINER_LIMITS, *observation.limits]
        try:
            await sandbox.stop_server()
            record = await sandbox.snapshot()
            observation.phases.append(
                Phase(
                    name="shutdown",
                    file_changes=record.changes,
                    file_changes_truncated=record.truncated,
                    network=record.network,
                    rewrites_checked=record.rewrites_checked,
                )
            )
        except SandboxError as exc:
            observation.status = "partial" if observation.status == "complete" else observation.status
            observation.limits.append(f"Shutdown was not recorded: {exc}")
        if not sandbox.ipv6:
            observation.limits.append("IPv6 attempts were blocked but not recorded.")
    return observation, tools, command


def remote_refusal(url: str, user_supplied: bool) -> str | None:
    """Refuse templated URLs, and registry-supplied URLs that resolve to non-public addresses.

    A URL you pass yourself is your explicit choice (loopback included). One that
    comes from registry metadata is not, so it must resolve only to public addresses.
    """
    if "{" in url or "}" in url:
        return "The remote URL is a template; fill in its variables and pass the URL directly."
    if user_supplied:
        return None
    host = urlsplit(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return f"The remote host {host} did not resolve."
    addresses = {ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]) for info in infos}
    if not addresses or any(not address.is_global for address in addresses):
        return (
            f"The registry-supplied remote host {host} resolves to a non-public address; "
            "not connecting. Pass the URL directly to connect anyway."
        )
    return None


async def run_trust(target: str, resolver: Resolver, options: TrustOptions) -> TrustResult:
    resolution: Resolution = await anyio.to_thread.run_sync(resolver.resolve, target)
    package = resolution.package
    tools: list[ToolInfo] = []
    command: list[str] | None = None
    if (
        package is not None
        and package.registry_type in {"npm", "pypi"}
        and package.transport in {None, "stdio"}
    ):
        observation, tools, command = await observe_container(package, options, resolution.checks)
    elif resolution.remote is not None:
        observation = Observation(mode="outside", status="failed", limits=list(REMOTE_LIMITS))
        refusal = await anyio.to_thread.run_sync(
            remote_refusal, resolution.remote.url, resolution.kind == "url"
        )
        if refusal is None:
            tools = await observe_remote(
                resolution.remote.url, options.plan, observation, public_only=resolution.kind != "url"
            )
        else:
            observation.status, observation.error = "skipped", refusal
    else:
        reason = (
            f"{package.registry_type} package with {package.transport} transport "
            "is not run in this milestone."
            if package is not None
            else "Nothing runnable was resolved."
        )
        observation = Observation(mode="none", status="skipped", error=reason)
    # An empty listing still pins: a server that drops every tool is drift too.
    pin = build_pin(resolution, observation, tools) if observation.tools_listed else None
    drift = compare_pin(options.previous_pin, pin) if options.previous_pin and pin else []
    return TrustResult(card=build_card(resolution, observation, drift, command), pin=pin)
