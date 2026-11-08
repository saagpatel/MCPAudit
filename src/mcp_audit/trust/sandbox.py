"""Throwaway container sandbox: install a package, run it, record writes and egress attempts.

Two containers share one network namespace. The sinkhole container owns it:
no real network, a dummy default route, and iptables redirects that send every
DNS query and TCP connection to local recorders (see sinkhole_agent.py). The
server container joins that namespace as an unprivileged user with all
capabilities dropped and no host mounts; its home is a scratch directory
inside the container. File writes come from `docker diff` against the
installed image, so they include everything outside tmpfs mounts.
"""

from __future__ import annotations

import io
import json
import os
import secrets
import shutil
import subprocess
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

import anyio
from mcp.client.stdio import StdioServerParameters

from mcp_audit.trust.models import FileChange, NetworkEvent, PackageRef

DEFAULT_NODE_IMAGE = "node:24-slim"
DEFAULT_PYTHON_IMAGE = "python:3.13-slim"
DEFAULT_SINK_BASE_IMAGE = "python:3.13-alpine"
LABEL = "io.mcp-audit.trust=1"
SERVER_USER = "10001:10001"
HOME = "/scratch"
MAX_CHANGES_PER_PHASE = 200
_PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
)

_NPM_META = (
    'const p=require("/srv/node_modules/"+process.env.MCPAUDIT_NAME+"/package.json");'
    'console.log("MCPAUDIT_META="+JSON.stringify({version:p.version||null,bin:p.bin||null}))'
)
_PYPI_META = (
    "import importlib.metadata as m,json,os;d=m.distribution(os.environ['MCPAUDIT_NAME']);"
    "s=sorted(e.name for e in d.entry_points if e.group=='console_scripts');"
    "print('MCPAUDIT_META='+json.dumps({'version':d.version,'scripts':s}))"
)
_NPM_INSTALL = r"""set -eu
mkdir -p /srv /scratch
cd /srv
printf '{"name":"mcp-audit-trust-install","private":true}' > package.json
npm install --no-audit --no-fund --no-update-notifier --loglevel=error \
  $MCPAUDIT_SCRIPTS --save-exact "$MCPAUDIT_SPEC" >&2
chown -R 10001:10001 /scratch
chmod -R a+rX /srv
node -e "$MCPAUDIT_META"
"""
_PYPI_INSTALL = r"""set -eu
mkdir -p /scratch
python -m venv /srv/venv
/srv/venv/bin/pip install --disable-pip-version-check --no-input --quiet \
  $MCPAUDIT_SCRIPTS "$MCPAUDIT_SPEC" >&2
chown -R 10001:10001 /scratch
chmod -R a+rX /srv
/srv/venv/bin/python -c "$MCPAUDIT_META"
"""


class RuntimeUnavailable(RuntimeError):
    """No reachable container runtime; nothing was started."""


class SandboxError(RuntimeError):
    """The sandbox could not be prepared; the server was not started."""


@dataclass(frozen=True)
class SandboxConfig:
    binary: str = "docker"
    node_image: str = DEFAULT_NODE_IMAGE
    python_image: str = DEFAULT_PYTHON_IMAGE
    sink_base_image: str = DEFAULT_SINK_BASE_IMAGE
    allow_install_scripts: bool = False
    install_timeout: float = 600.0
    memory: str = "1g"
    cpus: str = "1"
    pids_limit: int = 256


@dataclass
class Prepared:
    image: str
    base_image: str
    base_digest: str | None
    command: list[str]
    version: str | None


@dataclass
class _Seen:
    changes: dict[str, str] = field(default_factory=dict)
    last_seq: int = 0


def runtime_env() -> dict[str, str]:
    return {key: os.environ[key] for key in _PASSTHROUGH_ENV if key in os.environ}


def parse_diff(output: str) -> list[FileChange]:
    """Parse `docker diff`, dropping directories that only changed because a child did."""
    kinds = {"A": "added", "C": "changed", "D": "deleted"}
    entries: list[tuple[str, str]] = []
    for line in output.splitlines():
        code, _, path = line.partition(" ")
        if code in kinds and path.startswith("/"):
            entries.append((path, kinds[code]))
    paths = {path for path, _ in entries}
    result: list[FileChange] = []
    for path, change in entries:
        if change == "changed" and any(other.startswith(path.rstrip("/") + "/") for other in paths):
            continue
        result.append(
            FileChange(
                path=path,
                change=change,  # type: ignore[arg-type]
                in_home=path == HOME or path.startswith(HOME + "/"),
            )
        )
    return sorted(result, key=lambda c: c.path)


def parse_sink_log(output: str, after: int) -> tuple[list[NetworkEvent], int, dict[str, object] | None]:
    """Return events with seq > after, the highest seq seen, and the ready/setup record."""
    events: list[NetworkEvent] = []
    last = after
    status: dict[str, object] | None = None
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        kind = record.get("kind")
        if kind in {"ready", "setup_error"}:
            status = record
            continue
        seq = record.get("seq")
        if not isinstance(seq, int) or seq <= after or kind not in {"dns", "tcp", "udp"}:
            continue
        last = max(last, seq)
        events.append(
            NetworkEvent(
                kind=kind,
                host=_text(record.get("name")),
                ip=_text(record.get("dst_ip")),
                port=record.get("dst_port") if isinstance(record.get("dst_port"), int) else None,
                sni=_text(record.get("sni")),
                http_method=_text(record.get("http_method")),
                http_host=_text(record.get("http_host")),
                qtype=record.get("qtype") if isinstance(record.get("qtype"), int) else None,
            )
        )
    return events, last, status


def _text(value: object) -> str | None:
    return value[:253] if isinstance(value, str) and value else None


def choose_command(package: PackageRef, meta: dict[str, object]) -> list[str]:
    """Pick the executable an installed package exposes, preferring one named like the package."""
    short = package.identifier.rsplit("/", 1)[-1]
    if package.registry_type == "npm":
        bin_field = meta.get("bin")
        if isinstance(bin_field, str) and bin_field:
            return [f"/srv/node_modules/.bin/{short}"]
        if isinstance(bin_field, dict) and bin_field:
            names = sorted(str(k) for k in bin_field)
            return [f"/srv/node_modules/.bin/{short if short in names else names[0]}"]
        raise SandboxError(f"npm package {package.identifier} declares no executable (bin).")
    scripts = meta.get("scripts")
    names = sorted(str(s) for s in scripts) if isinstance(scripts, list) else []
    if not names:
        raise SandboxError(f"PyPI project {package.identifier} declares no console script.")
    normal = short.lower().replace("_", "-")
    pick = next((n for n in names if n.lower().replace("_", "-") == normal), names[0])
    return [f"/srv/venv/bin/{pick}"]


def sink_context(agent_source: bytes, base_image: str) -> tuple[bytes, str]:
    """Build an in-memory docker build context for the sinkhole image and its content tag."""
    dockerfile = (
        f"FROM {base_image}\n"
        "RUN apk add --no-cache iptables ip6tables iproute2\n"
        "COPY sinkhole_agent.py /sinkhole_agent.py\n"
        'ENTRYPOINT ["python3", "-u", "/sinkhole_agent.py"]\n'
    ).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in (("Dockerfile", dockerfile), ("sinkhole_agent.py", agent_source)):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            tar.addfile(info, io.BytesIO(data))
    tag = "mcp-audit-trust-sinkhole:" + sha256(dockerfile + agent_source).hexdigest()[:16]
    return buffer.getvalue(), tag


class Sandbox:
    """One run's containers. Use as an async context manager; exit removes everything it made."""

    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        resolved = shutil.which(config.binary)
        if resolved is None:
            raise RuntimeUnavailable(f"{config.binary} is not installed or not on PATH.")
        self.binary = resolved
        self.env = runtime_env()
        run_id = secrets.token_hex(4)
        self.sink = f"mcp-audit-trust-sink-{run_id}"
        self.server = f"mcp-audit-trust-server-{run_id}"
        self.installer = f"mcp-audit-trust-install-{run_id}"
        self.image = f"mcp-audit-trust-run:{run_id}"
        self.runtime: str | None = None
        self.ipv6 = False
        self._seen = _Seen()
        self._image_made = False

    async def docker(
        self, *args: str, input: bytes | None = None, timeout: float = 60.0, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        try:
            with anyio.fail_after(timeout):
                result = await anyio.run_process([self.binary, *args], input=input, check=False, env=self.env)
        except TimeoutError:
            raise SandboxError(f"{self.config.binary} {args[0]} timed out after {timeout:.0f}s.") from None
        if check and result.returncode != 0:
            tail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-3:]
            raise SandboxError(f"{self.config.binary} {args[0]} failed: {' | '.join(tail)}")
        return result

    async def __aenter__(self) -> Sandbox:
        try:
            result = await self.docker(
                "version", "--format", "{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}", timeout=20
            )
        except SandboxError as exc:
            raise RuntimeUnavailable(
                f"The {self.config.binary} daemon is not reachable. Start a container runtime "
                "(Docker Desktop, colima, OrbStack) or set DOCKER_CONTEXT."
            ) from exc
        self.runtime = f"{self.config.binary} {result.stdout.decode().strip()}"
        if "linux/" not in self.runtime:
            raise RuntimeUnavailable(f"Linux containers are required; the runtime reports {self.runtime}.")
        return self

    async def __aexit__(self, *exc: object) -> None:
        with anyio.CancelScope(shield=True):
            await self.docker("rm", "-f", self.server, self.sink, self.installer, check=False, timeout=60)
            if self._image_made:
                await self.docker("rmi", "-f", self.image, check=False, timeout=60)

    async def prepare(self, package: PackageRef) -> Prepared:
        """Install the package into a fresh container and commit it as the run image."""
        from mcp_audit.trust.resolve import TargetError, validate_package

        try:
            validate_package(package)
        except TargetError as exc:
            raise SandboxError(str(exc)) from None
        if package.registry_type == "npm":
            base, script, meta_program = self.config.node_image, _NPM_INSTALL, _NPM_META
            spec = f"{package.identifier}@{package.version}" if package.version else package.identifier
            blocker = "" if self.config.allow_install_scripts else "--ignore-scripts"
        elif package.registry_type == "pypi":
            base, script, meta_program = self.config.python_image, _PYPI_INSTALL, _PYPI_META
            spec = f"{package.identifier}=={package.version}" if package.version else package.identifier
            blocker = "" if self.config.allow_install_scripts else "--only-binary=:all:"
        else:
            raise SandboxError(f"{package.registry_type} packages are not supported in this milestone.")
        result = await self.docker(
            "run",
            "--name",
            self.installer,
            "--label",
            LABEL,
            "--cap-drop",
            "ALL",
            "--cap-add",
            "CHOWN",
            "--cap-add",
            "FOWNER",
            "--cap-add",
            "DAC_OVERRIDE",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "512",
            "--env",
            f"MCPAUDIT_SPEC={spec}",
            "--env",
            f"MCPAUDIT_NAME={package.identifier}",
            "--env",
            f"MCPAUDIT_SCRIPTS={blocker}",
            "--env",
            f"MCPAUDIT_META={meta_program}",
            "--entrypoint",
            "sh",
            base,
            "-c",
            script,
            timeout=self.config.install_timeout,
            check=False,
        )
        if result.returncode != 0:
            tail = result.stderr.decode("utf-8", "replace").strip().splitlines()[-4:]
            hint = (
                " Install scripts and source builds are disabled; --allow-install-scripts enables them."
                if not self.config.allow_install_scripts
                else ""
            )
            raise SandboxError(f"Package install failed: {' | '.join(tail)}.{hint}")
        meta = _meta(result.stdout.decode("utf-8", "replace"))
        command = choose_command(package, meta)
        await self.docker(
            "commit",
            "--change",
            f"USER {SERVER_USER}",
            "--change",
            f"WORKDIR {HOME}",
            "--change",
            f"ENV HOME={HOME}",
            self.installer,
            self.image,
            timeout=120,
        )
        self._image_made = True
        await self.docker("rm", "-f", self.installer, check=False)
        digest = await self.docker(
            "image",
            "inspect",
            "--format",
            "{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
            base,
            check=False,
        )
        version = meta.get("version")
        return Prepared(
            image=self.image,
            base_image=base,
            base_digest=digest.stdout.decode().strip() or None,
            command=command,
            version=version if isinstance(version, str) else package.version,
        )

    async def start_sink(self) -> None:
        source = Path(__file__).with_name("sinkhole_agent.py").read_bytes()
        context, tag = sink_context(source, self.config.sink_base_image)
        exists = await self.docker("image", "inspect", tag, check=False)
        if exists.returncode != 0:
            await self.docker("build", "--quiet", "--tag", tag, "-", input=context, timeout=300)
        await self.docker(
            "run",
            "--detach",
            "--name",
            self.sink,
            "--label",
            LABEL,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "NET_RAW",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "128m",
            "--pids-limit",
            "64",
            tag,
        )
        with anyio.move_on_after(20):
            while True:
                logs = await self.docker("logs", self.sink, check=False)
                _, _, status = parse_sink_log(logs.stdout.decode("utf-8", "replace"), 0)
                if status is not None:
                    if status.get("kind") != "ready":
                        raise SandboxError("Network sinkhole failed to set up; the server was not started.")
                    self.ipv6 = status.get("ipv6") is True
                    return
                await anyio.sleep(0.2)
        raise SandboxError("Network sinkhole did not become ready; the server was not started.")

    def server_parameters(
        self, prepared: Prepared, args: Sequence[str], env: dict[str, str]
    ) -> StdioServerParameters:
        """The stdio command that runs the server inside the sandbox via the runtime CLI."""
        docker_args = [
            "run",
            "--interactive",
            "--name",
            self.server,
            "--label",
            LABEL,
            "--network",
            f"container:{self.sink}",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            SERVER_USER,
            "--workdir",
            HOME,
            "--memory",
            self.config.memory,
            "--cpus",
            self.config.cpus,
            "--pids-limit",
            str(self.config.pids_limit),
            "--env",
            f"HOME={HOME}",
        ]
        for key, value in sorted(env.items()):
            docker_args += ["--env", f"{key}={value}"]
        docker_args += ["--entrypoint", prepared.command[0], prepared.image, *prepared.command[1:], *args]
        return StdioServerParameters(command=self.binary, args=docker_args, env=self.env)

    async def attest(self) -> list[str]:
        """Read back the server container's isolation settings from the runtime."""
        result = await self.docker(
            "inspect",
            "--format",
            "{{json .Mounts}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.CapAdd}}|"
            "{{.HostConfig.NetworkMode}}|{{.Config.User}}|{{json .HostConfig.SecurityOpt}}",
            self.server,
            check=False,
        )
        if result.returncode != 0:
            return ["Server container settings could not be read back."]
        mounts, drop, add, network, user, secopt = result.stdout.decode().strip().split("|", 5)
        facts = [
            "Host mounts: none." if mounts in {"[]", "null"} else f"Host mounts present: {mounts}.",
            f"Capabilities dropped: {drop}; added: {add if add != 'null' else 'none'}.",
            f"Network: {network.split(':', 1)[0]} namespace of the sinkhole (no route out).",
            f"User: {user}.",
            f"Security options: {secopt}.",
        ]
        return facts

    async def snapshot(self) -> tuple[list[FileChange], int, list[NetworkEvent]]:
        """Changes and egress attempts since the previous snapshot."""
        diff = await self.docker("diff", self.server, check=False)
        current = {c.path: c for c in parse_diff(diff.stdout.decode("utf-8", "replace"))}
        new = [c for path, c in current.items() if self._seen.changes.get(path) != c.change]
        self._seen.changes.update({path: c.change for path, c in current.items()})
        truncated = max(0, len(new) - MAX_CHANGES_PER_PHASE)
        logs = await self.docker("logs", self.sink, check=False)
        events, self._seen.last_seq, _ = parse_sink_log(
            logs.stdout.decode("utf-8", "replace"), self._seen.last_seq
        )
        return new[:MAX_CHANGES_PER_PHASE], truncated, events

    async def stop_server(self) -> None:
        await self.docker("stop", "--time", "2", self.server, check=False, timeout=30)


def _meta(stdout: str) -> dict[str, object]:
    for line in reversed(stdout.splitlines()):
        if line.startswith("MCPAUDIT_META="):
            try:
                value = json.loads(line.removeprefix("MCPAUDIT_META="))
            except ValueError:
                break
            if isinstance(value, dict):
                return value
    raise SandboxError("Installed package metadata could not be read.")
