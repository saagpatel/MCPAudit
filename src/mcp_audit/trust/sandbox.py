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
import re
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
STAT_BATCH = 500
MAX_STAT_PATHS = 20000
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
# Read the installed distribution with the base interpreter in isolated mode with
# `site` disabled. Starting the venv interpreter would run any `.pth` hook a wheel
# shipped, as root with real network, before observation starts.
_PYPI_META = (
    "import glob,importlib.metadata as m,json,os;"
    "p=glob.glob('/srv/venv/lib/python*/site-packages');"
    "d=next(iter(m.distributions(name=os.environ['MCPAUDIT_NAME'],path=p)));"
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
python -I -S -c "$MCPAUDIT_META"
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
    stats: dict[str, str] = field(default_factory=dict)
    last_seq: int = 0


@dataclass
class PhaseRecord:
    """What one snapshot found since the previous one."""

    changes: list[FileChange]
    truncated: int
    network: list[NetworkEvent]
    rewrites_checked: bool


def parse_stat(output: str) -> dict[str, str]:
    """Parse `stat --printf '%F\\t%s\\t%y\\t%n\\n'` into path -> 'type|size mtime'."""
    stats: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split("\t", 3)
        if len(parts) == 4 and parts[3].startswith("/"):
            stats[parts[3]] = f"{parts[0]}|{parts[1]} {parts[2]}"
    return stats


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


def diff_paths(output: str) -> set[str]:
    """Every path `docker diff` lists, including parents parse_diff folds away."""
    return {line[2:] for line in output.splitlines() if line[:2] in {"A ", "C ", "D "} and line[2:3] == "/"}


def parse_sink_log(output: str, after: int) -> tuple[list[NetworkEvent], int, dict[str, object] | None]:
    """Return events with seq > after, the highest seq seen, and the ready/setup record."""
    events: list[NetworkEvent] = []
    opened: dict[int, NetworkEvent] = {}
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
        if not isinstance(seq, int) or seq <= after or kind not in {"dns", "tcp", "tcp_detail", "udp"}:
            continue
        last = max(last, seq)
        conn = record.get("conn")
        if kind == "tcp_detail":
            # SNI and Host arrive after the connect record; enrich it when it is in
            # this batch. A later batch keeps the connect already attributed.
            if isinstance(conn, int) and conn in opened:
                event = opened[conn]
                event.sni = _host(record.get("sni"))
                event.http_method = _text(record.get("http_method"))
                event.http_host = _host(record.get("http_host"))
            continue
        events.append(
            NetworkEvent(
                kind=kind,
                host=_host(record.get("name")),
                ip=_host(record.get("dst_ip")),
                port=record.get("dst_port") if isinstance(record.get("dst_port"), int) else None,
                sni=_host(record.get("sni")),
                http_method=_text(record.get("http_method")),
                http_host=_host(record.get("http_host")),
                qtype=record.get("qtype") if isinstance(record.get("qtype"), int) else None,
            )
        )
        if kind == "tcp" and isinstance(conn, int):
            opened[conn] = events[-1]
    return events, last, status


def _text(value: object) -> str | None:
    return value[:253] if isinstance(value, str) and value else None


_NOT_HOSTNAME = re.compile(r"[^a-z0-9._:-]")


def _host(value: object) -> str | None:
    """Server-controlled names reduced to a hostname alphabet, so they cannot carry
    line breaks or markup into suggestion lines; anything else becomes '?'."""
    text = _text(value)
    return _NOT_HOSTNAME.sub("?", text.lower()) if text else None


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
            "--memory",
            "2g",
            "--cpus",
            "2",
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

    async def snapshot(self) -> PhaseRecord:
        """Changes and egress attempts since the previous snapshot.

        `docker diff` is cumulative against the image, so a file already reported
        keeps its code when it is written again, and one added then removed simply
        vanishes. Paths seen before and now absent are reported as deleted. While
        the server runs, size and mtime of every changed path are compared too,
        which catches rewrites; any path that could not be checked marks the phase
        as not fully checked. Collection failures raise: missing evidence must
        never read as no effects.
        """
        diff = await self.docker("diff", self.server, check=False)
        if diff.returncode != 0:
            raise SandboxError("File-write recording failed (docker diff); observation is incomplete.")
        output = diff.stdout.decode("utf-8", "replace")
        current = {c.path: c for c in parse_diff(output)}
        present = diff_paths(output)
        existing = sorted(path for path, c in current.items() if c.change != "deleted")
        stats = await self._stat(existing) if existing else {}
        complete = stats is not None and all(path in stats for path in existing)
        new: list[FileChange] = []
        rewritten: list[FileChange] = []
        for path, change in current.items():
            known = path in self._seen.stats
            if path in self._seen.changes and not known and change.change != "deleted":
                complete = False  # no earlier size/mtime to compare: a rewrite here is unknowable
            moved = stats is not None and path in stats and known and self._seen.stats[path] != stats[path]
            if self._seen.changes.get(path) != change.change:
                new.append(change)
            elif moved and change.change != "deleted":
                directory = stats is not None and stats[path].startswith("directory|")
                rewritten.append(change.model_copy(update={"entries_only": directory}))
        for path, earlier in list(self._seen.changes.items()):
            if path not in present and earlier != "deleted":
                # Created in an earlier phase and removed since: a deletion, not churn.
                new.append(
                    FileChange(
                        path=path, change="deleted", in_home=path == HOME or path.startswith(HOME + "/")
                    )
                )
                del self._seen.changes[path]
                self._seen.stats.pop(path, None)
        lasting = {c.path for c in new} | {c.path for c in rewritten if not c.entries_only}
        for change in rewritten:
            # A directory only counts on its own when no child change explains it.
            if not change.entries_only or not any(p.startswith(change.path + "/") for p in lasting):
                new.append(change)
        # Writes outside home come first so presentation truncation never hides them.
        new.sort(key=lambda c: (c.in_home, c.entries_only, c.path))
        self._seen.changes.update({path: c.change for path, c in current.items()})
        if stats:
            self._seen.stats.update(stats)
        truncated = max(0, len(new) - MAX_CHANGES_PER_PHASE)
        logs = await self.docker("logs", self.sink, check=False)
        running = await self.docker("inspect", "--format", "{{.State.Running}}", self.sink, check=False)
        if logs.returncode != 0 or running.stdout.decode().strip() != "true":
            raise SandboxError(
                "The network recorder stopped or could not be read; observation is incomplete."
            )
        events, self._seen.last_seq, _ = parse_sink_log(
            logs.stdout.decode("utf-8", "replace"), self._seen.last_seq
        )
        return PhaseRecord(
            changes=new[:MAX_CHANGES_PER_PHASE],
            truncated=truncated,
            network=events,
            rewrites_checked=complete,
        )

    async def _stat(self, paths: list[str]) -> dict[str, str] | None:
        """Size and mtime of paths inside the running server, in bounded batches.

        Returns None when coverage cannot be complete: the server is not running,
        or there are more paths than MAX_STAT_PATHS. Paths missing from the result
        (for example removed between diff and stat) leave coverage incomplete.
        """
        if len(paths) > MAX_STAT_PATHS:
            return None
        stats: dict[str, str] = {}
        for start in range(0, len(paths), STAT_BATCH):
            result = await self.docker(
                "exec",
                "--user",
                SERVER_USER,
                self.server,
                "stat",
                "--printf",
                "%F\\t%s\\t%y\\t%n\\n",
                "--",
                *paths[start : start + STAT_BATCH],
                check=False,
                timeout=30,
            )
            batch = parse_stat(result.stdout.decode("utf-8", "replace"))
            if result.returncode != 0 and not batch:
                return None
            stats.update(batch)
        return stats

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
