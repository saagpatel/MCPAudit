"""Observed canary calls: check served read-only hints against behavior.

`check --canary-check --canary-observe` launches each stdio server under macOS
`sandbox-exec` in a per-server trap:

- The real HOME and working folder stay readable, so servers find their own data.
  Direct file writes by the server's process tree are allowed only under the
  trap: TMPDIR, XDG_CACHE_HOME and XDG_STATE_HOME point there, so well-behaved
  caches land where they can be seen. Other direct writes are denied.
- Outbound TCP is allowed only to loopback. HTTP(S)_PROXY point at a local proxy
  that records the requested host and refuses the request; loopback is exempt.
  Unix-socket connections and non-local name resolution are denied.
- The sandbox is not total containment: Mach and XPC IPC stay open, so a server
  could still ask another process to act for it.

A tool claiming readOnlyHint=true whose call and immediate repeat both changed
trap entries, with the server quiet around each, is an observed contradiction
(MCP055). One-off effects, writes shared across tools, permission errors,
unscannable traps and errored calls without effects are inconclusive.

Network requests are evidence, never contradictions: openWorldHint describes a
tool's domain, and a closed-world tool may call its own fixed remote backend.
Requests by tools declaring openWorldHint=false are listed for review.

Limits: local stdio servers on macOS only; an empty-argument call and its repeat
per exercised tool, so a tool that misbehaves only on some inputs passes.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socketserver
import stat as stat_module
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import anyio
import anyio.to_thread
from mcp import StdioServerParameters

from mcp_audit.models import (
    AnnotationFinding,
    Confidence,
    ObservedCall,
    ObservedVerdict,
    PermissionCategory,
    ServerAudit,
    ToolAnnotations,
)

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
# Lowercased; Python, Node (EPERM/EACCES) and Go spellings.
BLOCKED_MARKERS = (b"operation not permitted", b"permissionerror", b"permission denied", b"eperm", b"eacces")
SETTLE_SECONDS = 0.3  # let a child process finish writing before the after-snapshot
# Rough cost of observation for the --timeout warning: quiet checks plus snapshots per call,
# and server startup for two identity sessions.
OBSERVE_SECONDS_PER_CALL = 2
OBSERVE_STARTUP_SECONDS = 10
MAX_REPORTED_PATHS = 10
MAX_SNAPSHOT_ENTRIES = 5000  # files, directories and links together
SNAPSHOT_SECONDS = 2.0
MAX_PROXY_LOG = 10_000  # bounded memory against a request flood; overflow is detected, not hidden
MAX_REPORTED_HOSTS = 50  # per call, distinct hosts kept in the report
UNPARSED_REQUEST = "(unparsed request)"
LOOPBACK_NAMES = {"localhost", "localhost.localdomain"}
MAX_PROXY_CONNECTIONS = 32
_HOSTNAME = re.compile(r"^[a-z0-9.-]{1,253}$|^\[[0-9a-f:.]+\]$")
UNSUPPORTED_WARNING = (
    "Canary observation applies to local stdio servers; this server's calls were not observed."
)
STARTUP_FAILED_WARNING = (
    "Canary observation sandbox was active: a server that writes outside its temporary folder or "
    "downloads at startup (for example npx/uvx) can fail to start under it. Re-run without "
    "--canary-observe to separate a sandbox failure from a server failure."
)


def observation_supported(transport_is_stdio: bool) -> bool:
    return transport_is_stdio and sys.platform == "darwin" and Path(SANDBOX_EXEC).exists()


class StderrScanner:
    """Counts permission-error markers in a server's stderr stream, across chunk boundaries."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._carry = b""
        self.count = 0

    def feed(self, chunk: bytes) -> None:
        overlap = max(len(m) for m in BLOCKED_MARKERS) - 1
        with self._lock:
            data = self._carry + chunk.lower()
            # Count each marker occurrence that ends inside the new chunk only.
            for marker in BLOCKED_MARKERS:
                start = 0
                while (index := data.find(marker, start)) >= 0:
                    if index + len(marker) > len(self._carry):
                        self.count += 1
                    start = index + 1
            self._carry = data[-overlap:]


def _request_host(request_line: str) -> str:
    """A validated host[:port] only: URLs can carry credentials, so nothing else is kept."""
    parts = request_line.split()
    if len(parts) < 2:
        return ""
    target = parts[1] if "://" in parts[1] else "//" + parts[1]
    try:
        split = urlsplit(target)
        host, port = split.hostname, split.port
    except ValueError:
        return ""
    if host and ":" in host:
        host = f"[{host}]"  # IPv6 literal
    if not host or not _HOSTNAME.match(host):
        return ""
    return f"{host}:{port}" if port else host


def is_loopback(host: str) -> bool:
    """`host` is a value recorded by `_request_host`: name, IPv4 or [IPv6], optional port."""
    try:
        name = urlsplit("//" + host).hostname or ""
    except ValueError:
        return False
    name = name.rstrip(".")
    if name in LOOPBACK_NAMES or name.endswith(".localhost"):
        return True
    try:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(name)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        return address.is_loopback or address.is_unspecified
    except ValueError:
        return False


class _ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 2  # an idle connection must not pin a handler thread

    def handle(self) -> None:
        try:
            line = self.rfile.readline(4096).decode("latin-1").strip()
        except OSError:
            return
        if not line:
            return  # an opened-and-dropped connection is not a request
        # A request whose destination cannot be validated is counted, but it is
        # missing evidence, never proof of an external destination.
        self.server.record(_request_host(line) or UNPARSED_REQUEST)  # type: ignore[attr-defined]
        try:
            self.wfile.write(
                b"HTTP/1.1 502 Refused by mcp-audit canary observation\r\nContent-Length: 0\r\n\r\n"
            )
        except OSError:
            return  # the client hung up first; the request is already recorded


class _LoggingProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ProxyHandler)
        self._slots = threading.BoundedSemaphore(MAX_PROXY_CONNECTIONS)
        self._lock = threading.Lock()
        self.total = 0  # every request, logged or not
        self.log: list[str] = []
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def process_request(self, request: Any, client_address: Any) -> None:
        """Bound concurrent handlers: excess connections are closed and counted as unlogged."""
        if not self._slots.acquire(blocking=False):
            with self._lock:
                self.total += 1
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def record(self, host: str) -> None:
        with self._lock:
            self.total += 1
            if len(self.log) < MAX_PROXY_LOG:
                self.log.append(host)

    def position(self) -> tuple[int, int]:
        with self._lock:
            return self.total, len(self.log)


def sandbox_profile(trap: Path) -> str:
    return (
        "(version 1)\n(allow default)\n(deny file-write*)\n"
        f'(allow file-write* (subpath "{trap}") (literal "/dev/null"))\n'
        "(deny network-outbound)\n"
        '(allow network-outbound (remote ip "localhost:*"))\n'
    )


# (kind f/d/l/o, size, mtime_ns, ctime_ns, mode). ctime cannot be set from userland, so an
# equal-length overwrite with a restored mtime, or a permission change, still shows.
Entry = tuple[str, int, int, int, int]


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def _snapshot(root: Path) -> dict[str, Entry] | None:
    """Every entry in the trap; None when the trap cannot be judged.

    The walk opens each folder with O_NOFOLLOW and works relative to verified
    descriptors, so a folder swapped for a symlink mid-walk cannot lead the scan out
    of the trap: the open fails and the snapshot is unjudgeable. Every entry counts
    toward MAX_SNAPSHOT_ENTRIES and the walk stops after SNAPSHOT_SECONDS.
    """
    deadline = time.monotonic() + SNAPSHOT_SECONDS
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    out: dict[str, Entry] = {}
    entries = 0
    try:
        stack: list[tuple[int, str]] = [(os.open(root, flags), "")]
    except OSError:
        return None
    try:
        while stack:
            fd, rel = stack.pop()
            try:
                with os.scandir(fd) as listing:
                    for entry in listing:
                        entries += 1
                        if entries > MAX_SNAPSHOT_ENTRIES or time.monotonic() > deadline:
                            return None
                        name = f"{rel}/{entry.name}" if rel else entry.name
                        try:
                            info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue  # renamed or removed mid-walk (atomic writes)
                        if stat_module.S_ISDIR(info.st_mode):
                            out[name] = ("d", 0, 0, 0, info.st_mode)  # children are listed separately
                            try:
                                stack.append((os.open(entry.name, flags, dir_fd=fd), name))
                            except FileNotFoundError:
                                continue
                        elif stat_module.S_ISLNK(info.st_mode):
                            out[name] = ("l", *_fingerprint(info))
                        elif stat_module.S_ISREG(info.st_mode):
                            out[name] = ("f", *_fingerprint(info))
                        else:
                            out[name] = ("o", *_fingerprint(info))
            finally:
                os.close(fd)
    except OSError:
        return None  # unreadable, or a folder replaced by a link (ELOOP/ENOTDIR)
    finally:
        for fd, _ in stack:
            os.close(fd)
    return out


@dataclass(frozen=True)
class _State:
    files: dict[str, Entry] | None
    requests: int  # proxy requests seen, logged or not
    logged: int  # proxy log entries
    blocked: int


class ObservationTrap:
    """One server's sandbox: trap folders, logging proxy and stderr marker scanner."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="mcp-audit-observe-")).resolve()
        self._proxy: _LoggingProxy | None = None
        try:
            if any(ch in str(self.root) for ch in '"\\\n'):
                # The path is spliced into an SBPL string; refuse rather than escape it.
                raise OSError(f"temporary folder path cannot be used in a sandbox profile: {self.root}")
            self.writable = self.root / "w"
            for sub in ("tmp", "cache", "state"):
                (self.writable / sub).mkdir(parents=True)
            self._proxy = _LoggingProxy()
            self.profile = self.root / "profile.sb"
            self.profile.write_text(sandbox_profile(self.writable), encoding="utf-8")
        except BaseException:
            self.close()
            raise
        self.stderr = StderrScanner()
        self._last_end: _State | None = None
        self._noisy_before = False

    @property
    def proxy(self) -> _LoggingProxy:
        assert self._proxy is not None
        return self._proxy

    def wrap(self, params: StdioServerParameters) -> StdioServerParameters:
        proxy = f"http://127.0.0.1:{self.proxy.port}"
        loopback = "localhost,.localhost,127.0.0.1,::1,0.0.0.0"
        env = {
            **(params.env or {}),
            "TMPDIR": str(self.writable / "tmp"),
            "XDG_CACHE_HOME": str(self.writable / "cache"),
            "XDG_STATE_HOME": str(self.writable / "state"),
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "NO_PROXY": loopback,
            "no_proxy": loopback,
        }
        return StdioServerParameters(
            command=SANDBOX_EXEC,
            args=["-f", str(self.profile), params.command, *params.args],
            env=env,
            # The server keeps its own working folder (relative launch paths still work);
            # direct writes there are denied.
            cwd=params.cwd,
        )

    async def _state(self) -> _State:
        files = await anyio.to_thread.run_sync(_snapshot, self.writable, abandon_on_cancel=True)
        requests, logged = self.proxy.position()
        return _State(files, requests, logged, self.stderr.count)

    async def begin(self) -> _State:
        """Start a call window, first checking the server is quiet (startup work included)."""
        settle_start = await self._state()
        await anyio.sleep(SETTLE_SECONDS)
        start = await self._state()
        self._noisy_before = settle_start != start or (
            self._last_end is not None and self._last_end != settle_start
        )
        return start

    async def end(
        self, start: _State, tool_name: str, call: int, annotations: ToolAnnotations | None, errored: bool
    ) -> ObservedCall:
        await anyio.sleep(SETTLE_SECONDS)
        after = await self._state()
        await anyio.sleep(SETTLE_SECONDS)
        post = await self._state()
        self._last_end = post
        # Quiet before and after the window, or the effect cannot be pinned on this call.
        spillover = self._noisy_before or post != after
        created: set[str] = set()
        if start.files is None or after.files is None:
            changed: list[str] = []
            oversized = True
        else:
            oversized = False
            before_files, after_files = start.files, after.files
            changed = sorted(
                {k for k, v in after_files.items() if before_files.get(k) != v}
                | (before_files.keys() - after_files.keys())
            )
            created = set(after_files.keys() - before_files.keys())
        window = self.proxy.log[start.logged : after.logged]
        unlogged = (after.requests - start.requests) - len(window)
        distinct = set(window)
        # Classify the whole window before capping what the report keeps.
        remote = sorted(h for h in distinct if h != UNPARSED_REQUEST and not is_loopback(h))
        hosts = (remote + sorted(distinct - set(remote)))[:MAX_REPORTED_HOSTS]
        blocked = after.blocked > start.blocked
        # Only readOnlyHint can be contradicted by behavior. A remote request does not show
        # that a closed-world tool's domain is open (a fixed private backend is closed), so
        # network evidence is recorded for review instead.
        contradicted = (
            ["readOnlyHint"] if annotations and annotations.read_only_hint is True and changed else []
        )
        reason = ""
        if oversized:
            reason = "the trap could not be fully scanned (too many entries, too slow, or unreadable)"
        elif spillover:
            reason = "activity just before or after the call could belong to other work"
        elif blocked:
            reason = "a permission error was reported; it may have been a blocked write or a denied read"
        elif errored and not (changed or hosts or unlogged):
            reason = "the call errored without an observable effect"
        verdict: ObservedVerdict
        if contradicted and not (spillover or oversized or blocked):
            verdict = "contradiction"
        elif reason:
            verdict = "inconclusive"
            contradicted = []
        else:
            verdict = "consistent"
        observed = ObservedCall(
            tool_name=tool_name,
            call=call,
            files_changed=changed[:MAX_REPORTED_PATHS],
            files_changed_count=len(changed),
            blocked_operations=blocked,
            network_hosts=hosts,
            network_unknown=max(unlogged, 0) + window.count(UNPARSED_REQUEST),
            errored=errored,
            contradicted_hints=contradicted,
            verdict=verdict,
            inconclusive_reason=reason if verdict == "inconclusive" else "",
        )
        observed._changed_paths = set(changed)
        observed._created_paths = created
        observed._closed_world = bool(annotations and annotations.open_world_hint is False)
        observed._read_only = bool(annotations and annotations.read_only_hint is True)
        return observed

    def close(self) -> None:
        if self._proxy is not None:
            self._proxy.shutdown()
            self._proxy.server_close()
            self._proxy = None
        shutil.rmtree(self.root, ignore_errors=True)


def confirm_contradictions(calls: list[ObservedCall]) -> None:
    """A contradiction stands only when the immediately following call is the same tool
    showing the same contradicted hint (the repeat the canary schedules).

    A one-off effect may have been a delayed effect of another call; without an adjacent
    confirming repeat, every hit for that tool and hint is downgraded to inconclusive
    rather than pinned on whichever tool happened to be running.
    """

    # Writes that show up during calls to different tools are the server's (an access log,
    # a shared cache), not any one tool's; they cannot be pinned on the tool that ran.
    def paths(observed: ObservedCall) -> set[str]:
        # The complete set when recorded in this run; the reported first 10 otherwise.
        return observed._changed_paths or set(observed.files_changed)

    tools_by_path: dict[str, set[str]] = {}
    for observed in calls:
        for path in paths(observed):
            tools_by_path.setdefault(path, set()).add(observed.tool_name)
    for observed in calls:
        changed = paths(observed)
        if (
            "readOnlyHint" in observed.contradicted_hints
            and changed
            and all(len(tools_by_path[path]) > 1 for path in changed)
        ):
            observed.contradicted_hints = [h for h in observed.contradicted_hints if h != "readOnlyHint"]
            if not observed.contradicted_hints:
                observed.verdict = "inconclusive"
                observed.inconclusive_reason = (
                    "the same files changed during calls to different tools (server-level logging or caching)"
                )
    # With one tool exercised there is nothing to compare against: if its calls keep touching
    # the same entries (a log created lazily on the first call, then appended), the writes
    # cannot be separated from server-level logging.
    if len({c.tool_name for c in calls}) == 1:
        hits = [c for c in calls if "readOnlyHint" in c.contradicted_hints]
        first = hits[0]._changed_paths if hits else set()
        if (
            hits
            and all(c._changed_paths and c._changed_paths <= first for c in hits[1:])
            and (len(hits) > 1 or not hits[0]._created_paths)
        ):
            for observed in hits:
                observed.contradicted_hints = [h for h in observed.contradicted_hints if h != "readOnlyHint"]
                if not observed.contradicted_hints:
                    observed.verdict = "inconclusive"
                    observed.inconclusive_reason = (
                        "with one tool exercised, repeated changes to the same entries cannot be "
                        "separated from server-level logging"
                    )
    confirmed: set[tuple[str, str]] = set()
    for current, following in zip(calls, calls[1:], strict=False):
        if following.tool_name == current.tool_name and following.call == current.call + 1:
            for hint in set(current.contradicted_hints) & set(following.contradicted_hints):
                confirmed.add((current.tool_name, hint))
    # If two or more tools were exercised (read-only or operator-marked safe) and every one of
    # them wrote, the writes look like the server's own per-request activity (for example a
    # new log file per request). Decided from raw effects, independent of repeat confirmation.
    exercised = {c.tool_name for c in calls}
    writers = {c.tool_name for c in calls if c._changed_paths}
    if len(exercised) >= 2 and exercised <= writers:
        confirmed = {(tool, hint) for tool, hint in confirmed if hint != "readOnlyHint"}
        for observed in calls:
            if "readOnlyHint" in observed.contradicted_hints:
                observed.contradicted_hints = [h for h in observed.contradicted_hints if h != "readOnlyHint"]
                if not observed.contradicted_hints:
                    observed.verdict = "inconclusive"
                    observed.inconclusive_reason = (
                        "every tool exercised wrote, which looks like server-level activity"
                    )
    for observed in calls:
        unconfirmed = [h for h in observed.contradicted_hints if (observed.tool_name, h) not in confirmed]
        if not unconfirmed:
            continue
        observed.contradicted_hints = [h for h in observed.contradicted_hints if h not in unconfirmed]
        if not observed.contradicted_hints:
            observed.verdict = "inconclusive"
            observed.inconclusive_reason = (
                "the effect was not confirmed by an immediate repeat call of this tool"
            )


def observed_annotation_findings(audit: ServerAudit) -> list[AnnotationFinding]:
    """One MCP055 finding per tool and contradicted hint, from attributable observed effects."""
    if audit.canary is None:
        return []
    seen: dict[tuple[str, str], list[str]] = {}
    for observed in audit.canary.observed_calls:
        for hint in observed.contradicted_hints:
            evidence = seen.setdefault((observed.tool_name, hint), [])
            count = observed.files_changed_count
            noun = "entry" if count == 1 else "entries"
            evidence.append(f"call {observed.call}: created, changed or removed {count} trap {noun}")
    return [
        AnnotationFinding(
            basis="observed",
            tool_name=tool,
            hint=hint,
            declared_value=hint == "readOnlyHint",
            category=PermissionCategory.FILE_WRITE,
            confidence=Confidence.HIGH,
            severity="high",
            evidence=sorted(set(evidence)),
        )
        for (tool, hint), evidence in sorted(seen.items())
        if len(evidence) >= 2  # confirmed by an adjacent repeat call (see confirm_contradictions)
    ]


def network_review_note(calls: list[ObservedCall]) -> str:
    """Closed-world tools that reached remote hosts: evidence for a person, not a finding."""
    seen: dict[str, set[str]] = {}
    unlogged: dict[str, int] = {}
    for observed in calls:
        if not observed._closed_world:
            continue
        remote = {h for h in observed.network_hosts if h != UNPARSED_REQUEST and not is_loopback(h)}
        if remote:
            seen.setdefault(observed.tool_name, set()).update(remote)
        if unknown := observed.network_unknown:
            unlogged[observed.tool_name] = unlogged.get(observed.tool_name, 0) + unknown
    if not seen and not unlogged:
        return ""
    parts = []
    for tool in sorted(set(seen) | set(unlogged)):
        detail = ", ".join(sorted(seen.get(tool, set())))
        if unlogged.get(tool):
            detail = (
                detail + "; " if detail else ""
            ) + f"{unlogged[tool]} request(s) to an unknown destination"
        parts.append(f"{tool} -> {detail}")
    return (
        "For review: tools declaring openWorldHint=false made proxied network requests. This can be a "
        "fixed private backend inside a closed domain, so it is not reported as a finding: "
        + "; ".join(parts)
        + "."
    )
