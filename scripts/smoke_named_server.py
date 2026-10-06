#!/usr/bin/env python3
"""Verify named-server selection over stdio using only disposable fixtures.

Run with the source or installed environment's Python and absolute executable:
  python scripts/smoke_named_server.py --executable /path/bin/mcp-audit
For artifacts, also supply --expected-commit; source imports are then forbidden.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from mcp.types import LATEST_PROTOCOL_VERSION, jsonrpc_message_adapter

EXPECTED_VERSION = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())[
    "project"
]["version"]

# Expected ServerAudit/ServerConfig contract, including additive canary coverage.
AUDIT_FIELDS = set(
    "server connection_status connection_error tools prompts resources permissions "
    "capability_findings risk_score non_tool_risk has_annotations annotation_coverage "
    "injection_findings ssrf_findings egress_findings drift_findings trifecta_findings "
    "escalation_findings provenance_findings integrity_findings package_verify_findings "
    "artifact_verify_findings llm_analysis canary".split()
)
SERVER_FIELDS = set(
    "name client config_path project_path scope command args env_keys transport url headers_keys".split()
)


def controlled_environment(home: Path) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": os.defpath,
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


class WireSession:
    """Capture every stdout frame, including frames emitted during shutdown."""

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process
        self.frames: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self.reader = asyncio.create_task(self._read_stdout())
        self.stderr = asyncio.create_task(self._read_stderr())
        self.request_id = 0
        self.frame_count = 0

    async def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            async for line in self.process.stdout:
                jsonrpc_message_adapter.validate_json(line, by_name=False)
                frame = json.loads(line)
                self.frame_count += 1
                await self.frames.put(frame)
        finally:
            await self.frames.put(None)

    async def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        while await self.process.stderr.read(65536):
            pass

    async def send(self, frame: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(frame).encode() + b"\n")
        await self.process.stdin.drain()

    async def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.request_id += 1
        request_id = self.request_id
        await self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        async with asyncio.timeout(30):
            while True:
                frame = await self.frames.get()
                if frame is None:
                    await self.reader  # Surface invalid stdout before the EOF error.
                    raise RuntimeError("MCPAudit exited before replying")
                if frame.get("id") == request_id:
                    assert "error" not in frame, frame
                    result = frame["result"]
                    assert isinstance(result, dict)
                    return result
                assert "id" not in frame, "unexpected protocol request/response"

    async def initialize(self) -> None:
        await self.request(
            "initialize",
            {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "named-server-smoke", "version": "1"},
            },
        )
        await self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        result = await self.request("tools/list", {})
        tool = next(tool for tool in result["tools"] if tool["name"] == "check_server")
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert schema["required"] == ["name"]
        assert set(schema["properties"]) == {"name"}
        assert schema["properties"]["name"]["type"] == "string"

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return await self.request("tools/call", {"name": name, "arguments": arguments})

    async def close(self) -> None:
        assert self.process.stdin is not None
        self.process.stdin.close()
        try:
            await self._wait_for_exit(8)
        except TimeoutError:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await self._wait_for_exit(2)
            raise RuntimeError("MCPAudit did not shut down within the smoke deadline") from None
        finally:
            try:
                await asyncio.wait_for(asyncio.gather(self.reader, self.stderr), timeout=2)
            except TimeoutError:
                raise RuntimeError("MCPAudit pipes did not close within the smoke deadline") from None
            finally:
                for task in (self.reader, self.stderr):
                    task.cancel()
                await asyncio.gather(self.reader, self.stderr, return_exceptions=True)
        assert self.process.returncode == 0, self.process.returncode

    async def _wait_for_exit(self, timeout: float) -> None:
        # Process.wait() can also wait for inherited pipes on asyncio. Keep the
        # process-exit and pipe-drain deadlines separate for detached fixtures.
        async with asyncio.timeout(timeout):
            while self.process.returncode is None:
                await asyncio.sleep(0.02)


def payload(result: dict[str, Any]) -> Any:
    assert result.get("isError", False) is False, result
    content = result["content"]
    assert len(content) == 1 and content[0]["type"] == "text"
    return json.loads(content[0]["text"])


def audit_contract(audit: dict[str, Any], status: str = "connected") -> None:
    assert set(audit) == AUDIT_FIELDS
    assert set(audit["server"]) == SERVER_FIELDS
    assert audit["server"]["name"] == "Target"
    assert audit["connection_status"] == status
    assert isinstance(audit["tools"], list)
    assert isinstance(audit["permissions"], list)
    assert isinstance(audit["has_annotations"], bool)
    assert isinstance(audit["annotation_coverage"], (int, float))
    if status == "connected":
        assert {tool["name"] for tool in audit["tools"]} == {"read_file", "write_file", "execute_command"}
        assert [prompt["name"] for prompt in audit["prompts"]] == ["summarize_file"]
        assert [resource["name"] for resource in audit["resources"]] == ["example"]
        assert audit["connection_error"] is None
    elif status == "failed":
        assert isinstance(audit["connection_error"], str) and audit["connection_error"]
    else:
        assert status == "timeout" and audit["connection_error"] is None


def write_config(path: Path, entries: dict[str, Any], **extra: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": entries, **extra}))


def startup_counts(markers: list[Path]) -> list[int]:
    return [len(path.read_text().splitlines()) if path.exists() else 0 for path in markers]


def fixture_group(pid: int, marker: Path, launcher: Path) -> int | None:
    """Bind a surviving PID to this case's exact launcher and marker before killing."""
    try:
        group = os.getpgid(pid)
    except ProcessLookupError:
        return None
    command = subprocess.run(
        ["/bin/ps", "-ww", "-p", str(pid), "-o", "stat=", "-o", "args="],
        text=True,
        capture_output=True,
        check=False,
        timeout=1,
    )
    if command.returncode == 1:  # Exited between the two observations.
        return None
    if command.returncode == 0 and command.stdout.lstrip().startswith("Z"):
        return None  # A zombie holds no pipes and cannot be terminated again.
    if command.returncode or str(launcher) not in command.stdout or str(marker) not in command.stdout:
        raise RuntimeError("refusing cleanup of a process without matching fixture identity")
    if group != pid:
        raise RuntimeError("refusing cleanup of a fixture outside its dedicated process group")
    return group


async def ensure_children_stopped(markers: list[Path], launcher: Path) -> None:
    survivors: list[int] = []
    for marker in markers:
        if not marker.exists():
            continue
        for line in marker.read_text().splitlines():
            pid = int(line)
            group = fixture_group(pid, marker, launcher)
            if group is None:
                continue
            survivors.append(pid)
            try:
                os.killpg(group, signal.SIGTERM)
            except ProcessLookupError:
                continue
            for _ in range(40):
                await asyncio.sleep(0.05)
                if fixture_group(pid, marker, launcher) is None:
                    break
            else:
                # Revalidate identity before escalating; never kill a reused PID.
                group = fixture_group(pid, marker, launcher)
                if group is not None:
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            for _ in range(40):
                if fixture_group(pid, marker, launcher) is None:
                    break
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError(f"fixture process could not be stopped: {pid}")
    if survivors:
        raise RuntimeError(f"fixture processes survived MCPAudit shutdown and were cleaned up: {survivors}")


async def run_case(executable: Path, mock: Path, case: str) -> int:
    with tempfile.TemporaryDirectory(prefix="mcpaudit-wire-") as temporary:
        root = Path(temporary)
        home, cwd = root / "home", root / "cwd"
        home.mkdir()
        cwd.mkdir()
        markers = [root / "target.starts", root / "other.starts"]
        launcher = root / "marked_server.py"
        launcher.write_text(
            "import os, runpy, sys, time\n"
            "with open(sys.argv[1], 'a') as marker: marker.write(str(os.getpid()) + '\\n')\n"
            "if sys.argv[2] == 'failed': sys.exit(1)\n"
            "if sys.argv[2] == 'timeout': time.sleep(60)\n"
            "runpy.run_path(sys.argv[3], run_name='__main__')\n"
        )
        python = executable.parent / "python"

        def entry(index: int, mode: str = "connected") -> dict[str, Any]:
            return {
                "command": str(python),
                "args": [str(launcher), str(markers[index]), mode, str(mock)],
            }

        target = entry(0, case if case in {"failed", "timeout"} else "connected")
        other = entry(1)
        write_config(home / ".claude.json", {"Target": target, "Other": other})
        if case == "duplicate-client":
            write_config(home / ".cursor/mcp.json", {"Target": other})
        elif case == "duplicate-path":
            write_config(cwd / ".mcp.json", {"Target": other})
        elif case == "duplicate-project":
            write_config(
                home / ".claude.json",
                {"Target": target, "Other": other},
                projects={str(cwd): {"mcpServers": {"Target": other}}},
            )
        elif case.startswith("parse-"):
            if case == "parse-no-target":
                write_config(home / ".claude.json", {"Other": other})
            malformed = home / ".cursor/mcp.json"
            malformed.parent.mkdir()
            malformed.write_text('{"mcpServers": {"PRIVATE_PARSE_SENTINEL":')
        elif case == "override":
            (home / ".mcp-audit.yaml").write_text(
                "overrides:\n  - server: Target\n    tool: read_file\n"
                "    permissions:\n      shell_execution: true\n"
            )

        process = await asyncio.create_subprocess_exec(
            str(executable),
            "serve",
            cwd=cwd,
            env=controlled_environment(home),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        session = WireSession(process)
        expected = [0, 0]
        try:
            await session.initialize()
            if case == "fleet":
                report = payload(await session.call("scan_mcp_servers", {}))
                assert report["servers_discovered"] == report["servers_connected"] == 2
                assert {audit["server"]["name"] for audit in report["audits"]} == {"Target", "Other"}
                expected = [1, 1]
            elif case == "skip-connect":
                report = payload(await session.call("scan_mcp_servers", {"skip_connect": True}))
                assert report["servers_discovered"] == 2 and report["servers_connected"] == 0
                assert all(audit["connection_status"] == "skipped" for audit in report["audits"])
            elif case in {"unique", "override", "failed", "timeout"}:
                audit = payload(await session.call("check_server", {"name": "Target"}))
                audit_contract(audit, case if case in {"failed", "timeout"} else "connected")
                if case == "override":
                    assert any(
                        finding["tool_name"] == "read_file"
                        and finding["category"] == "shell_execution"
                        and finding["confidence"] == "manual"
                        and finding["source_trust"] == "operator_override"
                        for finding in audit["permissions"]
                    )
                expected = [1, 0]
            else:
                name = {"missing": "Absent", "case": "target", "space": " Target"}.get(case, "Target")
                result = await session.call("check_server", {"name": name})
                assert result["isError"] is True
                text = " ".join(item.get("text", "") for item in result["content"])
                expected_reason = (
                    "config parse error"
                    if case.startswith("parse-")
                    else "ambiguous"
                    if case.startswith("duplicate-")
                    else "not found"
                )
                assert expected_reason in text
                assert "PRIVATE_PARSE_SENTINEL" not in text and str(root) not in text
                # A rejected tools/call must leave the session usable.
                assert isinstance(payload(await session.call("list_discovered_servers", {})), list)
            assert startup_counts(markers) == expected, (case, startup_counts(markers))
        finally:
            try:
                await session.close()
            finally:
                await ensure_children_stopped(markers, launcher)
        assert startup_counts(markers) == expected
        print(f"PASS {case}: starts={expected}, protocol_frames={session.frame_count}")
        return session.frame_count


def check_identity(executable: Path, expected_commit: str | None) -> None:
    with tempfile.TemporaryDirectory(prefix="mcpaudit-identity-") as temporary:
        home = Path(temporary)
        environment = controlled_environment(home)
        python = executable.parent / "python"
        code = (
            "import importlib.metadata as m, json, pathlib, mcp_audit; "
            "p=pathlib.Path(mcp_audit.__file__).resolve(); "
            "v=p.parent/'_build_provenance.json'; "
            "print(json.dumps({'package':str(p),'version':m.version('mcp-audits'),"
            "'mcp':m.version('mcp'),'provenance':json.loads(v.read_text()) if v.exists() else None}))"
        )
        result = subprocess.run(
            [str(python), "-c", code],
            cwd=home,
            env=environment,
            check=True,
            text=True,
            capture_output=True,
        )
        identity = json.loads(result.stdout)
        assert identity["version"] == EXPECTED_VERSION
        if expected_commit:
            package = Path(identity["package"])
            assert package.is_relative_to(executable.parent.parent) and "site-packages" in package.parts
            assert identity["provenance"]["commit"] == expected_commit
            assert identity["provenance"]["dirty"] is False
        for command in ("mcp-audit", "mcp-audits", "proof-before-action"):
            version = subprocess.run(
                [str(executable.parent / command), "--version"],
                cwd=home,
                env=environment,
                check=True,
                text=True,
                capture_output=True,
            ).stdout
            assert EXPECTED_VERSION in version
        print("PASS identity: " + json.dumps(identity, sort_keys=True))


async def smoke(executable: Path, mock: Path) -> None:
    cases = (
        "unique",
        "missing",
        "case",
        "space",
        "duplicate-client",
        "duplicate-path",
        "duplicate-project",
        "parse-visible-target",
        "parse-no-target",
        "failed",
        "timeout",
        "override",
        "fleet",
        "skip-connect",
    )
    total_frames = 0
    for case in cases:
        total_frames += await run_case(executable, mock, case)
    print(f"PASS {len(cases)} synthetic stdio cases; {total_frames} valid stdout frames")


def main() -> None:
    if not __debug__:
        raise RuntimeError("run this verification script without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expected-commit")
    args = parser.parse_args()
    executable = args.executable.absolute()
    mock = Path(__file__).resolve().parents[1] / "tests/fixtures/mock_server.py"
    assert executable.is_file() and mock.is_file()
    check_identity(executable, args.expected_commit)
    asyncio.run(smoke(executable, mock))


if __name__ == "__main__":
    main()
