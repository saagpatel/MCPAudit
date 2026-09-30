"""Exercise the smoke harness's actual detached-child shutdown failure path."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "named_server_smoke", Path(__file__).resolve().parents[1] / "scripts/smoke_named_server.py"
)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


@pytest.mark.anyio
async def test_shutdown_bounds_pipe_drain_and_cleans_detached_fixture(tmp_path: Path) -> None:
    marker = tmp_path / "fixture.starts"
    launcher = tmp_path / "fixture.py"
    launcher.write_text(
        "import os, sys, time\n"
        "with open(sys.argv[1], 'w') as marker: marker.write(str(os.getpid()) + '\\n')\n"
        "time.sleep(60)\n"
    )
    # The parent exits, but its detached child retains the captured stderr pipe.
    parent = tmp_path / "parent.py"
    parent.write_text("import subprocess, sys\nsubprocess.Popen(sys.argv[1:], start_new_session=True)\n")
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(parent),
        sys.executable,
        str(launcher),
        str(marker),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    session = smoke.WireSession(process)
    try:
        async with asyncio.timeout(5):
            while not marker.exists() or not marker.read_text().strip():
                await asyncio.sleep(0.01)
        pid = int(marker.read_text())
        with pytest.raises(RuntimeError, match="pipes did not close"):
            async with asyncio.timeout(6):
                await session.close()
        assert session.reader.done() and session.stderr.done()
    finally:
        # A cleanup failure is still a failed smoke; it must leave no fixture running.
        with pytest.raises(RuntimeError, match="survived MCPAudit shutdown and were cleaned up"):
            await smoke.ensure_children_stopped([marker], launcher)
    async with asyncio.timeout(5):
        while True:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)
