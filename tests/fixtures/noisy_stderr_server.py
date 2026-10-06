"""Local-only MCP fixture: flood stderr before serving or hanging."""

from __future__ import annotations

import asyncio
import os
import sys
import time

from tests.fixtures.mock_server import main

for _ in range(256):
    os.write(2, b"stderr-noise-\x1b[2J" + b"x" * (4096 - 17))
os.write(2, b"\x1b]0;pwned\x07stderr-tail[/bold]\nBearer fixture-sensitive-marker\n")

if "hang" in sys.argv:
    time.sleep(60)
elif "fail" in sys.argv:
    raise RuntimeError("fixture failure")
else:
    asyncio.run(main())
