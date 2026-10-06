"""Local-only MCP fixture: flood stderr before serving or hanging."""

from __future__ import annotations

import asyncio
import os
import sys
import time

from tests.fixtures.mock_server import main

if "short" in sys.argv:
    os.write(2, b"before token=abc123 after\n")
elif "boundary-bearer" in sys.argv or "boundary-token" in sys.argv:
    prefix = b"Bearer " if "boundary-bearer" in sys.argv else b"token="
    secret = b"fixture-boundary-marker"
    suffix = b"\nstderr-whole-tail\n" if "newline" in sys.argv else b""
    record = secret + b"x" * (4096 - len(secret) - len(suffix)) + suffix
    os.write(2, prefix + record)
else:
    for _ in range(256):
        os.write(2, b"stderr-noise-\x1b[2J" + b"x" * (4096 - 17))
    os.write(2, b"\n\x1b]0;pwned\x07stderr-tail[/bold]\nBearer fixture-sensitive-marker\n")

if "hang" in sys.argv:
    time.sleep(60)
elif "fail" in sys.argv:
    raise RuntimeError("fixture failure")
else:
    asyncio.run(main())
