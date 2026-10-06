"""Local connection fixture: record a spawn before serving harmless MCP metadata."""

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    Path(sys.argv[1]).touch()
    runpy.run_path(str(Path(__file__).with_name("mock_server.py")), run_name="__main__")
