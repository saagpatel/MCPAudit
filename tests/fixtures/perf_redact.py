"""Disposable full-field redaction process, without listing text truncation."""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

from mcp_audit.redaction import redact_text
from tests.fixtures.escape_dense import escape_dense_field


def _peak_rss() -> int:
    """This process's own peak RSS in bytes.

    Linux ru_maxrss keeps the forked parent's high-water mark across exec, so a
    large pytest parent would inflate every later case; VmHWM is per address space.
    """
    if sys.platform.startswith("linux"):
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return rss if sys.platform == "darwin" else rss * 1024


def run() -> None:
    field = escape_dense_field()
    start = time.perf_counter()
    redacted = redact_text(field)
    seconds = time.perf_counter() - start
    Path(sys.argv[1]).write_text(
        json.dumps(
            {
                "redaction_seconds": seconds,
                "redaction_input_bytes": len(field.encode("utf-8")),
                "redaction_output_bytes": len(redacted.encode("utf-8")),
                "credential_withheld": "fixture-credential" not in redacted and "<redacted>" in redacted,
                "stable": redact_text(redacted) == redacted,
                "peak_rss_bytes": _peak_rss(),
            }
        )
    )


if __name__ == "__main__":
    run()
