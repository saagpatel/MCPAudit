"""Disposable full-field redaction process, without listing text truncation."""

from __future__ import annotations

import json
import resource
import sys
import time
from pathlib import Path

from mcp_audit.redaction import redact_text
from tests.fixtures.escape_dense import escape_dense_field


def run() -> None:
    field = escape_dense_field()
    start = time.perf_counter()
    redacted = redact_text(field)
    seconds = time.perf_counter() - start
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    Path(sys.argv[1]).write_text(
        json.dumps(
            {
                "redaction_seconds": seconds,
                "redaction_input_bytes": len(field.encode("utf-8")),
                "redaction_output_bytes": len(redacted.encode("utf-8")),
                "credential_withheld": "fixture-credential" not in redacted and "<redacted>" in redacted,
                "stable": redact_text(redacted) == redacted,
                "peak_rss_bytes": rss if sys.platform == "darwin" else rss * 1024,
            }
        )
    )


if __name__ == "__main__":
    run()
