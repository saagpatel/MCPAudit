#!/usr/bin/env python3
"""Build the deterministic v2 evidence-package candidate."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from package_lib import build_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="v2 package root",
    )
    args = parser.parse_args()
    result = build_package(args.root)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
