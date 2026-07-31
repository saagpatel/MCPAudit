#!/usr/bin/env python3
"""Validate schemas, full artifacts, locality, privacy, and package bindings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
from package_lib import validate_package


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="v2 package root",
    )
    args = parser.parse_args()
    result = validate_package(args.root, jsonschema)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
