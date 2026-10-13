#!/usr/bin/env python3
"""Check locked PyPI packages against the OSV batch API."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
REQUEST_TIMEOUT_SECONDS = 15
MAX_REQUEST_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 2_000_000
MAX_QUERIES = 500
PIN_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)"
    r"(?:\s+--hash=sha256:[0-9a-fA-F]{64})?$"
)


class AdvisoryCheckError(Exception):
    """Raised when the lock, constraints, or OSV response cannot be checked."""


def load_queries(lock_path: Path, constraints_path: Path | None) -> list[dict[str, object]]:
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise AdvisoryCheckError(f"cannot read lock file: {exc}") from exc

    packages = lock.get("package")
    if not isinstance(packages, list):
        raise AdvisoryCheckError("lock file has no package list")

    versions: set[tuple[str, str]] = set()
    for package_value in packages:
        if not isinstance(package_value, dict):
            raise AdvisoryCheckError("lock file contains an invalid package entry")
        package = cast(dict[str, object], package_value)
        source_value = package.get("source")
        if not isinstance(source_value, dict):
            continue
        source = cast(dict[str, object], source_value)
        if source.get("registry") != "https://pypi.org/simple":
            continue
        name, version = package.get("name"), package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise AdvisoryCheckError("registry package is missing its name or version")
        versions.add((name, version))

    if constraints_path is not None and constraints_path.exists():
        try:
            lines = constraints_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise AdvisoryCheckError(f"cannot read build constraints: {exc}") from exc
        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.partition("#")[0].strip()
            if not line:
                continue
            match = PIN_RE.fullmatch(line)
            if match is None:
                raise AdvisoryCheckError(
                    f"build constraint line {line_number} must be an exact name==version pin"
                )
            name, version = match.groups()
            versions.add((name, version))

    if len(versions) > MAX_QUERIES:
        raise AdvisoryCheckError(f"package query count exceeds limit ({MAX_QUERIES})")
    return [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in sorted(versions, key=lambda item: (item[0].casefold(), item[1]))
    ]


def read_bounded(stream: object, limit: int) -> bytes:
    reader = getattr(stream, "read", None)
    if not callable(reader):
        raise AdvisoryCheckError("OSV response stream is invalid")
    payload = reader(limit + 1)
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise AdvisoryCheckError("OSV response exceeds the configured size limit")
    return payload


def request_osv(queries: list[dict[str, object]]) -> object:
    body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise AdvisoryCheckError("OSV request exceeds the configured size limit")
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            payload = read_bounded(response, MAX_RESPONSE_BYTES)
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise AdvisoryCheckError(f"OSV advisory feed unavailable: {type(exc).__name__}") from exc
    try:
        return json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdvisoryCheckError("OSV returned invalid JSON") from exc


def load_fixture(path: Path) -> object:
    try:
        with path.open("rb") as fixture_file:
            payload = read_bounded(fixture_file, MAX_RESPONSE_BYTES)
    except OSError as exc:
        raise AdvisoryCheckError(f"cannot read fixture response: {exc}") from exc
    try:
        return json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AdvisoryCheckError("fixture response is invalid JSON") from exc


def vulnerable_packages(response: object, queries: list[dict[str, object]]) -> list[tuple[str, list[str]]]:
    if not isinstance(response, dict):
        raise AdvisoryCheckError("OSV response must be a JSON object")
    results = response.get("results")
    if not isinstance(results, list) or len(results) != len(queries):
        raise AdvisoryCheckError("OSV response result count does not match the query count")
    findings: list[tuple[str, list[str]]] = []
    for index, result_value in enumerate(results):
        if not isinstance(result_value, dict):
            raise AdvisoryCheckError(f"OSV result {index} is invalid")
        result = cast(dict[str, object], result_value)
        status = result.get("status")
        if "error" in result or (isinstance(status, str) and status.casefold() == "error"):
            raise AdvisoryCheckError(f"OSV result {index} indicates an error")
        vulnerabilities_value = result.get("vulns", [])
        if vulnerabilities_value is None:
            continue
        if not isinstance(vulnerabilities_value, list):
            raise AdvisoryCheckError(f"OSV result {index} has invalid vulnerabilities")
        ids: list[str] = []
        for vulnerability_value in vulnerabilities_value:
            if not isinstance(vulnerability_value, dict):
                raise AdvisoryCheckError(f"OSV result {index} has an invalid vulnerability")
            vulnerability = cast(dict[str, object], vulnerability_value)
            identifier = vulnerability.get("id")
            if not isinstance(identifier, str) or not identifier:
                raise AdvisoryCheckError(f"OSV result {index} has a vulnerability without an id")
            ids.append(identifier)
        if ids:
            query = queries[index]
            package = cast(dict[str, object], query["package"])
            findings.append((str(package["name"]), ids))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "uv.lock")
    parser.add_argument(
        "--build-constraints",
        type=Path,
        default=ROOT / "build-constraints.txt",
        help="exact-pinned build constraints file (read only if present)",
    )
    parser.add_argument(
        "--response-json",
        type=Path,
        help="read a saved OSV batch response fixture instead of contacting OSV",
    )
    args = parser.parse_args()
    constraints_missing = not args.build_constraints.exists()
    if constraints_missing:
        print("build-input coverage unavailable: build-constraints.txt missing", file=sys.stderr)

    try:
        queries = load_queries(args.lock, args.build_constraints)
        if not queries:
            raise AdvisoryCheckError("no public PyPI package versions found in lock or constraints")
        response = load_fixture(args.response_json) if args.response_json else request_osv(queries)
        findings = vulnerable_packages(response, queries)
    except AdvisoryCheckError as exc:
        print(f"advisory check unavailable: {exc}", file=sys.stderr)
        return 2

    if args.response_json:
        print("advisory check fixture mode")
    print(f"checked {len(queries)} locked public PyPI package versions")
    if findings:
        for package_name, identifiers in findings:
            print(f"advisory: {package_name}: {', '.join(identifiers)}")
        return 1
    print("no advisories found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
