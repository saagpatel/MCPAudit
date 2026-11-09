"""Scan generated inert surfaces directly with isolated detector inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from mcp_audit.pkgverify import PackageRef
from redteam.range.gen.__main__ import BASE, OUTPUT, ROOT
from redteam.range.harness.adapter import DETECTOR_KEYS, DetectorKey, IntegrityInput, run_detectors
from redteam.surface import ServerSurface

RESULTS = ROOT / "build/redteam/range/results.json"


class IntegrityData(BaseModel):
    artifacts: dict[str, str]
    current_files: dict[str, str]
    current_files_encoding: Literal["hex"]


class Companions(BaseModel):
    baseline: ServerSurface | None = None
    fleet: list[ServerSurface] = Field(default_factory=list)
    integrity: IntegrityData | None = None
    package_fetch: None = None


class TwinData(BaseModel):
    twin_id: str
    category: str
    detector: DetectorKey
    expected_ids: list[str]
    allowed_collateral: list[str]
    predicted: Literal["catch", "miss"]
    surface: ServerSurface
    companions: Companions


def _fetch(_reference: PackageRef) -> str:
    """A deterministic offline stand-in; never contact a registry."""
    return "a" * 64


def scan(twins_dir: Path = OUTPUT, *, disabled: set[str] | None = None) -> dict[str, object]:
    ids = json.loads((twins_dir / "index.json").read_text(encoding="utf-8"))
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        raise ValueError("twin index must be a list of IDs")
    if len(ids) != len(set(ids)) or any(Path(item).name != item or item in {".", ".."} for item in ids):
        raise ValueError("twin index contains duplicate or unsafe IDs")
    base = ServerSurface.load(BASE / "surface.json")
    clean = ServerSurface.load(ROOT / "redteam/fixtures/servers/fleet/clean-companion.json")
    artifact = b"synthetic fixture artifact"
    clean_integrity = IntegrityInput(
        artifacts={"artifact.txt": hashlib.sha256(artifact).hexdigest()},
        current_files={"artifact.txt": artifact},
    )
    records: list[dict[str, object]] = []
    expected_all: set[str] = set()
    for twin_id in ids:
        twin = TwinData.model_validate_json((twins_dir / twin_id / "twin.json").read_text(encoding="utf-8"))
        if twin.twin_id != twin_id:
            raise ValueError(f"twin identity mismatch: {twin_id}")
        companion = twin.companions
        integrity = clean_integrity
        if companion.integrity is not None:
            integrity = IntegrityInput(
                artifacts=companion.integrity.artifacts,
                current_files={k: bytes.fromhex(v) for k, v in companion.integrity.current_files.items()},
            )
        result = run_detectors(
            twin.surface,
            baseline=companion.baseline or base,
            fleet=companion.fleet or [clean],
            integrity=integrity,
            package_fetch=_fetch,
            disabled=disabled,
        )
        status = result.statuses[twin.detector]
        emitted = sorted({finding.check_id for finding in result.findings})
        targeted = {finding.check_id for finding in result.findings if finding.detector == twin.detector}
        expected = set(twin.expected_ids)
        expected_all.update(expected)
        allowed = set(twin.allowed_collateral)
        outcome = "NOT_RUN" if status.state != "completed" else "CAUGHT" if targeted & expected else "MISSED"
        records.append(
            {
                "id": twin_id,
                "category": twin.category,
                "detector": twin.detector,
                "expected_ids": sorted(expected),
                "allowed_collateral": sorted(allowed),
                "result": outcome,
                "reason": status.reason,
                "statuses": {twin.detector: {"state": status.state, "reason": status.reason}},
                "predicted": twin.predicted,
                "emitted_ids": emitted,
                "collateral_ids": sorted(set(emitted) & allowed - expected),
                "unexpected_ids": sorted(set(emitted) - expected - allowed),
                "provenance": sorted(result.provenance),
            }
        )
    control = run_detectors(
        base, baseline=base, fleet=[clean], integrity=clean_integrity, package_fetch=_fetch, disabled=disabled
    )
    control_ids = sorted({finding.check_id for finding in control.findings})
    negative = sorted(set(control_ids) & expected_all)
    control_result = (
        "FINDINGS"
        if negative
        else "INCOMPLETE"
        if any(s.state != "completed" for s in control.statuses.values())
        else "CLEAN"
    )
    return {
        "twins": records,
        "control": {
            "result": control_result,
            "emitted_ids": control_ids,
            "expected_id_findings": negative,
            "provenance": sorted(control.provenance),
            "statuses": {
                key: {"state": value.state, "reason": value.reason} for key, value in control.statuses.items()
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disable", action="append", choices=DETECTOR_KEYS, default=[], metavar="DETECTOR")
    args = parser.parse_args()
    data = scan(disabled=set(args.disable))
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    control = data["control"]
    twins = data["twins"]
    assert isinstance(control, dict) and isinstance(twins, list)
    print(
        f"Scanned {len(twins)} twins; clean control expected-ID findings: {control['expected_id_findings']}"
    )
    return int(bool(control["expected_id_findings"]))


if __name__ == "__main__":
    raise SystemExit(main())
