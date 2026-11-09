"""Write the registered twins after validating their mutation records."""

from __future__ import annotations

import json
from pathlib import Path

from redteam.range.mutations import OPERATORS, TwinInput, validate_twin
from redteam.surface import ServerSurface

ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "redteam/fixtures/servers/base"
OUTPUT = ROOT / "build/redteam/range/twins"


def generate(output: Path = OUTPUT) -> None:
    """Generate all twins in registry order, without executing fixture code."""
    base = TwinInput(
        surface=ServerSurface.load(BASE / "surface.json"),
        source=(BASE / "server.py.txt").read_text(encoding="utf-8"),
    )
    operator_ids = [operator.id for operator in OPERATORS]
    if len(operator_ids) < 30 or len(set(operator_ids)) != len(operator_ids):
        raise ValueError("expected at least 30 uniquely identified operators")
    twins = [(operator, operator.apply(base)) for operator in OPERATORS]
    for operator, twin in twins:
        if twin.twin_id != operator.id or twin.operator_id != operator.id:
            raise ValueError(f"{operator.id}: twin identity mismatch")
        validate_twin(base, twin)

    output.mkdir(parents=True, exist_ok=True)
    for operator, twin in twins:
        directory = output / twin.twin_id
        directory.mkdir(parents=True, exist_ok=True)
        integrity = twin.companions.integrity
        data = {
            "twin_id": twin.twin_id,
            "operator_id": twin.operator_id,
            "category": twin.category,
            "detector": operator.detector,
            "expected_ids": operator.expected_ids,
            "allowed_collateral": operator.allowed_collateral,
            "predicted": operator.predicted,
            "rationale": operator.rationale,
            "surface": twin.surface.model_dump(mode="json"),
            "source": twin.source,
            "companions": {
                "baseline": (
                    twin.companions.baseline.model_dump(mode="json")
                    if twin.companions.baseline is not None
                    else None
                ),
                "fleet": [member.model_dump(mode="json") for member in twin.companions.fleet],
                "integrity": (
                    {
                        "artifacts": integrity.artifacts,
                        "current_files": {
                            path: content.hex() for path, content in integrity.current_files.items()
                        },
                        "current_files_encoding": "hex",
                    }
                    if integrity is not None
                    else None
                ),
                "package_fetch": twin.companions.package_fetch,
            },
            "mutation_record": twin.mutation_record,
        }
        (directory / "twin.json").write_text(
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (directory / "server.py.txt").write_text(twin.source, encoding="utf-8")
    (output / "index.json").write_text(
        json.dumps([twin.twin_id for _, twin in twins], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    generate()
    print(f"{len(OPERATORS)} twins, each with exactly one mutation")


if __name__ == "__main__":
    main()
