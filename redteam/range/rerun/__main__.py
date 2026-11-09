"""Run the complete offline mutation range flow."""

import argparse
import json

from redteam.range.gen.__main__ import ROOT, generate
from redteam.range.harness.scan import RESULTS, scan
from redteam.range.report.report import build_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--accept", action="store_true", help="replace the baseline with current results")
    args = parser.parse_args()
    generate()
    data = scan()
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    control = data["control"]
    assert isinstance(control, dict)
    if control["expected_id_findings"]:
        print(f"Clean control emitted expected IDs: {control['expected_id_findings']}")
        return 1
    report, status = build_report(
        RESULTS,
        ROOT / "redteam/range/baseline.json",
        ROOT / "build/redteam/range/report.html",
        accept=args.accept,
    )
    print(report, end="")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
