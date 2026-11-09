"""Deterministic Markdown and offline HTML reports for Mutation Range scans.

Success requires complete inventory evidence, no unaccepted regressions and a
CLEAN control. Acceptance can approve twin changes, but cannot waive a failed
control or an invalid inventory. The generated report documents the sole
package-verification not-applicable exception.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, TypedDict, cast

from redteam.range.harness.adapter import DETECTOR_KEYS

Result = Literal["CAUGHT", "MISSED", "NOT_RUN"]


class TwinRecord(TypedDict, total=False):
    id: str
    category: str
    detector: str
    expected_ids: list[str]
    allowed_collateral: list[str]
    result: Result
    predicted: str
    emitted_ids: list[str]
    collateral_ids: list[str]
    unexpected_ids: list[str]
    provenance: list[str]
    reason: str
    statuses: dict[str, object]
    expected_id_findings: list[str]


class ControlRecord(TypedDict, total=False):
    result: Literal["CLEAN", "FINDINGS", "INCOMPLETE"]
    emitted_ids: list[str]
    expected_id_findings: list[str]
    medium_plus_findings: list[str]
    statuses: dict[str, object]
    detector_provenance: dict[str, list[str]]
    not_applicable: list[str]


class ScanData(TypedDict, total=False):
    twins: list[TwinRecord]
    control: ControlRecord


def _read_scan(path: Path) -> ScanData:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("twins"), list) or not raw["twins"]:
        raise ValueError("results must be a JSON object with a non-empty twins list")
    twins: list[TwinRecord] = []
    seen: set[str] = set()
    for index, value in enumerate(raw["twins"]):
        if not isinstance(value, dict):
            raise ValueError(f"twins[{index}] must be an object")
        twin = cast(TwinRecord, value)
        for field in ("id", "category", "detector", "predicted"):
            if not isinstance(twin.get(field), str) or not twin.get(field):
                raise ValueError(f"twins[{index}].{field} must be a non-empty string")
        if twin["detector"] not in DETECTOR_KEYS:
            raise ValueError(f"twins[{index}].detector has an unknown value")
        for field in ("expected_ids", "emitted_ids", "expected_id_findings"):
            field_value = twin.get(field)
            if field_value is not None and (
                not isinstance(field_value, list) or not all(isinstance(item, str) for item in field_value)
            ):
                raise ValueError(f"twins[{index}].{field} must be a list of strings")
        if not isinstance(twin.get("emitted_ids"), list):
            raise ValueError(f"twins[{index}].emitted_ids must be a list of strings")
        result = twin.get("result")
        if result is not None and result not in {"CAUGHT", "MISSED", "NOT_RUN"}:
            raise ValueError(f"twins[{index}].result has an unknown value")
        status_map = twin.get("statuses")
        status_value = status_map.get(twin["detector"]) if isinstance(status_map, dict) else None
        state = status_value.get("state") if isinstance(status_value, dict) else status_value
        if state != "completed":
            twin["result"] = "NOT_RUN"
        elif result is None:
            emitted_expected = set(twin.get("expected_id_findings", []))
            emitted_expected.update(set(twin.get("expected_ids", [])) & set(twin["emitted_ids"]))
            twin["result"] = "CAUGHT" if emitted_expected else "MISSED"
        twin_id = twin["id"]
        if twin_id in seen:
            raise ValueError(f"duplicate twin id: {twin_id}")
        seen.add(twin_id)
        twins.append(twin)
    normalized: ScanData = {"twins": twins}
    control = raw.get("control")
    if not isinstance(control, dict):
        raise ValueError("clean control must be an object")
    if control.get("result") not in {"CLEAN", "FINDINGS", "INCOMPLETE"}:
        raise ValueError("clean control result must be CLEAN, FINDINGS or INCOMPLETE")
    for field in ("emitted_ids", "expected_id_findings", "medium_plus_findings", "not_applicable"):
        value = control.get(field, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"control.{field} must be a list of strings")
    normalized_control = cast(ControlRecord, control)
    # Scan classifies medium+ findings. Recheck coverage here as well, so a
    # stale CLEAN label cannot hide missing/disabled detector evidence.
    statuses = normalized_control.get("statuses", {})
    if not isinstance(statuses, dict):
        raise ValueError("control.statuses must be an object")
    incomplete = False
    not_applicable = normalized_control.get("not_applicable", [])
    for key in DETECTOR_KEYS:
        status = statuses.get(key)
        if not isinstance(status, dict):
            incomplete = True
            continue
        # The scan establishes that the base has no package refs. This exact
        # exemption does not cover disabled, incomplete or missing checks.
        exempt = (
            key == "pkgverify"
            and not_applicable == ["pkgverify"]
            and status.get("state") == "not_run"
            and status.get("reason") == "baseline capture failed"
        )
        incomplete |= status.get("state") != "completed" and not exempt
    incomplete |= bool(set(not_applicable) - {"pkgverify"})
    # Older scans did not serialize a severity-filtered finding list. Empty
    # emissions are unambiguous; non-empty emissions need a fresh scan.
    incomplete |= bool(normalized_control.get("emitted_ids")) and "medium_plus_findings" not in control
    if normalized_control.get("expected_id_findings") or normalized_control.get("medium_plus_findings"):
        normalized_control["result"] = "FINDINGS"
    elif incomplete and normalized_control["result"] == "CLEAN":
        normalized_control["result"] = "INCOMPLETE"
    normalized["control"] = normalized_control
    return normalized


def _validate_inventory(current: ScanData, index_path: Path) -> None:
    ids = json.loads(index_path.read_text(encoding="utf-8"))
    if not isinstance(ids, list) or not ids or not all(isinstance(item, str) and item for item in ids):
        raise ValueError("twin index must be a non-empty list of IDs")
    if len(ids) != len(set(ids)):
        raise ValueError("twin index contains duplicate IDs")
    current_ids = {twin["id"] for twin in current["twins"]}
    missing, extra = sorted(set(ids) - current_ids), sorted(current_ids - set(ids))
    if missing or extra:
        raise ValueError(f"results do not match twin index: missing={missing}, extra={extra}")


def _ordered_ids(items: Sequence[str] | None) -> str:
    return ", ".join(sorted(items or ())) or "—"


def _matrix_rows(
    twins: Sequence[TwinRecord],
) -> tuple[list[str], list[str], dict[tuple[str, str], Result]]:
    categories = sorted({twin["category"] for twin in twins})
    twin_ids = [twin["id"] for twin in twins]
    cells = {(twin["category"], twin["id"]): twin["result"] for twin in twins}
    return categories, twin_ids, cells


def _markdown(
    data: ScanData, regressions: Sequence[str], improvements: Sequence[str], additions: Sequence[str]
) -> str:
    twins = data["twins"]
    categories, twin_ids, cells = _matrix_rows(twins)
    lines = ["# Mutation Range report", "", "## Detection matrix", ""]
    lines.append("| Category | " + " | ".join(twin_ids) + " |")
    lines.append("|---|" + "|".join("---" for _ in twin_ids) + "|")
    for category in categories:
        values = [cells.get((category, twin_id), "") for twin_id in twin_ids]
        lines.append("| " + " | ".join([category, *values]) + " |")
    counts = Counter((twin["category"], twin["result"]) for twin in twins)
    total = Counter(twin["result"] for twin in twins)
    lines.extend(["", "## Summary", "", "| Category | CAUGHT | MISSED | NOT_RUN |", "|---|---:|---:|---:|"])
    for category in categories:
        lines.append(
            f"| {category} | {counts[(category, 'CAUGHT')]} | {counts[(category, 'MISSED')]} | "
            f"{counts[(category, 'NOT_RUN')]} |"
        )
    lines.append(f"| Total | {total['CAUGHT']} | {total['MISSED']} | {total['NOT_RUN']} |")
    predicted_miss_confirmed = sum(
        twin["predicted"] == "miss" and twin["result"] == "MISSED" for twin in twins
    )
    prediction_surprises = sum(
        (twin["predicted"] == "catch" and twin["result"] == "MISSED")
        or (twin["predicted"] == "miss" and twin["result"] == "CAUGHT")
        for twin in twins
    )
    lines.extend(
        [
            "",
            f"Predicted miss confirmed: {predicted_miss_confirmed}; "
            f"prediction surprises: {prediction_surprises}.",
            "",
            "## Per-twin results",
            "",
            "| Twin | Category | Detector | Detector state | Expected IDs | Result | Predicted | "
            "Emitted IDs | Allowed collateral | Unexpected IDs | Provenance | Reason | "
            "Other incomplete detectors |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for twin in twins:
        statuses = twin.get("statuses", {})
        status_value = statuses.get(twin["detector"]) if isinstance(statuses, dict) else None
        detector_state = status_value.get("state", "") if isinstance(status_value, dict) else ""
        other_incomplete = "; ".join(
            f"{key}: {value.get('reason') or 'incomplete'}"
            for key, value in sorted(statuses.items())
            if key != twin["detector"] and isinstance(value, dict) and value.get("state") == "incomplete"
        )
        lines.append(
            "| {id} | {category} | {detector} | {state} | {expected} | {result} | {predicted} | "
            "{emitted} | {allowed} | {unexpected} | {provenance} | {reason} | {other_incomplete} |".format(
                id=twin["id"],
                category=twin["category"],
                detector=twin["detector"],
                state=detector_state,
                expected=_ordered_ids(twin.get("expected_ids")),
                result=twin["result"],
                predicted=twin["predicted"],
                emitted=_ordered_ids(twin.get("emitted_ids")),
                allowed=_ordered_ids(twin.get("allowed_collateral")),
                unexpected=_ordered_ids(twin.get("unexpected_ids")),
                provenance=_ordered_ids(twin.get("provenance")),
                reason=twin.get("reason") or "",
                other_incomplete=other_incomplete,
            )
        )
    control = data.get("control")
    if control is not None:
        lines.extend(["", "## Clean base control", "", f"Result: {control.get('result', 'UNKNOWN')}."])
        lines.append(f"Expected-ID findings: {_ordered_ids(control.get('expected_id_findings'))}.")
        lines.append(f"Medium+ findings: {_ordered_ids(control.get('medium_plus_findings'))}.")
        lines.append(f"Emitted IDs: {_ordered_ids(control.get('emitted_ids'))}.")
        lines.append(f"Not applicable: {_ordered_ids(control.get('not_applicable'))}.")
        lines.append(
            "Only pkgverify is exempt when the base has no package references and its state is "
            "not_run with reason 'baseline capture failed'; all other control checks must complete."
        )
        control_statuses = control.get("statuses")
        if isinstance(control_statuses, dict):
            state_text = ", ".join(
                f"{key}={value.get('state', '') if isinstance(value, dict) else value}"
                for key, value in sorted(control_statuses.items())
            )
            lines.append(f"Detector states: {state_text}.")
        provenance = control.get("detector_provenance", {})
        lines.append(f"Package verification provenance: {_ordered_ids(provenance.get('pkgverify'))}.")
    lines.extend(["", "## Baseline diff", ""])
    lines.append(
        f"Regressions: {len(regressions)}; improvements: {len(improvements)}; additions: {len(additions)}."
    )
    for title, changes in (
        ("Regressions", regressions),
        ("Improvements", improvements),
        ("Additions", additions),
    ):
        if changes:
            lines.extend(["", f"{title}:"])
            lines.extend(f"- {change}" for change in changes)
    return "\n".join(lines) + "\n"


def _html_report(markdown: str) -> str:
    rendered: list[str] = []
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("|"):
            rows: list[list[str]] = []
            while index < len(lines) and lines[index].startswith("|"):
                cells = [cell.strip() for cell in lines[index].strip("|").split("|")]
                if not cells or all(set(cell) <= {"-", ":"} for cell in cells):
                    index += 1
                    continue
                rows.append(cells)
                index += 1
            if rows:
                rendered.append("<table><thead><tr>")
                rendered.extend(f"<th>{html.escape(cell)}</th>" for cell in rows[0])
                rendered.append("</tr></thead><tbody>")
                for row in rows[1:]:
                    rendered.append("<tr>")
                    rendered.extend(f"<td>{html.escape(cell)}</td>" for cell in row)
                    rendered.append("</tr>")
                rendered.append("</tbody></table>")
            continue
        if line.startswith("# "):
            rendered.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            rendered.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("- "):
            rendered.append(f"<p>• {html.escape(line[2:])}</p>")
        elif line:
            rendered.append(f"<p>{html.escape(line)}</p>")
        index += 1
    body = "\n".join(rendered)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Mutation Range report</title><style>"
        "body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#17202a}"
        "table{border-collapse:collapse;display:block;overflow:auto;margin:1rem 0}"
        "th,td{border:1px solid #dce2e8;padding:.35rem .55rem;text-align:left;white-space:nowrap}"
        "th{background:#f5f7f9}main{max-width:100%}"
        f"</style></head><body><main>{body}</main></body></html>\n"
    )


def _baseline_diff(current: ScanData, baseline: ScanData) -> tuple[list[str], list[str], list[str]]:
    before = {twin["id"]: twin for twin in baseline["twins"]}
    after = {twin["id"]: twin for twin in current["twins"]}
    regressions: list[str] = []
    improvements: list[str] = []
    additions = [f"{twin_id}: twin added" for twin_id in sorted(after.keys() - before.keys())]
    regressions.extend(f"{twin_id}: twin removed" for twin_id in sorted(before.keys() - after.keys()))
    for twin_id in sorted(before.keys() & after.keys()):
        previous, twin = before[twin_id], after[twin_id]
        for field in ("category", "detector"):
            if previous[field] != twin[field]:
                regressions.append(f"{twin_id}: {field} changed: {previous[field]} → {twin[field]}")
        # Retargeting a twin's check IDs (or widening what counts as collateral) changes what a
        # CAUGHT result means, so it needs explicit acceptance even when the result is unchanged.
        for id_field in ("expected_ids", "allowed_collateral"):
            old_ids = sorted(set(previous.get(id_field, [])))
            new_ids = sorted(set(twin.get(id_field, [])))
            if old_ids != new_ids:
                old_text, new_text = ", ".join(old_ids) or "—", ", ".join(new_ids) or "—"
                regressions.append(f"{twin_id}: {id_field} changed: {old_text} → {new_text}")
        old = previous["result"]
        new = twin["result"]
        if (old == "CAUGHT" and new in {"MISSED", "NOT_RUN"}) or (old == "MISSED" and new == "NOT_RUN"):
            regressions.append(f"{twin['id']}: {old} → {new}")
        elif old == "MISSED" and new == "CAUGHT":
            improvements.append(f"{twin['id']}: MISSED → CAUGHT")
    return regressions, improvements, additions


def build_report(
    results_path: Path,
    baseline_path: Path,
    html_path: Path,
    *,
    accept: bool = False,
    index_path: Path | None = None,
) -> tuple[str, int]:
    current = _read_scan(results_path)
    _validate_inventory(current, index_path or results_path.parent / "twins/index.json")
    control_clean = current["control"]["result"] == "CLEAN"
    if accept and not control_clean:
        raise ValueError(f"cannot accept baseline: clean control is {current['control']['result']}")
    if accept:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(current, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        baseline = current
    else:
        baseline = _read_scan(baseline_path)
    regressions, improvements, additions = _baseline_diff(current, baseline)
    rendered = _markdown(current, regressions, improvements, additions)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(_html_report(rendered), encoding="utf-8")
    return rendered, int(bool(regressions) or not control_clean)


def main(argv: Sequence[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=root / "build/redteam/range/results.json")
    parser.add_argument("--baseline", type=Path, default=root / "redteam/range/baseline.json")
    parser.add_argument("--html", type=Path, default=root / "build/redteam/range/report.html")
    parser.add_argument(
        "--index", type=Path, help="generated twin index (default: twins/index.json beside results)"
    )
    parser.add_argument(
        "--accept",
        action="store_true",
        help="replace the baseline only with complete results and a CLEAN control",
    )
    args = parser.parse_args(argv)
    try:
        output, status = build_report(
            args.results, args.baseline, args.html, accept=args.accept, index_path=args.index
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"report: {error}", file=sys.stderr)
        return 2
    print(output, end="")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
