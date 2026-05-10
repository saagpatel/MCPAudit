#!/usr/bin/env python3
"""Parse an MCPAudit JSON report into a compact server-risk summary."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def summarize(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one summary row per audited server."""
    rows: list[dict[str, Any]] = []
    for audit in report.get("audits", []):
        risk_score = audit.get("risk_score") or {}
        non_tool_risk = audit.get("non_tool_risk") or {}
        non_tool_targets = [
            {
                "target_type": finding.get("target_type"),
                "target_name": finding.get("target_name"),
                "kind": kind,
            }
            for kind, findings in [
                ("capability", audit.get("capability_findings", [])),
                ("injection", audit.get("injection_findings", [])),
            ]
            for finding in findings
            if finding.get("target_type") in {"prompt", "resource"}
        ]
        rows.append(
            {
                "server": audit.get("server", {}).get("name"),
                "status": audit.get("connection_status"),
                "tool_risk": risk_score.get("composite", 0),
                "non_tool_risk": non_tool_risk.get("composite", 0),
                "permission_findings": len(audit.get("permissions", [])),
                "capability_findings": len(audit.get("capability_findings", [])),
                "injection_findings": len(audit.get("injection_findings", [])),
                "drift_findings": len(audit.get("drift_findings", [])),
                "non_tool_targets": non_tool_targets,
            }
        )
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: parse_report.py mcp-audit.json", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[1]).read_text())
    print(json.dumps(summarize(report), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
