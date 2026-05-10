#!/usr/bin/env python3
"""Build a dashboard-oriented MCPAudit JSON summary."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    """Return an aggregate summary suitable for CI dashboards."""
    config_health_by_server: dict[str | None, list[dict[str, Any]]] = {}
    for finding in report.get("config_health_findings", []):
        config_health_by_server.setdefault(finding.get("server_name"), []).append(finding)

    servers: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    for audit in report.get("audits", []):
        server_name = audit.get("server", {}).get("name")
        config_findings = config_health_by_server.get(server_name, [])
        risk_score = audit.get("risk_score") or {}
        non_tool_risk = audit.get("non_tool_risk") or {}
        status = audit.get("connection_status") or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1
        servers.append(
            {
                "server": server_name,
                "status": status,
                "tool_risk": risk_score.get("composite", 0),
                "non_tool_risk": non_tool_risk.get("composite", 0),
                "config_health": _count_by(config_findings, "severity"),
                "policy_failures": _policy_failures_for_server(report, server_name),
            }
        )

    policy_result = report.get("policy_result") or {}
    policy_violations = policy_result.get("violations", [])
    return {
        "servers_discovered": report.get("servers_discovered", 0),
        "servers_failed": report.get("servers_failed", 0),
        "status_counts": status_counts,
        "policy_passed": policy_result.get("passed"),
        "policy_failure_count": len(policy_violations),
        "max_tool_risk": max((server["tool_risk"] for server in servers), default=0),
        "max_non_tool_risk": max((server["non_tool_risk"] for server in servers), default=0),
        "config_health": _count_by(report.get("config_health_findings", []), "severity"),
        "attention": _attention_rows(servers),
        "servers": servers,
    }


def _policy_failures_for_server(report: dict[str, Any], server_name: str | None) -> int:
    policy_result = report.get("policy_result") or {}
    return sum(
        1 for violation in policy_result.get("violations", []) if violation.get("server_name") == server_name
    )


def _count_by(findings: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        key = str(finding.get(field, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _attention_rows(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for server in servers:
        reasons: list[str] = []
        if server["status"] not in {"connected", "skipped"}:
            reasons.append(f"connection:{server['status']}")
        if server["policy_failures"]:
            reasons.append("policy")
        if server["config_health"]:
            reasons.append("config_health")
        if server["tool_risk"] >= 7:
            reasons.append("tool_risk")
        if server["non_tool_risk"] >= 5:
            reasons.append("non_tool_risk")
        if reasons:
            rows.append(
                {
                    "server": server["server"],
                    "reasons": reasons,
                    "tool_risk": server["tool_risk"],
                    "non_tool_risk": server["non_tool_risk"],
                }
            )
    return rows


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: dashboard_summary.py mcp-audit.json", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[1]).read_text())
    print(json.dumps(summarize(report), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
