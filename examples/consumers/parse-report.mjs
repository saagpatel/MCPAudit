#!/usr/bin/env node
import { readFileSync } from "node:fs";

function summarize(report) {
  const configHealthByServer = new Map();
  for (const finding of report.config_health_findings ?? []) {
    const serverName = finding.server_name ?? null;
    configHealthByServer.set(serverName, [...(configHealthByServer.get(serverName) ?? []), finding]);
  }

  return (report.audits ?? []).map((audit) => {
    const serverName = audit.server?.name ?? null;
    const configHealthFindings = configHealthByServer.get(serverName) ?? [];
    const riskScore = audit.risk_score ?? {};
    const nonToolRisk = audit.non_tool_risk ?? {};
    const configHealthBySeverity = {};
    for (const finding of configHealthFindings) {
      const severity = finding.severity ?? "unknown";
      configHealthBySeverity[severity] = (configHealthBySeverity[severity] ?? 0) + 1;
    }
    const nonToolTargets = [
      ...(audit.capability_findings ?? []).map((finding) => ({ ...finding, kind: "capability" })),
      ...(audit.injection_findings ?? []).map((finding) => ({ ...finding, kind: "injection" })),
    ]
      .filter((finding) => finding.target_type === "prompt" || finding.target_type === "resource")
      .map((finding) => ({
        target_type: finding.target_type,
        target_name: finding.target_name,
        kind: finding.kind,
      }));
    return {
      server: serverName,
      status: audit.connection_status ?? null,
      tool_risk: riskScore.composite ?? 0,
      non_tool_risk: nonToolRisk.composite ?? 0,
      config_health_findings: configHealthFindings.length,
      config_health_by_severity: configHealthBySeverity,
      config_health_types: configHealthFindings.map((finding) => finding.finding_type),
      permission_findings: (audit.permissions ?? []).length,
      capability_findings: (audit.capability_findings ?? []).length,
      injection_findings: (audit.injection_findings ?? []).length,
      drift_findings: (audit.drift_findings ?? []).length,
      non_tool_targets: nonToolTargets,
    };
  });
}

function main(argv) {
  if (argv.length !== 3) {
    console.error("usage: parse-report.mjs mcp-audit.json");
    return 2;
  }

  const report = JSON.parse(readFileSync(argv[2], "utf8"));
  console.log(JSON.stringify(summarize(report), null, 2));
  return 0;
}

process.exitCode = main(process.argv);
