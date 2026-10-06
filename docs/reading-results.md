# Reading results

Read each finding as evidence about a configured server or inspected schema,
not as a verdict that the server is malicious. Higher risk indicates a broader
declared or observed capability surface and helps prioritize review.

## What the report tells you

- **Risk score:** a prioritization signal derived from classified capability
  findings. It is not a probability of compromise.
- **Findings:** detector-specific observations with rule IDs, severity,
  evidence, and a suggested action where available.
- **Warnings:** checks that were skipped, unavailable, or degraded. An empty
  finding list is only meaningful alongside the warnings and scan mode.
- **Config health:** malformed, conflicting, or risky launch configuration
  observations; this is separate from tool-schema inspection.
- **Drift:** differences against a saved pin baseline, when one exists.

## Limits

Config-only mode reasons from the supplied configuration. It does not start
servers or inspect live schemas. Connected mode observes the schemas returned
during that run; it does not establish future runtime behavior or package
integrity. Package verification and downloads are separate opt-in operations.

JSON is the structured report, SARIF is intended for code-scanning consumers,
and HTML is a shareable rendering. See the [output contract](OUTPUT-CONTRACT.md)
for field meanings, schema compatibility, and exit behavior.
