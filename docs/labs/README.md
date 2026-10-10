# Experimental labs

These tools explore bounded, synthetic, or experimental evidence contracts.
Their results do not establish production behavior or general ecosystem
coverage. The main MCPAudit workflow is described in [Start here](../start-here.md).

Use `mcp-audit lab <topic> --help` to explore the offline labs below. The previous
top-level topic names remain hidden aliases through 2.x. `mcp-audit --help-all`
lists all command paths, including aliases; shell completion includes them too.
SafeForge uses `mcp-audit safeforge preinstall|run`, local skill review uses
`mcp-audit skills scan`, and pin management uses `mcp-audit baseline pin` with
the existing pin options. `monitor` is hidden and deprecated for removal in 3.0.
The PostgreSQL exemplar lives in the repository's `research/` directory and is
not included in the installed wheel.

- [Agent UI contract auditor](AGENT-UI-CONTRACT-AUDITOR.md)
- [Authorization posture adoption](AUTHORIZATION-POSTURE-ADOPTION.md)
- [Cache contract auditor](CACHE-CONTRACT-AUDITOR.md)
- [Evidence enforcement fixture](EVIDENCE-ENFORCEMENT-AGT-FIXTURE.md)
- [Evidence enforcement threat model](EVIDENCE-ENFORCEMENT-THREAT-MODEL.md)
- [OAuth transcript auditor](OAUTH-TRANSCRIPT-AUDITOR.md)
- [Proof Before Action](PROOF-BEFORE-ACTION.md)
- [Proof Before Action threat model](PROOF-BEFORE-ACTION-THREAT-MODEL.md)
- [ProofOS PostgreSQL threat model](PROOFOS-POSTGRES-THREAT-MODEL.md)
- [Result parcel lab](RESULT-PARCEL-LAB.md)
- [SafeForge runtime threat model](SAFEFORGE-RUNTIME-THREAT-MODEL.md)
- [Session resume fault lab](SESSION-RESUME-FAULT-LAB.md)
- [MCP Task Time Machine](MCP-TASK-TIME-MACHINE.md)
