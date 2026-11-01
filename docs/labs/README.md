# Experimental labs

These tools explore bounded, synthetic, or experimental evidence contracts.
Their results do not establish production behavior or general ecosystem
coverage. The main MCPAudit workflow is described in [Start here](../start-here.md).

Use `mcp-audit lab <topic> --help` to explore the offline labs below. Lab topics
are available only as `mcp-audit lab <topic>`; the former top-level topic names
were removed in 3.0.
SafeForge uses `mcp-audit safeforge preinstall|run`, local skill review uses
`mcp-audit skills scan`, and pin management uses `mcp-audit baseline pin` with
the existing pin options.
The PostgreSQL exemplar lives in the repository's `research/` directory and is
not included in the installed wheel.

## Negative conformance probes (explicit opt-in)

Unlike the offline topics, `mcp-audit lab --conformance-probe --url URL`
contacts exactly the supplied MCP HTTP endpoint. It never discovers configs,
sends credentials, follows redirects, retains cookies, or calls tools. Use it
only against an endpoint you intend to test with deliberately invalid requests.
Ordinary `lab`, `check`, and `scan` do not run these negative probes.

For a disposable local fixture endpoint:

```sh
mcp-audit lab --conformance-probe --url http://127.0.0.1:8765/mcp
```

There are at most five POSTs, with a default three-second deadline per request
(`--timeout` accepts 0.1–30 seconds) and a 64 KiB response-body limit:

- A valid `server/discover` control establishes MCP `2026-07-28` support for T7.
- T7 mismatches `MCP-Protocol-Version` and `Mcp-Method` separately on discovery
  requests, then mismatches `Mcp-Name` on a `resources/read` request for a fixed
  synthetic URN. Each expects HTTP 400 and JSON-RPC error `-32020`.
- T9 sends an otherwise valid discovery request with
  `Origin: https://mcpaudit-conformance.invalid`, expecting HTTP 403. It runs
  only for `localhost` or literal loopback addresses, with DNS pinned to
  loopback. T9 does not require modern-protocol support; a control rejected
  with 403 or an unavailable control leaves Origin validation unknown.

The JSON report marks expected rejections `pass` and accepted negative requests
`fail`. Authentication, redirects, unavailable requests, other unexpected
rejections, and incomplete T7 error envelopes are `unknown`.
T9 is `not_run` for other hosts.
Only status and numeric error codes are retained; no endpoint, response body,
headers, session IDs, or error messages are emitted. Exit 0 means a report was
generated, including unknown/fail observations; invalid usage exits 2.
Results describe these requests only. They do not certify general conformance,
security, localhost binding, or credentialed behavior. Header requirements use
the repository's MCP `2026-07-28` profile (SEP-2243).

## Offline topics

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
