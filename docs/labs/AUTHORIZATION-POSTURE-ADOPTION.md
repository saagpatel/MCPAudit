# MCP Authorization Posture Adoption

`mcp-audit authorization-posture` is an experimental offline consumer for the
portable `McpAuthorizationPostureV1` JSON contract. It lets MCPAudit accept a
saved, credential-free public-metadata posture produced by another tool without
repeating that tool's network activity or inheriting authority to contact the
MCP endpoint.

This is an advisory bridge, not an authenticated scan path. The strongest
possible disposition is `policy-review-only`.

## Commands

```bash
# Canonical advisory JSON to stdout
mcp-audit authorization-posture review posture.json

# Descriptor-bound atomic output; existing files are not replaced by default
mcp-audit authorization-posture review posture.json --json report.json

# Authoritative strict contracts
mcp-audit authorization-posture schema input
mcp-audit authorization-posture schema report
```

Exit codes are:

- `0`: the producer artifact is internally consistent and declares
  `metadata-ready`; the result is still `policy-review-only`;
- `1`: valid producer evidence remains `unknown`, so the result is `blocked`;
- `2`: the input or output operation is invalid.

## Authority flow

The consumer keeps the boundary explicit:

1. The producer declares an observation time, official-Registry manifest
   binding, public metadata results, bounded fetch evidence, capabilities, and
   claim ceiling.
2. MCPAudit validates the exact versioned shape and its cross-field
   consistency entirely offline.
3. MCPAudit emits a deterministic advisory projection bound to the input
   SHA-256.
4. An operator remains the decision authority for any later policy review.

The input has `input_provenance=unverified` and
`input_freshness=unverified`. Shape validation and an input digest do not
authenticate the producer, observation time, Registry export, remote metadata
bodies, or the current applicability of a saved posture. The report therefore
labels remote evidence `producer-asserted` and metadata state
`producer-declared-*` even when the declared posture is metadata-ready.

## Accepted producer contract

The v1 consumer accepts only:

- `schema_version=McpAuthorizationPostureV1`;
- `contract_version=1.0.0`;
- specification profile `mcp-authorization-2025-11-25` with its fixed primary
  references;
- one exact `official-mcp-registry-export` binding and manifest SHA-256;
- HTTPS-only resource, metadata, issuer, and authorization endpoint fields;
- bounded, current or unknown fetch evidence;
- a fixed GET-only, credential-free, no-proxy, no-redirect, address-pinned,
  public-address-only, no-mutation producer capability boundary;
- a fixed claim ceiling that proves no authorization, credentials, runtime
  security, or trust-grade authority.

`metadata-ready` is valid only when protected-resource metadata remains bound
to the selected Registry resource and at least one declared authorization
server has internally consistent metadata including PKCE `S256` support.
`unknown` must remain `blocked` and cannot contain an accepted metadata-ready
authorization server.

Unknown fields, type coercion, duplicate keys, non-finite JSON constants,
incompatible versions, widened capabilities, widened claims, malformed URLs,
cross-field binding drift, symlinks, excessive input, excessive nesting, and
excessive JSON nodes are rejected. Rejected values are not reflected in the
sanitized CLI error.

Authoritative checked-in schemas are:

- `examples/schemas/authorization-posture-input-v1.schema.json`;
- `examples/schemas/authorization-posture-report-v1.schema.json`.

Breaking producer changes require a new explicit consumer contract. The
consumer has no runtime dependency on the producer package, preserving the JSON
contract as the portability and vendor-exit boundary.

## Report contract

`mcpaudit.authorization-posture.report.v1` contains:

- the input schema and contract versions plus exact input SHA-256;
- the declared observation time and Registry binding;
- `disposition=policy-review-only|blocked`;
- `metadata_state=producer-declared-ready|producer-declared-unknown`;
- declared and metadata-ready authorization-server counts;
- sanitized producer reason codes;
- one stable `MCPPOSTURE001` advisory or `MCPPOSTURE000` unknown finding;
- the fixed authority flow, parser limits, supported inputs, unsupported inputs,
  and claim ceiling.

The report intentionally omits fetch records, metadata bodies, authorization
and token endpoints, and other producer detail not needed for the advisory
decision. Canonical JSON is sorted and compact with one terminal newline. It
contains no MCPAudit-generated timestamp or local input path.

## Claim ceiling

The supported claim is only:

> The supplied JSON is structurally consistent with
> `McpAuthorizationPostureV1` version `1.0.0` and has been projected
> deterministically.

The command performs no HTTP, DNS, Registry, OAuth, MCP, browser, account,
keychain, token, credential, endpoint-session, scan, grading, or mutation
operation. A metadata-ready result does not prove producer provenance,
authorization, credential availability, runtime security, adoption,
deployment, production safety, or permission to proceed beyond policy review.
