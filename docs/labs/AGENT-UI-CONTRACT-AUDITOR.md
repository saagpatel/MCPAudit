# Agent UI Contract Auditor

The Agent UI Contract Auditor is an **experimental, fixture-first MCPAudit
capability** for reviewing whether a generated or widget-backed interface
faithfully represents the authority it can invoke. It is a finite static CLI,
not a renderer, host, protocol bridge, or runtime enforcement layer.

The scanner accepts only program-owned synthetic fixtures. It never executes or
parses widget HTML or JavaScript, contacts an MCP server, calls a tool, fetches a
resource or catalog, authenticates, installs a plugin, or processes real user
data.

## Command

```bash
mcp-audit agent-ui scan tests/fixtures/agent_ui/mcpui001-authority-vulnerable.json \
  --json agent-ui-report.json \
  --html agent-ui-report.html

mcp-audit agent-ui schema mcp-apps-fixture
mcp-audit agent-ui schema a2ui-fixture-manifest
mcp-audit agent-ui schema a2ui-message
mcp-audit agent-ui schema report
```

`--json` writes the canonical machine-readable report. `--html` writes an inert,
offline projection with `default-src 'none'`; it contains no script or active
link. Existing output files are not replaced unless `--force` is explicit.
Output targets are preflighted as one set, must be distinct from each other and
from the input fixture, and are staged in descriptor-bound parent directories.
Without `--force`, commit uses atomic create-if-absent semantics and rolls back
its own already-created sibling artifact if a later target appears after
preflight. With `--force`, replacement remains explicit and occurs relative to
the already-opened parent directory.

Exit codes:

- `0`: every supported check passed and no ambiguity remained.
- `1`: one or more contract findings fired, or an unsupported/ambiguous
  construct left the verdict `unknown`.
- `2`: the input or output artifact could not be safely read or written.

## Supported MCP Apps / OpenAI metadata fixture

The JSON input contract is
`mcpaudit.agent-ui.mcp-apps-fixture.v1`. `program_owned` must be `true`.
The supported standard MCP Apps fields are:

- tool `_meta.ui.resourceUri`;
- tool `_meta.ui.visibility`;
- resource `_meta.ui.csp.connectDomains`, `resourceDomains`, and
  `frameDomains`;
- resource MIME type `text/html;profile=mcp-app`.

For the `openai-chatgpt` host profile, the scanner additionally understands the
OpenAI-specific compatibility/extension fields:

- `openai/outputTemplate`;
- `openai/widgetAccessible`;
- `openai/visibility`;
- `openai/widgetCSP`, including `connect_domains` and `redirect_domains`;
- `openai/widgetDescription` and `openai/widgetDomain`.

The `generic-mcp-apps` profile does not consume those OpenAI-specific fields.
A rendered tool call must be available to the app through standard
`_meta.ui.visibility`; the OpenAI host profile also requires
`openai/widgetAccessible: true`. Missing, conflicting, or cross-profile
bindings are `UNKNOWN`. When both standard and OpenAI compatibility fields are
present, resource URIs must match; `openai/visibility` must agree with standard
model visibility; widget domains must normalize to the same HTTPS origin; and
the standard/OpenAI connect, resource, and frame origin sets must agree.
`redirect_domains` remains OpenAI-specific. Every supported domain, CSP,
redirect, external-link, and data-sink value must contain a syntactically valid,
credential-free HTTPS authority; malformed authorities are `UNKNOWN` even when
the same malformed string is repeated in every declaration.

The program-owned `audit_contract` and `rendered_controls` sidecars provide the
expected tool authority and the UI presentation to compare. They are not MCP
wire fields and must not be presented as host interoperability.

This profile follows the current separation documented by
[MCP Apps](https://github.com/modelcontextprotocol/ext-apps/blob/main/docs/overview.md)
and the
[OpenAI plugin metadata reference](https://developers.openai.com/plugins/reference).
The scanner does not test whether a host actually fetches, sandboxes, renders,
or enforces any declared resource.

## Supported A2UI JSONL fixture

An A2UI fixture is JSONL with:

1. one program-owned manifest envelope using
   `mcpaudit.agent-ui.a2ui-fixture.v1`; then
2. A2UI v0.9 `createSurface`, `updateComponents`, `updateDataModel`, and
   `deleteSurface` messages.

The manifest line is a test sidecar, **not an A2UI wire message**. The remaining
lines follow the v0.9 envelope shape and must use the fixed synthetic catalog
identifier:

```text
urn:mcpaudit:agent-ui-audit:catalog:v1
```

The catalog supports only `Column`, `Text`, `Button`, `StatusBadge`, and
`ExternalLink` components with the strict nested shapes defined by the emitted
`a2ui-message` schema. Component IDs must be unique within one update, JSON
Pointers accept only `~0` and `~1` escapes, and generic JSON nesting is bounded.
It exists solely for MCPAudit fixtures. The scanner applies file ordering,
surface lifecycle, root reachability, JSON Pointer data updates, and static
bindings. Approval and status bindings resolve provenance from the exact JSON
Pointer or its nearest declared ancestor. Missing or explicit-unknown
provenance is `UNKNOWN`; untrusted approval bindings fire `MCPUI004`, while an
untrusted passing status presentation fires `MCPUI005`. Bound evidence and
visual states must resolve to the finite supported enums, so an out-of-domain
string cannot become `pass`. Supported contradictions observed in an
established surface remain findings if a later update replaces the component
or deletes the surface; a fixture with no analyzable A2UI messages is
`UNKNOWN`. The scanner does not fetch a catalog or test a renderer.

The supported envelope is aligned to the
[A2UI v0.9 stable protocol family](https://a2ui.org/specification/v0.9-a2ui/),
where surface creation precedes updates and protocol metadata remains
transport-specific. A2UI v0.8, v1.0, other catalogs, inline catalogs,
client-to-server messages, and transport metadata are unsupported and produce
`UNKNOWN`.

## Stable rules

| Rule | Severity | Contract contradiction |
| --- | --- | --- |
| `MCPUI000` | unknown | Unsupported or ambiguous protocol, host, catalog, binding, or fixture construct |
| `MCPUI001` | high | Rendered authority is smaller than the invoked tool/action authority |
| `MCPUI002` | high | Approval state contradicts the required/current contract, or evidence/version is stale |
| `MCPUI003` | high | A tool/action invocation is hidden or not disclosed to the user |
| `MCPUI004` | high | Untrusted tool output controls approval label, version, evidence, enabled state, or checks |
| `MCPUI005` | high | Unknown or unverifiable evidence is rendered as pass/green/safe |
| `MCPUI006` | high | An external link or data sink is absent from the program and host-specific declarations |

Every finding includes the stable rule ID, severity, target, deterministic
evidence, remediation, protocol, host profile, and the assumptions that make
the finding meaningful.

## Fixture controls

`tests/fixtures/agent_ui/` contains 18 fixtures:

- six positive controls showing the expected safe contract;
- six matched vulnerable controls, one for each `MCPUI001`–`MCPUI006`;
- six near-miss negative controls proving the detector does not fire on a
  non-applicable lookalike.

The first, third, and sixth families exercise MCP Apps/OpenAI metadata. The
second, fourth, and fifth exercise A2UI v0.9 JSONL. Tests also cover alias
conflicts, unsupported versions/components, unreachable components, duplicate
JSON keys, component IDs and nested shapes, lifecycle deletion/replacement,
untrusted approval labels, host-access conflicts, JSON Pointer and nesting
bounds, exact/ancestor/missing provenance, finite evidence-state values,
standard/OpenAI metadata reconciliation, strict HTTPS authorities,
descriptor-bound bounded reads, atomic no-clobber output commit, safe output
identity, symlink rejection, deterministic JSON/HTML, schema strictness, and
the no-network/no-process-execution boundary.

## Unsupported inputs

The auditor does not support:

- widget HTML, JavaScript, CSS, binaries, or remote resource content;
- real MCP configs, servers, tools, credentials, authentication, user data,
  logs, or transcripts;
- A2UI protocols or catalogs outside the exact profile above;
- AG-UI streams or state events;
- WebMCP browser APIs or tool-registration behavior;
- translation between A2UI, MCP Apps, OpenAI extensions, AG-UI, or WebMCP;
- claims about host consent UI, sandboxing, CSP enforcement, transport
  ordering, authorization, or runtime effects.

Unsupported, ambiguous, malformed-but-parseable, or unbound constructs are
`MCPUI000` / `UNKNOWN`, never safe.

## Claim ceiling

A passing report means only that the supported program-owned fixture contains
no contradiction covered by `MCPUI001`–`MCPUI006` and no known ambiguity.
It does **not** prove that:

- widget code matches the fixture;
- a host enforces declared CSP, visibility, confirmation, or sandbox behavior;
- an MCP server implements the declared tool authority;
- an A2UI renderer resolves state or dispatches actions as modeled;
- a transport preserves order, identity, or metadata;
- any real plugin, user workflow, or data path is safe.

Real-host testing, connected MCP inspection, plugin installation, and user-data
processing remain outside this experimental capability.

## Recommendation

Keep this as an experimental MCPAudit feature. Its detector, finding, fixture,
output, and claim-ceiling contracts belong with MCPAudit's existing static
assurance workflow. Do not promote it to a public workshop artifact until a
separately reviewed, public-safe fixture corpus and facilitator-facing exercises
exist; the current corpus proves scanner semantics, not workshop usefulness or
host behavior.
