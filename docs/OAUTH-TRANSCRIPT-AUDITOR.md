# MCP OAuth Discovery and Audience Transcript Auditor

`mcp-audit oauth-transcript` is an experimental, offline analyzer for
explicitly synthetic and redacted MCP/OAuth HTTP transcript fixtures. It
evaluates observable discovery, issuer, resource, audience, registration,
credential, and scope bindings. It never contacts an MCP server,
authorization server, identity provider, browser, DNS resolver, keychain, or
credential store.

## Specification profile

The v1 contract is pinned to
`mcp-authorization-2025-11-25+draft-2026-07-28`:

- [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  supplies the published discovery, resource-indicator, token-audience, client
  registration, and scope requirements.
- The [current MCP Authorization draft](https://modelcontextprotocol.io/specification/draft/basic/authorization),
  retrieved 2026-07-28, supplies authorization-response `iss` validation.
  Its [discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery)
  and [client registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration)
  pages supply issuer-bound credential and `application_type` requirements.
- Relevant primary standards are
  [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728),
  [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414),
  [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707),
  [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207),
  [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591), and
  [OpenID Connect Dynamic Client Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html).

The draft retrieval date is part of the profile because draft text can change.
New normative behavior requires a new explicit profile; it is not silently
folded into v1.

## Requirement classification

| Surface | Classification in v1 |
|---|---|
| Protected-resource metadata and authorization-server discovery validation | required |
| RFC 8707 `resource` in authorization and token requests | required by MCP |
| Server-side token audience validation | required by MCP; only supplied synthetic evidence is checked |
| Present `iss` comparison, and required `iss` when metadata advertises support | required |
| Issuer binding for persisted pre-registered, DCR, and user-supplied credentials | required in the pinned MCP draft |
| Pre-registration / CIMD / DCR / manual selection priority | recommended |
| Dynamic Client Registration | deprecated in the pinned draft, but still allowed as a supported fallback |
| DCR `application_type` appropriate to native/web client kind | required by the pinned MCP draft |
| Challenge-first least-privilege scope selection | recommended; silent drops and cross-resource attribution are violations |
| Registered, received, and redemption-time redirect URI binding | required; native loopback registration permits only the RFC 8252 port exception |
| Token signatures, PKCE correctness, IdP integrity, consent, and production authorization | unsupported |
| Authorization-server mappings from resource indicators to abstract/general audiences | unsupported; mark the audience evidence `unverifiable` |

Dynamic Client Registration is therefore not rejected universally. A valid DCR
fallback produces a low-severity `deprecated` advisory and a passing verdict.
An unsupported DCR endpoint or incompatible `application_type` is a violation.
Non-DCR method-priority advisories remain `recommended`, not `deprecated`.

RFC 8707 permits an authorization server to downscope a token and requires the
effective scope to be returned when it differs. The v1 analyzer intentionally
uses a stricter, `recommended` flow invariant: a clean report preserves the
challenged scope set through the recorded token request and response. A
token-stage reduction is therefore a fixture-policy violation, not a claim that
OAuth universally forbids downscoping.

## Commands

```bash
# Canonical JSON to stdout
uv run mcp-audit oauth-transcript scan \
  tests/fixtures/oauth_transcript/mcpoauth001-negative.json

# Atomic no-clobber JSON and SARIF artifacts
uv run mcp-audit oauth-transcript scan fixture.json \
  --json report.json \
  --sarif report.sarif

# Authoritative strict contracts
uv run mcp-audit oauth-transcript schema fixture
uv run mcp-audit oauth-transcript schema report
```

Exit codes are:

- `0`: supported checks pass; advisory findings may be present;
- `1`: at least one violation or `UNKNOWN` remains;
- `2`: the input or requested output operation is invalid.

## Fixture contract

`mcpaudit.oauth-transcript.fixture.v1` is a strict normalized transcript rather
than an arbitrary HTTP log. It records only fields needed by the supported
rules:

- the intended MCP resource and selected authorization server;
- ordered 401 challenge, protected-resource metadata, authorization-server
  metadata, authorization request/response, token request/response, and
  protected-resource-use observations;
- registered redirect URIs plus normalized authorization-request,
  authorization-response, and optional redemption-time redirect evidence;
- the selected registration method and redacted issuer-bound credential record;
- supplied synthetic audience evidence and prior-scope context.

Secret-bearing fields accept only `<redacted>` markers. Client identifiers use
`SYNTHETIC_CLIENT_ID` or a reserved `.example` HTTPS URL. Non-loopback URLs must
use reserved `.example` hosts; redirect URIs may use HTTP only on loopback.
Current audience evidence uses exact resource-URI audience values. RFC 8707
authorization-server mappings to a general or abstract audience are not
inferred; fixtures that depend on such a mapping must set audience evidence to
`unverifiable`, which yields `UNKNOWN`.
Unknown fields, duplicate keys, fragments, URL user information, credential-like
values, symlink inputs, malformed authorities, excessive nesting, or excessive
traversal are rejected without echoing the input value or retaining the source
parse/validation error in the sanitized public exception chain.

Parser limits are part of every report:

- 1 MiB input;
- 32 JSON levels;
- 64 observations;
- 8 metadata documents;
- 5 recorded redirect hops;
- 2,048 characters per URL.

The analyzer never follows a redirect or fetches a URL found in a fixture.

## Stable rules

| ID | Surface | Material outcome |
|---|---|---|
| `MCPOAUTH000` | missing, malformed, redacted, unsupported, or unverifiable binding evidence | `UNKNOWN` |
| `MCPOAUTH001` | 401 → protected-resource metadata → authorization-server metadata chain | violation |
| `MCPOAUTH002` | authorization/token resource indicators and supplied token audience evidence | violation |
| `MCPOAUTH003` | exact authorization-response issuer binding before code redemption | violation |
| `MCPOAUTH004` | issuer-bound persisted client credential reuse | violation |
| `MCPOAUTH005` | registration selection and `application_type` compatibility | violation or deprecated advisory |
| `MCPOAUTH006` | challenged/requested/returned scope binding | violation |
| `MCPOAUTH007` | registration/request/response/redemption redirect URI binding | violation |

Findings contain a stable ID, severity, outcome, requirement level, title,
semantic target, redacted evidence summary, remediation, primary references,
and assumptions. They never include raw codes, tokens, secrets, cookies,
authorization headers, arbitrary bodies, query values, or input URLs.

## Verdicts and SARIF

Canonical JSON is sorted, compact, deterministic, and terminated by one
newline. It contains no timestamp or input path:

- `pass`: no violation or unknown finding; advisories may remain;
- `fail`: at least one `violation`;
- `unknown`: no violation, but binding evidence is incomplete or unverifiable.

`--sarif` is an optional SARIF 2.1.0 projection using the established
`mcp-audit` driver and the same stable rule IDs. It adds no source location,
fixture path, or extra evidence. JSON remains the authoritative report.

## Fixture corpus

`tests/fixtures/oauth_transcript/` contains vulnerable, negative, and near-miss
triplets for `MCPOAUTH000` through `MCPOAUTH007`. Each negative control clears
its vulnerable twin by changing one semantic binding. The corpus includes:

- stale discovery and wrong-resource metadata;
- incorrect authorization/token resource indicators and accepted wrong-audience evidence;
- valid multi-resource authorization with a token-request subset;
- issuer mix-up and allowed absent `iss` when support is not advertised;
- changed-issuer credential reuse and portable CIMD behavior;
- invalid DCR `application_type` and a safe deprecated DCR fallback;
- scope widening, authoritative challenge scopes, and reauthorization scope
  preservation;
- redemption redirect mismatch and the native-loopback registration port
  exception;
- malformed metadata, missing audience evidence, wrong-audience rejection, and
  credential-looking input rejection.

## Claim ceiling

The supported claim is only:

> The supplied synthetic transcript satisfies or violates the implemented
> observable MCP/OAuth binding invariants.

Audience evidence is accepted as a synthetic observation. The auditor does not
validate token signatures or introspection authenticity. It does not prove
PKCE correctness, client authentication strength, identity-provider compromise
resistance, user consent, live authorization, or production security.
