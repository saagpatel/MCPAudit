# Trust Before Connect

`mcp-audit trust` checks an MCP server **before** you install it. Everything
else in MCPAudit reviews servers you already have configured. This command
starts from a name, looks up what the server claims to be, runs it in a
throwaway container, and writes a verdict card comparing what it claims with
what it did.

```sh
mcp-audit trust io.github.owner/server          # official MCP Registry name
mcp-audit trust npm:@scope/package@1.2.3        # npm package
mcp-audit trust pypi:package==0.4.1             # PyPI project
mcp-audit trust https://mcp.example.com/mcp     # remote server (outside view only)
```

It never discovers, reads or edits your MCP client configuration. The only
inputs are the target you name and public registry metadata.

## What it does

1. **Resolve.** It fetches the server's `server.json` from the official MCP
   Registry, or package metadata from npm or PyPI, and runs these checks:
   - Is the server listed, and is its registry status `active`?
   - Does `server.json` have the expected shape?
   - For `io.github.<owner>/…` names, does the repository belong to `<owner>`?
     For reverse-DNS names, are remote hosts under that domain?
   - Does the package point back at the same registry name? npm uses
     `mcpName` in package.json; PyPI uses `mcp-name:` in the project
     description. A package that names a registry entry that does not list it
     is reported.
   - Does the package declare npm install scripts?
2. **Install.** The exact version is installed into a fresh container from a
   stock `node:24-slim` or `python:3.13-slim` image. npm install scripts and
   PyPI source builds are disabled unless you pass `--allow-install-scripts`.
   Installed metadata is read with the base interpreter in isolated mode, so a
   wheel's `.pth` startup hooks never run during install. The install
   container has unrestricted network access (it fetches the package) and is
   the only step that does. With `--allow-install-scripts`, untrusted install
   code runs there with that access.
3. **Run.** The server runs in a second container:
   - no host mounts, no credentials, no host environment
   - all Linux capabilities dropped, `no-new-privileges`, and a non-root user
     (`10001`)
   - memory, CPU and process limits
   - its home directory is `/scratch` inside the container

   Declared environment variables that are required get inert placeholder
   values. Optional ones stay unset.
4. **Talk MCP.** The client negotiates protocol `2026-07-28` and falls back to
   the `2025-11-25` handshake. It lists tools, prompts and resources, then
   calls only tools that declare `readOnlyHint: true` and pass the same
   keyword and injection vetoes the connected canary uses. Calls use
   synthetic inputs, and only required fields are filled. `--safe-tool NAME`
   adds a tool to the list. Results are not stored.
5. **Record.** After startup, after each call and after shutdown it records:
   - **File writes**, from `docker diff` against the freshly installed image.
   - **Network attempts**, from a sinkhole that owns the server's network
     namespace. There is no route out. DNS queries are answered with
     placeholder addresses, and every TCP connection and UDP datagram is
     redirected to a local recorder. That recorder notes the host, port, TLS
     SNI and HTTP `Host`, never paths, headers or bodies, then closes the
     connection. Nothing the server sends leaves the sandbox.
6. **Judge.** It writes a verdict card and a pin of the tool surface.

A remote URL taken from registry metadata is only contacted through
connections that are resolved and vetted as public at connect time, so DNS
rebinding cannot redirect them to a private address; a URL you pass yourself
is used as given. Templated
remote URLs (`https://{region}.example.com/mcp`) are skipped with a note.

Remote servers can only be observed from outside. Their surface is listed
over Streamable HTTP, but their tools are never called, and their file writes
and outbound connections happen on infrastructure MCPAudit cannot see. Their
cards say so.

## Requirements

You need a Docker-compatible runtime with Linux containers, such as Docker
Desktop, colima or OrbStack. MCPAudit uses the `docker` CLI and respects
`DOCKER_CONTEXT` and `DOCKER_HOST`. Use `--runtime` for another compatible
CLI. If no runtime is reachable, nothing is installed or started and the
command exits with code 3.

## Verdicts and exit codes

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `no_mismatches_observed` | 0 | Nothing it did contradicted what it claims. This is evidence, not a guarantee. |
| `review` | 1 | At least one medium mismatch, such as network use at startup or writes outside its home directory. |
| `do_not_install` | 1 | At least one high mismatch, such as a read-only tool writing files, an ownership check failing, or injection text. |
| `incomplete` | 3 | The server could not be observed, or observation stopped early. |

## Mismatch rules

| Rule | Severity | Raised when |
| --- | --- | --- |
| `TBC-RESOLVE` | high / medium / low | A resolver check failed (high) or warned (medium for namespace and listing checks, low otherwise). |
| `TBC-READONLY-WRITE` | high | Files changed during a call to a tool declared read-only. |
| `TBC-READONLY-NET` | high / low | A read-only tool reached the network: high if it declared `openWorldHint: false`, low otherwise. |
| `TBC-INJECTION` | high | Tool text matches prompt-injection patterns. |
| `TBC-UNPROMPTED-NET` | medium | Network attempts at startup or shutdown, before or after any tool call. |
| `TBC-WRITE-OUTSIDE-HOME` | medium | Writes outside `/scratch` outside a read-only call. |
| `TBC-LOCAL-CLAIM-NET` | medium | Its description reads as local or offline, but network attempts were seen. |
| `TBC-DRIFT` | medium / low | The tool surface differs from the pin passed with `--pin`. |
| `TBC-TRANSIENT-WRITE` | low | A read-only tool created and removed temporary entries (such as lock files) in a directory during its call. |
| `TBC-INSTALL-SCRIPTS` | low | npm install scripts are declared. They were not run, so their effects are unobserved. |
| `TBC-STARTUP-WRITE` | info | Files created in its home directory at startup. |

## Output

By default the files go to `./mcp-audit-trust/<server>/`. Use `--out DIR` to
choose another directory.

- `card.json`: the full card (`schema: mcp-audit.trust-card/1`). `--json`
  also prints it to stdout.
- `card.html`: a small self-contained page with the same content. All
  server-provided text is escaped.
- `pin.json`: tool names, redacted descriptions, and SHA-256 hashes of each
  description, input schema and annotation set (`schema:
  mcp-audit.trust-pin/1`).

The card ends with suggested lines to paste yourself after review:

- a pinned launch entry with the exact version
- Claude Code tool permissions: `allow` only for read-only tools whose call
  completed successfully with no observed effects in a complete run, `deny` for declared-destructive, injection-matching or
  high-mismatch tools, and `ask` for the rest
- the egress hosts that were attempted
- the paths that were written

## Detecting drift later

Keep the `pin.json`. Rerun with the earlier pin to see tools that were added,
removed, or changed (description, schema or annotations):

```sh
mcp-audit trust io.github.owner/server --pin ./mcp-audit-trust/server/pin.json
```

## Limits

- File reads are not recorded. Writes to tmpfs mounts such as `/dev/shm` are
  not visible.
- Only tools declared read-only (plus any `--safe-tool`) are called. Every
  other tool's behaviour is unobserved.
- Effects are attributed to the phase in which they appeared. Background
  activity can land in a neighbouring phase.
- A file already changed in an earlier phase is reported again when its size
  or modification time moves while the server runs. A rewrite that keeps
  both, or one during shutdown, is not seen.
- If write or network recording fails, the run is reported as incomplete
  rather than clean.
- One short session is observed. Delayed or conditional behaviour may not
  trigger.
- Non-DNS UDP is counted without its destination. If the runtime has no IPv6
  NAT support, IPv6 attempts are blocked but not recorded.
- OCI packages and non-stdio package transports are not run in this
  milestone.

## Cleanup

Each run removes its containers and its run image, including after Ctrl-C.
The base images and the small sinkhole image stay cached. Everything the
command creates carries the label `io.mcp-audit.trust=1`, so leftovers from
a killed process can be found with:

```sh
docker ps -a --filter label=io.mcp-audit.trust=1
```

## Live test lane

The default test suite uses synthetic fixtures only. With a runtime available,
`MCP_AUDIT_TRUST_DOCKER=1 uv run pytest tests/test_trust.py -k live` builds
the sinkhole image and checks that it records and blocks egress. It never
installs a third-party package.
