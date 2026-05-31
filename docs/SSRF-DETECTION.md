# SSRF Detection

`mcp-audit scan --ssrf-check` flags MCP tools and resources whose interface lets
a caller steer where the **server** makes an outbound request — the classic
server-side request forgery (SSRF) primitive that can reach internal services,
link-local addresses, or cloud metadata endpoints.

This check is **static and schema-derived**. It never issues a network request,
never connects to a flagged target, and never reads a credential value. A finding
describes an *interface shape*, not a proven exploit: it tells you "this tool
accepts a caller-controllable fetch target and you should confirm the server
validates it," not "this server is vulnerable."

Like prompt-injection findings, SSRF findings are **additive and opt-in**. They do
not change `risk_score.composite`, they only appear when `--ssrf-check` is passed,
and they are gated in policy only through the dedicated `fail_on.ssrf` key.

## What it flags

SSRF detection reasons over two surfaces.

### Tools (from `input_schema` + name/description)

A parameter is treated as a **URL-shaped** input when its name contains a URL
token (`url`, `uri`, `endpoint`, `webhook`, `callback`, `href`) or its JSON Schema
`format` is a URL format (`uri`, `url`, `iri`, `uri-reference`, `uri-template`).
A parameter is treated as a weaker **host/address** input when its name contains a
host token (`host`, `hostname`, `domain`, `ip`, `proxy`, `upstream`).

A **fetch verb** is detected when the tool name or description contains a
server-side request root such as `fetch`, `http`, `curl`, `wget`, `download`,
`proxy`, `crawl`, `scrape`, `ping`, `probe`, `resolve`, `request`, `retrieve`,
or `visit`.

At most one finding is emitted per tool, at the highest applicable severity:

| Severity | Pattern | Condition |
|----------|---------|-----------|
| high | `url_param_with_fetch_verb` | URL-shaped param **and** a fetch verb |
| medium | `url_param` | URL-shaped param, no fetch verb |
| medium | `host_param_with_fetch_verb` | host/address param **and** a fetch verb |
| low | `host_param` | host/address param only |

### Resources (from the resource URI)

A remote-scheme URI (`http`, `https`, `ws`, `wss`) that contains an RFC-6570-style
template variable (`{...}`) is flagged:

| Severity | Pattern | Condition |
|----------|---------|-----------|
| high | `remote_uri_host_template` | the template variable sits in the host authority (`https://{host}/...`) |
| low | `remote_uri_path_template` | the template variable is path-only on a fixed remote host (`https://api.example.com/{path}`) |

Fixed remote URIs, local schemes (`file:`), and template variables on local
schemes are not flagged.

## What it deliberately does not flag

To stay low-noise, the check does **not** flag a tool merely because it touches the
network. A search tool, a "create repository" tool, or a "fetch latest news" tool
with no caller-controllable target produces no SSRF finding even though it has
network capability — that signal already lives in the `network` permission
(`MCP003`). SSRF is specifically the *caller-steers-the-destination* shape.

## Output

- **Rule IDs:** `MCP011` (high) and `MCP012` (medium/low), stable in SARIF.
- **Terminal:** an "SSRF Warnings" section listing server, target, type, severity,
  pattern, evidence, and suggested action.
- **JSON:** each `ServerAudit` carries an additive `ssrf_findings` list. Each
  finding has `target_type`, `target_name`, `severity`, `pattern_name`,
  `evidence`, `description`, plus computed `rule_id`, `title`, and `remediation`.
- **SARIF:** `MCP011`/`MCP012` results with `level` `error`/`warning`/`note` by
  severity, and the same stable-fingerprint scheme used by other findings.

## Policy gating

SSRF is opt-in in policy. The broad `fail_on.severity` shortcut does **not** gate
SSRF, so existing policy files keep their behavior. To enforce it, add the
dedicated key (globally or per server):

```yaml
fail_on:
  ssrf: high   # fail the scan on any high-severity SSRF finding

servers:
  webproxy:
    fail_on:
      ssrf: medium
```

## Example

```bash
# Flag SSRF-prone tools/resources, write JSON + SARIF, gate in CI
mcp-audit scan --ssrf-check --json audit.json --sarif audit.sarif --policy policy.yaml
```
