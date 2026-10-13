# Use MCPAudit in CI

Start with a config-only workflow. It avoids starting MCP servers while still
letting a local policy evaluate available configuration evidence.

```yaml
- uses: actions/checkout@v6
- uses: saagpatel/MCPAudit@v2.11.0
  with:
    skip-connect: "true"
    sarif: mcp-audit.sarif
```

The Action defaults to config-only operation and uploads SARIF when enabled.
This example names the current repository release; check the release checklist
when updating it. Use a reviewed immutable revision where your workflow
requires a fixed source. Check the Action's current inputs in
[`action.yml`](../../action.yml).

## Command grammar and release tags

The Action probes the installed command's help for the expanded `check`
capabilities, rather than dispatching by major version. Packages below 2.12
(including older 2.x packages with an earlier `check` command) retain legacy
`scan` arguments. Expanded 2.12 and newer packages, including 3.x, use `check`.
This applies to both the `version` input and an installed local `wheel`.

Under `check`, the default includes discovered configurations with no
connections. `config` selects only that file; `skip-connect: "false"` selects
`--connect-all`, unless `args` explicitly selects `--connect` or `--connect-all`.
Project connections still require `--connect-project-configs`. With the default
`skip-connect: "true"`, connection flags in `args` fail instead of overriding
the safety constraint.

The structured `clients` input accepts comma-separated names and maps them to
repeated `--client` options. The structured `json` input maps to
`--output-json`. Free-form `args` follows the selected command's grammar and
uses shell quoting to group arguments; it is never evaluated as shell code or
expanded as a glob. The Action logs the resulting translated command when
`args` is supplied. Under `check`, legacy `--json PATH` (also `--json=PATH`) is
translated to `--output-json PATH`; native `--json` alone retains stdout JSON.
Legacy `--clients NAME` maps to `--client NAME`. Comma-separated free-form
`--clients a,b` fails with exit 2 and names repeated `--client` as the
replacement; write those options explicitly. Hidden `--skip-connect` and
`--config-only` compatibility flags retain their `check` safety constraints.
Other arguments pass through to the selected CLI for validation.

Use an exact published release tag (`vMAJOR.MINOR.PATCH`) or its reviewed
immutable commit for the Action and hook. Examples stay on the latest complete
public release; candidate metadata does not advance them. For the split release
train, no tag, GitHub Release, Registry entry or Action ref advances until all
lockstep core, labs and proof wheels and sdists have been published and verified. See the
[release checklist](../../maintainers/RELEASE-CHECKLIST.md#three-distribution-release-train-groundwork-not-active-yet)
for publication and partial-publication recovery.

The package, Action and hook receive **security-only 2.x backports for 120
calendar days after 3.0.0** on `release/2.x`. The explicit end date belongs in
the 3.0.0 notes; the branch carries its own release state, checked by
`verify_release.py`. This policy does not promise feature backports. See
[2.x security maintenance](../../maintainers/RELEASE-CHECKLIST.md#release2x-security-maintenance).

## Local policy gate

Pass a repository-owned policy file through the Action's `policy` input, or run
the CLI with an explicit configuration:

```sh
mcp-audit check --config ./mcp.json --policy ./policy.yaml --sarif mcp-audit.sarif
```

Use policy thresholds that match the evidence available in CI. A failed policy
returns a nonzero status after requested artifacts are written. See the
[policy examples](../../examples/policies/README.md) and the
[output contract](../OUTPUT-CONTRACT.md).

Connected checks can execute configured local programs or contact endpoints.
Enable them only in a workflow where that reach is intended and reviewed.

For signed pins in one-shot CI, provision the public key through a trusted
channel, then require a signed manifest sequence in protected policy or with
`--pin-min-sequence`:

```sh
mcp-audit check --config ./fixture.json --config-only --skip-connect \
  --override-config /dev/null --pin-file ./pins.yaml --pin-min-sequence 12
```

An older, missing, untrusted, or sequence-less manifest fails with policy exit
status 2, including when no servers are configured. Persisting the separate
trust store retains per-server timestamp history and signing expectations;
see [pinning](pinning.md) for storage protection and migration details.
