# Registry Package Verification (`--verify-artifacts`)

`mcp-audit check --verify-artifacts` is the **network-gated** complement to the
offline integrity check (`--integrity-check`, MCP024). For package-runner launches
— `npx pkg@1.2.3`, `uvx pkg==1.4.0` — the on-disk `command` is the *runner*
(`npx`/`uvx`), not the server code. The meaningful artifact is the remote package,
so this check compares the **registry-published hash** for the exact pinned
`package@version` against the hash captured when it was pinned.

  `MCP025` (registry_drift) — the registry's published hash for a fixed version
  changed (**HIGH**: a registry must never serve different bytes for the same
  version — a republish-in-place / tampering signal), or could not be re-fetched to
  verify (**MEDIUM**: registry unreachable or version withdrawn).

## How it works

- **Capture (pin time).** `mcp-audit pin --verify-artifacts` resolves each server's
  package spec from its launch args, fetches the registry-published hash for that
  exact `package@version`, and stores it in the pin baseline (hashes only — never
  package bytes).
  - npm: `https://registry.npmjs.org/<name>/<version>` → `dist.integrity`.
  - PyPI: `https://pypi.org/pypi/<name>/<version>/json` → the sorted set of
    per-file `sha256` digests (so any distribution file changing is caught).
- **Compare (scan time).** `mcp-audit check --verify-artifacts` re-resolves the
  packages, re-fetches the published hashes, and flags any that differ from the
  baseline (HIGH) or can't be fetched (MEDIUM).

## Scope and boundaries

- **Network only when asked.** The registry is contacted **only** under
  `--verify-artifacts` (on `pin` and `check`). Every other mode stays offline-first
  — consistent with `--llm-analysis` being the only other networked path.
- **Exact version only.** The check keys by `package@version`. A version *float*
  (the config now launches a different version than pinned) is provenance's job
  (`MCP021`), not this one — so `--verify-artifacts` never double-reports a float.
- **Registry-shaped only.** Only a registry-shaped name with an exact version is
  ever sent to a registry. A PyPI requirement yields a package only when the whole
  string is one plain requirement: a name, optional extras, optional version
  specifiers (or uv's `@version`), and an optional marker of plain characters.
  Direct references (`tool @ https://host/tool.whl`), VCS and file sources, paths,
  and any `--with` list with an item that is not such a requirement resolve to no
  package, so no part of a URL, credential included, ever leaves the machine.
- **Exact means immutable.** npm needs a semver version (`pkg@1.2.3`); a dist-tag
  or range (`pkg@latest`, `pkg@^1.2.0`) is never captured or verified, so the pin
  store holds no hash that check time would skip. PyPI needs `==` without a `*`
  wildcard (`pkg==1.4.0`), or uv's `pkg@1.4.0` spelling (`pkg@latest` is not exact).
- **Ecosystems and runners.** Each runner's own option grammar decides which
  registry packages a launch installs, so option values are never mistaken for
  the package. Unrecognised runners and unparseable specs yield nothing (no
  invented references): `uv run server.py` resolves no package.
  - npm: `npx` (every `--package`/`-p`, or else the first positional; options
    end at that positional) and `npm exec`/`npm x` (every `--package`, or else
    the command; npm reads options anywhere until `--`, and its `-p` is
    `--parseable`). Other `npm` subcommands (`npm run build`) launch no registry
    package.
  - PyPI: `uvx` and `uv tool run` (`--from` or the command, plus each `--with`
    requirement), `uv run` (only its `--with` requirements: the command or script
    it runs is local), and `pipx run` (`--spec` or the first positional, plus each `--with`).
- **Implies a pin comparison.** Requires a baseline captured with
  `pin --verify-artifacts`; servers pinned without it are skipped with a warning.

## Credential safety

Only registry metadata is fetched (public package hashes); no credential value is
read or transmitted, and the baseline stores only `ecosystem:name:version → hash`.

## Usage

```bash
# Capture the approved registry hashes once.
mcp-audit pin --verify-artifacts

# Later, flag any registry-published hash drift for pinned versions.
mcp-audit check --include-discovered --verify-artifacts

# Gate CI on it (opt-in; not covered by the broad fail_on.severity shortcut).
mcp-audit check --include-discovered --verify-artifacts --output-json mcp-audit.json --policy examples/policies/package-verify-ci.yaml
```

## The over-time / supply-chain check family

| Check | Compares | Catches |
|-------|----------|---------|
| `--escalation-check` | inferred capabilities + injection patterns | a tool that *gained* a dangerous capability or injection text |
| `--provenance-check` | launch config strings (command, args, URL, cred keys) | a swapped command, floated version, new flag, changed endpoint |
| `--integrity-check` | on-disk artifact bytes | the launch command is unchanged but the local file it runs was modified |
| `--verify-artifacts` | registry-published package hash (network) | a fixed `package@version` was republished with different bytes upstream |

All are opt-in and additive; none changes `risk_score.composite`.
