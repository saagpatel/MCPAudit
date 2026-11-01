# Known issues

- Reports use structural credential redaction, with pattern matching as a
  fallback for free text. Arbitrary unlabeled secrets may remain unrecognized;
  review field reports before sharing. Redacted tool schemas are display
  evidence and must not be used as replacement execution schemas.
- Terminal control stripping still treats ESC ESC as one escape rather than
  abandoning the first and restarting at the second. Restart semantics would
  add redaction withholding for benign long OSC payloads, so the current
  behavior is retained. For example, `mode=fast` or `--verbose` followed by
  ESC ESC `]`, 65 `a` characters, and BEL is currently retained by redaction;
  restart semantics would withhold the whole field and the next argv element.
  Argv redaction also reads each element as a terminal would (restarting at
  the second ESC) for detection only, so a secret label and inline delimiter
  exposed by that reading withhold the element without changing displayed
  text. Free-text fields (descriptions, schema text) do not yet add the
  restart reading: a label separated from its delimiter only by a restarted
  sequence, such as `token ESC ESC ]x BEL: value`, can keep its value there.
  A restarted sequence whose payload exceeds 64 printable bytes is not read
  for argv detection either (it adds no withholding, per the rule above), so a
  label and delimiter exposed only through such a sequence keep their value.
- Argv elements that begin with a URL still keep part of a secret value when
  the value starts with a separator (`--password=,SECRET`) or when a later
  `name=` word follows the first value word (`--password=one&a=b&SECRET`).
  These cases behave the same as in 2.10.1.
- Large-fleet sharding (more than 256 servers, stateless options only) runs
  server stages in worker processes. If a worker is killed in the instant
  between starting an MCP server and registering its process group, that
  group is not known to the parent and is not reaped. This matches the
  existing exposure when the scanner itself is killed mid-spawn.
  In containers whose PID 1 does not reap adopted processes (no `--init` or
  equivalent), descendants of a killed server can remain as zombies after a
  worker crash; the same applies to descendants of stdio servers in
  single-process scans. Run scans under an init process that reaps children.
- A fresh CI trust store has no rollback high-water mark until its first
  verification. In a one-shot CI job, set `require.pin_min_sequence` (or
  `--pin-min-sequence`) outside the pin file to refuse an older signed pin
  file, or persist the trust store. A missing trust store while the pin file
  carries a signed manifest is `MCP027`; expectations are keyed by server name
  across pin files.
- Static schema header checks follow local `$ref`, `allOf`, `anyOf`, and `oneOf`
  within bounded depth and work. External or ambiguous references, embedded
  resource scopes, dynamic references, malformed branches, cycles, and budget
  exhaustion still report incomplete coverage. These checks analyze declared
  types and header mappings, not full JSON Schema validation.
- Legacy v1 pins do not cover annotation-only changes, title, output schema,
  icons, or metadata. Review `pin --refresh` before upgrading to v2; current
  v2 pins cover these fields, including security-relevant annotation deltas.
- A translated `scan --skip-connect` runs `check`, which applies its source
  limits: a discovered source that is a symlink (or under one), larger than
  1,048,576 bytes, deeper than nesting depth 64, or over the 1,000-server cap
  is skipped with a `review_source_skipped` warning and a HIGH
  `config_parse_failure` config-health finding, where 2.x `scan` read it. The
  run exits 0 unless a policy sets `fail_on.config_health`, and the default
  `--sarif-profile compatibility` output reports the skip only as a
  `review_source_skipped` tool execution notification, without a result, and
  keeps `executionSuccessful: true`. JSON reports, stderr and the `extended`
  SARIF profile (which includes config-health results) show it in full. Select a skipped source explicitly with
  `--config FILE`. Making the skip visible in compatibility SARIF is planned
  before 3.0.0.
