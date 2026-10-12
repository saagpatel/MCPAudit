# Known issues

- Reports use structural credential redaction, with pattern matching as a
  fallback for free text. Arbitrary unlabeled secrets may remain unrecognized;
  review field reports before sharing. Redacted tool schemas are display
  evidence and must not be used as replacement execution schemas.
- Two free-text redaction edge cases remain open for a 2.10.x follow-up: an
  argv element whose inline `=` or `:` is supplied only by a terminal escape
  sequence (`--password<ESC-seq>=one two secret`) can keep the last word of a
  multi-word value, and a flag containing a fullwidth delimiter
  (`--＝password SECRET`) is not paired with its value. Plain
  `--password=...` and `--password value` are unaffected.
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
