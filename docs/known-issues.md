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
- A fresh CI trust store has no rollback high-water mark until its first
  verification. In a one-shot CI job, set `require.pin_min_sequence` (or
  `--pin-min-sequence`) outside the pin file to refuse an older signed pin
  file, or persist the trust store. A missing trust store while the pin file
  carries a signed manifest is `MCP027`; expectations are keyed by server name
  across pin files.
- Static schema header checks do not follow every composition form. Unsupported
  or ambiguous cases report incomplete coverage rather than findings.
- Legacy v1 pins do not cover annotation-only changes, title, output schema,
  icons, or metadata. Review `pin --refresh` before upgrading to v2; current
  v2 pins cover these fields, including security-relevant annotation deltas.
