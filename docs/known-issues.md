# Known issues

- Reports use structural credential redaction, with pattern matching as a
  fallback for free text. Arbitrary unlabeled secrets may remain unrecognized;
  review field reports before sharing. Redacted tool schemas are display
  evidence and must not be used as replacement execution schemas.
- Two free-text redaction edge cases remain open for a 2.10.x follow-up:
  a terminal CSI sequence whose final byte is a letter can remove one letter
  of a secret label (so `pa<CSI>ssword=...` is not recognized as a password
  assignment), and a token-only URL userinfo separated from `@` by whitespace
  (`https://token @host`) is not redacted. Typed URL fields are unaffected.
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
