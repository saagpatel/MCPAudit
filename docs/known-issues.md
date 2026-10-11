# Known issues

- Reports use structural credential redaction, with pattern matching as a
  fallback for free text. Arbitrary unlabeled secrets may remain unrecognized;
  review field reports before sharing. Redacted tool schemas are display
  evidence and must not be used as replacement execution schemas.
- A fresh CI trust store has no rollback high-water mark until its first
  verification, so restoring a complete older signed pin file in a one-shot
  CI job is not detected. Persist the trust store. Deleting it removes trusted
  keys and signing expectations; expectations are keyed by server name across
  pin files.
- Static schema header checks do not follow every composition form. Unsupported
  or ambiguous cases report incomplete coverage rather than findings.
- Legacy v1 pins do not cover annotation-only changes, title, output schema,
  icons, or metadata. Review `pin --refresh` before upgrading to v2; current
  v2 pins cover these fields, including security-relevant annotation deltas.
