# Known issues

- Credential redaction is pattern-based: a quoted secret flag value containing
  an escaped quote can leak its suffix; a zero-width character inside a
  bearer/basic token can leave its tail. Secret-shaped schema property names
  are not redacted, and terminal output prints tool names without credential
  redaction (terminal controls are still sanitized). A structural redaction
  redesign is planned for 2.10. Review field reports before sharing.
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
