# Evidence Conservation v2 admission report

## Severity-ordered findings

1. **High:** this is a review candidate only. Independent oracle and fixture
   reviews are 0 completed, so no record is admitted and 0/21 consumers ran.
2. **High:** P1 freeze admission is blocked because exact pnpm 11.5.2 remains
   `UNKNOWN`; pnpm was not invoked and no installation or network was attempted.
3. **Medium:** P3 POSIX materialization capability is `PASS` on this
   environment. Any unproved environment must abort and may not emulate modes.
4. **Medium:** a second supported deterministic environment is pending.
5. **Medium:** the previously authorized one-shot BridgeDB postflight attempt
   failed before any receipt or Markdown export was written. No retry or other
   Bridge mutation is authorized.

## Candidate inventory

- Primary corpus: 3 controls + 18 mutations = 21 fixtures.
- Boundaries: 6 no-op + 6 near-miss.
- Candidate records: exactly 29.
- Coverage: 11 COVERED / 6 PARTIAL / 1 CROSS; 3/3 controls covered.
- Runtime observations: 0/21; all consumer and scanner entrypoints forbidden.
- Same-environment deterministic regeneration: 100/100 byte-identical.
- Structural validation proves schema, hash, locality, bounded-closure, and
  declared-consistency properties only; it does not prove oracle semantics.

## Admission ceiling

The package is ready only for blind independent review. Admission and baseline
execution require a new authority decision after missing prerequisites and
reviews are closed.
