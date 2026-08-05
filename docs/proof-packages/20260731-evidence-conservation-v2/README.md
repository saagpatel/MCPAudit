# Evidence Conservation v2 package

This directory is a fresh, local-only `EVIDENCE_PACKAGE_ONLY` candidate. It
contains 3 controls, 18 primary mutations, 6 no-op boundaries, 6 near-miss
boundaries, full synthetic contract artifacts, 29 candidate records, schemas,
and offline validators.

It does **not** admit fixtures, invoke consumers, execute the pilot, prove a
baseline, or authorize publication. The rejected v1 package is not an input.

## Provenance amendment — 2026-08-04

**This package was amended after generation. Its receipts attest to the amended
bytes, not to the bytes frozen on 2026-07-31.** Read this before treating any
digest here as evidence about the original freeze.

**What changed.** Seven indexed artifacts recorded absolute home-directory paths
of the machine that generated the package. Every such path was replaced with a
placeholder — `<workspace>/` for the projects directory, `<home>/` for anything
else. No other content was touched.

```text
contracts/frozen-contracts-v2.json
records/freeze-receipt-p1-v1.json
records/freeze-receipt-p2-v1.json
records/freeze-receipt-p3-v1.json
records/ownership-preflight-v1.json
schemas/ownership-preflight-v1.schema.json
tools/package_lib.py
```

**Why.** The branch carrying this package had never been pushed. The paths were
removed before first publication rather than after, so no scrubbed content was
ever public. Rewriting local history was the cheap, reversible option; rewriting
published history would not have been.

**Which digests were recomputed.** Rewriting those files invalidated the digests
recorded over them, so the following were recomputed from the amended bytes:

- `generation-manifest.json` → `artifacts[].sha256` and `artifacts[].bytes` for
  the seven paths above, and for this README, which this note amends.
- `verification/package-validation.json` →
  `receipt_provenance.package_lib_sha256`.

`generation-manifest.json` and `verification/package-validation.json` are
excluded from the manifest's own digest set (`self_digest_rule`), so amending
them does not invalidate anything further.

**This package no longer passes its own validator. Read this part.**

Measured, not assumed: `tools/validate_package.py` returns `PASS` on the
pre-amendment bytes and `FAIL` on the amended bytes, with six errors:

```text
frozen_inventory_validation      1   cannot resolve the redacted repository path
record_integrity                 4   record content_sha256 no longer matches body
stored_validation_receipt_mismatch 1 stored receipt differs from a fresh run
```

**Why redaction and verifiability conflict here.** `frozen_inventory_validation`
does not merely read the recorded `repository_path` — it *executes* it, running
`git -C <path> rev-parse ...` against the filesystem. Those paths were load-bearing,
not decorative. Once they are placeholders the check cannot resolve them, and no
placeholder can satisfy it. The check could only ever have passed on the machine
that generated the package, with those repositories still at those exact paths.
**This package cannot be both publishable and self-verifying**, and that is a
property of its design, not of this amendment.

The four `record_integrity` errors are different in kind: each record carries a
`content_sha256` over its own body, and amending the bodies invalidated them.
Those are mechanically repairable. **They were deliberately not repaired.**
Repairing them would re-sign four more attestations over amended content and
would still not produce `PASS`, because the frozen-inventory failure is
unfixable. Leaving them visibly stale is the more honest artifact: the mismatch
is itself the signal that this package was amended.

**How to read this package now.** As a documented record of what was frozen on
2026-07-31, amended for publication, with the amendment disclosed. Not as a
verifiable proof. The `status: PASS` stored in
`verification/package-validation.json` was captured before the amendment, on the
generating machine; it describes bytes that were never published and cannot be
reproduced from what is here.

**What did not change.** No evidence record, candidate, control, mutation,
boundary, fixture, schema, or count was altered. The amendment touched path
strings and the manifest digests over the files containing them, and nothing
else. The *findings* the package records are unchanged; only its ability to
prove them mechanically is reduced, in the specific ways listed above.

Package-local checks:

```text
python tools/validate_package.py --root .
pytest -q -p no:cacheprovider tests/test_evidence_package_v2.py
```

Use a disposable destination with `tools/materialize_fixture.py`. Materializing
does not authorize consumer invocation. P3-06 requires native POSIX mode
semantics; an unproved platform must abort without emulation.
