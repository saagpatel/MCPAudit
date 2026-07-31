# Evidence Conservation v2 package

This directory is a fresh, local-only `EVIDENCE_PACKAGE_ONLY` candidate. It
contains 3 controls, 18 primary mutations, 6 no-op boundaries, 6 near-miss
boundaries, full synthetic contract artifacts, 29 candidate records, schemas,
and offline validators.

It does **not** admit fixtures, invoke consumers, execute the pilot, prove a
baseline, or authorize publication. The rejected v1 package is not an input.

Package-local checks:

```text
python tools/validate_package.py --root .
pytest -q -p no:cacheprovider tests/test_evidence_package_v2.py
```

Use a disposable destination with `tools/materialize_fixture.py`. Materializing
does not authorize consumer invocation. P3-06 requires native POSIX mode
semantics; an unproved platform must abort without emulation.
