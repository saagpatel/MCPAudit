# Mutation Range

The range measures MCPAudit's existing detectors against deliberately mutated,
synthetic server surfaces. The first 30 operators are the initial set; the
external-schema-ref operator is the 31st and demonstrates a new category.
The committed baseline records the current results, including misses, rather
than claiming that every mutation is detected.

Fixtures and generated twins are inert: source is parsed as data, never imported
or executed. The harness calls detectors directly on metadata; it is not an
end-to-end CLI or server connection test. Package fetches use an offline
stand-in; only package-verification results that actually invoke it are marked
`MOCKED`. Twin rows show the targeted detector's provenance; the clean control
shows package-verification provenance separately. No registry or server is contacted.

After an MCPAudit release, update the checkout to the version under review and
run `make rerun`. This generates twins, scans them and prints a matrix and
baseline diff, also writing `build/redteam/range/report.html`. A regression
returns a nonzero exit status. Inspect the changes before deliberately updating
the baseline with `make rerun ACCEPT=1`. To exercise a missing detector, run
`make scan DISABLE=injection` followed by `make report`.

To add a category, add an operator module in `mutations/`, register it in the
registry, and specify its expected detector IDs and allowed collateral. Run
`make rerun ACCEPT=1` after reviewing the result; the matrix gains its row from
the generated records. Add a focused test for the new behavior.
