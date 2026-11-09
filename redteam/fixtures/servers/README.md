# Shared inert server fixtures

The six scaffold files are byte-for-byte copies of the allowlist recorded in
`base/MANIFEST.json`. The Python copies are renamed to `server.py.txt` and
`test_server.py.txt` so Python tooling never imports or collects them. Do not run,
install, or import this fixture. The generated `README.md` is preserved as
provenance, not as instructions to execute the scaffold. `.env.example` is never
opened or copied.

Manifest names refer to the renamed, committed files. The command uses a symbolic
temporary output path; the builder supplies a fresh directory on each invocation.
`base/surface.json` is the AST-extracted metadata, with `source: ast` and a synthetic
launcher. `make base` verifies both the newly scaffolded and committed bytes;
`make base REGEN=1` intentionally replaces the baseline after review.

`catalog/` holds unversioned validation-corpus surfaces, not verified current
package metadata. `fleet/` contains the clean synthetic companion shared by the
range and chains fixtures. None of these surfaces authorizes a connection.
