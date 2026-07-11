# ProofOS PostgreSQL Migration Exemplar

This research profile proves one narrow proposition: exact migration bytes can
be bound to a declared effect and rollback model, exercised against a fresh
local PostgreSQL baseline, and rejected when runtime state contradicts that
model.

It is not a production migration service, duration predictor, SQL firewall, or
approval to run against an existing database. The implementation is internal in
`mcp_audit.proofos_postgres`; it has no public CLI.

## Trust boundary

The verifier accepts a strict `proofos.postgres-migration` v0 manifest, exact
baseline SQL, and exact forward and rollback SQL for every phase. Baselines are
limited to lowercase, unquoted `CREATE SCHEMA`, `CREATE TABLE`, and `INSERT`
fixtures. Tables require an explicit parenthesized column list; inserts require
an explicit column list and `VALUES`. `CREATE TABLE AS`, `LIKE`, `INHERITS`,
`INSERT ... SELECT`, and `RETURNING` are rejected. Baselines also prohibit
callable expressions, triggers, cross-object references, and metacommands.
Apply and rollback are limited to a separate conservative subset.
The verifier rejects unknown contract fields, incompatible versions, inventory
or digest drift, undeclared target objects, unsupported functions, quoted-name
bypasses, artifact-controlled session state, dynamic SQL, `CASCADE`, psql
metacommands, and server file/process/external access.
Compound top-level `ALTER TABLE` action lists are also rejected so a supported
column or constraint action cannot conceal authority changes such as RLS.

Runtime is a fresh socket-only PostgreSQL cluster with:

- an isolated data directory and home;
- no TCP listener;
- a fixed `pg_catalog`-first search path;
- a non-login, non-superuser migration role;
- observed role flags, schema/relation ACLs, and exact PostgreSQL binary hashes;
- bounded lock and statement timeouts;
- source byte ceilings and an 8 MB combined output ceiling that kills the
  client process when exceeded;
- fixture ceilings of 8 tables, 32 columns per table, 25 rows per table, and
  4 KiB per baseline string literal, checked statically and against the live
  catalog before every committed snapshot aggregation;
- forward and reverse-rollback column budgets evaluated in statement order, so
  transient add-then-drop sequences cannot cross the 32-column ceiling;
- at most 8 phases, 1 MB of aggregate forward/rollback SQL, 16 KiB per phase
  literal, and a shared 120-second runtime deadline that does not prevent
  teardown from running;
- mode-0600 disposable SQL script files instead of bidirectional psql pipes, so
  output draining and its timeout begin with the client process;
- fresh databases for preview and actual apply;
- exact catalog, constraint, index, owner, ACL, role, row-security, sequence,
  and ordered data snapshots for every table in the bound schemas;
- explicit server shutdown and directory-removal verification.

The temporary Unix socket uses a short path under `/tmp` because PostgreSQL and
macOS impose a small Unix-domain-socket path limit. The socket directory is
mode-restricted by PostgreSQL and removed during verified cleanup; all durable
test state remains in the caller-owned disposable workspace.

## Evidence chain

1. Bind the manifest, baseline, forward SQL, and rollback SQL by SHA-256.
2. Statically classify the conservative SQL subset, effects, exact target
   objects, callable functions, transaction compatibility, and maximum lock for
   both apply and rollback.
   Receipts retain the declared and statically derived object sets alongside
   runtime-observed apply and rollback objects.
3. Create the baseline under `proofos_migrator` in a disposable PG16 cluster.
4. For each transactional phase, capture proposed state and held relation locks
   inside the transaction, issue `ROLLBACK`, and prove the prior state returns.
5. Apply the phase to the preview database and compare declared, static, and
   observed effect categories.
6. Apply identical bytes to a second fresh database and require the final state
   to equal preview state.
7. Execute exact rollback bytes in reverse order, compare each phase's observed
   effect and object set with its rollback declaration, and require final state
   to equal the baseline—not merely a zero exit code.
8. Stop the server, delete cluster and socket state, and finalize only after
   cleanup is verified.

## Executable contradictions

The fixture suite includes:

- phase-byte tampering;
- hostile baseline metacommands, functions, and triggers;
- forward or rollback mutation of an undeclared second table;
- `COPY ... PROGRAM` in apply SQL;
- `COPY ... PROGRAM` hidden in rollback SQL;
- timeout suppression, sleeping, large-object calls, and quoted function-name
  bypasses;
- `CREATE TABLE AS SELECT`, `AS VALUES`, `AS TABLE`, `INSERT ... SELECT`,
  `RETURNING`, and psql full-duplex amplification attempts;
- compound `ALTER TABLE` attempts that pair a column add with RLS changes;
- a transaction rollback claim contradicted by `nextval`, whose sequence effect
  survives `ROLLBACK`;
- preview/apply mutation drift driven by distinct transaction IDs;
- rollback SQL that exits successfully but leaves a column behind;
- cluster-entry and shutdown-failure cleanup paths;
- a benign expand/validate/concurrent-index chain whose preview, apply, and
  compensating rollback states match exactly.

These cover the PostgreSQL-specific portions of the wider ProofOS attack set.
SafeForge remains the executable evidence for dependency substitution,
filesystem/network expansion, path escape, hanging/forking processes, stale
evidence, receipt-schema incompatibility, and host-contamination checks.

## Source-grounded limits

- Transactions are all-or-nothing for ordinary changes, but sequence operations
  are not rolled back. See PostgreSQL's
  [transaction tutorial](https://www.postgresql.org/docs/16/tutorial-transactions.html)
  and [sequence functions](https://www.postgresql.org/docs/16/functions-sequence.html).
- `CREATE INDEX CONCURRENTLY` cannot run inside a transaction block, performs
  multiple phases, and can leave an invalid index after failure. See
  [`CREATE INDEX`](https://www.postgresql.org/docs/16/sql-createindex.html).
- many `ALTER TABLE` forms take `ACCESS EXCLUSIVE`; locks otherwise wait until a
  configured timeout. See [`ALTER TABLE`](https://www.postgresql.org/docs/16/sql-altertable.html),
  [explicit locking](https://www.postgresql.org/docs/16/explicit-locking.html),
  and [client timeouts](https://www.postgresql.org/docs/16/runtime-config-client.html).
- untrusted schemas in `search_path` can capture object resolution. See
  [schemas and search path](https://www.postgresql.org/docs/16/ddl-schemas.html#DDL-SCHEMAS-PATH).
- `COPY` with a file or `PROGRAM` crosses into server filesystem or process
  authority and is rejected before execution. See
  [`COPY`](https://www.postgresql.org/docs/16/sql-copy.html).

The fixture proves deterministic semantics on a bounded local dataset. It does
not prove production duration, disk amplification, vacuum interactions, live
traffic behavior, extension safety, server hardening, or support for arbitrary
SQL. Those remain explicit unknowns rather than inferred safety.
