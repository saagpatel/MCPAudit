"""ProofOS PostgreSQL migration exemplar.

This module is deliberately internal.  It binds a small migration bundle to
exact bytes, classifies a conservative SQL subset, and executes those bytes in
a disposable local PostgreSQL cluster.  It is not a production migration
runner and it never connects to an existing database.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

PROOFOS_POSTGRES_CONTRACT_ID: Literal["proofos.postgres-migration"] = "proofos.postgres-migration"
PROOFOS_POSTGRES_CONTRACT_VERSION: Literal["0.1.0"] = "0.1.0"
PROOFOS_POSTGRES_PROFILE: Literal["research-mvp"] = "research-mvp"
_MAX_BASELINE_BYTES = 1_000_000
_MAX_PHASE_BYTES = 256_000
_MAX_BUNDLE_SQL_BYTES = 1_000_000
_MAX_CAPTURE_BYTES = 8_000_000
_MAX_VERIFICATION_SECONDS = 120
_MAX_FIXTURE_TABLES = 8
_MAX_FIXTURE_COLUMNS = 32
_MAX_FIXTURE_ROWS = 25
_MAX_BASELINE_LITERAL_BYTES = 4_096
_MAX_PHASE_LITERAL_BYTES = 16_384

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]*$")]
SqlIdentifier = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]*$")]
QualifiedName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$"),
]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MigrationMode(StrEnum):
    TRANSACTIONAL = "transactional"
    NONTRANSACTIONAL = "nontransactional"


class RollbackType(StrEnum):
    TRANSACTION = "transaction"
    COMPENSATING_SQL = "compensating_sql"
    RESTORE_ONLY = "restore_only"
    IRREVERSIBLE = "irreversible"


class Effect(StrEnum):
    SCHEMA = "schema"
    DATA = "data"
    INDEX = "index"
    SEQUENCE = "sequence"
    PERMISSION = "permission"


class LockMode(StrEnum):
    ACCESS_SHARE = "AccessShareLock"
    ROW_SHARE = "RowShareLock"
    ROW_EXCLUSIVE = "RowExclusiveLock"
    SHARE_UPDATE_EXCLUSIVE = "ShareUpdateExclusiveLock"
    SHARE = "ShareLock"
    SHARE_ROW_EXCLUSIVE = "ShareRowExclusiveLock"
    EXCLUSIVE = "ExclusiveLock"
    ACCESS_EXCLUSIVE = "AccessExclusiveLock"


_LOCK_RANK = {mode.value: rank for rank, mode in enumerate(LockMode, start=1)}


class ContractHeader(_StrictModel):
    contract_id: Literal["proofos.postgres-migration"] = PROOFOS_POSTGRES_CONTRACT_ID
    contract_version: Literal["0.1.0"] = PROOFOS_POSTGRES_CONTRACT_VERSION
    profile: Literal["research-mvp"] = PROOFOS_POSTGRES_PROFILE


class ObservedTable(_StrictModel):
    schema_name: SqlIdentifier
    table_name: SqlIdentifier
    order_by: list[SqlIdentifier] = Field(min_length=1, max_length=4)

    @property
    def qualified_name(self) -> str:
        return f"{self.schema_name}.{self.table_name}"


class MigrationPhase(_StrictModel):
    phase_id: Identifier
    mode: MigrationMode
    sql_digest: Digest
    rollback_type: RollbackType
    rollback_digest: Digest | None
    declared_effects: list[Effect] = Field(min_length=1)
    expected_objects: list[QualifiedName] = Field(min_length=1)
    max_lock_mode: LockMode
    rollback_effects: list[Effect] = Field(min_length=1)
    rollback_expected_objects: list[QualifiedName] = Field(min_length=1)
    rollback_max_lock_mode: LockMode

    @model_validator(mode="after")
    def rollback_shape(self) -> MigrationPhase:
        if self.rollback_type in {RollbackType.TRANSACTION, RollbackType.COMPENSATING_SQL}:
            if self.rollback_digest is None:
                raise ValueError("reversible phase requires rollback_digest")
        elif self.rollback_digest is not None:
            raise ValueError("restore-only or irreversible phase cannot claim rollback SQL")
        if self.mode is MigrationMode.NONTRANSACTIONAL and self.rollback_type is RollbackType.TRANSACTION:
            raise ValueError("nontransactional phase cannot claim transaction rollback")
        if len(set(self.declared_effects)) != len(self.declared_effects):
            raise ValueError("declared_effects must be unique")
        if len(set(self.expected_objects)) != len(self.expected_objects):
            raise ValueError("expected_objects must be unique")
        if len(set(self.rollback_effects)) != len(self.rollback_effects):
            raise ValueError("rollback_effects must be unique")
        if len(set(self.rollback_expected_objects)) != len(self.rollback_expected_objects):
            raise ValueError("rollback_expected_objects must be unique")
        if Effect.PERMISSION in {*self.declared_effects, *self.rollback_effects}:
            raise ValueError("permission-changing migrations are unsupported in research-mvp")
        if Effect.SCHEMA in self.declared_effects and len(self.expected_objects) != 1:
            raise ValueError("schema phases must target exactly one object")
        if Effect.SCHEMA in self.rollback_effects and len(self.rollback_expected_objects) != 1:
            raise ValueError("schema rollback must target exactly one object")
        return self


class PostgresMigrationManifest(_StrictModel):
    contract: ContractHeader = Field(default_factory=ContractHeader)
    artifact_id: Identifier
    target_postgres_major: int = Field(ge=12, le=18)
    baseline_sql_digest: Digest
    migration_role: Literal["proofos_migrator"] = "proofos_migrator"
    fixed_search_path: list[SqlIdentifier] = Field(min_length=2)
    observed_tables: list[ObservedTable] = Field(min_length=1, max_length=_MAX_FIXTURE_TABLES)
    lock_timeout_ms: int = Field(ge=10, le=5_000)
    statement_timeout_ms: int = Field(ge=10, le=20_000)
    phases: list[MigrationPhase] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def manifest_shape(self) -> PostgresMigrationManifest:
        if self.fixed_search_path[0] != "pg_catalog":
            raise ValueError("fixed_search_path must put pg_catalog first")
        if len(set(self.fixed_search_path)) != len(self.fixed_search_path):
            raise ValueError("fixed_search_path must be unique")
        phase_ids = [phase.phase_id for phase in self.phases]
        if len(set(phase_ids)) != len(phase_ids):
            raise ValueError("phase_id must be unique")
        table_names = [table.qualified_name for table in self.observed_tables]
        if len(set(table_names)) != len(table_names):
            raise ValueError("observed_tables must be unique")
        return self


class PhaseArtifact(_StrictModel):
    sql: str = Field(min_length=1)
    rollback_sql: str | None = None


class Finding(_StrictModel):
    code: str
    stage: Literal["source", "static", "runtime", "rollback", "cleanup"]
    detail: str


class PhaseEvidence(_StrictModel):
    phase_id: Identifier
    statement_kinds: list[str]
    declared_effects: list[Effect]
    static_effects: list[Effect]
    declared_objects: list[QualifiedName]
    static_objects: list[str]
    rollback_statement_kinds: list[str]
    rollback_static_effects: list[Effect]
    rollback_declared_objects: list[QualifiedName]
    rollback_static_objects: list[str]
    observed_effects: list[Effect] = Field(default_factory=list)
    observed_objects: list[str] = Field(default_factory=list)
    rollback_observed_effects: list[Effect] = Field(default_factory=list)
    rollback_observed_objects: list[str] = Field(default_factory=list)
    observed_lock_modes: list[LockMode] = Field(default_factory=list)
    transaction_rollback_clean: bool | None = None
    preview_state_digest: Digest | None = None
    rollback_state_digest: Digest | None = None


class RoleEvidence(_StrictModel):
    declared_role: Literal["proofos_migrator"]
    observed_current_user: Literal["proofos_migrator"]
    superuser: bool
    inherit: bool
    create_role: bool
    create_db: bool
    login: bool
    replication: bool
    bypass_rls: bool


class PostgresVerificationReceipt(_StrictModel):
    contract: ContractHeader
    artifact_id: Identifier
    decision: Literal["eligible", "blocked"]
    source_bound: bool
    server_version: str | None
    migration_role: str
    role_evidence: RoleEvidence | None
    binary_digests: dict[str, Digest]
    baseline_state_digest: Digest | None
    preview_state_digest: Digest | None
    actual_state_digest: Digest | None
    rollback_state_digest: Digest | None
    phases: list[PhaseEvidence]
    findings: list[Finding]
    preview_matches_actual: bool | None
    rollback_verified: bool | None
    cleanup_verified: bool
    limitations: list[str]


class StaticPhaseResult(_StrictModel):
    phase_id: Identifier
    statement_kinds: list[str]
    effects: list[Effect]
    touched_objects: list[str]
    required_lock: LockMode
    rollback_statement_kinds: list[str]
    rollback_effects: list[Effect]
    rollback_touched_objects: list[str]
    rollback_required_lock: LockMode
    findings: list[Finding]


class PostgresBinaries(_StrictModel):
    bindir: Path
    postgres: Path
    initdb: Path
    pg_ctl: Path
    psql: Path
    createdb: Path
    dropdb: Path

    @classmethod
    def from_bindir(cls, bindir: Path) -> PostgresBinaries:
        root = bindir.expanduser().resolve()
        names = ("postgres", "initdb", "pg_ctl", "psql", "createdb", "dropdb")
        paths = {name: root / name for name in names}
        missing = [name for name, path in paths.items() if not path.is_file()]
        if missing:
            raise ValueError(f"PostgreSQL bindir is incomplete: {', '.join(missing)}")
        return cls(bindir=root, **paths)

    def digests(self) -> dict[str, Digest]:
        return {
            name: digest_bytes(path.read_bytes())
            for name, path in {
                "postgres": self.postgres,
                "initdb": self.initdb,
                "pg_ctl": self.pg_ctl,
                "psql": self.psql,
                "createdb": self.createdb,
                "dropdb": self.dropdb,
            }.items()
        }


def digest_bytes(value: bytes) -> Digest:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def postgres_migration_json_schema() -> dict[str, object]:
    return PostgresMigrationManifest.model_json_schema()


def postgres_receipt_json_schema() -> dict[str, object]:
    return PostgresVerificationReceipt.model_json_schema()


def validate_sources(
    manifest: PostgresMigrationManifest,
    baseline_sql: str,
    artifacts: Mapping[str, PhaseArtifact],
) -> list[Finding]:
    findings: list[Finding] = []
    if len(baseline_sql.encode()) > _MAX_BASELINE_BYTES:
        findings.append(
            _finding("PG-SOURCE-BASELINE-SIZE", "source", "baseline exceeds the research byte cap")
        )
    if digest_bytes(baseline_sql.encode()) != manifest.baseline_sql_digest:
        findings.append(_finding("PG-SOURCE-BASELINE-DIGEST", "source", "baseline bytes drifted"))
    expected_ids = {phase.phase_id for phase in manifest.phases}
    if set(artifacts) != expected_ids:
        findings.append(
            _finding(
                "PG-SOURCE-PHASE-INVENTORY",
                "source",
                "phase artifact inventory does not exactly match the manifest",
            )
        )
        return findings
    bundle_bytes = sum(
        len(artifact.sql.encode())
        + (len(artifact.rollback_sql.encode()) if artifact.rollback_sql is not None else 0)
        for artifact in artifacts.values()
    )
    if bundle_bytes > _MAX_BUNDLE_SQL_BYTES:
        findings.append(
            _finding(
                "PG-SOURCE-BUNDLE-SIZE",
                "source",
                "aggregate forward and rollback SQL exceeds the research bundle cap",
            )
        )
    for phase in manifest.phases:
        artifact = artifacts[phase.phase_id]
        if len(artifact.sql.encode()) > _MAX_PHASE_BYTES or (
            artifact.rollback_sql is not None and len(artifact.rollback_sql.encode()) > _MAX_PHASE_BYTES
        ):
            findings.append(
                _finding(
                    "PG-SOURCE-PHASE-SIZE",
                    "source",
                    f"{phase.phase_id} exceeds the research byte cap",
                )
            )
        if _max_sql_literal_bytes(artifact.sql) > _MAX_PHASE_LITERAL_BYTES or (
            artifact.rollback_sql is not None
            and _max_sql_literal_bytes(artifact.rollback_sql) > _MAX_PHASE_LITERAL_BYTES
        ):
            findings.append(
                _finding(
                    "PG-SOURCE-PHASE-LITERAL-SIZE",
                    "source",
                    f"{phase.phase_id} contains an oversized string literal",
                )
            )
        if digest_bytes(artifact.sql.encode()) != phase.sql_digest:
            findings.append(_finding("PG-SOURCE-SQL-DIGEST", "source", f"{phase.phase_id} SQL bytes drifted"))
        if phase.rollback_digest is None:
            if artifact.rollback_sql is not None:
                findings.append(
                    _finding(
                        "PG-SOURCE-UNDECLARED-ROLLBACK",
                        "source",
                        f"{phase.phase_id} supplied undeclared rollback bytes",
                    )
                )
        elif artifact.rollback_sql is None or digest_bytes(artifact.rollback_sql.encode()) != (
            phase.rollback_digest
        ):
            findings.append(
                _finding(
                    "PG-SOURCE-ROLLBACK-DIGEST",
                    "source",
                    f"{phase.phase_id} rollback bytes drifted or are missing",
                )
            )
    return findings


def analyze_baseline(manifest: PostgresMigrationManifest, baseline_sql: str) -> list[Finding]:
    findings: list[Finding] = []
    if _max_sql_literal_bytes(baseline_sql) > _MAX_BASELINE_LITERAL_BYTES:
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-LITERAL-SIZE",
                "static",
                "baseline string literal exceeds the bounded fixture limit",
            )
        )
    if "\\" in baseline_sql:
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-PSQL-META",
                "static",
                "baseline psql metacommands are forbidden",
            )
        )
    if '"' in baseline_sql:
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-QUOTED-IDENTIFIER",
                "static",
                "quoted identifiers are outside the lowercase research profile",
            )
        )
    if "$" in baseline_sql:
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-DOLLAR-QUOTE",
                "static",
                "dollar quoting and parameters are outside the research profile",
            )
        )
    statements = _split_statements(baseline_sql)
    created_schemas: set[str] = set()
    created_tables: set[str] = set()
    inserted_tables: set[str] = set()
    inserted_rows: defaultdict[str, int] = defaultdict(int)
    for statement in statements:
        upper = [token.upper() for token in _tokens(statement)]
        token_set = set(upper)
        baseline_functions = _baseline_disallowed_functions(statement)
        if baseline_functions:
            findings.append(
                _finding(
                    "PG-STATIC-BASELINE-FUNCTION-UNSUPPORTED",
                    "static",
                    f"baseline calls unsupported functions: {', '.join(baseline_functions)}",
                )
            )
        if token_set & {
            "COPY",
            "PROGRAM",
            "PG_READ_FILE",
            "PG_WRITE_FILE",
            "LO_IMPORT",
            "LO_EXPORT",
            "DBLINK",
            "EXECUTE",
            "DO",
            "CALL",
            "TRIGGER",
            "FUNCTION",
            "PROCEDURE",
            "EXTENSION",
            "REFERENCES",
        }:
            findings.append(
                _finding(
                    "PG-STATIC-BASELINE-CAPABILITY",
                    "static",
                    "baseline contains unsupported executable or cross-object capability",
                )
            )
        if "CASCADE" in token_set or (upper and upper[0] in {"SET", "RESET", "ALTER"}):
            findings.append(
                _finding(
                    "PG-STATIC-BASELINE-STATE",
                    "static",
                    "baseline dependency or session mutation is unsupported",
                )
            )
        if tuple(upper[:2]) == ("CREATE", "SCHEMA"):
            match = re.search(
                r'^\s*CREATE\s+SCHEMA\s+"?([a-z_][a-z0-9_]*)"?\s*$',
                statement,
                flags=re.IGNORECASE,
            )
            if match:
                created_schemas.add(match.group(1).lower())
                continue
        if tuple(upper[:2]) == ("CREATE", "TABLE"):
            target = _baseline_table_target(statement, "CREATE TABLE")
            if _baseline_parenthesized_item_count(statement, "CREATE TABLE") > (_MAX_FIXTURE_COLUMNS):
                findings.append(
                    _finding(
                        "PG-STATIC-BASELINE-COLUMN-LIMIT",
                        "static",
                        "baseline table exceeds the fixture column limit",
                    )
                )
            if (
                target
                and _baseline_has_parenthesized_shape(statement, "CREATE TABLE")
                and not ({"SELECT", "FROM", "LIKE", "INHERITS"} & token_set)
            ):
                created_tables.add(target)
                continue
        if tuple(upper[:2]) == ("INSERT", "INTO"):
            target = _baseline_table_target(statement, "INSERT INTO")
            row_count = _baseline_values_row_count(statement)
            if _baseline_parenthesized_item_count(statement, "INSERT INTO") > (_MAX_FIXTURE_COLUMNS):
                findings.append(
                    _finding(
                        "PG-STATIC-BASELINE-INSERT-WIDTH",
                        "static",
                        "baseline insert exceeds the fixture column limit",
                    )
                )
            if row_count > _MAX_FIXTURE_ROWS:
                findings.append(
                    _finding(
                        "PG-STATIC-BASELINE-ROW-LIMIT",
                        "static",
                        "baseline insert exceeds the fixture row limit",
                    )
                )
            if (
                target
                and _baseline_has_parenthesized_shape(statement, "INSERT INTO")
                and "VALUES" in token_set
                and not ({"SELECT", "FROM", "RETURNING"} & token_set)
            ):
                inserted_rows[target] += row_count
                if inserted_rows[target] > _MAX_FIXTURE_ROWS:
                    findings.append(
                        _finding(
                            "PG-STATIC-BASELINE-TOTAL-ROW-LIMIT",
                            "static",
                            f"baseline rows for {target} exceed the fixture limit",
                        )
                    )
                inserted_tables.add(target)
                continue
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-UNSUPPORTED",
                "static",
                "baseline statement is outside CREATE SCHEMA, CREATE TABLE, and INSERT INTO",
            )
        )
    expected_tables = {table.qualified_name for table in manifest.observed_tables}
    expected_schemas = {table.schema_name for table in manifest.observed_tables}
    if created_schemas != expected_schemas or created_tables != expected_tables:
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-INVENTORY",
                "static",
                "baseline schema and table inventory does not exactly match observed_tables",
            )
        )
    if not inserted_tables.issubset(expected_tables):
        findings.append(
            _finding(
                "PG-STATIC-BASELINE-INSERT-SCOPE",
                "static",
                "baseline inserts outside the declared table inventory",
            )
        )
    return findings


def analyze_phase(phase: MigrationPhase, artifact: PhaseArtifact) -> StaticPhaseResult:
    findings: list[Finding] = []
    statement_kinds: list[str] = []
    effects: set[Effect] = set()
    touched_objects: set[str] = set()
    required_lock = LockMode.ACCESS_SHARE
    sql = artifact.sql
    if "\\" in sql:
        findings.append(_finding("PG-STATIC-PSQL-META", "static", "psql metacommands are forbidden"))
    if '"' in sql:
        findings.append(
            _finding(
                "PG-STATIC-QUOTED-IDENTIFIER",
                "static",
                "quoted identifiers are outside the lowercase research profile",
            )
        )
    if "$" in sql:
        findings.append(
            _finding(
                "PG-STATIC-DOLLAR-QUOTE",
                "static",
                "dollar quoting and parameters are outside the research profile",
            )
        )
    statements = _split_statements(sql)
    if not statements:
        findings.append(_finding("PG-STATIC-EMPTY", "static", "phase contains no SQL statements"))
    for statement in statements:
        tokens = _tokens(statement)
        upper = [token.upper() for token in tokens]
        token_set = set(upper)
        if token_set & {
            "COPY",
            "PROGRAM",
            "PG_READ_FILE",
            "PG_WRITE_FILE",
            "LO_IMPORT",
            "LO_EXPORT",
            "DBLINK",
        }:
            findings.append(
                _finding(
                    "PG-STATIC-EXTERNAL-CAPABILITY",
                    "static",
                    "server filesystem, process, or external access is forbidden",
                )
            )
        if token_set & {"DO", "CALL", "EXECUTE"} or (
            len(upper) >= 2 and upper[0] == "CREATE" and upper[1] in {"FUNCTION", "PROCEDURE"}
        ):
            findings.append(
                _finding("PG-STATIC-DYNAMIC-SQL", "static", "dynamic or procedural SQL is unsupported")
            )
        if "CASCADE" in token_set:
            findings.append(
                _finding("PG-STATIC-CASCADE", "static", "dependency-expanding CASCADE is forbidden")
            )
        if "REFERENCES" in token_set:
            findings.append(
                _finding(
                    "PG-STATIC-DEPENDENCY-UNSUPPORTED",
                    "static",
                    "cross-object REFERENCES is outside the research profile",
                )
            )
        if upper and upper[0] in {"SET", "RESET"}:
            findings.append(
                _finding(
                    "PG-STATIC-SESSION-STATE",
                    "static",
                    "artifact-controlled session state is forbidden",
                )
            )

        kind, statement_effects, lock, requires_nontransactional = _classify_statement(upper)
        if kind is None:
            findings.append(
                _finding(
                    "PG-STATIC-UNSUPPORTED-STATEMENT",
                    "static",
                    "statement is outside the research profile's conservative SQL subset",
                )
            )
            continue
        statement_kinds.append(kind)
        disallowed_functions = _disallowed_functions(statement, kind)
        if disallowed_functions:
            findings.append(
                _finding(
                    "PG-STATIC-FUNCTION-UNSUPPORTED",
                    "static",
                    f"{kind} calls unsupported functions: {', '.join(disallowed_functions)}",
                )
            )
        if kind.startswith("alter-table-") and _has_top_level_comma(statement):
            findings.append(
                _finding(
                    "PG-STATIC-COMPOUND-ALTER-UNSUPPORTED",
                    "static",
                    "compound ALTER TABLE actions are outside the research profile",
                )
            )
        if kind == "update" and ({"FROM", "SELECT"} & set(upper[1:])):
            findings.append(
                _finding(
                    "PG-STATIC-UPDATE-SCOPE-UNSUPPORTED",
                    "static",
                    "UPDATE subqueries and FROM clauses are outside the research profile",
                )
            )
        if kind == "update" and "RETURNING" in upper:
            findings.append(
                _finding(
                    "PG-STATIC-RETURNING-UNSUPPORTED",
                    "static",
                    "UPDATE RETURNING is forbidden in the bounded-output profile",
                )
            )
        if kind == "sequence-operation" and "FROM" in upper:
            findings.append(
                _finding(
                    "PG-STATIC-SEQUENCE-SCOPE-UNSUPPORTED",
                    "static",
                    "sequence probes must be a single scalar SELECT without FROM",
                )
            )
        touched = _extract_touched_object(statement, kind)
        if touched is None:
            findings.append(
                _finding(
                    "PG-STATIC-OBJECT-UNRESOLVED",
                    "static",
                    "statement target must be one schema-qualified object",
                )
            )
        else:
            touched_objects.add(touched)
        effects.update(statement_effects)
        if _LOCK_RANK[lock.value] > _LOCK_RANK[required_lock.value]:
            required_lock = lock
        if requires_nontransactional and phase.mode is not MigrationMode.NONTRANSACTIONAL:
            findings.append(
                _finding(
                    "PG-STATIC-NONTRANSACTIONAL-MISMATCH",
                    "static",
                    f"{kind} cannot run in a transactional phase",
                )
            )
        if not requires_nontransactional and phase.mode is MigrationMode.NONTRANSACTIONAL:
            findings.append(
                _finding(
                    "PG-STATIC-TRANSACTIONAL-MISMATCH",
                    "static",
                    f"{kind} was unnecessarily declared nontransactional",
                )
            )
    if touched_objects != set(phase.expected_objects):
        findings.append(
            _finding(
                "PG-STATIC-OBJECT-MISMATCH",
                "static",
                f"{phase.phase_id} touched objects do not exactly match expected_objects",
            )
        )
    if effects != set(phase.declared_effects):
        findings.append(
            _finding(
                "PG-STATIC-EFFECT-MISMATCH",
                "static",
                "observed SQL effects do not exactly match declared_effects",
            )
        )
    if _LOCK_RANK[required_lock.value] > _LOCK_RANK[phase.max_lock_mode.value]:
        findings.append(
            _finding(
                "PG-STATIC-LOCK-AMPLIFICATION",
                "static",
                f"required {required_lock.value} exceeds declared {phase.max_lock_mode.value}",
            )
        )
    (
        rollback_kinds,
        rollback_effects,
        rollback_lock,
        rollback_objects,
        rollback_findings,
    ) = _analyze_rollback(phase, artifact)
    findings.extend(rollback_findings)
    return StaticPhaseResult(
        phase_id=phase.phase_id,
        statement_kinds=statement_kinds,
        effects=sorted(effects, key=lambda effect: effect.value),
        touched_objects=sorted(touched_objects),
        required_lock=required_lock,
        rollback_statement_kinds=rollback_kinds,
        rollback_effects=rollback_effects,
        rollback_touched_objects=rollback_objects,
        rollback_required_lock=rollback_lock,
        findings=findings,
    )


def _analyze_rollback(
    phase: MigrationPhase, artifact: PhaseArtifact
) -> tuple[list[str], list[Effect], LockMode, list[str], list[Finding]]:
    sql = artifact.rollback_sql
    if sql is None:
        return [], [], LockMode.ACCESS_SHARE, [], []
    findings: list[Finding] = []
    kinds: list[str] = []
    effects: set[Effect] = set()
    touched_objects: set[str] = set()
    required_lock = LockMode.ACCESS_SHARE
    if "\\" in sql:
        findings.append(
            _finding("PG-STATIC-ROLLBACK-PSQL-META", "static", "rollback metacommands are forbidden")
        )
    if '"' in sql:
        findings.append(
            _finding(
                "PG-STATIC-ROLLBACK-QUOTED-IDENTIFIER",
                "static",
                "quoted rollback identifiers are outside the lowercase research profile",
            )
        )
    if "$" in sql:
        findings.append(
            _finding(
                "PG-STATIC-ROLLBACK-DOLLAR-QUOTE",
                "static",
                "rollback dollar quoting and parameters are unsupported",
            )
        )
    statements = _split_statements(sql)
    if not statements:
        findings.append(_finding("PG-STATIC-ROLLBACK-EMPTY", "static", "rollback contains no SQL statements"))
    for statement in statements:
        upper = [token.upper() for token in _tokens(statement)]
        token_set = set(upper)
        if token_set & {
            "COPY",
            "PROGRAM",
            "PG_READ_FILE",
            "PG_WRITE_FILE",
            "LO_IMPORT",
            "LO_EXPORT",
            "DBLINK",
        }:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-EXTERNAL-CAPABILITY",
                    "static",
                    "rollback server filesystem, process, or external access is forbidden",
                )
            )
        if token_set & {"DO", "CALL", "EXECUTE"} or (
            len(upper) >= 2 and upper[0] == "CREATE" and upper[1] in {"FUNCTION", "PROCEDURE"}
        ):
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-DYNAMIC-SQL",
                    "static",
                    "dynamic or procedural rollback SQL is unsupported",
                )
            )
        if "CASCADE" in token_set:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-CASCADE",
                    "static",
                    "dependency-expanding rollback CASCADE is forbidden",
                )
            )
        if "REFERENCES" in token_set:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-DEPENDENCY-UNSUPPORTED",
                    "static",
                    "rollback REFERENCES is outside the research profile",
                )
            )
        if upper and upper[0] in {"SET", "RESET"}:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-SESSION-STATE",
                    "static",
                    "artifact-controlled rollback session state is forbidden",
                )
            )
        kind, statement_effects, lock, requires_nontransactional = _classify_statement(upper)
        if kind is None:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-UNSUPPORTED",
                    "static",
                    "rollback statement is outside the conservative SQL subset",
                )
            )
            continue
        kinds.append(kind)
        disallowed_functions = _disallowed_functions(statement, kind)
        if disallowed_functions:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-FUNCTION-UNSUPPORTED",
                    "static",
                    f"rollback calls unsupported functions: {', '.join(disallowed_functions)}",
                )
            )
        if kind.startswith("alter-table-") and _has_top_level_comma(statement):
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-COMPOUND-ALTER-UNSUPPORTED",
                    "static",
                    "compound rollback ALTER TABLE actions are unsupported",
                )
            )
        if kind == "update" and ({"FROM", "SELECT"} & set(upper[1:])):
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-UPDATE-SCOPE-UNSUPPORTED",
                    "static",
                    "rollback UPDATE subqueries and FROM clauses are unsupported",
                )
            )
        if kind == "update" and "RETURNING" in upper:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-RETURNING-UNSUPPORTED",
                    "static",
                    "rollback UPDATE RETURNING is forbidden",
                )
            )
        if kind == "sequence-operation" and "FROM" in upper:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-SEQUENCE-SCOPE-UNSUPPORTED",
                    "static",
                    "rollback sequence probes must be scalar SELECTs",
                )
            )
        touched = _extract_touched_object(statement, kind)
        if touched is None:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-OBJECT-UNRESOLVED",
                    "static",
                    "rollback target must be one schema-qualified object",
                )
            )
        else:
            touched_objects.add(touched)
        effects.update(statement_effects)
        if _LOCK_RANK[lock.value] > _LOCK_RANK[required_lock.value]:
            required_lock = lock
        if requires_nontransactional and phase.mode is not MigrationMode.NONTRANSACTIONAL:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-MODE-MISMATCH",
                    "static",
                    f"rollback {kind} cannot run in a transactional phase",
                )
            )
        if not requires_nontransactional and phase.mode is MigrationMode.NONTRANSACTIONAL:
            findings.append(
                _finding(
                    "PG-STATIC-ROLLBACK-MODE-MISMATCH",
                    "static",
                    f"rollback {kind} was unnecessarily declared nontransactional",
                )
            )
    if touched_objects != set(phase.rollback_expected_objects):
        findings.append(
            _finding(
                "PG-STATIC-ROLLBACK-OBJECT-MISMATCH",
                "static",
                f"{phase.phase_id} rollback objects do not match its declaration",
            )
        )
    if effects != set(phase.rollback_effects):
        findings.append(
            _finding(
                "PG-STATIC-ROLLBACK-EFFECT-MISMATCH",
                "static",
                "rollback SQL effects do not exactly match rollback_effects",
            )
        )
    if _LOCK_RANK[required_lock.value] > _LOCK_RANK[phase.rollback_max_lock_mode.value]:
        findings.append(
            _finding(
                "PG-STATIC-ROLLBACK-LOCK-AMPLIFICATION",
                "static",
                f"rollback requires {required_lock.value} beyond its declared lock ceiling",
            )
        )
    return (
        kinds,
        sorted(effects, key=lambda effect: effect.value),
        required_lock,
        sorted(touched_objects),
        findings,
    )


def _validate_column_budget(
    manifest: PostgresMigrationManifest,
    baseline_sql: str,
    results: Sequence[StaticPhaseResult],
) -> list[Finding]:
    counts = _baseline_column_counts(baseline_sql)
    by_phase = {result.phase_id: result for result in results}
    findings: list[Finding] = []

    def apply_kinds(phase_id: str, target: str, kinds: Sequence[str], direction: str) -> None:
        for kind in kinds:
            if kind == "alter-table-add-column":
                counts[target] = counts.get(target, 0) + 1
            elif kind == "alter-table-drop-column":
                counts[target] = counts.get(target, 0) - 1
            else:
                continue
            if counts[target] < 1 or counts[target] > _MAX_FIXTURE_COLUMNS:
                findings.append(
                    _finding(
                        "PG-STATIC-LIVE-COLUMN-LIMIT",
                        "static",
                        f"{phase_id} {direction} exceeds the live fixture column budget",
                    )
                )

    for phase in manifest.phases:
        if Effect.SCHEMA in phase.declared_effects:
            apply_kinds(
                phase.phase_id,
                phase.expected_objects[0],
                by_phase[phase.phase_id].statement_kinds,
                "apply",
            )
    for phase in reversed(manifest.phases):
        if Effect.SCHEMA in phase.rollback_effects:
            apply_kinds(
                phase.phase_id,
                phase.rollback_expected_objects[0],
                by_phase[phase.phase_id].rollback_statement_kinds,
                "rollback",
            )
    return findings


def _baseline_column_counts(baseline_sql: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for statement in _split_statements(baseline_sql):
        upper = [token.upper() for token in _tokens(statement)]
        if tuple(upper[:2]) != ("CREATE", "TABLE"):
            continue
        target = _baseline_table_target(statement, "CREATE TABLE")
        if target is not None:
            counts[target] = _baseline_parenthesized_item_count(statement, "CREATE TABLE")
    return counts


def verify_postgres_migration(
    manifest: PostgresMigrationManifest,
    baseline_sql: str,
    artifacts: Mapping[str, PhaseArtifact],
    *,
    binaries: PostgresBinaries,
    workspace: Path,
) -> PostgresVerificationReceipt:
    findings = validate_sources(manifest, baseline_sql, artifacts)
    static_results: list[StaticPhaseResult] = []
    if not findings:
        findings.extend(analyze_baseline(manifest, baseline_sql))
    if not findings:
        for phase in manifest.phases:
            result = analyze_phase(phase, artifacts[phase.phase_id])
            static_results.append(result)
            findings.extend(result.findings)
    if static_results:
        findings.extend(_validate_column_budget(manifest, baseline_sql, static_results))
    phase_by_id = {phase.phase_id: phase for phase in manifest.phases}
    phase_evidence = [
        PhaseEvidence(
            phase_id=result.phase_id,
            statement_kinds=result.statement_kinds,
            declared_effects=phase_by_id[result.phase_id].declared_effects,
            static_effects=result.effects,
            declared_objects=phase_by_id[result.phase_id].expected_objects,
            static_objects=result.touched_objects,
            rollback_statement_kinds=result.rollback_statement_kinds,
            rollback_static_effects=result.rollback_effects,
            rollback_declared_objects=phase_by_id[result.phase_id].rollback_expected_objects,
            rollback_static_objects=result.rollback_touched_objects,
        )
        for result in static_results
    ]
    if findings:
        return _blocked_receipt(manifest, findings, phase_evidence, cleanup_verified=True)

    expected_major = manifest.target_postgres_major
    binary_digests = binaries.digests()
    runtime_deadline = time.monotonic() + _MAX_VERIFICATION_SECONDS
    server_version: str | None = None
    role_evidence: RoleEvidence | None = None
    baseline_digest: Digest | None = None
    preview_digest: Digest | None = None
    actual_digest: Digest | None = None
    rollback_digest: Digest | None = None
    preview_matches_actual: bool | None = None
    rollback_verified: bool | None = None
    cleanup_verified = False
    cluster: _DisposablePostgres | None = None

    workspace.mkdir(parents=True, exist_ok=True)
    try:
        cluster = _DisposablePostgres(binaries, workspace, deadline=runtime_deadline)
        with cluster:
            server_version = cluster.server_version
            actual_major = int(server_version.split(".", maxsplit=1)[0])
            if actual_major != expected_major:
                findings.append(
                    _finding(
                        "PG-RUNTIME-VERSION-MISMATCH",
                        "runtime",
                        f"server major {actual_major} does not match target {expected_major}",
                    )
                )
            if not findings:
                cluster.prepare_baseline("proofos_base", baseline_sql, manifest)
                role_evidence = cluster.role_evidence("proofos_base")
                if any(
                    (
                        role_evidence.superuser,
                        role_evidence.inherit,
                        role_evidence.create_role,
                        role_evidence.create_db,
                        role_evidence.login,
                        role_evidence.replication,
                        role_evidence.bypass_rls,
                    )
                ):
                    findings.append(
                        _finding(
                            "PG-RUNTIME-ROLE-EXPANDED",
                            "runtime",
                            "migration role exceeded the fixed least-privilege profile",
                        )
                    )
                baseline = cluster.snapshot("proofos_base", manifest.observed_tables)
                baseline_digest = _state_digest(baseline)
                cluster.clone_database("proofos_base", "proofos_preview")
                cluster.clone_database("proofos_base", "proofos_apply")

                evidence_by_id = {item.phase_id: item for item in phase_evidence}
                for phase in manifest.phases:
                    artifact = artifacts[phase.phase_id]
                    before = cluster.snapshot("proofos_preview", manifest.observed_tables)
                    if phase.mode is MigrationMode.TRANSACTIONAL:
                        proposed, locks = cluster.transaction_preview(
                            "proofos_preview", artifact.sql, manifest
                        )
                        after_rollback = cluster.snapshot("proofos_preview", manifest.observed_tables)
                        clean = after_rollback == before
                        evidence_by_id[phase.phase_id].transaction_rollback_clean = clean
                        evidence_by_id[phase.phase_id].observed_lock_modes = locks
                        if any(
                            _LOCK_RANK[lock.value] > _LOCK_RANK[phase.max_lock_mode.value] for lock in locks
                        ):
                            findings.append(
                                _finding(
                                    "PG-RUNTIME-LOCK-AMPLIFICATION",
                                    "runtime",
                                    f"{phase.phase_id} exceeded its declared lock ceiling",
                                )
                            )
                            break
                        if not clean:
                            findings.append(
                                _finding(
                                    "PG-RUNTIME-TRANSACTION-ROLLBACK-DIRTY",
                                    "runtime",
                                    f"{phase.phase_id} left state after ROLLBACK",
                                )
                            )
                            break
                        evidence_by_id[phase.phase_id].preview_state_digest = _state_digest(proposed)
                    if not findings:
                        cluster.apply_phase("proofos_preview", phase, artifact.sql, manifest)
                        after_apply = cluster.snapshot("proofos_preview", manifest.observed_tables)
                        observed_effects = _state_effects(before, after_apply)
                        observed_objects = _state_changed_objects(before, after_apply)
                        evidence_by_id[phase.phase_id].observed_effects = observed_effects
                        evidence_by_id[phase.phase_id].observed_objects = observed_objects
                        evidence_by_id[phase.phase_id].preview_state_digest = _state_digest(after_apply)
                        if set(observed_effects) != set(phase.declared_effects):
                            findings.append(
                                _finding(
                                    "PG-RUNTIME-EFFECT-MISMATCH",
                                    "runtime",
                                    f"{phase.phase_id} runtime effects differ from its declaration",
                                )
                            )
                        if set(observed_objects) != set(phase.expected_objects):
                            findings.append(
                                _finding(
                                    "PG-RUNTIME-OBJECT-MISMATCH",
                                    "runtime",
                                    f"{phase.phase_id} mutated objects outside its declaration",
                                )
                            )

                if not findings:
                    preview = cluster.snapshot("proofos_preview", manifest.observed_tables)
                    preview_digest = _state_digest(preview)
                    for phase in manifest.phases:
                        cluster.apply_phase("proofos_apply", phase, artifacts[phase.phase_id].sql, manifest)
                    actual = cluster.snapshot("proofos_apply", manifest.observed_tables)
                    actual_digest = _state_digest(actual)
                    preview_matches_actual = preview == actual
                    if not preview_matches_actual:
                        findings.append(
                            _finding(
                                "PG-RUNTIME-PREVIEW-ACTUAL-MISMATCH",
                                "runtime",
                                "fresh apply state differs from preview state",
                            )
                        )

                if not findings:
                    for phase in reversed(manifest.phases):
                        artifact = artifacts[phase.phase_id]
                        if phase.rollback_type not in {
                            RollbackType.TRANSACTION,
                            RollbackType.COMPENSATING_SQL,
                        }:
                            findings.append(
                                _finding(
                                    "PG-ROLLBACK-NOT-EXECUTABLE",
                                    "rollback",
                                    f"{phase.phase_id} cannot prove executable rollback",
                                )
                            )
                            break
                        assert artifact.rollback_sql is not None
                        before_rollback = cluster.snapshot("proofos_apply", manifest.observed_tables)
                        cluster.apply_phase(
                            "proofos_apply", phase, artifact.rollback_sql, manifest, rollback=True
                        )
                        after_rollback = cluster.snapshot("proofos_apply", manifest.observed_tables)
                        evidence = evidence_by_id[phase.phase_id]
                        evidence.rollback_observed_effects = _state_effects(before_rollback, after_rollback)
                        evidence.rollback_observed_objects = _state_changed_objects(
                            before_rollback, after_rollback
                        )
                        evidence.rollback_state_digest = _state_digest(after_rollback)
                        if set(evidence.rollback_observed_effects) != set(phase.rollback_effects) or set(
                            evidence.rollback_observed_objects
                        ) != set(phase.rollback_expected_objects):
                            findings.append(
                                _finding(
                                    "PG-ROLLBACK-EFFECT-MISMATCH",
                                    "rollback",
                                    f"{phase.phase_id} rollback effects differ from its declaration",
                                )
                            )
                            break
                    if not findings:
                        rollback = cluster.snapshot("proofos_apply", manifest.observed_tables)
                        rollback_digest = _state_digest(rollback)
                        rollback_verified = rollback == baseline
                        if not rollback_verified:
                            findings.append(
                                _finding(
                                    "PG-ROLLBACK-STATE-MISMATCH",
                                    "rollback",
                                    "rollback SQL succeeded but did not restore baseline state",
                                )
                            )
        cleanup_verified = cluster.cleanup_verified
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
        if cluster is not None:
            cleanup_verified = cluster.cleanup_verified
        findings.append(_finding("PG-RUNTIME-EXECUTION-FAILED", "runtime", _safe_error(exc)))

    if not cleanup_verified:
        findings.append(
            _finding("PG-CLEANUP-UNVERIFIED", "cleanup", "disposable cluster cleanup was not verified")
        )
    decision: Literal["eligible", "blocked"] = "blocked" if findings else "eligible"
    return PostgresVerificationReceipt(
        contract=manifest.contract,
        artifact_id=manifest.artifact_id,
        decision=decision,
        source_bound=True,
        server_version=server_version,
        migration_role=manifest.migration_role,
        role_evidence=role_evidence,
        binary_digests=binary_digests,
        baseline_state_digest=baseline_digest,
        preview_state_digest=preview_digest,
        actual_state_digest=actual_digest,
        rollback_state_digest=rollback_digest,
        phases=phase_evidence,
        findings=findings,
        preview_matches_actual=preview_matches_actual,
        rollback_verified=rollback_verified,
        cleanup_verified=cleanup_verified,
        limitations=[
            "Disposable PostgreSQL proves bounded semantics, not production duration or disk cost.",
            "The research profile rejects SQL outside its conservative statement subset.",
            "Nontransactional lock evidence is static unless a later profile adds workload polling.",
        ],
    )


def _blocked_receipt(
    manifest: PostgresMigrationManifest,
    findings: list[Finding],
    phases: list[PhaseEvidence],
    *,
    cleanup_verified: bool,
) -> PostgresVerificationReceipt:
    return PostgresVerificationReceipt(
        contract=manifest.contract,
        artifact_id=manifest.artifact_id,
        decision="blocked",
        source_bound=not any(finding.stage == "source" for finding in findings),
        server_version=None,
        migration_role=manifest.migration_role,
        role_evidence=None,
        binary_digests={},
        baseline_state_digest=None,
        preview_state_digest=None,
        actual_state_digest=None,
        rollback_state_digest=None,
        phases=phases,
        findings=findings,
        preview_matches_actual=None,
        rollback_verified=None,
        cleanup_verified=cleanup_verified,
        limitations=["Runtime was not entered because fail-closed preflight rejected the artifact."],
    )


class _DisposablePostgres(AbstractContextManager["_DisposablePostgres"]):
    def __init__(self, binaries: PostgresBinaries, workspace: Path, *, deadline: float | None = None) -> None:
        self.binaries = binaries
        self.workspace = workspace.resolve()
        self.root: Path | None = None
        self.socket_dir: Path | None = None
        self.data_dir: Path | None = None
        self.home_dir: Path | None = None
        self.log_path: Path | None = None
        self.port = 49_152 + secrets.randbelow(16_000)
        self.deadline = deadline
        self.started = False
        self.cleanup_verified = False
        self.cleanup_errors: list[str] = []
        self.server_version = ""

    def __enter__(self) -> _DisposablePostgres:
        try:
            return self._start()
        except BaseException:
            self._teardown()
            raise

    def _start(self) -> _DisposablePostgres:
        self.root = Path(tempfile.mkdtemp(prefix="proofos-postgres-", dir=self.workspace))
        self.socket_dir = Path(tempfile.mkdtemp(prefix="proofos-pg-socket-", dir="/tmp"))
        self.data_dir = self.root / "data"
        self.home_dir = self.root / "home"
        self.log_path = self.root / "postgres.log"
        self.home_dir.mkdir(mode=0o700)
        self._run(
            [
                self.binaries.initdb,
                "-D",
                self.data_dir,
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
            ],
            database=None,
            timeout=30,
        )
        options = (
            f"-k {self.socket_dir} -h '' -p {self.port} -F "
            "-c unix_socket_permissions=0700 -c max_connections=20"
        )
        self._run(
            [
                self.binaries.pg_ctl,
                "-D",
                self.data_dir,
                "-l",
                self.log_path,
                "-o",
                options,
                "-w",
                "start",
            ],
            database=None,
            timeout=30,
        )
        self.started = True
        version = self._psql("postgres", "SHOW server_version;")
        self.server_version = version.strip()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._teardown()

    def _teardown(self) -> None:
        if self.cleanup_verified:
            return
        errors: list[str] = []
        root = self.root
        socket_dir = self.socket_dir
        should_stop = bool(
            self.data_dir is not None and (self.started or (self.data_dir / "postmaster.pid").exists())
        )
        stopped = not should_stop
        if should_stop and self.data_dir is not None:
            for mode in ("fast", "immediate"):
                try:
                    self._run(
                        [
                            self.binaries.pg_ctl,
                            "-D",
                            self.data_dir,
                            "-m",
                            mode,
                            "-w",
                            "stop",
                        ],
                        database=None,
                        timeout=30,
                        enforce_deadline=False,
                    )
                except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                    errors = [f"{mode} stop failed: {_safe_error(exc)}"]
                else:
                    errors = []
                    stopped = True
                    self.started = False
                    break
        if stopped:
            for path, label in ((root, "cluster"), (socket_dir, "socket")):
                if path is None or not path.exists():
                    continue
                try:
                    shutil.rmtree(path, ignore_errors=False)
                except OSError as exc:
                    errors.append(f"{label} cleanup failed: {_safe_error(exc)}")
        else:
            errors.append("server termination could not be verified; state was preserved")
        self.cleanup_errors = errors
        self.cleanup_verified = bool(
            stopped
            and root is not None
            and socket_dir is not None
            and not root.exists()
            and not socket_dir.exists()
            and not errors
        )

    def prepare_baseline(self, database: str, baseline_sql: str, manifest: PostgresMigrationManifest) -> None:
        self._run([self.binaries.createdb, database], database=None, timeout=30)
        setup = (
            "CREATE ROLE proofos_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS;\n"
            f"GRANT CONNECT, CREATE, TEMPORARY ON DATABASE {_quote_identifier(database)} "
            "TO proofos_migrator;\n"
            "REVOKE ALL ON SCHEMA public FROM PUBLIC;\n"
            "SET ROLE proofos_migrator;\n"
            f"SET search_path TO {self._search_path(manifest)};\n"
            f"SET lock_timeout = '{manifest.lock_timeout_ms}ms';\n"
            f"SET statement_timeout = '{manifest.statement_timeout_ms}ms';\n"
            f"{baseline_sql}\n"
            "RESET ROLE;\n"
        )
        self._psql(database, setup)
        self._enforce_fixture_limits(database, manifest.observed_tables)

    def clone_database(self, source: str, target: str) -> None:
        self._run([self.binaries.createdb, "--template", source, target], database=None, timeout=30)

    def _enforce_fixture_limits(self, database: str, observed_tables: Sequence[ObservedTable]) -> list[str]:
        inventory = self._table_inventory(database, observed_tables)
        for table in observed_tables:
            schema = _quote_identifier(table.schema_name)
            name = _quote_identifier(table.table_name)
            columns = int(
                self._psql(
                    database,
                    "SELECT count(*) FROM pg_catalog.pg_attribute a "
                    "JOIN pg_catalog.pg_class c ON c.oid = a.attrelid "
                    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                    f"WHERE n.nspname = {_sql_literal(table.schema_name)} "
                    f"AND c.relname = {_sql_literal(table.table_name)} "
                    "AND a.attnum > 0 AND NOT a.attisdropped;",
                ).strip()
            )
            rows = int(self._psql(database, f"SELECT count(*) FROM {schema}.{name};").strip())
            if columns > _MAX_FIXTURE_COLUMNS or rows > _MAX_FIXTURE_ROWS:
                raise RuntimeError("live baseline exceeds the bounded fixture dimensions")
        return inventory

    def role_evidence(self, database: str) -> RoleEvidence:
        output = self._psql(
            database,
            """
SET ROLE proofos_migrator;
SELECT jsonb_build_object(
  'declared_role', 'proofos_migrator',
  'observed_current_user', current_user,
  'superuser', rolsuper,
  'inherit', rolinherit,
  'create_role', rolcreaterole,
  'create_db', rolcreatedb,
  'login', rolcanlogin,
  'replication', rolreplication,
  'bypass_rls', rolbypassrls
)::text
FROM pg_catalog.pg_roles WHERE rolname = current_user;
""",
        )
        return RoleEvidence.model_validate_json(output.strip().splitlines()[-1])

    def transaction_preview(
        self, database: str, sql: str, manifest: PostgresMigrationManifest
    ) -> tuple[dict[str, object], list[LockMode]]:
        inventory = self._enforce_fixture_limits(database, manifest.observed_tables)
        snapshot_sql = self._snapshot_sql(manifest.observed_tables, inventory)
        lock_sql = (
            "SELECT COALESCE(jsonb_agg(DISTINCT l.mode ORDER BY l.mode), '[]'::jsonb)::text "
            "FROM pg_catalog.pg_locks l WHERE l.pid = pg_catalog.pg_backend_pid() "
            "AND l.granted AND l.relation IS NOT NULL;"
        )
        script = (
            "BEGIN;\n"
            "SET LOCAL ROLE proofos_migrator;\n"
            f"SET LOCAL search_path TO {self._search_path(manifest)};\n"
            f"SET LOCAL lock_timeout = '{manifest.lock_timeout_ms}ms';\n"
            f"SET LOCAL statement_timeout = '{manifest.statement_timeout_ms}ms';\n"
            f"{sql}\n"
            "\\echo __PROOFOS_SNAPSHOT__\n"
            f"{snapshot_sql}\n"
            "\\echo __PROOFOS_LOCKS__\n"
            f"{lock_sql}\n"
            "ROLLBACK;\n"
        )
        output = self._psql(database, script)
        snapshot_text = _after_marker(output, "__PROOFOS_SNAPSHOT__")
        locks_text = _after_marker(output, "__PROOFOS_LOCKS__")
        snapshot = cast(dict[str, object], json.loads(snapshot_text))
        lock_values = cast(list[str], json.loads(locks_text))
        known = [LockMode(value) for value in lock_values if value in _LOCK_RANK]
        return snapshot, sorted(set(known), key=lambda mode: _LOCK_RANK[mode.value])

    def apply_phase(
        self,
        database: str,
        phase: MigrationPhase,
        sql: str,
        manifest: PostgresMigrationManifest,
        *,
        rollback: bool = False,
    ) -> None:
        mode = phase.mode
        if rollback and "CONCURRENTLY" in {token.upper() for token in _tokens(sql)}:
            mode = MigrationMode.NONTRANSACTIONAL
        prefix = (
            "SET ROLE proofos_migrator;\n"
            f"SET search_path TO {self._search_path(manifest)};\n"
            f"SET lock_timeout = '{manifest.lock_timeout_ms}ms';\n"
            f"SET statement_timeout = '{manifest.statement_timeout_ms}ms';\n"
        )
        if mode is MigrationMode.TRANSACTIONAL:
            script = f"BEGIN;\n{prefix}{sql}\nCOMMIT;\n"
        else:
            script = f"{prefix}{sql}\n"
        self._psql(database, script)

    def snapshot(self, database: str, observed_tables: Sequence[ObservedTable]) -> dict[str, object]:
        inventory = self._enforce_fixture_limits(database, observed_tables)
        output = self._psql(database, self._snapshot_sql(observed_tables, inventory))
        return cast(dict[str, object], json.loads(output.strip().splitlines()[-1]))

    def _table_inventory(self, database: str, observed_tables: Sequence[ObservedTable]) -> list[str]:
        schemas = sorted({table.schema_name for table in observed_tables})
        schema_literals = ", ".join(_sql_literal(schema) for schema in schemas)
        output = self._psql(
            database,
            "SELECT n.nspname || '.' || c.relname "
            "FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            f"WHERE n.nspname IN ({schema_literals}) AND c.relkind IN ('r', 'p') "
            "ORDER BY n.nspname, c.relname;",
        )
        inventory = [line.strip() for line in output.splitlines() if line.strip()]
        declared = sorted(table.qualified_name for table in observed_tables)
        if inventory != declared:
            raise RuntimeError("runtime table inventory differs from the bound baseline inventory")
        return inventory

    def _snapshot_sql(self, observed_tables: Sequence[ObservedTable], table_inventory: Sequence[str]) -> str:
        schemas = sorted({table.schema_name for table in observed_tables})
        schema_literals = ", ".join(_sql_literal(schema) for schema in schemas)
        table_config = {table.qualified_name: table for table in observed_tables}
        data_pairs: list[str] = []
        for qualified_name in table_inventory:
            table = table_config[qualified_name]
            schema = _quote_identifier(table.schema_name)
            name = _quote_identifier(table.table_name)
            order = ", ".join(f"t.{_quote_identifier(column)}" for column in table.order_by)
            data_pairs.extend(
                [
                    _sql_literal(table.qualified_name),
                    "(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY "
                    f"{order}), '[]'::jsonb) FROM {schema}.{name} t)",
                ]
            )
        data_json = ", ".join(data_pairs)
        return f"""
SELECT jsonb_build_object(
  'columns', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname, a.attname,
      pg_catalog.format_type(a.atttypid, a.atttypmod), a.attnotnull,
      pg_catalog.pg_get_expr(ad.adbin, ad.adrelid))
      ORDER BY n.nspname, c.relname, a.attnum)
    FROM pg_catalog.pg_attribute a
    JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = c.oid AND ad.adnum = a.attnum
    WHERE n.nspname IN ({schema_literals}) AND c.relkind IN ('r', 'p')
      AND a.attnum > 0 AND NOT a.attisdropped
  ), '[]'::jsonb),
  'constraints', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname, con.conname,
      con.convalidated, pg_catalog.pg_get_constraintdef(con.oid, true))
      ORDER BY n.nspname, c.relname, con.conname)
    FROM pg_catalog.pg_constraint con
    JOIN pg_catalog.pg_class c ON c.oid = con.conrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ({schema_literals})
  ), '[]'::jsonb),
  'indexes', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname, i.relname,
      ix.indisvalid, ix.indisready, pg_catalog.pg_get_indexdef(i.oid))
      ORDER BY n.nspname, c.relname, i.relname)
    FROM pg_catalog.pg_index ix
    JOIN pg_catalog.pg_class c ON c.oid = ix.indrelid
    JOIN pg_catalog.pg_class i ON i.oid = ix.indexrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ({schema_literals})
  ), '[]'::jsonb),
  'sequences', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(schemaname, sequencename, last_value)
      ORDER BY schemaname, sequencename)
    FROM pg_catalog.pg_sequences WHERE schemaname IN ({schema_literals})
  ), '[]'::jsonb),
  'owners', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname, r.rolname)
      ORDER BY n.nspname, c.relname)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
    WHERE n.nspname IN ({schema_literals}) AND c.relkind IN ('r', 'S')
  ), '[]'::jsonb),
  'table_security', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname,
      c.relrowsecurity, c.relforcerowsecurity) ORDER BY n.nspname, c.relname)
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname IN ({schema_literals}) AND c.relkind IN ('r', 'p')
  ), '[]'::jsonb),
  'acls', jsonb_build_object(
    'schemas', COALESCE((
      SELECT jsonb_agg(jsonb_build_array(nspname, COALESCE(nspacl::text, '')) ORDER BY nspname)
      FROM pg_catalog.pg_namespace WHERE nspname IN ({schema_literals})
    ), '[]'::jsonb),
    'relations', COALESCE((
      SELECT jsonb_agg(jsonb_build_array(n.nspname, c.relname, COALESCE(c.relacl::text, ''))
        ORDER BY n.nspname, c.relname)
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname IN ({schema_literals}) AND c.relkind IN ('r', 'S')
    ), '[]'::jsonb)
  ),
  'role_flags', COALESCE((
    SELECT jsonb_agg(jsonb_build_array(rolname, rolsuper, rolinherit, rolcreaterole,
      rolcreatedb, rolcanlogin, rolreplication, rolbypassrls) ORDER BY rolname)
    FROM pg_catalog.pg_roles WHERE rolname = 'proofos_migrator'
  ), '[]'::jsonb),
  'data', jsonb_build_object({data_json})
)::text;
"""

    def _search_path(self, manifest: PostgresMigrationManifest) -> str:
        return ", ".join(_quote_identifier(value) for value in manifest.fixed_search_path)

    def _psql(self, database: str, sql: str) -> str:
        if self.root is None:
            raise RuntimeError("disposable runtime has not been initialized")
        script_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="psql-",
                suffix=".sql",
                dir=self.root,
                delete=False,
            ) as script:
                script.write(sql)
                script_path = Path(script.name)
            script_path.chmod(0o600)
            result = self._run(
                [
                    self.binaries.psql,
                    "-X",
                    "-q",
                    "-A",
                    "-t",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    script_path,
                    database,
                ],
                database=database,
                timeout=150,
            )
            return result.stdout
        finally:
            if script_path is not None:
                script_path.unlink(missing_ok=True)

    def _run(
        self,
        command: Sequence[Path | str],
        *,
        database: str | None,
        timeout: int,
        enforce_deadline: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if self.home_dir is None or self.socket_dir is None:
            home = self.workspace
            socket_dir = self.workspace
        else:
            home = self.home_dir
            socket_dir = self.socket_dir
        env = {
            "HOME": str(home),
            "LC_ALL": "C",
            "LANG": "C",
            "PATH": str(self.binaries.bindir),
            "PGHOST": str(socket_dir),
            "PGPORT": str(self.port),
            "PGUSER": getpass.getuser(),
            "PGAPPNAME": "proofos-postgres-research",
        }
        if database is not None:
            env["PGDATABASE"] = database
        args = [str(item) for item in command]
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        effective_timeout = float(timeout)
        if enforce_deadline and self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise subprocess.TimeoutExpired(process.args, 0)
            effective_timeout = min(effective_timeout, remaining)
        stdout, stderr = _bounded_process_output(process, timeout=effective_timeout)
        assert process.returncode is not None
        result = subprocess.CompletedProcess(
            args=args,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip().splitlines()[-1:]
            diagnostic = detail[0] if detail else "no diagnostic"
            if self.root is not None:
                diagnostic = diagnostic.replace(str(self.root), "<runtime>")
            if self.socket_dir is not None:
                diagnostic = diagnostic.replace(str(self.socket_dir), "<socket>")
            raise RuntimeError(f"PostgreSQL command failed with exit {result.returncode}: {diagnostic}")
        return result


def _classify_statement(
    upper: Sequence[str],
) -> tuple[str | None, set[Effect], LockMode, bool]:
    prefix = tuple(upper[:4])
    if prefix[:2] == ("ALTER", "TABLE"):
        if "VALIDATE" in upper and "CONSTRAINT" in upper:
            return (
                "alter-table-validate-constraint",
                {Effect.SCHEMA},
                LockMode.SHARE_UPDATE_EXCLUSIVE,
                False,
            )
        if "ADD" in upper and "COLUMN" in upper:
            return "alter-table-add-column", {Effect.SCHEMA}, LockMode.ACCESS_EXCLUSIVE, False
        if "ADD" in upper and "CONSTRAINT" in upper:
            return "alter-table-add-constraint", {Effect.SCHEMA}, LockMode.ACCESS_EXCLUSIVE, False
        if "DROP" in upper and "COLUMN" in upper:
            return "alter-table-drop-column", {Effect.SCHEMA}, LockMode.ACCESS_EXCLUSIVE, False
        if "DROP" in upper and "CONSTRAINT" in upper:
            return "alter-table-drop-constraint", {Effect.SCHEMA}, LockMode.ACCESS_EXCLUSIVE, False
    if prefix[:3] == ("CREATE", "INDEX", "CONCURRENTLY"):
        return (
            "create-index-concurrently",
            {Effect.INDEX},
            LockMode.SHARE_UPDATE_EXCLUSIVE,
            True,
        )
    if prefix[:3] == ("DROP", "INDEX", "CONCURRENTLY"):
        return (
            "drop-index-concurrently",
            {Effect.INDEX},
            LockMode.SHARE_UPDATE_EXCLUSIVE,
            True,
        )
    if prefix[:1] == ("UPDATE",):
        return "update", {Effect.DATA}, LockMode.ROW_EXCLUSIVE, False
    if prefix[:1] == ("SELECT",) and ({"NEXTVAL", "SETVAL"} & set(upper)):
        return "sequence-operation", {Effect.SEQUENCE}, LockMode.ROW_EXCLUSIVE, False
    return None, set(), LockMode.ACCESS_SHARE, False


def _extract_touched_object(statement: str, kind: str) -> str | None:
    identifier = r'"?([a-z_][a-z0-9_]*)"?'
    if kind == "create-index-concurrently":
        match = re.search(
            rf"^\s*CREATE\s+INDEX\s+CONCURRENTLY\s+"
            rf'"?([a-z_][a-z0-9_]*)"?\s+ON\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}',
            statement,
            flags=re.IGNORECASE,
        )
        if match is None:
            return None
        return f"{match.group(2).lower()}.{match.group(1).lower()}"
    patterns = {
        "alter-table-add-column": rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}",
        "alter-table-add-constraint": rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}",
        "alter-table-drop-column": rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}",
        "alter-table-drop-constraint": rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}",
        "alter-table-validate-constraint": (
            rf"^\s*ALTER\s+TABLE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}"
        ),
        "drop-index-concurrently": (
            rf"^\s*DROP\s+INDEX\s+CONCURRENTLY\s+(?:IF\s+EXISTS\s+)?"
            rf"{identifier}\s*\.\s*{identifier}"
        ),
        "update": rf"^\s*UPDATE\s+(?:ONLY\s+)?{identifier}\s*\.\s*{identifier}",
        "sequence-operation": rf"\b(?:nextval|setval)\s*\(\s*'{identifier}\s*\.\s*{identifier}'",
    }
    pattern = patterns.get(kind)
    if pattern is None:
        return None
    match = re.search(pattern, statement, flags=re.IGNORECASE)
    if match is None:
        return None
    return f"{match.group(1).lower()}.{match.group(2).lower()}"


def _disallowed_functions(statement: str, kind: str) -> list[str]:
    scrubbed = re.sub(r"'(?:''|[^'])*'", " STRING ", statement)
    if kind == "create-index-concurrently":
        scrubbed = re.sub(
            r"\bON\s+(?:ONLY\s+)?\"?[a-z_][a-z0-9_]*\"?\s*\.\s*"
            r'"?[a-z_][a-z0-9_]*"?\s*\(',
            "ON (",
            scrubbed,
            flags=re.IGNORECASE,
        )
    calls = {
        ".".join(part for part in match.groups() if part).lower()
        for match in re.finditer(
            r"(?:(\b[a-z_][a-z0-9_]*)\s*\.\s*)?\b([a-z_][a-z0-9_]*)\s*\(",
            scrubbed,
            flags=re.IGNORECASE,
        )
    }
    calls -= {"check", "on"}
    allowed = {
        "alter-table-add-column": {"length"},
        "alter-table-add-constraint": {"length"},
        "alter-table-drop-column": set(),
        "alter-table-drop-constraint": set(),
        "alter-table-validate-constraint": set(),
        "create-index-concurrently": {"lower"},
        "drop-index-concurrently": set(),
        "update": {"pg_catalog.txid_current"},
        "sequence-operation": {"nextval", "setval"},
    }.get(kind, set())
    return sorted(calls - allowed)


def _baseline_disallowed_functions(statement: str) -> list[str]:
    scrubbed = re.sub(r"'(?:''|[^'])*'", " STRING ", statement)
    scrubbed = re.sub(
        r"^\s*CREATE\s+TABLE\s+[a-z_][a-z0-9_]*\s*\.\s*[a-z_][a-z0-9_]*\s*\(",
        "CREATE TABLE (",
        scrubbed,
        flags=re.IGNORECASE,
    )
    scrubbed = re.sub(
        r"^\s*INSERT\s+INTO\s+[a-z_][a-z0-9_]*\s*\.\s*[a-z_][a-z0-9_]*\s*\(",
        "INSERT INTO (",
        scrubbed,
        flags=re.IGNORECASE,
    )
    calls = {
        ".".join(part for part in match.groups() if part).lower()
        for match in re.finditer(
            r"(?:(\b[a-z_][a-z0-9_]*)\s*\.\s*)?\b([a-z_][a-z0-9_]*)\s*\(",
            scrubbed,
            flags=re.IGNORECASE,
        )
    }
    return sorted(calls - {"check", "into", "table", "values"})


def _baseline_table_target(statement: str, prefix: str) -> str | None:
    escaped = r"\s+".join(re.escape(part) for part in prefix.split())
    match = re.search(
        rf'^\s*{escaped}\s+"?([a-z_][a-z0-9_]*)"?\s*\.\s*'
        r'"?([a-z_][a-z0-9_]*)"?',
        statement,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    return f"{match.group(1).lower()}.{match.group(2).lower()}"


def _baseline_has_parenthesized_shape(statement: str, prefix: str) -> bool:
    escaped = r"\s+".join(re.escape(part) for part in prefix.split())
    match = re.match(
        rf"^\s*{escaped}\s+[a-z_][a-z0-9_]*\s*\.\s*[a-z_][a-z0-9_]*\s*\(",
        statement,
        flags=re.IGNORECASE,
    )
    if match is None:
        return False
    end = _matching_parenthesis_end(statement, match.end() - 1)
    if end is None:
        return False
    trailing = statement[end:].strip()
    if prefix == "CREATE TABLE":
        return trailing == ""
    if prefix != "INSERT INTO" or not trailing.upper().startswith("VALUES"):
        return False
    values = trailing[len("VALUES") :].strip()
    while values:
        if not values.startswith("("):
            return False
        tuple_end = _matching_parenthesis_end(values, 0)
        if tuple_end is None:
            return False
        values = values[tuple_end:].strip()
        if not values:
            return True
        if not values.startswith(","):
            return False
        values = values[1:].strip()
    return False


def _baseline_parenthesized_item_count(statement: str, prefix: str) -> int:
    escaped = r"\s+".join(re.escape(part) for part in prefix.split())
    match = re.match(
        rf"^\s*{escaped}\s+[a-z_][a-z0-9_]*\s*\.\s*[a-z_][a-z0-9_]*\s*\(",
        statement,
        flags=re.IGNORECASE,
    )
    if match is None:
        return _MAX_FIXTURE_COLUMNS + 1
    opening = match.end() - 1
    end = _matching_parenthesis_end(statement, opening)
    if end is None:
        return _MAX_FIXTURE_COLUMNS + 1
    return _top_level_item_count(statement[opening + 1 : end - 1])


def _baseline_values_row_count(statement: str) -> int:
    escaped = r"\s+".join(re.escape(part) for part in "INSERT INTO".split())
    match = re.match(
        rf"^\s*{escaped}\s+[a-z_][a-z0-9_]*\s*\.\s*[a-z_][a-z0-9_]*\s*\(",
        statement,
        flags=re.IGNORECASE,
    )
    if match is None:
        return _MAX_FIXTURE_ROWS + 1
    columns_end = _matching_parenthesis_end(statement, match.end() - 1)
    if columns_end is None:
        return _MAX_FIXTURE_ROWS + 1
    values = statement[columns_end:].strip()
    if not values.upper().startswith("VALUES"):
        return _MAX_FIXTURE_ROWS + 1
    values = values[len("VALUES") :].strip()
    rows = 0
    while values:
        if not values.startswith("("):
            return _MAX_FIXTURE_ROWS + 1
        tuple_end = _matching_parenthesis_end(values, 0)
        if tuple_end is None:
            return _MAX_FIXTURE_ROWS + 1
        rows += 1
        values = values[tuple_end:].strip()
        if not values:
            return rows
        if not values.startswith(","):
            return _MAX_FIXTURE_ROWS + 1
        values = values[1:].strip()
    return _MAX_FIXTURE_ROWS + 1


def _top_level_item_count(value: str) -> int:
    if not value.strip():
        return 0
    depth = 0
    count = 1
    for token in _tokens(value):
        if token == "(":
            depth += 1
        elif token == ")":
            depth = max(0, depth - 1)
        elif token == "," and depth == 0:
            count += 1
    return count


def _max_sql_literal_bytes(sql: str) -> int:
    literals = re.findall(r"'(?:''|[^'])*'", sql)
    return max(
        (len(literal[1:-1].replace("''", "'").encode()) for literal in literals),
        default=0,
    )


def _matching_parenthesis_end(value: str, opening: int) -> int | None:
    depth = 0
    state = "normal"
    index = opening
    while index < len(value):
        char = value[index]
        next_char = value[index + 1] if index + 1 < len(value) else ""
        if state == "normal":
            if char == "'":
                state = "single"
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index + 1
        elif char == "'" and next_char == "'":
            index += 1
        elif char == "'":
            state = "normal"
        index += 1
    return None


def _split_statements(sql: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    index = 0
    state = "normal"
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if state == "normal":
            if char == "'":
                state = "single"
                current.append(char)
            elif char == '"':
                state = "double"
                current.append(char)
            elif char == "-" and next_char == "-":
                state = "line-comment"
                index += 1
            elif char == "/" and next_char == "*":
                state = "block-comment"
                index += 1
            elif char == ";":
                value = "".join(current).strip()
                if value:
                    statements.append(value)
                current = []
            else:
                current.append(char)
        elif state == "single":
            current.append(char)
            if char == "'" and next_char == "'":
                current.append(next_char)
                index += 1
            elif char == "'":
                state = "normal"
        elif state == "double":
            current.append(char)
            if char == '"' and next_char == '"':
                current.append(next_char)
                index += 1
            elif char == '"':
                state = "normal"
        elif state == "line-comment":
            if char == "\n":
                state = "normal"
                current.append(" ")
        elif state == "block-comment" and char == "*" and next_char == "/":
            state = "normal"
            current.append(" ")
            index += 1
        index += 1
    if state in {"single", "double", "block-comment"}:
        return []
    value = "".join(current).strip()
    if value:
        statements.append(value)
    return statements


def _tokens(statement: str) -> list[str]:
    scrubbed = re.sub(r"'(?:''|[^'])*'", " STRING ", statement)
    return re.findall(r"[A-Za-z_][A-Za-z0-9_$]*|\.|[,()]", scrubbed)


def _has_top_level_comma(statement: str) -> bool:
    depth = 0
    for token in _tokens(statement):
        if token == "(":
            depth += 1
        elif token == ")":
            depth = max(0, depth - 1)
        elif token == "," and depth == 0:
            return True
    return False


def _quote_identifier(value: str) -> str:
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", value):
        raise ValueError("unsafe SQL identifier")
    return f'"{value}"'


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _after_marker(output: str, marker: str) -> str:
    lines = [line.strip() for line in output.splitlines()]
    try:
        index = lines.index(marker)
    except ValueError as exc:
        raise RuntimeError(f"missing verifier marker {marker}") from exc
    for line in lines[index + 1 :]:
        if line and not line.startswith("__PROOFOS_"):
            return line
    raise RuntimeError(f"missing verifier output after {marker}")


def _state_digest(state: Mapping[str, object]) -> Digest:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    return digest_bytes(canonical)


def _state_effects(before: Mapping[str, object], after: Mapping[str, object]) -> list[Effect]:
    effects: set[Effect] = set()
    schema_changed = any(before.get(key) != after.get(key) for key in ("columns", "constraints"))
    if schema_changed:
        effects.add(Effect.SCHEMA)
    if before.get("indexes") != after.get("indexes"):
        effects.add(Effect.INDEX)
    if before.get("sequences") != after.get("sequences"):
        effects.add(Effect.SEQUENCE)
    if any(before.get(key) != after.get(key) for key in ("owners", "table_security", "acls", "role_flags")):
        effects.add(Effect.PERMISSION)
    if not schema_changed and before.get("data") != after.get("data"):
        effects.add(Effect.DATA)
    return sorted(effects, key=lambda effect: effect.value)


def _state_changed_objects(before: Mapping[str, object], after: Mapping[str, object]) -> list[str]:
    changed: set[str] = set()
    before_data = cast(dict[str, object], before.get("data", {}))
    after_data = cast(dict[str, object], after.get("data", {}))
    for name in set(before_data) | set(after_data):
        if before_data.get(name) != after_data.get(name):
            changed.add(name)
    for key, name_positions in {
        "columns": (0, 1),
        "constraints": (0, 1),
        "indexes": (0, 2),
        "sequences": (0, 1),
        "owners": (0, 1),
        "table_security": (0, 1),
    }.items():
        before_rows = {json.dumps(row, sort_keys=True) for row in cast(list[object], before.get(key, []))}
        after_rows = {json.dumps(row, sort_keys=True) for row in cast(list[object], after.get(key, []))}
        for encoded in before_rows ^ after_rows:
            row = cast(list[object], json.loads(encoded))
            changed.add(f"{row[name_positions[0]]}.{row[name_positions[1]]}")
    if before.get("acls") != after.get("acls") or before.get("role_flags") != after.get("role_flags"):
        changed.add("<authority>")
    return sorted(changed)


def _finding(code: str, stage: str, detail: str) -> Finding:
    return Finding(code=code, stage=stage, detail=detail)  # type: ignore[arg-type]


def _safe_error(exc: BaseException) -> str:
    text = str(exc).replace(str(Path.home()), "<home>")
    return text[:500]


def _bounded_process_output(process: subprocess.Popen[bytes], *, timeout: float) -> tuple[str, str]:
    assert process.stdout is not None
    assert process.stderr is not None
    streams = selectors.DefaultSelector()
    streams.register(process.stdout, selectors.EVENT_READ, "stdout")
    streams.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise subprocess.TimeoutExpired(process.args, timeout)
            for key, _ in streams.select(min(remaining, 0.25)):
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    streams.unregister(key.fileobj)
                    continue
                target = cast(str, key.data)
                buffers[target].extend(chunk)
                if sum(len(buffer) for buffer in buffers.values()) > _MAX_CAPTURE_BYTES:
                    process.kill()
                    process.wait(timeout=5)
                    raise RuntimeError("PostgreSQL command exceeded the output byte cap")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            process.wait(timeout=5)
            raise subprocess.TimeoutExpired(process.args, timeout)
        process.wait(timeout=remaining)
    finally:
        streams.close()
    return (
        buffers["stdout"].decode("utf-8", errors="replace"),
        buffers["stderr"].decode("utf-8", errors="replace"),
    )
