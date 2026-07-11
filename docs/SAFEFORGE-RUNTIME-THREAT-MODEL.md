# SafeForge Runtime Threat Model

## Decision

SafeForge runtime verification uses a narrow macOS Seatbelt provider for the
credential-free research profile. The provider is eligible only when
`sandbox-exec` is present and an executable self-test proves that the sandbox
denies user-home reads, user-home writes, and all network access.

The provider does not claim that a normal subprocess, a temporary directory, or
an MCP client timeout is a sandbox. If the kernel policy cannot be installed or
any self-test fails, `sandbox.prepare` is `blocked` and no generated code runs.

The current provider supports only receipts whose declared egress set is empty.
macOS Seatbelt has not been proven here to enforce redirect-safe DNS hostname
allowlists, so declared-network fixtures fail closed rather than weakening the
network policy.

## Assets and trust boundary

Protected host assets include:

- credential files, keychains, browser profiles, MCP client configuration, and
  private transcripts;
- source repositories and unrelated home-directory data;
- host network reachability and local listening services;
- host process mutation through generated child processes.

Trusted inputs are the MCPAudit coordinator, the verified ForgeReceiptV0, the
receipt-bound artifact tree, the committed dependency lock, the Seatbelt
profile builder, and the resource-limit supervisor. Generated source, generated
tests, the generated MCP server, and every descendant process are untrusted.

## Boundary construction

Each run receives a new directory beneath the system temporary directory. It
contains only the receipt-bound artifact copy, an empty HOME, isolated cache and
temporary directories, an isolated virtual environment, structured evidence,
and a generated Seatbelt profile.

Before generated code can run, the coordinator:

1. revalidates the receipt and artifact tree;
2. requires and verifies the dependency-lock digest;
3. prepares a disposable dependency cache from the exact lock without running
   generated code, after restricting registry and distribution URLs to HTTPS
   PyPI and `files.pythonhosted.org` with SHA-256 hashes;
4. invokes dependency materialization inside Seatbelt with network disabled;
5. verifies the installed distribution set against the lock;
6. rehashes the materialized artifact tree before and after generated execution.

The Seatbelt policy denies all networking, denies reads from user homes,
mounted volumes, and keychain storage, and denies writes by default. It allows
writes only inside the disposable root, while separately denying keychain
service lookup.
Generated tests and the connected MCP session run under a stricter profile that
kernel-denies process creation. The MCP server is launched through FastMCP's
in-memory protocol transport, which still performs MCP initialization and
capability requests without granting generated code a child process to detach.

The supervisor starts a new process session and applies CPU, file-size,
open-file, and core-dump limits. It also enforces wall time, aggregate resident
memory, process count, and disposable-root disk usage. A breached
limit kills the entire process group. Cleanup kills remaining descendants and
removes the run root after pass, failure, crash, timeout, or coordinator
cancellation.

## Fail-closed checks

SafeForge blocks on any of the following:

- missing or changed receipt, artifact, dependency manifest, or lock digest;
- unverified Seatbelt availability or a failed denial self-test;
- any declared or observed egress for the no-network provider;
- dependency resolution that is not locked or not offline during materialize;
- generated tests that fail, hang, attempt to fork, exhaust a
  resource limit, resist shutdown, or escape the artifact root;
- MCP initialization failure, protocol mismatch, or capability enumeration
  failure;
- runtime tools, prompts, resources, schemas, or annotations that differ from
  the receipt and ToolBOM;
- a connected audit warning, failure, hidden capability, unexpected child
  process, or incomplete cleanup;
- a stale grade, policy not bound to exact artifact and audit digests, a dry-run
  publication mutation, or incomplete final evidence.

## Executable acceptance plan

The test suite must deterministically cover:

1. benign credential-free echo: materialize, generated tests, MCP negotiation,
   capability enumeration, synthetic tool call, connected audit, grade,
   policy, publication dry run, and final receipt all pass;
2. post-receipt artifact and lock substitution: blocked before execution;
3. undeclared filesystem access and artifact-root escape: kernel denial and a
   failed runtime decision;
4. declared, undeclared, dynamic, and redirected egress: blocked before or by
   the no-network boundary;
5. runtime-only tool, schema, prompt, resource, or annotation change: connected
   evidence mismatch and no final receipt;
6. hanging, forking, resource-exhausting, crash, and shutdown-resistant
   processes: limit evidence, process-group termination, and clean removal;
7. additive and breaking producer-contract changes: contract gate blocks;
8. contradictory read-only, destructive, idempotent, and open-world
   annotations: trust grade and policy fail closed;
9. deterministic replay: identical inputs produce identical canonical results;
10. privacy: structured outputs contain no absolute home path, environment
    value, source text, or private file content.

## Proven limitation

This architecture proves the credential-free, zero-egress research profile. It
does not prove hostile-kernel isolation, a process-metadata namespace,
VM/container isolation, Windows/Linux parity, or redirect-safe hostname
allowlisting. Child-process creation is denied instead of relying on a PID
namespace. Receipts outside this profile remain `blocked` or `unknown`; they
cannot finalize as `eligible`.
