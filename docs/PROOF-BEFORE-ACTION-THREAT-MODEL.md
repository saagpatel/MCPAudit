# Proof Before Action Threat Model

## Assets and trust boundaries

The protected assets are host files and credentials, host databases, network
authority, the reviewed repository, mcp-trust evidence, capsule integrity, and
operator understanding. Untrusted inputs include the command, repository
contents, tool configuration, dependency names, command output, and any existing
capsule.

The implementation has four relevant boundaries:

1. the macOS host and local Docker client;
2. the Colima Linux VM;
3. the restricted Docker container;
4. the exported evidence directory.

The container is disposable. The Colima VM is not treated as a security
boundary equivalent to a fresh mountless VM.

## Enforced controls

- The untrusted command executes only in the container.
- Docker image lookup is local-only; the tool never pulls an image.
- The runtime container has network mode `none`, a read-only image root, no
  host mounts, no forwarded sockets, no inherited host environment,
  `no-new-privileges`, and CPU, memory, PID, time, and tmpfs bounds.
- A fixed root-owned PID 1 observer retains only `KILL`, `SETGID`, `SETPCAP`,
  and `SETUID` so it can protect the evidence tmpfs, empty the tested command's
  capability bounding set, launch it as UID/GID `65534:65534`, enforce its
  deadline, and terminate surviving descendants.
- The tested command's actual UID/GID tuples, supplementary groups, all five
  Linux capability masks, and `NoNewPrivs` value are captured from `/proc`
  through a pre-opened evidence descriptor that is closed before the declared
  command starts. Any missing or nonconforming profile blocks inspection.
- PID 1 uses a fixed observer `PATH` that excludes the writable workspace, then
  verifies that every task of every command descendant is terminal before
  streaming one attached workspace/evidence archive. A failed quiescence
  readback blocks the inspection.
- Container configuration is read back and mismatches block execution.
- Known secret-bearing files, detected literal credentials, non-UTF-8/binary
  assets, databases not clearly named as synthetic SQLite fixtures, and every
  input symlink are rejected before staging.
- Repository and evidence collection have file-count and byte bounds.
- Runtime archive collection rejects path traversal, links, and special files.
- Raw stdout and stderr are omitted. Arguments receive best-effort secret-option
  redaction. Output is redirected through a bounded in-container file before
  hashing. Config environment/header values are never retained.
- Network effects are tested only with synthetic loopback attempts. The product
  has no external-network test mode.
- Offline HTML uses escaped text, no JavaScript, and a restrictive CSP.
- Capsule, artifact, payload, subject-commit, producer-commit, schema, and
  optional external-root checks fail closed.
- Distribution builds embed producer revision and dirty-state metadata; source
  checkout discovery requires the executing module to be under the exact Git
  root instead of accepting an arbitrary ancestor repository.
- Every required mcp-trust input is read back from the recorded trust commit and
  compared byte-for-byte before grade details can remain authoritative.

## Residual threats and honest unknowns

| Threat or surface | Status | Consequence |
| --- | --- | --- |
| Container, VM, or hypervisor escape | Unknown | Could bypass the container controls. A capsule records containment as `partial`. |
| Current Colima VM host sharing | Not a proven isolation boundary | The VM may expose broader host-adjacent state than the runtime container. A hostile-kernel test should use a fresh mountless VM instead. |
| macOS Keychain, TCC, XPC, Apple Events, GUI, devices, and host kernel | Unobserved | The Linux fixture cannot justify claims about these surfaces. |
| Transient create-delete or write-restore | Unobserved | Final-state hashing can miss an attempt that leaves no persisted delta. |
| Nested or very short-lived child processes | Final state quiesced; identity attribution incomplete | Surviving descendants are terminated before the final archive, but child executable identities and transient effects are not completely attributed. |
| SQLite transactions with no final delta | Unobserved | Semantic comparison proves final content, not every query or transaction attempt. |
| Non-SQLite databases | File-level only | Semantic records and remote database effects are unknown. |
| Network destination | Unobserved | Namespace counters reveal common IP/TCP/UDP attempts, not the requested hostname or endpoint. |
| Loopback inside the namespace | Available | A command can contact its own processes; the evidence marks attempts but does not call loopback external contact. |
| Output links or special files | Fail-closed | Collection stops; the effect is not silently omitted and no completed capsule is issued. |
| Unknown secret formats or low-entropy secret hashes | Residual risk | Redaction is best effort, and a digest can sometimes be guessed. Review declarations and commands before sharing capsules. |
| Malicious local Docker daemon or image | Trusted locally | A local image can contain hostile infrastructure. Pin and independently verify the image digest. |
| Internal capsule hashes | Consistency only | They do not prove who authorized the capsule. Record the index root in an external authority channel. |
| mcp-trust grade applicability | Evidence-limited | Stale, masked, missing, version-unbound, dirty, ignored/untracked, or commit-mismatched evidence remains unknown. |
| Producer build metadata | Evidence-limited | A clean embedded revision binds packaged code to its build source claim, but package authenticity still requires a trusted distribution channel or an externally anchored capsule root. |

## False claims the product must not make

A successful run means the persisted regular-file/SQLite state and observable
network counters matched the declaration within this container experiment. It
does not mean the command is safe, cannot mutate, is sandboxed on macOS, is free
of data exfiltration paths, or is approved for release.

`pass` is a deterministic comparison result. Release authority still belongs to
the operator and must account for every recorded limitation and unknown.

## Safer high-risk profile

For deliberately hostile native code or kernel-focused testing, use a freshly
created VM with no host-directory sharing, no host sockets, no credentials, no
external network interface, an immutable input image, and destruction after
evidence extraction. That profile is deliberately outside this finite local
developer tool until it has its own live, repeatable isolation proof.
