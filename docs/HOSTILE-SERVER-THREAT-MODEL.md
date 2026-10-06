# Connected-scan threat model

## What a hostile server can do to the scanner

A connected scan executes configured stdio commands with the scanner user's
authority, or contacts a configured HTTP/SSE endpoint. Read-only auditing means
the scanner does not deliberately edit client configuration or invoke ordinary
tools. It does not sandbox server code. A server can read or change files and
use the network independently of the scanner's listing requests. Canary mode
also calls eligible tools and fetches eligible prompt bodies.

Server metadata and protocol bytes are untrusted. The synthetic hostile fixture
covers stalled initialization/listings, ignored termination, slow bytes, malformed
JSON, mismatched response IDs, crashes, banners, notification/stderr floods,
infinite pagination, deep schemas, large enums/descriptions, oversized frames,
unterminated lines, ANSI/OSC/Rich/HTML payloads, and surviving child processes.
Returned file URIs and links are inert metadata; these fixtures never follow them.

Current output protections sanitize terminal controls and render markup literally,
escape HTML, and capture stderr in a bounded tail. These protections do not impose
a frame-size or analysis budget. Large descriptions can consume substantial CPU
after the connection timeout; large protocol frames can amplify memory use.
Launching hundreds of servers together can exhaust the timeout before responsive
servers get scheduled. A crashed process leader can leave a child holding its
pipes. A child that creates a new session escapes process-group cleanup entirely:
detached grandchildren need an OS/container sandbox, not a scanner guarantee.
Connection success and clean findings do not establish server safety.

The fixture itself has a narrower boundary: it requires an explicit disposable
working directory and HOME, denies socket operations and file opens outside that
directory (except the null device), and only spawns fixed 60-second Python
sleepers. It writes PID/group ledgers for those owned processes. Payload URLs use
reserved `.example.test` names; no network requests, credentials, or real home
files are used. The harness launches only these local servers from an explicit
synthetic config, with `--config-only` and a task-owned empty override. Scanner
and fixture environments are constructed from an allowlist, without inheriting
credential variables. The harness observes leftovers **before** cleaning them;
cleanup cannot make the scanner's measurement pass. Process-query permission
errors fail the gate rather than claiming zero leftovers.

## Performance regression gate

Run the five cases explicitly (ordinary pytest runs deselect the `perf` marker):

```sh
uv run --offline --no-sync pytest tests/test_hostile_perf.py -m perf -q -s \
  -p no:cacheprovider --perf-profile=baseline --perf-output=build/perf
```

Use a fresh output directory each time. Each case saves wall seconds, scanner
peak RSS in bytes, permission-analysis seconds, connection/tool counts, status
and failure reasons, recorded-process counts and ledger roles, leftover processes and groups,
and exit/deadline state. The 500-server case also records a separate timeout-2
run. RSS is the scanner process high-water mark, not aggregate fixture memory.
Wall time includes scanner interpreter startup and report rendering; the 5 MB
target measures permission analysis only. Post-scan process observation has a
0.5-second grace, matching the original stress runner. A missing measurement,
nonzero scanner exit, wrong tool count, or regression fails the test. A separate
hard deadline bounds the runner even if the scanner stalls outside its timeout.
Description cases also require analyzer invocation and tool-count coverage, plus
the expected per-tool `file_read` findings. The orphan case requires ledger
records for both servers and the child before accepting its cleanup measurement.

The approved Phase 0 acceptance is the **baseline** profile. The limits come
from the published 2.8.0 stress run (14-core macOS, 48 GB RAM); they are absolute
ceilings, without an automatic tolerance or recalibration. Different runner
hardware/SDK versions can fail these limits and require investigation; do not
increase a limit to obtain a green run.

| Case | Baseline ceiling | Cumulative target profile |
| --- | --- | --- |
| `scale_500` (500 × 10 tools) | 5.8 s wall, 213 MiB RSS; timeout-2 coverage observed | `p1-9`: ≤ 4 s wall and 500/500 connected at timeout 2 |
| `desc_5mb_x1` | 18.8 s wall, ≤ 18 s permission analysis | `p1-9`: ≤ 1 s permission analysis |
| `desc_1mb_x20` | 75 s wall, 1282 MiB RSS | `p1-9`: ≤ 3 s wall, < 400 MB RSS |
| `oversized_50mb` | 191.7 s wall, 3217 MiB RSS; connected with one tool | `p3-7`: < 1 s wall, < 300 MB RSS, failed with frame-size reason |
| `spawn_child_exit` (plus healthy sibling) | timeout 2 + 4.5 s wall; at most one leftover process/group | `p3-8`: same wall bound, zero leftovers |

Other cases always require zero leftovers. Baseline timeout-2 permits only
connected/timeout statuses; it does not certify full coverage. Description and
frame sizes are decimal bytes (5,000,000; 1,000,000 × 20; 50,000,000).
Future memory targets use decimal MB; baseline RSS uses the stress runner's MiB.
The orphan allowance is an explicit known baseline defect, not a safety claim.

Profiles are cumulative: `p3-7` includes `p1-9`, and `p3-8` includes both.
As each fixing phase lands, promote the default in `tests/conftest.py` and the
nightly/dispatch defaults in `.github/workflows/hostile-perf.yml`. Tight targets
can already be selected on demand and fail normally; they are not skipped or
xfail assertions. The nightly workflow runs all five cases and uploads metrics
even on failure. This item does not implement the detector/concurrency or
transport repairs, nor gate the other §5a scenarios (2000 servers, 20k tools,
100k config-only servers, or the SSRF tokenizer).
