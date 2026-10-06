# Permission validation corpus

Run `uv run python tests/validation/validate_patterns.py` from the repository root.
Pytest parametrizes the server fixtures and the synthetic benign fixtures by
server name, so failures identify the affected input.

Existing positive rows list required categories at a minimum confidence. These
labels are not exhaustive: an unlisted category on a positive or unlabeled tool
is not scored. An explicit `categories: []` row instead requires silence: every
distinct tool/category finding counts as a false positive, even at low confidence.
The reported precision therefore covers explicitly labeled pairs, not the entire
unlabeled permission surface. Recall retains its confidence requirement. F1 is
`2 * TP / (2 * TP + FP + FN)`, rather than a copy of recall.

`benign_tools.json` contains synthetic, in-memory operations. It uses keyword-only
analysis with absent annotations to reproduce the six M2 keyword false positives;
it does not test the separate spec-default annotation findings. Existing server
fixtures retain full annotation-plus-keyword analysis. The six known gaps have
individual `xfail(strict=True, raises=AssertionError)` tests until P2-1 retunes the
keywords. Fixing one produces XPASS and requires removing that case's xfail.
No known false positive is excluded from CLI metrics.

## Gates

Recall retains the existing floor of 80% for categories with at least three
expected positives. Precision is gated independently, including categories with
zero positives: a false positive in such a category fails. No predictions gives
precision 100% by convention; no positives gives recall 100% by convention. These
vacuous ratios do not establish coverage.

| Category | Expected positives | Current TP | Known FP | Precision floor |
| --- | ---: | ---: | ---: | ---: |
| file_read | 19 | 19 | 1 | 19/20 = 95% |
| file_write | 31 | 30 | 2 | 30/32 = 93.75% |
| exfiltration | 5 | 5 | 3 | 5/8 = 62.5% |
| network | 49 | 49 | 0 | 100% |
| destructive | 10 | 10 | 0 | 100% |
| shell_execution | 4 | 4 | 0 | 100% |

These fixed floors bound the existing six failures while detector tuning remains
out of Phase 0. In the small exfiltration category, each of the three known FPs
materially changes precision; a generic 80% floor would fail this baseline.
The file_write baseline includes one existing missed positive. At the recorded TP
counts, one additional FP fails each category gate. Per-fixture benign checks also
reject every new FP without relying on aggregate support. As P2-1 fixes gaps,
raise the affected floors along with removing xfails; do not lower them to admit
regressions.
