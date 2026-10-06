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
analysis with absent annotations to guard the six M2 keyword false positives,
now fixed by P2-1. All six are ordinary passing tests; no false positive is
excluded from CLI metrics. Server fixtures retain annotation-plus-keyword
analysis. Their optional `tool_annotations` applies explicit synthetic hints to
every tool on that fixture server. Network-positive servers whose labels
previously passed via spec defaults now declare `open_world_hint: true`.
These labels validate declarations, not independent keyword recall or actual
network behavior. Missing hints are tested separately by the scoring fixtures.

## Gates

Recall retains the existing floor of 80% for categories with at least three
expected positives. Precision is gated independently, including categories with
zero positives: a false positive in such a category fails. No predictions gives
precision 100% by convention; no positives gives recall 100% by convention. These
vacuous ratios do not establish coverage.

| Category | Expected positives | Current TP | Known FP | Precision floor |
| --- | ---: | ---: | ---: | ---: |
| file_read | 19 | 19 | 0 | 100% |
| file_write | 31 | 30 | 0 | 100% |
| exfiltration | 5 | 5 | 0 | 100% |
| network | 49 | 49 | 0 | 100% |
| destructive | 10 | 10 | 0 | 100% |
| shell_execution | 4 | 4 | 0 | 100% |

P2-1 raises the affected floors to 100% and removes the xfails. The file_write
baseline still includes one existing missed positive. Any FP now fails each
category gate. Per-fixture benign checks also reject every FP without relying
on aggregate support. The recall threshold and minimum support are unchanged.
