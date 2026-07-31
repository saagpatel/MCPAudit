# v2 fixture adapters

These adapters are deliberately mechanical. They decode, materialize, and
capture exact bytes. They do not import a frozen consumer, invoke any consumer
under the current authority, compare identities, grade evidence, fill missing
fields, classify from labels, or create reason codes.

`p1_adapter.py`, `p2_adapter.py`, and `p3_adapter.py` expose preparation
functions for a future separately authorized runner. `adapter_common.py`
captures raw bytes without semantic normalization. Materialization must always
target a disposable empty directory. P3 mode failures abort; they are never
emulated.
