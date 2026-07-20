#!/bin/bash -eu

python3 -m pip install --require-hashes -r .clusterfuzzlite/requirements.txt
export PYTHONPATH="$SRC/MCPAudit/src${PYTHONPATH:+:$PYTHONPATH}"

for fuzzer in fuzz/*_fuzzer.py; do
  compile_python_fuzzer "$fuzzer"
done
