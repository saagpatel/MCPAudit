#!/bin/bash -eu

python3 -m pip install .

for fuzzer in fuzz/*_fuzzer.py; do
  compile_python_fuzzer "$fuzzer"
done
