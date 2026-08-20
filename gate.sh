#!/usr/bin/env bash
# The full verification gate. Four independent layers, each answering a
# different question, because none of them alone would have caught the bugs
# this project actually had.
#
#   1. unit tests        — does the code do what it says?
#   2. mutation testing  — do the tests fail when the code is wrong?
#   3. precision audit   — are the FINDINGS real, per the raw specs?
#   4. end-to-end run    — does the whole pipeline still produce output?
#
# Layer 3 is the one that mattered: layers 1 and 2 were green while 86% of
# findings were fabricated by an asymmetric depth cap.
set -uo pipefail
cd "$(dirname "$0")"
PY=./.venv/bin/python
fail=0

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

step "1/4 unit tests"
$PY -m unittest discover -s tests 2>&1 | tail -3 || fail=1

step "2/4 mutation testing"
$PY tests/mutation_check.py 2>&1 | tail -2 || fail=1

step "3/4 precision audit (every finding, checked against raw specs)"
echo "-- breaking --"
$PY tests/measure_precision.py --sample 1000 --severity breaking 2>&1 | sed -n '4,10p' || fail=1
echo "-- potentially breaking --"
$PY tests/measure_precision.py --sample 1000 --severity potentially_breaking 2>&1 | sed -n '4,10p' || fail=1

step "4/4 end-to-end run"
if $PY -m apidrift.cli --days 90 --quiet; then
  echo "pipeline OK -> out/report.md"
else
  echo "pipeline FAILED"; fail=1
fi

printf '\n'
if [ "$fail" -eq 0 ]; then
  echo "GATE GREEN"
else
  echo "GATE RED"
fi
exit "$fail"
