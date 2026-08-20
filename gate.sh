#!/usr/bin/env bash
# The full verification gate. Four independent layers, each answering a
# different question, because none of them alone would have caught the bugs
# this project actually had.
#
#   1. unit tests        — does the code do what it says?
#   2. mutation testing  — do the tests fail when the code is wrong?
#   3. precision audit   — are the FINDINGS real, per the raw specs?
#   4. end-to-end run    — does the whole pipeline still produce output?
#   5. lead standing     — are the LEADS real, per the last adversarial audit?
#
# Layer 3 is the one that mattered first: layers 1 and 2 were green while 86%
# of findings were fabricated by an asymmetric depth cap.
#
# Layer 5 exists because a green gate on layers 1-4 was compatible with a lead
# list where nine of ten sampled entries were refuted. Nothing measured leads,
# so nothing reported them. It reads lead_audit.json, which only an actual
# audit may update.
set -uo pipefail
cd "$(dirname "$0")"
PY=./.venv/bin/python
fail=0

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

step "1/5 unit tests"
$PY -m unittest discover -s tests 2>&1 | tail -3 || fail=1

step "2/5 mutation testing"
$PY tests/mutation_check.py 2>&1 | tail -2 || fail=1

step "3/5 precision audit (every finding, checked against raw specs)"
echo "-- breaking --"
$PY tests/measure_precision.py --sample 1000 --severity breaking 2>&1 | sed -n '4,10p' || fail=1
echo "-- potentially breaking --"
$PY tests/measure_precision.py --sample 1000 --severity potentially_breaking 2>&1 | sed -n '4,10p' || fail=1

step "4/5 end-to-end run"
if $PY -m apidrift.cli --days 90 --quiet; then
  echo "pipeline OK -> out/report.md"
else
  echo "pipeline FAILED"; fail=1
fi

step "5/5 lead standing (from the last adversarial audit)"
if [ -f lead_audit.json ]; then
  $PY - <<'PY'
import json, sys
data = json.load(open("lead_audit.json"))
standing = data["standing"]
audits = data["audits"]
print(f"  audits run           : {len(audits)}")
for a in audits:
    print(f"    {a['date']}  {a['refuted']}/{a['sampled']} refuted  ({a['run']})")
print(f"  lead precision       : {standing['lead_precision']}")
print(f"  findings precision   : {standing['findings_precision']}")
print(f"  leads sendable       : {standing['sendable']}")
if not standing["sendable"]:
    print(f"  BLOCKER: {standing['blocker']}")
    sys.exit(2)
PY
  lead_state=$?
else
  echo "  no audit on record — leads are UNMEASURED, which is not the same as fine"
  lead_state=2
fi

printf '\n'
if [ "$fail" -ne 0 ]; then
  echo "GATE RED"
  exit 1
fi
if [ "$lead_state" -ne 0 ]; then
  echo "GATE GREEN for findings — LEADS NOT SENDABLE"
  echo "The engine is verified. The outreach list is not. Do not send."
  exit 3
fi
echo "GATE GREEN"
exit 0
