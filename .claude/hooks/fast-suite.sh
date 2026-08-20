#!/bin/bash
# fast-suite.sh — PostToolUse(Edit|Write) for apidrift only.
#
# The global post-edit-verify.sh runs `ruff check --select F,E9` on the single
# edited file. That catches an undefined name inside that file and nothing else.
# This project's failures are CROSS-MODULE -- a suppressor added in diff.py that
# measure_precision.py no longer agrees with, a finding kind that falls through
# classify, a renamed helper that four call sites still reference. Ruff cannot
# see any of those.
#
# The whole 212-test suite runs in 0.1s, so there is no reason not to run it on
# every edit. Non-blocking, always exit 0, and it only writes when something is
# RED -- it appends to the same build-errors.log that associative-surface.sh
# surfaces at the next prompt and then clears.
#
# It deliberately does NOT run layers 2-5 of gate.sh (~65s). This is the fast
# signal, not the proof. ./gate.sh is the proof.
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"

REPO="/Users/claudebot/apidrift"
PY="$REPO/.venv/bin/python"
LOG="$HOME/.claude/logs/build-errors.log"
STAMP="$REPO/.claude/.fast-suite-last"

PAYLOAD="$(cat 2>/dev/null)"
FILE_PATH="$(printf '%s' "$PAYLOAD" | python3 -c '
import sys, json
try:
    print(json.load(sys.stdin).get("tool_input", {}).get("file_path", ""))
except Exception:
    print("")' 2>/dev/null)"

# Only fire for edits INSIDE the repo, and never for the scratch/cache trees --
# editing a session scratchpad file says nothing about whether apidrift builds.
case "$FILE_PATH" in
  "$REPO"/*) ;;
  *) exit 0 ;;
esac
case "$FILE_PATH" in
  *"/.venv/"*|*"/.cache/"*|*"/out/"*|*"/.snapshots/"*|*"/__pycache__/"*) exit 0 ;;
esac

[ -x "$PY" ] || exit 0

# Throttle: edits arrive in bursts, and a 0.1s suite still costs a process spawn.
now=$(date +%s)
last=$(cat "$STAMP" 2>/dev/null || echo 0)
[ $((now - last)) -lt 10 ] && exit 0
mkdir -p "$(dirname "$STAMP")"; printf '%s' "$now" > "$STAMP"

(
  mkdir -p "$(dirname "$LOG")"
  out="$(cd "$REPO" && "$PY" -m unittest discover -s tests 2>&1)"
  if [ $? -ne 0 ]; then
    {
      echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] apidrift suite RED after editing $FILE_PATH:"
      printf '%s\n' "$out" | grep -E '^(FAIL|ERROR|Ran |FAILED|[A-Za-z_]+Error)' | head -12
      printf '%s\n' "$out" | grep -A4 -E '^(FAIL|ERROR):' | head -20
      echo "  -> ./gate.sh is the proof; this is only layer 1"
      echo "---"
    } >> "$LOG"
  fi
) >/dev/null 2>&1 &
disown 2>/dev/null || true
exit 0
