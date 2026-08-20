#!/usr/bin/env bash
# apidrift — 90-day breaking-change sweep across the tracked API vendors.
set -euo pipefail
cd "$(dirname "$0")"
./.venv/bin/python -m apidrift.cli "$@"
