"""Scan real third-party repositories and hold the impact count to a baseline.

`scan_control.py` proves the scanner can FIRE. This is the other half: proof
that it stays QUIET on code that is not affected. Both are needed, and neither
substitutes for the other -- a scanner tuned only for recall reports everything
and a scanner tuned only for precision reports nothing.

The measurement that produced this tool: four real repositories, 27 impacts,
all 27 false. `error.name` on a DOMException reported as a dependence on
Sentry's replay endpoint, because the prover took a read of the field without
also requiring a call to an operation carrying it. Nothing in the gate could
have caught that, because nothing in the gate had ever looked at real
third-party code.

Every impact here must be hand-verified before the baseline moves. A rising
count is not a better scanner; it is a claim that needs checking one impact at
a time, against the source.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.scan import scan_repo                          # noqa: E402
from apidrift.vendors import VENDORS                         # noqa: E402

# Chosen because they are real products that genuinely call tracked vendors, in
# TypeScript, at a size where a false positive is easy to find by hand.
CORPUS: Dict[str, str] = {
    "documenso": "documenso/documenso",
    "formbricks": "formbricks/formbricks",
    "langfuse": "langfuse/langfuse",
    "ai-chatbot": "vercel/ai-chatbot",
}

# Hand-verified 2026-08-21 against the source of each cited line. Raising a
# number here without doing that again is forging the record that this file
# exists to keep.
BASELINE: Dict[str, int] = {
    "documenso": 0, "formbricks": 0, "langfuse": 0, "ai-chatbot": 0,
}


def _ensure(root: Path, repo: str, target: Path) -> bool:
    if (target / ".git").is_dir():
        return True
    root.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet",
         f"https://github.com/{repo}", str(target)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode == 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="corpus_scan")
    parser.add_argument("--corpus", required=True,
                        help="directory to hold the checkouts")
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--asof", default=dt.date.today().isoformat())
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    root = Path(args.corpus)
    since = (dt.date.fromisoformat(args.asof)
             - dt.timedelta(days=args.days)).isoformat()
    keys = sorted(VENDORS)

    print("Real third-party repositories. Every impact must be hand-verified\n"
          "against the source before the baseline moves.\n")
    header = f"{'repo':14} {'files':>7} {'checked':>9} {'impacts':>9} {'baseline':>9}"
    print(header)
    print("-" * len(header))
    rows, problems = [], []
    for name, repo in CORPUS.items():
        target = root / name
        if not _ensure(root, repo, target):
            print(f"{name:14} could not clone {repo}")
            problems.append(f"{name}: clone failed")
            continue
        result = scan_repo(root=target, since=since, vendor_keys=keys,
                           cache_dir=Path(args.cache), fetch=False,
                           asof=args.asof, window_days=args.days, progress=None)
        count = len(result.breaking)
        expected = BASELINE.get(name)
        flag = ""
        if expected is None:
            flag = "NO BASELINE"
            problems.append(f"{name}: no baseline recorded")
        elif count > expected:
            flag = f"ROSE from {expected}"
            problems.append(f"{name}: {count} impacts, baseline {expected}")
        print(f"{name:14} {result.files_scanned:7} "
              f"{result.findings_considered:9} {count:9} "
              f"{expected if expected is not None else '?':>9}  {flag}")
        for impact in result.breaking[:8]:
            print(f"               {impact.file}:{impact.line}: "
                  f"{impact.vendor_name} {impact.label} — {impact.subject}")
        rows.append({"repo": name, "impacts": count, "baseline": expected,
                     "files": result.files_scanned,
                     "considered": result.findings_considered,
                     "sites": [f"{i.file}:{i.line} {i.subject}"
                               for i in result.breaking[:20]]})

    total = sum(r["impacts"] for r in rows)
    print(f"\n{len(rows)} repositories, {total} impact(s), "
          f"{len(problems)} problem(s)")
    for line in problems:
        print(f"  {line}")
    if not rows:
        print("  NOTHING WAS SCANNED — that is a failed measurement of this "
              "tool, not a clean corpus.")
        return 1
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
