"""Prove every registered vendor actually clones, parses and diffs.

A config line is a claim; a successful diff is evidence; and a plausible NUMBER
is neither. The first run of this said "20/22 working" and six of those twenty
were reporting zero breaking changes because their spec was younger than the
window, while four more reported more breaking changes than they have
operations. Read the counts, not the OK.

Three states, not two. "FAIL" used to swallow a repo that is simply YOUNGER
than the look-back window, which is not a defect in anything -- it is the tool
correctly having nothing to compare. That is SHORT, it is reported with the
date history actually begins, and it never reads as clean.

Every row prints the window the tool could SEE next to the window that was
ASKED for. A count over an invisible period is not a measurement, and this is
the surface where that lie was told six times.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.cli import analyse                        # noqa: E402
from apidrift.loader import SpecParseError              # noqa: E402
from apidrift.source import GitError, HistoryTooShort   # noqa: E402
from apidrift.vendors import VENDORS, get               # noqa: E402


def _days(a: str, b: str) -> int:
    try:
        return (dt.date.fromisoformat(b) - dt.date.fromisoformat(a)).days
    except ValueError:
        return -1


def check(key: str, cache: Path, since: str, asof: str, fetch: bool) -> dict:
    row = {"vendor": key, "repo": get(key).repo, "state": "FAIL",
           "requested_since": since, "asof": asof, "detail": ""}
    try:
        r = analyse(get(key), cache, since, fetch=fetch)
    except HistoryTooShort as exc:
        row["state"] = "SHORT"
        row["history_begins"] = exc.first_commit_date
        row["detail"] = (f"repo history begins {exc.first_commit_date}, "
                         f"after the window opened at {since}")
        return row
    except (GitError, SpecParseError) as exc:
        row["detail"] = f"{type(exc).__name__}: {exc}".replace("\n", " ")[:160]
        return row

    breaking = r.breaking
    ops_touched = len({(f.method, f.path) for f in breaking})
    observed = _days(r.old_date, r.new_date)
    requested = _days(since, asof)
    row.update(
        state="OK",
        old_ref=r.old_ref[:8], new_ref=r.new_ref[:8],
        observed_from=r.old_date, observed_to=r.new_date,
        observed_days=observed, requested_days=requested,
        window_is_short=observed < requested,
        specs_matched=r.specs_matched, specs_changed=r.specs_changed,
        old_ops=r.old_op_count, new_ops=r.new_op_count,
        breaking=len(breaking),
        potentially=len(r.potentially_breaking),
        additions=len(r.additions),
        breaking_ops_touched=ops_touched,
        breaking_per_op=round(len(breaking) / ops_touched, 1) if ops_touched else 0.0,
        specs_without_history=len(r.specs_without_history),
    )
    flags = []
    if row["window_is_short"]:
        flags.append(f"WINDOW {observed}d of {requested}d requested")
    if r.specs_without_history:
        flags.append(f"{len(r.specs_without_history)} spec(s) with no history")
    # A vendor cannot break a caller more times than it has operations to break.
    if row["old_ops"] and row["breaking"] > row["old_ops"]:
        flags.append(f"IMPLAUSIBLE breaking({row['breaking']}) > operations({row['old_ops']})")
    if ops_touched and row["breaking_per_op"] >= 10:
        flags.append(f"DENSE {row['breaking_per_op']} breaking per operation")
    row["detail"] = "; ".join(flags)
    return row


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="vendor_check")
    p.add_argument("--days", type=int, default=180)
    p.add_argument("--asof", default=dt.date.today().isoformat())
    p.add_argument("--fetch", action="store_true")
    p.add_argument("--cache", default=str(ROOT / ".cache"))
    p.add_argument("--json", default=None, help="write the rows here")
    p.add_argument("--vendors", default="all")
    args = p.parse_args(argv)

    asof = dt.date.fromisoformat(args.asof)
    since = (asof - dt.timedelta(days=args.days)).isoformat()
    keys = sorted(VENDORS) if args.vendors == "all" else [
        k.strip() for k in args.vendors.split(",") if k.strip()]

    print(f"window requested: {since} .. {asof}  ({args.days}d)\n")
    head = (f"{'vendor':17} {'state':5} {'seen':>13} {'ops':>6} {'break':>6} "
            f"{'pot':>5} {'add':>6}  notes")
    print(head)
    print("-" * len(head))
    rows = []
    for key in keys:
        row = check(key, Path(args.cache), since, asof.isoformat(), args.fetch)
        rows.append(row)
        if row["state"] == "OK":
            seen = f"{row['observed_days']}d/{row['requested_days']}d"
            print(f"{key:17} {row['state']:5} {seen:>13} {row['new_ops']:6} "
                  f"{row['breaking']:6} {row['potentially']:5} {row['additions']:6}"
                  f"  {row['detail']}", flush=True)
        else:
            print(f"{key:17} {row['state']:5} {'-':>13} {'-':>6} {'-':>6} "
                  f"{'-':>5} {'-':>6}  {row['detail']}", flush=True)

    ok = [r for r in rows if r["state"] == "OK"]
    short = [r for r in rows if r["state"] == "SHORT"]
    fail = [r for r in rows if r["state"] == "FAIL"]
    flagged = [r for r in ok if r["detail"]]
    print(f"\n{len(ok)}/{len(rows)} diffed   "
          f"{len(short)} history shorter than the window   {len(fail)} failed")
    print(f"{len(flagged)} of the {len(ok)} that diffed carry a caveat "
          f"— those counts are NOT measurements yet")
    print(f"total operations covered: {sum(r['new_ops'] for r in ok):,}")
    print(f"total breaking:           {sum(r['breaking'] for r in ok)}")
    print(f"total additions:          {sum(r['additions'] for r in ok)}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
