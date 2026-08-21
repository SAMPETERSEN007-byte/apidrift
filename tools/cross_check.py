"""Diff apidrift's verdicts against an INDEPENDENT implementation (oasdiff).

The seventh question, and the only one asked by code this project did not
write. Layers 1-6 are all apidrift checking apidrift: the unit suite, the
mutations, the end-to-end run, a precision checker in this repo, a lead record,
and recall controls whose stimulus this repo's author chose. That last one is
the gap this tool closes. `vendor_control.py` injects breaks somebody thought
of; it cannot surface a break nobody thought of, and on 2026-08-21 oasdiff
surfaced two on the FIRST vendor and the FIRST window tried:

  * `POST /v1/checkout/sessions` lost the request property
    `line_items[].dynamic_tax_rates`. apidrift flattens it as
    `Field(type='__truncated__')` because it sits past `MAX_DEPTH=2`, and the
    truncation abstention then silences it. That abstention was kept because
    narrowing it was MEASURED UNSAFE -- it had deleted 49 confirmed findings.
    Only its PRECISION cost was ever measured. This is its recall cost.
  * `POST /v1/terminal/readers/{reader}/cancel_action` repointed its 200 body
    from `$ref: terminal.reader` to an `anyOf`, dropping the required
    `device_type`. apidrift sees neither side's `device_type` at all.

Both were verified by hand against the raw documents before being written down.

🚨 oasdiff is an ORACLE, not an authority. On that same Stripe pair it emitted
577,044 breaking changes to apidrift's 4 -- 367,596 of them
`response-property-enum-value-added` and 209,438 `response-optional-property-
removed`, which is the fan-out apidrift's `collapse()` exists to prevent. Its
value is entirely in the DISAGREEMENTS, and every disagreement is a lead to be
checked against the raw spec, never a verdict to adopt.

    ./.venv/bin/python tools/cross_check.py --vendors stripe --days 90
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.cli import analyse                                   # noqa: E402
from apidrift.diff import BREAKING                                 # noqa: E402
from apidrift.source import GitError                               # noqa: E402
from apidrift.vendors import VENDORS, get                          # noqa: E402

# oasdiff ids whose sheer volume makes them noise on a real vendor, recorded
# with the count that earned the exclusion so this can never read as a quiet
# filter. Excluded from the DISAGREEMENT report only; still counted and printed.
NOISY = {
    "response-property-enum-value-added": "367,596 on one Stripe pair",
    "response-optional-property-removed": "209,438 on the same pair; this is "
                                          "the fan-out `collapse()` exists for",
}


def _spec_blob(cache: Path, repo: str, spec_path: str, date: str) -> bytes:
    sha = subprocess.run(
        ["git", "-C", str(cache / repo.replace("/", "_")), "rev-list", "-1",
         f"--before={date}T23:59:59", "HEAD"],
        capture_output=True, text=True).stdout.strip()
    if not sha:
        raise GitError(f"no commit before {date}")
    return subprocess.run(
        ["git", "-C", str(cache / repo.replace("/", "_")), "show",
         f"{sha}:{spec_path}"], capture_output=True).stdout


def cross_check(key: str, days: int, asof: str, cache: Path) -> Dict[str, object]:
    vendor = get(key)
    if any(ch in vendor.spec_path for ch in "*?["):
        return {"vendor": key, "skipped": "spec_path is a glob; oasdiff takes "
                                          "one file and choosing one would be "
                                          "a claim about which matters"}
    since = (dt.date.fromisoformat(asof) - dt.timedelta(days=days)).isoformat()
    result = analyse(vendor, cache, since, fetch=False)
    mine = [f for f in result.findings if f.severity == BREAKING]

    tmp = Path(tempfile.mkdtemp(prefix=f"crosscheck-{key}-"))
    try:
        for label, date in (("old", result.old_date), ("new", result.new_date)):
            (tmp / f"{label}.json").write_bytes(
                _spec_blob(cache, vendor.repo, vendor.spec_path, date))
        proc = subprocess.run(
            ["oasdiff", "breaking", str(tmp / "old.json"), str(tmp / "new.json"),
             "--format", "json"], capture_output=True, text=True)
        if proc.returncode not in (0, 1):
            return {"vendor": key, "error": proc.stderr[-300:]}
        theirs = json.loads(proc.stdout or "[]")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    by_id = collections.Counter(x.get("id", "?") for x in theirs)
    signal = [x for x in theirs if x.get("id") not in NOISY]
    # An operation apidrift said nothing breaking about, that the oracle did.
    mine_ops = {f"{f.method.upper()} {f.path}" for f in mine}
    unmatched = [x for x in signal
                 if f"{(x.get('operation') or '').upper()} {x.get('path')}"
                 not in mine_ops]
    return {
        "vendor": key,
        "window": f"{result.old_date} → {result.new_date}",
        "apidrift_breaking": len(mine),
        "oasdiff_breaking": len(theirs),
        "oasdiff_signal": len(signal),
        "oasdiff_by_id": dict(by_id.most_common()),
        "only_the_oracle_flagged": [
            {"id": x.get("id"), "op": f"{(x.get('operation') or '').upper()} "
                                      f"{x.get('path')}",
             "text": (x.get("text") or "")[:160]}
            for x in unmatched[:40]],
        "unmatched_total": len(unmatched),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="cross_check")
    parser.add_argument("--vendors", default="stripe")
    parser.add_argument("--days", type=int, default=90)
    parser.add_argument("--asof", default=dt.date.today().isoformat())
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    if not shutil.which("oasdiff"):
        print("oasdiff is not installed — `brew install oasdiff`.\n"
              "This tool has no fallback ON PURPOSE: an oracle that silently "
              "does not run reports agreement, which is the failure mode it "
              "exists to prevent.")
        return 2

    keys = (sorted(VENDORS) if args.vendors == "all"
            else [k.strip() for k in args.vendors.split(",") if k.strip()])
    out: List[Dict[str, object]] = []
    for key in keys:
        try:
            row = cross_check(key, args.days, args.asof, Path(args.cache))
        except Exception as exc:                                  # noqa: BLE001
            row = {"vendor": key, "error": f"{type(exc).__name__}: {exc}"[:200]}
        out.append(row)
        if "skipped" in row:
            print(f"{key:12} skipped — {row['skipped']}")
        elif "error" in row:
            print(f"{key:12} ERROR — {row['error']}")
        else:
            print(f"{key:12} apidrift {row['apidrift_breaking']:>4} | "
                  f"oasdiff {row['oasdiff_breaking']:>7} "
                  f"({row['oasdiff_signal']} after noise) | "
                  f"{row['unmatched_total']} operations only the oracle flagged")

    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=1))
        print(f"\nwrote {args.out}")
    print("\nEvery entry in `only_the_oracle_flagged` is a LEAD, not a verdict. "
          "Check it against the raw document before believing either side.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
