"""Prove every registered vendor actually clones, parses and diffs.

A config line is a claim; a successful diff is evidence; and a plausible NUMBER
is neither. The first run of this said "20/22 working" and six of those twenty
were reporting zero breaking changes because their spec was younger than the
window, while four more reported more breaking changes than they have
operations. Read the counts, not the OK.
"""
import datetime as dt, sys, traceback
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apidrift.cli import analyse
from apidrift.vendors import VENDORS, get

since = (dt.date(2026, 8, 20) - dt.timedelta(days=180)).isoformat()
cache = Path(__file__).resolve().parent / '.cache'
rows = []
for key in sorted(VENDORS):
    try:
        r = analyse(get(key), cache, since, fetch=False)
        rows.append((key, "OK", r.new_op_count, len(r.breaking),
                     len(r.potentially_breaking), len(r.additions), ""))
    except Exception as exc:
        rows.append((key, "FAIL", 0, 0, 0, 0, f"{type(exc).__name__}: {exc}"[:110]))
    print(f"{rows[-1][0]:17} {rows[-1][1]:5} ops={rows[-1][2]:5} break={rows[-1][3]:4} "
          f"pot={rows[-1][4]:4} add={rows[-1][5]:5} {rows[-1][6]}", flush=True)

ok = [r for r in rows if r[1] == "OK"]
print(f"\n{len(ok)}/{len(rows)} vendors working")
print(f"total operations covered: {sum(r[2] for r in ok):,}")
print(f"total breaking (180d):    {sum(r[3] for r in ok)}")
print(f"total additions (180d):   {sum(r[5] for r in ok)}")
