"""Parallel corpus sweep. Writes one JSON with every impact, for hand audit."""
import json, subprocess, sys, pathlib, time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(sys.argv[1])          # apidrift checkout to use
DAYS = sys.argv[2]
DEST = pathlib.Path(sys.argv[3])
PY = "/Users/claudebot/apidrift/.venv/bin/python"
repos = sorted(p for p in pathlib.Path("/tmp/corpus").iterdir() if (p/".git").is_dir())

def one(r):
    t0 = time.time()
    proc = subprocess.run(
        [PY, "-m", "apidrift.cli", "scan", str(r), "--days", DAYS,
         "--asof", "2026-08-21", "--exit-zero", "--format", "json", "--quiet"],
        cwd=ROOT, capture_output=True, text=True)
    try:
        d = json.loads(proc.stdout)
    except Exception:
        d = {"error": (proc.stderr or proc.stdout)[-800:], "impact_count": 0}
    d["_secs"] = round(time.time() - t0)
    print(f"{r.name:16s} {d.get('impact_count',0):3d} impacts "
          f"{d.get('findings_considered',0):5d} findings  {d['_secs']:4d}s", flush=True)
    return r.name, d

with ThreadPoolExecutor(max_workers=6) as ex:
    results = dict(ex.map(one, repos))

out = {"root": str(ROOT), "days": int(DAYS), "repos": results}
DEST.write_text(json.dumps(out, indent=1))
tot = sum(v.get("impact_count", 0) for v in results.values())
hits = sum(1 for v in results.values() if v.get("impact_count", 0))
print(f"=== {DEST.name}: {tot} impacts across {hits}/{len(repos)} repos")
