"""Probe a candidate vendor before registering it.

A registry line is a claim: that the repo exists, that the glob matches, that
what it matches parses as a spec with operations, and that the history is long
enough to diff. Four separate things, each of which has already been wrong for
some vendor in this repo -- SendGrid's glob, Adyen's blob fetch, Column's young
repo, Datadog's private canonical source.

So a candidate is not added until this says every one of them holds. It prints
the numbers, not an OK: a spec that parses to 3 operations is a wrong glob, and
a plausible count is the only thing that distinguishes a real integration from
a line of YAML that happens not to crash.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.loader import SpecParseError, load_spec       # noqa: E402
from apidrift.vendors import VENDORS                        # noqa: E402


def _run(args: List[str], cwd: Optional[Path] = None, binary: bool = False,
         timeout: int = 300):
    proc = subprocess.run(args, cwd=str(cwd) if cwd else None,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip()[:180])
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace").strip()


def probe(key: str, repo: str, glob: str, cache: Path,
          days: int = 180, asof: str = "") -> Dict[str, Any]:
    row: Dict[str, Any] = {"key": key, "repo": repo, "glob": glob,
                           "state": "FAIL", "detail": "", "ops": 0,
                           "matched": 0, "head_date": "", "first_date": ""}
    repo_dir = cache / repo.replace("/", "_")
    try:
        if not (repo_dir / ".git").is_dir():
            _run(["git", "clone", "--filter=blob:none", "--quiet",
                  f"https://github.com/{repo}", str(repo_dir)], timeout=600)
        head = _run(["git", "rev-parse", "HEAD"], repo_dir)
        row["head_date"] = _run(
            ["git", "show", "-s", "--format=%cd", "--date=short", head], repo_dir)
        roots = _run(["git", "rev-list", "--max-parents=0", "HEAD"],
                     repo_dir).splitlines()
        row["first_date"] = _run(
            ["git", "show", "-s", "--format=%cd", "--date=short",
             roots[-1].strip()], repo_dir)
    except Exception as exc:                                  # noqa: BLE001
        row["detail"] = f"clone/history: {exc}"[:150]
        return row

    try:
        tree = _run(["git", "ls-tree", "-r", "--name-only", head],
                    repo_dir).splitlines()
    except Exception as exc:                                  # noqa: BLE001
        row["detail"] = f"ls-tree: {exc}"[:150]
        return row

    matches = [p for p in tree if fnmatch.fnmatch(p, glob)]
    row["matched"] = len(matches)
    if not matches:
        near = [p for p in tree
                if p.lower().endswith((".json", ".yaml", ".yml"))
                and any(w in p.lower() for w in
                        ("openapi", "swagger", "spec", "api"))]
        row["detail"] = "glob matched nothing"
        row["suggestions"] = near[:8]
        return row

    total_ops, parsed, errors = 0, 0, []
    for path in matches[:200]:
        try:
            raw = _run(["git", "show", f"{head}:{path}"], repo_dir, binary=True)
            spec = load_spec(raw, path)
        except (SpecParseError, RuntimeError) as exc:
            errors.append(f"{path}: {type(exc).__name__}")
            continue
        total_ops += spec.op_count
        parsed += 1
    row["ops"] = total_ops
    row["parsed"] = parsed
    if not parsed:
        row["detail"] = "nothing matched parsed as a spec: " + "; ".join(errors[:2])
        return row
    if total_ops == 0:
        row["detail"] = f"{parsed} file(s) parsed but define ZERO operations"
        return row

    # Is there anything behind the window to diff against?
    since = (dt.date.fromisoformat(asof or dt.date.today().isoformat())
             - dt.timedelta(days=days)).isoformat()
    try:
        before = _run(["git", "rev-list", "-1", f"--before={since}", "HEAD"], repo_dir)
    except Exception:                                         # noqa: BLE001
        before = ""
    if not before:
        row["state"] = "SHORT"
        row["detail"] = (f"history begins {row['first_date']}, after the window "
                         f"opened at {since}")
        return row

    row["state"] = "OK"
    row["detail"] = f"{parsed}/{len(matches)} file(s) parsed"
    if errors:
        row["detail"] += f"; {len(errors)} unparsed"
    return row


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vendor_probe")
    parser.add_argument("candidates", help="JSON file: [[key, repo, glob], ...]")
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--asof", default=dt.date.today().isoformat())
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    candidates = json.loads(Path(args.candidates).read_text())
    head = f"{'key':20} {'state':5} {'ops':>6} {'files':>6} {'first':>11} {'head':>11}  detail"
    print(head)
    print("-" * len(head))
    rows = []
    for key, repo, glob in candidates:
        if key in VENDORS:
            print(f"{key:20} {'HAVE':5} {'-':>6} {'-':>6} {'-':>11} {'-':>11}  already registered")
            continue
        row = probe(key, repo, glob, Path(args.cache), args.days, args.asof)
        rows.append(row)
        print(f"{key:20} {row['state']:5} {row['ops']:6} {row['matched']:6} "
              f"{row['first_date']:>11} {row['head_date']:>11}  {row['detail'][:70]}",
              flush=True)
        for hint in row.get("suggestions", [])[:5]:
            print(f"{'':20} {'':5} {'':6} {'':6} {'':11} {'':11}    ? {hint}")
    ok = [r for r in rows if r["state"] == "OK"]
    print(f"\n{len(ok)}/{len(rows)} probed candidates are registrable "
          f"({sum(r['ops'] for r in ok):,} operations)")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
