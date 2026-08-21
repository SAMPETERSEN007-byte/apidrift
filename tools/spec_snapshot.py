"""Extract a vendor's RAW spec bytes at two dates, for an auditor to read.

Deliberately dumb plumbing. It runs `git show` and writes files; it decides
nothing, parses nothing and knows no rules. An auditor who used the engine's
own resolver would inherit the engine's blind spots, which is this project's
most-repeated defect -- so this hands over the document and gets out of the
way.

    ./.venv/bin/python tools/spec_snapshot.py openai 2023-08-21 2026-08-21
    -> /tmp/apidrift-audit/openai/old/... and .../new/...
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apidrift.vendors import get                                   # noqa: E402

CACHE = ROOT / ".cache"
OUT = Path("/tmp/apidrift-audit")


def _git(cache: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(cache), *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise SystemExit(f"git {' '.join(args[:3])}: "
                         f"{proc.stderr.decode('utf-8', 'replace')[:300]}")
    return proc.stdout.decode("utf-8", "replace").strip()


def commit_at(cache: Path, date: str) -> str:
    sha = _git(cache, "rev-list", "-1", f"--before={date}T23:59:59", "HEAD")
    if not sha:
        raise SystemExit(f"no commit before {date} in {cache.name}")
    return sha


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    key, old_date, new_date = sys.argv[1], sys.argv[2], sys.argv[3]
    vendor = get(key)
    cache = CACHE / vendor.repo.replace("/", "_")
    if not (cache / ".git").is_dir():
        raise SystemExit(f"no clone at {cache}")

    dest = OUT / key
    for label, date in (("old", old_date), ("new", new_date)):
        sha = commit_at(cache, date)
        stamp = _git(cache, "show", "-s", "--format=%ci", sha)
        names = _git(cache, "ls-tree", "-r", "--name-only", sha).splitlines()
        wanted = [n for n in names
                  if n.endswith((".json", ".yaml", ".yml"))
                  and ("openapi" in n.lower() or "spec" in n.lower()
                       or n == vendor.spec_path or "api" in n.lower())]
        target = dest / label
        target.mkdir(parents=True, exist_ok=True)
        written = 0
        for name in wanted:
            blob = subprocess.run(["git", "-C", str(cache), "show",
                                   f"{sha}:{name}"], stdout=subprocess.PIPE).stdout
            path = target / name.replace("/", "__")
            path.write_bytes(blob)
            written += 1
        print(f"{label}: {sha[:12]} {stamp}  {written} file(s) -> {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
