"""For each named mutation, apply it and print exactly which tests go red."""
import re, shutil, subprocess, sys, tempfile
from pathlib import Path
ROOT = Path("/Users/claudebot/apidrift")
sys.path.insert(0, str(ROOT / "tests"))
import mutation_check as mc

want = set(sys.argv[1:]) if len(sys.argv) > 1 else None
for name, rel, needle, repl, expect in mc.MUTATIONS:
    if want and not any(w in name for w in want):
        continue
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "t"
        shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(
            ".venv", ".cache", "out", "__pycache__", ".git", ".snapshots"))
        target = tree / rel
        src = target.read_text()
        if needle not in src:
            print(f"STALE  {name}"); continue
        target.write_text(src.replace(needle, repl, 1))
        out = subprocess.run([str(ROOT/".venv/bin/python"), "-m", "unittest",
                              "discover", "-s", "tests", "-v"], cwd=str(tree),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT
                             ).stdout.decode("utf-8", "replace")
        red = sorted(set(re.findall(r"^(?:FAIL|ERROR): (\w+)", out, re.M)))
        ok = "KILLED" if all(t in red for t in expect) else "SURVIVED"
        print(f"{ok:8s} {name}")
        print(f"         red: {red or 'nothing'}")
