"""Run the prospecting pass over the current findings and write the lead list."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apidrift.diff import Finding
from apidrift.prospect import prospect
from apidrift.vendors import get

ROOT = Path(__file__).resolve().parent
PER_VENDOR = int(sys.argv[1]) if len(sys.argv) > 1 else 2

data = json.load(open(ROOT / "out" / "findings.json"))
report = {}
for entry in data:
    vendor = get(entry["vendor"])
    findings = [
        Finding(
            kind=f["kind"], severity=f["severity"], op_key=f["op_key"],
            path=f["path"], method=f["method"], detail=f["detail"],
            subject=f["subject"], old=f["old"], new=f["new"],
            operation_id=f.get("operation_id"), signatures=f["signatures"],
            occurrences=f["occurrences"], root_cause=f.get("root_cause", ""),
        )
        for f in entry["findings"] if f["severity"] == "breaking"
    ]
    if not findings:
        continue
    print(f"\n[{vendor.name}]")
    report[vendor.key] = [p.as_dict() for p in
                          prospect(findings, vendor, limit=PER_VENDOR)]

out_path = ROOT / "out" / "prospects.json"
out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

print("\n" + "=" * 74)
usable = [p for v in report.values() for p in v if p["precision"] == "usable"]
low = [p for v in report.values() for p in v if p["precision"] == "low"]
named = {h["repo"] for p in usable for h in p["hits"]}
print(f"{len(usable)} queries returned a usable lead list "
      f"({sum(p['total_count'] for p in usable):,} candidate files, "
      f"{len(named)} repos sampled); {len(low)} were too broad to use")
for vkey, entries in report.items():
    for p in entries:
        if p["hits"] and p["precision"] == "usable":
            repos = ", ".join(dict.fromkeys(h["repo"] for h in p["hits"]))[:56]
            print(f"  {vkey:8s} {p['root_cause'][:30]:32s} "
                  f"{p['total_count']:6d} candidate files · {repos}")
