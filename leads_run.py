"""Full pipeline: findings -> code-search candidates -> verified leads.

Prints the rejection breakdown as well as the survivors, because the ratio is
the thing that tells you whether the outreach list is real.
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apidrift.diff import Finding
from apidrift.prospect import prospect
from apidrift.vendors import get
from apidrift.verify import CONFIRMED, LIKELY, verify_candidate

ROOT = Path(__file__).resolve().parent
FINDINGS_PER_VENDOR = int(sys.argv[1]) if len(sys.argv) > 1 else 2
CANDIDATES_PER_FINDING = int(sys.argv[2]) if len(sys.argv) > 2 else 10
LANGUAGE = sys.argv[3] if len(sys.argv) > 3 else "python"
MAX_ATTEMPTS = int(sys.argv[5]) if len(sys.argv) > 5 else 14
VENDOR_FILTER = (None if len(sys.argv) <= 4 or sys.argv[4] in ("all", "")
                 else sys.argv[4].split(","))


def load_findings(entry):
    return [
        Finding(
            kind=f["kind"], severity=f["severity"], op_key=f["op_key"], path=f["path"],
            method=f["method"], detail=f["detail"], subject=f["subject"],
            old=f["old"], new=f["new"], operation_id=f.get("operation_id"),
            signatures=f["signatures"], occurrences=f["occurrences"],
            root_cause=f.get("root_cause", ""),
            affected_ops=f.get("affected_ops") or [],
            affected_op_count=f.get("affected_op_count") or 0,
        )
        for f in entry["findings"] if f["severity"] == "breaking"
    ]


def main() -> int:
    data = json.load(open(ROOT / "out" / "findings.json"))
    verdict_counts: collections.Counter = collections.Counter()
    leads = []
    report = {}

    for entry in data:
        if VENDOR_FILTER and entry["vendor"] not in VENDOR_FILTER:
            continue
        vendor = get(entry["vendor"])
        findings = load_findings(entry)
        if not findings:
            continue
        print(f"\n[{vendor.name}]")
        ranked = sorted(findings, key=lambda f: -f.occurrences)
        prospects = prospect(ranked, vendor, limit=FINDINGS_PER_VENDOR,
                             language=LANGUAGE, verbose=True,
                             max_attempts=MAX_ATTEMPTS)
        by_finding = {p.root_cause: p for p in prospects}

        vendor_leads = []
        for finding in ranked:
            key = finding.root_cause or finding.subject
            found = by_finding.get(key)
            if not found or found.precision != "usable" or not found.hits:
                continue
            print(f"      verifying {len(found.hits[:CANDIDATES_PER_FINDING])} "
                  f"candidates for {key} …")
            for hit in found.hits[:CANDIDATES_PER_FINDING]:
                verdict = verify_candidate(hit.repo, hit.file_path, hit.url,
                                           finding, vendor)
                verdict_counts[verdict.verdict] += 1
                mark = "LEAD " if verdict.is_lead else "     "
                print(f"        {mark}{verdict.verdict:22s} {hit.repo[:38]:40s} "
                      f"{verdict.reason[:44]}")
                if verdict.is_lead:
                    record = verdict.as_dict()
                    record["vendor"] = vendor.key
                    record["breaks_on"] = (
                        f"{finding.kind} on {finding.method.upper()} {finding.path}"
                        if key in ("security", "server", "operation")
                        else key)
                    record["change"] = finding.detail
                    vendor_leads.append(record)
                    leads.append(record)
        report[vendor.key] = vendor_leads

    # Merge rather than overwrite: a run scoped to a vendor filter must not
    # delete the vendors it was not asked to look at.
    out_path = ROOT / "out" / f"leads_{LANGUAGE}.json"
    merged = {}
    if out_path.exists():
        merged = json.load(open(out_path))
    merged.update(report)
    out_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")

    total = sum(verdict_counts.values())
    print("\n" + "=" * 78)
    print(f"{total} candidates verified -> {len(leads)} real leads "
          f"({len(leads) * 100 // max(total, 1)}% survival)")
    for verdict, count in verdict_counts.most_common():
        print(f"   {count:4d}  {verdict}")
    if leads:
        print("\nVerified leads (repo, file, line, the code that breaks):")
        for lead in leads:
            site = lead["sites"][0] if lead["sites"] else {"line": "?", "text": ""}
            print(f"  {lead['vendor']:8s} {lead['repo'][:34]:36s} "
                  f"{lead['file'].rsplit('/', 1)[-1][:22]:24s} :{site['line']}")
            print(f"           breaks on {lead['breaks_on']} -> {site['text'][:78]}")
    print(f"\nwritten to {ROOT / 'out' / 'leads.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
