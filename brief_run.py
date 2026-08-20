"""Generate one outreach brief per vendor, containing only that vendor's data.

A combined five-vendor report is not sendable: nobody wants a document that
details a competitor's breakage alongside their own. Each brief stands alone.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from apidrift.classify import (ECOSYSTEM, INTEGRATOR, dedupe_by_repo,
                               partition)
from apidrift.vendors import get

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out" / "briefs"


def kind_table(findings: List[dict]) -> str:
    counts: Dict[str, int] = {}
    for f in findings:
        if f["severity"] == "breaking":
            counts[f["kind"]] = counts.get(f["kind"], 0) + 1
    rows = sorted(counts.items(), key=lambda kv: -kv[1])
    lines = ["| Change type | Count |", "|---|---:|"]
    lines += [f"| `{k}` | {v} |" for k, v in rows]
    return "\n".join(lines)


def lead_rows(leads: List[dict], limit: int = 12) -> str:
    lines = ["| Repository | File | Line | Code |", "|---|---|---:|---|"]
    for lead in leads[:limit]:
        site = (lead.get("sites") or [{}])[0]
        code = str(site.get("text", "")).replace("|", "\\|")[:88]
        lines.append(
            f"| [{lead['repo']}](https://github.com/{lead['repo']}) "
            f"| `{lead['file'].rsplit('/', 1)[-1]}` | {site.get('line', '?')} "
            f"| `{code}` |"
        )
    return "\n".join(lines)


def build(vendor_key: str, entry: dict, leads: List[dict], window: dict) -> str:
    vendor = get(vendor_key)
    breaking = [f for f in entry["findings"] if f["severity"] == "breaking"]
    potential = [f for f in entry["findings"] if f["severity"] == "potentially_breaking"]
    buckets = partition(leads, vendor_key)
    integrators = dedupe_by_repo(buckets[INTEGRATOR])
    ecosystem = dedupe_by_repo(buckets[ECOSYSTEM])
    excluded = len(buckets["vendor_owned"]) + len(buckets["corpus"])

    out: List[str] = []
    out.append(f"# {vendor.name} — breaking API changes, "
               f"{window['old_date']} to {window['new_date']}\n")
    out.append(
        f"Generated from `{vendor.repo}` at `{window['old_ref']}` → "
        f"`{window['new_ref']}` by diffing the published OpenAPI spec and "
        f"classifying each change by what it does to a consumer.\n")

    out.append("## Summary\n")
    out.append(f"| | |\n|---|---|")
    out.append(f"| Operations in spec | {entry['operations']['new']} |")
    out.append(f"| Breaking changes | **{len(breaking)}** |")
    out.append(f"| Potentially breaking | {len(potential)} |")
    out.append(f"| Raw findings before de-duplication | {entry['counts']['raw_findings']} |")
    out.append(f"| Public repos verified as affected | **{len(integrators) + len(ecosystem)}** |")
    out.append("")

    out.append("## What changed\n")
    out.append(kind_table(entry["findings"]))
    out.append("")

    top = sorted(breaking, key=lambda f: -f["occurrences"])[:6]
    out.append("### Highest fan-out changes\n")
    for f in top:
        fan = (f" — reaches **{f['occurrences']} operations**"
               if f["occurrences"] > 1 else "")
        out.append(f"- `{f['root_cause'] or f['subject']}`{fan}  \n  "
                   f"{f['detail'][:180]}")
    out.append("")

    out.append("## Who this lands on\n")
    out.append(
        "Every row below was confirmed by fetching the file and parsing it. "
        "A match inside a comment, a docstring or a prose string does not "
        "count as a call site, and a file with no import, host or key tying it "
        "to your API is discarded regardless of what it matches.\n")

    if integrators:
        out.append(f"### Applications calling the affected endpoints "
                   f"({len(integrators)})\n")
        out.append(lead_rows(integrators))
        out.append("")
    if ecosystem:
        out.append(f"### Third-party SDKs and wrappers ({len(ecosystem)})\n")
        out.append(
            "These are higher leverage than a single application: everything "
            "built on them inherits the break.\n")
        out.append(lead_rows(ecosystem))
        out.append("")
    if excluded:
        out.append(f"_{excluded} further matches were discarded as your own "
                   f"repositories or as dataset mirrors._\n")

    out.append("## Method and limits\n")
    out.append(
        "- Findings come from the spec you publish, diffed across the window "
        "above. Nothing here is inferred from documentation or changelogs.\n"
        "- One edit to a shared schema is reported once, with the number of "
        "operations it reaches, rather than once per operation.\n"
        "- Search covers **public GitHub repositories with Python as the "
        "detected language only**. It is a floor, not a census: private "
        "repositories are invisible, and other languages were not swept.\n"
        "- Python call sites are established with the `ast` module. Other "
        "languages fall back to a lexical scan and are labelled as weaker "
        "evidence.\n")
    return "\n".join(out) + "\n"


def main() -> int:
    findings = {e["vendor"]: e for e in json.load(open(ROOT / "out" / "findings.json"))}
    leads = json.load(open(ROOT / "out" / "leads.json"))
    OUT.mkdir(parents=True, exist_ok=True)

    written = []
    for vendor_key, entry in findings.items():
        text = build(vendor_key, entry, leads.get(vendor_key, []), entry["window"])
        path = OUT / f"{vendor_key}.md"
        path.write_text(text, encoding="utf-8")
        vendor_leads = leads.get(vendor_key, [])
        buckets = partition(vendor_leads, vendor_key)
        targets = len(dedupe_by_repo(buckets[INTEGRATOR])) + \
            len(dedupe_by_repo(buckets[ECOSYSTEM]))
        written.append((vendor_key, path, len(entry["findings"]), targets))

    print(f"{'vendor':10s} {'findings':>9s} {'outreach repos':>15s}  file")
    for key, path, n_findings, targets in written:
        print(f"{key:10s} {n_findings:9d} {targets:15d}  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
