"""Render diff results as JSON and as a markdown outreach brief."""
from __future__ import annotations

import json
from typing import Dict, List

from .diff import ADDITIVE, BREAKING, POTENTIALLY_BREAKING, DiffResult
from .vendors import Vendor

MAX_DETAIL_ROWS = 12


def to_json(results: List[DiffResult]) -> str:
    payload = []
    for res in results:
        payload.append({
            "vendor": res.vendor,
            "window": {
                "old_ref": res.old_ref[:12], "old_date": res.old_date,
                "new_ref": res.new_ref[:12], "new_date": res.new_date,
            },
            "operations": {"old": res.old_op_count, "new": res.new_op_count},
            "specs": {"matched": res.specs_matched, "changed": res.specs_changed},
            "counts": {
                "raw_findings": res.raw_finding_count,
                "breaking": len(res.breaking),
                "potentially_breaking": len(res.potentially_breaking),
                "total": len(res.findings),
            },
            "findings": [f.as_dict() for f in res.findings],
        })
    return json.dumps(payload, indent=2)


def _kind_histogram(res: DiffResult, severity: str) -> Dict[str, int]:
    hist: Dict[str, int] = {}
    for finding in res.by_severity(severity):
        hist[finding.kind] = hist.get(finding.kind, 0) + 1
    return dict(sorted(hist.items(), key=lambda kv: -kv[1]))


def to_markdown(results: List[DiffResult], vendors: Dict[str, Vendor], window_days: int) -> str:
    lines: List[str] = []
    lines.append(f"# apidrift — breaking changes in the last {window_days} days\n")

    lines.append("| Vendor | Window | Ops | Breaking | Potentially | Fan-out | Top change |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    for res in results:
        top = _kind_histogram(res, BREAKING) or _kind_histogram(res, POTENTIALLY_BREAKING)
        top_kind = next(iter(top), "—")
        lines.append(
            f"| **{vendors[res.vendor].name}** | {res.old_date} → {res.new_date} "
            f"| {res.new_op_count} | {len(res.breaking)} | "
            f"{len(res.potentially_breaking)} | {res.raw_finding_count}→{len(res.findings)} | `{top_kind}` |"
        )
    total_breaking = sum(len(r.breaking) for r in results)
    lines.append(f"\n**{total_breaking} breaking changes** across "
                 f"{len(results)} vendors in {window_days} days.\n")

    for res in results:
        vendor = vendors[res.vendor]
        lines.append(f"\n## {vendor.name}\n")
        lines.append(
            f"`{vendor.repo}` · `{res.old_ref[:12]}` ({res.old_date}) → "
            f"`{res.new_ref[:12]}` ({res.new_date}) · "
            f"{res.old_op_count} → {res.new_op_count} operations · "
            f"{res.specs_changed}/{res.specs_matched} spec files changed\n"
        )
        hist = _kind_histogram(res, BREAKING)
        if hist:
            lines.append("Breaking-change kinds: " +
                         ", ".join(f"`{k}` ×{v}" for k, v in hist.items()) + "\n")
        else:
            lines.append("_No breaking changes detected in this window._\n")

        shown = res.breaking[:MAX_DETAIL_ROWS]
        for finding in shown:
            near = finding.direct_op_count
            reach = finding.affected_op_count or finding.occurrences
            ops = near or reach
            fanout = (f" · **{near} operations use it directly**" if near > 1
                      else (f" · **{reach} operations affected**" if reach > 1 else ""))
            lines.append(f"### `{finding.kind}` — `{finding.root_cause or finding.subject}`{fanout}")
            if finding.path.startswith("#"):
                # A schema finding with no concrete route: name the schema,
                # not a JSON pointer dressed up as an endpoint.
                where = f"In schema `{finding.path.rsplit('/', 1)[-1]}`"
            else:
                where = f"Seen at `{finding.method.upper()} {finding.path}`"
            if near > 1:
                where += f" and {near - 1} other operations"
                if reach > near:
                    where += (f" ({reach} in total once indirect schema "
                              f"references are followed)")
            lines.append(where + "  ")
            lines.append(f"{finding.detail}  ")
            lines.append(f"`{finding.old}` → `{finding.new}`\n")
            if finding.grep:
                lines.append("Find affected code:")
                lines.append(f"```bash\n{finding.grep}\n```")
            if finding.github_search:
                lines.append(f"[Public code search]({finding.github_search})\n")
        remaining = len(res.breaking) - len(shown)
        if remaining > 0:
            lines.append(f"\n_…and {remaining} more breaking changes "
                         f"(full list in the JSON output)._\n")
    return "\n".join(lines) + "\n"
