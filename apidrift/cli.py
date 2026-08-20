"""apidrift — detect breaking API changes and emit the search that finds who breaks."""
from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import signatures as sig
from .diff import BREAKING, DiffResult, Finding, collapse, diff_specs
from .loader import Operation, SpecParseError, load_spec
from .report import to_json, to_markdown
from .source import GitError, SpecPair, spec_pairs
from .vendors import DEFAULT_VENDORS, VENDORS, Vendor, get

ROOT = Path(__file__).resolve().parent.parent


def _spec_removed_finding(pair: SpecPair) -> Finding:
    return Finding(
        kind="spec_removed", severity=BREAKING,
        op_key=pair.path, path="/", method="get",
        subject=pair.path, old=pair.path, new="<removed>",
        detail=f"the entire spec `{pair.path}` was removed from the repo",
        spec_file=pair.path,
    )


def analyse(vendor: Vendor, cache_dir: Path, since: str, fetch: bool) -> DiffResult:
    pairs, meta = spec_pairs(vendor, cache_dir, since, fetch=fetch)
    result = DiffResult(
        vendor=vendor.key,
        old_ref=meta["old_ref"], new_ref=meta["new_ref"],
        old_date=meta["old_date"], new_date=meta["new_date"],
        specs_matched=int(meta["specs_matched"]),
        specs_changed=int(meta["specs_changed"]),
    )
    parse_errors: List[str] = []

    for pair in pairs:
        if pair.old is None:
            continue  # brand-new spec file: purely additive
        if pair.new is None:
            result.findings.append(_spec_removed_finding(pair))
            continue
        try:
            old_spec = load_spec(pair.old.raw, pair.old.path)
            new_spec = load_spec(pair.new.raw, pair.new.path)
        except SpecParseError as exc:
            parse_errors.append(str(exc))
            continue
        result.old_op_count += old_spec.op_count
        result.new_op_count += new_spec.op_count
        sub = diff_specs(vendor.key, old_spec, new_spec, meta)
        for finding in sub.findings:
            finding.spec_file = pair.path
        result.findings.extend(sub.findings)

    if parse_errors and not result.findings:
        raise SpecParseError("; ".join(parse_errors[:3]))

    result.raw_finding_count = len(result.findings)
    result.findings = collapse(result.findings)
    sig.annotate(result.findings, vendor)
    from .diff import SEVERITY_RANK
    result.findings.sort(
        key=lambda f: (SEVERITY_RANK[f.severity], f.spec_file, f.path, f.method, f.kind, f.subject)
    )
    return result


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="apidrift", description=__doc__)
    parser.add_argument("--vendors", default=",".join(DEFAULT_VENDORS),
                        help="comma-separated vendor keys, or 'all'")
    parser.add_argument("--days", type=int, default=90,
                        help="look-back window in days (default: 90)")
    parser.add_argument("--asof", default=None,
                        help="treat this ISO date as 'today' (default: system date)")
    parser.add_argument("--fetch", action="store_true",
                        help="git fetch before diffing (default: use local cache)")
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--out", default=str(ROOT / "out"))
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    keys = sorted(VENDORS) if args.vendors == "all" else [
        k.strip() for k in args.vendors.split(",") if k.strip()
    ]
    vendors: Dict[str, Vendor] = {k: get(k) for k in keys}

    today = dt.date.fromisoformat(args.asof) if args.asof else dt.date.today()
    since = (today - dt.timedelta(days=args.days)).isoformat()

    cache_dir, out_dir = Path(args.cache), Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[DiffResult] = []
    failures: List[str] = []
    for key, vendor in vendors.items():
        if not args.quiet:
            print(f"[{key}] {vendor.repo} … ", end="", flush=True, file=sys.stderr)
        try:
            result = analyse(vendor, cache_dir, since, args.fetch)
        except (GitError, SpecParseError) as exc:
            failures.append(f"{key}: {exc}")
            if not args.quiet:
                print("FAILED", file=sys.stderr)
            continue
        results.append(result)
        if not args.quiet:
            print(f"{len(result.breaking)} breaking / "
                  f"{len(result.potentially_breaking)} potential "
                  f"({result.specs_changed}/{result.specs_matched} specs changed)",
                  file=sys.stderr)

    if not results:
        print("no vendors analysed successfully", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        return 1

    (out_dir / "findings.json").write_text(to_json(results), encoding="utf-8")
    (out_dir / "report.md").write_text(
        to_markdown(results, vendors, args.days), encoding="utf-8"
    )

    if failures and not args.quiet:
        print("\npartial failures:", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)

    total = sum(len(r.breaking) for r in results)
    if not args.quiet:
        print(f"\n{total} breaking changes → {out_dir/'report.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
