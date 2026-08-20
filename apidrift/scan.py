"""Scan a local repository for breaking vendor-API changes that land on ITS code.

Everything else in this project points the engine at strangers: prospect the
whole of public GitHub, fetch a file over the API, try to prove dependence from
one file in isolation. Three adversarial audits refuted 9, 9 and 10 of 10 such
leads. The engine was never the problem -- the vantage point was. Proving that
`card.iin` is read off a Stripe response is hard when you can see ONE file of a
repo you do not have; it is tractable when you have the checkout.

So this module inverts the direction. Same diff, same dependence proof, aimed
at a repository the caller owns:

    apidrift scan ~/myrepo --days 30

It answers one question -- "which of the last N days of vendor API changes
break code in THIS repo, and on which line" -- and it answers it with a proof
chain, not a match count. Exit status is the product: non-zero means a change
lands on code that is actually here, which is the thing a CI job can gate on.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .classify import is_generated_path, is_vendored_path
from .diff import BREAKING, ENDPOINT_KINDS, Finding, label_for
from .loader import SpecParseError
from .source import GitError
from .vendors import VENDORS, Vendor, get
from .verify import (CONFIRMED, _identifier_present, _named_identifier,
                     find_vendor_evidence, verify_source)

# Directories that never contain code the repo's author maintains. Distinct
# from classify's vendored-path rules, which are about GitHub search results;
# these are the local-checkout equivalents.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "site-packages",
    "dist", "build", "target", "vendor", "third_party", "external", ".next",
    ".terraform", "migrations", ".idea", ".vscode", "htmlcov", ".eggs",
})

# A file larger than this is a data blob or a bundle, not hand-written code.
MAX_FILE_BYTES = 512 * 1024

PY_SUFFIX = ".py"


@dataclass
class Impact:
    """One breaking change, proven to land on one line of this repository."""
    vendor: str
    vendor_name: str
    file: str                       # repo-relative, POSIX separators
    line: int
    kind: str
    label: str
    severity: str
    subject: str
    detail: str
    old: str
    new: str
    operation: str                  # the operation the FILE calls, from the proof
    chain: List[str] = field(default_factory=list)
    text: str = ""
    evidence: str = ""
    spec_window: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "vendor": self.vendor, "vendor_name": self.vendor_name,
            "file": self.file, "line": self.line,
            "kind": self.kind, "label": self.label, "severity": self.severity,
            "subject": self.subject, "detail": self.detail,
            "old": self.old, "new": self.new,
            "operation": self.operation, "chain": self.chain,
            "text": self.text, "evidence": self.evidence,
            "spec_window": self.spec_window,
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    python_files: int = 0
    vendors_detected: Dict[str, int] = field(default_factory=dict)
    vendors_failed: Dict[str, str] = field(default_factory=dict)
    findings_considered: int = 0
    impacts: List[Impact] = field(default_factory=list)
    window_days: int = 90
    asof: str = ""

    @property
    def breaking(self) -> List[Impact]:
        return [i for i in self.impacts if i.severity == BREAKING]

    def as_dict(self) -> Dict[str, object]:
        return {
            "root": self.root,
            "asof": self.asof,
            "window_days": self.window_days,
            "python_files": self.python_files,
            "files_scanned": self.files_scanned,
            "vendors_detected": self.vendors_detected,
            "vendors_failed": self.vendors_failed,
            "findings_considered": self.findings_considered,
            "impact_count": len(self.impacts),
            "breaking_count": len(self.breaking),
            "impacts": [i.as_dict() for i in self.impacts],
        }


# --------------------------------------------------------------------------
# walking the checkout
# --------------------------------------------------------------------------

def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def candidate_files(root: Path, vendor_keys: Sequence[str] = ()) -> List[Path]:
    """Every Python file in the checkout that the repo's author plausibly wrote.

    A dependency copy is excluded for the same reason it is excluded from a
    lead: `site-packages/stripe/_card.py` breaking is the vendor's problem,
    not this repo's, and repairing it means reinstalling rather than editing.
    """
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(PY_SUFFIX):
                continue
            path = Path(dirpath) / name
            rel = _relative(root, path)
            if is_generated_path(rel):
                continue
            if any(is_vendored_path(rel, key) for key in vendor_keys or [""]):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append(path)
    found.sort()
    return found


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return None


def detect_vendors(
    root: Path, paths: Sequence[Path], vendor_keys: Sequence[str],
) -> Tuple[Dict[str, List[Tuple[str, str]]], int]:
    """Which vendors this repo actually calls, and the files that call them.

    Returns {vendor_key: [(relative_path, source)]} plus the number of files
    read. A file with no import, host or key for a vendor cannot be a caller of
    it, and skipping those here is what keeps the scan linear in repo size
    rather than in repo size x findings.
    """
    by_vendor: Dict[str, List[Tuple[str, str]]] = {k: [] for k in vendor_keys}
    read = 0
    for path in paths:
        source = _read(path)
        if source is None:
            continue
        read += 1
        rel = _relative(root, path)
        for key in vendor_keys:
            vendor = get(key)
            if is_vendored_path(rel, key):
                continue
            if find_vendor_evidence(source, vendor):
                by_vendor[key].append((rel, source))
    return {k: v for k, v in by_vendor.items() if v}, read


# --------------------------------------------------------------------------
# the prefilter
# --------------------------------------------------------------------------

def _static_segments(path: str, minimum: int = 4) -> List[str]:
    """Literal path segments long enough to be worth searching for."""
    return [seg for seg in path.split("/")
            if seg and "{" not in seg and len(seg) >= minimum]


def can_possibly_match(source: str, finding: Finding) -> bool:
    """A sound, cheap "no". Never rejects a file `prove()` would have accepted.

    For a change that names a field, `prove()` requires that name to be read or
    sent, so a file that never spells it cannot qualify. For an operation-level
    change, `find_operation_calls` matches a path LITERAL in the source against
    the template, and a literal can only match if the template's static
    segments appear -- so a file containing none of them cannot qualify either,
    unless the change carries SDK idioms, which are checked separately.
    """
    identifier = _named_identifier(finding)
    if identifier and finding.kind not in ENDPOINT_KINDS:
        return _identifier_present(source, identifier)

    if finding.kind in ENDPOINT_KINDS:
        idioms = [s for s in (finding.signatures or []) if not s.startswith("/")]
        if any(idiom in source for idiom in idioms):
            return True
        targets = list(finding.affected_ops or [])
        if finding.path and not finding.path.startswith("#"):
            targets.append(f"{finding.method.upper()} {finding.path}")
        if not targets:
            return True
        for op_key in targets[:40]:
            _, _, op_path = op_key.partition(" ")
            segments = _static_segments(op_path)
            if not segments:
                return True          # nothing distinctive to filter on
            if any(seg in source for seg in segments):
                return True
        return False
    return True


# --------------------------------------------------------------------------
# the scan
# --------------------------------------------------------------------------

def scan_repo(
    root: Path,
    since: str,
    vendor_keys: Sequence[str],
    cache_dir: Path,
    fetch: bool = False,
    asof: str = "",
    window_days: int = 90,
    progress=None,
) -> ScanResult:
    from .cli import analyse          # imported here: cli imports this module

    root = root.resolve()
    result = ScanResult(root=str(root), window_days=window_days, asof=asof)

    paths = candidate_files(root, vendor_keys)
    result.python_files = len(paths)
    by_vendor, read = detect_vendors(root, paths, vendor_keys)
    result.files_scanned = read
    result.vendors_detected = {k: len(v) for k, v in by_vendor.items()}

    for key, files in sorted(by_vendor.items()):
        vendor = get(key)
        if progress:
            progress(f"[{key}] {len(files)} calling files … ")
        try:
            diff = analyse(vendor, cache_dir, since, fetch)
        except (GitError, SpecParseError) as exc:
            result.vendors_failed[key] = str(exc)[:200]
            if progress:
                progress("spec unavailable\n")
            continue

        window = f"{diff.old_date} → {diff.new_date}"
        relevant = [f for f in diff.findings if f.severity == BREAKING]
        result.findings_considered += len(relevant)
        before = len(result.impacts)

        for finding in relevant:
            for rel, source in files:
                if not can_possibly_match(source, finding):
                    continue
                verdict, reason, evidence, sites = verify_source(
                    source, rel, finding, vendor)
                if verdict != CONFIRMED or not sites:
                    continue
                site = sites[0]
                operation = ""
                for link in site.chain:
                    if link.startswith("which is `"):
                        operation = link[len("which is `"):].rstrip("`")
                if not operation:
                    operation = f"{finding.method.upper()} {finding.path}"
                result.impacts.append(Impact(
                    vendor=key, vendor_name=vendor.name, file=rel,
                    line=site.line, kind=finding.kind,
                    label=label_for(finding.kind), severity=finding.severity,
                    subject=finding.root_cause or finding.subject,
                    detail=finding.detail, old=finding.old, new=finding.new,
                    operation=operation, chain=list(site.chain),
                    text=site.text.strip()[:120], evidence=evidence,
                    spec_window=window,
                ))
        if progress:
            progress(f"{len(result.impacts) - before} impact(s)\n")

    result.impacts.sort(key=lambda i: (i.vendor, i.file, i.line, i.subject))
    return result


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

def to_markdown(result: ScanResult) -> str:
    lines: List[str] = []
    name = Path(result.root).name
    lines.append(f"# apidrift — `{name}`")
    lines.append("")
    detected = ", ".join(f"{get(k).name} ({n} files)"
                         for k, n in sorted(result.vendors_detected.items()))
    lines.append(
        f"Scanned **{result.files_scanned} Python files** over the last "
        f"**{result.window_days} days**. "
        f"APIs this repo calls: {detected or '_none detected_'}."
    )
    lines.append("")

    if result.vendors_failed:
        for key, why in sorted(result.vendors_failed.items()):
            lines.append(f"> ⚠️ `{key}` spec unavailable — {why}")
        lines.append("")

    if not result.impacts:
        lines.append(
            f"**No breaking change in the window lands on this repository.** "
            f"{result.findings_considered} breaking changes were checked "
            f"against every calling file; none could be proven to reach code "
            f"here."
        )
        return "\n".join(lines) + "\n"

    by_file: Dict[str, List[Impact]] = {}
    for impact in result.impacts:
        by_file.setdefault(impact.file, []).append(impact)

    lines.append(
        f"## {len(result.breaking)} breaking change"
        f"{'' if len(result.breaking) == 1 else 's'} land on "
        f"{len(by_file)} file{'' if len(by_file) == 1 else 's'}"
    )
    lines.append("")
    lines.append("| File | Line | Vendor | Change | What broke |")
    lines.append("|---|---:|---|---|---|")
    for impact in result.impacts:
        lines.append(
            f"| `{impact.file}` | {impact.line} | {impact.vendor_name} "
            f"| {impact.label} | `{impact.subject}` |"
        )
    lines.append("")

    for path, impacts in by_file.items():
        lines.append(f"### `{path}`")
        lines.append("")
        for impact in impacts:
            lines.append(
                f"**{path}:{impact.line}** — {impact.label}: "
                f"`{impact.subject}`"
            )
            lines.append("")
            lines.append(f"```python\n{impact.text}\n```")
            lines.append("")
            lines.append(f"- {impact.detail}")
            lines.append(f"- `{impact.old}` → `{impact.new}`")
            lines.append(f"- calls `{impact.operation}`")
            lines.append(f"- proof: {' → '.join(impact.chain)}")
            lines.append(
                f"- source: {impact.vendor_name} OpenAPI spec, "
                f"{impact.spec_window}"
            )
            lines.append("")
    return "\n".join(lines) + "\n"


def to_text(result: ScanResult) -> str:
    """Terminal/CI output: one line per impact, in the file:line:message form
    every editor and log scraper already knows how to jump to."""
    if not result.impacts:
        return (f"apidrift: clean — {result.findings_considered} breaking "
                f"changes checked, none reach this repo\n")
    out = []
    for impact in result.impacts:
        out.append(
            f"{impact.file}:{impact.line}: {impact.vendor_name} "
            f"{impact.label} — {impact.subject} "
            f"({impact.old} → {impact.new}) via {impact.operation}"
        )
    out.append("")
    out.append(f"apidrift: {len(result.breaking)} breaking change(s) land on "
               f"this repository")
    return "\n".join(out) + "\n"


def write_outputs(result: ScanResult, out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "scan.md"
    js = out_dir / "scan.json"
    md.write_text(to_markdown(result), encoding="utf-8")
    js.write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
    return md, js
