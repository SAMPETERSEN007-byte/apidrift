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
import re
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .classify import is_generated_path, is_vendored_path
from .dependence import prove_relevance
from .js_dependence import _SDK_PACKAGES, is_js
from .js_dependence import prove_relevance as prove_relevance_js
from .diff import (ADDITIVE_LABEL, BREAKING, ENDPOINT_KINDS, Finding,
                   label_for)
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

# Languages dependence can be PROVEN in. Everything else is counted and
# reported as UNMEASURED. TypeScript joined this list on 2026-08-21 after
# eight real repositories were scanned and every vendor-calling file in all of
# them was TypeScript -- the tool's whole output was the apology below.
PROVABLE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

# Dependence is provable only in Python. Everything else is UNMEASURED, which is
# not the same as unaffected, and the difference is the whole safety of the
# tool: a repo whose only Stripe caller is `src/pay.ts` was told
# "clean — 0 breaking changes checked", exit 0, while a sibling TypeScript file
# called a Plaid endpoint that had been deleted. Zero results is a failed
# measurement until something says otherwise.
OTHER_SOURCE_SUFFIXES = {
    ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript",
    ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".go": "Go", ".rb": "Ruby", ".java": "Java", ".kt": "Kotlin",
    ".php": "PHP", ".cs": "C#", ".rs": "Rust", ".swift": "Swift",
    ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
}

# A suggestion should point at the code someone would actually change. Anchoring
# 65 OpenAI additions to the same line of `test_llm.py` is technically a true
# statement about where the API is called and useless as advice.
_TEST_MARKERS = ("/test_", "/tests/", "/test/", "_test.py", "/conftest.py",
                 "/examples/", "/example/", "/docs/", "/samples/", "/demo")


def reaches_through_sdk(source: str, vendor: Vendor) -> bool:
    """Does this file call the vendor through its SDK rather than raw HTTP?

    It matters only for a vendor that serves DATED API versions. The SDK sends
    the version it was built against, so the vendor keeps serving that shape
    however far HEAD has moved -- which is the entire purpose of a dated
    version. A caller writing its own `fetch` sends no version header and gets
    the account default, so that one CAN drift.

    Refuted the most convincing impact this tool ever produced: langfuse reads
    `subscription.current_period_start`, removed from Stripe's subscription
    object in `2025-03-31.basil`, through `stripe-node@17.4.0`, which sends
    `2024-11-20.acacia`. Two independent auditors killed it on 2026-08-21 and
    both were right.

    Asked as an IMPORT of the SDK package, not as a substring of the vendor's
    evidence markers. The first version of this looked for `"import stripe"`
    and langfuse writes `import Stripe from "stripe"` -- the marker that
    actually matched its file was `"stripe."`, which is a method call and not
    an import at all, so the check passed straight over the case it was written
    for.
    """
    for package in _SDK_PACKAGES.get(vendor.key, ()):
        quoted = re.escape(package)
        if re.search(rf"""from\s+['"]{quoted}(/[^'"]*)?['"]""", source):
            return True
        if re.search(rf"""require\(\s*['"]{quoted}(/[^'"]*)?['"]""", source):
            return True
        if re.search(rf"""import\s+['"]{quoted}(/[^'"]*)?['"]""", source):
            return True
    key = re.escape(vendor.key)
    if re.search(rf"^\s*import\s+{key}\b", source, re.M):
        return True
    if re.search(rf"^\s*from\s+{key}(\.\w+)*\s+import\b", source, re.M):
        return True
    return False


def pinned_sdk_version(root: Path, vendor: Vendor) -> str:
    """The SDK release this repo declares for `vendor`, if it declares one.

    "You are pinned" is not actionable; "you are pinned to `stripe@^17.4.0`" is,
    because that is the number a reader can look up and the number that changes
    on the day the break arrives. Read from the manifests a checkout actually
    carries -- `package.json`, `requirements.txt`, `pyproject.toml` -- never
    from `node_modules`, which is usually absent.

    Deliberately reports the DECLARED range verbatim rather than resolving it.
    Resolving `^17.4.0` to the release that would install today is a claim about
    a registry this tool cannot see, and a wrong version number here would be
    worse than none: it is the input to the only question that matters for a
    dated-version vendor, which is what changed BETWEEN two API versions.
    """
    packages = set(_SDK_PACKAGES.get(vendor.key, ())) | {vendor.key}
    for name in ("package.json", "requirements.txt", "pyproject.toml",
                 "Pipfile", "setup.py"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if name == "package.json":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            for section in ("dependencies", "devDependencies",
                            "peerDependencies", "optionalDependencies"):
                for pkg, spec in (doc.get(section) or {}).items():
                    if pkg in packages:
                        return f"{pkg}@{spec}"
            continue
        for line in text.splitlines():
            stripped = line.strip().strip('"\'')
            for pkg in packages:
                if re.match(rf"^{re.escape(pkg)}\s*(==|>=|~=|\^|=|,|\[)", stripped) \
                        or re.match(rf"^{re.escape(pkg)}$", stripped):
                    return stripped.rstrip(",").strip()
    return ""


def _is_incidental(rel_path: str) -> bool:
    lowered = "/" + rel_path.lower()
    return any(marker in lowered for marker in _TEST_MARKERS)


# Not every addition is equally worth a developer's attention, and the
# difference is not a matter of taste. A new field on a RESPONSE requires
# nothing of you -- it simply arrives. A new field you may SEND, or a whole new
# endpoint, is something you have to choose to use. Ranking by that is what
# separates nine useful suggestions from sixty.
_ADDITION_RANK = {
    "spec_added": 0,                # a whole new API version outranks everything
    "endpoint_added": 1,
    "schema_field_added": 2,        # request-side: you could start sending it
    "param_added_optional": 3,
    "response_field_added": 4,      # arrives whether you act or not
}

DEFAULT_OPPORTUNITY_LIMIT = 12


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
    blurb: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "vendor": self.vendor, "vendor_name": self.vendor_name,
            "file": self.file, "line": self.line,
            "kind": self.kind, "label": self.label, "severity": self.severity,
            "subject": self.subject, "detail": self.detail,
            "old": self.old, "new": self.new,
            "operation": self.operation, "chain": self.chain,
            "text": self.text, "evidence": self.evidence,
            "spec_window": self.spec_window, "blurb": self.blurb,
        }


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    python_files: int = 0
    vendors_detected: Dict[str, int] = field(default_factory=dict)
    vendors_failed: Dict[str, str] = field(default_factory=dict)
    findings_considered: int = 0
    additions_considered: int = 0
    impacts: List[Impact] = field(default_factory=list)
    # Kept separate from impacts all the way to the output. Nothing here
    # is wrong with the code; conflating the two would turn a suggestion
    # into an alarm, and there are five times as many suggestions.
    opportunities: List[Impact] = field(default_factory=list)
    # Never a silent truncation. A capped list that does not say it was capped
    # reads as a census.
    opportunities_dropped: int = 0
    # {kind: count} of every addition CONSIDERED, whether or not it reached
    # this repo. Without it the report cannot say "three new endpoints, none on
    # a resource you call", and that sentence is the difference between advice
    # and a list: a reader who is shown twelve passive response fields and not
    # told the actionable ones were checked assumes they were not.
    additions_by_kind: Dict[str, int] = field(default_factory=dict)
    # {vendor_key: {language: file_count}} — files that call a vendor in a
    # language this tool cannot parse. Reported, never counted as clean.
    unmeasured: Dict[str, Dict[str, int]] = field(default_factory=dict)
    # {vendor_key: [spec paths]} with no version before the window opened.
    # Nothing behind them could be compared.
    short_history: Dict[str, List[str]] = field(default_factory=dict)
    # Impacts whose cited line is in a test, fixture, example or doc. The claim
    # may be perfectly true and it is still not a broken product: a unit test
    # asserting on a mocked field, or a vendor URL inside a `parametrize`
    # decorator proving the code does NOT match that vendor, is not a reason to
    # fail anybody's build. Eight of 74 audited impacts were exactly this
    # (2026-08-21). Reported in their own section; never in the exit status.
    incidental: List[Impact] = field(default_factory=list)
    # {vendor_key: [files]} that reach a DATED-VERSION vendor through its SDK.
    # The SDK pins the API version it shipped with, so HEAD-to-HEAD spec drift
    # does not describe what these files receive. Reported, never counted as
    # clean and never counted as broken -- see `Vendor.versioned`.
    pinned: Dict[str, List[str]] = field(default_factory=dict)
    # {vendor_key: "stripe@^17.4.0"} — the SDK release the repo DECLARES, read
    # from its manifests. The number a reader can act on.
    pinned_versions: Dict[str, str] = field(default_factory=dict)

    @property
    def unmeasured_files(self) -> int:
        return sum(sum(langs.values()) for langs in self.unmeasured.values())

    @property
    def pinned_files(self) -> int:
        return sum(len(files) for files in self.pinned.values())
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
            "additions_considered": self.additions_considered,
            "impact_count": len(self.impacts),
            "breaking_count": len(self.breaking),
            "opportunity_count": len(self.opportunities),
            "opportunities_dropped": self.opportunities_dropped,
            "additions_by_kind": self.additions_by_kind,
            "unmeasured": self.unmeasured,
            "short_history": self.short_history,
            "pinned": self.pinned,
            "pinned_versions": self.pinned_versions,
            "pinned_files": self.pinned_files,
            "unmeasured_files": self.unmeasured_files,
            "impacts": [i.as_dict() for i in self.impacts],
            "incidental_count": len(self.incidental),
            "incidental": [i.as_dict() for i in self.incidental],
            "opportunities": [o.as_dict() for o in self.opportunities],
        }


# --------------------------------------------------------------------------
# walking the checkout
# --------------------------------------------------------------------------

def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def candidate_files(root: Path, vendor_keys: Sequence[str] = ()) -> List[Path]:
    """Every source file in a provable language that the author plausibly wrote.

    A dependency copy is excluded for the same reason it is excluded from a
    lead: `site-packages/stripe/_card.py` breaking is the vendor's problem,
    not this repo's, and repairing it means reinstalling rather than editing.
    """
    found: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(PROVABLE_SUFFIXES):
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


def unmeasurable_callers(
    root: Path, vendor_keys: Sequence[str],
) -> Dict[str, Dict[str, int]]:
    """Files that call a vendor in a language dependence cannot be proven in.

    Counted from the same walk rules as the Python pass so the two numbers are
    comparable, and reported separately so an all-clear can never be printed
    over a language that was simply never opened.
    """
    out: Dict[str, Dict[str, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            suffix = Path(name).suffix.lower()
            if suffix in PROVABLE_SUFFIXES:
                continue          # proven, not unmeasured
            language = OTHER_SOURCE_SUFFIXES.get(suffix)
            if not language:
                continue
            path = Path(dirpath) / name
            rel = _relative(root, path)
            if is_generated_path(rel):
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            source = _read(path)
            if source is None:
                continue
            for key in vendor_keys:
                if is_vendored_path(rel, key):
                    continue
                if find_vendor_evidence(source, get(key), rel):
                    out.setdefault(key, {})
                    out[key][language] = out[key].get(language, 0) + 1
    return out


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
            if find_vendor_evidence(source, vendor, rel):
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
    want_opportunities: bool = False,
    opportunity_limit: int = DEFAULT_OPPORTUNITY_LIMIT,
) -> ScanResult:
    from .cli import analyse          # imported here: cli imports this module

    root = root.resolve()
    result = ScanResult(root=str(root), window_days=window_days, asof=asof)

    paths = candidate_files(root, vendor_keys)
    result.python_files = len(paths)
    by_vendor, read = detect_vendors(root, paths, vendor_keys)
    result.files_scanned = read
    result.unmeasured = unmeasurable_callers(root, vendor_keys)
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
        if diff.specs_without_history:
            result.short_history[key] = list(diff.specs_without_history)
        relevant = [f for f in diff.findings if f.severity == BREAKING]
        result.findings_considered += len(relevant)
        before = len(result.impacts)

        # A dated-version vendor reached through its SDK is pinned to the
        # version that SDK shipped with, and this diff runs HEAD to HEAD.
        # Those files are UNMEASURED for breakage, which is not the same as
        # unaffected and emphatically not the same as broken.
        provable = files
        if vendor.versioned:
            pinned = [rel for rel, source in files
                      if reaches_through_sdk(source, vendor)]
            if pinned:
                result.pinned[key] = sorted(pinned)
                declared = pinned_sdk_version(root, vendor)
                if declared:
                    result.pinned_versions[key] = declared
                provable = [(rel, src) for rel, src in files
                            if rel not in set(pinned)]

        for finding in relevant:
            for rel, source in provable:
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
        opportunities_before = len(result.opportunities)
        if want_opportunities:
            additions = [a for a in diff.additions
                         if a.kind in ADDITIVE_LABEL]
            result.additions_considered += len(additions)
            for addition in additions:
                result.additions_by_kind[addition.kind] = (
                    result.additions_by_kind.get(addition.kind, 0) + 1)
            # Production code first, so a suggestion lands where someone
            # would act on it rather than in a fixture.
            ranked = sorted(files, key=lambda pair: _is_incidental(pair[0]))
            for addition in additions:
                for rel, source in ranked:
                    relevance = (prove_relevance_js if is_js(rel)
                                 else prove_relevance)
                    proofs, _ = relevance(source, addition, vendor)
                    if not proofs:
                        continue
                    proof = proofs[0]
                    operation = ""
                    for link in proof.chain:
                        if link.startswith("which is `"):
                            operation = link[len("which is `"):].rstrip("`")
                    result.opportunities.append(Impact(
                        vendor=key, vendor_name=vendor.name, file=rel,
                        line=proof.line, kind=addition.kind,
                        label=ADDITIVE_LABEL.get(addition.kind, addition.kind),
                        severity=addition.severity,
                        subject=addition.root_cause or addition.subject,
                        detail=addition.detail, old=addition.old,
                        new=addition.new, operation=operation or addition.new,
                        chain=list(proof.chain),
                        text=proof.text.strip()[:120], evidence="",
                        spec_window=window, blurb=addition.blurb,
                    ))
                    break     # one place per addition is enough to act on
        if progress:
            progress(f"{len(result.impacts) - before} impact(s), "
                     f"{len(result.opportunities) - opportunities_before} "
                     f"opportunit"
                     f"{'y' if len(result.opportunities) - opportunities_before == 1 else 'ies'}\n")

    # Split before sorting so neither list can be read as the other.
    result.incidental = [i for i in result.impacts if _is_incidental(i.file)]
    result.impacts = [i for i in result.impacts if not _is_incidental(i.file)]
    result.incidental.sort(key=lambda i: (i.vendor, i.file, i.line, i.subject))
    result.impacts.sort(key=lambda i: (i.vendor, i.file, i.line, i.subject))
    result.opportunities.sort(
        key=lambda i: (_ADDITION_RANK.get(i.kind, 9), i.vendor, i.subject))
    if opportunity_limit and len(result.opportunities) > opportunity_limit:
        result.opportunities_dropped = (
            len(result.opportunities) - opportunity_limit)
        result.opportunities = result.opportunities[:opportunity_limit]
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
        if result.unmeasured:
            lines.append(
                f"**No breaking change was proven against this repository's "
                f"Python.** {result.findings_considered} breaking changes were "
                f"checked. This is not an all-clear — see the unmeasured "
                f"languages below."
            )
        elif not result.vendors_detected:
            lines.append("**Nothing was checked.** No file in this repository "
                         "carries an import, host or key for any vendor this "
                         "tool knows about.")
        else:
            lines.append(
                f"**No breaking change in the window lands on this "
                f"repository.** {result.findings_considered} breaking changes "
                f"were checked against every calling file; none could be "
                f"proven to reach code here."
            )
        lines.extend(_unmeasured_markdown(result))
        lines.extend(_opportunity_markdown(result))
        return "\n".join(lines) + "\n"

    by_file: Dict[str, List[Impact]] = {}
    for impact in result.impacts:
        by_file.setdefault(impact.file, []).append(impact)

    count = len(result.breaking)
    lines.append(
        f"## {count} breaking change{'' if count == 1 else 's'} "
        f"{'lands' if count == 1 else 'land'} on "
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
    lines.extend(_unmeasured_markdown(result))
    lines.extend(_opportunity_markdown(result))
    return "\n".join(lines) + "\n"


def _unmeasured_markdown(result: ScanResult) -> List[str]:
    if not result.unmeasured:
        return []
    out = ["", f"## ⚠️ {result.unmeasured_files} caller"
               f"{'' if result.unmeasured_files == 1 else 's'} could not be "
               f"checked", "",
           "Dependence is proven in Python and in JavaScript/TypeScript. "
           "These files call the same APIs in a language this tool does not "
           "parse, so they were not examined at all. **Unmeasured is not "
           "unaffected.**", "",
           "| Vendor | Language | Files |", "|---|---|---:|"]
    for key, langs in sorted(result.unmeasured.items()):
        for lang, n in sorted(langs.items()):
            out.append(f"| {get(key).name} | {lang} | {n} |")
    return out


def _opportunity_markdown(result: ScanResult) -> List[str]:
    """Additions are rendered apart from impacts, and said to be optional.

    Nothing here is broken. Presenting a suggestion in the same table as a
    break is how a useful tool becomes one people mute.
    """
    if not result.opportunities:
        if result.additions_considered:
            return ["", f"_{result.additions_considered} additions were "
                        f"checked; none reach a resource this repo calls._"]
        return []
    out = ["", f"## {len(result.opportunities)} new capabilit"
               f"{'y' if len(result.opportunities) == 1 else 'ies'} you could "
               f"adopt", "",
           "_Nothing below is broken. These are things the vendor added in "
           "the same window, on resources this repo already calls._", "",
           "| Vendor | What is new | What it does | Where you already call it |",
           "|---|---|---|---|"]
    for o in result.opportunities:
        says = (o.blurb[:120].replace("|", "\\|") + "…"
                if len(o.blurb) > 120 else o.blurb.replace("|", "\\|"))
        out.append(f"| {o.vendor_name} | {o.label}: `{o.subject}` "
                   f"| {says or '_no description in the spec_'} "
                   f"| `{o.file}:{o.line}` |")
    if result.opportunities_dropped:
        out += ["", f"_{result.opportunities_dropped} further additions ranked "
                    f"lower and are not listed — mostly new response fields, "
                    f"which arrive whether you act on them or not. Run with "
                    f"`--opportunity-limit 0` to see every one._"]
    return out


def _short_history_lines(result: ScanResult) -> List[str]:
    """Say when the tool could not see as far back as it was asked to."""
    if not result.short_history:
        return []
    out = ["", "SHORTER HISTORY THAN REQUESTED — these specs did not exist at "
               "the start of the window, so nothing before them was compared:"]
    for key, paths in sorted(result.short_history.items()):
        shown = ", ".join(paths[:3]) + ("…" if len(paths) > 3 else "")
        out.append(f"  {get(key).name}: {shown}")
    out.append("  A quiet result here means unseen, not safe.")
    return out


def _unmeasured_lines(result: ScanResult) -> List[str]:
    """Say what was not looked at. An all-clear that hides a blind spot is
    worse than no answer, because it is acted on."""
    if not result.unmeasured:
        return []
    parts = []
    for key, langs in sorted(result.unmeasured.items()):
        detail = ", ".join(f"{n} {lang}" for lang, n in sorted(langs.items()))
        parts.append(f"{get(key).name}: {detail}")
    n = result.unmeasured_files
    return ["", f"UNMEASURED — {n} file{'' if n == 1 else 's'} "
                f"{'calls' if n == 1 else 'call'} these APIs in a language "
                f"this tool cannot parse:",
            *[f"  {p}" for p in parts],
            "  Dependence is proven in Python and JavaScript/TypeScript. "
            "These files were not checked, which is not the same as "
            "unaffected."]


# A new endpoint or a field you may SEND is a decision. A new field on a
# response is not -- it arrives whether you act or not. Presenting the two the
# same way is how twelve honest suggestions read as noise: a developer shown
# `account_capabilities.bizum_payments` alongside a new endpoint concludes the
# tool cannot tell the difference, and mutes it.
_ACTIONABLE_KINDS = ("spec_added", "endpoint_added", "schema_field_added",
                     "param_added_optional")


def _opportunity_lines(result: ScanResult) -> List[str]:
    if not result.opportunities and not result.additions_by_kind:
        return []
    actionable = [o for o in result.opportunities if o.kind in _ACTIONABLE_KINDS]
    passive = [o for o in result.opportunities if o.kind not in _ACTIONABLE_KINDS]
    out: List[str] = ["", "WHAT THESE VENDORS ADDED, AND WHETHER IT TOUCHES YOU"]

    considered_actionable = sum(result.additions_by_kind.get(k, 0)
                                for k in _ACTIONABLE_KINDS)
    out.append("")
    out.append(f"  Worth a decision — {len(actionable)} of "
               f"{considered_actionable} new endpoint(s)/request field(s) "
               f"reach code you have:")
    if actionable:
        for o in actionable:
            out.append(f"    {o.vendor_name} {o.label} — {o.subject}")
            if o.blurb:
                out.append(f"        {o.blurb[:150]}")
            out.append(f"        you already call this at {o.file}:{o.line}")
    elif considered_actionable:
        # Saying this out loud is the point. Silence here reads as "nothing was
        # added", which is a different and much more comforting claim.
        out.append(f"    none — all {considered_actionable} were added on "
                   f"resources this repo does not call")
    else:
        out.append("    none — these vendors added no new endpoint or request "
                   "field in this window")

    considered_passive = (result.additions_considered - considered_actionable)
    if passive or considered_passive:
        out.append("")
        out.append(f"  Arrives on its own — {len(passive)} of "
                   f"{considered_passive} new response field(s) land on "
                   f"responses you already read. Nothing to do; they are "
                   f"listed so a schema change is not a surprise:")
        for o in passive[:8]:
            out.append(f"    {o.subject}  ({o.file}:{o.line})")
        if len(passive) > 8:
            out.append(f"    … and {len(passive) - 8} more")
    if result.opportunities_dropped:
        out.append(f"  … {result.opportunities_dropped} further suggestions "
                   f"were ranked lower and not shown. "
                   f"--opportunity-limit 0 shows all.")
    return out


def _pinned_lines(result: ScanResult) -> List[str]:
    """Say what could not be judged, every time. `clean` may not be printed
    while a pinned file exists — the same rule that already governs an
    unparseable language, applied to an unknowable API version."""
    if not result.pinned:
        return []
    out = ["", "PINNED TO AN SDK'S OWN API VERSION — these files were NOT "
           "judged for breakage:"]
    for key, files in sorted(result.pinned.items()):
        vendor = get(key)
        shown = ", ".join(files[:3])
        more = f" and {len(files) - 3} more" if len(files) > 3 else ""
        declared = result.pinned_versions.get(key)
        at = f" [{declared}]" if declared else ""
        out.append(f"  {vendor.name}{at}: {len(files)} file(s) — {shown}{more}")
    out.append("  This vendor serves dated API versions and its SDK sends the "
               "one it shipped with,")
    out.append("  so drift at HEAD does not describe what these files receive. "
               "Unmeasured, not safe.")
    return out


def _incidental_lines(result: ScanResult) -> List[str]:
    """Shown, never counted. Silence here would be a different lie."""
    if not result.incidental:
        return []
    out = ["", f"IN TEST / EXAMPLE / DOC FILES — {len(result.incidental)} "
           f"change(s) land on code that is not the product. Not in the exit "
           f"status:"]
    for impact in result.incidental[:10]:
        out.append(f"  {impact.file}:{impact.line}: {impact.vendor_name} "
                   f"{impact.label} — {impact.subject}")
    if len(result.incidental) > 10:
        out.append(f"  … and {len(result.incidental) - 10} more.")
    return out


def to_text(result: ScanResult) -> str:
    """Terminal/CI output: one line per impact, in the file:line:message form
    every editor and log scraper already knows how to jump to."""
    if not result.impacts:
        if (result.unmeasured or result.short_history or result.pinned
                or result.incidental):
            head = (f"apidrift: no impact found "
                    f"({result.findings_considered} breaking changes checked) "
                    f"— but this repo is NOT clean-checked, see below")
        elif not result.vendors_detected:
            head = ("apidrift: no calls to any known vendor found in this repo "
                    "— nothing was checked")
        else:
            head = (f"apidrift: clean — {result.findings_considered} breaking "
                    f"changes checked, none reach this repo")
        return "\n".join([head] + _short_history_lines(result)
                          + _incidental_lines(result)
                          + _pinned_lines(result)
                          + _unmeasured_lines(result)
                          + _opportunity_lines(result)) + "\n"
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
    out.extend(_short_history_lines(result))
    out.extend(_incidental_lines(result))
    out.extend(_pinned_lines(result))
    out.extend(_unmeasured_lines(result))
    out.extend(_opportunity_lines(result))
    return "\n".join(out) + "\n"


def write_outputs(result: ScanResult, out_dir: Path) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / "scan.md"
    js = out_dir / "scan.json"
    md.write_text(to_markdown(result), encoding="utf-8")
    js.write_text(json.dumps(result.as_dict(), indent=2), encoding="utf-8")
    return md, js
