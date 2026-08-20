"""Turn a finding into a list of public repositories that will actually break.

The diff says *what* changed. This says *who* it lands on — which is the only
part a vendor is willing to pay for.
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .diff import Finding
from .vendors import Vendor

# GitHub code search allows 10 requests/minute for an authenticated user.
CODE_SEARCH_QPM = 10
_SPACING = 60.0 / CODE_SEARCH_QPM


@dataclass
class Hit:
    repo: str
    stars: int
    file_path: str
    url: str


@dataclass
class Prospect:
    finding_kind: str
    root_cause: str
    query: str
    total_count: int = 0
    hits: List[Hit] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def precision(self) -> str:
        """A query matching thousands of files has not identified anybody."""
        if self.error:
            return "error"
        if self.total_count == 0:
            return "none"
        return "low" if self.total_count > 2000 else "usable"

    def as_dict(self) -> Dict[str, object]:
        return {
            "finding_kind": self.finding_kind,
            "root_cause": self.root_cause,
            "query": self.query,
            "total_count": self.total_count,
            "precision": self.precision,
            "error": self.error,
            "hits": [{"repo": h.repo, "stars": h.stars,
                      "file": h.file_path, "url": h.url} for h in self.hits],
        }


class GhError(RuntimeError):
    pass


def _gh_code_search(query: str, per_page: int = 20) -> Dict:
    proc = subprocess.run(
        ["gh", "api", "-X", "GET", "search/code",
         "-f", f"q={query}", "-f", f"per_page={per_page}"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise GhError(proc.stderr.decode("utf-8", "replace").strip()[:200])
    return json.loads(proc.stdout.decode("utf-8", "replace"))


_ENDPOINT_KINDS = ("endpoint_removed", "endpoint_moved", "spec_removed",
                   "response_status_removed", "security_requirement_added",
                   "server_url_changed")

# Tokens too common to discriminate anything on their own.
_WEAK_TOKENS = frozenset({
    "id", "type", "name", "url", "data", "code", "key", "user", "text",
    "value", "status", "object", "items", "input", "output", "error",
})


def _leaf(finding: Finding) -> str:
    subject = finding.root_cause or finding.subject
    leaf = subject.split(".")[-1].replace("[]", "").strip("<>")
    return leaf if leaf and not leaf.startswith("<") else ""


def build_query(finding: Finding, vendor: Vendor, language: str = "") -> str:
    """Build the most discriminating code-search query for one finding.

    Neither half works alone. The endpoint path alone matches every caller of
    that endpoint whether or not they touch the changed field; the field name
    alone matches every unrelated use of a common word. Requiring *both* in the
    same file is what makes the result a lead list rather than a word count:
    `"iin" "/v1/customers"` returns 155 files where `"iin" stripe` returns 5,632.
    """
    terms: List[str] = []
    path_literal = ""
    if finding.path and finding.path != "/":
        path_literal = (finding.path.split("{", 1)[0].rstrip("/")
                        if "{" in finding.path else finding.path)

    leaf = _leaf(finding)
    # A newly-required field is verified by its ABSENCE, so searching for it
    # would return precisely the callers who are already fine.
    from .verify import _ABSENCE_KINDS
    field_usable = (finding.kind not in _ENDPOINT_KINDS
                    and finding.kind not in _ABSENCE_KINDS
                    and len(leaf) >= 3 and leaf.lower() not in _WEAK_TOKENS)

    if field_usable:
        terms.append(f'"{leaf}"')
    if len(path_literal) > 6:
        terms.append(f'"{path_literal}"')

    if not terms:
        for candidate in finding.signatures:
            if len(candidate) > 8 and " " not in candidate and candidate[0] not in "'\"":
                terms.append(f'"{candidate}"')
                break
    if not terms:
        return ""

    # One short literal on its own is not specific enough to name a vendor's
    # customers; anchor it. Two literals already constrain each other.
    if len(terms) == 1 and len(terms[0]) < 24:
        terms.append(vendor.key)
    if language:
        terms.append(f"language:{language}")
    return " ".join(terms)


def prospect(
    findings: Sequence[Finding], vendor: Vendor, limit: int = 5,
    language: str = "python", verbose: bool = True, max_attempts: int = 14,
) -> List[Prospect]:
    out: List[Prospect] = []
    ranked = sorted(findings, key=lambda f: -f.occurrences)
    seen_queries: set = set()
    index = 0
    usable = 0
    attempts = 0
    for finding in ranked:
        # Fan-out ranks how much of the spec a change touches, not how many
        # customers it reaches. Stopping at the top N findings left three of
        # five vendors with no leads at all, so keep going until enough queries
        # actually return a workable result.
        if usable >= limit or attempts >= max_attempts:
            break
        query = build_query(finding, vendor, language)
        if not query or query in seen_queries:
            continue
        seen_queries.add(query)
        attempts += 1
        result = Prospect(finding_kind=finding.kind,
                          root_cause=finding.root_cause or finding.subject,
                          query=query)
        if index:
            time.sleep(_SPACING)
        index += 1
        try:
            payload = _gh_code_search(query, per_page=20)
        except GhError as exc:
            result.error = str(exc)
        else:
            result.total_count = payload.get("total_count", 0)
            for item in payload.get("items", []):
                repo = item.get("repository", {})
                result.hits.append(Hit(
                    repo=repo.get("full_name", "?"),
                    stars=int(repo.get("stargazers_count") or -1),
                    file_path=item.get("path", ""),
                    url=item.get("html_url", ""),
                ))
        if result.precision == "usable":
            usable += 1
        if verbose:
            status = result.error or f"{result.total_count:>7,} files  [{result.precision}]"
            print(f"    {query[:64]:66s} {status}")
        out.append(result)
    return out
