"""Turn a finding into a list of public repositories that will actually break.

The diff says *what* changed. This says *who* it lands on — which is the only
part a vendor is willing to pay for.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .diff import ABSENCE_KINDS, ENDPOINT_KINDS, Finding
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


_ENDPOINT_KINDS = ENDPOINT_KINDS

# Tokens too common to discriminate anything on their own.
_WEAK_TOKENS = frozenset({
    "id", "type", "name", "url", "data", "code", "key", "user", "text",
    "value", "status", "object", "items", "input", "output", "error",
})


def _leaf(finding: Finding) -> str:
    subject = finding.root_cause or finding.subject
    leaf = subject.split(".")[-1].replace("[]", "").strip("<>")
    return leaf if leaf and not leaf.startswith("<") else ""


def canonical_path(finding: Finding) -> str:
    """The most representative endpoint for a finding, not just the first one.

    A change to a shared schema is reachable from many operations, and the
    representative is whichever sorted first. That is often a niche endpoint:
    `payment_intent.amount_capturable` is a widely used field, but paired with
    `/v1/terminal/readers` the search returns nothing. The shortest affected
    path is almost always the primary resource endpoint.
    """
    candidates = []
    for op_key in finding.affected_ops or []:
        _, _, path = op_key.partition(" ")
        if path and not path.startswith("#"):
            candidates.append(path)
    if not candidates:
        # A schema finding with no reachable operation carries a pseudo-path
        # (`#/components/schemas/X`), which is not a URL and matches nothing.
        return "" if finding.path.startswith("#") else finding.path
    # Fewest segments wins, then fewest path parameters, then shortest.
    return min(candidates,
               key=lambda p: (p.count("/"), p.count("{"), len(p)))


def static_run(path: str) -> str:
    """The most distinctive literal substring of a templated path.

    Truncating at the first `{` throws away the specific half. For
    `/guilds/{guild_id}/auto-moderation/rules` it leaves `/guilds`, which
    matches every guild call in every Discord bot and attributes an
    auto-moderation change to a delete-member route. The longest contiguous run
    of static segments is what a caller's code actually contains.
    """
    if not path or path == "/" or path.startswith("#"):
        return ""
    runs, current = [], []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.startswith("{"):
            if current:
                runs.append(current)
                current = []
        else:
            current.append(segment)
    if current:
        runs.append(current)
    if not runs:
        return ""
    # Longest by characters; on a tie prefer the later, more specific run.
    best = max(runs, key=lambda run: (len("/".join(run)), runs.index(run)))
    return "/" + "/".join(best)


def build_query(finding: Finding, vendor: Vendor, language: str = "") -> str:
    """Build the most discriminating code-search query for one finding.

    Neither half works alone. The endpoint path alone matches every caller of
    that endpoint whether or not they touch the changed field; the field name
    alone matches every unrelated use of a common word. Requiring *both* in the
    same file is what makes the result a lead list rather than a word count:
    `"iin" "/v1/customers"` returns 155 files where `"iin" stripe` returns 5,632.
    """
    terms: List[str] = []
    best_path = canonical_path(finding)
    path_literal = static_run(best_path)

    leaf = _leaf(finding)
    # A newly-required field is verified by its ABSENCE, so searching for it
    # would return precisely the callers who are already fine.
    field_usable = (finding.kind not in _ENDPOINT_KINDS
                    and finding.kind not in ABSENCE_KINDS
                    and len(leaf) >= 3 and leaf.lower() not in _WEAK_TOKENS)

    if field_usable:
        terms.append(f'"{leaf}"')
    if len(path_literal) > 6:
        terms.append(f'"{path_literal}"')
    elif not terms:
        # No usable endpoint: fall back to the schema name, which generated
        # clients carry verbatim as a class or type name.
        schema = (finding.root_cause or finding.subject).split(".")[0]
        if len(schema) > 8 and schema.lower() not in _WEAK_TOKENS:
            terms.append(f'"{schema}"')

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


_COMPOUND = re.compile(r"_|(?<=[a-z])(?=[A-Z])")


def searchability(finding: Finding) -> int:
    """How likely this finding is to yield a usable code search.

    Fan-out measures how much of the spec a change touches. It says nothing
    about whether the change can be FOUND in someone's code. `frequency` and
    `day` have high fan-out and are unsearchable; `SpamLinkRuleResponse` and
    `hd_streaming_buyer_id` have low fan-out and are unmistakable. Ranking by
    fan-out alone left 29 real Discord findings unsearched.
    """
    subject = finding.root_cause or finding.subject
    leaf = subject.split(".")[-1].replace("[]", "").strip("<>")
    if not leaf:
        return -10
    score = 0
    if _COMPOUND.search(leaf):
        score += 3               # multi-word identifier: rarely a coincidence
    if len(leaf) >= 14:
        score += 3
    elif len(leaf) >= 9:
        score += 2
    elif len(leaf) >= 6:
        score += 1
    if leaf.lower() in _WEAK_TOKENS:
        score -= 6               # a common English word finds everything
    if len(leaf) <= 4:
        score -= 2
    if finding.kind in _ENDPOINT_KINDS:
        # Endpoint changes search on the path, which is specific by nature.
        score += 2
    return score


def rank_findings(findings: Sequence[Finding]) -> List[Finding]:
    """Order findings for prospecting: most findable first, then widest reach."""
    return sorted(findings, key=lambda f: (-searchability(f), -f.occurrences))


def prospect(
    findings: Sequence[Finding], vendor: Vendor, limit: int = 5,
    language: str = "python", verbose: bool = True, max_attempts: int = 14,
) -> List[Prospect]:
    out: List[Prospect] = []
    ranked = rank_findings(findings)
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
