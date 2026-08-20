"""Turn a code-search candidate into a verified lead — or reject it.

A code-search hit proves a token appears in a file. It does not prove the file
calls the vendor's API, and it does not prove the token appears in *code*: the
first Stripe `iin` hit this project ever produced was a line of prose inside a
docstring. Both gaps have to close before a finding is worth a pull request.

Two independent conditions must hold:

  1. vendor evidence — something in the file ties it to THIS vendor's API
  2. a real call site — the symbol is read or written in executable code,
     established by parsing (Python) rather than by matching text

Python is parsed with `ast`, so comments, docstrings and prose string literals
can never produce a site. Other languages fall back to a lexical scan with
comments stripped, and are labelled as the weaker evidence they are.
"""
from __future__ import annotations

import ast
import base64
import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .diff import Finding
from .signatures import build_signatures
from .vendors import Vendor

CONFIRMED = "confirmed"          # parsed call site + vendor evidence
LIKELY = "likely"                # lexical call site + vendor evidence
NO_VENDOR = "rejected_no_vendor"  # symbol used, but not this vendor's API
NO_SITE = "rejected_no_site"      # symbol only in comments / prose / strings
UNSUPPORTED = "unsupported"
ERROR = "error"

VERDICT_RANK = {CONFIRMED: 0, LIKELY: 1, NO_VENDOR: 2, NO_SITE: 3,
                UNSUPPORTED: 4, ERROR: 5}

PY_EXT = (".py",)
LEXICAL_EXT = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php", ".java")

# Field-level changes verify by finding the symbol. Endpoint-level changes
# verify by finding the path. Anything else is not yet verifiable.
_FIELD_KINDS = (
    "response_field_removed", "request_field_removed",
    "response_field_type_changed", "request_field_type_changed",
    "param_removed", "param_type_changed", "param_deprecated",
    "response_enum_value_added", "response_enum_value_removed",
    "request_enum_value_removed",
)
_ABSENCE_KINDS = (
    "request_field_added_required", "request_field_now_required",
    "param_added_required", "param_now_required", "request_body_now_required",
)
_ENDPOINT_KINDS = (
    "endpoint_removed", "endpoint_moved", "spec_removed",
    "response_status_removed", "security_requirement_added",
)


@dataclass
class Site:
    line: int
    kind: str
    text: str


@dataclass
class Verdict:
    repo: str
    file_path: str
    url: str
    verdict: str
    reason: str = ""
    vendor_evidence: str = ""
    sites: List[Site] = field(default_factory=list)

    @property
    def is_lead(self) -> bool:
        return self.verdict in (CONFIRMED, LIKELY)

    def as_dict(self) -> Dict[str, object]:
        return {
            "repo": self.repo, "file": self.file_path, "url": self.url,
            "verdict": self.verdict, "reason": self.reason,
            "vendor_evidence": self.vendor_evidence,
            "sites": [{"line": s.line, "kind": s.kind, "text": s.text} for s in self.sites],
        }


# --------------------------------------------------------------------------
# call-site detection
# --------------------------------------------------------------------------

class _PythonSites(ast.NodeVisitor):
    """Find executable uses of `symbol`.

    Only structural positions count: attribute access, subscript with a string
    key, `.get("symbol")`, a keyword argument, or a dict literal key. A bare
    string constant is never a site, which is what makes a docstring mention
    impossible to mistake for a call.
    """

    def __init__(self, symbol: str, lines: Sequence[str]):
        self.symbol = symbol
        self.lines = lines
        self.sites: List[Site] = []

    def _add(self, node: ast.AST, kind: str) -> None:
        line = getattr(node, "lineno", 0)
        text = self.lines[line - 1].strip()[:160] if 0 < line <= len(self.lines) else ""
        self.sites.append(Site(line=line, kind=kind, text=text))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == self.symbol:
            self._add(node, "attribute")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        target = node.slice
        if isinstance(target, ast.Constant) and target.value == self.symbol:
            self._add(node, "subscript")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "get", "pop", "setdefault", "getdefault"
        ):
            if node.args and isinstance(node.args[0], ast.Constant) \
                    and node.args[0].value == self.symbol:
                self._add(node, "dict_get")
        for keyword in node.keywords:
            if keyword.arg == self.symbol:
                self._add(node, "kwarg")
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key in node.keys:
            if isinstance(key, ast.Constant) and key.value == self.symbol:
                self._add(node, "dict_key")
        self.generic_visit(node)


# `//` must not match inside a URL scheme, or stripping comments would delete
# the second half of every line containing an https:// address.
_LINE_COMMENT = re.compile(r"(?:(?<!:)//|#).*?$", re.M)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _blank_block(match: re.Match) -> str:
    """Replace a block comment with its own newlines so line numbers survive."""
    return "\n" * match.group(0).count("\n")


def _strip_comments(text: str) -> str:
    return _LINE_COMMENT.sub("", _BLOCK_COMMENT.sub(_blank_block, text))


def python_sites(source: str, symbol: str) -> Tuple[List[Site], Optional[str]]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return [], f"unparseable python: {type(exc).__name__}"
    visitor = _PythonSites(symbol, source.splitlines())
    visitor.visit(tree)
    return visitor.sites, None


def lexical_sites(source: str, symbol: str) -> List[Site]:
    """Weaker fallback for languages with no parser available here."""
    escaped = re.escape(symbol)
    patterns = [
        (rf"\.{escaped}\b", "property"),
        (rf"\[\s*['\"]{escaped}['\"]\s*\]", "subscript"),
        (rf"['\"]?{escaped}['\"]?\s*:", "object_key"),
        (rf"\b{escaped}\s*=[^=]", "assignment"),
    ]
    stripped = _strip_comments(source).splitlines()
    raw = source.splitlines()
    sites: List[Site] = []
    for index, line in enumerate(stripped):
        for pattern, kind in patterns:
            if re.search(pattern, line):
                sites.append(Site(line=index + 1, kind=kind,
                                  text=raw[index].strip()[:160] if index < len(raw) else ""))
                break
    return sites


def _docstring_ids(tree: ast.AST) -> set:
    """Object ids of every Constant that is a docstring, not a value."""
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", None)
        if body and isinstance(body[0], ast.Expr) \
                and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            out.add(id(body[0].value))
    return out


def python_endpoint_sites(source: str, path_literal: str) -> Tuple[List[Site], Optional[str]]:
    """Find a URL path inside a *value* string, not a docstring or comment.

    A path almost always lives in a string literal, so string constants cannot
    simply be excluded the way they are for field names. Docstrings can be, and
    must be: half the first-pass "leads" were prose describing an endpoint
    rather than code calling it.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return [], f"unparseable python: {type(exc).__name__}"
    skip = _docstring_ids(tree)
    lines = source.splitlines()
    sites: List[Site] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in skip or path_literal not in node.value:
            continue
        line = getattr(node, "lineno", 0)
        sites.append(Site(line=line, kind="endpoint_ref",
                          text=lines[line - 1].strip()[:160]
                          if 0 < line <= len(lines) else ""))
    return sites, None


def endpoint_call_sites(
    source: str, file_path: str, finding: Finding, vendor: Vendor,
) -> Tuple[List[Site], bool]:
    """Sites where this file calls the finding's endpoint, by path OR SDK idiom.

    Returns (sites, parsed). Most callers never write the raw path -- they write
    `stripe.checkout.Session.create(...)` -- so matching only the URL misses the
    majority of a vendor's actual customers.
    """
    path_literal = (finding.path.split("{", 1)[0].rstrip("/")
                    if "{" in finding.path else finding.path)
    sites: List[Site] = []
    parsed = file_path.endswith(PY_EXT)

    if path_literal and len(path_literal) > 6:
        if parsed:
            found, error = python_endpoint_sites(source, path_literal)
            if error:
                parsed = False
            else:
                sites.extend(found)
        if not parsed:
            stripped = _strip_comments(source).splitlines()
            raw = source.splitlines()
            sites.extend(
                Site(line=i + 1, kind="endpoint_ref",
                     text=raw[i].strip()[:160] if i < len(raw) else "")
                for i, line in enumerate(stripped) if path_literal in line
            )

    # SDK idioms are distinctive enough ("stripe.checkout.") that a lexical
    # match on comment-stripped source is sound.
    idioms = [sig for sig in build_signatures(finding, vendor)
              if not sig.startswith("/") and len(sig) > 6
              and sig[0] not in "'\"" and not sig.endswith("=")]
    if idioms:
        stripped = _strip_comments(source).splitlines()
        raw = source.splitlines()
        for index, line in enumerate(stripped):
            if any(idiom in line for idiom in idioms):
                sites.append(Site(line=index + 1, kind="sdk_call",
                                  text=raw[index].strip()[:160]
                                  if index < len(raw) else ""))
    sites.sort(key=lambda s: s.line)
    return sites, parsed


def find_vendor_evidence(source: str, vendor: Vendor) -> str:
    lowered = source.lower()
    for marker in vendor.evidence:
        if marker.lower() in lowered:
            return marker
    return ""


# --------------------------------------------------------------------------
# target extraction
# --------------------------------------------------------------------------

def target_symbol(finding: Finding) -> Tuple[str, str]:
    """Return (symbol, mode) describing what to look for in a candidate file."""
    subject = finding.root_cause or finding.subject
    leaf = subject.split(".")[-1].replace("[]", "").strip("<>")
    if finding.kind in _ENDPOINT_KINDS:
        literal = finding.path.split("{", 1)[0].rstrip("/") if "{" in finding.path \
            else finding.path
        return literal, "endpoint"
    if finding.kind in _ABSENCE_KINDS:
        return leaf, "absence"
    if finding.kind in _FIELD_KINDS:
        return leaf, "presence"
    return leaf, "presence"


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

class FetchError(RuntimeError):
    pass


def fetch_file(repo: str, path: str, ref: str = "") -> str:
    args = ["gh", "api", f"repos/{repo}/contents/{path}"]
    if ref:
        args += ["-f", f"ref={ref}"]
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise FetchError(proc.stderr.decode("utf-8", "replace").strip()[:160])
    payload = json.loads(proc.stdout.decode("utf-8", "replace"))
    if payload.get("encoding") != "base64":
        raise FetchError(f"unexpected encoding {payload.get('encoding')!r}")
    if int(payload.get("size") or 0) > 800_000:
        raise FetchError("file too large")
    return base64.b64decode(payload["content"]).decode("utf-8", "replace")


# --------------------------------------------------------------------------
# the pass
# --------------------------------------------------------------------------

def verify_source(
    source: str, file_path: str, finding: Finding, vendor: Vendor,
) -> Tuple[str, str, str, List[Site]]:
    """Return (verdict, reason, vendor_evidence, sites) for one file's contents."""
    evidence = find_vendor_evidence(source, vendor)
    symbol, mode = target_symbol(finding)

    if mode == "endpoint":
        # The path literal is itself vendor evidence: only that vendor serves it.
        if not symbol:
            return NO_SITE, "no path literal to search for", evidence, []
        if file_path.endswith(PY_EXT):
            sites, error = python_endpoint_sites(source, symbol)
            if error:
                return ERROR, error, evidence or symbol, []
            if sites:
                return (CONFIRMED, f"calls {symbol} at {len(sites)} site(s)",
                        evidence or symbol, sites)
            return (NO_SITE,
                    f"`{symbol}` appears only in comments or docstrings",
                    evidence, [])
        stripped_lines = _strip_comments(source).splitlines()
        raw = source.splitlines()
        sites = [Site(line=i + 1, kind="endpoint_ref",
                      text=raw[i].strip()[:160] if i < len(raw) else "")
                 for i, line in enumerate(stripped_lines) if symbol in line]
        if sites:
            return (LIKELY, f"references {symbol}, unparsed language",
                    evidence or symbol, sites)
        return NO_SITE, f"`{symbol}` appears only in comments", evidence, []

    if not evidence:
        return (NO_VENDOR,
                f"no {vendor.name} import, host or key in the file", "", [])

    if mode == "absence":
        # A newly-required field breaks the callers that DO NOT send it. So the
        # caller must first be shown to call the endpoint, and the field must
        # then be shown to be missing. Finding the field means they already
        # migrated; not finding the endpoint means they were never affected.
        if not file_path.endswith(PY_EXT + LEXICAL_EXT):
            return UNSUPPORTED, f"no analyser for {file_path.rsplit('.', 1)[-1]}", evidence, []
        call_sites, parsed = endpoint_call_sites(source, file_path, finding, vendor)
        if parsed:
            supplies, _ = python_sites(source, symbol)
        else:
            supplies = lexical_sites(source, symbol)

        if not call_sites:
            return (NO_SITE, f"does not call {finding.path}", evidence, [])
        if supplies:
            return (NO_SITE, f"already supplies `{symbol}` — migrated",
                    evidence, supplies)
        return ((CONFIRMED if parsed else LIKELY),
                f"calls {finding.path} without required `{symbol}`",
                evidence, call_sites)

    if file_path.endswith(PY_EXT):
        sites, error = python_sites(source, symbol)
        if error:
            return ERROR, error, evidence, []
        if not sites:
            in_text = symbol in source
            return (NO_SITE,
                    f"`{symbol}` appears only in comments or prose" if in_text
                    else f"`{symbol}` not present at all", evidence, [])
        return CONFIRMED, f"{len(sites)} parsed call site(s)", evidence, sites

    if file_path.endswith(LEXICAL_EXT):
        sites = lexical_sites(source, symbol)
        if not sites:
            return NO_SITE, f"`{symbol}` not used in code", evidence, []
        return LIKELY, f"{len(sites)} lexical match(es), unparsed language", evidence, sites

    return UNSUPPORTED, f"no analyser for {file_path.rsplit('.', 1)[-1]}", evidence, []


def verify_candidate(
    repo: str, file_path: str, url: str, finding: Finding, vendor: Vendor,
) -> Verdict:
    try:
        source = fetch_file(repo, file_path)
    except (FetchError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return Verdict(repo=repo, file_path=file_path, url=url,
                       verdict=ERROR, reason=str(exc)[:160])
    verdict, reason, evidence, sites = verify_source(source, file_path, finding, vendor)
    return Verdict(repo=repo, file_path=file_path, url=url, verdict=verdict,
                   reason=reason, vendor_evidence=evidence, sites=sites[:5])
