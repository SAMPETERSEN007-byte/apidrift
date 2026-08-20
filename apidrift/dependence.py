"""Prove that code DEPENDS on a change, rather than merely sitting near it.

Two adversarial audits refuted nine of ten leads each, and the second one named
the reason precisely: the verifier established co-location -- this file mentions
this vendor and this path -- and never established dependence. Every gate added
between the two audits changed *why* leads died without changing *how often*,
because none of them asked the causal question.

The causal question has three parts, and a lead has to answer all three:

  1. does this code reach the operation that changed, by METHOD and by PATH?
  2. does it read or write the element that changed, on a value that came from
     the vendor?
  3. does the DIRECTION of the change break that particular usage?

Answering (2) means following a value backwards. `card.iin` is only a read of
Stripe's card object if `card` traces to a Stripe call; in `quay` it traced to
a Swagger literal describing quay's own API, and in `PayMCP` the field was read
off a response while the change applied to a request body. Neither is visible
without a def-use chain, which is why heuristics kept missing them.

Python is analysed with `ast`. Other languages cannot be proven here, and a
lead that cannot be proven is not emitted -- an unprovable lead is not a weaker
lead, it is an unmeasured claim.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field as dataclass_field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .diff import ABSENCE_KINDS, ENDPOINT_KINDS, Finding
from .vendors import Vendor

# How a proof was established, strongest first.
OPERATION_CALL = "operation_call"          # reaches the changed operation
FIELD_READ = "field_read"                  # reads the changed field off vendor data
FIELD_SENT = "field_sent"                  # sends the changed field to the vendor
FIELD_MISSING = "field_missing"            # calls the operation without a now-required field

HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

# Callables that perform a request. The name alone is not proof; it is one link
# in a chain that must also carry a vendor path or host.
_REQUEST_CALLEES = frozenset({
    "request", "_request", "arequest", "send", "fetch", "call", "execute",
    "get", "post", "put", "patch", "delete", "route", "Route", "api_call",
})

# Keyword arguments that carry a request body.
_BODY_ARGS = frozenset({"data", "json", "body", "payload", "params_json",
                        "content", "files"})

_MAX_TRACE = 6


@dataclass
class Proof:
    """Why this code is affected. Every field is quotable in an outreach note."""
    kind: str
    line: int
    text: str
    chain: List[str] = dataclass_field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {"kind": self.kind, "line": self.line, "text": self.text,
                "chain": self.chain}


# ---------------------------------------------------------------------------
# literals
# ---------------------------------------------------------------------------

def literal_of(node: ast.AST) -> Optional[str]:
    """The string a node evaluates to, with interpolations as `{}`.

    An f-string is how most callers actually write a templated path, so
    `f"{BASE}/v1/Stores/{sid}/Events"` has to reduce to something comparable
    with `/v1/Stores/{storeId}/Events`.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: List[str] = []
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
            else:
                parts.append("{}")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = literal_of(node.left), literal_of(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _segments(path: str) -> List[str]:
    """Path segments with every parameter reduced to a wildcard."""
    out: List[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.startswith("{") or segment.startswith("%") or segment == "{}":
            out.append("*")
        elif "{" in segment or "}" in segment:
            out.append("*")
        else:
            out.append(segment.lower())
    return out


def paths_match(template: str, candidate: str) -> bool:
    """Does a path written in code correspond to a spec path template?

    Compared segment-wise with parameters as wildcards, and anchored at the
    END: a caller writing `f"{BASE}/v1/Stores/{s}/Events"` supplies the host in
    a variable, so the leading segments are often absent from the literal.
    """
    want = _segments(template)
    got = _segments(candidate)
    if not want or not got:
        return False
    if candidate.rstrip().endswith("/"):
        # A literal ending in a slash is a prefix the caller concatenates onto,
        # so the path it really requests is longer than what is written here.
        # `"https://verify.twilio.com/v2/Services/"` was matching the shorter
        # `POST /v2/Services` while the code actually posts to
        # `/v2/Services/{sid}/Verifications`.
        return False
    if len(got) < len(want):
        # Trimming the template to fit a shorter literal was far too generous:
        # a FastAPI router prefix of `/communications` "matched"
        # `/v2/Conversations/{sid}/Communications` because only the final
        # segment survived the trim. A caller writing part of a path is a lead
        # we lose; a caller of something else entirely is a lead we invent.
        return False
    tail = got[len(got) - len(want):]
    if len(tail) != len(want):
        return False
    # A LITERAL segment in the template must be matched by the same literal in
    # the code. Letting a caller's interpolated variable satisfy it made
    # `/guilds/{id}/members/{uid}` match a `/guilds/{id}/bulk-ban` template,
    # since every position was a wildcard on one side or the other.
    for want_segment, got_segment in zip(want, tail):
        if want_segment == "*":
            continue
        if want_segment != got_segment:
            return False
    return any(segment != "*" for segment in want)


# ---------------------------------------------------------------------------
# def-use tracing
# ---------------------------------------------------------------------------

class _Assignments(ast.NodeVisitor):
    """Every `name = <expr>` in the module, last write wins per name."""

    def __init__(self) -> None:
        self.by_name: Dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.by_name[target.id] = node.value
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.by_name[node.target.id] = node.value
        self.generic_visit(node)

    def visit_withitem(self, node: ast.withitem) -> None:  # pragma: no cover
        self.generic_visit(node)


def _root_name(node: ast.AST) -> str:
    """The leftmost identifier of an attribute chain: `a.b.c()` -> `a`."""
    while True:
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        elif isinstance(node, (ast.Subscript, ast.Await)):
            node = node.value
        else:
            break
    return node.id if isinstance(node, ast.Name) else ""


def _attr_chain(node: ast.AST) -> str:
    """`stripe.checkout.Session.create` -> that string, best effort."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _mentions_vendor_host(node: ast.AST, vendor: Vendor) -> Optional[str]:
    """A literal inside `node` naming the vendor's API host."""
    hosts = tuple(m for m in vendor.evidence if "." in m and "/" not in m)
    for child in ast.walk(node):
        text = literal_of(child)
        if not text:
            continue
        lowered = text.lower()
        for host in hosts:
            if host.lower() in lowered:
                return host
        if f"{vendor.key}.com" in lowered or f"api.{vendor.key}" in lowered:
            return vendor.key
    return None


def call_reaches_vendor(node: ast.AST, vendor: Vendor,
                        assignments: Dict[str, ast.AST],
                        depth: int = 0) -> Optional[str]:
    """Does this expression obtain a value from the vendor's API?

    Returns a one-line explanation of the link, or None. This is the step that
    separates `card.iin` on a Stripe response from `record.iin` on an IBAN
    parser -- the heuristic version could not tell them apart.
    """
    if depth > _MAX_TRACE or node is None:
        return None

    if isinstance(node, ast.Await):
        return call_reaches_vendor(node.value, vendor, assignments, depth + 1)

    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func)
        root = _root_name(node.func)
        if root and root.lower() == vendor.key:
            return f"`{chain}(...)` is a {vendor.name} SDK call"
        host = _mentions_vendor_host(node, vendor)
        callee = chain.rsplit(".", 1)[-1] if chain else ""
        if host and (callee in _REQUEST_CALLEES or callee.lower() in HTTP_VERBS):
            return f"`{chain}(...)` requests `{host}`"
        if host:
            return f"`{chain}(...)` carries `{host}`"
        # A client object obtained from the vendor earlier in the file.
        if root and root in assignments:
            inner = call_reaches_vendor(assignments[root], vendor, assignments,
                                        depth + 1)
            if inner:
                return f"`{chain}(...)` on a client where {inner}"
        return None

    if isinstance(node, (ast.Attribute, ast.Subscript)):
        return call_reaches_vendor(node.value, vendor, assignments, depth + 1)

    if isinstance(node, ast.Name):
        origin = assignments.get(node.id)
        if origin is None:
            return None
        inner = call_reaches_vendor(origin, vendor, assignments, depth + 1)
        return f"`{node.id}` comes from {inner}" if inner else None

    return None


# ---------------------------------------------------------------------------
# operation calls
# ---------------------------------------------------------------------------

def _method_of(node: ast.Call) -> Set[str]:
    """HTTP methods named by this call, from literals or the callee itself."""
    found: Set[str] = set()
    callee = _attr_chain(node.func).rsplit(".", 1)[-1].lower()
    if callee in HTTP_VERBS:
        found.add(callee)
    else:
        # Callers wrap the verb into the helper's name: `plaid_post`, `_post`,
        # `post_json`. Reading only an exact match missed most hand-written
        # clients, which then looked like calls of unknown method.
        for verb in HTTP_VERBS:
            if callee in (f"_{verb}", f"{verb}_json", f"{verb}_request") \
                    or callee.endswith(f"_{verb}") or callee.startswith(f"{verb}_"):
                found.add(verb)
                break
    for child in list(node.args) + [kw.value for kw in node.keywords]:
        text = literal_of(child)
        if text and text.strip().lower() in HTTP_VERBS:
            found.add(text.strip().lower())
    for keyword in node.keywords:
        if keyword.arg in ("method", "verb", "http_method"):
            text = literal_of(keyword.value)
            if text:
                found.add(text.strip().lower())
    if not found and any(kw.arg in _BODY_ARGS for kw in node.keywords):
        # A body implies a write. `self.api(path="/link/token/get", data=d)`
        # names no verb but is plainly not a GET, and rejecting it lost real
        # callers of POST-only APIs.
        found.update({"post", "put", "patch"})
    return found


def find_sdk_calls(tree: ast.AST, idioms: Sequence[str],
                   lines: Sequence[str]) -> List[Proof]:
    """Calls written through the vendor's SDK, which never name a path.

    `stripe.checkout.Session.create(...)` reaches `POST /v1/checkout/sessions`
    without the string ever appearing, so a path-only proof misses the majority
    of a vendor's actual customers.
    """
    wanted = [idiom.rstrip(".(") for idiom in idioms if len(idiom) > 6]
    if not wanted:
        return []
    proofs: List[Proof] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _attr_chain(node.func)
        if not chain:
            continue
        hit = next((idiom for idiom in wanted if chain.startswith(idiom)), None)
        if not hit:
            continue
        line = getattr(node, "lineno", 0)
        text = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        proofs.append(Proof(
            kind=OPERATION_CALL, line=line, text=text,
            chain=[f"`{chain}(...)` is the SDK form of this operation"],
        ))
    return proofs


# Registering a route means this code SERVES that path. It is the opposite of
# calling the vendor, and `@app.get("/communications")` was being read as a
# Twilio call.
_ROUTE_REGISTRARS = frozenset({
    "route", "add_route", "add_api_route", "include_router", "APIRouter",
    "add_url_rule", "websocket", "middleware", "mount",
})


def _is_route_registration(node: ast.Call) -> bool:
    chain = _attr_chain(node.func)
    leaf = chain.rsplit(".", 1)[-1] if chain else ""
    if leaf in _ROUTE_REGISTRARS:
        return True
    root = _root_name(node.func)
    if root in ("app", "router", "api", "blueprint", "bp") and leaf in HTTP_VERBS:
        return True
    return any(keyword.arg == "prefix" for keyword in node.keywords)


def find_operation_calls(tree: ast.AST, method: str, path: str,
                         lines: Sequence[str]) -> List[Proof]:
    """Calls that name BOTH the method and a path matching the template.

    Requiring both is what separates `POST /guilds/{id}/bulk-ban` from the
    kick, ban and member-search routes that share the `/guilds` prefix. Ten of
    twenty leads in one run were that confusion.
    """
    wanted = method.lower()
    proofs: List[Proof] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _is_route_registration(node):
            continue
        candidates = [literal_of(child) for child in ast.walk(node)]
        matched_path = next(
            (text for text in candidates if text and paths_match(path, text)), None)
        if not matched_path:
            continue
        methods = _method_of(node)
        if methods and wanted not in methods:
            continue
        if not methods and wanted != "get":
            # A change scoped to DELETE, POST, PUT or PATCH cannot be pinned on
            # a call that never says which verb it uses. A pytest parametrize
            # list of path strings was confirming a DELETE-only change.
            continue
        line = getattr(node, "lineno", 0)
        text = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        proofs.append(Proof(
            kind=OPERATION_CALL, line=line, text=text,
            chain=[f"call names path `{matched_path}`",
                   (f"and method `{wanted.upper()}`" if methods
                    else f"method not stated at the call; path matches "
                         f"`{path}` uniquely")],
        ))
    return proofs


# ---------------------------------------------------------------------------
# field use
# ---------------------------------------------------------------------------

def find_field_uses(tree: ast.AST, field_name: str,
                    lines: Sequence[str]) -> List[Proof]:
    """Every read of `field_name`, without asking where the value came from."""
    proofs: List[Proof] = []
    for node in ast.walk(tree):
        matched = False
        if isinstance(node, ast.Attribute) and node.attr == field_name:
            matched = True
        elif isinstance(node, ast.Subscript) and literal_of(node.slice) == field_name:
            matched = True
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("get", "setdefault"):
            if node.args and literal_of(node.args[0]) == field_name:
                matched = True
        if not matched:
            continue
        line = getattr(node, "lineno", 0)
        proofs.append(Proof(
            kind=FIELD_READ, line=line,
            text=lines[line - 1].strip()[:160] if 0 < line <= len(lines) else "",
            chain=[f"reads `{field_name}`"],
        ))
    return proofs


def find_field_reads(tree: ast.AST, field_name: str, vendor: Vendor,
                     assignments: Dict[str, ast.AST],
                     lines: Sequence[str]) -> List[Proof]:
    """Reads of `field_name` off a value traced back to the vendor."""
    proofs: List[Proof] = []
    for node in ast.walk(tree):
        source_expr: Optional[ast.AST] = None
        if isinstance(node, ast.Attribute) and node.attr == field_name:
            source_expr = node.value
        elif isinstance(node, ast.Subscript):
            key = literal_of(node.slice)
            if key == field_name:
                source_expr = node.value
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr in ("get", "setdefault"):
            if node.args and literal_of(node.args[0]) == field_name:
                source_expr = node.func.value
        if source_expr is None:
            continue
        link = call_reaches_vendor(source_expr, vendor, assignments)
        if not link:
            continue
        line = getattr(node, "lineno", 0)
        text = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        proofs.append(Proof(
            kind=FIELD_READ, line=line, text=text,
            chain=[f"reads `{field_name}`", link],
        ))
    return proofs


def find_field_sends(tree: ast.AST, field_name: str, vendor: Vendor,
                     method: str, path: str,
                     lines: Sequence[str]) -> List[Proof]:
    """Writes of `field_name` into a body or argument of a vendor request."""
    proofs: List[Proof] = []
    operation_lines = {
        p.line for p in find_operation_calls(tree, method, path, lines)
    } if path else set()

    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        written = False
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == field_name:
                    written = True
        elif isinstance(node, ast.Dict):
            for key in node.keys:
                if literal_of(key) == field_name:
                    written = True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) \
                        and literal_of(target.slice) == field_name:
                    written = True
        if not written:
            continue
        text = lines[line - 1].strip()[:160] if 0 < line <= len(lines) else ""
        near = min((abs(line - other) for other in operation_lines), default=None)
        if operation_lines and (near is None or near > 60):
            continue      # written somewhere unrelated to the changed operation
        chain = [f"sets `{field_name}`"]
        if operation_lines:
            chain.append(f"within {near} lines of a call to `{method.upper()} {path}`")
        proofs.append(Proof(kind=FIELD_SENT, line=line, text=text, chain=chain))
    return proofs


def find_missing_required(tree: ast.AST, field_name: str, method: str,
                          path: str, lines: Sequence[str]) -> List[Proof]:
    """Calls to the operation that do NOT supply a newly required field.

    The break here is an absence, so the proof is a call that reaches the
    operation plus the field being absent from the whole file.
    """
    calls = find_operation_calls(tree, method, path, lines)
    if not calls:
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if any(kw.arg == field_name for kw in node.keywords):
                return []
        if isinstance(node, ast.Dict):
            if any(literal_of(key) == field_name for key in node.keys):
                return []
    return [Proof(kind=FIELD_MISSING, line=call.line, text=call.text,
                  chain=call.chain + [f"and never supplies `{field_name}`"])
            for call in calls]


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

def _leaf_of(finding: Finding) -> str:
    """The field or schema the change names, or empty if it names none.

    An endpoint-level change carries a path as its subject, and a path is not
    a name a caller writes as an identifier. Treating `/guilds/{id}/bulk-ban`
    as a field name sent every endpoint change down the field-read route,
    where it could never be proven.
    """
    subject = finding.root_cause or finding.subject
    leaf = subject.split(".")[-1].replace("[]", "").strip("<>")
    if not leaf or leaf.startswith("<") or leaf.startswith("/"):
        return ""
    if not leaf[0].isalpha():
        return ""
    if not leaf.replace("_", "").replace("-", "").isalnum():
        return ""
    return leaf


def prove(source: str, finding: Finding, vendor: Vendor) -> Tuple[List[Proof], str]:
    """Return (proofs, why-not). Empty proofs means no dependence was shown.

    Three routes count, in descending strength:

      1. the value is traced to a vendor call and the changed field is read
         off it, which is dependence proven end to end;
      2. the file calls an operation that CARRIES the changed schema and reads
         the changed field, which is dependence proven in two halves -- needed
         because most reads happen on a function parameter, whose origin is in
         the caller and not visible here;
      3. for an operation-level change, a call reaching that operation by
         method and path, or through the vendor's SDK.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        return [], f"unparseable python: {type(exc).__name__}"

    lines = source.splitlines()
    collector = _Assignments()
    collector.visit(tree)
    assignments = collector.by_name

    method = (finding.method or "get").lower()
    path = finding.path if not finding.path.startswith("#") else ""
    leaf = _leaf_of(finding)
    idioms = [s for s in (finding.signatures or []) if not s.startswith("/")]

    def operation_reached() -> List[Proof]:
        """Any call reaching an operation that carries the changed schema."""
        found: List[Proof] = []
        targets = list(finding.affected_ops or [])
        if path and f"{method.upper()} {path}" not in targets:
            targets.append(f"{method.upper()} {path}")
        for op_key in targets[:40]:
            op_method, _, op_path = op_key.partition(" ")
            if not op_path or op_path.startswith("#"):
                continue
            hits = find_operation_calls(tree, op_method.lower(), op_path, lines)
            if hits:
                # A change can touch many operations; say which one this file
                # actually calls. Reporting the representative made a Twilio
                # security change read as `DELETE /v2/Services/{Sid}` against
                # code that only ever POSTs Verifications.
                for hit in hits:
                    hit.chain.append(f"which is `{op_method.upper()} {op_path}`")
                found.extend(hits)
                break
        if not found:
            found = find_sdk_calls(tree, idioms, lines)
        return found

    if finding.kind in ABSENCE_KINDS:
        if not leaf:
            return [], "the change names no field to check for"
        calls = operation_reached()
        if not calls:
            return [], f"no call reaching `{method.upper()} {path}`"
        supplied = find_field_sends(tree, leaf, vendor, method, "", lines)
        if supplied:
            return [], f"already supplies `{leaf}` — migrated"
        return ([Proof(kind=FIELD_MISSING, line=c.line, text=c.text,
                       chain=c.chain + [f"and never supplies required `{leaf}`"])
                 for c in calls], "")

    if finding.kind in ENDPOINT_KINDS:
        # Operation-level and whole-schema changes are proven by reaching the
        # operation. A caller does not name `LinkSessionProtectResult` anywhere
        # -- schema names are OpenAPI-internal -- but if that schema is deleted
        # the payload they receive changes. Requiring them to write the name
        # rejected every genuine caller of every such change.
        calls = operation_reached()
        return calls, ("" if calls else
                       f"no call reaching `{method.upper()} {path or '?'}`")

    if not leaf:
        return [], "the change names nothing a caller could reference"

    # Route 1: the read is traced to a vendor call.
    traced = find_field_reads(tree, leaf, vendor, assignments, lines)
    if traced:
        return traced, ""

    # Route 2: the field is read somewhere, AND this file calls an operation
    # that carries the schema it was removed from.
    uses = find_field_uses(tree, leaf, lines)
    if uses:
        calls = operation_reached()
        if calls:
            return ([Proof(kind=FIELD_READ, line=u.line, text=u.text,
                           chain=u.chain + [
                               f"and this file calls `{calls[0].text[:60]}`, an "
                               f"operation carrying the changed schema"])
                     for u in uses], "")
        if "request" in finding.kind:
            sends = find_field_sends(tree, leaf, vendor, method, path, lines)
            if sends:
                return sends, ""
        return [], (f"reads `{leaf}` but never calls an operation that "
                    f"carries it")

    # No fallback to "calls an operation that carries it". When the change
    # names a schema or field, code that never names it cannot be shown to
    # depend on it, however many of the vendor's endpoints it calls.
    return [], f"`{leaf}` is never read or sent in this file"
