"""Prove dependence in JavaScript and TypeScript.

Same contract and same standard as the Python prover: co-location is not
dependence, and an unproven claim is UNMEASURED rather than clean. Two audits
put the cost of confusing those at nine refutations in ten.

Three routes, mirroring `dependence.prove()`:

  1. a CALL that reaches the changed operation -- either an SDK member chain on
     a value the file bound to this vendor's client, or a `fetch()` whose URL
     literal matches the operation's path template;
  2. a READ of the changed field off a variable that a vendor call was assigned
     to, which is dependence end to end;
  3. a SEND of the changed field as a key of an object argument to a vendor
     call, which is the request-side direction.

Direction is not decoration. An object key is how you SEND a field and a
property access is how you READ one, and treating either as the other is
already recorded here as a gated false-positive class -- it is why
`phasehq/console` was reported broken by a request-side change it only ever
read the response of.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence, Set, Tuple

from .dependence import (FIELD_MISSING, FIELD_READ, FIELD_SENT, Proof,
                         _is_distinctive, _leaf_of, paths_match,
                         read_sits_where_subject_says, subject_ancestry,
                         wire_subject)
from .diff import ABSENCE_KINDS, ENDPOINT_KINDS, Finding
from .js import CallSite, Module, UnreadableSource, analyse
from .vendors import Vendor

JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

# Package names an SDK is imported from, per vendor key. A local variable is a
# vendor client only if it can be traced to one of these -- `client.foo.list()`
# on a variable this file built from something else is not a call to anybody.
_SDK_PACKAGES: Dict[str, Tuple[str, ...]] = {
    "stripe": ("stripe",),
    "openai": ("openai",),
    "anthropic": ("@anthropic-ai/sdk",),
    "twilio": ("twilio",),
    "plaid": ("plaid",),
    "discord": ("discord.js", "@discordjs/rest", "discord-api-types"),
    "resend": ("resend",),
    "square": ("square", "squareup"),
    "sendgrid": ("@sendgrid/mail", "@sendgrid/client"),
    "cloudflare": ("cloudflare",),
    "github": ("@octokit/rest", "@octokit/core", "octokit"),
    "vercel": ("@vercel/sdk",),
    "klaviyo": ("klaviyo-api",),
    "intercom": ("intercom-client",),
    "sentry": ("@sentry/node", "@sentry/browser", "@sentry/nextjs"),
    "modern_treasury": ("modern-treasury",),
    "lithic": ("lithic",),
    "box": ("box-node-sdk", "box-typescript-sdk-gen"),
    "asana": ("asana",),
    "telnyx": ("telnyx",),
    "hubspot": ("@hubspot/api-client",),
    "deepgram": ("@deepgram/sdk",),
    "recurly": ("recurly",),
    "xero": ("xero-node",),
    "docusign": ("docusign-esign",),
    "pagerduty": ("@pagerduty/pdjs",),
    "adyen": ("@adyen/api-library",),
    "paypal": ("@paypal/checkout-server-sdk", "@paypal/paypal-server-sdk"),
    "datadog": ("@datadog/datadog-api-client",),
    "auth0": ("auth0",),
    "cohere": ("cohere-ai",),
    "mistral": ("@mistralai/mistralai",),
    "column": (),
}

_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head",
                         "options"})


def is_js(file_path: str) -> bool:
    return file_path.lower().endswith(JS_SUFFIXES)


def _vendor_bindings(module: Module, vendor: Vendor) -> Set[str]:
    """Local names that hold this vendor's client.

    A name qualifies when it was imported from one of the vendor's packages, or
    constructed from a class that was. Nothing weaker: matching on the variable
    being called `stripe` would convict any file that happens to use the word.
    """
    packages = _SDK_PACKAGES.get(vendor.key, ())
    if not packages:
        return set()
    imported = {local for local, source in module.imports.items()
                if source in packages or any(
                    source.startswith(p + "/") for p in packages)}
    bound = set(imported)
    for variable, class_name in module.constructed.items():
        if class_name in imported:
            bound.add(variable)
    return bound


def _fetch_targets(module: Module) -> List[Tuple[str, str, CallSite]]:
    """(method, url) for every `fetch(...)` with a literal URL.

    The method comes from the options object's `method` key when it is a
    literal; absent one, `fetch` defaults to GET, which is what the runtime
    does and therefore what a caller depends on.
    """
    out: List[Tuple[str, str, CallSite]] = []
    for call in module.calls:
        if call.chain[-1] != "fetch":
            continue
        urls = [s for s in call.arg_strings if "/" in s]
        if not urls:
            continue
        method = "get"
        if "method" in call.arg_keys:
            for text in call.arg_strings:
                if text.lower() in _HTTP_VERBS:
                    method = text.lower()
                    break
        out.append((method, urls[0], call))
    return out


def _lines(source: str) -> List[str]:
    return source.splitlines()


def _text_at(lines: Sequence[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:160]
    return ""


def _chain_matches_path(chain: Sequence[str], path: str) -> bool:
    """Does an SDK member chain correspond to `path`'s resource segments?

    Extracted from `_operation_calls` unchanged so that a single call site --
    the one a traced read was assigned from -- can be tested against an
    operation without re-walking the module. `_chain_reaches_change` needs
    exactly that.
    """
    wanted = [segment for segment in path.split("/")
              if segment and not segment.startswith("{")]
    if not wanted or len(chain) < 2:
        return False
    middle = {part.lower().rstrip("s") for part in chain[1:-1]}
    if not middle:
        return False
    return all(any(segment.lower().rstrip("s") == part
                   or segment.lower().rstrip("s").endswith(part)
                   for part in middle)
               for segment in wanted[-len(middle):])


def _change_operation_paths(finding: Finding) -> List[str]:
    """Every path this change is KNOWN to touch.

    `affected_ops` only. `finding.path` is the REPRESENTATIVE operation --
    a display choice, arbitrary among the many an operation-spanning change
    covers, and `card.iin` carries `DELETE /v1/accounts/{account}` for 551 of
    them. Including it here made reach demand that a caller use the one
    operation the report happened to name, which is the thing
    `test_a_traced_read_stands_ALONE_when_the_path_does_not_match` exists to
    forbid. A check must not smuggle an arbitrary pick in as a fact.
    """
    out: List[str] = []
    for key in (finding.affected_ops or []):
        _, _, op_path = key.partition(" ")
        if op_path and not op_path.startswith("#"):
            out.append(op_path)
    return out


def _chain_reaches_change(chain: Sequence[str], finding: Finding) -> bool:
    """Does the call a traced read came from reach an operation that CHANGED?

    The second half of the positional fix, and a different question from
    `read_sits_where_subject_says`: that one asks where in a body the read
    sits, this one asks whether the body is one the change touches at all.
    Langfuse reads `subscription.customer` off `stripe.subscriptions.retrieve`;
    `invoice.discount.customer` was removed from invoice operations, which that
    call does not reach. Either question alone leaves real false positives
    standing -- `subscription.discount.customer` DOES touch subscription
    operations and dies only on position -- so both are asked.

    Abstains (True) in two cases, both of them "cannot be measured here", and
    neither of them a pass on the merits -- position still has to hold:

      * the finding names no operation at all, so there is nothing to compare
        against;
      * the operation list is TRUNCATED. `affected_ops` is capped at 200 while
        `affected_op_count` records the real total, and Stripe's `card.iin`
        touches 551. Answering "not reached" from a list known to be partial
        would reject a caller for using operation 300 of 551 -- a false
        NEGATIVE manufactured by a cap, which is the one failure mode this
        project rates worse than a false positive, because nothing downstream
        can see it.
    """
    paths = _change_operation_paths(finding)
    if not paths:
        return True
    if finding.affected_op_count > len(finding.affected_ops or ()):
        return True
    return any(_chain_matches_path(chain, op_path) for op_path in paths)


def _operation_calls(module: Module, bindings: Set[str], method: str,
                     path: str, lines: Sequence[str]) -> List[Proof]:
    """Calls that reach `METHOD path`, by SDK chain or by fetch URL."""
    found: List[Proof] = []
    for verb, url, call in _fetch_targets(module):
        if path and verb == method.lower() and paths_match(path, url):
            found.append(Proof(
                kind=FIELD_READ, line=call.line, text=_text_at(lines, call.line),
                chain=[f"`fetch` to `{url}`",
                       f"which matches `{method.upper()} {path}`"]))
    if found:
        return found
    # SDK route: a member chain rooted at a value bound to this vendor's client,
    # whose resource segments correspond to the operation's path.
    wanted = [segment for segment in path.split("/")
              if segment and not segment.startswith("{")]
    if not wanted:
        return found
    for call in module.calls:
        if len(call.chain) < 2 or call.chain[0] not in bindings:
            continue
        if _chain_matches_path(call.chain, path):
            found.append(Proof(
                kind=FIELD_READ, line=call.line, text=_text_at(lines, call.line),
                chain=[f"`{'.'.join(call.chain)}(...)` on the "
                       f"`{call.chain[0]}` client",
                       f"which is `{method.upper()} {path}`"]))
    return found


def _reads_of(module: Module, leaf: str, bindings: Set[str],
              lines: Sequence[str], traced_only: bool = False,
              finding: Optional[Finding] = None,
              origins: Optional[Dict[int, Tuple[str, ...]]] = None) -> List[Proof]:
    """Reads of `leaf`, optionally only where the value came from this vendor.

    `finding` turns on the POSITIONAL filter: a read only counts when it sits
    where the subject says it sits. Without it this accepted
    `subscription.currency` as a read of `deleted_discount.coupon.currency` --
    the same word at a different place -- which was twelve of the thirteen
    impacts the scanner reported across 22 real repositories on 2026-08-21.
    See `dependence.read_sits_where_subject_says`.

    `traced_only` is the difference between dependence and coincidence. Without
    it this returned every `.name`, `.id` and `.user` in the file: Langfuse's
    `_app.tsx` was reported as depending on Sentry's replay endpoint because it
    reads `error.name` off a DOMException and `sessionUser.id` off NextAuth.
    That is co-location, which took three adversarial audits to remove from the
    Python prover and which I reintroduced here by reading only half its
    contract.
    """
    origin: Dict[str, Tuple[str, ...]] = {
        call.assigned_to: call.chain for call in module.calls
        if call.assigned_to and call.chain and call.chain[0] in bindings}
    found: List[Proof] = []
    for read in module.reads:
        if leaf not in read.path:
            continue
        chain = origin.get(read.base)
        if traced_only and chain is None:
            continue
        if finding is not None and not read_sits_where_subject_says(
                finding, (read.base,) + tuple(read.path), leaf):
            continue
        if origins is not None and chain is not None:
            origins[read.line] = chain
        proof_chain = [f"reads `{read.base}.{'.'.join(read.path)}`"]
        if chain is not None:
            proof_chain.append(
                f"and `{read.base}` came from `{'.'.join(chain)}(...)`")
        found.append(Proof(kind=FIELD_READ, line=read.line,
                           text=_text_at(lines, read.line), chain=proof_chain))
    return found


def _sends_of(module: Module, leaf: str, bindings: Set[str],
              lines: Sequence[str]) -> List[Proof]:
    """`leaf` passed as a key of an object argument to a vendor call."""
    found: List[Proof] = []
    for call in module.calls:
        if not call.chain or call.chain[0] not in bindings:
            continue
        if leaf in call.arg_keys:
            found.append(Proof(
                kind=FIELD_SENT, line=call.line,
                text=_text_at(lines, call.line),
                chain=[f"sends `{leaf}` to `{'.'.join(call.chain)}(...)`"]))
    return found


def prove(source: str, finding: Finding, vendor: Vendor) -> Tuple[List[Proof], str]:
    """(proofs, reason_when_empty). Never returns a proof it cannot show."""
    try:
        module = analyse(source)
    except UnreadableSource as exc:
        return [], f"unreadable javascript: {exc}"

    bindings = _vendor_bindings(module, vendor)
    lines = _lines(source)
    method = (finding.method or "get").lower()
    path = finding.path if not finding.path.startswith("#") else ""
    leaf = _leaf_of(finding)

    # A file that pins the API version is not affected by a change to the
    # latest one. Named as an open blind spot and never modelled anywhere.
    if module.version_pins:
        pinned = module.version_pins[0]
        return [], (f"pins the API version to `{pinned[1]}` at line "
                    f"{pinned[2]} — a change to the current version does not "
                    f"reach a caller on an older one")

    if not bindings and not _fetch_targets(module):
        return [], "no client of this vendor is constructed or imported here"

    if finding.kind in ABSENCE_KINDS:
        if not leaf:
            return [], "the change names no field to check for"
        calls = _operation_calls(module, bindings, method, path, lines)
        if not calls:
            return [], f"no call reaching `{method.upper()} {path}`"
        if _sends_of(module, leaf, bindings, lines):
            return [], f"already supplies `{leaf}` — migrated"
        return ([Proof(kind=FIELD_MISSING, line=c.line, text=c.text,
                       chain=c.chain + [f"and never supplies required `{leaf}`"])
                 for c in calls], "")

    if finding.kind in ENDPOINT_KINDS:
        calls = _operation_calls(module, bindings, method, path, lines)
        if not calls:
            return [], f"no call reaching `{method.upper()} {path or '?'}`"
        if finding.kind == "schema_removed":
            leaves = [n for n in (finding.leaf_fields or []) if _is_distinctive(n)]
            if not leaves:
                return [], (f"schema `{finding.subject}` names no field "
                            f"distinctive enough to prove a read")
            touched: List[Proof] = []
            for name in leaves:
                touched.extend(_reads_of(module, name, bindings, lines))
            if not touched:
                return [], (f"calls the operation but reads no field of the "
                            f"deleted schema `{finding.subject}`")
            return touched, ""
        return calls, ""

    # Field-level changes. Two routes, and the second needs BOTH halves --
    # mirroring `dependence.prove()`, whose contract is a read of the field AND
    # a call to an operation that carries it. Taking only the first half is
    # co-location: it reported Langfuse as depending on Sentry's replay
    # endpoint for reading `error.name` off a DOMException.
    if not leaf:
        return [], "the change names no field to check for"
    if finding.kind.startswith("request_") or finding.in_request:
        sends = _sends_of(module, leaf, bindings, lines)
        if not sends:
            return [], f"never sends `{leaf}` to this vendor"
        if not _operation_calls(module, bindings, method, path, lines):
            return [], (f"sends `{leaf}` but never calls an operation that "
                        f"accepts it")
        return sends, ""

    # Route 1: the value is traced to a vendor call and the field is read off
    # it. Dependence end to end -- but "the field" is a POSITION, not a word.
    # This route used to return on the word alone, and twelve of the thirteen
    # impacts it produced across 22 real repositories were the same word at a
    # different place: `subscription.currency` returned as a read of
    # `deleted_discount.coupon.currency`. Two questions now, and neither is
    # the other: does the read sit where the subject says (position), and does
    # the call it came from reach an operation this change touches (reach).
    origins: Dict[int, Tuple[str, ...]] = {}
    traced = _reads_of(module, leaf, bindings, lines, traced_only=True,
                       finding=finding, origins=origins)
    reaching = [proof for proof in traced
                if _chain_reaches_change(origins.get(proof.line, ()), finding)]
    if reaching:
        return reaching, ""

    # Route 2: the field is read somewhere, AND this file calls an operation
    # that carries it. Needed because most reads happen on a function
    # parameter whose origin is in the caller and not visible here.
    reads = _reads_of(module, leaf, bindings, lines, finding=finding)
    if not reads:
        if traced:
            origin_chain = ".".join(origins.get(traced[0].line, ()) or ("?",))
            return [], (f"reads `{leaf}` off `{origin_chain}(...)`, which "
                        f"reaches no operation this change touches")
        ancestry = subject_ancestry(finding)
        if ancestry:
            return [], (f"never reads `{leaf}` at `{'.'.join(ancestry)}`, "
                        f"where `{wire_subject(finding)}` sits")
        return [], f"never reads `{leaf}` off a value from this vendor"
    calls = _operation_calls(module, bindings, method, path, lines)
    if not calls:
        return [], (f"reads `{leaf}` but never calls an operation that "
                    f"carries it")
    anchor = calls[0].text[:60]
    return ([Proof(kind=p.kind, line=p.line, text=p.text,
                   chain=p.chain + [f"and this file calls `{anchor}`, an "
                                    f"operation carrying the changed schema"])
             for p in reads], "")


def prove_relevance(source: str, addition: Finding,
                    vendor: Vendor) -> Tuple[List[Proof], str]:
    """Is this repo positioned to USE something the vendor just added?

    Deliberately a weaker standard than `prove()`, and kept in its own function
    for the reason the Python side keeps it in its own function: a breaking
    change requires dependence on the changed element, and an ADDITION cannot
    be depended on by anyone because it did not exist. Reach is not a weak
    substitute for the proof here -- it IS the proof, and "you already call
    this resource" is the whole claim.

    Sharing one function with `prove` would put the two one edit away from
    accepting reach as evidence of a break again, which is the defect that
    took three adversarial audits to find.
    """
    try:
        module = analyse(source)
    except UnreadableSource as exc:
        return [], f"unreadable javascript: {exc}"

    bindings = _vendor_bindings(module, vendor)
    if not bindings and not _fetch_targets(module):
        return [], "no client of this vendor is constructed or imported here"
    lines = _lines(source)

    for op_key in (addition.affected_ops or [])[:40]:
        op_method, _, op_path = op_key.partition(" ")
        if not op_path or op_path.startswith("#"):
            continue
        hits = _operation_calls(module, bindings, op_method.lower(), op_path, lines)
        if hits:
            return hits[:3], ""

    # No specific operation reached, but the file does hold this vendor's
    # client. That is still reach at the RESOURCE level when the chain names
    # the resource the addition belongs to.
    resource = (addition.resource or "").lower().rstrip("s")
    if resource:
        for call in module.calls:
            if len(call.chain) < 2 or call.chain[0] not in bindings:
                continue
            if any(part.lower().rstrip("s") == resource for part in call.chain[1:]):
                return [Proof(
                    kind=FIELD_READ, line=call.line,
                    text=_text_at(lines, call.line),
                    chain=[f"already calls `{'.'.join(call.chain)}(...)`",
                           f"on the `{addition.resource}` resource"])], ""
    return [], (f"calls nothing on `{addition.resource or 'this resource'}`, "
                f"so there is nothing here to adopt it into")
