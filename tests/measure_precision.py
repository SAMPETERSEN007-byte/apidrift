"""Measure what fraction of findings are real, over a RANDOM sample.

Five hand-picked confirmations say nothing about the other 393. This draws a
random sample and re-derives each finding from the raw specs using plain
dictionary lookups. It deliberately imports nothing from `apidrift.diff` or
`apidrift.loader`: a checker built on the engine would be wrong the same way
the engine is.

Findings this method cannot decide are reported as UNDECIDABLE and excluded
from the precision ratio rather than silently counted as passes.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import random
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
sys.path.insert(0, str(ROOT))

from apidrift.vendors import VENDORS  # noqa: E402  (registry only, no diff logic)

CONFIRMED = "CONFIRMED"
REFUTED = "REFUTED"
UNDECIDABLE = "UNDECIDABLE"


def sh(args: List[str], cwd: Path) -> bytes:
    proc = subprocess.run(args, cwd=str(cwd), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:200])
    return proc.stdout


def load_spec(repo_dir: Path, ref: str, path: str) -> Dict[str, Any]:
    raw = sh(["git", "show", f"{ref}:{path}"], repo_dir)
    if path.endswith(".json"):
        return json.loads(raw)
    return yaml.safe_load(raw)


def tree(repo_dir: Path, ref: str) -> List[str]:
    return sh(["git", "ls-tree", "-r", "--name-only", ref], repo_dir) \
        .decode("utf-8", "replace").splitlines()


def schemas_of(doc: Dict[str, Any]) -> Dict[str, Any]:
    return ((doc.get("components") or {}).get("schemas")
            or doc.get("definitions") or {})


def walk_properties(schema: Any, parts: List[str], doc: Dict[str, Any],
                    depth: int = 0) -> Tuple[bool, Any]:
    """Follow a dotted field path through properties, allOf and $ref."""
    if depth > 12 or not isinstance(schema, dict):
        return False, None
    if "$ref" in schema:
        name = str(schema["$ref"]).rsplit("/", 1)[-1]
        target = schemas_of(doc).get(name)
        if target is None:
            return False, None
        return walk_properties(target, parts, doc, depth + 1)
    if not parts:
        return True, schema

    head, rest = parts[0], parts[1:]
    if head == "[]":
        return walk_properties(schema.get("items"), rest, doc, depth + 1)

    props = schema.get("properties") or {}
    if head in props:
        return walk_properties(props[head], rest, doc, depth + 1)
    for key in ("allOf", "oneOf", "anyOf"):
        for arm in schema.get(key) or []:
            found, node = walk_properties(arm, parts, doc, depth + 1)
            if found:
                return True, node
    return False, None


def merge_all_of(prop: Dict[str, Any], doc: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten an `allOf` into the single schema a consumer actually faces.

    `allOf` is an INTERSECTION: a value must satisfy every arm at once, so what
    the consumer sees is all of them merged. Reading only the node's own
    keywords sees an empty schema, and an empty schema is what a document says
    when it accepts ANYTHING -- so `{}` and
    `allOf: [$ref crypto_request, {title, description}]` both scored
    `('scalar', None, None)` and compared EQUAL. PayPal narrowed
    `order_request.payment_source.crypto` from "any JSON" to "a crypto_request"
    and this file called it unchanged, twice from the schema side and twice
    from the request side.

    Sibling keywords on the node itself win over an arm's, because they are
    the more specific statement about this use.
    """
    merged = {key: value for key, value in prop.items() if key != "allOf"}
    props = dict(merged.get("properties") or {})
    required = list(merged.get("required") or [])
    for arm in prop.get("allOf") or []:
        # Resolve the arm's whole reference chain before reading it. Taking one
        # hop and copying a `$ref` up into the merged node would let that ref
        # win in `effective_shape` -- which consults `$ref` before
        # `properties` -- and silently discard every other arm.
        target = follow(doc, arm)
        if isinstance(target, dict) and target.get("allOf"):
            target = merge_all_of(target, doc)
        if not isinstance(target, dict) or "$ref" in target:
            continue
        props.update(target.get("properties") or {})
        required += list(target.get("required") or [])
        # `allOf: [{$ref: X}, {nullable: true}]` is the OpenAPI 3.0 idiom for
        # "a nullable X" -- there is no other way to attach nullability to a
        # reference. Cloudflare's email-security request fields carry it in the
        # ARM, and dropping it silently made a field that stopped accepting
        # null compare equal to its old self.
        if target.get("nullable") is True:
            merged["nullable"] = True
        for key in ("type", "enum", "items", "oneOf", "anyOf"):
            if key not in merged and key in target:
                merged[key] = target[key]
    if props:
        merged["properties"] = props
    if required:
        merged["required"] = sorted(set(required))
    return merged


#: What `effective_shape` returns when it could not resolve the node at all.
#: An admission of ignorance, never to be compared for equality against another
#: one -- see `_informative` below.
UNRESOLVED = ("unresolved",)

#: What a document says when it accepts ANY JSON value: `{}`, or a node
#: carrying only annotations. This is a POSITIVE statement and must not be
#: confused with the admission above, which is what `("scalar", None, None)`
#: did by serving as both. PayPal narrowed `order_request.payment_source.crypto`
#: from `{}` to a `crypto_request` -- a real narrowing that reads as "I could
#: not tell" the moment the two share a value.
ANY_VALUE = ("any",)

#: Keywords that say nothing about the VALUE, only about how to document it.
_ANNOTATION_ONLY = frozenset({
    "title", "description", "example", "examples", "deprecated", "readOnly",
    "writeOnly", "externalDocs", "xml", "default", "$comment"})


def _informative(shape: Any) -> bool:
    """False when the shape is this checker admitting it could not tell.

    Two admissions of ignorance are not evidence that two things are the same,
    and one admission set against a resolved shape is not evidence that they
    differ. Both readings shipped: the first REFUTED eight findings, the second
    CONFIRMED three hundred more of the identical PayPal rewrite.
    """
    return shape not in ("opaque", UNRESOLVED, ("ref-unresolved",))


def effective_shape(prop: Any, doc: Dict[str, Any], depth: int = 0) -> Any:
    """What a consumer actually sees for this property.

    Written independently of the engine, and deliberately so: it answers the
    same question by resolving to a concrete shape rather than by comparing
    type labels. An `allOf` is flattened to its intersection, and a reference
    resolves to the sorted field names of its target so that a rename is
    invisible.
    """
    if not isinstance(prop, dict) or depth > 3:
        return "opaque"
    # `{}` accepts any JSON value, and so does a node carrying nothing but
    # annotations. That is the DOCUMENT speaking, not this function failing,
    # and the two used to return the same tuple.
    if not (set(prop) - _ANNOTATION_ONLY):
        return ANY_VALUE
    arms = prop.get("allOf")
    if isinstance(arms, list) and arms:
        # `allOf` is an INTERSECTION: a document must satisfy every arm, so
        # what a consumer sees is all of them at once. Reading only the node's
        # own keywords finds no type, no properties and no enum, and the
        # fall-through then answered UNRESOLVED -- "I know nothing about this
        # node". PayPal rewrote `$ref` + sibling keywords into exactly that
        # form across its whole checkout spec in this window.
        #
        # Merged rather than evaluated arm-by-arm, because an arm can carry
        # `nullable` for a sibling `$ref` -- the OpenAPI 3.0 idiom for "a
        # nullable X" -- and reading arms separately drops it.
        #
        # Recursed at the SAME depth on purpose: an `allOf` is a conjunction,
        # not a level of nesting, and spending budget on it made one schema
        # resolve differently depending on which notation named it.
        merged = merge_all_of(prop, doc)
        if merged.get("allOf") == arms:          # nothing was flattened
            return UNRESOLVED
        return effective_shape(merged, doc, depth)
    # Nullability is part of the VALUE a caller may send or receive, and this
    # function never looked at it. Cloudflare dropped `nullable: true` from
    # five email-security REQUEST fields in this window: a caller that was
    # sending null is now rejected, and every one of them compared equal.
    if prop.get("nullable") is True:
        rest = {k: v for k, v in prop.items() if k != "nullable"}
        return ("nullable", effective_shape(rest, doc, depth + 1))
    ref = prop.get("$ref")
    if isinstance(ref, str):
        target = schemas_of(doc).get(ref.rsplit("/", 1)[-1])
        if not isinstance(target, dict):
            return ("ref-unresolved",)
        # Resolve the target the same way as anything else, so an enum behind a
        # reference is not silently discarded. Dropping it made the OpenAI
        # ServiceTier widening (which gained `fast` and `ultrafast`) compare
        # equal to its predecessor.
        return effective_shape(target, doc, depth + 1)
    if "properties" in prop:
        return ("object", tuple(sorted(prop["properties"].keys())))
    if prop.get("type") == "array":
        return ("array", effective_shape(prop.get("items") or {}, doc, depth + 1))
    for key in ("oneOf", "anyOf"):
        if key in prop:
            return (key, tuple(sorted(
                str(effective_shape(a, doc, depth + 1)) for a in prop[key])))
    enum = prop.get("enum")
    if prop.get("type") is None and not enum:
        # Keywords this function does not model, and no type or enum to fall
        # back on. That is ignorance, not a shape, and it used to be spelled
        # `("scalar", None, None)` -- the very same tuple `{}` produced. One
        # value meaning both "accepts anything" and "I cannot tell" is what let
        # a real narrowing read as no change.
        return UNRESOLVED
    return ("scalar", prop.get("type"), tuple(sorted(map(str, enum))) if enum else None)


def body_roots_at(doc: Dict[str, Any], node: Any, depth: int = 0,
                  seen: Optional[set] = None) -> set:
    """Schema NAMES this body node resolves to at its ROOT position.

    Only `$ref` and the composition keywords are followed, never `properties`
    or `items`: the question is what schema the body IS, not what it contains.
    `allOf: [Envelope, {...}]` is both `Envelope` and an inline object, so both
    arms count.

    Written here with this file's own resolver. The engine has its own notion
    of which schema an operation's body is, and a checker that borrows it
    agrees with it by construction.
    """
    seen = set() if seen is None else seen
    names: set = set()
    if depth > 8 or not isinstance(node, dict):
        return names
    ref = node.get("$ref")
    if isinstance(ref, str):
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            return names
        names.add(name)
        return names | body_roots_at(doc, schemas_of(doc).get(name) or {},
                                     depth + 1, seen | {name})
    for keyword in ("allOf", "anyOf", "oneOf"):
        for arm in node.get(keyword) or []:
            names |= body_roots_at(doc, arm, depth + 1, seen)
    return names


def subject_tokens(subject: str) -> List[Tuple[str, str]]:
    """Split a subject into ('mark'|'prop'|'item', value) steps."""
    out: List[Tuple[str, str]] = []
    i = 0
    while i < len(subject):
        char = subject[i]
        if char == "<":
            close = subject.find(">", i)
            if close < 0:
                return []
            out.append(("mark", subject[i + 1:close]))
            i = close + 1
        elif subject.startswith("[]", i):
            out.append(("item", "[]"))
            i += 2
        elif char == ".":
            i += 1
        else:
            j = i
            while j < len(subject) and subject[j] not in ".<[":
                j += 1
            if j == i:
                return []
            out.append(("prop", subject[i:j]))
            i = j
    return out


def pointer(doc: Dict[str, Any], ref: str) -> Any:
    """Resolve a local JSON pointer by walking it, not by guessing its section."""
    if not ref.startswith("#/"):
        return None
    node: Any = doc
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            return None
        node = node[token]
    return node


def deref(doc: Dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Follow a local `$ref` chain. Written here; the engine's is not imported."""
    seen: Set[str] = set()
    while isinstance(node, dict) and isinstance(node.get("$ref"), str) and depth < 24:
        ref = node["$ref"]
        if ref in seen:
            return {}
        seen.add(ref)
        node = schemas_of(doc).get(ref.rsplit("/", 1)[-1])
        depth += 1
    return node if isinstance(node, dict) else {}


def payload_alternatives(doc: Dict[str, Any], node: Any, depth: int = 0) -> List[Any]:
    """Every shape a payload at this position may take.

    `oneOf`/`anyOf` are alternatives; `allOf` is one shape and stays whole. A
    `null` arm is dropped: it is the absence of a payload, not a payload with
    fields to read, and a response that can no longer be null is narrower
    rather than broken.
    """
    node = deref(doc, node)
    if depth > 6 or not node:
        return [node] if node else []
    out: List[Any] = []
    for key in ("oneOf", "anyOf"):
        arms = node.get(key)
        if isinstance(arms, list) and arms:
            if is_documented_enum(doc, node, arms):
                return [node]
            for arm in arms:
                resolved = deref(doc, arm)
                if type_name(resolved) == "null":
                    continue
                out.extend(payload_alternatives(doc, arm, depth + 1))
            return out
    return [node]


def is_documented_enum(doc: Dict[str, Any], node: Dict[str, Any],
                       arms: List[Any]) -> bool:
    """A `oneOf` of `const` values is one scalar with docs, not alternatives.

    Discord writes `ForumLayout` as `{"type": "integer", "oneOf": [{"title":
    "DEFAULT", "const": 0}, ...]}` so each value gets a name and a sentence.
    Splitting that into three alternatives loses the declared `integer` and
    leaves three shapes of type `any`, which then match nothing -- and the
    checker CONFIRMS a field that never moved. A union whose members only pin
    values is a value set, so the node stays whole.
    """
    if not node.get("type"):
        return False
    for arm in arms:
        resolved = deref(doc, arm)
        if not resolved:
            return False
        if "const" not in resolved and not resolved.get("enum"):
            return False
        if resolved.get("properties") or resolved.get("items"):
            return False
    return True


def type_name(node: Any) -> str:
    if not isinstance(node, dict):
        return "any"
    raw = node.get("type")
    if isinstance(raw, list):
        rest = [t for t in raw if t != "null"]
        return str(rest[0]) if rest else "null"
    if raw:
        return str(raw)
    if "properties" in node:
        return "object"
    if "items" in node:
        return "array"
    if "allOf" in node:
        return "object"
    for key in ("oneOf", "anyOf"):
        if key in node:
            return key
    return "any"


def flat_properties(doc: Dict[str, Any], node: Any,
                    depth: int = 0) -> Tuple[Dict[str, Any], Set[str]]:
    """Properties visible on ONE alternative, merging `allOf` (not unions)."""
    node = deref(doc, node)
    props: Dict[str, Any] = {}
    required: Set[str] = set()
    if depth > 6 or not node:
        return props, required
    for arm in node.get("allOf") or []:
        sub, sub_req = flat_properties(doc, arm, depth + 1)
        props.update(sub)
        required |= sub_req
    props.update(node.get("properties") or {})
    required |= {str(r) for r in (node.get("required") or [])}
    return props, required


def allowed_values(doc: Dict[str, Any], node: Any) -> Optional[Set[str]]:
    """The value set a property is pinned to, if any (`const` or `enum`)."""
    node = deref(doc, node)
    if not node:
        return None
    if "const" in node:
        return {str(node["const"])}
    enum = node.get("enum")
    if isinstance(enum, list) and enum:
        return {str(v) for v in enum}
    return None


def shape_of(doc: Dict[str, Any], node: Any) -> Tuple[str, frozenset, Dict[str, Set[str]]]:
    """What a caller can rely on from one alternative: type, names, pinned values."""
    props, _ = flat_properties(doc, node)
    pinned = {}
    for name, sub in props.items():
        values = allowed_values(doc, sub)
        if values:
            pinned[name] = values
    return type_name(deref(doc, node)), frozenset(props), pinned


def still_presented(doc_new: Dict[str, Any], candidates: List[Any],
                    old_shape: Tuple[str, frozenset, Dict[str, Set[str]]]) -> bool:
    """Can some new alternative still deliver everything the old one did?

    Names alone are not enough. Discord replaced `SpamLinkRuleResponse` with
    `UserProfileRuleResponse` in the 200 of
    `GET /guilds/{id}/auto-moderation/rules`; the two carry the SAME eleven
    property names and differ only in the value `trigger_type` is pinned to
    (2 vs 4). A caller keyed on `trigger_type == 2` has lost its arm, so the
    pinned values are part of what an alternative promises.
    """
    old_type, old_props, old_pinned = old_shape
    for candidate in candidates:
        cand_type, cand_props, cand_pinned = shape_of(doc_new, candidate)
        if old_type != cand_type:
            continue
        if not old_props <= cand_props:
            continue
        if any(name in cand_pinned and not values <= cand_pinned[name]
               for name, values in old_pinned.items()):
            continue
        return True
    return False


def unconstrained(doc: Dict[str, Any], node: Any) -> bool:
    """An object that declares no properties at all constrains nothing.

    Sentry replaced an issue's `metadata` -- a two-arm union with declared
    fields -- by `{"type": "object", "additionalProperties": {}}`. Nothing in
    that document says whether `filename` still arrives, so the honest answer is
    that this checker cannot tell. Deciding it either way would be a verdict
    read off a premise that holds vacuously, which is how the first
    `unreachable` rule nearly deleted a real Sentry break.

    `additionalProperties: false` is the opposite case and must not be swept in
    with it. Cloudflare's `DELETE /accounts/{id}/ai-search/tokens/{id}` returns
    `{"type": "object", "additionalProperties": false}` where nine fields used
    to be: that document says, explicitly, that nothing else arrives. Treating
    the two spellings alike would abstain on nine real breaks.
    """
    resolved = deref(doc, node)
    if not resolved or type_name(resolved) != "object":
        return False
    if resolved.get("additionalProperties") is False:
        return False
    props, _ = flat_properties(doc, resolved)
    return not props


def guaranteed_property(doc: Dict[str, Any], node: Any, name: str) -> Tuple[bool, Any]:
    """Is `name` promised here whatever the server answers with?

    Under a `oneOf` a property present in ONE arm is not promised: the server
    may answer with another arm. `walk_properties` returns the first arm that
    has it, which is right for `allOf` and wrong for a union -- and it is the
    difference between "the field is still somewhere in the document" (the
    engine's question) and "a caller can still read it" (the caller's).
    """
    alts = payload_alternatives(doc, node)
    if not alts:
        return False, None
    found = None
    for alt in alts:
        props, _ = flat_properties(doc, alt)
        if name not in props:
            return False, None
        found = props[name] if found is None else found
    return True, found


def walk_subject(doc: Dict[str, Any], body: Any,
                 tokens: List[Tuple[str, str]]) -> Tuple[bool, Any]:
    """Follow subject tokens through a raw body. Schema marks are not steps."""
    node = body
    for index, (kind, value) in enumerate(tokens):
        if kind == "mark":
            picked = pick_arm(doc, node, value)
            if picked is None:
                if index == 0 and value in body_roots_at(doc, node):
                    continue  # the root stamp names what the body IS, not a step
                if index == 0:
                    # ...but only when the body really IS that schema. A
                    # subject rooted at `<Foo>` walked against an operation
                    # that returns `Bar` re-reads `Foo.id` as `Bar.id`, and an
                    # unrelated field that never moved then decides a real
                    # change. Abstaining is the direction that cannot
                    # manufacture a verdict.
                    return False, None
                return False, None
            node = picked
        elif kind == "item":
            items = None
            for alt in payload_alternatives(doc, node):
                if isinstance(alt, dict) and alt.get("items") is not None:
                    items = alt["items"]
                    break
            if items is None:
                return False, None
            node = items
        else:
            ok, sub = guaranteed_property(doc, node, value)
            if not ok:
                return False, None
            node = sub
    return True, node


def pick_arm(doc: Dict[str, Any], node: Any, name: str) -> Optional[Any]:
    """The union arm the engine called `name`, matched by `$ref` name or title."""
    raw = deref(doc, node)
    for key in ("oneOf", "anyOf"):
        arms = raw.get(key)
        if not isinstance(arms, list):
            continue
        for arm in arms:
            if isinstance(arm, dict):
                ref = arm.get("$ref")
                if isinstance(ref, str) and ref.rsplit("/", 1)[-1] == name:
                    return arm
        for arm in arms:
            target = deref(doc, arm)
            if str(target.get("title") or "") == name:
                return arm
    return None


def resolve_root(doc: Dict[str, Any], root_cause: str) -> Optional[Tuple[Any, List[str]]]:
    """Split `Schema.a.b` into (schema object, ['a','b']). None if no schema."""
    segments = [s for s in root_cause.replace("[]", ".[].").split(".") if s]
    if not segments:
        return None
    schemas = schemas_of(doc)
    head = segments[0]
    if head not in schemas:
        return None
    return schemas[head], segments[1:]


_ERASED = re.compile(r"\{[^}]*\}")


def find_operation(doc: Dict[str, Any], op_key: str) -> Optional[Dict[str, Any]]:
    """The operation this key names, addressed the way a CALLER addresses it.

    A path parameter's NAME is OpenAPI-internal and never reaches the wire:
    `/investigate/{postfix_id}` and `/investigate/{investigate_id}` produce
    byte-identical URLs for every concrete value, so they are one endpoint. The
    `endpoint_removed` and `endpoint_moved` branches below have always known
    that; this lookup did not, so a vendor renaming a path parameter made every
    OTHER finding on that operation UNDECIDABLE -- the operation "was missing
    from one side" when it was sitting right there under a different spelling.

    Cloudflare renamed `{postfix_id}` -> `{investigate_id}` in this window, and
    that alone is why `result.action_log` could not be decided.

    The fallback is deliberately narrow. It runs only when the exact key is
    absent, and only when exactly ONE path normalises to the same template: a
    document holding two distinct paths that differ only in parameter names is
    self-contradictory, and guessing which one was meant would answer a
    question nobody asked. Ambiguity stays UNDECIDABLE.
    """
    method, _, path = op_key.partition(" ")
    item = find_path_item(doc, path)
    if item is None:
        return None
    node = item.get(method.lower())
    return node if isinstance(node, dict) else None




def find_path_item(doc: Dict[str, Any], path: str) -> Optional[Dict[str, Any]]:
    """The path item, matched on the URL a caller would actually build."""
    paths = doc.get("paths") or {}
    item = paths.get(path)
    if isinstance(item, dict):
        return item
    wanted = _ERASED.sub("{}", path)
    candidates = [value for key, value in paths.items()
                  if isinstance(value, dict)
                  and _ERASED.sub("{}", str(key)) == wanted]
    return candidates[0] if len(candidates) == 1 else None


def operation_params(doc: Dict[str, Any], op_key: str) -> Dict[str, Any]:
    """Every parameter in effect on this operation, by name.

    Path-item parameters apply to every operation under them and the operation
    may override one, so the operation's own entries are merged last.
    """
    method, _, path = op_key.partition(" ")
    item = find_path_item(doc, path) or {}
    op = item.get(method.lower())
    op = op if isinstance(op, dict) else {}
    merged: Dict[str, Any] = {}
    for entry in list(item.get("parameters") or []) + list(op.get("parameters") or []):
        if isinstance(entry, dict) and "$ref" in entry:
            ref = str(entry["$ref"]).rsplit("/", 1)[-1]
            entry = ((doc.get("components") or {}).get("parameters")
                     or doc.get("parameters") or {}).get(ref) or {}
        if isinstance(entry, dict) and entry.get("name"):
            merged[str(entry["name"])] = entry
    return merged


def param_schema(entry: Dict[str, Any]) -> Any:
    """Where a parameter's value schema lives, across the dialects in use.

    OpenAPI 3 puts it under `schema`, or under `content/<mime>/schema` for a
    serialised one; Swagger 2 writes `type`/`enum` on the parameter itself.
    """
    if not isinstance(entry, dict):
        return None
    if isinstance(entry.get("schema"), dict):
        return entry["schema"]
    for body in (entry.get("content") or {}).values():
        if isinstance(body, dict) and isinstance(body.get("schema"), dict):
            return body["schema"]
    if "enum" in entry or "type" in entry:
        return entry
    return None


# --------------------------------------------------------------------------
# "newly required", asked the VALIDATOR's way
#
# The engine's question is "does the string `leaf` appear in a `required: [...]`
# array at the one node my dotted path reaches?", and this checker asked the
# same thing at the same node -- the sixth instance of a checker sharing the
# engine's question. The caller's question is different and it is the only one
# that decides anything: **is there a JSON body that validated under OLD and is
# REJECTED under NEW?**
#
# Two things follow that the string test cannot see:
#
#   * `oneOf`/`anyOf` is a DISJUNCTION. A body need only satisfy one arm, so a
#     name is genuinely obligatory only when EVERY arm demands it. Unioning the
#     arms' `required` arrays -- which is what reading one node's array after
#     the flattener has picked an arm amounts to -- turns a union-arm rename
#     into a new obligation that no validator would ever enforce.
#   * A requirement inside an object that DID NOT EXIST in the old document
#     cannot reject an old body, because no old body could contain that object.
#     The obligation is additive; it arrives with the object.
#
# Both are decided here, from the raw document, with this file's own resolver.
# --------------------------------------------------------------------------

_MARKER = re.compile(r"<[^>]*>")


def body_path(subject: str) -> List[str]:
    """The property path inside the body, engine-internal markers erased.

    `<CheckoutForwardRequest>.amount.currency` is the flattener's notation for
    the property `amount.currency` of the body: the angle-bracketed segments
    name a SCHEMA or an anonymous union arm, neither of which is a property and
    neither of which reaches the wire. Walking them as property names is why
    103 findings in this class came back "could not resolve the parent object"
    -- undecidable for a purely notational reason.
    """
    bare = _MARKER.sub("", subject)
    return [p for p in bare.replace("[]", ".[].").split(".") if p]


def required_everywhere(node: Any, doc: Dict[str, Any], depth: int = 0,
                        seen: frozenset = frozenset()) -> set:
    """Names that EVERY valid object instance of `node` must carry.

    `allOf` is a conjunction, so its arms' obligations union. `oneOf`/`anyOf`
    is a disjunction, so only what every arm demands is guaranteed -- the
    intersection. Deliberately written here rather than imported: the engine's
    flattener resolves an arm and then reads that arm's `required` array, which
    is the union answer, and a checker that reuses it agrees with it.
    """
    if not isinstance(node, dict) or depth > 10:
        return set()
    ref = node.get("$ref")
    if isinstance(ref, str):
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            return set()
        target = schemas_of(doc).get(name)
        if target is None:
            return set()
        return required_everywhere(target, doc, depth + 1, seen | {name})
    names = {str(r) for r in (node.get("required") or []) if isinstance(r, str)}
    for arm in node.get("allOf") or []:
        names |= required_everywhere(arm, doc, depth + 1, seen)
    for keyword in ("oneOf", "anyOf"):
        arms = node.get(keyword)
        if not isinstance(arms, list) or not arms:
            continue
        common: Optional[set] = None
        for arm in arms:
            got = required_everywhere(arm, doc, depth + 1, seen)
            common = got if common is None else (common & got)
        names |= (common or set())
    return names


def descend(node: Any, parts: List[str], doc: Dict[str, Any],
            depth: int = 0, seen: frozenset = frozenset()) -> List[Any]:
    """Every schema node a body can present at this property path.

    A list rather than a single node because a union puts the same path in
    several arms, and a body reaching it through one arm is not governed by the
    others. Empty means no valid body can carry that path at all.
    """
    if not isinstance(node, dict) or depth > 12:
        return []
    ref = node.get("$ref")
    if isinstance(ref, str):
        name = ref.rsplit("/", 1)[-1]
        if name in seen:
            return []
        target = schemas_of(doc).get(name)
        if target is None:
            return []
        return descend(target, parts, doc, depth + 1, seen | {name})
    if not parts:
        return [node]
    head, rest = parts[0], parts[1:]
    out: List[Any] = []
    if head == "[]":
        items = node.get("items")
        if items is not None:
            out.extend(descend(items, rest, doc, depth + 1, seen))
    else:
        child = (node.get("properties") or {}).get(head)
        if child is not None:
            out.extend(descend(child, rest, doc, depth + 1, seen))
    for keyword in ("allOf", "oneOf", "anyOf"):
        for arm in node.get(keyword) or []:
            out.extend(descend(arm, parts, doc, depth + 1, seen))
    return out


def check_now_required(finding: Dict[str, Any], old: Dict[str, Any],
                       new: Dict[str, Any], old_body: Any,
                       new_body: Any) -> Tuple[str, str]:
    """Is some body that validated under OLD now rejected for missing `leaf`?"""
    parts = body_path(finding.get("subject") or finding.get("root_cause") or "")
    if not parts:
        return UNDECIDABLE, "the finding names no field path"
    leaf, parents = parts[-1], parts[:-1]
    if new_body is None:
        return UNDECIDABLE, "no request body found on the new side"

    new_nodes = descend(new_body, parents, new)
    if not new_nodes:
        return UNDECIDABLE, (f"`{'.'.join(parents) or '<body>'}` is not "
                             f"resolvable in the new request body")
    if not any(leaf in required_everywhere(n, new) for n in new_nodes):
        # Not obligatory for every body the new document accepts. Saying
        # "therefore not a break" would be over-refuting: the obligation may be
        # real inside ONE arm of a union, and a caller who was using that arm
        # does break. Deciding that needs a correspondence between the old and
        # new arms, which the documents do not state -- so this is undecidable
        # here, not refuted. Over-refuting is the same failure as
        # over-confirming, one sign flipped.
        if any(n.get("oneOf") or n.get("anyOf")
               for n in new_nodes if isinstance(n, dict)):
            return UNDECIDABLE, (
                f"`{leaf}` is required by some arm of a union at "
                f"`{'.'.join(parents) or '<body>'}` but not by every arm — "
                f"deciding it needs an old-arm/new-arm correspondence the "
                f"documents do not state")
        return REFUTED, (f"`{leaf}` is not in the obligations of "
                         f"`{'.'.join(parents) or '<body>'}` in the NEW "
                         f"document at all")

    if old_body is None:
        node = find_operation(old, finding["op_key"])
        if node is None:
            return UNDECIDABLE, "the operation is absent from the old document"
        return REFUTED, ("the operation accepted no request body at old, so no "
                         "old body can be rejected for a field inside one")

    old_nodes = descend(old_body, parents, old)
    if not old_nodes:
        # The enclosing object did not exist in the old document. Nothing a
        # caller sent could contain it, so the obligation arrives WITH the
        # object rather than being imposed on anything that already existed.
        # If the object is itself newly required, that is a break -- but it is
        # the OBJECT's break, reported on its own shorter path, and counting it
        # again on every leaf inside is how one restructure becomes fifty
        # findings.
        deepest = 0
        for cut in range(len(parents), -1, -1):
            if descend(old_body, parents[:cut], old):
                deepest = cut
                break
        missing = parents[deepest] if deepest < len(parents) else leaf
        return REFUTED, (f"`{'.'.join(parents)}` does not exist in the OLD "
                         f"request body (`{missing}` is new), so no body that "
                         f"validated under OLD can contain it — the obligation "
                         f"is additive")

    if all(leaf in required_everywhere(n, old) for n in old_nodes):
        return REFUTED, (f"`{leaf}` was ALREADY required of every old body at "
                         f"`{'.'.join(parents) or '<body>'}` — the obligation "
                         f"did not change, only the notation did")
    return CONFIRMED, (f"a body that validated under OLD (reaching "
                       f"`{'.'.join(parents) or '<body>'}` without `{leaf}`) is "
                       f"rejected by NEW, which requires it")



# --------------------------------------------------------------------------
# schema_removed, asked the CALLER's way
#
# The engine's question is "is the name still in components/schemas?", and for
# 1007 findings across 21 vendors this checker asked exactly the same thing and
# agreed 1007/1007. That is the fifth time a checker has shared the engine's
# assumption, and it is the largest: 36% of the whole breaking population,
# audited by a test that could not fail.
#
# A schema NAME never travels on the wire. Its disappearance can only break a
# caller if the CONTRACT AT THE PLACE IT WAS USED changed. So find every $ref
# to it in the OLD document and look at the same place in the NEW one.
# --------------------------------------------------------------------------

_MISSING = object()


def ref_sites(node: Any, target: Optional[str], path: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
    """Every JSON location in `node` holding `{"$ref": target}`.

    `target=None` matches ANY reference into `components/schemas`, which is how
    the control counts whether this document links schemas at all.
    """
    found: List[Tuple[Any, ...]] = []
    if isinstance(node, dict):
        ref = node.get("$ref")
        if (ref == target if target is not None
                else isinstance(ref, str) and "/schemas/" in ref):
            found.append(path)
        # `discriminator.mapping` values are bare pointer STRINGS, the only
        # reference form in OpenAPI that is not a `{"$ref": ...}` object. Adyen
        # names `BalanceAccountResource` and `MerchantAccountResource` nowhere
        # else, so a walk that looks only for the object form calls them
        # orphans and refutes two real removals.
        disc = node.get("discriminator")
        if isinstance(disc, dict) and isinstance(disc.get("mapping"), dict):
            for slot, pointer in disc["mapping"].items():
                if not isinstance(pointer, str):
                    continue
                if (pointer == target if target is not None
                        else "/schemas/" in pointer):
                    found.append(path + ("discriminator", "mapping", slot))
        for key, value in node.items():
            found.extend(ref_sites(value, target, path + (key,)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(ref_sites(value, target, path + (index,)))
    return found


def value_at(doc: Any, path: Tuple[Any, ...]) -> Any:
    cur = doc
    for step in path:
        try:
            cur = cur[step]
        except (KeyError, IndexError, TypeError):
            return _MISSING
    return cur


def follow(doc: Dict[str, Any], node: Any, budget: int = 8) -> Any:
    """Resolve a chain of local $refs. Returns the node itself if it cannot."""
    while isinstance(node, dict) and "$ref" in node and budget > 0:
        target = str(node["$ref"])
        if not target.startswith("#/"):
            return node
        cur: Any = doc
        for part in target[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            try:
                cur = cur[part]
            except (KeyError, IndexError, TypeError):
                return node
        node, budget = cur, budget - 1
    return node


def _same_contract(old: Dict[str, Any], new: Dict[str, Any],
                   old_body: Any, site: Tuple[Any, ...]) -> bool:
    """Does the NEW document still present `old_body` where the ref used to be?

    Compared at the same JSON location, and — because deleting one arm of a
    `oneOf` shifts every later index — also against every member of the
    enclosing list when the site sits inside one.
    """
    here = value_at(new, site)
    if here is not _MISSING and follow(new, here) == old_body:
        return True
    if site and isinstance(site[-1], int):
        siblings = value_at(new, site[:-1])
        if isinstance(siblings, list):
            return any(follow(new, member) == old_body for member in siblings)
    return False


def _removed_ancestors(old: Dict[str, Any], new: Dict[str, Any],
                       site: Tuple[Any, ...]) -> Optional[str]:
    """The nearest named schema ENCLOSING this site that is also gone.

    `error_409` lived only inside `error_default`, and PayPal deleted both.
    That is one restructure, not two breaks: nothing can observe the inner
    removal except through the outer one, which is reported on its own.
    """
    if len(site) >= 3 and site[0] == "components" and site[1] == "schemas":
        owner = str(site[2])
        if owner in schemas_of(old) and owner not in schemas_of(new):
            return owner
    return None


def check_schema_removed(finding: Dict[str, Any], old: Dict[str, Any],
                         new: Dict[str, Any]) -> Tuple[str, str]:
    name = finding.get("root_cause") or finding["subject"]
    old_schemas, new_schemas = schemas_of(old), schemas_of(new)
    if name not in old_schemas:
        return REFUTED, f"schema `{name}` was not in the old spec either"
    if name in new_schemas:
        return REFUTED, f"schema `{name}` is still defined in the new spec"

    target = f"#/components/schemas/{name}"
    sites = ref_sites(old, target)
    if not sites:
        # CONTROL. On a DEREFERENCED document nothing references anything, so
        # "no $ref points at it" is true of every schema and decides nothing.
        # Sentry's `openapi-derefed.json` inlines each schema body straight
        # into the operation, and refuting on absence-of-$ref there would
        # discard real breaks. Count the linking constructs first: a refuter
        # whose precondition holds for 100% of inputs is a broken instrument,
        # not a result.
        linked = len(ref_sites(old, None))
        if linked == 0:
            return UNDECIDABLE, ("the old document contains no $ref into "
                                 "components/schemas at all — it is "
                                 "dereferenced, so reference-based reasoning "
                                 "has no signal here")
        return REFUTED, (f"nothing in the old document referenced it, though "
                         f"{linked} other schema reference(s) exist — no "
                         f"request or response could carry it, so no caller "
                         f"can observe its removal")

    old_body = follow(old, {"$ref": target})
    if old_body == {"$ref": target}:
        return UNDECIDABLE, f"could not resolve `{name}` in the old document"

    intact, subsumed, broken = 0, [], []
    for site in sites:
        if _same_contract(old, new, old_body, site):
            intact += 1
            continue
        owner = _removed_ancestors(old, new, site)
        if owner:
            subsumed.append(owner)
            continue
        broken.append("/".join(str(x) for x in site))

    if intact == len(sites):
        return REFUTED, (f"inlined or renamed: all {intact} use site(s) still "
                         f"carry an identical shape, so the wire contract is "
                         f"unchanged")
    if not broken and subsumed:
        owners = sorted(set(subsumed))
        return REFUTED, (f"not independently observable — every use site is "
                         f"inside `{owners[0]}`, which was removed too and is "
                         f"reported on its own")
    return CONFIRMED, (f"{len(broken)} of {len(sites)} use site(s) no longer "
                       f"carry the shape, e.g. {broken[0]}")


def check(finding: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any],
          old_tree: List[str], new_tree: List[str]) -> Tuple[str, str]:
    kind = finding["kind"]
    # The SUBJECT is read through `subject_tokens` where a path is needed;
    # `root` is only the collapsed dotted form, and a subject that never went
    # through `collapse()` has none. A regex that stripped the engine's arm
    # markers to fake one stood here and was removed: with it neutered the
    # checker returned byte-identical verdicts on all 1,810 findings across 31
    # vendors, so it was answering nothing that the bracket reader does not.
    root = finding.get("root_cause") or ""

    if kind == "spec_removed":
        target = finding["subject"]
        if target in old_tree and target not in new_tree:
            return CONFIRMED, f"{target} present at old, absent at new"
        return REFUTED, f"{target} old={target in old_tree} new={target in new_tree}"

    if kind == "endpoint_moved":
        # `old` and `new` hold the two op keys; the path itself is what moved.
        old_path = finding["old"].partition(" ")[2]
        new_path = finding["new"].partition(" ")[2]
        # Ask the CALLER's question, not the spec author's. A path parameter's
        # name never reaches the wire, so renaming one moves no endpoint. This
        # check is deliberately written here rather than imported: the engine
        # sharing its resolver with its checker is how the security defect and
        # the schema-relocation defect both survived a "100%" measurement.
        erased = re.compile(r"\{[^}]*\}")
        if erased.sub("{}", old_path) == erased.sub("{}", new_path):
            return REFUTED, (
                f"`{old_path}` and `{new_path}` differ only in parameter "
                f"NAMES — every concrete URL is byte-identical, so no caller "
                f"moved")
        old_paths, new_paths = (old.get("paths") or {}), (new.get("paths") or {})
        if old_path in old_paths and old_path not in new_paths \
                and new_path in new_paths:
            return CONFIRMED, f"`{old_path}` -> `{new_path}`"
        return REFUTED, (f"old_path in old={old_path in old_paths} "
                         f"in new={old_path in new_paths}; "
                         f"new_path in new={new_path in new_paths}")

    if kind == "endpoint_removed":
        # An endpoint is a METHOD at a PATH, and this asked only about the
        # path. Removing `GET /emails` while `POST /emails` stays is a total
        # break for every reader of that collection, and it read as "path
        # present in both" and was refuted. Caught by injecting exactly that
        # into Resend's real spec: the engine found it, this refuted it, and
        # the engine was right.
        #
        # A path parameter's NAME never reaches the wire, so the comparison is
        # made on the normalised template -- otherwise a vendor renaming
        # `{Sid}` to `{id}` looks like a removal plus an addition. That
        # normalisation is written here rather than imported, for the same
        # reason as everywhere else in this file.
        erased = re.compile(r"\{[^}]*\}")

        def verbs(doc, wanted):
            found = set()
            for path, item in (doc.get("paths") or {}).items():
                if erased.sub("{}", str(path)) != wanted or not isinstance(item, dict):
                    continue
                found |= {m for m in ("get", "post", "put", "patch", "delete",
                                      "options", "head", "trace")
                          if isinstance(item.get(m), dict)}
            return found

        method = finding["method"].lower()
        wanted = erased.sub("{}", finding["path"])
        was, now = verbs(old, wanted), verbs(new, wanted)
        if not was:
            return UNDECIDABLE, f"`{finding['path']}` is absent from the old spec too"
        if method in was and method not in now:
            others = ", ".join(sorted(now)) or "nothing"
            return CONFIRMED, (f"`{method.upper()} {finding['path']}` present at "
                               f"old, absent at new ({others} remain there)")
        return REFUTED, (f"`{method.upper()}` old={method in was} "
                         f"new={method in now}")

    if kind == "security_requirement_added":
        op_old = find_operation(old, finding["op_key"])
        op_new = find_operation(new, finding["op_key"])
        if op_old is None or op_new is None:
            return UNDECIDABLE, "operation not found on one side"

        def alternatives(op):
            return [frozenset(req) for req in (op.get("security") or [])
                    if isinstance(req, dict)]

        # Security is a list of ALTERNATIVES. Comparing flattened scheme names
        # confirmed a finding that was wrong: Twilio added `access_token_bearer`
        # ALONGSIDE `accountSid_authToken`, so every existing caller kept
        # working. This checker shared the engine's mistake and so agreed with
        # it, which is the failure a separate checker exists to prevent.
        before, after = alternatives(op_old), alternatives(op_new)
        if not before:
            if after:
                return CONFIRMED, "auth now required where there was none"
            return REFUTED, "no security on either side"
        stranded = [alt for alt in before
                    if not any(candidate <= alt for candidate in after)]
        if stranded:
            return CONFIRMED, ("callers using "
                               + " OR ".join("+".join(sorted(a)) for a in stranded)
                               + " can no longer authenticate")
        return REFUTED, (f"every old alternative still satisfiable: "
                         f"{[sorted(a) for a in before]} -> "
                         f"{[sorted(a) for a in after]}")

    def _body_schema(doc, op_key, where, status=""):
        op = find_operation(doc, op_key)
        if not isinstance(op, dict):
            return None
        if where == "request":
            node = op.get("requestBody") or {}
        else:
            responses = op.get("responses") or {}
            # The status the FINDING names, when it names one. Resolving a 4XX
            # body against the 200 body is not a measurement of anything, and
            # it decided this class for months because the engine knew the
            # status and recorded it only in the prose.
            node = responses.get(status) if status else None
            if not node:
                node = responses.get("200") or responses.get("201") or {}
            if not node:
                for candidate, body in responses.items():
                    if str(candidate).startswith("2"):
                        node = body
                        break
        # A response object may itself be a `$ref`, and it points into
        # `components/responses`, not `components/schemas`. Taking only the
        # basename and looking it up among the schemas resolved nothing, so
        # every operation Cloudflare writes that way -- `rulesets_RulesetOrDryRun`
        # and its siblings -- had no body on either side and went UNDECIDABLE.
        if "$ref" in (node or {}):
            node = pointer(doc, str(node["$ref"])) or {}
        content = (node or {}).get("content") or {}
        for mime in ("application/json", "application/x-www-form-urlencoded"):
            if mime in content:
                return (content[mime] or {}).get("schema")
        for body in content.values():
            return (body or {}).get("schema")
        return (node or {}).get("schema")

    def _reachable_names(doc, node, depth=0, seen=None):
        """Every property NAME under `node`, resolving refs and composition.

        Written here, against the raw document, deliberately not sharing the
        engine's resolver. A checker that reuses the engine's assumptions
        agrees with the engine's mistakes -- which is exactly how the security
        OR-of-AND bug survived a 86/86 "independent" measurement.
        """
        seen = set() if seen is None else seen
        names = set()
        if depth > 8 or not isinstance(node, dict):
            return names
        ref = node.get("$ref")
        if isinstance(ref, str):
            name = ref.rsplit("/", 1)[-1]
            if name in seen:
                return names
            return _reachable_names(doc, schemas_of(doc).get(name) or {},
                                    depth + 1, seen | {name})
        for keyword in ("allOf", "anyOf", "oneOf"):
            for arm in node.get(keyword) or []:
                names |= _reachable_names(doc, arm, depth + 1, seen)
        for prop_name, child in (node.get("properties") or {}).items():
            names.add(prop_name)
            names |= _reachable_names(doc, child, depth + 1, seen)
        items = node.get("items")
        if items is not None:
            names |= _reachable_names(doc, items, depth + 1, seen)
        extra = node.get("additionalProperties")
        if isinstance(extra, dict):
            names |= _reachable_names(doc, extra, depth + 1, seen)
        return names

    def _operation_names(doc, op_key):
        """Field names a caller can see on this operation, either direction."""
        names = set()
        for where in ("request", "response"):
            names |= _reachable_names(doc, _body_schema(doc, op_key, where) or {})
        return names

    def _is_relocation(field_name, ops):
        """Did the field merely move between schemas of the same operation?

        The schema-level question ("is it still in this schema?") is not the
        consumer's question ("can I still send or receive it here?"). OpenAI
        removed `ResponseProperties.reasoning` while `POST /responses` kept
        accepting `reasoning` the whole time.
        """
        seen_anywhere = False
        for op_key in (ops or [])[:40]:
            was = _operation_names(old, op_key)
            if field_name not in was:
                continue
            seen_anywhere = True
            if field_name not in _operation_names(new, op_key):
                return False
        return seen_anywhere

    def effective_enum(node, doc, depth=0):
        """Enum values a consumer sees, through refs and nullable unions."""
        if not isinstance(node, dict) or depth > 4:
            return None
        if isinstance(node.get("enum"), list):
            return tuple(sorted(map(str, node["enum"])))
        ref = node.get("$ref")
        if isinstance(ref, str):
            return effective_enum(schemas_of(doc).get(ref.rsplit("/", 1)[-1]),
                                  doc, depth + 1)
        for key in ("allOf", "oneOf", "anyOf"):
            arms = node.get(key)
            if not isinstance(arms, list):
                continue
            found = [effective_enum(a, doc, depth + 1) for a in arms]
            found = [f for f in found if f]
            if len(found) == 1:
                return found[0]
        # An array of enum values carries the enum on its items.
        if node.get("type") == "array" or "items" in node:
            return effective_enum(node.get("items"), doc, depth + 1)
        return None

    if kind == "response_status_removed":
        status = str(finding["subject"])
        op_old = find_operation(old, finding["op_key"])
        op_new = find_operation(new, finding["op_key"])
        if op_old is None or op_new is None:
            return UNDECIDABLE, "operation missing on one side"
        in_old = status in (op_old.get("responses") or {})
        in_new = status in (op_new.get("responses") or {})
        if in_old and not in_new:
            return CONFIRMED, f"response `{status}` present at old, absent at new"
        return REFUTED, f"response `{status}` old={in_old} new={in_new}"

    if kind in ("request_field_type_changed", "response_field_type_changed"):
        where = "request" if kind.startswith("request") else "response"
        old_body = _body_schema(old, finding["op_key"], where, finding.get("status", ""))
        new_body = _body_schema(new, finding["op_key"], where, finding.get("status", ""))
        if old_body is None or new_body is None:
            return UNDECIDABLE, f"no {where} body on one side"
        parts = [p for p in root.replace("[]", ".[].").split(".") if p]
        found_old, node_old = walk_properties(old_body, parts, old)
        found_new, node_new = walk_properties(new_body, parts, new)
        if not (found_old and found_new):
            # `root_cause` flattens schema names and wire segments into one
            # dotted string, so its head is often a SCHEMA that no property
            # walk can find. The SUBJECT keeps the brackets the engine wrote;
            # read those instead of guessing where a name ends. A dotted-string
            # heuristic stood here too and was removed rather than kept beside
            # this: two mechanisms answering one question mask each other's
            # mutations, and a suppressor nothing can falsify is not a
            # suppressor.
            tokens = subject_tokens(finding.get("subject") or "")
            if tokens:
                found_old, node_old = walk_subject(old, old_body, tokens)
                found_new, node_new = walk_subject(new, new_body, tokens)
        if not (found_old and found_new):
            return UNDECIDABLE, f"field not resolvable (old={found_old}, new={found_new})"
        before, after = effective_shape(node_old, old), effective_shape(node_new, new)
        # The same guard the schema-side comparisons already carry, and this
        # branch was the one site without it. Two admissions of ignorance are
        # not evidence that two things are the same, and one admission set
        # against a resolved shape is not evidence that they differ.
        if not _informative(before) or not _informative(after):
            return UNDECIDABLE, f"shape not resolvable ({before} -> {after})"
        if before != after:
            return CONFIRMED, f"shape {before} -> {after}"
        return REFUTED, f"same effective shape {before}"

    if kind == "endpoint_deprecated":
        op_old = find_operation(old, finding["op_key"])
        op_new = find_operation(new, finding["op_key"])
        if op_new is None:
            return UNDECIDABLE, "operation absent from the new spec"
        was = bool((op_old or {}).get("deprecated"))
        now = bool(op_new.get("deprecated"))
        if now and not was:
            return CONFIRMED, "deprecated flag newly set"
        return REFUTED, f"deprecated old={was} new={now}"

    if kind in ("schema_enum_value_added", "schema_enum_value_removed",
                "response_enum_value_added", "response_enum_value_removed",
                "request_enum_value_removed", "schema_field_now_nullable"):
        parts = root.split(".")
        available = schemas_of(old) | schemas_of(new)
        schema_name = None
        field_name = ""
        for cut in range(len(parts) - 1, 0, -1):
            if ".".join(parts[:cut]) in available:
                schema_name = ".".join(parts[:cut])
                # `field[]` names the array, not a property called "field[]".
                field_name = ".".join(parts[cut:]).replace("[]", "")
                break

        def prop(doc):
            node = schemas_of(doc).get(schema_name)
            if not isinstance(node, dict):
                return None
            props = dict(node.get("properties") or {})
            for arm in node.get("allOf") or []:
                target = schemas_of(doc).get(str(arm.get("$ref", "")).rsplit("/", 1)[-1]) \
                    if "$ref" in arm else arm
                if isinstance(target, dict):
                    props.update(target.get("properties") or {})
            return props.get(field_name)

        if schema_name is None:
            # A QUERY or PATH parameter's enum lives in `parameters`, not in a
            # schema, so `root` is a bare parameter name and every one of these
            # was UNDECIDABLE -- including the injected control that
            # `vendor_control.py` reports as `found+undecidable` on twelve
            # vendors: a break we KNOW is real that nothing could confirm.
            #
            # Asked the caller's way: can a request that was legal under OLD
            # still be sent under NEW? Two refutations fall out of that and
            # neither is available to the engine's question. Widening to an
            # unconstrained parameter is the important one -- dropping the
            # `enum` keyword altogether makes every value legal, so "no longer
            # accepts X" is false.
            if kind == "schema_field_now_nullable":
                return UNDECIDABLE, f"root `{root}` names no known schema"
            name = str(finding.get("subject") or root)
            op_key = finding.get("op_key") or ""
            was_param = operation_params(old, op_key).get(name)
            now_param = operation_params(new, op_key).get(name)
            if was_param is not None and now_param is not None:
                before = effective_enum(param_schema(was_param), old)
                after = effective_enum(param_schema(now_param), new)
                if before is None:
                    return UNDECIDABLE, (
                        f"parameter `{name}` had no resolvable enum in the "
                        f"old spec")
                if after is None:
                    return REFUTED, (
                        f"parameter `{name}` no longer constrains its value "
                        f"at all — the enum keyword is gone, so every value "
                        f"the old {len(before)}-value list allowed is still "
                        f"accepted")
                lost = sorted(set(before) - set(after))
                if kind.endswith("_added"):
                    gained = sorted(set(after) - set(before))
                    if gained:
                        return CONFIRMED, f"parameter `{name}` gained {gained}"
                    return REFUTED, f"parameter `{name}` gained no values"
                if lost:
                    return CONFIRMED, f"parameter `{name}` no longer accepts {lost}"
                return REFUTED, (f"parameter `{name}` lost no values "
                                 f"(old={len(before)}, new={len(after)})")
            # Not a parameter either. Stripe sends `ui_mode` in a form-encoded
            # request BODY, so fall through to the operation-body resolution
            # below rather than giving up here -- returning UNDECIDABLE at this
            # point is what kept those undecidable when the answer was one
            # walk away.
            before_prop = after_prop = None
        else:
            before_prop, after_prop = prop(old), prop(new)
        if kind == "schema_field_now_nullable":
            def nullable(node, doc):
                if not isinstance(node, dict):
                    return None
                if node.get("nullable") is True:
                    return True
                t = node.get("type")
                if isinstance(t, list):
                    return "null" in t
                ref = node.get("$ref")
                if isinstance(ref, str):
                    return nullable(schemas_of(doc).get(ref.rsplit("/", 1)[-1]), doc)
                return False
            was, now = nullable(before_prop, old), nullable(after_prop, new)
            if now and not was:
                return CONFIRMED, "became nullable"
            return REFUTED, f"nullable old={was} new={now}"

        before = effective_enum(before_prop, old)
        after = effective_enum(after_prop, new)
        if before is None or after is None:
            # Route-level findings sit inside an inline body rather than a
            # named schema, so resolve them through the operation instead.
            where = "request" if "request" in kind else "response"
            status = finding.get("status", "")
            old_body = _body_schema(old, finding["op_key"], where, status)
            new_body = _body_schema(new, finding["op_key"], where, status)
            path_parts = [p for p in root.replace("[]", ".[].").split(".") if p]
            if old_body is not None and new_body is not None:
                found_old, node_old = walk_properties(old_body, path_parts, old)
                found_new, node_new = walk_properties(new_body, path_parts, new)
                if found_old and found_new:
                    before = effective_enum(node_old, old)
                    after = effective_enum(node_new, new)
        if before is None or after is None:
            return UNDECIDABLE, f"no enum resolvable (old={before}, new={after})"
        gained = sorted(set(after) - set(before))
        lost = sorted(set(before) - set(after))
        if kind.endswith("_added"):
            if gained:
                return CONFIRMED, f"gained {gained}"
            return REFUTED, f"no values gained (old={len(before)}, new={len(after)})"
        if lost:
            return CONFIRMED, f"lost {lost}"
        return REFUTED, f"no values lost (old={len(before)}, new={len(after)})"

    if kind == "server_url_changed":
        # The document-level counterpart of `operation_server_changed`, and it
        # had no check at all. A base URL is the one part of a spec that is
        # PURELY a caller's concern, so the question is simply whether any
        # host a caller was pointed at still works.
        #
        # Server URLs are templates: `https://{region}.example.com` with a
        # `default` is the same address as the expanded literal, so both sides
        # are expanded with their own defaults before comparing. Without that
        # a vendor parameterising a URL it did not move would score as a
        # relocation -- the same notation-versus-contract mistake as a path
        # parameter rename.
        def bases(doc):
            block = doc.get("servers")
            if not isinstance(block, list) or not block:
                return None
            urls = set()
            for entry in block:
                if not isinstance(entry, dict) or not entry.get("url"):
                    continue
                url = str(entry["url"])
                for name, spec in (entry.get("variables") or {}).items():
                    if isinstance(spec, dict) and spec.get("default") is not None:
                        url = url.replace("{%s}" % name, str(spec["default"]))
                urls.add(url.rstrip("/"))
            return urls or None

        was, now = bases(old), bases(new)
        if was is None or now is None:
            return UNDECIDABLE, (
                f"no `servers` block on one side (old={was is not None}, "
                f"new={now is not None}) — the base URL is then whatever "
                f"served the document, which is not in the document")
        if was & now:
            return REFUTED, f"the base URLs still overlap: {sorted(was & now)}"
        return CONFIRMED, (f"every base URL changed: {sorted(was)} -> "
                           f"{sorted(now)}")

    if kind == "request_body_now_required":
        # No check existed for this kind either. The caller's question is
        # whether a request that carried NO body stops being accepted.
        op_old = find_operation(old, finding["op_key"])
        op_new = find_operation(new, finding["op_key"])
        if op_new is None:
            return UNDECIDABLE, "the operation is absent from the new spec"
        # `requestBody` is frequently a $ref into components/requestBodies, and
        # `required` lives on the TARGET. Reading the flag off the reference
        # object sees nothing and would refute every one of them.
        body_new = follow(new, op_new.get("requestBody"))
        now = bool(body_new.get("required")) if isinstance(body_new, dict) else False
        if not now:
            return REFUTED, "the new spec does not mark the request body required"
        if op_old is None:
            return UNDECIDABLE, "the operation is absent from the old spec"
        body_old = follow(old, op_old.get("requestBody"))
        if not isinstance(body_old, dict):
            return CONFIRMED, ("the old operation took no request body at all "
                               "and the new one requires it")
        was = bool(body_old.get("required"))
        if was:
            return REFUTED, "the request body was already required"
        return CONFIRMED, "request body optional at old, required at new"

    if kind == "operation_server_changed":
        # Resolved here from the raw document, with this checker's own reading
        # of OpenAPI's override chain, so it can disagree with the loader's.
        def effective(doc):
            method, _, path = finding["op_key"].partition(" ")
            item = (doc.get("paths") or {}).get(path)
            if not isinstance(item, dict):
                return None
            op = item.get(method.lower())
            for node in (op if isinstance(op, dict) else {}, item, doc):
                block = node.get("servers") if isinstance(node, dict) else None
                if isinstance(block, list) and block:
                    return {str(e["url"]) for e in block
                            if isinstance(e, dict) and e.get("url")}
            return set()

        was, now = effective(old), effective(new)
        if was is None or now is None:
            return UNDECIDABLE, "the operation is missing from one document"
        if not was or not now:
            return UNDECIDABLE, "no servers declared on one side"
        if was & now:
            return REFUTED, f"the host sets still overlap: {sorted(was & now)}"
        return CONFIRMED, f"{sorted(was)} -> {sorted(now)}"

    if kind == "schema_removed":
        return check_schema_removed(finding, old, new)

    if kind in ("schema_field_removed", "schema_field_type_changed",
                "schema_field_now_required", "schema_field_added_required",
                "schema_enum_value_removed", "schema_enum_value_added",
                "schema_field_now_nullable"):
        # Twilio names schemas with dots in them (`conversations.v2.address`),
        # so the first segment is not the schema. Take the LONGEST prefix that
        # is actually a schema name.
        available = schemas_of(old) | schemas_of(new)
        parts = root.split(".")
        schema_name = None
        for cut in range(len(parts) - 1, 0, -1):
            candidate = ".".join(parts[:cut])
            if candidate in available:
                schema_name = candidate
                field_name = ".".join(parts[cut:])
                break
        if schema_name is None:
            return UNDECIDABLE, f"root `{root}` names no known schema"
        old_schema = schemas_of(old).get(schema_name)
        new_schema = schemas_of(new).get(schema_name)
        if old_schema is None:
            return REFUTED, f"schema `{schema_name}` absent from the old spec"

        def props(node, doc):
            if node is None:
                return {}, set()
            merged = dict(node.get("properties") or {})
            required = set(node.get("required") or [])
            for arm in node.get("allOf") or []:
                target = schemas_of(doc).get(str(arm.get("$ref", "")).rsplit("/", 1)[-1]) \
                    if "$ref" in arm else arm
                if isinstance(target, dict):
                    sub, sub_req = props(target, doc)
                    merged.update(sub)
                    required |= sub_req
            return merged, required

        old_props, old_req = props(old_schema, old)
        new_props, new_req = props(new_schema, new)

        if kind == "schema_field_removed":
            if field_name in old_props and field_name not in new_props:
                leaf = field_name.split(".")[-1].replace("[]", "")
                if _is_relocation(leaf, finding.get("affected_ops")):
                    return REFUTED, (
                        f"`{schema_name}.{field_name}` left the schema but every "
                        f"affected operation still exposes `{leaf}` — a move "
                        f"between schemas, which breaks no caller")
                return CONFIRMED, f"`{schema_name}.{field_name}` present at old, absent at new"
            return REFUTED, (f"`{schema_name}.{field_name}` "
                             f"old={field_name in old_props} new={field_name in new_props}")
        if kind in ("schema_field_now_required", "schema_field_added_required"):
            if field_name in new_req and field_name not in old_req:
                return CONFIRMED, f"`{field_name}` newly required"
            return REFUTED, (f"`{field_name}` required "
                             f"old={field_name in old_req} new={field_name in new_req}")
        if kind == "schema_field_type_changed":
            o, n = old_props.get(field_name), new_props.get(field_name)
            if o is None or n is None:
                return REFUTED, "field missing on one side"
            # "The definition differs" is too weak: a description edit or a
            # notation change satisfies it. Ask the consumer's question -- does
            # the shape they receive or send actually differ?
            before, after = effective_shape(o, old), effective_shape(n, new)
            if not _informative(before) or not _informative(after):
                return UNDECIDABLE, (
                    f"the shape is unresolvable on one side "
                    f"(old={before}, new={after}) — this checker cannot see it")
            if before != after:
                return CONFIRMED, f"shape {before} -> {after}"
            return REFUTED, f"same effective shape {before}"
        return UNDECIDABLE, f"no independent check for `{kind}`"

    if kind in ("param_removed", "param_added_required", "param_now_required",
                "param_type_changed", "param_deprecated"):
        # Parameters live in `parameters`, not the request body, and the
        # existing body-shaped check below cannot decide them. Written here
        # against the raw document rather than importing anything from the
        # engine, because the engine agreeing with its own checker is how the
        # security defect and the schema-relocation defect both survived.
        name = finding.get("subject") or root

        def _params(doc, op_key):
            method, _, path = op_key.partition(" ")
            item = (doc.get("paths") or {}).get(path) or {}
            op = item.get(method.lower()) or {}
            merged = {}
            for entry in list(item.get("parameters") or []) + list(op.get("parameters") or []):
                if isinstance(entry, dict) and "$ref" in entry:
                    ref = str(entry["$ref"]).rsplit("/", 1)[-1]
                    entry = ((doc.get("components") or {}).get("parameters")
                             or {}).get(ref) or {}
                if isinstance(entry, dict) and entry.get("name"):
                    merged[entry["name"]] = entry
            return merged

        old_params = _params(old, finding["op_key"])
        new_params = _params(new, finding["op_key"])
        if not old_params and not new_params:
            return UNDECIDABLE, f"no parameters resolvable on `{finding['op_key']}`"
        entry = new_params.get(name) or old_params.get(name) or {}
        # A path parameter is POSITIONAL: its name is substituted into the URL
        # and never sent, so nothing a caller wrote depends on its NAME.
        #
        # That is a claim about the name and nothing else. The VALUE very much
        # reaches the wire, so a type change on a path parameter has to be
        # decided on its merits -- applying the positional rule to
        # `param_type_changed` refuted six real findings on a premise that had
        # nothing to do with them. Over-refuting is the same failure as
        # over-confirming: a checker that answers a question it was not asked.
        if entry.get("in") == "path" and kind != "param_type_changed":
            return REFUTED, (
                f"`{name}` is a PATH parameter — positional in the URL and "
                f"never sent by name, so no caller can depend on its name")
        if kind == "param_removed":
            if name in old_params and name not in new_params:
                return CONFIRMED, f"`{name}` present at old, absent at new"
            return REFUTED, (f"`{name}` old={name in old_params} "
                             f"new={name in new_params}")
        if kind in ("param_added_required", "param_now_required"):
            was = bool((old_params.get(name) or {}).get("required"))
            now = bool((new_params.get(name) or {}).get("required"))
            if now and not was:
                return CONFIRMED, f"`{name}` newly required"
            return REFUTED, f"`{name}` required old={was} new={now}"
        if kind == "param_type_changed":
            was = (old_params.get(name) or {}).get("schema")
            now = (new_params.get(name) or {}).get("schema")
            if was is None or now is None:
                return UNDECIDABLE, f"`{name}` has no schema on one side"
            before = effective_shape(was, old)
            after = effective_shape(now, new)
            if not _informative(before) or not _informative(after):
                return UNDECIDABLE, (
                    f"the shape is unresolvable on one side "
                    f"(old={before}, new={after}) — this checker cannot see it")
            if before == after:
                return REFUTED, f"same effective shape {before}"
            return CONFIRMED, f"{before} -> {after}"
        return UNDECIDABLE, f"no independent check for `{kind}`"

    if kind in ("request_field_added_required", "request_field_now_required"):
        # Asked as a VALIDATOR would: does some body that validated under OLD
        # get rejected under NEW? See `check_now_required`.
        return check_now_required(
            finding, old, new,
            _body_schema(old, finding["op_key"], "request"),
            _body_schema(new, finding["op_key"], "request"))

    if kind == "response_field_removed":
        # Ask what a CALLER loses, reading the subject's brackets rather than
        # re-splitting the dotted key. Everything this needs is in the raw
        # document; the fall-throughs below stay for subjects this cannot parse.
        tokens = subject_tokens(finding.get("subject") or "")
        status = finding.get("status", "")
        old_body = _body_schema(old, finding["op_key"], "response", status)
        new_body = _body_schema(new, finding["op_key"], "response", status)
        if tokens and old_body is not None and new_body is not None:
            last_kind, last_value = tokens[-1]
            stem = tokens[:-1]
            reached_old, parent_old = walk_subject(old, old_body, stem)
            reached_new, parent_new = walk_subject(new, new_body, stem)
            if reached_old and reached_new:
                new_alts = payload_alternatives(new, parent_new)
                if any(unconstrained(new, alt) for alt in new_alts):
                    return UNDECIDABLE, ("the new schema at that position "
                                         "declares no properties, so nothing in "
                                         "the document says whether the field "
                                         "still arrives")
                if last_kind == "prop":
                    was, _ = guaranteed_property(old, parent_old, last_value)
                    now, _ = guaranteed_property(new, parent_new, last_value)
                    if was and not now:
                        return CONFIRMED, (f"`{last_value}` was promised by every "
                                           f"alternative at old, and is not at new")
                    if was and now:
                        return REFUTED, (f"`{last_value}` is still promised by every "
                                         f"alternative the new response can return")
                elif last_kind == "item":
                    def elements(doc, parent):
                        out = []
                        for alt in payload_alternatives(doc, parent):
                            if isinstance(alt, dict) and alt.get("items") is not None:
                                out.extend(payload_alternatives(doc, alt["items"]))
                        return out
                    was_items = elements(old, parent_old)
                    now_items = elements(new, parent_new)
                    if was_items and not now_items:
                        return CONFIRMED, "the array no longer declares an element type"
                    if was_items:
                        lost = [i for i in was_items
                                if not still_presented(new, now_items, shape_of(old, i))]
                        if lost:
                            return CONFIRMED, (f"the array's elements no longer "
                                               f"present {shape_of(old, lost[0])[0]}"
                                               f"{sorted(shape_of(old, lost[0])[1])[:6]}")
                        return REFUTED, "the array still carries the same element type"
                else:
                    # A schema marker. It names either one arm of a union at
                    # this position, or -- when nothing at this position is a
                    # union with that name -- the body itself, which is not a
                    # field at all. A marker at index 0 can be either, so ask
                    # the document rather than the index.
                    arm = pick_arm(old, parent_old, last_value)
                    old_alts = ([arm] if arm is not None
                                else payload_alternatives(old, parent_old))
                    if not old_alts:
                        return REFUTED, (f"the `{last_value}` alternative carried no "
                                         f"payload — the response merely stopped "
                                         f"being nullable there")
                    lost = [a for a in old_alts
                            if not still_presented(new, payload_alternatives(
                                new, parent_new), shape_of(old, a))]
                    if lost:
                        return CONFIRMED, (f"no alternative the new response can "
                                           f"return still delivers "
                                           f"{sorted(shape_of(old, lost[0])[1])[:6]}")
                    return REFUTED, (f"the shape `{last_value}` denoted is still "
                                     f"presented at that position — a union that "
                                     f"collapsed, a body that gained an `allOf` "
                                     f"wrapper, or a schema renamed, and none of "
                                     f"the three is on the wire")
        # Fall through: unparsed subject, or a body this could not resolve.

    if kind in ("response_field_removed", "request_field_removed"):
        where = "response" if kind.startswith("response") else "request"
        old_schema = _body_schema(old, finding["op_key"], where, finding.get("status", ""))
        new_schema = _body_schema(new, finding["op_key"], where, finding.get("status", ""))
        if old_schema is not None and new_schema is not None:
            parts = [p for p in root.replace("[]", ".[].").split(".") if p]
            in_old, _ = walk_properties(old_schema, parts, old)
            in_new, _ = walk_properties(new_schema, parts, new)
            if not (in_old or in_new) and parts:
                # `collapse()` rewrites root_cause to a SCHEMA-qualified path:
                # `<secrets-store_store_response>.result.id` becomes
                # `secrets-store_store_response.result.id`. The head is a
                # schema NAME, never a property, so walking it through the
                # operation body finds nothing on either side -- and the
                # fall-through then answers a DOCUMENT-scoped question ("is
                # that schema still defined and does it still hold the
                # field?"), which says "present in both" precisely when the
                # vendor changed WHICH SCHEMA THE OPERATION RETURNS. Same
                # schema-name defect as `schema_removed`, in a fallback path.
                if parts[0] in (schemas_of(old) | schemas_of(new)) and parts[1:]:
                    in_old, _ = walk_properties(old_schema, parts[1:], old)
                    in_new, _ = walk_properties(new_schema, parts[1:], new)
            if in_old and not in_new:
                return CONFIRMED, f"`{root}` present at old, absent at new"
            if in_old or in_new:
                return REFUTED, f"`{root}` old={in_old} new={in_new}"
        # Fall through to the schema-rooted check below.
        resolved = resolve_root(old, root)
        if resolved is None:
            return UNDECIDABLE, f"root `{root}` is not a named schema"
        schema, parts = resolved
        found_old, _ = walk_properties(schema, parts, old)
        new_resolved = resolve_root(new, root)
        if new_resolved is None:
            if found_old:
                return CONFIRMED, "whole schema removed from the new spec"
            return REFUTED, "field absent from old too"
        found_new, _ = walk_properties(new_resolved[0], new_resolved[1], new)
        if found_old and not found_new:
            return CONFIRMED, "present at old, absent at new"
        return REFUTED, f"old={found_old} new={found_new}"

    # NOTE: a second `request_field_added_required`/`request_field_now_required`
    # branch used to sit here, asking the schema-rooted version of the same
    # question. It was unreachable -- the branch above returns on every path --
    # so it decided nothing and hid the fact that this class had exactly one
    # implementation. Removed rather than left as scenery.

    return UNDECIDABLE, f"no independent check implemented for `{kind}`"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", type=int, default=60)
    parser.add_argument("--seed", type=int, default=20260820)
    parser.add_argument("--severity", default="breaking")
    parser.add_argument("--findings", default=str(ROOT / "out" / "findings.json"),
                        help="findings.json to audit (default: the 5-vendor run)")
    parser.add_argument("--vendor", default="",
                        help="comma-separated vendor keys; default is all in the file")
    parser.add_argument("--by-vendor", action="store_true",
                        help="print precision per vendor. A vendor with no row "
                             "here is UNMEASURED, which is not a pass.")
    args = parser.parse_args()

    data = json.load(open(args.findings))
    if args.vendor:
        keep = {k.strip() for k in args.vendor.split(",") if k.strip()}
        data = [e for e in data if e["vendor"] in keep]
    population: List[Tuple[str, Dict[str, Any], Dict[str, str]]] = []
    for entry in data:
        for finding in entry["findings"]:
            if finding["severity"] == args.severity:
                population.append((entry["vendor"], finding, entry["window"]))

    rng = random.Random(args.seed)
    sample = rng.sample(population, min(args.sample, len(population)))
    print(f"Population: {len(population)} {args.severity} findings across "
          f"{len(data)} vendors")
    print(f"Random sample: {len(sample)} (seed {args.seed})\n")

    # A vendor may publish many spec files (Twilio publishes 36). Loading only
    # the first one made every finding from the other 35 look refuted, because
    # its schemas are "absent" from a file they were never in.
    import fnmatch
    trees: Dict[str, Tuple[str, str, List[str], List[str], Path]] = {}
    for entry in data:
        vendor = VENDORS[entry["vendor"]]
        repo_dir = CACHE / vendor.repo.replace("/", "_")
        w = entry["window"]
        trees[entry["vendor"]] = (w["old_ref"], w["new_ref"],
                                  tree(repo_dir, w["old_ref"]),
                                  tree(repo_dir, w["new_ref"]), repo_dir)

    spec_cache: Dict[Tuple[str, str, str], Dict] = {}

    def spec_for(vendor_key: str, finding: Dict[str, Any]):
        old_ref, new_ref, ot, nt, repo_dir = trees[vendor_key]
        vendor = VENDORS[vendor_key]
        wanted = finding.get("spec_file") or ""
        if not wanted:
            wanted = next((p for p in nt if fnmatch.fnmatch(p, vendor.spec_path)), "")
        loaded = []
        for ref, listing in ((old_ref, ot), (new_ref, nt)):
            key = (vendor_key, ref, wanted)
            if key not in spec_cache:
                spec_cache[key] = (load_spec(repo_dir, ref, wanted)
                                   if wanted in listing else {})
            loaded.append(spec_cache[key])
        return loaded[0], loaded[1], ot, nt

    tally = collections.Counter()
    by_kind: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    by_vendor: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    refuted: List[str] = []

    for vendor_key, finding, _ in sample:
        try:
            old, new, ot, nt = spec_for(vendor_key, finding)
            verdict, why = check(finding, old, new, ot, nt)
        except Exception as exc:  # noqa: BLE001
            verdict, why = UNDECIDABLE, f"{type(exc).__name__}: {exc}"
        tally[verdict] += 1
        by_kind[finding["kind"]][verdict] += 1
        by_vendor[vendor_key][verdict] += 1
        if verdict == REFUTED:
            refuted.append(f"  {vendor_key:8s} {finding['kind']:30s} "
                           f"{(finding.get('root_cause') or finding['subject'])[:40]:42s} {why}")

    decidable = tally[CONFIRMED] + tally[REFUTED]
    print(f"{'verdict':14s} {'count':>6s}")
    for verdict in (CONFIRMED, REFUTED, UNDECIDABLE):
        print(f"{verdict:14s} {tally[verdict]:6d}")
    print()
    if decidable:
        precision = tally[CONFIRMED] / decidable
        print(f"PRECISION on independently decidable findings: "
              f"{tally[CONFIRMED]}/{decidable} = {precision:.1%}")
    else:
        print("No findings were independently decidable — the measurement failed, "
              "which is a statement about this checker, not about the engine.")
    print(f"({tally[UNDECIDABLE]} undecidable, excluded from the ratio rather "
          f"than counted as passes)\n")

    print("by finding kind:")
    for kind, counts in sorted(by_kind.items(), key=lambda kv: -sum(kv[1].values())):
        d = counts[CONFIRMED] + counts[REFUTED]
        rate = f"{counts[CONFIRMED]}/{d}" if d else "0/0"
        print(f"  {kind:34s} confirmed={counts[CONFIRMED]:3d} "
              f"refuted={counts[REFUTED]:3d} undecidable={counts[UNDECIDABLE]:3d}  ({rate})")

    if args.by_vendor:
        print("\nby vendor — a vendor absent from this table is UNMEASURED, "
              "which is not a pass:")
        in_file = {e["vendor"] for e in data}
        for key in sorted(in_file):
            counts = by_vendor.get(key)
            if not counts:
                print(f"  {key:18s} NOT SAMPLED — unmeasured")
                continue
            d = counts[CONFIRMED] + counts[REFUTED]
            rate = f"{counts[CONFIRMED]}/{d} = {counts[CONFIRMED]/d:.1%}" if d \
                else "0/0 — nothing decidable, the measurement failed here"
            print(f"  {key:18s} {rate:26s} "
                  f"(undecidable {counts[UNDECIDABLE]})")

    if refuted:
        print(f"\nREFUTED findings ({len(refuted)}) — each is a real defect:")
        for line in refuted:
            print(line)
    return 1 if tally[REFUTED] else 0


if __name__ == "__main__":
    raise SystemExit(main())
