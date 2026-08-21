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
from typing import Any, Dict, List, Optional, Tuple

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


def effective_shape(prop: Any, doc: Dict[str, Any], depth: int = 0) -> Any:
    """What a consumer actually sees for this property.

    Written independently of the engine, and deliberately so: it answers the
    same question by resolving to a concrete shape rather than by comparing
    type labels. A single-arm `allOf` is transparent, and a reference resolves
    to the sorted field names of its target so that a rename is invisible.
    """
    if not isinstance(prop, dict) or depth > 3:
        return "opaque"
    arms = prop.get("allOf")
    if isinstance(arms, list) and len(arms) == 1 and "properties" not in prop:
        return effective_shape(arms[0], doc, depth + 1)
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
    return ("scalar", prop.get("type"), tuple(sorted(map(str, enum))) if enum else None)


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


def find_operation(doc: Dict[str, Any], op_key: str) -> Optional[Dict[str, Any]]:
    method, _, path = op_key.partition(" ")
    item = (doc.get("paths") or {}).get(path)
    if not isinstance(item, dict):
        return None
    return item.get(method.lower())



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
    root = finding.get("root_cause") or finding.get("subject") or ""

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
        if "$ref" in (node or {}):
            node = schemas_of(doc).get(str(node["$ref"]).rsplit("/", 1)[-1]) or {}
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
            return UNDECIDABLE, f"field not resolvable (old={found_old}, new={found_new})"
        before, after = effective_shape(node_old, old), effective_shape(node_new, new)
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
        for cut in range(len(parts) - 1, 0, -1):
            if ".".join(parts[:cut]) in available:
                schema_name = ".".join(parts[:cut])
                # `field[]` names the array, not a property called "field[]".
                field_name = ".".join(parts[cut:]).replace("[]", "")
                break
        if schema_name is None:
            return UNDECIDABLE, f"root `{root}` names no known schema"

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
            if before == after:
                return REFUTED, f"same effective shape {before}"
            return CONFIRMED, f"{before} -> {after}"
        return UNDECIDABLE, f"no independent check for `{kind}`"

    if kind in ("request_field_added_required", "request_field_now_required"):
        # Operation-level: the body is inline, so walk it directly.
        leaf = root.split(".")[-1].replace("[]", "")
        old_schema = _body_schema(old, finding["op_key"], "request")
        new_schema = _body_schema(new, finding["op_key"], "request")
        if new_schema is None:
            return UNDECIDABLE, "no request body found on the new side"

        def required_of(schema, doc, path_parts):
            if not path_parts:
                node = schema
            else:
                found, node = walk_properties(schema, path_parts[:-1], doc)
                if not found:
                    return None
            if isinstance(node, dict) and "$ref" in node:
                node = schemas_of(doc).get(str(node["$ref"]).rsplit("/", 1)[-1]) or {}
            return set((node or {}).get("required") or [])

        parts = [p for p in root.replace("[]", ".[].").split(".") if p]
        new_req = required_of(new_schema, new, parts)
        old_req = required_of(old_schema, old, parts) if old_schema is not None else set()
        if new_req is None:
            return UNDECIDABLE, "could not resolve the parent object"
        if leaf in new_req and leaf not in (old_req or set()):
            return CONFIRMED, f"`{leaf}` newly required in the request body"
        return REFUTED, (f"`{leaf}` required old={leaf in (old_req or set())} "
                         f"new={leaf in new_req}")

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

    if kind in ("request_field_added_required", "request_field_now_required"):
        resolved_new = resolve_root(new, root)
        if resolved_new is None or not resolved_new[1]:
            return UNDECIDABLE, f"root `{root}` is not a named schema with a field"
        schema_new, parts = resolved_new
        parent_new = walk_properties(schema_new, parts[:-1], new)[1] if len(parts) > 1 \
            else schema_new
        leaf = parts[-1]
        req_new = set((parent_new or {}).get("required") or [])
        resolved_old = resolve_root(old, root)
        if resolved_old is None:
            return UNDECIDABLE, "schema absent from the old spec"
        schema_old, parts_old = resolved_old
        parent_old = walk_properties(schema_old, parts_old[:-1], old)[1] \
            if len(parts_old) > 1 else schema_old
        req_old = set((parent_old or {}).get("required") or [])
        if leaf in req_new and leaf not in req_old:
            return CONFIRMED, f"`{leaf}` newly in required"
        return REFUTED, f"`{leaf}` required old={leaf in req_old} new={leaf in req_new}"

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
