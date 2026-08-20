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
        old_paths, new_paths = (old.get("paths") or {}), (new.get("paths") or {})
        if old_path in old_paths and old_path not in new_paths \
                and new_path in new_paths:
            return CONFIRMED, f"`{old_path}` -> `{new_path}`"
        return REFUTED, (f"old_path in old={old_path in old_paths} "
                         f"in new={old_path in new_paths}; "
                         f"new_path in new={new_path in new_paths}")

    if kind == "endpoint_removed":
        path = finding["path"]
        in_old = path in (old.get("paths") or {})
        in_new = path in (new.get("paths") or {})
        if in_old and not in_new:
            return CONFIRMED, "path present at old, absent at new"
        return REFUTED, f"path old={in_old} new={in_new}"

    if kind == "security_requirement_added":
        op_old = find_operation(old, finding["op_key"])
        op_new = find_operation(new, finding["op_key"])
        if op_old is None or op_new is None:
            return UNDECIDABLE, "operation not found on one side"
        names = lambda op: {k for req in (op.get("security") or [])
                            if isinstance(req, dict) for k in req}
        gained = names(op_new) - names(op_old)
        if gained:
            return CONFIRMED, f"gained {sorted(gained)}"
        return REFUTED, f"old={sorted(names(op_old))} new={sorted(names(op_new))}"

    def _body_schema(doc, op_key, where):
        op = find_operation(doc, op_key)
        if not isinstance(op, dict):
            return None
        if where == "request":
            node = op.get("requestBody") or {}
        else:
            responses = op.get("responses") or {}
            node = responses.get("200") or responses.get("201") or {}
            if not node:
                for status, body in responses.items():
                    if str(status).startswith("2"):
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
        old_body = _body_schema(old, finding["op_key"], where)
        new_body = _body_schema(new, finding["op_key"], where)
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
            old_body = _body_schema(old, finding["op_key"], where)
            new_body = _body_schema(new, finding["op_key"], where)
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

    if kind == "schema_removed":
        name = finding.get("root_cause") or finding["subject"]
        in_old = name in schemas_of(old)
        in_new = name in schemas_of(new)
        if in_old and not in_new:
            return CONFIRMED, f"schema `{name}` present at old, absent at new"
        return REFUTED, f"schema `{name}` old={in_old} new={in_new}"

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

    if kind in ("request_field_added_required", "request_field_now_required",
                "param_added_required", "param_now_required"):
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
        old_schema = _body_schema(old, finding["op_key"], where)
        new_schema = _body_schema(new, finding["op_key"], where)
        if old_schema is not None and new_schema is not None:
            parts = [p for p in root.replace("[]", ".[].").split(".") if p]
            in_old, _ = walk_properties(old_schema, parts, old)
            in_new, _ = walk_properties(new_schema, parts, new)
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
    args = parser.parse_args()

    data = json.load(open(ROOT / "out" / "findings.json"))
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
    refuted: List[str] = []

    for vendor_key, finding, _ in sample:
        try:
            old, new, ot, nt = spec_for(vendor_key, finding)
            verdict, why = check(finding, old, new, ot, nt)
        except Exception as exc:  # noqa: BLE001
            verdict, why = UNDECIDABLE, f"{type(exc).__name__}: {exc}"
        tally[verdict] += 1
        by_kind[finding["kind"]][verdict] += 1
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

    if refuted:
        print(f"\nREFUTED findings ({len(refuted)}) — each is a real defect:")
        for line in refuted:
            print(line)
    return 1 if tally[REFUTED] else 0


if __name__ == "__main__":
    raise SystemExit(main())
