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
            if json.dumps(o, sort_keys=True) != json.dumps(n, sort_keys=True):
                return CONFIRMED, "property definition differs"
            return REFUTED, "property definition is identical"
        return UNDECIDABLE, f"no independent check for `{kind}`"

    if kind in ("response_field_removed", "request_field_removed"):
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
