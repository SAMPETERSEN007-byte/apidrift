"""Prove the engine can SEE a break in each vendor's own spec dialect.

Seven of twenty-two vendors produce zero breaking findings in the window. That
is either "this vendor broke nothing" or "the instrument is dead against this
vendor's dialect", and a count cannot tell you which. Every negative result
needs a control that fires.

So: take each vendor's REAL spec at HEAD, inject a known break of a known kind,
and require the engine to find it AND the independent checker to confirm it. A
vendor is covered when its controls fire, not when its count is zero.

Injection is done on the raw document, chosen from what that vendor's spec
actually contains -- specs differ enough that a fixed target would simply be
absent from most of them. Where a kind cannot be injected the row says so;
"not applicable" is printed, never skipped silently, because a control that
could not run is not a control that passed.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from apidrift.diff import BREAKING, diff_specs            # noqa: E402
from apidrift.loader import load_spec                     # noqa: E402
from apidrift.vendors import VENDORS, get                 # noqa: E402
import measure_precision as MP                            # noqa: E402

HTTP = ("get", "post", "put", "patch", "delete")

# Both sides of a control are serialised through this, so any type YAML carries
# and JSON does not is flattened the SAME way on both sides and cancels out.
CONTROL_NAME = "control.json"


def _serialise(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, default=str).encode("utf-8")


def _sh(args: List[str], cwd: Path) -> bytes:
    proc = subprocess.run(args, cwd=str(cwd), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[:200])
    return proc.stdout


def _load_raw(vendor, cache: Path) -> Tuple[str, bytes, Dict[str, Any]]:
    """The vendor's largest matching spec file at HEAD, raw and parsed."""
    import fnmatch
    repo = cache / vendor.repo.replace("/", "_")
    ref = _sh(["git", "rev-parse", "HEAD"], repo).decode().strip()
    tree = _sh(["git", "ls-tree", "-r", "--name-only", ref], repo).decode().splitlines()
    matches = [p for p in tree if fnmatch.fnmatch(p, vendor.spec_path)]
    if not matches:
        raise RuntimeError(f"no file matched '{vendor.spec_path}'")
    best, best_raw, best_doc = "", b"", {}
    for path in matches:
        raw = _sh(["git", "show", f"{ref}:{path}"], repo)
        if len(raw) <= len(best_raw):
            continue
        try:
            doc = json.loads(raw) if path.endswith(".json") else __import__(
                "yaml").safe_load(raw)
        except Exception:
            continue
        if isinstance(doc, dict) and doc.get("paths"):
            best, best_raw, best_doc = path, raw, doc
    if not best:
        raise RuntimeError("no matching file parsed into a spec with paths")
    return best, best_raw, best_doc


def _operations(doc) -> List[Tuple[str, str, dict]]:
    out = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in HTTP:
            node = item.get(method)
            if isinstance(node, dict):
                out.append((path, method, node))
    return out


def _resolve(doc, node, budget=8):
    while isinstance(node, dict) and "$ref" in node and budget > 0:
        target = str(node["$ref"])
        if not target.startswith("#/"):
            return None
        cur: Any = doc
        for part in target[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            try:
                cur = cur[part]
            except (KeyError, IndexError, TypeError):
                return None
        node, budget = cur, budget - 1
    return node


def _body_of(doc, op, where: str):
    if where == "request":
        node = _resolve(doc, op.get("requestBody"))
    else:
        responses = op.get("responses") or {}
        node = None
        for status in sorted(responses):
            if str(status).startswith("2"):
                node = _resolve(doc, responses[status])
                break
    if not isinstance(node, dict):
        return None
    content = node.get("content") or {}
    for mime in ("application/json",):
        if mime in content:
            return (content[mime] or {}).get("schema")
    for body in content.values():
        return (body or {}).get("schema")
    return node.get("schema")


# --------------------------------------------------------------------------
# injections -- each returns (mutated_doc, predicate) or None when the vendor's
# spec has no suitable target.
# --------------------------------------------------------------------------

def inject_endpoint_removed(doc) -> Optional[Tuple[dict, str, Callable]]:
    for path, method, _ in _operations(doc):
        if len((doc["paths"][path] or {})) >= 1:
            out = copy.deepcopy(doc)
            del out["paths"][path][method]
            if not any(m in out["paths"][path] for m in HTTP):
                del out["paths"][path]
            want = f"{method.upper()} {path}"
            return out, want, lambda f, w=want: (
                f.kind in ("endpoint_removed", "endpoint_moved")
                and f.op_key == w)
    return None


def inject_request_field_added_required(doc) -> Optional[Tuple[dict, str, Callable]]:
    for path, method, op in _operations(doc):
        schema = _body_of(doc, op, "request")
        resolved = _resolve(doc, schema)
        if not isinstance(resolved, dict) or resolved.get("type") != "object":
            continue
        if not isinstance(resolved.get("properties"), dict):
            continue
        out = copy.deepcopy(doc)
        target = _resolve(out, _body_of(out, out["paths"][path][method], "request"))
        target["properties"]["apidrift_control_field"] = {"type": "string"}
        target["required"] = list(target.get("required") or []) + [
            "apidrift_control_field"]
        return out, "apidrift_control_field", lambda f: (
            "apidrift_control_field" in f.subject
            and f.kind in ("request_field_added_required",
                           "schema_field_added_required"))
    return None


def inject_response_field_removed(doc) -> Optional[Tuple[dict, str, Callable]]:
    for path, method, op in _operations(doc):
        schema = _body_of(doc, op, "response")
        resolved = _resolve(doc, schema)
        if not isinstance(resolved, dict):
            continue
        props = resolved.get("properties")
        if not isinstance(props, dict) or len(props) < 2:
            continue
        victim = sorted(props)[0]
        out = copy.deepcopy(doc)
        target = _resolve(out, _body_of(out, out["paths"][path][method], "response"))
        del target["properties"][victim]
        if victim in (target.get("required") or []):
            target["required"] = [r for r in target["required"] if r != victim]
        return out, victim, lambda f, v=victim: (
            v == f.subject.split(".")[-1].split("<")[0]
            and f.kind in ("response_field_removed", "schema_field_removed"))
    return None


def inject_param_type_changed(doc) -> Optional[Tuple[dict, str, Callable]]:
    for path, method, op in _operations(doc):
        for index, param in enumerate(op.get("parameters") or []):
            entry = _resolve(doc, param)
            if not isinstance(entry, dict) or entry.get("in") != "query":
                continue
            schema = entry.get("schema")
            if not isinstance(schema, dict) or schema.get("type") != "string":
                continue
            if schema.get("enum"):
                continue
            out = copy.deepcopy(doc)
            live = _resolve(out, (out["paths"][path][method]["parameters"])[index])
            live["schema"] = {"type": "integer"}
            name = entry.get("name")
            return out, str(name), lambda f, n=name: (
                f.kind == "param_type_changed" and f.subject == n)
    return None


def inject_request_enum_value_removed(doc) -> Optional[Tuple[dict, str, Callable]]:
    for path, method, op in _operations(doc):
        for index, param in enumerate(op.get("parameters") or []):
            entry = _resolve(doc, param)
            if not isinstance(entry, dict):
                continue
            schema = entry.get("schema")
            if not isinstance(schema, dict):
                continue
            values = schema.get("enum")
            if not isinstance(values, list) or len(values) < 2:
                continue
            out = copy.deepcopy(doc)
            live = _resolve(out, (out["paths"][path][method]["parameters"])[index])
            live["schema"] = dict(live["schema"])
            live["schema"]["enum"] = list(values)[:-1]
            name = entry.get("name")
            return out, f"{name} -{values[-1]!r}", lambda f, n=name: (
                f.subject == n and "enum" in f.kind)
    return None


CONTROLS: Tuple[Tuple[str, Callable], ...] = (
    ("endpoint_removed", inject_endpoint_removed),
    ("response_field_removed", inject_response_field_removed),
    ("request_field_added_required", inject_request_field_added_required),
    ("param_type_changed", inject_param_type_changed),
    ("request_enum_value_removed", inject_request_enum_value_removed),
)


def run_vendor(key: str, cache: Path, check_the_checker: bool) -> Dict[str, Any]:
    vendor = get(key)
    row: Dict[str, Any] = {"vendor": key, "results": {}, "spec_file": "",
                           "error": ""}
    try:
        path, raw, doc = _load_raw(vendor, cache)
    except Exception as exc:                                  # noqa: BLE001
        row["error"] = f"{type(exc).__name__}: {exc}"[:120]
        return row
    row["spec_file"] = path
    # BOTH sides are built from the parsed document by the same serialiser.
    # YAML 1.1 auto-resolves an unquoted `2023-09-29` to a Python date, which
    # JSON cannot carry -- Cohere and Datadog errored on every control for
    # that reason alone. Loading the baseline from the original bytes and the
    # mutation from a round-trip would be worse than the error: the two sides
    # would disagree about every date in the document and manufacture findings.
    base = load_spec(_serialise(doc), CONTROL_NAME)
    meta = {"old_ref": "control", "new_ref": "control"}

    for name, inject in CONTROLS:
        made = inject(doc)
        if made is None:
            row["results"][name] = "n/a"
            continue
        mutated_doc, label, predicate = made
        try:
            mutated = load_spec(_serialise(mutated_doc), CONTROL_NAME)
            result = diff_specs(key, base, mutated, meta)
        except Exception as exc:                              # noqa: BLE001
            row["results"][name] = f"ERROR {type(exc).__name__}"
            continue
        hits = [f for f in result.findings
                if f.severity == BREAKING and predicate(f)]
        if not hits:
            row["results"][name] = "MISSED"
            continue
        if not check_the_checker:
            row["results"][name] = "found"
            continue
        verdict = MP.UNDECIDABLE
        for finding in hits:
            payload = finding.as_dict()
            try:
                verdict, _ = MP.check(payload, doc, mutated_doc, [], [])
            except Exception:                                 # noqa: BLE001
                verdict = MP.UNDECIDABLE
            if verdict == MP.CONFIRMED:
                break
        row["results"][name] = {"CONFIRMED": "found+confirmed",
                                "REFUTED": "found+REFUTED",
                                }.get(verdict, "found+undecidable")
    return row


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="vendor_control")
    parser.add_argument("--cache", default=str(ROOT / ".cache"))
    parser.add_argument("--vendors", default="all")
    parser.add_argument("--json", default=None)
    parser.add_argument("--no-checker", action="store_true",
                        help="only ask whether the ENGINE finds the injection")
    args = parser.parse_args(argv)

    keys = sorted(VENDORS) if args.vendors == "all" else [
        k.strip() for k in args.vendors.split(",") if k.strip()]
    names = [n for n, _ in CONTROLS]
    width = max(len(n) for n in names)
    print("Each cell: a KNOWN break injected into that vendor's real spec.\n"
          "found+confirmed = the engine saw it and the independent checker "
          "agreed.\nn/a = that vendor's spec has no target for this injection "
          "-- printed, never skipped.\n")
    header = f"{'vendor':17} " + " ".join(f"{n[:13]:>14}" for n in names)
    print(header)
    print("-" * len(header))
    rows = []
    for key in keys:
        row = run_vendor(key, Path(args.cache), not args.no_checker)
        rows.append(row)
        if row["error"]:
            print(f"{key:17} ERROR {row['error']}")
            continue
        cells = " ".join(f"{str(row['results'].get(n, '?'))[:14]:>14}"
                         for n in names)
        print(f"{key:17} {cells}", flush=True)

    total = sum(1 for r in rows for v in r["results"].values()
                if isinstance(v, str) and v.startswith("found"))
    missed = [(r["vendor"], n) for r in rows for n, v in r["results"].items()
              if v == "MISSED"]
    refuted = [(r["vendor"], n) for r in rows for n, v in r["results"].items()
               if v == "found+REFUTED"]
    na = sum(1 for r in rows for v in r["results"].values() if v == "n/a")
    errored = [r["vendor"] for r in rows if r["error"]]
    print(f"\n{total} controls fired, {len(missed)} MISSED, {len(refuted)} "
          f"found-but-refuted, {na} not applicable, {len(errored)} vendors errored")
    for vendor, name in missed:
        print(f"  MISSED   {vendor:17} {name}")
    for vendor, name in refuted:
        print(f"  REFUTED  {vendor:17} {name}")
    covered = [r["vendor"] for r in rows
               if any(isinstance(v, str) and v.startswith("found")
                      for v in r["results"].values())]
    print(f"\nvendors with at least one firing control: {len(covered)}/{len(rows)}")
    dead = [r["vendor"] for r in rows if r["vendor"] not in covered]
    if dead:
        print(f"NO CONTROL FIRED — the instrument is unproven here: {dead}")
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=1))
    return 1 if (missed or refuted or errored or dead) else 0


if __name__ == "__main__":
    raise SystemExit(main())
