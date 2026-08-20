"""Independently confirm sampled findings by re-reading the raw specs.

This deliberately does NOT use apidrift.diff: if the engine is wrong, a check
built on the engine would be wrong the same way.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"


def show(repo: str, ref: str, path: str) -> bytes:
    return subprocess.run(["git", "show", f"{ref}:{path}"], cwd=str(CACHE / repo),
                          stdout=subprocess.PIPE, check=True).stdout


def load(repo: str, ref: str, path: str):
    raw = show(repo, ref, path)
    return json.loads(raw) if path.endswith(".json") else yaml.safe_load(raw)


def tree_has(repo: str, ref: str, path: str) -> bool:
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", ref],
                         cwd=str(CACHE / repo), stdout=subprocess.PIPE, check=True)
    return path in out.stdout.decode().splitlines()


CHECKS = []


def check(name):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


@check("stripe: `iin` removed from the shared `card` schema")
def _stripe():
    repo, p = "stripe_openapi", "openapi/spec3.json"
    old = load(repo, "af2baf95dbff", p)["components"]["schemas"]["card"]["properties"]
    new = load(repo, "9077e369dfaf", p)["components"]["schemas"]["card"]["properties"]
    return ("iin" in old and "iin" not in new,
            f"old has iin={'iin' in old}, new has iin={'iin' in new}")


@check("openai: Response.service_tier enum widened (auto->…->fast/ultrafast)")
def _openai():
    repo, p = "openai_openai-openapi", "openapi.yaml"

    def tier_values(ref):
        doc = load(repo, ref, p)
        schemas = doc["components"]["schemas"]

        def find(node, name, depth=0):
            """Resolve `properties` through allOf and $ref, unlike a naive read."""
            if depth > 4 or not isinstance(node, dict):
                return None
            if name in (node.get("properties") or {}):
                return node["properties"][name]
            for arm in node.get("allOf") or []:
                target = (schemas.get(arm["$ref"].rsplit("/", 1)[-1], {})
                          if "$ref" in arm else arm)
                got = find(target, name, depth + 1)
                if got is not None:
                    return got
            return None

        node = find(schemas["Response"], "service_tier")
        if node is None:
            return None, None
        ref_name = node.get("$ref", "").rsplit("/", 1)[-1]
        target = schemas.get(ref_name, node)
        for arm in target.get("anyOf") or [target]:
            if arm.get("enum"):
                return ref_name, set(arm["enum"])
        return ref_name, None

    old_name, old_vals = tier_values("5162af98d314")
    new_name, new_vals = tier_values("b8d775d82e8c")
    if not old_vals or not new_vals:
        return (False, f"could not resolve enum (old={old_name}, new={new_name})")
    gained = sorted(new_vals - old_vals)
    return (bool(gained) and not (old_vals - new_vals),
            f"{old_name}{sorted(old_vals)} -> {new_name}{sorted(new_vals)}; "
            f"gained {gained}, lost {sorted(old_vals - new_vals) or 'nothing'}")


@check("twilio: the twilio_assistants_v1 spec file was deleted")
def _twilio():
    repo, p = "twilio_twilio-oai", "spec/json/twilio_assistants_v1.json"
    old_has = tree_has(repo, "7efd1f014b83", p)
    new_has = tree_has(repo, "b02705eb7dbf", p)
    return (old_has and not new_has, f"present at old={old_has}, at new={new_has}")


@check("discord: RecurrenceRule gained required fields")
def _discord():
    repo, p = "discord_discord-api-spec", "specs/openapi.json"
    old = load(repo, "ac55939ed657", p)["components"]["schemas"]
    new = load(repo, "1314ec6fee3b", p)["components"]["schemas"]
    key = next((k for k in new if k.startswith("RecurrenceRule")), None)
    if key is None:
        return (False, "no RecurrenceRule schema in the new spec")
    old_req = set(old.get(key, {}).get("required", []))
    new_req = set(new.get(key, {}).get("required", []))
    gained = new_req - old_req
    return (bool(gained), f"schema={key} required gained {sorted(gained) or 'nothing'}")


@check("plaid: an operation gained an oauth2 security requirement")
def _plaid():
    repo, p = "plaid_plaid-openapi", "2020-09-14.yml"
    old = load(repo, "f92f197d391a", p)["paths"]
    new = load(repo, "52b9a6f20f04", p)["paths"]

    def sec(paths):
        out = {}
        for path, item in paths.items():
            if not isinstance(item, dict):
                continue
            for method, op in item.items():
                if isinstance(op, dict) and "security" in op:
                    names = {k for req in op["security"] if isinstance(req, dict) for k in req}
                    out[f"{method.upper()} {path}"] = names
        return out

    o, n = sec(old), sec(new)
    gained = [k for k, v in n.items() if "oauth2" in v and "oauth2" not in o.get(k, set())]
    return (bool(gained), f"{len(gained)} ops gained oauth2, e.g. {gained[:2]}")


def main() -> int:
    print("Independent verification against raw specs (no diff engine involved)\n")
    failures = 0
    for name, fn in CHECKS:
        try:
            ok, evidence = fn()
        except Exception as exc:  # noqa: BLE001
            ok, evidence = False, f"{type(exc).__name__}: {exc}"
        print(f"  {'CONFIRMED' if ok else 'NOT CONFIRMED'}  {name}")
        print(f"             evidence: {evidence}")
        failures += 0 if ok else 1
    print()
    if failures:
        print(f"{failures}/{len(CHECKS)} findings could NOT be independently confirmed")
        return 1
    print(f"all {len(CHECKS)} sampled findings independently confirmed against the raw specs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
