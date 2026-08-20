"""Mutation harness: a passing test proves nothing until you watch it fail.

Each mutation deliberately breaks one behaviour in the engine and asserts that
a *specific* named test goes red. A mutation that leaves the suite green means
that behaviour is untested.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY_BIN = str(ROOT / ".venv" / "bin" / "python")

MUTATIONS = [
    (
        "union arms keyed positionally again",
        "apidrift/loader.py",
        'for name, member in _named_arms(list(resolved.get(stype) or []), resolver, seen):\n            child_prefix = f"{prefix}<{name}>" if prefix else f"<{name}>"',
        'for name, member in [(str(i), m) for i, m in enumerate(resolved.get(stype) or [])]:\n            child_prefix = f"{prefix}<{stype}[{name}]>" if prefix else f"<{stype}[{name}]>"',
        ["test_inserting_a_union_arm_does_not_look_like_removal",
         "test_reordering_union_arms_is_silent"],
    ),
    (
        "root-cause collapsing disabled",
        "apidrift/diff.py",
        "    groups: Dict[Tuple[str, str, str, str], List[Finding]] = {}",
        "    return list(findings)\n    groups: Dict[Tuple[str, str, str, str], List[Finding]] = {}",
        ["test_shared_schema_change_collapses_to_one_finding"],
    ),
    (
        "optional->required transition ignored",
        "apidrift/diff.py",
        "        if not p_old.required and p_new.required:",
        "        if False:",
        ["test_param_now_required"],
    ),
    (
        "endpoint removal never reported",
        "apidrift/diff.py",
        '        findings.append(_mk(\n            op, "endpoint_removed", BREAKING,',
        '        continue\n        findings.append(_mk(\n            op, "endpoint_removed", BREAKING,',
        ["test_endpoint_removed"],
    ),
    (
        "response field removal downgraded to non-breaking",
        "apidrift/diff.py",
        '            sev = BREAKING if where == "response" else POTENTIALLY_BREAKING',
        '            sev = POTENTIALLY_BREAKING',
        ["test_response_field_removed_through_ref",
         "test_shared_schema_change_collapses_to_one_finding"],
    ),
    (
        "every change marked breaking (false-positive flood)",
        "apidrift/diff.py",
        '            continue  # same arm, re-fingerprinted — already reported as a reshape\n        if where == "request" and f_new.required:',
        '            continue  # same arm, re-fingerprinted — already reported as a reshape\n        if True:',
        ["test_new_response_field_is_not_breaking"],
    ),
    (
        "named-ref prefix seeding removed",
        "apidrift/loader.py",
        '    if not prefix and isinstance(schema, dict) and isinstance(schema.get("$ref"), str):',
        '    if False and isinstance(schema, dict) and isinstance(schema.get("$ref"), str):',
        ["test_shared_schema_change_collapses_to_one_finding"],
    ),
    (
        "anonymous-arm reshape detection disabled",
        "apidrift/diff.py",
        "            if blind != name and blind in new_blind:",
        "            if False:",
        ["test_enum_widening_is_not_a_field_removal",
         "test_enum_narrowing_is_reported",
         "test_arm_type_change_is_breaking_not_removal"],
    ),
    (
        "verifier: vendor-evidence gate removed",
        "apidrift/verify.py",
        "    if not evidence:\n        return (NO_VENDOR,",
        "    if False:\n        return (NO_VENDOR,",
        ["test_symbol_without_vendor_evidence_is_rejected"],
    ),
    (
        "verifier: python parsed instead by text match (docstrings count)",
        "apidrift/verify.py",
        "    visitor = _PythonSites(symbol, source.splitlines())\n    visitor.visit(tree)\n    return visitor.sites, None",
        "    return ([Site(line=i + 1, kind='text', text=l)\n             for i, l in enumerate(source.splitlines()) if symbol in l], None)",
        ["test_docstring_mention_is_not_a_site", "test_docstring_candidate_is_rejected"],
    ),
    (
        "verifier: comment stripping disabled",
        "apidrift/verify.py",
        "def _strip_comments(text: str) -> str:\n    return _LINE_COMMENT.sub(\"\", _BLOCK_COMMENT.sub(_blank_block, text))",
        "def _strip_comments(text: str) -> str:\n    return text",
        ["test_javascript_comment_only_is_rejected", "test_comments_are_stripped_before_matching"],
    ),
    (
        "verifier: unparsed languages promoted to confirmed",
        "apidrift/verify.py",
        'return LIKELY, f"{len(sites)} lexical match(es), unparsed language", evidence, sites',
        'return CONFIRMED, f"{len(sites)} lexical match(es), unparsed language", evidence, sites',
        ["test_javascript_is_likely_not_confirmed"],
    ),
    (
        "verifier: endpoint mode ignores docstrings/comments distinction",
        "apidrift/verify.py",
        "        if file_path.endswith(PY_EXT):\n            sites, error = python_endpoint_sites(source, symbol)",
        "        if False:\n            sites, error = python_endpoint_sites(source, symbol)",
        ["test_docstring_endpoint_mention_is_rejected"],
    ),
    (
        "verifier: block comments no longer preserve line numbers",
        "apidrift/verify.py",
        "    return _LINE_COMMENT.sub(\"\", _BLOCK_COMMENT.sub(_blank_block, text))",
        "    return _LINE_COMMENT.sub(\"\", _BLOCK_COMMENT.sub(\"\", text))",
        ["test_block_comment_preserves_line_numbers"],
    ),
    (
        "verifier: absence mode inverted (field presence treated as the break)",
        "apidrift/verify.py",
        '        if supplies:\n            return (NO_SITE, f"already supplies `{symbol}` — migrated",',
        '        if not supplies:\n            return (NO_SITE, f"already supplies `{symbol}` — migrated",',
        ["test_caller_missing_the_new_required_field_is_a_lead",
         "test_already_migrated_caller_is_not_a_lead"],
    ),
    (
        "verifier: SDK idioms no longer count as calling the endpoint",
        "apidrift/verify.py",
        "    if idioms:\n        stripped = _strip_comments(source).splitlines()",
        "    if False:\n        stripped = _strip_comments(source).splitlines()",
        ["test_caller_missing_the_new_required_field_is_a_lead",
         "test_already_migrated_caller_is_not_a_lead"],
    ),
    (
        "signature builder drops the field name",
        "apidrift/signatures.py",
        "        if leaf and not leaf.startswith(\"<\"):",
        "        if False:",
        ["test_signatures_include_path_and_field_literals"],
    ),
]


def run_suite(tree: Path) -> str:
    proc = subprocess.run(
        [PY_BIN, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(tree), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return proc.stdout.decode("utf-8", "replace")


def failed_tests(output: str) -> set:
    return set(re.findall(r"^(?:FAIL|ERROR): (\w+)", output, re.M))


def main() -> int:
    baseline = run_suite(ROOT)
    if "\nOK" not in baseline:
        print("BASELINE IS NOT GREEN — fix the suite before mutation testing")
        print(baseline[-2000:])
        return 1
    print(f"baseline: green ({re.search(r'Ran (\d+) tests', baseline).group(1)} tests)\n")

    survived = []
    for name, rel_path, needle, replacement, expect in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "apidrift_mut"
            shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(
                ".venv", ".cache", "out", "__pycache__", ".git"))
            target = tree / rel_path
            source = target.read_text()
            if needle not in source:
                print(f"  ✗ {name}: MUTATION DID NOT APPLY (needle not found in {rel_path})")
                survived.append(name)
                continue
            target.write_text(source.replace(needle, replacement, 1))

            output = run_suite(tree)
            red = failed_tests(output)
            caught = [t for t in expect if t in red]
            missed = [t for t in expect if t not in red]
            if missed:
                print(f"  ✗ SURVIVED: {name}")
                print(f"      expected red: {missed}")
                print(f"      actually red: {sorted(red) or 'nothing — suite stayed green'}")
                survived.append(name)
            else:
                print(f"  ✓ killed: {name}")
                print(f"      caught by: {', '.join(caught)}")

    print()
    if survived:
        print(f"{len(survived)}/{len(MUTATIONS)} mutations SURVIVED — those behaviours "
              f"are not actually covered:")
        for name in survived:
            print(f"   - {name}")
        return 1
    print(f"all {len(MUTATIONS)} mutations killed — the suite has real teeth")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
