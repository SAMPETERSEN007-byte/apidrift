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
        ["test_arm_paths_are_independent_of_order",
         "test_inserting_an_arm_leaves_the_others_untouched"],
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
        ["test_field_removed_from_an_inline_response"],
    ),
    (
        "every change marked breaking (false-positive flood)",
        "apidrift/diff.py",
        '            continue  # same field reshaped or re-rooted — already accounted for\n        if where == "request" and f_new.required:',
        '            continue  # same field reshaped or re-rooted — already accounted for\n        if True:',
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
        "            if blind in new_blind:",
        "            if False:",
        ["test_enum_widening_is_not_a_field_removal",
         "test_enum_narrowing_is_reported",
         "test_arm_type_change_is_breaking_not_removal"],
    ),
    (
        "classifier: vendor's own repos treated as leads",
        "apidrift/classify.py",
        "    if owner_l in VENDOR_ORGS.get(vendor_key, ()):",
        "    if False:",
        ["test_vendor_own_sdk_is_excluded",
         "test_only_ecosystem_and_integrators_are_outreach_targets"],
    ),
    (
        "classifier: dataset dumps counted as customers",
        "apidrift/classify.py",
        "    hit = _matches(_CORPUS_PATTERNS, name_l)\n    if hit:",
        "    hit = None\n    if hit:",
        ["test_dataset_dump_is_corpus"],
    ),
    (
        "classifier: dedupe keeps the first row instead of the richest",
        "apidrift/classify.py",
        "        if existing is None or len(lead.get(\"sites\") or []) > len(existing.get(\"sites\") or []):",
        "        if existing is None:",
        ["test_dedupe_keeps_the_richest_row_per_repo"],
    ),
    (
        "reachability stops following schema references",
        "apidrift/loader.py",
        "                queue.extend((ref, hops + 1) for ref in view.refs if ref not in seen)",
        "                pass",
        ["test_transitive_reference_is_reachable",
         "test_a_cycle_terminates_and_does_not_double_count"],
    ),
    (
        "classifier: vendored dependency paths counted as author code",
        "apidrift/classify.py",
        "    if file_path and is_vendored_path(file_path, vendor_key):",
        "    if False:",
        ["test_vendored_sdk_path_is_not_author_code"],
    ),
    (
        "classifier: vendor-package SDK modules counted as author code",
        "apidrift/classify.py",
        "            if basename.startswith(\"_\"):\n                return True",
        "            if False:\n                return True",
        ["test_sdk_internal_modules_are_vendored"],
    ),
    (
        "classifier: build output counted as author code",
        "apidrift/classify.py",
        "    if file_path and is_generated_path(file_path):",
        "    if False:",
        ["test_generated_files_are_not_outreach_targets"],
    ),
    (
        "root schema marker no longer blinded (inline->$ref fabricates changes)",
        "apidrift/diff.py",
        "        _strip_root_marker(path),",
        "        path,",
        ["test_inlining_to_a_ref_produces_no_findings"],
    ),
    (
        "reshape swallows a genuine new requirement",
        "apidrift/diff.py",
        '                if where == "request" and not f_old.required and counterpart.required:',
        "                if False:",
        ["test_a_real_tightening_still_surfaces_across_the_move"],
    ),
    (
        "prospecting ranked by fan-out alone again",
        "apidrift/prospect.py",
        "    return sorted(findings, key=lambda f: (-searchability(f), -f.occurrences))",
        "    return sorted(findings, key=lambda f: -f.occurrences)",
        ["test_ranking_puts_searchable_before_high_fanout"],
    ),
    (
        "searchability ignores weak common words",
        "apidrift/prospect.py",
        "    if leaf.lower() in _WEAK_TOKENS:\n        score -= 6",
        "    if False:\n        score -= 6",
        ["test_weak_tokens_are_penalised_below_zero"],
    ),
    (
        "schema diffing disabled entirely",
        "apidrift/diff.py",
        "    findings.extend(_diff_schema_views(old, new))",
        "    pass",
        ["test_field_removed_from_a_named_schema",
         "test_a_shallow_removal_is_still_caught"],
    ),
    (
        "schema and route views no longer merge (same change reported twice)",
        "apidrift/diff.py",
        "        key = (_kind_class(finding.kind), root_cause_key(finding.subject),",
        "        key = (finding.kind, root_cause_key(finding.subject),",
        ["test_shared_schema_change_collapses_to_one_finding"],
    ),
    (
        "reachability count shrunk back to route count",
        "apidrift/diff.py",
        "        rep.affected_op_count = max(len(distinct_ops), rep.affected_op_count)",
        "        rep.affected_op_count = len(distinct_ops)",
        ["test_a_capped_op_list_does_not_shrink_the_count"],
    ),
    (
        "inline response bodies no longer diffed",
        "apidrift/diff.py",
        '        out.extend(_diff_fields(old_resp, new_resp, new, "response", status))',
        "        pass",
        ["test_field_removed_from_an_inline_response"],
    ),
    (
        "provenance ignored: response schemas scored as request schemas",
        "apidrift/diff.py",
        "            if not was.required and now.required and in_request:",
        "            if not was.required and now.required:",
        ["test_newly_required_in_a_response_schema_is_not_breaking"],
    ),
    (
        "request-only field removal scored as breaking",
        "apidrift/diff.py",
        "                emit(\"schema_field_removed\",\n                     BREAKING if in_response else POTENTIALLY_BREAKING,",
        "                emit(\"schema_field_removed\",\n                     BREAKING,",
        ["test_removing_a_request_only_field_is_downgraded"],
    ),
    (
        "detail line quotes the capped list length instead of the real count",
        "apidrift/diff.py",
        "            rep.detail = f\"{rep.detail} — affects {rep.affected_op_count} operations\"",
        "            rep.detail = f\"{rep.detail} — affects {len(distinct_ops)} operations\"",
        ["test_the_detail_line_quotes_the_authoritative_count"],
    ),
    (
        "hop limit ignored: nearby collapses into full transitive reach",
        "apidrift/loader.py",
        "            if max_hops is not None and hops >= max_hops:\n                continue",
        "            if False:\n                continue",
        ["test_direct_reach_is_smaller_than_transitive_reach"],
    ),
    (
        "single-arm allOf wrapper read as a different type",
        "apidrift/loader.py",
        "    arms = node.get(\"allOf\")\n    if isinstance(arms, list) and len(arms) == 1 and \"properties\" not in node:",
        "    arms = node.get(\"allOf\")\n    if False:",
        ["test_allof_wrapper_around_a_ref_is_not_a_type_change"],
    ),
    (
        "schema rename reported as a type change",
        "apidrift/diff.py",
        "            if was.type != now.type and not _same_shape(was, now, old, new):",
        "            if was.type != now.type:",
        ["test_retargeting_a_ref_to_an_identical_shape_is_not_breaking"],
    ),
    (
        "inline object shape discarded (extraction reads as a type change)",
        "apidrift/loader.py",
        "                    shape=(tuple(sorted(inline_props))\n                           if isinstance(inline_props, dict) else None),",
        "                    shape=None,",
        ["test_extracting_an_inline_object_is_not_a_type_change"],
    ),
    (
        "enum change behind a ref reported as a type break",
        "apidrift/diff.py",
        "                if (was_shape and now_shape\n                        and was_shape[0] == \"enum\" == now_shape[0]):",
        "                if False:",
        ["test_enum_change_behind_a_ref_is_an_enum_finding"],
    ),
    (
        "pseudo-paths searched as if they were URLs",
        "apidrift/prospect.py",
        "    if not path or path == \"/\" or path.startswith(\"#\"):\n        return \"\"",
        "    if not path or path == \"/\":\n        return \"\"",
        ["test_pseudo_and_empty_paths_yield_nothing"],
    ),
    (
        "path truncated at the first parameter again",
        "apidrift/prospect.py",
        "    tail = \"/\" + \"/\".join(runs[-1])\n    if len(tail) >= 5:",
        "    tail = \"/\" + \"/\".join(runs[0])\n    if len(tail) >= 5:",
        ["test_sibling_sub_resources_get_distinct_literals"],
    ),
    (
        "provenance no longer checked before fetching a candidate",
        "apidrift/verify.py",
        "    placement = classify(repo, vendor.key, file_path)\n    if not placement.is_outreach_target:",
        "    placement = classify(repo, vendor.key, file_path)\n    if False:",
        ["test_vendor_owned_repo_is_rejected_without_fetching",
         "test_vendored_dependency_path_is_rejected_without_fetching"],
    ),
    (
        "removing a success status scored breaking even when others remain",
        "apidrift/diff.py",
        "                remaining = sorted(new_success)\n                if remaining:",
        "                remaining = sorted(new_success)\n                if False:",
        ["test_removing_one_success_status_is_not_breaking_when_others_remain"],
    ),
    (
        "dependence: a template literal may be satisfied by a variable",
        "apidrift/dependence.py",
        "        if want_segment != got_segment:\n            return False",
        "        if False:\n            return False",
        ["test_a_sibling_sub_resource_is_not_a_match"],
    ),
    (
        "dependence: HTTP method no longer checked at the call",
        "apidrift/dependence.py",
        "        if methods and wanted not in methods:\n            continue",
        "        if False:\n            continue",
        ["test_the_same_path_with_a_different_method_is_not_a_match"],
    ),
    (
        "dependence: value origin no longer traced to the vendor",
        "apidrift/dependence.py",
        "        link = call_reaches_vendor(source_expr, vendor, assignments)\n        if not link:",
        "        link = call_reaches_vendor(source_expr, vendor, assignments)\n        if False:",
        ["test_a_read_off_a_parameter_needs_the_carrying_operation",
         "test_reading_the_field_while_calling_something_else_is_not_dependence"],
    ),
    (
        "dependence: a field read no longer needs a carrying operation",
        "apidrift/dependence.py",
        "        calls = operation_reached()\n        if calls:\n            return ([Proof(kind=FIELD_READ, line=u.line, text=u.text,",
        "        calls = operation_reached()\n        if True:\n            return ([Proof(kind=FIELD_READ, line=u.line, text=u.text,",
        ["test_reading_the_field_while_calling_something_else_is_not_dependence"],
    ),
    (
        "dependence: already-migrated callers counted as leads",
        "apidrift/dependence.py",
        "        supplied = find_field_sends(tree, leaf, vendor, method, \"\", lines)\n        if supplied:",
        "        supplied = find_field_sends(tree, leaf, vendor, method, \"\", lines)\n        if False:",
        ["test_a_caller_that_already_supplies_the_field_is_not_a_lead"],
    ),
    (
        "dependence: SDK-form calls no longer recognised",
        "apidrift/dependence.py",
        "        if not found:\n            found = find_sdk_calls(tree, idioms, lines)",
        "        if not found:\n            pass",
        ["test_an_sdk_call_reaches_an_operation_that_names_no_path"],
    ),
    (
        "verify: generated-code gate removed",
        "apidrift/verify.py",
        "    marker = looks_generated(source)\n    if marker:",
        "    marker = \"\"\n    if marker:",
        ["test_generated_code_is_rejected_before_anything_else",
         "test_openapi_generator_header_is_rejected"],
    ),
    (
        "verify: unprovable languages promoted to leads",
        "apidrift/verify.py",
        "    if not file_path.endswith(PY_EXT):",
        "    if False:",
        ["test_javascript_is_unproven_not_likely"],
    ),
    (
        "verify: a proof is no longer required",
        "apidrift/verify.py",
        "    proofs, why_not = prove(source, finding, vendor)\n    if not proofs:",
        "    proofs, why_not = prove(source, finding, vendor)\n    if False:",
        ["test_a_docstring_mention_is_not_dependence",
         "test_a_defaults_table_is_not_a_read"],
    ),
    (
        "verify: vendor evidence matched as an unbounded substring",
        "apidrift/verify.py",
        "            if not (following.isalnum() or following == \"_\"):\n                return marker",
        "            if True:\n                return marker",
        ["test_evidence_needs_a_word_boundary"],
    ),
    (
        "dependence: routes the repo SERVES counted as calls it makes",
        "apidrift/dependence.py",
        "        if _is_route_registration(node):\n            continue",
        "        if False:\n            continue",
        ["test_a_served_route_is_not_a_call_to_the_vendor"],
    ),
    (
        "dependence: identifier filter removed (paths read as field names)",
        "apidrift/dependence.py",
        "    if not leaf or leaf.startswith(\"<\") or leaf.startswith(\"/\"):\n        return \"\"\n    if not leaf[0].isalpha():\n        return \"\"\n    if not leaf.replace(\"_\", \"\").replace(\"-\", \"\").isalnum():\n        return \"\"",
        "    if not leaf:\n        return \"\"",
        ["test_an_endpoint_subject_is_not_read_as_a_field_name"],
    ),
    (
        "dependence: whole-schema changes demand the schema name in the code",
        "apidrift/dependence.py",
        "    if finding.kind in ENDPOINT_KINDS:\n        # Operation-level and whole-schema",
        "    if finding.kind in ENDPOINT_KINDS and not leaf:\n        # Operation-level and whole-schema",
        ["test_a_deleted_schema_is_proven_by_reaching_its_operation"],
    ),
    (
        "verify: a path treated as self-identifying (no vendor evidence needed)",
        "apidrift/verify.py",
        "    if not evidence:\n        return (NO_VENDOR,",
        "    if not evidence and False:\n        return (NO_VENDOR,",
        ["test_a_repos_own_route_is_not_a_vendor_call"],
    ),
    (
        "dependence: proof no longer names the matched operation",
        "apidrift/dependence.py",
        "                for hit in hits:\n                    hit.chain.append(f\"which is `{op_method.upper()} {op_path}`\")",
        "                for hit in hits:\n                    pass",
        ["test_the_chain_states_which_operation_was_called"],
    ),
    (
        "dependence: a non-GET change confirmed without any stated verb",
        "apidrift/dependence.py",
        "        if not methods and wanted != \"get\":",
        "        if False:",
        ["test_the_same_path_with_the_vendor_present_is_still_checked"],
    ),
    (
        "dependence: a body argument no longer implies a write",
        "apidrift/dependence.py",
        "    if not found and any(kw.arg in _BODY_ARGS for kw in node.keywords):",
        "    if False:",
        ["test_a_body_argument_stands_in_for_an_unstated_verb",
         "test_a_deleted_schema_is_proven_by_reaching_its_operation"],
    ),
    (
        "dependence: a concatenation prefix accepted as a complete path",
        "apidrift/dependence.py",
        "    if candidate.rstrip().endswith(\"/\"):",
        "    if False:",
        ["test_a_trailing_slash_marks_an_incomplete_path"],
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
