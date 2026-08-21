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
        "a spec with no history behind it goes back to reading as clean",
        "apidrift/scan.py",
        "        if result.unmeasured or result.short_history:",
        "        if result.unmeasured:",
        ["test_a_quiet_result_over_unseen_history_is_not_called_clean"],
    ),
    (
        "specs with no predecessor stop being recorded at all",
        "apidrift/cli.py",
        "            result.specs_without_history.append(pair.path)",
        "            pass",
        ["test_a_spec_with_no_predecessor_is_recorded_as_unseen_history"],
    ),
    (
        "a brand-new spec file skipped as purely additive again",
        "apidrift/cli.py",
        "            result.additions.append(spec_added_finding(pair.path, added))",
        "            pass",
        ["test_a_new_api_version_reaches_the_pipeline"],
    ),
    (
        "a version segment read as the resource, so relevance never matches",
        "apidrift/diff.py",
        '        if low in {"api", "2010-04-01"} or re.fullmatch(r"v\\d+", low):',
        '        if low in {"api", "2010-04-01"} or low in {"v1", "v2", "v3"}:',
        ["test_a_version_segment_is_not_mistaken_for_the_resource"],
    ),
    (
        "the shape projection carries prose, so a copy-edit becomes a finding",
        "apidrift/diff.py",
        '    return ("scalar", field.type)',
        '    return ("scalar", field.type, field.description)',
        ["test_the_shape_projection_never_carries_prose"],
    ),
    (
        "the vendor's sentence dropped, leaving a suggestion that only names a field",
        "apidrift/diff.py",
        "            finding.blurb = after.fields[field_name].description",
        '            finding.blurb = ""',
        ["test_the_description_is_still_carried_for_suggestions"],
    ),
    (
        "an unmeasured language reported as clean again",
        "apidrift/scan.py",
        "        if result.unmeasured or result.short_history:",
        "        if result.short_history:",
        ["test_the_word_clean_is_never_printed_over_an_unmeasured_language"],
    ),
    (
        "callers in other languages stop being counted at all",
        "apidrift/scan.py",
        "                if find_vendor_evidence(source, get(key)):",
        "                if False:",
        ["test_a_typescript_caller_is_counted_as_unmeasured"],
    ),
    (
        "a repo calling nobody claims a clean bill of health",
        "apidrift/scan.py",
        "        elif not result.vendors_detected:\n            head = (\"apidrift: no calls to any known vendor found in this repo \"",
        "        elif False:\n            head = (\"apidrift: no calls to any known vendor found in this repo \"",
        ["test_a_repo_calling_no_known_vendor_says_nothing_was_checked"],
    ),
    (
        "a query variant counted as a new endpoint again",
        "apidrift/diff.py",
        '    path = path.partition("?")[0]',
        "    path = path",
        ["test_a_query_variant_of_an_existing_path_is_not_a_new_endpoint"],
    ),
    (
        "a newly REQUIRED field offered as an opportunity",
        "apidrift/diff.py",
        "            if after.fields[field_name].required:\n                continue",
        "            if False:\n                continue",
        ["test_a_new_REQUIRED_field_is_a_break_and_not_an_opportunity"],
    ),
    (
        "an addition on a schema no operation reaches is still offered",
        "apidrift/diff.py",
        "        if not ops:\n            continue          # nothing a caller touches; not an opportunity",
        "        if False:\n            continue          # nothing a caller touches; not an opportunity",
        ["test_a_schema_no_operation_reaches_is_not_an_opportunity"],
    ),
    (
        "relevance stops requiring the repo to call the resource",
        "apidrift/dependence.py",
        "    sdk = find_sdk_calls(tree, idioms, lines)\n    if sdk:\n        return sdk[:3], \"\"\n    return [], (f\"calls nothing on",
        "    sdk = find_sdk_calls(tree, idioms, lines)\n    return sdk[:3] or [Proof(kind=OPERATION_CALL, line=1, text=\"\")], (f\"calls nothing on",
        ["test_a_repo_calling_nothing_on_it_is_not"],
    ),
    (
        "a fixture ranked as good a place for advice as production",
        "apidrift/scan.py",
        "    return any(marker in lowered for marker in _TEST_MARKERS)",
        "    return False",
        ["test_a_fixture_is_a_worse_place_to_put_advice_than_production"],
    ),
    (
        "path matching goes host-blind again",
        "apidrift/dependence.py",
        "            if hosts and not any(_is_vendor_host(h, vendor) for h in hosts):",
        "            if False:",
        ["test_another_service_sharing_the_tail_path_is_not_the_vendor",
         "test_an_interpolated_url_cannot_smuggle_a_foreign_host_past"],
    ),
    (
        "an interpolated host reported as if it named someone",
        "apidrift/dependence.py",
        '    if "{" in host or "}" in host or "%" in host:\n        return None',
        "    if False:\n        return None",
        ["test_an_interpolated_host_is_unknowable_and_so_not_rejected"],
    ),
    (
        "the vendor's own host rejected as foreign",
        "apidrift/dependence.py",
        "    return any(k in host for k in known) or vendor.key.lower() in host",
        "    return False",
        ["test_the_vendors_own_host_still_matches"],
    ),
    (
        "a send no longer requires the vendor to be receiving it",
        "apidrift/dependence.py",
        "        if not link:\n            continue\n\n        anchors:",
        '        if not link:\n            link = "any call at all"\n\n        anchors:',
        ["test_a_keyword_on_the_repos_own_constructor_is_not_a_send"],
    ),
    (
        "a body dict held in a variable is no longer followed",
        "apidrift/dependence.py",
        "    if isinstance(node, ast.Name):\n        origin = assignments.get(node.id)\n        return _dict_carrying(origin, field_name, assignments, depth + 1) \\\n            if origin is not None else None",
        "    if isinstance(node, ast.Name):\n        return None",
        ["test_a_body_dict_built_in_a_variable_is_still_a_send"],
    ),
    (
        "direction ignored: a read proves a request-side change again",
        "apidrift/dependence.py",
        "    read_proves, send_proves = directions(finding)",
        "    read_proves, send_proves = True, True",
        ["test_a_read_does_not_prove_a_request_side_change",
         "test_a_send_does_not_prove_a_response_side_change"],
    ),
    (
        "a request-side kind mis-read as bidirectional",
        "apidrift/dependence.py",
        '    if kind.startswith("request_") or kind.startswith("param_"):\n        return False, True',
        '    if kind.startswith("request_") or kind.startswith("param_"):\n        return True, True',
        ["test_a_read_does_not_prove_a_request_side_change"],
    ),
    (
        "a response-only schema accepts a send as proof",
        "apidrift/dependence.py",
        "        if finding.in_response and not finding.in_request:\n            return True, False",
        "        if finding.in_response and not finding.in_request:\n            return True, True",
        ["test_a_send_does_not_prove_a_response_side_change"],
    ),
    (
        "a renamed path parameter reported as removed again",
        "apidrift/diff.py",
        "            if _is_positional(p_old):\n                continue",
        "            if False:\n                continue",
        ["test_renaming_a_path_parameter_reports_nothing"],
    ),
    (
        "positional test widened to swallow query parameters too",
        "apidrift/diff.py",
        '    return param.location == "path"',
        "    return True",
        ["test_renaming_a_query_parameter_is_still_reported"],
    ),
    (
        "a path parameter rename reported as a move again",
        "apidrift/diff.py",
        "            if caller_visible_path(key) == caller_visible_path(new_op.key):",
        "            if False:",
        ["test_renaming_a_path_parameter_moves_nothing"],
    ),
    (
        "caller-visible path stops erasing parameter names",
        "apidrift/diff.py",
        '    return f"{method} {_PATH_PARAM.sub(\'{}\', path)}"',
        '    return f"{method} {path}"',
        ["test_renaming_a_path_parameter_moves_nothing"],
    ),
    (
        "a renamed operation is no longer diffed body-to-body",
        "apidrift/diff.py",
        "            findings.extend(_diff_operation(op, new_op))",
        "            pass",
        ["test_a_renamed_operation_is_still_compared_body_to_body"],
    ),
    (
        "a field moving between schemas reported as a removal again",
        "apidrift/diff.py",
        "                if _field_survived_where_it_was_visible(",
        "                if False and _field_survived_where_it_was_visible(",
        ["test_a_field_moving_between_arms_is_not_a_removal"],
    ),
    (
        "relocation suppresses a schema no operation could ever show",
        "apidrift/diff.py",
        "    return seen_anywhere",
        "    return True",
        ["test_a_schema_no_operation_reaches_is_not_silently_suppressed"],
    ),
    (
        "a request-side field send no longer proves dependence",
        "apidrift/dependence.py",
        "    if send_proves:\n        calls = operation_reached()",
        "    if False:\n        calls = operation_reached()",
        ["test_a_sent_field_on_a_request_schema_is_proven",
         "test_a_send_does_prove_a_request_side_change"],
    ),
    (
        "a keyword argument cited at the line the call opens on",
        "apidrift/dependence.py",
        '                line = getattr(keyword, "lineno", None) \\\n                    or getattr(keyword.value, "lineno", node.lineno)',
        "                line = node.lineno",
        ["test_a_send_is_cited_at_the_line_the_field_is_on"],
    ),
    (
        "scan: prefilter rejects a path with nothing distinctive to search for",
        "apidrift/scan.py",
        "            if not segments:\n                return True",
        "            if not segments:\n                continue",
        ["test_a_path_with_nothing_distinctive_is_never_filtered_out"],
    ),
    (
        "scan: prefilter ignores SDK idioms and demands a path literal",
        "apidrift/scan.py",
        "        if any(idiom in source for idiom in idioms):\n            return True",
        "        if False:\n            return True",
        ["test_an_sdk_idiom_alone_is_enough_for_an_endpoint_change"],
    ),
    (
        "scan: dependency copies walked as if the repo author wrote them",
        "apidrift/scan.py",
        "        dirnames[:] = [d for d in dirnames\n                       if d not in SKIP_DIRS and not d.startswith(\".\")]",
        "        dirnames[:] = list(dirnames)",
        ["test_dependency_copies_are_not_this_repos_code"],
    ),
    (
        "whole-schema deletion accepts operation reach alone (the third-audit defect)",
        "apidrift/dependence.py",
        '        if finding.kind == "schema_removed":',
        "        if False:",
        ["test_reaching_the_operation_alone_is_not_enough"],
    ),
    (
        "generic field names accepted as proof of a schema read",
        "apidrift/dependence.py",
        "    if len(name) < 4 or name.lower() in _GENERIC_FIELDS:\n        return False",
        "    if len(name) < 4:\n        return False",
        ["test_a_schema_of_only_generic_fields_cannot_be_proven"],
    ),
    (
        "deleted schema's field names never recorded",
        "apidrift/diff.py",
        "        finding.leaf_fields = sorted(view.fields)",
        "        finding.leaf_fields = []",
        ["test_deleted_schema_findings_carry_their_field_names"],
    ),
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
        "    findings.extend(_diff_schema_views(old, new, result.suppressed))",
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
        "        supplied = find_field_sends(tree, leaf, vendor, assignments, idioms, lines)\n        if supplied:",
        "        supplied = find_field_sends(tree, leaf, vendor, assignments, idioms, lines)\n        if False:",
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
        "    if finding.kind in ENDPOINT_KINDS:\n        # Operation-level changes",
        "    if finding.kind in ENDPOINT_KINDS and not leaf:\n        # Operation-level changes",
        ["test_a_deleted_schema_is_proven_by_reading_one_of_its_fields",
         "test_reaching_the_operation_alone_is_not_enough"],
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
         "test_reaching_the_operation_alone_is_not_enough"],
    ),
    (
        "dependence: a concatenation prefix accepted as a complete path",
        "apidrift/dependence.py",
        "    if candidate.rstrip().endswith(\"/\"):",
        "    if False:",
        ["test_a_trailing_slash_marks_an_incomplete_path"],
    ),
    (
        "security flattened back into a set of scheme names",
        "apidrift/diff.py",
        "    stranded = [alt for alt in old\n                if not any(candidate <= alt for candidate in new)]",
        "    stranded = list(old) if (set().union(*new) - set().union(*old)) else []",
        ["test_adding_an_alternative_scheme_breaks_nobody"],
    ),
    (
        "verify: vendored library copies no longer detected",
        "apidrift/verify.py",
        "    licence = looks_vendored_library(source, file_path, vendor)\n    if licence:",
        "    licence = looks_vendored_library(source, file_path, vendor)\n    if False:",
        ["test_a_library_dump_is_not_author_code"],
    ),
    (
        "signature builder drops the field name",
        "apidrift/signatures.py",
        "        if leaf and not leaf.startswith(\"<\"):",
        "        if False:",
        ["test_signatures_include_path_and_field_literals"],
    ),
    # ---------------------------------------------------------------------
    # The `schema_removed` suppressors. Each one removes findings, so each one
    # can hide a real break -- which is why every one of them gets a mutation
    # in BOTH directions: disable it and the "not a break" test must go red;
    # make it fire unconditionally and the "still a break" test must go red.
    # A suppressor with only the first half is a deletion nobody is checking.
    # ---------------------------------------------------------------------
    (
        "unreachable schemas are reported again",
        "apidrift/diff.py",
        "        if not reachability_has_signal:\n            return True, \"unreachable_unmeasurable\"\n        return False, \"unreachable\"",
        "        return True, \"\"",
        ["test_a_schema_no_operation_reaches_is_not_a_break"],
    ),
    (
        "the dereferenced-document control is dropped (unreachable always suppresses)",
        "apidrift/diff.py",
        "        if not reachability_has_signal:\n            return True, \"unreachable_unmeasurable\"\n        return False, \"unreachable\"",
        "        return False, \"unreachable\"",
        ["test_unreachable_is_not_claimed_when_nothing_is_reachable"],
    ),
    (
        "the shape-at-parents suppressor is disabled",
        "apidrift/diff.py",
        "    if live_parents and _shape_at_parents(name, view, live_parents, old, new):",
        "    if False:",
        ["test_a_schema_inlined_at_its_only_use_site_is_not_a_break"],
    ),
    (
        "shape-at-parents accepts any replacement (inlining a different shape)",
        "apidrift/diff.py",
        "            if _field_shape(field, old) != _field_shape(replacement, new):\n                return False",
        "            if False:\n                return False",
        ["test_inlining_a_DIFFERENT_shape_is_still_a_break"],
    ),
    (
        "the root-rename suppressor is disabled",
        "apidrift/diff.py",
        "        if _renamed_at_roots(name, view, carrying, old, new, new_roots or {},\n                             response_only):",
        "        if False:",
        ["test_a_root_schema_renamed_to_an_identical_shape_is_not_a_break"],
    ),
    (
        "a root rename is accepted without comparing shapes",
        "apidrift/diff.py",
        "        if not any(_still_presents(view, new.schemas[c], old, new, response_only)\n                   for c in candidates if c in new.schemas):\n            return False",
        "        if not candidates:\n            return False",
        ["test_a_rename_that_also_drops_a_field_is_still_a_break"],
    ),
    (
        "the subsumption suppressor is disabled",
        "apidrift/diff.py",
        "    if others and not direct and others <= removed:",
        "    if False:",
        ["test_a_removal_reachable_only_through_another_removal_is_reported_once"],
    ),
    (
        "the schema carrier is counted as an affected operation again",
        "apidrift/diff.py",
        "        distinct_ops = {m.op_key for m in members if not _is_pseudo_op(m.op_key)}",
        "        distinct_ops = {m.op_key for m in members}",
        ["test_a_schema_carrier_is_never_counted_as_an_affected_operation"],
    ),
    (
        "a bare-$ref schema is no longer resolved to its target",
        "apidrift/loader.py",
        "        schema = _follow_alias(schema, resolver)",
        "        pass",
        ["test_a_bare_ref_schema_is_an_alias_for_its_target"],
    ),
    (
        "an array forgets what its items are",
        "apidrift/loader.py",
        "    items = node.get(\"items\")",
        "    items = None",
        ["test_an_inline_array_and_a_named_array_of_the_same_item_agree",
         "test_an_array_whose_ITEM_type_changed_is_NOT_the_same_shape"],
    ),
    (
        "every array compares equal regardless of item type",
        "apidrift/diff.py",
        "    if field.type == \"array\":\n        return (\"array\", _item_shape(field.item, spec)) if field.item else None",
        "    if field.type == \"array\":\n        return (\"array\", None)",
        ["test_an_array_whose_ITEM_type_changed_is_NOT_the_same_shape"],
    ),
    (
        "a parameter's single-arm allOf is no longer unwrapped",
        "apidrift/loader.py",
        "            if \"allOf\" in schema:\n                schema = _merge_all_of(schema, resolver, set())",
        "            if False:\n                schema = _merge_all_of(schema, resolver, set())",
        ["test_a_single_arm_allOf_around_a_parameter_ref_is_that_ref"],
    ),
    (
        "parameter types are never compared",
        "apidrift/diff.py",
        "        if p_old.type != p_new.type:",
        "        if False:",
        ["test_a_parameter_whose_type_really_changed_is_still_a_break"],
    ),
    (
        "discriminator mappings stop counting as references",
        "apidrift/loader.py",
        "    out.extend(_discriminator_targets(node))",
        "    pass",
        ["test_a_subtype_named_only_by_a_mapping_is_reachable",
         "test_removing_a_subtype_named_only_by_a_mapping_is_reported"],
    ),
    (
        "subsumption drops the direct-operation guard",
        "apidrift/diff.py",
        "    if others and not direct and others <= removed:",
        "    if others and others <= removed:",
        ["test_a_schema_an_operation_names_directly_is_never_subsumed"],
    ),
    (
        "a schema counts as its own outer schema",
        "apidrift/diff.py",
        "    others = parents - {name}",
        "    others = parents",
        ["test_a_self_recursive_schema_is_not_its_own_outer_schema"],
    ),
    # ---------------------------------------------------------------------
    # The snapshotter. Every one of these was written after the FIRST real run
    # of a module that had never been run, and each corresponds to something
    # that run got wrong.
    # ---------------------------------------------------------------------
    (
        "the validator goes back to scanning the first 400 bytes",
        "apidrift/snapshot.py",
        "    doc, problem = _parse(body)",
        "    return \"\" if any(m in body[:400].decode(\"utf-8\", \"replace\").lower() for m in _ROOT_MARKERS[fmt]) else \"no marker\"\n    doc, problem = _parse(body)",
        ["test_a_marker_beyond_the_first_400_bytes_is_still_a_spec",
         "test_valid_json_that_is_not_a_spec_is_rejected"],
    ),
    (
        "the validator stops checking root keys (anything parseable passes)",
        "apidrift/snapshot.py",
        "    present = [m for m in _ROOT_MARKERS[fmt] if m in doc]",
        "    present = [True]",
        ["test_valid_json_that_is_not_a_spec_is_rejected"],
    ),
    (
        "HTML is no longer rejected outright",
        "apidrift/snapshot.py",
        "    if head[:1] == b\"<\" or head[:9].lower() == b\"<!doctype\":",
        "    if False:",
        ["test_html_is_named_as_html_not_merely_rejected"],
    ),
    (
        "the YAML 1.1 value tag is unhandled again",
        "apidrift/snapshot.py",
        "        return yaml.load(body, Loader=_SpecYamlLoader), \"\"",
        "        return yaml.safe_load(body), \"\"",
        ["test_yaml_with_a_bare_equals_scalar_parses"],
    ),
    (
        "the canonical form stops sorting keys",
        "apidrift/snapshot.py",
        "    return json.dumps(_strip_volatile(parsed), sort_keys=True,",
        "    return json.dumps(_strip_volatile(parsed), sort_keys=False,",
        ["test_key_order_does_not_move_the_digest"],
    ),
    (
        "examples are hashed again",
        "apidrift/snapshot.py",
        "        return {k: _strip_volatile(v) for k, v in node.items()\n                if k not in _VOLATILE_KEYS}",
        "        return {k: _strip_volatile(v) for k, v in node.items()}",
        ["test_an_example_changing_does_not_move_the_digest"],
    ),
    (
        "unique-by-construction values are hashed again",
        "apidrift/snapshot.py",
        "    return _TIMESTAMP.sub(\"<timestamp>\", _UUID.sub(\"<uuid>\", text))",
        "    return text",
        ["test_a_fresh_uuid_or_timestamp_does_not_move_the_digest"],
    ),
    (
        "the change detector is made insensitive to everything",
        "apidrift/snapshot.py",
        "    return hashlib.sha256(canonical(body, fmt)).hexdigest()",
        "    return hashlib.sha256(b\"same\").hexdigest()",
        ["test_a_real_contract_change_STILL_moves_the_digest",
         "test_a_changed_body_is_stored_and_indexed"],
    ),
    (
        "an invalid body is stored anyway",
        "apidrift/snapshot.py",
        "    problem = looks_like_a_spec(body, source.fmt)\n    if problem:",
        "    problem = looks_like_a_spec(body, source.fmt)\n    if False:",
        ["test_an_invalid_body_is_never_stored"],
    ),
    (
        "a refusal is downgraded to a generic error",
        "apidrift/snapshot.py",
        "        if exc.code in (401, 403, 404, 410):",
        "        if False:",
        ["test_a_403_is_a_refusal_and_a_500_is_not"],
    ),
    (
        "take() no longer distinguishes a refusal from an error",
        "apidrift/snapshot.py",
        "    except SourceBlocked as exc:\n        return Outcome(source.key, \"blocked\", str(exc))",
        "    except SourceBlocked as exc:\n        return Outcome(source.key, \"error\", str(exc))",
        ["test_a_refusal_is_its_own_state_not_an_error"],
    ),
    (
        "a quiet dead source reads as an all-clear",
        "apidrift/snapshot.py",
        "    quiet = [o for o in outcomes if o.status == \"unchanged\"\n             and (by_key.get(o.key) or Source(\"\", \"\", \"\")).liveness != LIVE]",
        "    quiet = []",
        ["test_a_quiet_dead_source_is_never_an_all_clear"],
    ),
    (
        "an unchanged body is re-stored every day",
        "apidrift/snapshot.py",
        "        if sha == self.latest_digest(key):\n            return False, sha",
        "        if False:\n            return False, sha",
        ["test_an_unchanged_day_costs_nothing_on_disk"],
    ),
    (
        "a parent's ref set is no longer searched for the same shape",
        "apidrift/diff.py",
        "        if not any(_view_shape(after_ref, new) == want\n                   for after_ref in (new.schemas[r] for r in after.refs\n                                     if r in new.schemas)):\n            return False",
        "        if False:\n            return False",
        ["test_a_union_arm_that_changed_shape_is_still_a_break"],
    ),
    (
        "renamed operations are matched by operationId before URL",
        "apidrift/diff.py",
        "        if key in matches or not op.operation_id:\n            continue",
        "        if not op.operation_id:\n            continue",
        ["test_a_recycled_operationId_does_not_pair_two_different_endpoints"],
    ),
    (
        "the caller-visible URL pass is removed from rename matching",
        "apidrift/diff.py",
        "        candidates = [k for k in by_visible.get(caller_visible_path(key), ())\n                      if k not in claimed]",
        "        candidates = []",
        ["test_the_same_URL_under_a_new_parameter_name_is_still_matched"],
    ),
    (
        "an operationId match ignores the HTTP method",
        "apidrift/diff.py",
        "            by_id.setdefault((op.method, op.operation_id), key)",
        "            by_id.setdefault((\"any\", op.operation_id), key)",
        ["test_a_real_move_is_reported_and_is_not_a_removal"],
    ),
    (
        "allOf drops a member's union again",
        "apidrift/loader.py",
        "        for keyword in (\"anyOf\", \"oneOf\"):\n            arms = resolved.get(keyword)\n            if isinstance(arms, list) and arms:\n                unions.append((keyword, arms))",
        "        pass",
        ["test_a_union_inside_allOf_still_has_fields",
         "test_the_same_body_in_two_notations_reports_nothing"],
    ),
    (
        "competing unions inside allOf are resolved to the first",
        "apidrift/loader.py",
        "    if (len(unions) == 1 and \"anyOf\" not in merged and \"oneOf\" not in merged):",
        "    if (unions and \"anyOf\" not in merged and \"oneOf\" not in merged):",
        ["test_several_different_unions_are_left_opaque"],
    ),
    (
        "operation and path-item server overrides are ignored again",
        "apidrift/loader.py",
        "            op_servers = (_server_urls(op_node.get(\"servers\"))\n                          or item_servers or tuple(servers))",
        "            op_servers = tuple(servers)",
        ["test_an_operation_level_server_overrides_the_document",
         "test_a_path_item_server_overrides_the_document",
         "test_moving_one_endpoint_to_another_host_is_breaking"],
    ),
    (
        "a path-item server no longer overrides the document",
        "apidrift/loader.py",
        "        item_servers = _server_urls(resolved_item.get(\"servers\"))",
        "        item_servers = ()",
        ["test_a_path_item_server_overrides_the_document"],
    ),
    (
        "an added host counts as a move",
        "apidrift/diff.py",
        "    if was and now and not (was & now):",
        "    if was and now and was != now:",
        ["test_adding_a_host_alongside_the_old_one_is_not_breaking"],
    ),
    (
        "response findings forget which response they came from",
        "apidrift/diff.py",
        "    for finding in out:\n        finding.status = status",
        "    for finding in out:\n        finding.status = \"\"",
        ["test_a_response_finding_records_which_response"],
    ),
    (
        "a renamed response schema must match exactly again",
        "apidrift/diff.py",
        "    if before[0] == \"object\" and after and after[0] == \"object\":\n        return set(before[1]) <= set(after[1])",
        "    if False:\n        return set(before[1]) <= set(after[1])",
        ["test_a_renamed_response_schema_that_gained_a_field_is_not_a_break",
         "test_the_superset_rule_is_a_SUPERSET_rule"],
    ),
    (
        "a renamed response schema may lose fields too",
        "apidrift/diff.py",
        "        return set(before[1]) <= set(after[1])",
        "        return True",
        ["test_the_superset_rule_is_a_SUPERSET_rule"],
    ),
    (
        "request schemas get the response widening rule too",
        "apidrift/diff.py",
        "    if not response_only:\n        return _view_shape(before, old) == _view_shape(after, new)",
        "    if False:\n        return _view_shape(before, old) == _view_shape(after, new)",
        ["test_the_widening_rule_applies_only_to_what_a_caller_READS"],
    ),
    # ---------------------------------------------------------------------
    # The CHECKER. Layer 3 of the gate caught the largest defects this engine
    # has had and nothing verified it until now: a silent break here makes the
    # layer report 100% while checking nothing, which is the failure mode it
    # exists to catch, one level up.
    # ---------------------------------------------------------------------
    (
        "the checker asks the engine's question about a removed schema again",
        "tests/measure_precision.py",
        "    if kind == \"schema_removed\":\n        return check_schema_removed(finding, old, new)",
        "    if kind == \"schema_removed\":\n        n = finding.get(\"root_cause\") or finding[\"subject\"]\n        return ((CONFIRMED, \"present at old, absent at new\")\n                if n in schemas_of(old) and n not in schemas_of(new)\n                else (REFUTED, \"still there\"))",
        ["test_an_inlined_schema_is_refuted",
         "test_a_dereferenced_document_is_UNDECIDABLE_not_refuted"],
    ),
    (
        "the checker drops the dereferenced-document control",
        "tests/measure_precision.py",
        "        linked = len(ref_sites(old, None))\n        if linked == 0:",
        "        linked = len(ref_sites(old, None))\n        if False:",
        ["test_a_dereferenced_document_is_UNDECIDABLE_not_refuted"],
    ),
    (
        "the checker stops treating a discriminator mapping as a reference",
        "tests/measure_precision.py",
        "        disc = node.get(\"discriminator\")\n        if isinstance(disc, dict) and isinstance(disc.get(\"mapping\"), dict):",
        "        disc = node.get(\"discriminator\")\n        if False:",
        ["test_a_discriminator_mapping_counts_as_a_reference"],
    ),
    (
        "the checker resolves a schema-qualified root against the schema table",
        "tests/measure_precision.py",
        "                if parts[0] in (schemas_of(old) | schemas_of(new)) and parts[1:]:",
        "                if False:",
        ["test_a_schema_qualified_root_is_decided_against_the_OPERATION"],
    ),
    (
        "the checker resolves every response against the 200 body",
        "tests/measure_precision.py",
        "            node = responses.get(status) if status else None",
        "            node = None",
        ["test_the_named_response_status_is_the_one_resolved"],
    ),
    (
        "the checker refutes a path parameter's TYPE change on positionality",
        "tests/measure_precision.py",
        "        if entry.get(\"in\") == \"path\" and kind != \"param_type_changed\":",
        "        if entry.get(\"in\") == \"path\":",
        ["test_a_path_parameter_type_change_is_decided_on_the_TYPE"],
    ),
    (
        "the checker ignores an operation's own servers",
        "tests/measure_precision.py",
        "            for node in (op if isinstance(op, dict) else {}, item, doc):",
        "            for node in (doc,):",
        ["test_a_host_move_on_one_operation_is_confirmed"],
    ),
    (
        "the checker asks only whether the PATH survives",
        "tests/measure_precision.py",
        "        was, now = verbs(old, wanted), verbs(new, wanted)",
        "        was, now = ({finding['method'].lower()} if wanted in [__import__('re').sub(r'\\{[^}]*\\}', '{}', p) for p in (old.get('paths') or {})] else set()), ({finding['method'].lower()} if wanted in [__import__('re').sub(r'\\{[^}]*\\}', '{}', p) for p in (new.get('paths') or {})] else set())",
        ["test_removing_one_VERB_from_a_live_path_is_confirmed"],
    ),
    (
        "the checker stops normalising path parameter names",
        "tests/measure_precision.py",
        "                if erased.sub(\"{}\", str(path)) != wanted or not isinstance(item, dict):",
        "                if str(path) != wanted or not isinstance(item, dict):",
        ["test_a_path_parameter_rename_is_not_a_removal"],
    ),
    (
        "the checker refutes instead of abstaining on an absent old path",
        "tests/measure_precision.py",
        "        if not was:\n            return UNDECIDABLE, f\"`{finding['path']}` is absent from the old spec too\"",
        "        if False:\n            return UNDECIDABLE, \"\"",
        ["test_a_path_absent_from_the_OLD_spec_is_undecidable"],
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
    stale = []
    for name, rel_path, needle, replacement, expect in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "apidrift_mut"
            shutil.copytree(ROOT, tree, ignore=shutil.ignore_patterns(
                ".venv", ".cache", "out", "__pycache__", ".git"))
            target = tree / rel_path
            source = target.read_text()
            if needle not in source:
                # A different problem from a surviving mutation, and it needs a
                # different fix. A stale needle means this harness is broken;
                # a survivor means the SUITE is. Reporting both as "survived"
                # sends you looking for missing coverage that is already there.
                print(f"  ✗ {name}: STALE MUTATION — needle no longer in "
                      f"{rel_path}, so nothing was mutated and nothing was tested")
                stale.append(name)
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
    if stale:
        print(f"{len(stale)}/{len(MUTATIONS)} mutations are STALE — the code moved "
              f"under them, so they tested nothing:")
        for name in stale:
            print(f"   - {name}")
    if survived:
        print(f"{len(survived)}/{len(MUTATIONS)} mutations SURVIVED — those behaviours "
              f"are not actually covered:")
        for name in survived:
            print(f"   - {name}")
    if stale or survived:
        return 1
    print(f"all {len(MUTATIONS)} mutations killed — the suite has real teeth")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
