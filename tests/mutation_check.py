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
