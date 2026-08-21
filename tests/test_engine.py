"""Unit tests over synthetic specs where ground truth is known by construction."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apidrift.diff import BREAKING, POTENTIALLY_BREAKING, collapse, diff_specs, root_cause_key
from apidrift.loader import load_spec
from apidrift.signatures import build_signatures
from apidrift.vendors import get

BASE = {
    "openapi": "3.0.3",
    "info": {"title": "Test API", "version": "1"},
    "servers": [{"url": "https://api.test.com/v1"}],
    "components": {
        "securitySchemes": {"bearer": {"type": "http"}},
        "schemas": {
            "Card": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "iin": {"type": "string"}},
                "required": ["id"],
            },
            "Bank": {
                "type": "object",
                "properties": {"id": {"type": "string"}, "routing": {"type": "string"}},
            },
        },
    },
    "paths": {
        "/charges": {
            "get": {
                "operationId": "listCharges",
                "parameters": [
                    {"name": "limit", "in": "query", "required": False,
                     "schema": {"type": "integer"}},
                    {"name": "status", "in": "query", "required": False,
                     "schema": {"type": "string", "enum": ["paid", "pending", "failed"]}},
                ],
                "responses": {
                    "200": {"content": {"application/json": {"schema": {
                        "type": "object",
                        "properties": {
                            "amount": {"type": "integer"},
                            "currency": {"type": "string"},
                            "source": {"anyOf": [
                                {"$ref": "#/components/schemas/Card"},
                                {"$ref": "#/components/schemas/Bank"},
                            ]},
                        },
                    }}}},
                },
            },
            "post": {
                "operationId": "createCharge",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"amount": {"type": "integer"}, "note": {"type": "string"}},
                    "required": ["amount"],
                }}}},
                "responses": {"200": {"content": {"application/json": {"schema": {
                    "$ref": "#/components/schemas/Card"}}}}},
            },
        },
        "/refunds/{id}": {
            "get": {
                "operationId": "getRefund",
                "parameters": [{"name": "id", "in": "path", "required": True,
                               "schema": {"type": "string"}}],
                "responses": {"200": {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {"id": {"type": "string"}}}}}}},
            },
        },
    },
}


def spec(doc):
    return load_spec(json.dumps(doc).encode(), "test.json")


def run(old_doc, new_doc):
    result = diff_specs("test", spec(old_doc), spec(new_doc), {})
    result.findings = collapse(result.findings)
    return result


def kinds(result, severity=BREAKING):
    return {f.kind for f in result.findings if f.severity == severity}


class TestBreakingDetection(unittest.TestCase):
    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def test_endpoint_removed(self):
        del self.new["paths"]["/refunds/{id}"]
        self.assertIn("endpoint_removed", kinds(run(self.old, self.new)))

    def test_a_real_move_is_reported_and_is_not_a_removal(self):
        """A STATIC segment changed, so every caller's URL changed with it."""
        self.new["paths"]["/credits/{id}"] = self.new["paths"].pop("/refunds/{id}")
        found = kinds(run(self.old, self.new))
        self.assertIn("endpoint_moved", found)
        self.assertNotIn("endpoint_removed", found)

    def test_renaming_a_path_parameter_moves_nothing(self):
        """`/refunds/{id}` and `/refunds/{refund_id}` are the same URL.

        A path parameter's name is OpenAPI-internal, exactly like a schema
        name, and never reaches the wire. `dependence.paths_match()` has
        always known this while PROVING; the diff did not know it while
        DIFFING, and Twilio's `{Sid}` -> `{id}` rename produced 15 of 79
        breaking findings that break nobody.
        """
        self.new["paths"]["/refunds/{refund_id}"] = self.new["paths"].pop("/refunds/{id}")
        found = kinds(run(self.old, self.new))
        self.assertNotIn("endpoint_moved", found)
        self.assertNotIn("endpoint_removed", found)

    def test_a_renamed_operation_is_still_compared_body_to_body(self):
        """Renaming the parameter must not hide a real change to the same op.

        The rename branch used to `continue` before the operation pair was
        diffed, so a vendor renaming a parameter AND tightening the operation
        in one release had the second change go entirely unreported.
        """
        moved = self.new["paths"].pop("/refunds/{id}")
        moved["get"]["parameters"] = [
            {"name": "reason", "in": "query", "required": True,
             "schema": {"type": "string"}}]
        self.new["paths"]["/refunds/{refund_id}"] = moved
        found = kinds(run(self.old, self.new))
        self.assertIn("param_added_required", found)

    def test_param_now_required(self):
        self.new["paths"]["/charges"]["get"]["parameters"][0]["required"] = True
        self.assertIn("param_now_required", kinds(run(self.old, self.new)))

    def test_param_added_required(self):
        self.new["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "account", "in": "query", "required": True, "schema": {"type": "string"}})
        self.assertIn("param_added_required", kinds(run(self.old, self.new)))

    def test_param_type_changed(self):
        self.new["paths"]["/charges"]["get"]["parameters"][0]["schema"]["type"] = "string"
        self.assertIn("param_type_changed", kinds(run(self.old, self.new)))

    def test_request_enum_value_removed(self):
        self.new["paths"]["/charges"]["get"]["parameters"][1]["schema"]["enum"] = ["paid", "pending"]
        self.assertIn("request_enum_value_removed", kinds(run(self.old, self.new)))

    def test_field_removed_from_a_named_schema(self):
        del self.new["components"]["schemas"]["Card"]["properties"]["iin"]
        self.assertIn("schema_field_removed", kinds(run(self.old, self.new)))

    def test_deleted_schema_findings_carry_their_field_names(self):
        """A caller never writes the schema name, only its fields.

        Without these the verifier can only show the caller reached the
        operation, which is what refuted seven of ten leads in the third
        adversarial audit.
        """
        del self.new["components"]["schemas"]["Card"]
        removed = [f for f in run(self.old, self.new).findings
                   if f.kind == "schema_removed" and f.subject == "Card"]
        self.assertTrue(removed, "deleting a named schema must be reported")
        self.assertIn("iin", removed[0].leaf_fields)

    def test_field_removed_from_an_inline_response(self):
        """No named schema exists here, so only the route pass can catch it."""
        body = self.new["paths"]["/charges"]["get"]["responses"]["200"][
            "content"]["application/json"]["schema"]
        del body["properties"]["currency"]
        self.assertIn("response_field_removed", kinds(run(self.old, self.new)))

    def test_response_field_type_changed(self):
        self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["amount"]["type"] = "string"
        self.assertIn("response_field_type_changed", kinds(run(self.old, self.new)))

    def test_request_field_now_required(self):
        body = self.new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]
        body["required"] = ["amount", "note"]
        self.assertIn("request_field_now_required", kinds(run(self.old, self.new)))

    def test_security_requirement_added_where_there_was_none(self):
        self.new["paths"]["/charges"]["get"]["security"] = [{"bearer": []}]
        self.assertIn("security_requirement_added", kinds(run(self.old, self.new)))

    def test_adding_an_alternative_scheme_breaks_nobody(self):
        """OpenAPI security is a list of ALTERNATIVES: [{A},{B}] means A or B.

        Twilio added `access_token_bearer` alongside `accountSid_authToken` on
        nine operations. Every existing caller kept working, and flattening the
        list scored all nine as breaking.
        """
        self.old["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.new["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.old["paths"]["/charges"]["get"]["security"] = [{"basic": []}]
        self.new["paths"]["/charges"]["get"]["security"] = [{"basic": []},
                                                            {"bearer": []}]
        self.assertNotIn("security_requirement_added",
                         {f.kind for f in run(self.old, self.new).findings})

    def test_adding_a_scheme_to_every_alternative_is_breaking(self):
        self.old["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.new["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.old["paths"]["/charges"]["get"]["security"] = [{"basic": []}]
        self.new["paths"]["/charges"]["get"]["security"] = [{"basic": [],
                                                             "bearer": []}]
        self.assertIn("security_requirement_added",
                      kinds(run(self.old, self.new)))

    def test_removing_an_alternative_is_breaking(self):
        self.old["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.new["components"]["securitySchemes"]["basic"] = {"type": "http"}
        self.old["paths"]["/charges"]["get"]["security"] = [{"basic": []},
                                                            {"bearer": []}]
        self.new["paths"]["/charges"]["get"]["security"] = [{"basic": []}]
        self.assertIn("security_requirement_added",
                      kinds(run(self.old, self.new)))

    def test_success_response_removed(self):
        # No success status remains, so callers have nothing to fall back to.
        self.new["paths"]["/refunds/{id}"]["get"]["responses"] = {
            "404": {"description": "gone"}}
        self.assertIn("response_status_removed", kinds(run(self.old, self.new)))

    def test_removing_one_success_status_is_not_breaking_when_others_remain(self):
        """Discord dropped 204 from bulk-ban and kept 200.

        That NARROWS what the server returns. Every client already handling
        the 200-with-body is unaffected, and scoring it breaking produced ten
        leads against libraries that never read the status.
        """
        self.old["paths"]["/refunds/{id}"]["get"]["responses"]["204"] = {
            "description": "no content"}
        result = run(self.old, self.new)
        self.assertNotIn("response_status_removed",
                         {f.kind for f in result.breaking})
        self.assertIn("response_status_removed",
                      {f.kind for f in result.potentially_breaking})

    def test_server_url_changed(self):
        self.new["servers"] = [{"url": "https://api.test.com/v2"}]
        self.assertIn("server_url_changed", kinds(run(self.old, self.new)))


class TestNoFalsePositives(unittest.TestCase):
    """The control tests. An additive change must stay silent."""

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def test_identical_specs_produce_nothing(self):
        self.assertEqual(run(self.old, self.new).findings, [])

    def test_new_endpoint_is_not_breaking(self):
        self.new["paths"]["/payouts"] = {"get": {
            "operationId": "listPayouts",
            "responses": {"200": {"content": {"application/json": {
                "schema": {"type": "object"}}}}}}}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_new_optional_param_is_not_breaking(self):
        self.new["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "cursor", "in": "query", "required": False, "schema": {"type": "string"}})
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_new_response_field_is_not_breaking(self):
        self.new["components"]["schemas"]["Card"]["properties"]["brand"] = {"type": "string"}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_inserting_a_union_arm_does_not_look_like_removal(self):
        """Regression: positional arm indices made every later arm look removed."""
        union = self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["source"]["anyOf"]
        self.new["components"]["schemas"]["Wallet"] = {
            "type": "object", "properties": {"id": {"type": "string"}}}
        union.insert(0, {"$ref": "#/components/schemas/Wallet"})
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_reordering_union_arms_is_silent(self):
        union = self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["source"]["anyOf"]
        union.reverse()
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_reordering_properties_is_silent(self):
        props = self.new["components"]["schemas"]["Card"]["properties"]
        self.new["components"]["schemas"]["Card"]["properties"] = dict(
            reversed(list(props.items())))
        self.assertEqual(run(self.old, self.new).breaking, [])


class TestAnonymousArmReshape(unittest.TestCase):
    """An anonymous arm is fingerprinted by content, so editing it renames it.

    Regression: that rename read as `field removed` (BREAKING) when the real
    change was an enum widening (POTENTIALLY_BREAKING).
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["tier"] = {
                "anyOf": [{"type": "string", "enum": ["auto", "flex"]},
                          {"type": "null"}]}

    def _tier(self, doc):
        return doc["components"]["schemas"]["Card"]["properties"]["tier"]["anyOf"][0]

    def test_enum_widening_is_not_a_field_removal(self):
        from apidrift.diff import _kind_class
        self._tier(self.new)["enum"] = ["auto", "flex", "fast"]
        result = run(self.old, self.new)
        classes = {_kind_class(f.kind) for f in result.findings}
        self.assertIn("enum_value_added", classes)
        self.assertNotIn("field_removed", classes)
        self.assertEqual(result.breaking, [], "widening an enum is not breaking")

    def test_enum_narrowing_is_reported(self):
        from apidrift.diff import _kind_class
        self._tier(self.new)["enum"] = ["auto"]
        classes = {_kind_class(f.kind) for f in run(self.old, self.new).findings}
        self.assertIn("enum_value_removed", classes)
        self.assertNotIn("field_removed", classes)

    def test_arm_type_change_is_breaking_not_removal(self):
        self._tier(self.new).clear()
        self._tier(self.new).update({"type": "integer"})
        result = run(self.old, self.new)
        found = {f.kind for f in result.findings}
        self.assertIn("response_field_type_changed", found)
        self.assertNotIn("response_field_removed", found)


class TestInlineToRefMove(unittest.TestCase):
    """Moving a request body from an inline schema to a `$ref` changes nothing.

    Regression: OpenAI moved `POST /batches` to `$ref: CreateBatchRequest`, and
    every already-required field was reported BOTH as removed and as newly
    required. Five fabricated breaking changes on one endpoint.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)
        self.new["components"]["schemas"]["CreateChargeRequest"] = {
            "type": "object",
            "properties": {"amount": {"type": "integer"}, "note": {"type": "string"}},
            "required": ["amount"],
        }
        self.new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {
                "$ref": "#/components/schemas/CreateChargeRequest"}

    def test_inlining_to_a_ref_produces_no_findings(self):
        result = run(self.old, self.new)
        self.assertEqual(result.findings, [],
                         f"unchanged contract produced {[f.kind for f in result.findings]}")

    def test_a_real_tightening_still_surfaces_across_the_move(self):
        self.new["components"]["schemas"]["CreateChargeRequest"]["required"] = [
            "amount", "note"]
        found = {f.kind for f in run(self.old, self.new).findings}
        self.assertIn("request_field_now_required", found,
                      "the ref move must not swallow a genuine new requirement")

    def test_a_real_removal_still_surfaces_across_the_move(self):
        del self.new["components"]["schemas"]["CreateChargeRequest"]["properties"]["note"]
        found = {f.kind for f in run(self.old, self.new).findings}
        self.assertTrue(found, "removing a field across the move must be reported")


class TestDepthTruncation(unittest.TestCase):
    """Absence past the depth cap is ignorance, not deletion.

    Regression: at MAX_DEPTH=6 Stripe's terminal-reader response flattened to
    571 fields on the old side and 208 on the new, because the new schema nests
    one level deeper along the same paths. Every field past the cap read as
    removed, and a random-sample audit refuted 39 of 44 `response_field_removed`
    findings on this alone. All four real paths were identical on both sides.
    """

    @staticmethod
    def _chain(levels, extra_at=None):
        """A `down.down.…` chain, optionally carrying a second property."""
        node = {"type": "object", "properties": {"leaf": {"type": "string"}}}
        for level in range(levels):
            props = {"down": node}
            if extra_at == level:
                props["extra"] = {"type": "string"}
            node = {"type": "object", "properties": props}
        return node

    def _build(self, levels, extra_at=None):
        doc = copy.deepcopy(BASE)
        doc["paths"]["/refunds/{id}"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"] = self._chain(levels, extra_at)
        return doc

    def test_deep_absence_is_not_reported_as_removal(self):
        # Identical deep chains; the old side alone carries `extra` far below
        # the point where flattening stops. Nothing can be concluded there.
        old = self._build(9, extra_at=1)
        new = self._build(9)
        removals = [f for f in run(old, new).findings
                    if f.kind == "response_field_removed"]
        self.assertEqual(removals, [],
                         f"claimed {len(removals)} removals past the depth cap")

    def test_the_reverse_direction_is_also_safe(self):
        old = self._build(9)
        new = self._build(9, extra_at=1)
        added = [f for f in run(old, new).findings
                 if f.kind.endswith("added_required")]
        self.assertEqual(added, [])

    def test_a_shallow_removal_is_still_caught(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        del new["components"]["schemas"]["Card"]["properties"]["iin"]
        found = {f.kind for f in run(old, new).findings}
        self.assertIn("schema_field_removed", found,
                      "the truncation guard must not suppress real removals")

    def test_truncation_markers_never_become_findings(self):
        old = self._build(9)
        new = self._build(12)
        for finding in run(old, new).findings:
            self.assertNotIn("__truncated__", f"{finding.old}{finding.new}",
                             "a truncation marker leaked into a finding")


class TestRefEquivalence(unittest.TestCase):
    """Two ways of writing the same type are not a change."""

    def test_allof_wrapper_around_a_ref_is_not_a_type_change(self):
        # `$ref` siblings are ignored in OpenAPI 3.0, so vendors wrap the ref
        # in a single-arm allOf to attach `deprecated`. Plaid did this to
        # Transfer.guarantee_decision. The referenced type is identical.
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Charge"] = {
            "type": "object",
            "properties": {"src": {"$ref": "#/components/schemas/Card"}}}
        new["components"]["schemas"]["Charge"] = {
            "type": "object",
            "properties": {"src": {"deprecated": True,
                                   "allOf": [{"$ref": "#/components/schemas/Card"}]}}}
        kinds_found = {f.kind for f in run(old, new).findings}
        self.assertNotIn("schema_field_type_changed", kinds_found)

    def test_a_single_arm_allof_over_a_UNION_is_not_a_type_change(self):
        """The wrapper case that only the reference identity can decide.

        A `oneOf` has no properties, so merging the wrapper's arms leaves an
        opaque union on one side and `->Choice` on the other, with no shape on
        either to compare. Nothing but recognising that the wrapper still
        points at `Choice` settles it.
        """
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        for document in (old, new):
            document["components"]["schemas"]["Choice"] = {"oneOf": [
                {"$ref": "#/components/schemas/Card"},
                {"$ref": "#/components/schemas/Bank"}]}
        old["components"]["schemas"]["Card"]["properties"]["src"] = {
            "$ref": "#/components/schemas/Choice"}
        new["components"]["schemas"]["Card"]["properties"]["src"] = {
            "deprecated": True,
            "allOf": [{"$ref": "#/components/schemas/Choice"}]}
        self.assertNotIn("schema_field_type_changed",
                         {f.kind for f in run(old, new).findings})

    def test_retargeting_a_ref_to_an_identical_shape_is_not_breaking(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        shape = {"type": "object",
                 "properties": {"id": {"type": "string"},
                                "amount": {"type": "integer"}}}
        old["components"]["schemas"]["OptionsGet"] = copy.deepcopy(shape)
        new["components"]["schemas"]["OptionsCreate"] = copy.deepcopy(shape)
        old["components"]["schemas"]["Card"]["properties"]["opts"] = {
            "$ref": "#/components/schemas/OptionsGet"}
        new["components"]["schemas"]["Card"]["properties"]["opts"] = {
            "$ref": "#/components/schemas/OptionsCreate"}
        kinds_found = {f.kind for f in run(old, new).findings}
        self.assertNotIn("schema_field_type_changed", kinds_found,
                         "a rename with an unchanged shape is not a break")

    def test_extracting_an_inline_object_is_not_a_type_change(self):
        """Naming an inline definition changes notation, not the payload."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        inline = {"type": "object",
                  "properties": {"completed": {"type": "integer"},
                                 "failed": {"type": "integer"}}}
        old["components"]["schemas"]["Card"]["properties"]["counts"] = \
            copy.deepcopy(inline)
        new["components"]["schemas"]["Counts"] = copy.deepcopy(inline)
        new["components"]["schemas"]["Card"]["properties"]["counts"] = {
            "$ref": "#/components/schemas/Counts"}
        self.assertNotIn("schema_field_type_changed",
                         {f.kind for f in run(old, new).findings})

    def test_enum_change_behind_a_ref_is_an_enum_finding(self):
        """OpenAI moved service_tier from ServiceTier to ServiceTierResponses.

        The values widened. That is a fall-through risk on a response, not a
        type break, and it was being reported as both.
        """
        from apidrift.diff import _kind_class
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Tier"] = {
            "type": "string", "enum": ["auto", "flex"]}
        new["components"]["schemas"]["TierV2"] = {
            "type": "string", "enum": ["auto", "flex", "fast"]}
        old["components"]["schemas"]["Card"]["properties"]["tier"] = {
            "$ref": "#/components/schemas/Tier"}
        new["components"]["schemas"]["Card"]["properties"]["tier"] = {
            "$ref": "#/components/schemas/TierV2"}
        result = run(old, new)
        classes = {_kind_class(f.kind) for f in result.findings}
        self.assertIn("enum_value_added", classes)
        self.assertNotIn("field_type_changed", classes)

    def test_retargeting_a_ref_to_a_different_shape_is_breaking(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Card"]["properties"]["opts"] = {
            "$ref": "#/components/schemas/Card"}
        new["components"]["schemas"]["Card"]["properties"]["opts"] = {
            "$ref": "#/components/schemas/Bank"}
        self.assertIn("schema_field_type_changed",
                      {f.kind for f in run(old, new).breaking})


class TestAllOfWrapperWithProseArm(unittest.TestCase):
    """`$ref` + siblings rewritten as `allOf: [$ref, {prose}]` is notation.

    A `$ref` sibling is ignored in OpenAPI 3.0, so the only way to attach a
    description is a wrapper -- and the description lands in a SECOND arm, not
    outside the wrapper. Only the single-arm form was recognised, so PayPal
    regenerating its checkout spec turned 296 properties into `->X` becoming a
    bare `object` and 37 more into `->X_list` becoming a bare `array`.
    """

    def _wrapped(self, arm):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Card"]["properties"]["src"] = {
            "$ref": "#/components/schemas/Bank", "description": "the source"}
        new["components"]["schemas"]["Card"]["properties"]["src"] = {
            "allOf": [{"$ref": "#/components/schemas/Bank"}, arm]}
        return old, new

    def test_a_prose_only_second_arm_is_not_a_type_change(self):
        old, new = self._wrapped({"description": "the source", "title": "src"})
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_a_prose_wrapped_UNION_is_not_a_type_change(self):
        """The case only the reference identity can save.

        A `oneOf` has no properties to merge, so collapsing the wrapper by
        merging its arms leaves an opaque `oneOf` on one side and `->Choice` on
        the other, with no shape on either to compare. Recognising that the
        wrapper still points at `Choice` is the only thing that decides it.
        """
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        for doc in (old, new):
            doc["components"]["schemas"]["Choice"] = {"oneOf": [
                {"$ref": "#/components/schemas/Card"},
                {"$ref": "#/components/schemas/Bank"}]}
        old["components"]["schemas"]["Card"]["properties"]["src"] = {
            "$ref": "#/components/schemas/Choice", "description": "either"}
        new["components"]["schemas"]["Card"]["properties"]["src"] = {
            "allOf": [{"$ref": "#/components/schemas/Choice"},
                      {"description": "either"}]}
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_an_arm_that_carries_a_contract_is_still_read(self):
        """The suppression is about PROSE. An arm with properties is content.

        Without this the rule would collapse every `allOf` onto its first
        reference and quietly delete whatever the other arms said.
        """
        old, new = self._wrapped({"properties": {"extra": {"type": "string"}}})
        from apidrift.loader import _ref_name
        self.assertIsNone(
            _ref_name(new["components"]["schemas"]["Card"]["properties"]["src"]),
            "an arm carrying properties must not be treated as prose")

    def test_the_wrapper_still_compares_the_TARGETS(self):
        """Seeing through the wrapper is not the same as ignoring it."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Card"]["properties"]["src"] = {
            "$ref": "#/components/schemas/Bank"}
        new["components"]["schemas"]["Card"]["properties"]["src"] = {
            "allOf": [{"$ref": "#/components/schemas/Widget"},
                      {"description": "now something else"}]}
        new["components"]["schemas"]["Widget"] = {
            "type": "object", "properties": {"colour": {"type": "string"}}}
        self.assertIn("schema_field_type_changed", kinds(run(old, new)),
                      "the wrapper points somewhere else and that IS a break")


class TestAllOfCarriesTheArmsEnum(unittest.TestCase):
    """`readOnly` is not prose, so the wrapper is merged rather than seen past.

    The merge carried properties, required and an unambiguous union, and
    dropped `enum` on the floor. PayPal attaches `readOnly` to a reference that
    way, so thirty card brands merged down to the bare word "string" and the
    identical property written as a plain `$ref` compared unequal to it.
    """

    def _docs(self, old_prop, new_prop, extra=None):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        for document in (old, new):
            document["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
            document["components"]["schemas"].update(
                copy.deepcopy(extra) or {})
        old["components"]["schemas"]["Card"]["properties"]["brand"] = old_prop
        new["components"]["schemas"]["Card"]["properties"]["brand"] = new_prop
        return old, new

    def test_a_readonly_arm_over_an_enum_ref_is_not_a_type_change(self):
        old, new = self._docs(
            {"$ref": "#/components/schemas/Brand", "readOnly": True},
            {"allOf": [{"$ref": "#/components/schemas/Brand"},
                       {"readOnly": True}]})
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_arms_with_disagreeing_enums_do_not_invent_one(self):
        """An `allOf` of two enums is their INTERSECTION, which this shape
        cannot represent. Picking one arm's answer would silently widen it."""
        old, new = self._docs(
            {"$ref": "#/components/schemas/Brand"},
            {"allOf": [{"$ref": "#/components/schemas/Brand"},
                       {"$ref": "#/components/schemas/Narrow"}]},
            {"Narrow": {"type": "string", "enum": ["visa"]}})
        self.assertIn("schema_field_type_changed", kinds(run(old, new)),
                      "the intersection is narrower and must not be papered over")


class TestArrayElementNotation(unittest.TestCase):
    """A named list schema and the same list inlined are one array.

    `_item_shape` resolved a NAMED element to `("scalar", "string")` and left an
    inline one as the bare string `"string"`, so the two notations could never
    compare equal however identical the elements were. PayPal inlined
    `products_list`, `labels_list`, `dispute_categories_list` and
    `callback_events_list` in one release.
    """

    def _named_then_inline(self, element, inline_element=None):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Items"] = {
            "type": "array", "items": {"$ref": "#/components/schemas/Element"}}
        old["components"]["schemas"]["Element"] = copy.deepcopy(element)
        old["components"]["schemas"]["Card"]["properties"]["tags"] = {
            "$ref": "#/components/schemas/Items"}
        new["components"]["schemas"]["Card"]["properties"]["tags"] = {
            "type": "array",
            "items": copy.deepcopy(inline_element or element)}
        return old, new

    def test_inlining_an_array_of_strings_is_not_a_type_change(self):
        old, new = self._named_then_inline({"type": "string"})
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_inlining_an_array_of_an_enum_keeps_its_values(self):
        old, new = self._named_then_inline(
            {"type": "string", "enum": ["a", "b"]})
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_the_elements_are_still_compared(self):
        """Symmetry is not blindness: a real element change still fires."""
        old, new = self._named_then_inline({"type": "string"},
                                           {"type": "integer"})
        self.assertIn("schema_field_type_changed", kinds(run(old, new)),
                      "array of string -> array of integer is a break")

    def test_the_element_VALUES_are_still_compared(self):
        old, new = self._named_then_inline(
            {"type": "string", "enum": ["a", "b"]},
            {"type": "string", "enum": ["a", "c"]})
        self.assertIn("schema_field_type_changed", kinds(run(old, new)),
                      "the element enum changed and that is not notation")


class TestPropertyLevelAllOf(unittest.TestCase):
    """An `allOf` written AT A PROPERTY was never merged, only named schemas.

    So a property composing a reference with an overlay read as a bare `object`
    with no fields, and the same thing written as a plain `$ref` read as
    `->Name`: unequal on notation with no shape on either side to compare them
    by. Klaviyo turned `allOf: [{$ref: X}, {properties: ...}]` into `$ref: X`
    and Cloudflare did the reverse in the same window.
    """

    def _overlay(self, overlay_props):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Card"]["properties"]["acct"] = {
            "allOf": [{"$ref": "#/components/schemas/Bank"},
                      {"type": "object", "properties": overlay_props}]}
        new["components"]["schemas"]["Card"]["properties"]["acct"] = {
            "$ref": "#/components/schemas/Bank"}
        return old, new

    def test_an_overlay_that_adds_nothing_visible_is_not_a_type_change(self):
        # The overlay only refines a property `Bank` already declares, so the
        # names a consumer sees are the same on both sides.
        old, new = self._overlay({"routing": {"type": "string",
                                              "maxLength": 9}})
        self.assertNotIn("schema_field_type_changed", kinds(run(old, new)))

    def test_an_overlay_that_adds_a_field_is_still_a_change(self):
        old, new = self._overlay({"sortcode": {"type": "string"}})
        self.assertIn("schema_field_type_changed", kinds(run(old, new)),
                      "the old side carried a field the new side does not")


class TestProvenanceSeverity(unittest.TestCase):
    """Tightening what a caller SENDS breaks them; what they RECEIVE does not."""

    def _with_request_schema(self):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["ChargeRequest"] = {
            "type": "object",
            "properties": {"amount": {"type": "integer"},
                           "note": {"type": "string"}},
            "required": ["amount"],
        }
        doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {
                "$ref": "#/components/schemas/ChargeRequest"}
        return doc

    def test_newly_required_in_a_request_schema_is_breaking(self):
        old = self._with_request_schema()
        new = copy.deepcopy(old)
        new["components"]["schemas"]["ChargeRequest"]["required"] = ["amount", "note"]
        found = {f.kind for f in run(old, new).breaking}
        self.assertIn("schema_field_now_required", found)

    def test_newly_required_in_a_response_schema_is_not_breaking(self):
        # `Card` is response-only in the fixture.
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        new["components"]["schemas"]["Card"]["required"] = ["id", "iin"]
        kinds_found = {f.kind for f in run(old, new).findings}
        self.assertNotIn("schema_field_now_required", kinds_found,
                         "receiving a guaranteed field does not break a caller")

    def test_removing_a_response_field_stays_breaking(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        del new["components"]["schemas"]["Card"]["properties"]["iin"]
        self.assertIn("schema_field_removed",
                      {f.kind for f in run(old, new).breaking})

    def test_removing_a_request_only_field_is_downgraded(self):
        old = self._with_request_schema()
        new = copy.deepcopy(old)
        del new["components"]["schemas"]["ChargeRequest"]["properties"]["note"]
        result = run(old, new)
        self.assertNotIn("schema_field_removed",
                         {f.kind for f in result.breaking})
        self.assertIn("schema_field_removed",
                      {f.kind for f in result.potentially_breaking})


class TestReachability(unittest.TestCase):
    """A schema is visible from an operation that reaches it indirectly."""

    def _doc(self):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Wallet"] = {
            "type": "object",
            "properties": {"primary": {"$ref": "#/components/schemas/Card"}},
        }
        doc["paths"]["/wallets"] = {"get": {
            "operationId": "listWallets",
            "responses": {"200": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Wallet"}}}}}}}
        return doc

    def test_transitive_reference_is_reachable(self):
        # GET /wallets names only Wallet, and Wallet names Card.
        reach = spec(self._doc()).reachable
        self.assertIn("GET /wallets", reach["Card"],
                      "Card must be reachable through Wallet")
        self.assertIn("GET /wallets", reach["Wallet"])

    def test_a_cycle_terminates_and_does_not_double_count(self):
        doc = self._doc()
        # Card points back at Wallet: the graph now has a cycle.
        doc["components"]["schemas"]["Card"]["properties"]["wallet"] = {
            "$ref": "#/components/schemas/Wallet"}
        reach = spec(doc).reachable
        self.assertIn("GET /wallets", reach["Card"])
        self.assertEqual(len(reach["Card"]), len(set(reach["Card"])),
                         "operations must not be listed twice")

    def test_direct_reach_is_smaller_than_transitive_reach(self):
        """"589 of 589 operations" is true and useless; bound it."""
        doc = self._doc()
        # GET /wallets roots at Wallet (hop 0), Wallet -> Card (1),
        # Card -> Bank (2), Bank -> Deep (3). The bound admits two hops.
        doc["components"]["schemas"]["Card"]["properties"]["bank"] = {
            "$ref": "#/components/schemas/Bank"}
        doc["components"]["schemas"]["Deep"] = {
            "type": "object", "properties": {"v": {"type": "string"}}}
        doc["components"]["schemas"]["Bank"]["properties"]["deep"] = {
            "$ref": "#/components/schemas/Deep"}
        loaded = spec(doc)
        self.assertIn("GET /wallets", loaded.reachable["Deep"],
                      "Deep is reachable transitively")
        self.assertNotIn("GET /wallets", loaded.nearby.get("Deep", []),
                         "Deep is three hops away, past the bound")
        self.assertIn("GET /wallets", loaded.nearby["Bank"],
                      "Bank is two hops away, within the bound")

    def test_an_unreferenced_schema_reaches_nothing(self):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Orphan"] = {
            "type": "object", "properties": {"x": {"type": "string"}}}
        self.assertEqual(spec(doc).reachable.get("Orphan", []), [])


class TestCollapseCounting(unittest.TestCase):
    """`affected_ops` is capped for output size; the COUNT must not be."""

    def test_a_capped_op_list_does_not_shrink_the_count(self):
        from apidrift.diff import Finding
        wide = Finding(
            kind="schema_field_removed", severity=BREAKING,
            op_key="GET /a", path="/a", method="get", detail="x",
            subject="Card.iin", root_cause="Card.iin",
            affected_ops=[f"GET /op{i}" for i in range(200)],
            affected_op_count=589,          # reachability found far more
        )
        collapsed = collapse([wide])[0]
        self.assertEqual(collapsed.affected_op_count, 589,
                         "the stored list is truncated, the count is not")

    def test_the_detail_line_quotes_the_authoritative_count(self):
        from apidrift.diff import Finding
        wide = Finding(
            kind="schema_field_removed", severity=BREAKING,
            op_key="GET /a", path="/a", method="get", detail="x was removed",
            subject="Card.iin", root_cause="Card.iin",
            affected_ops=[f"GET /op{i}" for i in range(200)],
            affected_op_count=589,
        )
        collapsed = collapse([wide])[0]
        self.assertIn("589 operations", collapsed.detail)
        self.assertNotIn("200 operations", collapsed.detail)

    def test_the_count_never_undercounts_merged_members(self):
        from apidrift.diff import Finding
        members = [
            Finding(kind="schema_field_removed", severity=BREAKING,
                    op_key=f"GET /op{i}", path=f"/op{i}", method="get",
                    detail="x", subject="Card.iin", root_cause="Card.iin")
            for i in range(4)
        ]
        collapsed = collapse(members)[0]
        self.assertEqual(collapsed.affected_op_count, 4)


class TestUnionArmNaming(unittest.TestCase):
    """Arm identity must not depend on arm order.

    With schema diffing carrying most of the load this is no longer visible
    through a whole-spec diff, so the contract is asserted directly rather than
    left to a test that would pass either way.
    """

    @staticmethod
    def _flatten(arms):
        from apidrift.loader import Resolver, flatten_schema
        doc = {"components": {"schemas": {
            "A": {"type": "object", "properties": {"x": {"type": "string"}}},
            "B": {"type": "object", "properties": {"y": {"type": "string"}}},
            "C": {"type": "object", "properties": {"z": {"type": "string"}}},
        }}}
        schema = {"anyOf": [{"$ref": f"#/components/schemas/{a}"} for a in arms]}
        return set(flatten_schema(schema, Resolver(doc), "root"))

    def test_arm_paths_are_independent_of_order(self):
        self.assertEqual(self._flatten(["A", "B"]), self._flatten(["B", "A"]))

    def test_inserting_an_arm_leaves_the_others_untouched(self):
        before = self._flatten(["A", "B"])
        after = self._flatten(["C", "A", "B"])
        self.assertTrue(before.issubset(after),
                        "inserting an arm rewrote the paths of its siblings")


class TestRootCauseCollapse(unittest.TestCase):
    def test_shared_schema_change_collapses_to_one_finding(self):
        """One edit seen as a schema change and as a route change is one finding."""
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        del new["components"]["schemas"]["Card"]["properties"]["iin"]
        raw = diff_specs("test", spec(old), spec(new), {})
        removals_raw = [f for f in raw.findings
                        if f.kind.endswith("field_removed")]
        collapsed = [f for f in collapse(raw.findings)
                     if f.kind.endswith("field_removed")]
        self.assertGreater(len(removals_raw), 1,
                           "fixture must produce both views to prove merging")
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0].root_cause, "Card.iin")
        self.assertEqual(collapsed[0].severity, BREAKING,
                         "losing a field breaks every consumer reading it")

    def test_root_cause_key_is_route_independent(self):
        self.assertEqual(root_cause_key("error.source<Card>.iin"), "Card.iin")
        self.assertEqual(root_cause_key("a<X>.b<Card>.iin"), "Card.iin")
        self.assertEqual(root_cause_key("data[].id"), "data[].id")

    def test_root_cause_skips_synthetic_arm_markers(self):
        # An anonymous enum/shape arm is not the thing that changed.
        self.assertEqual(
            root_cause_key("<Response>.service_tier<enum-3410da5c>"),
            "Response.service_tier")
        self.assertEqual(
            root_cause_key("<ConversationItem><MCPToolCall>.error<string>"),
            "MCPToolCall.error")
        self.assertEqual(root_cause_key("<shape-abc12345>.field"), "field")


class TestSignatures(unittest.TestCase):
    def test_signatures_include_path_and_field_literals(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        new["paths"]["/charges"]["get"]["parameters"][0]["required"] = True
        result = run(old, new)
        finding = next(f for f in result.findings if f.kind == "param_now_required")
        sigs = build_signatures(finding, get("stripe"))
        self.assertIn("/charges", sigs)
        self.assertTrue(any("limit" in s for s in sigs),
                        f"param name missing from signatures: {sigs}")

    def test_stripe_sdk_idioms_are_emitted(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        del new["paths"]["/refunds/{id}"]
        finding = next(f for f in run(old, new).findings if f.kind == "endpoint_removed")
        sigs = build_signatures(finding, get("stripe"))
        self.assertTrue(any(s.startswith("stripe.") for s in sigs),
                        f"no stripe SDK idiom in {sigs}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestFieldRelocation(unittest.TestCase):
    """A schema is an implementation detail; a caller only sees the operation.

    OpenAI removed `ResponseProperties.reasoning` while `POST /responses` kept
    accepting `reasoning` throughout -- the field moved to another arm of the
    same `allOf`. Diffing schemas in isolation reported every caller passing
    `reasoning=` as broken. Five of eighty-four breaking findings were this.
    """

    def _spec(self, home: str) -> dict:
        """`/thing` responds with allOf[Head, Tail]; `mode` lives in `home`."""
        doc = {
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "servers": [{"url": "https://api.test.com"}],
            "components": {"schemas": {
                "Head": {"type": "object",
                         "properties": {"id": {"type": "string"}}},
                "Tail": {"type": "object",
                         "properties": {"note": {"type": "string"}}},
            }},
            "paths": {"/thing": {"get": {
                "operationId": "getThing",
                "responses": {"200": {"content": {"application/json": {"schema": {
                    "allOf": [{"$ref": "#/components/schemas/Head"},
                              {"$ref": "#/components/schemas/Tail"}],
                }}}}},
            }}},
        }
        if home:
            doc["components"]["schemas"][home]["properties"]["mode"] = {
                "type": "string"}
        return doc

    def _kinds_for_mode(self, old: dict, new: dict) -> list:
        return [f.kind for f in run(old, new).findings if "mode" in f.subject]

    def test_a_field_moving_between_arms_is_not_a_removal(self):
        found = self._kinds_for_mode(self._spec("Head"), self._spec("Tail"))
        self.assertEqual(found, [],
                         "the operation still exposes `mode`; nobody broke")

    def test_a_field_leaving_the_operation_entirely_is_still_a_removal(self):
        """The control. Without it the suppression could hide everything."""
        found = self._kinds_for_mode(self._spec("Head"), self._spec(""))
        self.assertIn("schema_field_removed", found)

    def test_a_schema_no_operation_reaches_is_not_silently_suppressed(self):
        """Invisible is not the same as unchanged.

        Suppression is only valid as a POSITIVE observation that the field is
        still there. A schema no operation reaches supports no observation at
        all, so the change has to be reported, not assumed harmless.
        """
        old = self._spec("Head")
        old["components"]["schemas"]["Orphan"] = {
            "type": "object", "properties": {"mode": {"type": "string"}}}
        new = copy.deepcopy(old)
        del new["components"]["schemas"]["Orphan"]["properties"]["mode"]
        subjects = [f.subject for f in run(old, new).findings]
        self.assertIn("Orphan.mode", subjects)


class TestPositionalParameters(unittest.TestCase):
    """A path parameter's name is substituted into the URL and never sent.

    So its name appearing or disappearing is either a rename -- the URL is
    unchanged -- or a real change of path SHAPE, which comparing the templates
    already reports. Twilio renaming `{ConversationSid}` to `{ConversationId}`
    produced a `param_removed` and a `param_added_required` for one edit that
    breaks nobody. Query parameters are the opposite: their names go on the
    wire, so losing one is a real event.
    """

    def _op(self, param_name: str, location: str = "path") -> dict:
        return {
            "openapi": "3.0.3",
            "info": {"title": "T", "version": "1"},
            "servers": [{"url": "https://api.test.com"}],
            "paths": {"/thing/{id}": {"get": {
                "operationId": "getThing",
                "parameters": [
                    {"name": "id", "in": "path", "required": True,
                     "schema": {"type": "string"}},
                    {"name": param_name, "in": location, "required": True,
                     "schema": {"type": "string"}},
                ],
                "responses": {"200": {"content": {"application/json": {
                    "schema": {"type": "object",
                               "properties": {"ok": {"type": "boolean"}}}}}}},
            }}},
        }

    def test_renaming_a_path_parameter_reports_nothing(self):
        # Every severity, not just breaking: a downgraded false positive is
        # still a false positive, and `kinds()` filters to breaking by default.
        result = run(self._op("Sid"), self._op("Ident"))
        found = {f.kind for f in result.findings}
        self.assertNotIn("param_removed", found)
        self.assertNotIn("param_added_required", found)

    def test_renaming_a_query_parameter_is_still_reported(self):
        """The control. Query names go on the wire; losing one is real."""
        result = run(self._op("Sid", "query"), self._op("Ident", "query"))
        found = {f.kind for f in result.findings}
        self.assertIn("param_removed", found)
        self.assertIn("param_added_required", found)


class TestProseIsNotAPI(unittest.TestCase):
    """A reworded description is an edit to prose, not to the API.

    `Field` now carries the vendor's own sentence so a SUGGESTION can say what
    a new field is for instead of only naming it. `Field` is a frozen
    dataclass, so `==` compares that sentence too — and the moment anything
    compares two Fields directly, every vendor copy-edit becomes a finding.
    Nothing does today. This test is what keeps it that way.
    """

    def test_rewording_a_description_changes_nothing(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["components"]["schemas"]["Card"]["properties"]["iin"][
            "description"] = "The issuer identification number."
        new["components"]["schemas"]["Card"]["properties"]["iin"][
            "description"] = "Issuer Identification Number (first 8 digits)."
        result = run(old, new)
        self.assertEqual([f.kind for f in result.findings], [],
                         "a copy-edit is not an API change")
        self.assertEqual([a.kind for a in result.additions], [])

    def test_the_shape_projection_never_carries_prose(self):
        """The invariant, tested where it lives.

        Going through the diff cannot test this: a description-only edit never
        enters a comparison branch at all, so every mutation stays green. The
        protection is that `_field_shape` projects a field down to what a
        consumer can observe, and prose is not observable.
        """
        from apidrift.diff import _field_shape
        from apidrift.loader import Field
        empty = spec(copy.deepcopy(BASE))
        a = Field(type="string", required=False, nullable=False,
                  description="The issuer identification number.")
        b = Field(type="string", required=False, nullable=False,
                  description="Issuer Identification Number (first 8 digits).")
        self.assertNotEqual(a, b, "the Fields really do differ")
        self.assertEqual(_field_shape(a, empty), _field_shape(b, empty),
                         "but what a consumer sees is identical")

    def test_the_description_is_still_carried_for_suggestions(self):
        """The control: the sentence must actually survive to the addition."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        new["components"]["schemas"]["Card"]["properties"]["network"] = {
            "type": "string",
            "description": "The card network that will process the payment.",
        }
        added = [a for a in run(old, new).additions
                 if a.subject == "Card.network"]
        self.assertTrue(added, "a new optional field is an addition")
        self.assertIn("card network", added[0].blurb.lower())


class TestSchemaRemovalIsObservable(unittest.TestCase):
    """A schema NAME never travels on the wire.

    The same fact that made a field moving between schemas a non-event and a
    path-parameter rename a non-event was never applied to the schema itself.
    Measured across 21 vendors, 694 of 1007 `schema_removed` findings described
    nothing a caller could observe, and the precision checker agreed with every
    one of them because it asked the engine's own question -- "is the name
    still in components/schemas?" -- which is the spec author's question.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def _removed(self, result):
        return {f.subject for f in result.findings if f.kind == "schema_removed"}

    # -- still reported ----------------------------------------------------

    def test_a_reachable_schema_removal_is_still_reported(self):
        """The control. If this ever goes quiet the suppressors have eaten the
        signal, and every test below would pass over a dead engine."""
        del self.new["components"]["schemas"]["Card"]
        self.assertIn("Card", self._removed(run(self.old, self.new)))

    # -- unreachable -------------------------------------------------------

    def test_a_schema_no_operation_reaches_is_not_a_break(self):
        """Sentry publishes a dereferenced spec whose whole components table is
        vestigial: 25 of 25 of its removals reached no operation at all."""
        self.old["components"]["schemas"]["Ghost"] = {
            "type": "object", "properties": {"x": {"type": "string"}}}
        self.assertNotIn("Ghost", self._removed(run(self.old, self.new)))

    def test_unreachable_is_not_claimed_when_nothing_is_reachable(self):
        """The control for the control.

        On a document that links nothing, EVERY schema looks unreachable, so
        the test is satisfied by 100% of inputs and measures nothing. Refusing
        to suppress there is what keeps a dereferenced spec's real breaks --
        Sentry inlines each schema body straight into the operation.
        """
        for doc in (self.old, self.new):
            doc["paths"] = {"/ping": {"get": {
                "operationId": "ping",
                "responses": {"200": {"content": {"application/json": {
                    "schema": {"type": "object",
                               "properties": {"ok": {"type": "boolean"}}}}}}}}}}
        del self.new["components"]["schemas"]["Card"]
        result = run(self.old, self.new)
        self.assertIn("Card", self._removed(result))
        self.assertIn("unreachable_unmeasurable", result.suppressed)

    # -- dereferenced documents: reachability by BODY, not by name ---------
    #
    # Abstaining on a dereferenced document is honest but it is not an answer,
    # and it was 25 of the 337 UNDECIDABLE findings across 21 vendors. What a
    # caller sees is the operation's inline body, so ask where that body
    # appears. Sentry's whole `components/schemas` table is a parallel copy of
    # bodies that are also written out inside the operations.

    def _derefed(self, schemas, paths):
        """A document with schemas, operations, and not one `$ref`."""
        return {"openapi": "3.0.3", "info": {"title": "t", "version": "1"},
                "servers": [{"url": "https://api.test.com/v1"}],
                "components": {"schemas": copy.deepcopy(schemas)},
                "paths": copy.deepcopy(paths)}

    GHOST = {"type": "object", "required": ["id", "label"],
             "properties": {"id": {"type": "string"},
                            "label": {"type": "string"}}}

    @staticmethod
    def _op(body):
        return {"get": {"operationId": "read", "responses": {"200": {
            "content": {"application/json": {"schema": copy.deepcopy(body)}}}}}}

    def test_a_dereferenced_removal_whose_BODY_changed_is_still_reported(self):
        """The break this rule had to be built around.

        `DetailedOrganizationSerializerWithProjectsAndTeams` is verbatim the
        200 body of a PUT that still exists and lost seven required response
        properties. Any rule that suppresses on a dereferenced document
        without looking at the body would delete it.
        """
        thinner = {"type": "object", "required": ["id"],
                   "properties": {"id": {"type": "string"}}}
        old = self._derefed({"Ghost": self.GHOST}, {"/g": self._op(self.GHOST)})
        new = self._derefed({}, {"/g": self._op(thinner)})
        result = run(old, new)
        self.assertIn("Ghost", self._removed(result))
        self.assertNotIn("unreachable_unmeasurable", result.suppressed)

    def test_a_dereferenced_removal_still_inlined_unchanged_is_not_a_break(self):
        """Sentry's `Organization`: ten inline sites, all still identical. The
        components entry went; the wire did not move."""
        old = self._derefed({"Ghost": self.GHOST}, {"/g": self._op(self.GHOST)})
        new = self._derefed({}, {"/g": self._op(self.GHOST)})
        result = run(old, new)
        self.assertNotIn("Ghost", self._removed(result))

    def test_a_dereferenced_removal_only_on_a_removed_operation_is_not_a_break(self):
        """Twenty-two of Sentry's twenty-five. The operation itself is gone,
        `endpoint_removed` reports that, and the schema is not a second
        break -- the same reasoning the `carrying` filter already applies."""
        keep = {"type": "object", "properties": {"z": {"type": "string"}}}
        old = self._derefed({"Ghost": self.GHOST, "Keep": keep},
                            {"/g": self._op(self.GHOST), "/k": self._op(keep)})
        new = self._derefed({"Keep": keep}, {"/k": self._op(keep)})
        result = run(old, new)
        self.assertNotIn("Ghost", self._removed(result))
        self.assertIn("endpoint_removed", {f.kind for f in result.findings})

    def test_a_dereferenced_body_that_appears_nowhere_is_unreachable(self):
        """The precision half of body matching.

        Matching by VALUE must not invent reachability. `Ghost`'s body is
        written nowhere under `paths` while `Keep`'s is, so the control has
        fired and the honest verdict is the ordinary `unreachable` one -- the
        same verdict the independent checker reaches from the raw document.
        """
        keep = {"type": "object", "properties": {"z": {"type": "string"}}}
        old = self._derefed({"Ghost": self.GHOST, "Keep": keep},
                            {"/k": self._op(keep)})
        new = self._derefed({"Keep": keep}, {"/k": self._op(keep)})
        result = run(old, new)
        self.assertNotIn("Ghost", self._removed(result))
        self.assertEqual(1, result.suppressed.get("unreachable"),
                         "unreachable, not reachable-through-a-body-it-lacks")

    def test_body_matching_is_NOT_applied_to_a_document_that_links(self):
        """The guard. Where references exist they are exact and cheaper, and a
        body that merely coincides with a schema nobody named must not invent
        reachability. `Ghost` is an orphan here even though its body is
        written out inside a live operation."""
        linked = copy.deepcopy(BASE)
        linked["components"]["schemas"]["Ghost"] = {
            "type": "object", "properties": {"solo": {"type": "string"}}}
        linked["paths"]["/ghosts"] = {"get": {
            "operationId": "ghosts", "responses": {"200": {"content": {
                "application/json": {"schema": {
                    "type": "object",
                    "properties": {"solo": {"type": "string"}}}}}}}}}
        new = copy.deepcopy(linked)
        del new["components"]["schemas"]["Ghost"]
        result = run(linked, new)
        self.assertNotIn("Ghost", self._removed(result))
        self.assertEqual(1, result.suppressed.get("unreachable"))

    # -- relocated ---------------------------------------------------------

    def test_a_schema_inlined_at_its_only_use_site_is_not_a_break(self):
        """Klaviyo stopped naming single-value enum schemas and inlined them at
        the identical property. The bytes are identical."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["brand"] = {
                "$ref": "#/components/schemas/Brand"}
            doc["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
        del self.new["components"]["schemas"]["Brand"]
        self.new["components"]["schemas"]["Card"]["properties"]["brand"] = {
            "type": "string", "enum": ["visa", "amex"]}
        result = run(self.old, self.new)
        self.assertNotIn("Brand", self._removed(result))
        self.assertEqual(1, result.suppressed.get("relocated"))

    def test_inlining_a_DIFFERENT_shape_is_still_a_break(self):
        """The mirror of the test above. If the inlined value is not the same
        thing, the name going away is the least of it."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["brand"] = {
                "$ref": "#/components/schemas/Brand"}
            doc["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
        del self.new["components"]["schemas"]["Brand"]
        self.new["components"]["schemas"]["Card"]["properties"]["brand"] = {
            "type": "string", "enum": ["visa"]}
        self.assertIn("Brand", self._removed(run(self.old, self.new)))

    def test_an_unrelated_field_changing_in_the_parent_is_not_this_break(self):
        """The precision half of the parent loop. Only the properties that
        actually reached the removed schema may be compared: a sibling field
        changing in the same release is its own finding, and folding it in
        here would report every restructure once per neighbouring schema."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["brand"] = {
                "$ref": "#/components/schemas/Brand"}
            doc["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
        del self.new["components"]["schemas"]["Brand"]
        self.new["components"]["schemas"]["Card"]["properties"]["brand"] = {
            "type": "string", "enum": ["visa", "amex"]}
        # ...and a SIBLING changed, which has nothing to do with `Brand`.
        self.new["components"]["schemas"]["Card"]["properties"]["iin"] = {
            "type": "integer"}
        result = run(self.old, self.new)
        self.assertNotIn("Brand", self._removed(result))

    def test_a_schema_inlined_at_an_ARRAYS_ITEMS_is_not_a_break(self):
        """Klaviyo's `Constant_contactEnum` is never a property's TYPE. It is
        the `items` of `ConstantContactIntegrationFilter.value`, so a loop that
        only read `field.type` compared nothing and the flattener reported the
        inlined element as a bare "string" with its enum gone."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["brands"] = {
                "type": "array", "items": {"$ref": "#/components/schemas/Brand"}}
            doc["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
        del self.new["components"]["schemas"]["Brand"]
        self.new["components"]["schemas"]["Card"]["properties"]["brands"] = {
            "type": "array", "items": {"type": "string",
                                       "enum": ["visa", "amex"]}}
        result = run(self.old, self.new)
        self.assertNotIn("Brand", self._removed(result))
        self.assertEqual(1, result.suppressed.get("relocated"))

    def test_inlining_a_DIFFERENT_item_shape_is_still_a_break(self):
        """The mirror. An element enum that lost a value is not the same
        element, and the inlining must not launder it."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["brands"] = {
                "type": "array", "items": {"$ref": "#/components/schemas/Brand"}}
            doc["components"]["schemas"]["Brand"] = {
                "type": "string", "enum": ["visa", "amex"]}
        del self.new["components"]["schemas"]["Brand"]
        self.new["components"]["schemas"]["Card"]["properties"]["brands"] = {
            "type": "array", "items": {"type": "string", "enum": ["visa"]}}
        self.assertIn("Brand", self._removed(run(self.old, self.new)))

    def test_a_named_array_inlined_is_not_a_break_when_its_ELEMENT_changed(self):
        """PayPal inlined `billing_cycle_list` at the identical property and,
        in the same release, edited `billing_cycle` -- which the array points
        AT. Resolving the element made the pure inlining compare unequal, so a
        second change to a second schema was reported a second time against a
        schema that is byte-identical where it is used. That element change is
        its own finding against its own schema."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["CardList"] = {
                "type": "array", "items": {"$ref": "#/components/schemas/Card"}}
            doc["components"]["schemas"]["Bank"]["properties"]["cards"] = {
                "$ref": "#/components/schemas/CardList"}
        del self.new["components"]["schemas"]["CardList"]
        self.new["components"]["schemas"]["Bank"]["properties"]["cards"] = {
            "type": "array", "items": {"$ref": "#/components/schemas/Card"}}
        # ...and the ELEMENT changed, separately.
        self.new["components"]["schemas"]["Card"]["properties"]["issuer"] = {
            "type": "string"}
        result = run(self.old, self.new)
        self.assertNotIn("CardList", self._removed(result))

    def test_inlining_a_named_array_as_a_DIFFERENT_array_is_still_a_break(self):
        """The mirror of the notation escape: same notation is the whole
        licence, and an array that changed what it holds does not have it."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["CardList"] = {
                "type": "array", "items": {"$ref": "#/components/schemas/Card"}}
            doc["components"]["schemas"]["Bank"]["properties"]["cards"] = {
                "$ref": "#/components/schemas/CardList"}
        del self.new["components"]["schemas"]["CardList"]
        self.new["components"]["schemas"]["Bank"]["properties"]["cards"] = {
            "type": "array", "items": {"$ref": "#/components/schemas/Bank"}}
        self.assertIn("CardList", self._removed(run(self.old, self.new)))

    def _brands(self, items):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Card"]["properties"]["brands"] = {
            "type": "array", "items": items}
        loaded = spec(doc)
        return loaded, loaded.schemas["Card"].fields["brands"]

    def test_the_shape_projection_carries_an_INLINE_items_enum(self):
        """The other half of carrying the element's enum, tested where the
        comparison actually happens.

        `_item_type` reported `items: {type: string, enum: [...]}` as plain
        "string", so an array's element enum was invisible in BOTH directions:
        Twilio narrowing one read as no change at all, and a named enum schema
        inlined at that position read as a change when nothing had moved.
        """
        from apidrift.diff import _field_shape
        wide, a = self._brands({"type": "string", "enum": ["visa", "amex"]})
        narrow, b = self._brands({"type": "string", "enum": ["visa"]})
        self.assertNotEqual(_field_shape(a, wide), _field_shape(b, narrow),
                            "narrowing the element enum is a different shape")
        named_doc = copy.deepcopy(BASE)
        named_doc["components"]["schemas"]["BrandEnum"] = {
            "type": "string", "enum": ["visa", "amex"]}
        named_doc["components"]["schemas"]["Card"]["properties"]["brands"] = {
            "type": "array", "items": {"$ref": "#/components/schemas/BrandEnum"}}
        named = spec(named_doc)
        self.assertEqual(
            _field_shape(a, wide),
            _field_shape(named.schemas["Card"].fields["brands"], named),
            "a named element enum and its inlined body are the same thing")

    # -- renamed at an operation root --------------------------------------

    def test_a_root_schema_renamed_to_an_identical_shape_is_not_a_break(self):
        """Cloudflare renamed its response envelopes in bulk: 191 removals were
        `x_components-schemas-api-response-common-failure` becoming
        `x_api-response-common-failure-3` at the same operation with the same
        body."""
        self.new["components"]["schemas"]["CardV2"] = copy.deepcopy(
            self.new["components"]["schemas"]["Card"])
        del self.new["components"]["schemas"]["Card"]
        self.new["paths"]["/charges"]["post"]["responses"]["200"]["content"][
            "application/json"]["schema"] = {"$ref": "#/components/schemas/CardV2"}
        self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["source"]["anyOf"][0] = {
                "$ref": "#/components/schemas/CardV2"}
        result = run(self.old, self.new)
        self.assertNotIn("Card", self._removed(result))
        self.assertEqual(1, result.suppressed.get("renamed"))

    def test_a_rename_that_also_drops_a_field_is_still_a_break(self):
        """A rename is invisible; a rename plus a deletion is not."""
        self.new["components"]["schemas"]["CardV2"] = copy.deepcopy(
            self.new["components"]["schemas"]["Card"])
        del self.new["components"]["schemas"]["CardV2"]["properties"]["iin"]
        del self.new["components"]["schemas"]["Card"]
        self.new["paths"]["/charges"]["post"]["responses"]["200"]["content"][
            "application/json"]["schema"] = {"$ref": "#/components/schemas/CardV2"}
        self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["source"]["anyOf"][0] = {
                "$ref": "#/components/schemas/CardV2"}
        self.assertIn("Card", self._removed(run(self.old, self.new)))

    # -- direction: a whole schema travels ONE way -------------------------

    def _request_only(self):
        """`/charges` POST sends a `ChargeRequest` whose property names also
        appear in the 200 response it reads back. Auth0's
        `AddOrganizationConnectionRequestContent` is exactly this."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["ChargeRequest"] = {
                "type": "object", "required": ["id"],
                "properties": {"id": {"type": "string"},
                               "iin": {"type": "string"}}}
            doc["paths"]["/charges"]["post"]["requestBody"]["content"][
                "application/json"]["schema"] = {
                    "$ref": "#/components/schemas/ChargeRequest"}

    def test_replacing_a_request_body_outright_is_still_a_break(self):
        """The recall control injected exactly this into Auth0's real spec and
        came back MISSED: `id` and `iin` are also response property names on
        the same operation, so a merged name map said "still all there" while
        the request body had become a bare string. Nothing was reported at
        all."""
        self._request_only()
        del self.new["components"]["schemas"]["ChargeRequest"]
        self.new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {"type": "string"}
        self.assertIn("ChargeRequest", self._removed(run(self.old, self.new)))

    def test_a_request_schema_relocated_WITHIN_the_request_is_not_a_break(self):
        """The other half. Direction narrows the question; it must not disable
        the suppressor -- the names are still sent the same way."""
        self._request_only()
        del self.new["components"]["schemas"]["ChargeRequest"]
        self.new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {
                "type": "object", "required": ["id"],
                "properties": {"id": {"type": "string"},
                               "iin": {"type": "string"}}}
        result = run(self.old, self.new)
        self.assertNotIn("ChargeRequest", self._removed(result))

    # -- subsumed ----------------------------------------------------------

    def test_a_removal_reachable_only_through_another_removal_is_reported_once(self):
        """PayPal's `error_409` lived only inside `error_default`, and both went
        in the same release. One restructure is one finding, not ninety-two."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Inner"] = {
                "type": "object", "properties": {"code": {"type": "string"}}}
            doc["components"]["schemas"]["Outer"] = {
                "type": "object",
                "properties": {"inner": {"$ref": "#/components/schemas/Inner"}}}
            doc["paths"]["/charges"]["get"]["responses"]["200"]["content"][
                "application/json"]["schema"]["properties"]["envelope"] = {
                    "$ref": "#/components/schemas/Outer"}
        del self.new["components"]["schemas"]["Inner"]
        del self.new["components"]["schemas"]["Outer"]
        del self.new["paths"]["/charges"]["get"]["responses"]["200"]["content"][
            "application/json"]["schema"]["properties"]["envelope"]
        removed = self._removed(run(self.old, self.new))
        self.assertIn("Outer", removed)
        self.assertNotIn("Inner", removed)

    # -- the pseudo-operation ----------------------------------------------

    def test_a_schema_carrier_is_never_counted_as_an_affected_operation(self):
        """`GET #/components/schemas/X` is a carrier minted so schema findings
        can reuse the Finding shape. Counting it meant a schema reachable from
        ZERO operations still reported `affected_op_count: 1`, naming an
        operation that exists in no spec. A count of affected operations has to
        be able to reach zero or it can never say "this affects nobody".

        Written against the DEREFERENCED case on purpose: that is the only path
        that still emits a finding with no real operation behind it. The first
        version of this test used a reachable schema, whose `op_key` is
        rewritten to a real operation before the count is taken -- so it passed
        with the bug present and killed no mutation. A test that cannot fail is
        not a test.
        """
        for doc in (self.old, self.new):
            doc["paths"] = {"/ping": {"get": {
                "operationId": "ping",
                "responses": {"200": {"content": {"application/json": {
                    "schema": {"type": "object",
                               "properties": {"ok": {"type": "boolean"}}}}}}}}}}
        del self.new["components"]["schemas"]["Card"]
        card = [f for f in run(self.old, self.new).findings
                if f.kind == "schema_removed" and f.subject == "Card"][0]
        self.assertTrue(all("#/components/schemas/" not in op
                            for op in card.affected_ops),
                        f"pseudo-operation leaked into {card.affected_ops}")
        self.assertEqual(0, card.affected_op_count,
                         "a schema no operation reaches affects zero operations")


class TestNotationIsNotSemantics(unittest.TestCase):
    """Three ways of writing the same thing that read as three changes.

    All of the same family as `c97be9d`: a caller sees a contract, not the
    spelling a generator happened to emit this quarter. Each of these produced
    findings on Cloudflare in the 180-day window and none of them moved a byte.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def test_a_bare_ref_schema_is_an_alias_for_its_target(self):
        """`magic_interconnect_health_check` is `{"$ref": ".../health_check_base"}`
        in BOTH versions. Only which of the two names a property spelled moved."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["CardAlias"] = {
                "$ref": "#/components/schemas/Card"}
        self.old["components"]["schemas"]["Bank"]["properties"]["card"] = {
            "$ref": "#/components/schemas/CardAlias"}
        self.new["components"]["schemas"]["Bank"]["properties"]["card"] = {
            "$ref": "#/components/schemas/Card"}
        self.assertNotIn("schema_field_type_changed", kinds(run(self.old, self.new)))

    def test_an_inline_array_and_a_named_array_of_the_same_item_agree(self):
        """Cloudflare extracted `{"type": "array", "items": {"type": "string"}}`
        into `builds_path_excludes`, which is the same array."""
        self.old["components"]["schemas"]["Card"]["properties"]["tags"] = {
            "type": "array", "items": {"type": "string"}}
        self.new["components"]["schemas"]["Tags"] = {
            "type": "array", "items": {"type": "string"}}
        self.new["components"]["schemas"]["Card"]["properties"]["tags"] = {
            "$ref": "#/components/schemas/Tags"}
        self.assertNotIn("schema_field_type_changed", kinds(run(self.old, self.new)))

    def test_an_array_whose_ITEM_type_changed_is_NOT_the_same_shape(self):
        """The mirror, asserted where the behaviour actually lives.

        The first version of this went through the whole pipeline and passed
        with the item type deleted, because the ROUTE diff catches it
        independently -- so it killed neither mutation and proved nothing about
        `_field_shape`. Calling both sides "array" and stopping there is how an
        array-of-string and an array-of-object would compare equal, and this is
        the comparison that has to refuse them.
        """
        from apidrift.diff import _field_shape
        old_spec = spec(self.old)
        strings = spec({**self.old, "components": {**self.old["components"], "schemas": {
            **self.old["components"]["schemas"],
            "Card": {"type": "object", "properties": {
                "tags": {"type": "array", "items": {"type": "string"}}}}}}})
        integers = spec({**self.new, "components": {**self.new["components"], "schemas": {
            **self.new["components"]["schemas"],
            "Card": {"type": "object", "properties": {
                "tags": {"type": "array", "items": {"type": "integer"}}}}}}})
        of_string = _field_shape(strings.schemas["Card"].fields["tags"], strings)
        of_integer = _field_shape(integers.schemas["Card"].fields["tags"], integers)
        self.assertIsNotNone(of_string, "an array of a known item type is comparable")
        self.assertNotEqual(of_string, of_integer,
                            "an array of string is not an array of integer")
        del old_spec

    def test_a_single_arm_allOf_around_a_parameter_ref_is_that_ref(self):
        """A vendor wraps `$ref` in `allOf` to attach a sibling keyword, which
        OpenAPI 3.0 would otherwise ignore. Cloudflare unwrapping ten of its own
        sorting enums read as `object -> string` ten times."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["SortDir"] = {
                "type": "string", "enum": ["asc", "desc"]}
        self.old["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "direction", "in": "query", "required": False,
             "schema": {"allOf": [{"$ref": "#/components/schemas/SortDir"}]}})
        self.new["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "direction", "in": "query", "required": False,
             "schema": {"type": "string", "enum": ["asc", "desc"]}})
        self.assertNotIn("param_type_changed", kinds(run(self.old, self.new)))

    def test_a_parameter_whose_type_really_changed_is_still_a_break(self):
        """The control for the test above."""
        self.old["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "cursor", "in": "query", "required": False,
             "schema": {"type": "string"}})
        self.new["paths"]["/charges"]["get"]["parameters"].append(
            {"name": "cursor", "in": "query", "required": False,
             "schema": {"type": "integer"}})
        self.assertIn("param_type_changed", kinds(run(self.old, self.new)))


class TestDiscriminatorMapping(unittest.TestCase):
    """`discriminator.mapping` names subtypes with a bare pointer STRING.

    The only reference form in OpenAPI that is not a `{"$ref": ...}` object, so
    a walk looking for the object form goes straight past it. The word
    `discriminator` did not appear anywhere in this codebase until an
    adversarial audit found Adyen's `Resource`, whose subtypes
    `BalanceAccountResource` and `MerchantAccountResource` have exactly one
    reference each in the whole document -- a mapping value. Blind to it, they
    were called orphans and their removal suppressed.
    """

    def _doc(self):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Resource"] = {
            "type": "object",
            "properties": {"type": {"type": "string"}},
            "discriminator": {
                "propertyName": "type",
                "mapping": {"card": "#/components/schemas/CardResource"},
            },
        }
        doc["components"]["schemas"]["CardResource"] = {
            "type": "object", "properties": {"pan": {"type": "string"}}}
        doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]["properties"]["resource"] = {
                "$ref": "#/components/schemas/Resource"}
        return doc

    def test_a_subtype_named_only_by_a_mapping_is_reachable(self):
        spec_ = spec(self._doc())
        self.assertTrue(
            spec_.reachable.get("CardResource"),
            "a discriminator mapping is how this subtype is reached at all")

    def test_removing_a_subtype_named_only_by_a_mapping_is_reported(self):
        old, new = self._doc(), self._doc()
        del new["components"]["schemas"]["CardResource"]
        del new["components"]["schemas"]["Resource"]["discriminator"]["mapping"]["card"]
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertIn("CardResource", removed)


class TestSubsumptionGuards(unittest.TestCase):
    """The `not direct` guard on subsumption is load-bearing.

    An operation that names a schema itself can observe its removal no matter
    what happened to the schema's other parents. Without this guard PayPal's
    error_400/401/403/404/409/422/500 all disappear -- each is the declared body
    of a status-coded response on live operations AND an arm of `error_default`
    -- along with twenty Cloudflare schemas that are request surfaces in their
    own right.
    """

    def _paypal_shaped(self):
        """`error_409` as PayPal actually writes it: named directly by an
        operation's 409 response AND listed inside the `error_default` union."""
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Error409"] = {
            "type": "object", "properties": {"issue": {"type": "string"}}}
        doc["components"]["schemas"]["ErrorDefault"] = {
            "oneOf": [{"$ref": "#/components/schemas/Error409"}]}
        doc["paths"]["/charges"]["post"]["responses"]["409"] = {
            "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Error409"}}}}
        doc["paths"]["/charges"]["post"]["responses"]["default"] = {
            "content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/ErrorDefault"}}}}
        return doc

    def test_a_schema_an_operation_names_directly_is_never_subsumed(self):
        old, new = self._paypal_shaped(), self._paypal_shaped()
        del new["components"]["schemas"]["Error409"]
        del new["components"]["schemas"]["ErrorDefault"]
        del new["paths"]["/charges"]["post"]["responses"]["409"]
        del new["paths"]["/charges"]["post"]["responses"]["default"]
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertIn("Error409", removed,
                      "an operation named it directly, so its removal is visible")

    def test_a_self_recursive_schema_is_not_its_own_outer_schema(self):
        """A self-referencing schema satisfies `parents <= removed` with no
        outer schema in existence, so the chain would have no root to be
        reported at and the removal would vanish entirely.

        Asserted against `_removal_is_observable` directly, and deliberately so.
        End to end this input cannot be built: `operation_schema_roots` walks
        the whole request/response subtree, so anything reachable at all is also
        `direct`, and the `not direct` guard blocks the branch first. The guard
        below is therefore defence against a future narrowing of `rooted_at`
        rather than a live defect -- which is exactly why it is pinned here,
        where a mutation can still kill it, instead of behind a pipeline test
        that would stay green either way.
        """
        from apidrift.diff import _removal_is_observable
        old = spec(copy.deepcopy(BASE))
        new = spec(copy.deepcopy(BASE))
        # No operation names it directly -- otherwise the `not direct` guard
        # short-circuits the branch under test and this would pass either way.
        old.rooted_at = {}
        view = old.schemas["Card"]
        observable, reason = _removal_is_observable(
            "Card", view, ops=["GET /charges"], removed={"Card"},
            incoming={"Card": {"Card"}}, old=old, new=new,
            old_names={"GET /charges": {"id"}}, new_names={"GET /charges": set()},
            truncated=set(), reachability_has_signal=True, new_roots={},
        )
        self.assertNotEqual("subsumed", reason,
                            "a schema is not the outer schema that subsumes it")

    def test_a_rename_inside_a_union_arm_is_found_by_what_the_parent_POINTS_AT(self):
        """OpenAI renamed `Conversation-2` to `ResponseConversation` inside the
        `anyOf` of `Response.conversation` -- same `{id: string}`, same
        position, a different name.

        The one-level field map records that property as `anyOf` and nothing
        typed `->Conversation-2`, so the field comparison has nothing to
        compare. Comparing the whole parent does not work either: `Response`
        changed in other ways in the same release, which would call the rename
        a break. What settles it is comparing what the parent POINTS AT.
        """
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        for doc in (old, new):
            doc["components"]["schemas"]["Wrapper"] = {
                "type": "object",
                "properties": {"link": {"anyOf": [
                    {"$ref": "#/components/schemas/Link"}, {"type": "null"}]}},
            }
            doc["components"]["schemas"]["Link"] = {
                "type": "object", "properties": {"id": {"type": "string"}},
                "required": ["id"]}
            doc["paths"]["/charges"]["get"]["responses"]["200"]["content"][
                "application/json"]["schema"]["properties"]["wrapper"] = {
                    "$ref": "#/components/schemas/Wrapper"}
        # Renamed, and the parent independently gains an unrelated field so a
        # whole-parent comparison would refuse.
        new["components"]["schemas"]["LinkV2"] = new["components"]["schemas"].pop("Link")
        new["components"]["schemas"]["Wrapper"]["properties"]["link"]["anyOf"][0] = {
            "$ref": "#/components/schemas/LinkV2"}
        new["components"]["schemas"]["Wrapper"]["properties"]["note"] = {"type": "string"}
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertNotIn("Link", removed)

    def test_a_union_arm_that_changed_shape_is_still_a_break(self):
        """The control for the test above."""
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        for doc in (old, new):
            doc["components"]["schemas"]["Wrapper"] = {
                "type": "object",
                "properties": {"link": {"anyOf": [
                    {"$ref": "#/components/schemas/Link"}, {"type": "null"}]}},
            }
            doc["components"]["schemas"]["Link"] = {
                "type": "object", "properties": {"id": {"type": "string"}},
                "required": ["id"]}
            doc["paths"]["/charges"]["get"]["responses"]["200"]["content"][
                "application/json"]["schema"]["properties"]["wrapper"] = {
                    "$ref": "#/components/schemas/Wrapper"}
        new["components"]["schemas"]["LinkV2"] = {
            "type": "object", "properties": {"uuid": {"type": "string"}},
            "required": ["uuid"]}
        del new["components"]["schemas"]["Link"]
        new["components"]["schemas"]["Wrapper"]["properties"]["link"]["anyOf"][0] = {
            "$ref": "#/components/schemas/LinkV2"}
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertIn("Link", removed)


class TestRenameMatching(unittest.TestCase):
    """An operationId is a label the vendor controls, and vendors recycle them.

    Cloudflare renamed the operationId of
    `POST /accounts/{accountId}/resource-library/applications` and put the
    freed-up `createApplication` on a brand-new, unrelated endpoint
    `POST /accounts/{account_id}/containers/applications`. Matching on the id
    alone paired those two, diffed two different endpoints' response bodies
    against each other, and attributed every unmatched field to an operation
    that does not exist in the old spec -- nine fabricated findings.
    """

    def _cloudflare_shaped(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        body = {"type": "object", "properties": {
            "human_id": {"type": "string"}, "hostnames": {"type": "string"}}}
        old["paths"]["/accounts/{accountId}/resource-library/applications"] = {
            "post": {"operationId": "createApplication",
                     "parameters": [{"name": "accountId", "in": "path",
                                     "required": True,
                                     "schema": {"type": "string"}}],
                     "responses": {"201": {"content": {
                         "application/json": {"schema": body}}}}}}
        # Same URL, parameter renamed, operationId changed.
        new["paths"]["/accounts/{account_id}/resource-library/applications"] = {
            "post": {"operationId": "createResourceLibraryApplication",
                     "parameters": [{"name": "account_id", "in": "path",
                                     "required": True,
                                     "schema": {"type": "string"}}],
                     "responses": {"201": {"content": {
                         "application/json": {"schema": body}}}}}}
        # A genuinely new endpoint that inherited the freed-up operationId.
        new["paths"]["/accounts/{account_id}/containers/applications"] = {
            "post": {"operationId": "createApplication",
                     "parameters": [{"name": "account_id", "in": "path",
                                     "required": True,
                                     "schema": {"type": "string"}}],
                     "responses": {"201": {"content": {"application/json": {
                         "schema": {"type": "object",
                                    "properties": {"id": {"type": "string"}}}}}}}}}
        return old, new

    def test_a_recycled_operationId_does_not_pair_two_different_endpoints(self):
        old, new = self._cloudflare_shaped()
        result = run(old, new)
        fabricated = [f for f in result.findings
                      if "containers/applications" in f.path]
        self.assertEqual(
            [], fabricated,
            "an endpoint absent from the old spec cannot have lost a field")

    def test_the_same_URL_under_a_new_parameter_name_is_still_matched(self):
        """The control. If the URL pass stops matching, a parameter rename
        becomes an endpoint_removed plus an endpoint_added, which is the
        loudest false positive this tool can emit.

        No operationId on either side, deliberately: with one, the id pass
        could rescue the match and this would pass without the URL pass ever
        running.
        """
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        body = {"responses": {"200": {"content": {"application/json": {
            "schema": {"type": "object", "properties": {"id": {"type": "string"}}}}}}}}
        old["paths"]["/widgets/{widgetId}"] = {"get": dict(
            body, parameters=[{"name": "widgetId", "in": "path", "required": True,
                               "schema": {"type": "string"}}])}
        new["paths"]["/widgets/{id}"] = {"get": dict(
            body, parameters=[{"name": "id", "in": "path", "required": True,
                               "schema": {"type": "string"}}])}
        found = {f.kind for f in run(old, new).findings if "widgets" in f.path}
        self.assertNotIn("endpoint_removed", found,
                         "a byte-identical URL with a renamed parameter is not a removal")
        self.assertNotIn("endpoint_moved", found,
                         "nor is it a move -- the URL a caller writes is unchanged")


class TestAllOfCarriesUnions(unittest.TestCase):
    """`allOf: [X]` where X is `anyOf: [A, B]` IS `anyOf: [A, B]`.

    `_merge_all_of` copied properties, required and type from each member and
    dropped a member's union on the floor, so that body merged to `{}` -- no
    properties, no required, no type -- and the flattener reported ZERO fields
    for it. Cloudflare writes its request bodies that way:
    `POST /accounts/{id}/browser-rendering/content` flattened to 0 fields on
    the old side, so every field on the new side read as newly added and newly
    required. There was nothing to collapse, only something to carry through.
    """

    def _union_body(self, second_required):
        return {"allOf": [{"anyOf": [
            {"type": "object",
             "properties": {"username": {"type": "string"},
                            "password": {"type": "string"}},
             "required": ["username", "password"]},
            {"type": "object",
             "properties": {"token": {"type": "string"}},
             "required": second_required},
        ]}]}

    def test_a_union_inside_allOf_still_has_fields(self):
        doc = copy.deepcopy(BASE)
        doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = self._union_body(["token"])
        fields = spec(doc).operations["POST /charges"].request_fields
        self.assertTrue(fields, "a body written as allOf-of-anyOf is not empty")
        leaves = {f.rsplit(".", 1)[-1] for f in fields}
        self.assertIn("username", leaves)
        self.assertIn("token", leaves)

    def test_the_same_body_in_two_notations_reports_nothing(self):
        """The consequence that mattered, in the shape it actually occurs.

        Both sides identical would pass with the bug present -- zero fields
        against zero fields is also no change. What produced the fabrications
        is the SAME content written two ways: `allOf: [anyOf: [...]]` on one
        side, the bare `anyOf: [...]` on the other. With the union dropped the
        old side flattens to nothing and every field on the new side reads as
        newly added and newly required.
        """
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        wrapped = self._union_body(["token"])
        old["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = wrapped
        new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {"anyOf": wrapped["allOf"][0]["anyOf"]}
        found = kinds(run(old, new))
        self.assertNotIn("request_field_added_required", found)
        self.assertNotIn("request_field_now_required", found)

    def test_a_field_that_really_became_required_is_still_reported(self):
        """The control. Every change above makes this class quieter."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        old["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = self._union_body([])
        new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = self._union_body(["token"])
        self.assertIn("request_field_now_required", kinds(run(old, new)))

    def test_several_different_unions_are_left_opaque(self):
        """An intersection of unions is not representable in this shape, and
        inventing one arm's worth of an answer would be worse than keeping the
        schema opaque."""
        doc = copy.deepcopy(BASE)
        doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = {"allOf": [
                {"anyOf": [{"type": "object",
                            "properties": {"a": {"type": "string"}}}]},
                {"oneOf": [{"type": "object",
                            "properties": {"b": {"type": "string"}}}]},
            ]}
        fields = spec(doc).operations["POST /charges"].request_fields
        self.assertEqual({}, dict(fields),
                         "two competing unions must not be silently resolved to one")


class TestPerOperationServers(unittest.TestCase):
    """`servers` overrides per path-item and per operation, and only the
    document level was ever read.

    Stripe serves `POST /v1/files` and `GET /v1/quotes/{quote}/pdf` from
    files.stripe.com; GitHub serves release-asset upload from
    uploads.github.com. A vendor moving one of those breaks every caller with
    that host written down, while the document-level list never moves -- so the
    change was invisible. Verified against both raw specs before this existed.
    """

    def _with_server(self, host, where="op"):
        doc = copy.deepcopy(BASE)
        node = doc["paths"]["/charges"]
        target = node["post"] if where == "op" else node
        if host:
            target["servers"] = [{"url": host}]
        return doc

    def test_an_operation_level_server_overrides_the_document(self):
        loaded = spec(self._with_server("https://files.test.com/"))
        self.assertEqual(("https://files.test.com/",),
                         loaded.operations["POST /charges"].servers)
        self.assertEqual(("https://api.test.com/v1",),
                         loaded.operations["GET /charges"].servers,
                         "a sibling operation keeps the document's servers")

    def test_a_path_item_server_overrides_the_document(self):
        loaded = spec(self._with_server("https://path.test.com/", where="item"))
        self.assertEqual(("https://path.test.com/",),
                         loaded.operations["POST /charges"].servers)

    def test_moving_one_endpoint_to_another_host_is_breaking(self):
        old = self._with_server("https://files.test.com/")
        new = self._with_server("https://uploads.test.com/")
        found = [f for f in run(old, new).findings
                 if f.kind == "operation_server_changed"]
        self.assertTrue(found, "a host move on one endpoint must be reported")
        self.assertEqual("POST", found[0].method.upper())

    def test_adding_a_host_alongside_the_old_one_is_not_breaking(self):
        """Overlap means every caller that worked still works."""
        old = self._with_server("https://files.test.com/")
        new = copy.deepcopy(old)
        new["paths"]["/charges"]["post"]["servers"] = [
            {"url": "https://files.test.com/"}, {"url": "https://eu.test.com/"}]
        self.assertNotIn("operation_server_changed", kinds(run(old, new)))

    def test_an_unchanged_document_host_reports_nothing(self):
        """The control: every operation inherits the document's servers, so a
        naive comparison would fire on all of them."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        self.assertNotIn("operation_server_changed", kinds(run(old, new)))


class TestResponseFindingsCarryTheirStatus(unittest.TestCase):
    """A 4XX body decided against the 200 body is not a measurement.

    `_diff_fields` has always been given the response status and put it only in
    the prose, so the independent checker had to guess and resolved every
    response-side finding against the 200 body. Cloudflare removes `result`
    from a 400 body while the 200 body keeps it, which read as "still present"
    and refuted a real removal.
    """

    def test_a_response_finding_records_which_response(self):
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        for doc in (old, new):
            doc["paths"]["/charges"]["get"]["responses"]["400"] = {
                "content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"errors": {"type": "string"},
                                   "result": {"type": "string"}}}}}}
        del new["paths"]["/charges"]["get"]["responses"]["400"]["content"][
            "application/json"]["schema"]["properties"]["result"]
        found = [f for f in run(old, new).findings
                 if f.kind == "response_field_removed" and f.subject == "result"]
        self.assertTrue(found, "the removal must be reported")
        self.assertEqual("400", found[0].status,
                         "and it must say which response it left")

    def test_a_request_finding_carries_no_status(self):
        """The control: a request body has no status, and inventing one would
        send the checker looking in the wrong place."""
        old, new = copy.deepcopy(BASE), copy.deepcopy(BASE)
        new["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]["required"].append("note")
        found = [f for f in run(old, new).findings if "request" in f.kind]
        self.assertTrue(found)
        self.assertEqual("", found[0].status)


class TestRenamedResponseSchemaMayCarryMore(unittest.TestCase):
    """A schema a caller only ever READS cannot be broken by its replacement
    carrying more than it did.

    Exact equality is the right test for a schema a caller SENDS -- anything
    the new one adds as required is a new obligation. It is the wrong test for
    one a caller reads, and the rename check applied it to both. Cloudflare
    renamed `access_schemas-single_response` to `access_single_response-2` and
    added `enabled` to its `result`; 30 of its removals were that shape. This
    is the provenance rule f034a2a already applies to severity, applied to the
    rename test as well.
    """

    def _doc(self, direction="response", required=()):
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"]["Envelope"] = {
            "type": "object",
            "properties": {
                "success": {"type": "boolean"},
                # Nested on purpose: the superset rule only ever applies to a
                # field that IS an object, so a flat fixture exercises none of
                # it and passes whatever the rule says.
                "result": {"type": "object", "properties": {
                    "id": {"type": "string"}, "name": {"type": "string"}}},
            },
            "required": list(required),
        }
        node = doc["paths"]["/charges"]["post"]
        ref = {"$ref": "#/components/schemas/Envelope"}
        if direction == "response":
            node["responses"]["200"] = {"content": {"application/json": {
                "schema": ref}}}
        else:
            node["requestBody"] = {"required": True, "content": {
                "application/json": {"schema": ref}}}
        return doc

    def _renamed(self, direction, extra_props=(), required=()):
        doc = self._doc(direction, required)
        schema = doc["components"]["schemas"].pop("Envelope")
        for name in extra_props:
            schema["properties"]["result"]["properties"][name] = {"type": "boolean"}
        schema["required"] = list(required)
        doc["components"]["schemas"]["EnvelopeV2"] = schema
        ref = {"$ref": "#/components/schemas/EnvelopeV2"}
        node = doc["paths"]["/charges"]["post"]
        if direction == "response":
            node["responses"]["200"]["content"]["application/json"]["schema"] = ref
        else:
            node["requestBody"]["content"]["application/json"]["schema"] = ref
        return doc

    def test_a_renamed_response_schema_that_gained_a_field_is_not_a_break(self):
        """And it is the RENAME test that settles it, not a later branch.

        Asserting only "no findings" would pass with the superset rule deleted,
        because the leaf-name test one branch further down suppresses this too
        -- for the wrong reason, and only because the added field is nested
        deeper than that test can see. The suppression reason is the part that
        has to be right.
        """
        old = self._doc()
        new = self._renamed("response", extra_props=("enabled",))
        result = run(old, new)
        self.assertEqual(set(), kinds(result),
                         "a reader cannot be broken by a field appearing")
        self.assertEqual(1, result.suppressed.get("renamed"),
                         f"the rename test must be what settles it, got "
                         f"{result.suppressed}")

    def test_the_widening_rule_applies_only_to_what_a_caller_READS(self):
        """What a caller sends is a different question: the new one carrying
        more is a new obligation, not a gift.

        Asserted on `_still_presents` directly. End to end the distinction is
        worth exactly three findings across all 21 vendors -- real, but every
        synthetic fixture I could build is suppressed one branch earlier by the
        leaf-name test, so a pipeline test would pass with the distinction
        deleted and prove nothing.
        """
        from apidrift.diff import _still_presents
        old = spec(self._doc())
        new = spec(self._renamed("response", extra_props=("enabled",)))
        before, after = old.schemas["Envelope"], new.schemas["EnvelopeV2"]
        self.assertTrue(_still_presents(before, after, old, new, True),
                        "a reader is not broken by a field appearing")
        self.assertFalse(_still_presents(before, after, old, new, False),
                         "a sender's contract has to match exactly")

    def test_the_superset_rule_is_a_SUPERSET_rule(self):
        """Asserted where it lives.

        End to end a nested loss is already reported as `response_field_removed`
        by the operation diff, so a pipeline test stays green whether this rule
        says superset or "anything goes" -- it would prove nothing about the
        comparison it is meant to pin.
        """
        from apidrift.diff import _shape_presents
        smaller = ("object", ("id", "name"))
        bigger = ("object", ("enabled", "id", "name"))
        self.assertTrue(_shape_presents(smaller, bigger), "gaining a field is fine")
        self.assertFalse(_shape_presents(bigger, smaller), "losing one is not")
        self.assertFalse(_shape_presents(("scalar", "string"), ("scalar", "integer")),
                         "a scalar has to match exactly")


class TestLoaderRejectsNonMappings(unittest.TestCase):
    """A document that parses but is not a mapping is not a spec.

    It used to reach `doc.get(...)` and raise AttributeError, which is not a
    SpecParseError, so `analyse` did not catch it: one stray file inside a
    vendor's glob took that whole vendor down with a stack trace instead of
    being reported and skipped. Found by a probe pointing a glob at a repo
    whose matching file was a bare JSON array.
    """

    def test_a_json_array_is_a_parse_error_not_a_crash(self):
        from apidrift.loader import SpecParseError, load_spec
        with self.assertRaises(SpecParseError):
            load_spec(b'[{"openapi": "3.0.0"}]', "list.json")

    def test_a_yaml_scalar_is_a_parse_error_not_a_crash(self):
        from apidrift.loader import SpecParseError, load_spec
        with self.assertRaises(SpecParseError):
            load_spec(b"just a string\n", "scalar.yaml")

    def test_a_real_spec_still_loads(self):
        """The control: the guard must reject non-mappings, not everything."""
        self.assertTrue(spec(copy.deepcopy(BASE)).operations)
class TestNullabilityWrapperIsNotAUnion(unittest.TestCase):
    """`oneOf: [null, X]` is how OpenAPI 3.0 spells "nullable X".

    Collapsing the wrapper to a bare `$ref X` -- which Discord did across its
    whole spec -- moves no byte of the payload, and renaming the schema behind
    it (OpenAI, `Conversation-2` -> `ResponseConversation`) moves none either.
    Both used to delete every key under the arm and read as removed fields.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Theme"] = {
                "type": "object", "properties": {"hue": {"type": "string"}}}
            doc["components"]["schemas"]["Card"]["properties"]["theme"] = {
                "oneOf": [{"type": "null"},
                          {"$ref": "#/components/schemas/Theme"}]}

    def test_dropping_the_null_arm_is_not_a_break(self):
        self.new["components"]["schemas"]["Card"]["properties"]["theme"] = {
            "$ref": "#/components/schemas/Theme"}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_renaming_the_schema_behind_the_wrapper_is_not_a_break(self):
        schemas = self.new["components"]["schemas"]
        schemas["ThemeV2"] = schemas.pop("Theme")
        schemas["Card"]["properties"]["theme"] = {
            "oneOf": [{"type": "null"}, {"$ref": "#/components/schemas/ThemeV2"}]}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_a_single_arm_anyOf_beside_nullable_is_the_same_wrapper(self):
        """Stripe's spelling: `anyOf: [$ref X]` with `nullable: true`."""
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["theme"] = {
                "anyOf": [{"$ref": "#/components/schemas/Theme"}], "nullable": True}
        schemas = self.new["components"]["schemas"]
        schemas["ThemeV2"] = schemas.pop("Theme")
        schemas["Card"]["properties"]["theme"] = {
            "anyOf": [{"$ref": "#/components/schemas/ThemeV2"}], "nullable": True}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_losing_a_field_THROUGH_the_wrapper_is_still_a_break(self):
        """The other direction: transparency must not swallow a real loss."""
        del self.new["components"]["schemas"]["Theme"]["properties"]["hue"]
        self.assertTrue(run(self.old, self.new).breaking,
                        "a field vanishing behind the wrapper is a break")

    def test_a_union_with_two_REAL_arms_keeps_its_arms(self):
        """Discord's auto-moderation control, in miniature.

        `[null, Rule, SpamRule]` losing `SpamRule` is a response alternative
        genuinely disappearing. Nothing about nullability may silence it.
        """
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Rule"] = {
                "type": "object", "properties": {"kind": {"type": "string"}}}
            doc["components"]["schemas"]["SpamRule"] = {
                "type": "object", "properties": {"spam": {"type": "string"}}}
            doc["components"]["schemas"]["Card"]["properties"]["rule"] = {
                "oneOf": [{"type": "null"},
                          {"$ref": "#/components/schemas/Rule"},
                          {"$ref": "#/components/schemas/SpamRule"}]}
        self.new["components"]["schemas"]["Card"]["properties"]["rule"] = {
            "oneOf": [{"type": "null"}, {"$ref": "#/components/schemas/Rule"}]}
        found = {f.kind for f in run(self.old, self.new).breaking}
        self.assertIn("response_field_removed", found)

    def test_a_one_arm_union_that_declares_no_nullability_is_left_alone(self):
        """Cloudflare's `infra_ServiceConfig`: `oneOf: [Http]` + discriminator.

        It later grew a TCP arm. Treating a one-member union as transparent
        moved every key beneath it on one side only and invented six removed
        response fields whose value never left the payload.
        """
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["cfg"] = {
                "oneOf": [{"$ref": "#/components/schemas/Bank"}],
                "discriminator": {"propertyName": "id"}}
        self.new["components"]["schemas"]["Card"]["properties"]["cfg"]["oneOf"].append(
            {"$ref": "#/components/schemas/Theme"})
        self.assertEqual(
            [f.subject for f in run(self.old, self.new).breaking], [],
            "adding an arm must not read as the first arm's fields being removed")


class TestRootMarkerIsNotAField(unittest.TestCase):
    """`$ref X` becoming `allOf: [X, ...]` deletes the root key, not the payload.

    The flattener stamps `<X>` only when the body is a BARE `$ref`, so the two
    spellings of the same body are not comparable at the root. GitHub wrapped
    the 200 of `PATCH /repos/{o}/{r}/issues/{n}` in exactly that `allOf` and the
    root key read as a removed response field.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def _body(self, doc):
        return doc["paths"]["/charges"]["post"]["responses"]["200"]["content"][
            "application/json"]

    def test_wrapping_a_ref_body_in_an_allOf_is_not_a_break(self):
        self._body(self.new)["schema"] = {"allOf": [
            {"$ref": "#/components/schemas/Card"},
            {"type": "object", "properties": {"hint": {"type": "string"}}}]}
        self.assertEqual(run(self.old, self.new).breaking, [])

    def test_a_body_that_loses_its_fields_is_still_a_break(self):
        """The other direction: the marker rule must not eat a real loss."""
        self._body(self.new)["schema"] = {"allOf": [
            {"type": "object", "properties": {"hint": {"type": "string"}}}]}
        found = {f.kind for f in run(self.old, self.new).breaking}
        self.assertIn("response_field_removed", found)


class TestRequiredInsideANewParent(unittest.TestCase):
    """A required property of an object nobody was sending rejects nobody.

    Stripe added an optional `limits` object whose `accounts` is required and
    Twilio an optional `conversationsV1Bridge` whose `serviceId` is; both scored
    as "every existing caller is now rejected", which is the opposite of true.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def _body(self, doc):
        return doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]

    def test_a_required_field_inside_a_new_optional_object_is_not_breaking(self):
        self._body(self.new)["properties"]["limits"] = {
            "type": "object", "properties": {"accounts": {"type": "integer"}},
            "required": ["accounts"]}
        self.assertEqual([f.subject for f in run(self.old, self.new).breaking], [])

    def test_a_required_field_added_to_an_EXISTING_object_is_still_breaking(self):
        """The other direction: only a NEW parent excuses the requirement."""
        for doc in (self.old, self.new):
            self._body(doc)["properties"]["limits"] = {
                "type": "object", "properties": {"note": {"type": "string"}}}
        self._body(self.new)["properties"]["limits"]["properties"]["accounts"] = {
            "type": "integer"}
        self._body(self.new)["properties"]["limits"]["required"] = ["accounts"]
        found = {f.kind for f in run(self.old, self.new).breaking}
        self.assertIn("request_field_added_required", found)

    def test_a_new_TOP_LEVEL_required_field_is_still_breaking(self):
        self._body(self.new)["properties"]["idempotency_key"] = {"type": "string"}
        self._body(self.new)["required"].append("idempotency_key")
        found = {f.kind for f in run(self.old, self.new).breaking}
        self.assertIn("request_field_added_required", found)


class TestAnonymousArmReshapeInARealUnion(unittest.TestCase):
    """The reshape path, exercised where it still runs.

    `TestAnonymousArmReshape` builds its fixture out of a `[enum, null]`
    wrapper, which is now flattened transparently -- so those three tests
    stopped reaching the `blind in new_blind` branch and its mutation survived
    while they stayed green. A union with two REAL arms is where an anonymous
    arm's content-derived rename still has to be read as a reshape.
    """

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)
        for doc in (self.old, self.new):
            doc["components"]["schemas"]["Card"]["properties"]["tier"] = {
                "anyOf": [{"$ref": "#/components/schemas/Bank"},
                          {"type": "string", "enum": ["auto", "flex"]}]}

    def _tier(self, doc):
        return doc["components"]["schemas"]["Card"]["properties"]["tier"]["anyOf"][1]

    def test_enum_widening_in_a_real_union_is_not_a_field_removal(self):
        from apidrift.diff import _kind_class
        self._tier(self.new)["enum"] = ["auto", "flex", "fast"]
        result = run(self.old, self.new)
        classes = {_kind_class(f.kind) for f in result.findings}
        self.assertIn("enum_value_added", classes)
        self.assertNotIn("field_removed", classes)
        self.assertEqual(result.breaking, [], "widening an enum is not breaking")

    def test_enum_narrowing_in_a_real_union_is_reported(self):
        from apidrift.diff import _kind_class
        self._tier(self.new)["enum"] = ["auto"]
        classes = {_kind_class(f.kind) for f in run(self.old, self.new).findings}
        self.assertIn("enum_value_removed", classes)
        self.assertNotIn("field_removed", classes)

    def test_arm_type_change_in_a_real_union_is_breaking_not_removal(self):
        self._tier(self.new).clear()
        self._tier(self.new).update({"type": "integer"})
        result = run(self.old, self.new)
        found = {f.kind for f in result.findings}
        self.assertIn("response_field_type_changed", found)
        self.assertNotIn("response_field_removed", found)


class TestRenameInsideAMultiArmUnion(unittest.TestCase):
    """The parent's-ref-set rule, exercised where it still decides.

    The pair above builds its union as `anyOf: [$ref X, null]`, which the schema
    view now reads straight through as `->X` -- so the field comparison settles
    those cases and the ref-set branch stopped being reached, leaving its
    mutation alive while both tests stayed green. A union with two REAL arms
    still records the property as `anyOf` and nothing typed `->X`, which is the
    situation the branch was written for.
    """

    def _docs(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        for doc in (old, new):
            doc["components"]["schemas"]["Link"] = {
                "type": "object", "properties": {"id": {"type": "string"}},
                "required": ["id"]}
            doc["components"]["schemas"]["Wrapper"] = {
                "type": "object",
                "properties": {"link": {"anyOf": [
                    {"$ref": "#/components/schemas/Link"},
                    {"$ref": "#/components/schemas/Bank"}]}}}
            doc["paths"]["/charges"]["get"]["responses"]["200"]["content"][
                "application/json"]["schema"]["properties"]["wrapper"] = {
                    "$ref": "#/components/schemas/Wrapper"}
        return old, new

    def test_a_rename_inside_a_multi_arm_union_is_not_a_removal(self):
        old, new = self._docs()
        new["components"]["schemas"]["LinkV2"] = new["components"]["schemas"].pop("Link")
        new["components"]["schemas"]["Wrapper"]["properties"]["link"]["anyOf"][0] = {
            "$ref": "#/components/schemas/LinkV2"}
        new["components"]["schemas"]["Wrapper"]["properties"]["note"] = {"type": "string"}
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertNotIn("Link", removed)

    def test_a_multi_arm_union_arm_that_changed_shape_is_still_a_break(self):
        """The control: a different SHAPE at the same position is not a rename."""
        old, new = self._docs()
        new["components"]["schemas"]["LinkV2"] = {
            "type": "object", "properties": {"uuid": {"type": "string"}},
            "required": ["uuid"]}
        del new["components"]["schemas"]["Link"]
        new["components"]["schemas"]["Wrapper"]["properties"]["link"]["anyOf"][0] = {
            "$ref": "#/components/schemas/LinkV2"}
        removed = {f.subject for f in run(old, new).findings
                   if f.kind == "schema_removed"}
        self.assertIn("Link", removed)
class TestNewlyRequiredIsAClaimAboutBodies(unittest.TestCase):
    """`request_field_added_required` was a claim about the flattener's keys.

    The caller's question is whether a JSON body the OLD document accepted is
    REJECTED by the NEW one. Two shapes satisfied the key-level test while
    failing that one, and together they were 107 of the 158 findings of this
    class across 21 vendors:

      * the enclosing OBJECT is itself new -- Cloudflare added
        `global_acceleration` with four required members to a body where the
        property is optional, so nothing that validated before stopped
        validating;
      * the obligation was already there and only the KEY moved -- Cloudflare
        bulk-renamed the thirteen arms of its identity-provider union, every
        one of which required `config`, `name` and `type` before and after.

    Every test here is paired with a control that must stay a break, because a
    suppressor with only the quiet half is a deletion nobody is checking.
    """

    def _body(self, doc, schema):
        doc["paths"]["/charges"]["post"]["requestBody"]["content"][
            "application/json"]["schema"] = schema
        return doc

    def _obj(self, props, required):
        return {"type": "object", "properties": props, "required": required}

    def test_a_required_field_inside_a_NEW_object_is_not_a_break(self):
        old = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"}}, ["amount"]))
        new = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"},
             "limits": self._obj({"accounts": {"type": "integer"}}, ["accounts"])},
            ["amount"]))
        found = [f.subject for f in run(old, new).findings
                 if f.kind == "request_field_added_required"]
        self.assertEqual(
            [], found,
            "`limits` is optional, so a body without it still validates and "
            "`limits.accounts` binds nobody who was not already sending `limits`")

    def test_a_required_field_added_to_an_EXISTING_object_is_still_a_break(self):
        """The control: same shape, except the parent was already there."""
        old = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"},
             "limits": self._obj({"accounts": {"type": "integer"}}, [])}, ["amount"]))
        new = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"},
             "limits": self._obj({"accounts": {"type": "integer"},
                                  "cap": {"type": "integer"}}, ["cap"])}, ["amount"]))
        found = {f.subject for f in run(old, new).findings
                 if f.kind == "request_field_added_required"}
        self.assertTrue(
            any(s.endswith("limits.cap") for s in found),
            f"anyone already sending `limits` is now rejected; got {found}")

    def test_a_NEW_object_that_is_itself_required_is_reported_on_ITSELF(self):
        """The other control: the break is not lost, it is reported once.

        When the new object is mandatory, old bodies really are rejected -- for
        missing the OBJECT. That is the object's finding, on its own shorter
        path; repeating it on every leaf inside is how one restructure becomes
        ten findings.
        """
        old = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"}}, ["amount"]))
        new = self._body(copy.deepcopy(BASE), self._obj(
            {"amount": {"type": "integer"},
             "limits": self._obj({"accounts": {"type": "integer"}}, ["accounts"])},
            ["amount", "limits"]))
        found = {f.subject for f in run(old, new).findings
                 if f.kind == "request_field_added_required"}
        self.assertTrue(any(s.endswith("limits") for s in found),
                        f"the added mandatory object is the finding; got {found}")
        self.assertFalse(any(s.endswith("limits.accounts") for s in found),
                         f"and it is not counted again per leaf; got {found}")

    def _union_doc(self, arms, union_name):
        """A body that is a `$ref` to a NAMED union of NAMED arms.

        The shape matters. Written as a bare inline `anyOf`, the arm marker
        lands in ROOT position and `_strip_root_marker` erases it, so `_blind`
        already matches the two sides and the field never reaches the rules
        under test -- three mutations survived against exactly that mistake.
        Cloudflare's real shape is a `$ref` to `access_identity-providers-2`,
        which puts the ROOT marker outside and leaves the arm marker interior
        and nameable, where it is load-bearing.
        """
        doc = copy.deepcopy(BASE)
        doc["components"]["schemas"].update(arms)
        doc["components"]["schemas"][union_name] = {
            "anyOf": [{"$ref": f"#/components/schemas/{n}"} for n in arms]}
        return self._body(doc, {"$ref": f"#/components/schemas/{union_name}"})

    def test_renaming_every_union_arm_does_not_make_its_obligations_new(self):
        arm = {"type": "object",
               "properties": {"config": {"type": "object"},
                              "name": {"type": "string"}},
               "required": ["config", "name"]}
        old = self._union_doc({"AzureAD": copy.deepcopy(arm)}, "IdentityProviders")
        new = self._union_doc({"AzureADV2": copy.deepcopy(arm)}, "IdentityProvidersV2")
        found = [f.subject for f in run(old, new).findings
                 if f.kind in ("request_field_added_required",
                               "request_field_now_required")]
        self.assertEqual(
            [], found,
            "the arm was renamed; `config` and `name` were obligatory before "
            f"and after, so no body changed status. Got {found}")

    def test_an_arm_rename_that_ALSO_tightens_is_still_a_break(self):
        """The control for the rename rule: same rename, one new obligation."""
        props = {"config": {"type": "object"}, "name": {"type": "string"}}
        old = self._union_doc(
            {"AzureAD": {"type": "object", "properties": props,
                         "required": ["config"]}}, "IdentityProviders")
        new = self._union_doc(
            {"AzureADV2": {"type": "object", "properties": props,
                           "required": ["config", "name"]}}, "IdentityProvidersV2")
        found = {f.subject for f in run(old, new).findings
                 if f.kind in ("request_field_added_required",
                               "request_field_now_required")}
        self.assertTrue(any(s.endswith("name") for s in found),
                        f"`name` was optional at old and is now required; got {found}")

    def test_a_field_optional_through_ONE_old_arm_is_still_a_break(self):
        """An obligation counts as pre-existing only when EVERY old route had
        it. Required through one arm and optional through another was never an
        obligation of the body, so tightening the loose arm breaks its callers.
        """
        props = {"name": {"type": "string"}}
        strict = {"type": "object", "properties": props, "required": ["name"]}
        loose = {"type": "object", "properties": props, "required": []}
        old = self._union_doc({"ArmA": copy.deepcopy(strict),
                               "ArmB": copy.deepcopy(loose)}, "Union")
        new = self._union_doc({"ArmAV2": copy.deepcopy(strict),
                               "ArmBV2": copy.deepcopy(strict)}, "UnionV2")
        found = {f.subject for f in run(old, new).findings
                 if f.kind in ("request_field_added_required",
                               "request_field_now_required")}
        self.assertTrue(found, "callers using the loose arm are now rejected")

    def test_an_old_body_that_flattened_to_NOTHING_suppresses_nothing(self):
        """The precondition control, doctrine 3b.

        Both rules reason from what the OLD flattening contains. On a side that
        flattened to nothing they are vacuously true of every field, which is a
        broken instrument rather than a result -- the same failure as the first
        `unreachable` rule, whose precondition held for 100% of Sentry's
        schemas. So they abstain when the old side has no signal at all.
        """
        old = self._body(copy.deepcopy(BASE), {})
        new = self._body(copy.deepcopy(BASE), self._obj(
            {"limits": self._obj({"accounts": {"type": "integer"}}, ["accounts"])},
            []))
        found = {f.subject for f in run(old, new).findings
                 if f.kind == "request_field_added_required"}
        self.assertTrue(
            any(s.endswith("limits.accounts") for s in found),
            f"nothing about an empty old side justifies suppressing; got {found}")
