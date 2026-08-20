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
