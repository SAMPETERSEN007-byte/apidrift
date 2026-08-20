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

    def test_endpoint_moved_is_not_reported_as_removed(self):
        self.new["paths"]["/refunds/{refund_id}"] = self.new["paths"].pop("/refunds/{id}")
        found = kinds(run(self.old, self.new))
        self.assertIn("endpoint_moved", found)
        self.assertNotIn("endpoint_removed", found)

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

    def test_security_requirement_added(self):
        self.new["paths"]["/charges"]["get"]["security"] = [{"bearer": []}]
        self.assertIn("security_requirement_added", kinds(run(self.old, self.new)))

    def test_success_response_removed(self):
        self.new["paths"]["/refunds/{id}"]["get"]["responses"] = {
            "404": {"description": "gone"}}
        self.assertIn("response_status_removed", kinds(run(self.old, self.new)))

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
        self._tier(self.new)["enum"] = ["auto", "flex", "fast"]
        result = run(self.old, self.new)
        found = {f.kind for f in result.findings}
        self.assertIn("response_enum_value_added", found)
        self.assertNotIn("response_field_removed", found)
        self.assertEqual(result.breaking, [], "widening an enum is not breaking")

    def test_enum_narrowing_is_reported(self):
        self._tier(self.new)["enum"] = ["auto"]
        found = {f.kind for f in run(self.old, self.new).findings}
        self.assertIn("response_enum_value_removed", found)
        self.assertNotIn("response_field_removed", found)

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
