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

    def test_response_field_removed_through_ref(self):
        del self.new["components"]["schemas"]["Card"]["properties"]["iin"]
        result = run(self.old, self.new)
        self.assertIn("response_field_removed", kinds(result))

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


class TestRootCauseCollapse(unittest.TestCase):
    def test_shared_schema_change_collapses_to_one_finding(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        # Card is reachable from GET /charges (via anyOf) and POST /charges.
        del new["components"]["schemas"]["Card"]["properties"]["iin"]
        raw = diff_specs("test", spec(old), spec(new), {})
        raw_removals = [f for f in raw.findings if f.kind == "response_field_removed"]
        collapsed = [f for f in collapse(raw.findings) if f.kind == "response_field_removed"]
        self.assertGreater(len(raw_removals), 1, "fixture must fan out to prove collapsing")
        self.assertEqual(len(collapsed), 1)
        self.assertEqual(collapsed[0].occurrences, len(raw_removals))
        self.assertEqual(collapsed[0].root_cause, "Card.iin")
        self.assertEqual(collapsed[0].severity, BREAKING,
                         "losing a response field breaks every consumer reading it")

    def test_operation_count_is_distinct_operations_not_occurrences(self):
        """853 "operations" in a 589-operation spec was an occurrence count."""
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        # Two union routes to Card inside the SAME operation, plus one in another.
        for doc in (old, new):
            doc["paths"]["/charges"]["get"]["responses"]["200"]["content"][
                "application/json"]["schema"]["properties"]["fallback"] = {
                    "anyOf": [{"$ref": "#/components/schemas/Card"},
                              {"$ref": "#/components/schemas/Bank"}]}
        del new["components"]["schemas"]["Card"]["properties"]["iin"]
        raw = diff_specs("test", spec(old), spec(new), {})
        collapsed = [f for f in collapse(raw.findings)
                     if f.root_cause == "Card.iin"][0]
        distinct = len({f.op_key for f in raw.findings
                        if f.kind == "response_field_removed"})
        self.assertGreater(collapsed.occurrences, collapsed.affected_op_count,
                           "fixture must have more routes than operations")
        self.assertEqual(collapsed.affected_op_count, distinct)
        self.assertIn(f"{distinct} operations", collapsed.detail)
        self.assertNotIn(f"{collapsed.occurrences} operations", collapsed.detail)

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
