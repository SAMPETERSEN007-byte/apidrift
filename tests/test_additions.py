"""Tests for the additive surface.

Measured over the same 90-day window across the five vendors: 64 breaking
changes, against 112 new operations and 332 new optional fields. Twenty-two
real repositories were scanned against those 64 breaking changes and not one
was affected -- so a tool that only fires on breakage fires almost never. The
additions are where the volume is, and they need a DIFFERENT proof, because
nobody can depend on something that did not exist.
"""
from __future__ import annotations

import copy
import json
import unittest

from apidrift.dependence import prove_relevance
from apidrift.diff import (ADDITIVE_LABEL, OPPORTUNITY, caller_visible_path,
                           collapse, diff_specs)
from apidrift.loader import load_spec
from apidrift.scan import _ADDITION_RANK, _is_incidental
from apidrift.vendors import get


def spec(doc):
    return load_spec(json.dumps(doc).encode(), "s.json")


def additions(old, new):
    return diff_specs("test", spec(old), spec(new), {}).additions


BASE = {
    "openapi": "3.0.3",
    "info": {"title": "T", "version": "1"},
    "servers": [{"url": "https://api.plaid.com"}],
    "components": {"schemas": {
        "TransferReq": {"type": "object",
                        "properties": {"amount": {"type": "string"}},
                        "required": ["amount"]},
    }},
    "paths": {
        "/transfer/create": {"post": {
            "operationId": "transferCreate",
            "requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/TransferReq"}}}},
            "responses": {"200": {"content": {"application/json": {
                "schema": {"type": "object",
                           "properties": {"id": {"type": "string"}}}}}}},
        }},
    },
}


class TestWhatCountsAsAnAddition(unittest.TestCase):

    def setUp(self):
        self.old = copy.deepcopy(BASE)
        self.new = copy.deepcopy(BASE)

    def test_a_new_endpoint_is_an_opportunity(self):
        self.new["paths"]["/transfer/cancel"] = {"post": {
            "operationId": "transferCancel",
            "responses": {"200": {"description": "ok"}}}}
        found = [a for a in additions(self.old, self.new)
                 if a.kind == "endpoint_added"]
        self.assertEqual([a.subject for a in found], ["/transfer/cancel"])
        self.assertEqual(found[0].severity, OPPORTUNITY)

    def test_a_new_endpoint_knows_which_resource_it_belongs_to(self):
        """Relevance is judged by the resource, not the whole path."""
        self.new["paths"]["/transfer/cancel"] = {"post": {
            "operationId": "transferCancel",
            "responses": {"200": {"description": "ok"}}}}
        found = [a for a in additions(self.old, self.new)
                 if a.kind == "endpoint_added"][0]
        self.assertEqual(found.resource, "transfer")
        self.assertIn("POST /transfer/create", found.affected_ops)

    def test_a_renamed_path_parameter_is_not_a_new_endpoint(self):
        self.old["paths"]["/thing/{Sid}"] = {"get": {
            "operationId": "getThing",
            "responses": {"200": {"description": "ok"}}}}
        self.new["paths"]["/thing/{id}"] = {"get": {
            "operationId": "getThing",
            "responses": {"200": {"description": "ok"}}}}
        kinds = [a.subject for a in additions(self.old, self.new)
                 if a.kind == "endpoint_added"]
        self.assertEqual(kinds, [])

    def test_a_query_variant_of_an_existing_path_is_not_a_new_endpoint(self):
        """OpenAI publishes `/responses?beta=true` beside `/responses`.

        Same endpoint, a flag. Counting it as new told six callers they had
        gained something they already had.
        """
        self.new["paths"]["/transfer/create?beta=true"] = copy.deepcopy(
            self.new["paths"]["/transfer/create"])
        self.new["paths"]["/transfer/create?beta=true"]["post"][
            "operationId"] = "transferCreateBeta"
        found = [a.subject for a in additions(self.old, self.new)
                 if a.kind == "endpoint_added"]
        self.assertEqual(found, [])

    def test_a_new_optional_field_is_an_opportunity(self):
        self.new["components"]["schemas"]["TransferReq"]["properties"][
            "custom_attributes"] = {"type": "string"}
        found = [a for a in additions(self.old, self.new)
                 if a.subject.endswith("custom_attributes")]
        self.assertTrue(found)
        self.assertEqual(found[0].severity, OPPORTUNITY)

    def test_a_new_REQUIRED_field_is_a_break_and_not_an_opportunity(self):
        """The control. A field you must now send is not a gift."""
        schema = self.new["components"]["schemas"]["TransferReq"]
        schema["properties"]["idempotency_key"] = {"type": "string"}
        schema["required"] = ["amount", "idempotency_key"]
        found = [a.subject for a in additions(self.old, self.new)]
        self.assertNotIn("TransferReq.idempotency_key", found)

    def test_a_schema_no_operation_reaches_is_not_an_opportunity(self):
        self.new["components"]["schemas"]["Orphan"] = {
            "type": "object", "properties": {"a": {"type": "string"}}}
        self.old["components"]["schemas"]["Orphan"] = {
            "type": "object", "properties": {}}
        found = [a.subject for a in additions(self.old, self.new)]
        self.assertNotIn("Orphan.a", found)


class TestRelevanceIsNotDependence(unittest.TestCase):
    """Reach is the WHOLE proof here, and only here.

    `prove()` rejects reach as evidence of a break -- that was the fix that
    cleared the standing audit blocker. `prove_relevance()` accepts it, because
    an addition cannot be depended on by anyone. They are separate functions so
    that staying separate is not one edit away from failing.
    """

    def _addition(self):
        old = copy.deepcopy(BASE)
        new = copy.deepcopy(BASE)
        new["paths"]["/transfer/cancel"] = {"post": {
            "operationId": "transferCancel",
            "responses": {"200": {"description": "ok"}}}}
        return [a for a in additions(old, new) if a.kind == "endpoint_added"][0]

    def test_a_repo_calling_the_resource_is_relevant(self):
        source = ('import plaid\n'
                  'import requests\n'
                  'def go(b):\n'
                  '    return requests.post("https://api.plaid.com/transfer/create",\n'
                  '                         json=b)\n')
        proofs, why = prove_relevance(source, self._addition(), get("plaid"))
        self.assertTrue(proofs, why)

    def test_a_repo_calling_nothing_on_it_is_not(self):
        source = ('import plaid\n'
                  'import requests\n'
                  'def go(b):\n'
                  '    return requests.post("https://api.plaid.com/item/get", json=b)\n')
        proofs, why = prove_relevance(source, self._addition(), get("plaid"))
        self.assertFalse(proofs)
        self.assertIn("nothing here to adopt it into", why)


class TestRanking(unittest.TestCase):

    def test_something_you_must_act_on_outranks_something_that_arrives(self):
        self.assertLess(_ADDITION_RANK["spec_added"],
                        _ADDITION_RANK["endpoint_added"],
                        "a whole new API version is the biggest event there is")
        self.assertLess(_ADDITION_RANK["endpoint_added"],
                        _ADDITION_RANK["schema_field_added"])
        self.assertLess(_ADDITION_RANK["schema_field_added"],
                        _ADDITION_RANK["response_field_added"])

    def test_a_fixture_is_a_worse_place_to_put_advice_than_production(self):
        self.assertTrue(_is_incidental("py/autoevals/test_llm.py"))
        self.assertTrue(_is_incidental("tests/helpers.py"))
        self.assertTrue(_is_incidental("examples/demo.py"))
        self.assertFalse(_is_incidental("app/billing/stripe.py"))
        self.assertFalse(_is_incidental("src/latest_api.py"))

    def test_every_additive_kind_has_a_label_and_a_rank(self):
        for kind in ADDITIVE_LABEL:
            self.assertIn(kind, _ADDITION_RANK, f"{kind} would sort last")


if __name__ == "__main__":
    unittest.main()


class TestANewSpecFileIsANewApiVersion(unittest.TestCase):
    """A sharded vendor ships a new API version as a NEW FILE.

    Adyen publishes 129 per-service, per-version files; `CheckoutService-v52`
    arrives beside `-v51` rather than editing it. Skipping a file with no
    predecessor as "purely additive" therefore reported "no change" straight
    through the launch — the single most consequential event the tool exists
    to catch.
    """

    def _spec(self, version: int, ops: int) -> dict:
        paths = {}
        for n in range(ops):
            paths[f"/v{version}/payments/action{n}"] = {"post": {
                "operationId": f"pay{n}",
                "responses": {"200": {"description": "ok"}}}}
        return {"openapi": "3.0.3", "info": {"title": "Checkout", "version": "1"},
                "servers": [{"url": "https://checkout-test.adyen.com"}],
                "paths": paths}

    def _added(self, version: int, ops: int):
        from apidrift.diff import spec_added_finding
        return spec_added_finding(f"json/CheckoutService-v{version}.json",
                                  spec(self._spec(version, ops)))

    def test_a_new_spec_file_is_reported_not_skipped(self):
        finding = self._added(52, 3)
        self.assertEqual(finding.kind, "spec_added")
        self.assertEqual(finding.severity, OPPORTUNITY)
        self.assertIn("3 operations", finding.detail)

    def test_a_version_segment_is_not_mistaken_for_the_resource(self):
        """`v51` is a version, not a resource — and it is not just v1/v2/v3."""
        self.assertEqual(self._added(52, 1).resource, "payments")
        self.assertEqual(caller_visible_path("POST /v71/payments"),
                         "POST /v71/payments")

    def test_a_caller_of_the_old_version_is_found_by_the_resource(self):
        source = ('import requests\n'
                  'def pay(b):\n'
                  '    return requests.post(\n'
                  '        "https://checkout-test.adyen.com/v51/payments/action0",\n'
                  '        json=b)\n')
        from apidrift.vendors import Vendor
        adyen = Vendor(key="adyen", name="Adyen", repo="Adyen/adyen-openapi",
                       spec_path="json/*.json", docs_url="",
                       evidence=("checkout-test.adyen.com", "adyen"))
        proofs, why = prove_relevance(source, self._added(51, 1), adyen)
        self.assertTrue(proofs, why)


class TestNewSpecFileReachesThePipeline(unittest.TestCase):
    """The unit above proves the finding is built correctly. This proves
    `analyse()` actually puts it on the result, which is a different claim and
    was the part that was broken."""

    def test_a_new_api_version_reaches_the_pipeline(self):
        import datetime as dt
        from pathlib import Path
        from unittest import mock
        from apidrift import cli
        from apidrift.source import SpecPair, SpecVersion
        from apidrift.vendors import get

        raw = json.dumps({
            "openapi": "3.0.3", "info": {"title": "New", "version": "1"},
            "servers": [{"url": "https://api.stripe.com"}],
            "paths": {"/v2/widgets": {"get": {
                "operationId": "listWidgets",
                "responses": {"200": {"description": "ok"}}}}},
        }).encode()
        pair = SpecPair(path="openapi/spec4.json", old=None,
                        new=SpecVersion(ref="abc", date="2026-08-20",
                                        path="openapi/spec4.json", raw=raw))
        meta = {"old_ref": "a", "new_ref": "b", "old_date": "2026-05-01",
                "new_date": "2026-08-20", "specs_matched": "1",
                "specs_changed": "1"}
        with mock.patch.object(cli, "spec_pairs", return_value=([pair], meta)):
            result = cli.analyse(get("stripe"), Path("/nonexistent"),
                                 "2026-05-01", False)
        kinds = [a.kind for a in result.additions]
        self.assertIn("spec_added", kinds,
                      "a spec file with no predecessor must not be skipped")
        self._result = result

    def test_a_spec_with_no_predecessor_is_recorded_as_unseen_history(self):
        """Emitting the opportunity is not enough — the SILENCE has to be
        explained too, or "0 breaking changes" reads as a clean bill over a
        period nothing could be compared in."""
        self.test_a_new_api_version_reaches_the_pipeline()
        self.assertIn("openapi/spec4.json", self._result.specs_without_history)
