"""Tests for the checker itself.

`measure_precision.py` is layer 3 of the gate and the layer that caught the
largest defects this engine has had -- and until now nothing verified IT. A
silent break in the checker makes layer 3 report 100% while checking nothing,
which is the same failure mode it exists to catch, one level up.

Everything here is a synthetic document plus a synthetic finding, so each case
pins one decision and nothing else.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from measure_precision import (CONFIRMED, REFUTED, UNDECIDABLE,  # noqa: E402
                               check, ref_sites)


def finding(kind, **kw):
    base = {"kind": kind, "subject": kw.pop("subject", "x"),
            "op_key": kw.pop("op_key", "GET /things"),
            "root_cause": kw.pop("root_cause", None),
            "status": kw.pop("status", ""),
            "old": "", "new": ""}
    base.update(kw)
    return base


def doc(schemas=None, paths=None):
    return {"openapi": "3.0.0", "paths": paths or {},
            "components": {"schemas": schemas or {}}}


def resp(schema, status="200"):
    return {status: {"content": {"application/json": {"schema": schema}}}}


class TestSchemaRemoved(unittest.TestCase):
    def test_a_genuinely_removed_schema_is_confirmed(self):
        old = doc({"Card": {"type": "object",
                            "properties": {"iin": {"type": "string"}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Card"})}}})
        new = doc({}, {"/things": {"get": {"responses": resp(
            {"type": "object", "properties": {"other": {"type": "string"}}})}}})
        verdict, why = check(finding("schema_removed", subject="Card"),
                             old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_inlined_schema_is_refuted(self):
        body = {"type": "string", "enum": ["a"]}
        old = doc({"Brand": body,
                   "Card": {"type": "object", "properties": {
                       "brand": {"$ref": "#/components/schemas/Brand"}}}})
        new = doc({"Card": {"type": "object", "properties": {"brand": body}}})
        verdict, why = check(finding("schema_removed", subject="Brand"),
                             old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)
        self.assertIn("inlined or renamed", why)

    def test_a_dereferenced_document_is_UNDECIDABLE_not_refuted(self):
        """The control that stops the orphan test being a null test.

        Sentry's `openapi-derefed.json` contains zero `$ref` in 3.2 MB, so "no
        reference points at it" is true of every schema there and decides
        nothing. Refuting on it would have discarded 24 real breaks.
        """
        old = doc({"Ghost": {"type": "object",
                             "properties": {"x": {"type": "string"}}}},
                  {"/things": {"get": {"responses": resp(
                      {"type": "object", "properties": {"x": {"type": "string"}}})}}})
        new = doc({}, old["paths"])
        verdict, why = check(finding("schema_removed", subject="Ghost"),
                             old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)
        self.assertIn("dereferenced", why)

    def test_an_orphan_IS_refuted_when_the_document_does_link(self):
        """The other half. The control must not disable the rule outright."""
        old = doc({"Ghost": {"type": "object"},
                   "Card": {"type": "object", "properties": {"id": {"type": "string"}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Card"})}}})
        new = doc({"Card": old["components"]["schemas"]["Card"]}, old["paths"])
        verdict, why = check(finding("schema_removed", subject="Ghost"),
                             old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_discriminator_mapping_counts_as_a_reference(self):
        """The only pointer form in OpenAPI that is a bare string. Adyen names
        `BalanceAccountResource` nowhere else."""
        old = doc({
            "Resource": {"type": "object",
                         "discriminator": {"propertyName": "type", "mapping": {
                             "card": "#/components/schemas/CardResource"}}},
            "CardResource": {"type": "object",
                             "properties": {"pan": {"type": "string"}}}})
        self.assertEqual(
            1, len(ref_sites(old, "#/components/schemas/CardResource")),
            "a mapping value is a reference")


class TestResponseFieldRemoved(unittest.TestCase):
    def test_a_schema_qualified_root_is_decided_against_the_OPERATION(self):
        """`collapse()` rewrites root_cause to `<Schema>.a.b`. Walking that
        head through the operation body finds nothing on either side, and the
        fall-through then asks whether the SCHEMA still defines the field --
        which answers "present in both" precisely when the vendor changed which
        schema the operation returns."""
        kept = {"type": "object", "properties": {"id": {"type": "string"}}}
        old = doc({"StoreResponse": {"type": "object", "properties": {
                       "result": kept}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/StoreResponse"})}}})
        # The schema still exists -- it is simply no longer what this returns.
        new = doc({"StoreResponse": old["components"]["schemas"]["StoreResponse"],
                   "DeleteResponse": {"type": "object", "properties": {
                       "result": {"type": "object", "nullable": True}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/DeleteResponse"})}}})
        verdict, why = check(
            finding("response_field_removed", subject="StoreResponse.result.id",
                    root_cause="StoreResponse.result.id", status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_the_named_response_status_is_the_one_resolved(self):
        """Cloudflare removes `result` from a 400 body while the 200 keeps it.
        Decided against the 200 body that reads as "still present"."""
        ok_body = {"type": "object", "properties": {"result": {"type": "string"}}}
        old_400 = {"type": "object", "properties": {
            "errors": {"type": "string"}, "result": {"type": "string"}}}
        new_400 = {"type": "object", "properties": {"errors": {"type": "string"}}}
        old = doc({}, {"/things": {"get": {"responses": dict(
            resp(ok_body), **resp(old_400, status="400"))}}})
        new = doc({}, {"/things": {"get": {"responses": dict(
            resp(ok_body), **resp(new_400, status="400"))}}})
        verdict, why = check(
            finding("response_field_removed", subject="result",
                    root_cause="result", status="400"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)


class TestEndpointRemoved(unittest.TestCase):
    """An endpoint is a METHOD at a PATH, and the checker asked only about the
    path.

    Found by injecting a removal of `GET /emails` into Resend's real spec while
    `POST /emails` stayed. The engine reported it, this refuted it as "path
    present in both", and the engine was right -- every reader of that
    collection breaks. The five refutations of this kind in the corpus were
    never the engine's five.
    """

    def _doc(self, verbs, path="/emails"):
        item = {v: {"responses": resp({"type": "object"})} for v in verbs}
        return doc({}, {path: item})

    def test_removing_one_VERB_from_a_live_path_is_confirmed(self):
        verdict, why = check(
            finding("endpoint_removed", path="/emails", method="GET",
                    op_key="GET /emails"),
            self._doc(["get", "post"]), self._doc(["post"]), [], [])
        self.assertEqual(CONFIRMED, verdict, why)
        self.assertIn("post remain", why)

    def test_a_verb_that_is_still_there_is_refuted(self):
        verdict, why = check(
            finding("endpoint_removed", path="/emails", method="GET",
                    op_key="GET /emails"),
            self._doc(["get", "post"]), self._doc(["get"]), [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_path_parameter_rename_is_not_a_removal(self):
        """`{Sid}` -> `{id}` produces byte-identical URLs, so the normalised
        template is what gets compared."""
        verdict, why = check(
            finding("endpoint_removed", path="/emails/{Sid}", method="GET",
                    op_key="GET /emails/{Sid}"),
            self._doc(["get"], "/emails/{Sid}"),
            self._doc(["get"], "/emails/{id}"), [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_path_absent_from_the_OLD_spec_is_undecidable(self):
        """Not refuted. Nothing about the old document supports either verdict,
        and saying "not a break" would be an answer this cannot justify."""
        verdict, why = check(
            finding("endpoint_removed", path="/ghost", method="GET",
                    op_key="GET /ghost"),
            self._doc(["get"]), self._doc(["get"]), [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)


class TestParamTypeChanged(unittest.TestCase):
    def _docs(self, old_schema, new_schema, where="path"):
        def one(schema):
            return doc({}, {"/things/{id}": {"get": {
                "parameters": [{"name": "id", "in": where, "required": True,
                                "schema": schema}],
                "responses": resp({"type": "object"})}}})
        return one(old_schema), one(new_schema)

    def test_a_path_parameter_type_change_is_decided_on_the_TYPE(self):
        """A path parameter's NAME never reaches the wire. Its VALUE does, so
        the positional rule has nothing to say about a type change -- applying
        it anyway refuted six real findings on an irrelevant premise."""
        old, new = self._docs({"type": "string"}, {"type": "integer"})
        verdict, why = check(
            finding("param_type_changed", subject="id",
                    op_key="GET /things/{id}"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_path_parameter_RENAME_is_still_refuted_on_positionality(self):
        old, new = self._docs({"type": "string"}, {"type": "string"})
        verdict, why = check(
            finding("param_removed", subject="id",
                    op_key="GET /things/{id}"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)
        self.assertIn("PATH parameter", why)

    def test_two_notations_for_one_type_are_not_a_change(self):
        old, new = self._docs(
            {"allOf": [{"type": "string", "enum": ["a", "b"]}]},
            {"type": "string", "enum": ["a", "b"]}, where="query")
        verdict, why = check(
            finding("param_type_changed", subject="id",
                    op_key="GET /things/{id}"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)


class TestOperationServerChanged(unittest.TestCase):
    def test_a_host_move_on_one_operation_is_confirmed(self):
        old = doc({}, {"/things": {"get": {
            "servers": [{"url": "https://files.example.com"}],
            "responses": resp({"type": "object"})}}})
        old["servers"] = [{"url": "https://api.example.com"}]
        new = doc({}, {"/things": {"get": {
            "servers": [{"url": "https://uploads.example.com"}],
            "responses": resp({"type": "object"})}}})
        new["servers"] = old["servers"]
        verdict, why = check(finding("operation_server_changed",
                                     subject="<server>"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_overlapping_host_set_is_refuted(self):
        old = doc({}, {"/things": {"get": {
            "servers": [{"url": "https://files.example.com"}],
            "responses": resp({"type": "object"})}}})
        new = doc({}, {"/things": {"get": {
            "servers": [{"url": "https://files.example.com"},
                        {"url": "https://eu.example.com"}],
            "responses": resp({"type": "object"})}}})
        verdict, why = check(finding("operation_server_changed",
                                     subject="<server>"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)


if __name__ == "__main__":
    unittest.main()
