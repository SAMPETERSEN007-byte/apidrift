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


class TestOperationAddressing(unittest.TestCase):
    """A path parameter's NAME never reaches the wire, so it cannot decide
    whether the checker can FIND the operation a finding is about."""

    def test_a_renamed_path_parameter_still_finds_the_operation(self):
        """Cloudflare renamed `{postfix_id}` -> `{investigate_id}`. Every other
        finding on that operation then reported "missing from one side"."""
        old = doc({}, {"/investigate/{postfix_id}": {"get": {"responses": resp(
            {"type": "object", "properties": {"log": {"type": "string"}}})}}})
        new = doc({}, {"/investigate/{investigate_id}": {"get": {"responses": resp(
            {"type": "object", "properties": {"log": {"type": "integer"}}})}}})
        verdict, why = check(
            finding("response_field_type_changed", subject="log",
                    root_cause="log", op_key="GET /investigate/{investigate_id}",
                    status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_two_paths_sharing_a_template_stay_UNDECIDABLE(self):
        """The fallback must not GUESS. A document holding two paths that
        differ only in parameter names cannot say which one was meant, and
        picking one would answer a question nobody asked."""
        body = {"type": "object", "properties": {"log": {"type": "string"}}}
        old = doc({}, {"/investigate/{a_id}": {"get": {"responses": resp(body)}},
                       "/investigate/{b_id}": {"get": {"responses": resp(body)}}})
        new = doc({}, {"/investigate/{a_id}": {"get": {"responses": resp(body)}},
                       "/investigate/{b_id}": {"get": {"responses": resp(body)}}})
        verdict, why = check(
            finding("response_field_type_changed", subject="log",
                    root_cause="log", op_key="GET /investigate/{c_id}",
                    status="200"),
            old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)


class TestFieldTypeChanged(unittest.TestCase):
    def test_a_schema_qualified_root_is_walked_through_the_BODY(self):
        """`root_cause` is `MessageResponse.nonce` while the body's properties
        are `nonce`. Walking the schema NAME as a property found nothing on
        either side and the whole class reported UNDECIDABLE for that alone."""
        old = doc({"MessageResponse": {"type": "object", "properties": {
                       "nonce": {"oneOf": [{"type": "integer"},
                                           {"type": "null"}]}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/MessageResponse"})}}})
        new = doc({"MessageResponse": {"type": "object", "properties": {
                       "nonce": {"oneOf": [{"type": "integer"}]}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/MessageResponse"})}}})
        verdict, why = check(
            finding("response_field_type_changed",
                    subject="<MessageResponse>.nonce",
                    root_cause="MessageResponse.nonce", status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_head_the_BODY_does_not_use_is_not_stripped(self):
        """The guard is the whole safety of the head strip. `Foo.id` must not
        be re-read against whatever schema this operation happens to return,
        or an unrelated `Bar.id` decides it."""
        old = doc({"Foo": {"type": "object", "properties": {"id": {"type": "string"}}},
                   "Bar": {"type": "object", "properties": {"id": {"type": "string"}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Bar"})}}})
        new = doc({"Foo": {"type": "object", "properties": {"id": {"type": "integer"}}},
                   "Bar": {"type": "object", "properties": {"id": {"type": "string"}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Bar"})}}})
        verdict, why = check(
            finding("response_field_type_changed", subject="<Foo>.id",
                    root_cause="Foo.id", status="200"),
            old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)

    def test_an_allOf_is_read_as_an_intersection_not_as_nothing(self):
        """PayPal narrowed a field from `{}` -- which accepts anything -- to
        `allOf: [$ref crypto_request, {title}]`. Reading only the node's own
        keywords sees an empty schema on BOTH sides and calls them equal."""
        old = doc({"Req": {"type": "object", "properties": {"crypto": {}}},
                   "Crypto": {"type": "object",
                              "properties": {"chain": {"type": "string"}}}},
                  {"/things": {"post": {"requestBody": {"content": {
                      "application/json": {"schema": {
                          "$ref": "#/components/schemas/Req"}}}}}}})
        new = doc({"Req": {"type": "object", "properties": {"crypto": {
                       "allOf": [{"$ref": "#/components/schemas/Crypto"},
                                 {"title": "crypto"}]}}},
                   "Crypto": old["components"]["schemas"]["Crypto"]},
                  {"/things": {"post": {"requestBody": {"content": {
                      "application/json": {"schema": {
                          "$ref": "#/components/schemas/Req"}}}}}}})
        verdict, why = check(
            finding("request_field_type_changed", subject="<Req>.crypto",
                    root_cause="Req.crypto", op_key="POST /things"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_field_relocated_between_allOf_arms_is_refuted(self):
        """Klaviyo moved `relationships` out of an inline arm and into the
        referenced base schema. The property set a caller sees is identical,
        and reading `allOf` as an intersection is what shows that."""
        base_old = {"type": "object", "properties": {
            "id": {"type": "string"}, "attributes": {"type": "object"}}}
        base_new = {"type": "object", "properties": {
            "id": {"type": "string"}, "attributes": {"type": "object"},
            "relationships": {"type": "object"}}}
        old = doc({"Res": base_old,
                   "Envelope": {"type": "object", "properties": {"data": {
                       "allOf": [{"$ref": "#/components/schemas/Res"},
                                 {"properties": {
                                     "relationships": {"type": "object"}}}]}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Envelope"})}}})
        new = doc({"Res": base_new,
                   "Envelope": {"type": "object", "properties": {"data": {
                       "allOf": [{"$ref": "#/components/schemas/Res"}]}}}},
                  {"/things": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/Envelope"})}}})
        verdict, why = check(
            finding("response_field_type_changed", subject="<Envelope>.data",
                    root_cause="Envelope.data", status="200"),
            old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)


class TestNullability(unittest.TestCase):
    """Whether a value may be null is part of the contract, and
    `effective_shape` never looked at it. Cloudflare dropped `nullable: true`
    from five email-security REQUEST fields in one window: a caller that was
    sending null is now rejected, and every one compared equal to itself."""

    def _check(self, old_prop, new_prop):
        old = doc({"Req": {"type": "object", "properties": {"p": old_prop}},
                   "Pattern": {"type": "string", "enum": ["EMAIL", "IP"]}},
                  {"/things": {"post": {"requestBody": {"content": {
                      "application/json": {"schema": {
                          "$ref": "#/components/schemas/Req"}}}}}}})
        new = doc({"Req": {"type": "object", "properties": {"p": new_prop}},
                   "Pattern": {"type": "string", "enum": ["EMAIL", "IP"]}},
                  {"/things": {"post": {"requestBody": {"content": {
                      "application/json": {"schema": {
                          "$ref": "#/components/schemas/Req"}}}}}}})
        return check(finding("schema_field_type_changed", subject="<Req>.p",
                             root_cause="Req.p", op_key="POST /things"),
                     old, new, [], [])

    def test_dropping_nullable_from_an_allOf_arm_is_confirmed(self):
        """`allOf: [{$ref: X}, {nullable: true}]` is the only way OpenAPI 3.0
        can make a reference nullable, so the flag has to survive the merge."""
        verdict, why = self._check(
            {"allOf": [{"$ref": "#/components/schemas/Pattern"},
                       {"nullable": True, "type": "string"}]},
            {"$ref": "#/components/schemas/Pattern"})
        self.assertEqual(CONFIRMED, verdict, why)

    def test_dropping_nullable_from_the_field_itself_is_confirmed(self):
        verdict, why = self._check({"type": "string", "nullable": True},
                                   {"type": "string"})
        self.assertEqual(CONFIRMED, verdict, why)

    def test_nullable_on_both_sides_is_still_refuted(self):
        """The other direction: nullability must DISTINGUISH, not confirm
        everything it touches."""
        verdict, why = self._check(
            {"allOf": [{"$ref": "#/components/schemas/Pattern"},
                       {"nullable": True}]},
            {"allOf": [{"$ref": "#/components/schemas/Pattern"},
                       {"nullable": True, "description": "reworded"}]})
        self.assertEqual(REFUTED, verdict, why)


class TestAnyValueIsNotIgnorance(unittest.TestCase):
    """`{}` accepts any JSON value. That is the DOCUMENT speaking.

    It used to resolve to `("scalar", None, None)` -- the very same tuple the
    checker returned when it could not read a node at all. One value meaning
    both "accepts anything" and "I cannot tell" is what let PayPal's narrowing
    of `payment_source.crypto` from `{}` to a `crypto_request` read as no
    change, and it is why guarding the comparison on ignorance broke that case
    until the two were separated.
    """

    def test_an_empty_schema_is_a_positive_statement(self):
        from measure_precision import ANY_VALUE, effective_shape
        self.assertEqual(ANY_VALUE, effective_shape({}, doc()))
        self.assertEqual(ANY_VALUE, effective_shape(
            {"title": "anything", "description": "really"}, doc()))

    def test_a_node_this_cannot_read_is_NOT_a_positive_statement(self):
        from measure_precision import UNRESOLVED, _informative, effective_shape
        shape = effective_shape({"minLength": 3}, doc())
        self.assertEqual(UNRESOLVED, shape)
        self.assertFalse(_informative(shape))

    def test_narrowing_from_any_to_a_shape_is_still_decidable(self):
        from measure_precision import ANY_VALUE, _informative
        self.assertTrue(_informative(ANY_VALUE),
                        "'accepts anything' must be comparable, or every "
                        "narrowing away from it reads as unknown")


class TestParameterEnum(unittest.TestCase):
    """A query parameter's enum lives in `parameters`, not in a schema.
    `vendor_control.py` injected exactly this break into twelve vendors' real
    specs and printed `found+undecidable` for every one of them."""

    def _specs(self, new_schema):
        old = doc({}, {"/things": {"get": {
            "parameters": [{"name": "object", "in": "query",
                            "schema": {"type": "string",
                                       "enum": ["bank_account", "card"]}}],
            "responses": resp({"type": "object"})}}})
        new = doc({}, {"/things": {"get": {
            "parameters": [{"name": "object", "in": "query",
                            "schema": new_schema}],
            "responses": resp({"type": "object"})}}})
        return old, new

    def test_a_dropped_parameter_enum_value_is_confirmed(self):
        old, new = self._specs({"type": "string", "enum": ["bank_account"]})
        verdict, why = check(
            finding("request_enum_value_removed", subject="object",
                    root_cause=""), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_dropping_the_enum_KEYWORD_widens_and_is_refuted(self):
        """The refutation the engine's question cannot reach: with no `enum`
        the parameter accepts every value, so "no longer accepts card" is
        false."""
        old, new = self._specs({"type": "string"})
        verdict, why = check(
            finding("request_enum_value_removed", subject="object",
                    root_cause=""), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_parameter_that_kept_every_value_is_refuted(self):
        old, new = self._specs({"type": "string",
                                "enum": ["card", "bank_account", "other"]})
        verdict, why = check(
            finding("request_enum_value_removed", subject="object",
                    root_cause=""), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_referenced_parameter_is_resolved(self):
        old = doc({}, {"/things": {"get": {
            "parameters": [{"$ref": "#/components/parameters/Obj"}],
            "responses": resp({"type": "object"})}}})
        old["components"]["parameters"] = {"Obj": {
            "name": "object", "in": "query",
            "schema": {"type": "string", "enum": ["a", "b"]}}}
        new = doc({}, {"/things": {"get": {
            "parameters": [{"$ref": "#/components/parameters/Obj"}],
            "responses": resp({"type": "object"})}}})
        new["components"]["parameters"] = {"Obj": {
            "name": "object", "in": "query",
            "schema": {"type": "string", "enum": ["a"]}}}
        verdict, why = check(
            finding("request_enum_value_removed", subject="object",
                    root_cause=""), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)


class TestArmMarkers(unittest.TestCase):
    def test_an_uncollapsed_subject_is_still_addressable(self):
        """`root_cause` is only set on findings that went through collapse().
        Anything else arrives as `<ListCompanyResponse>._links`, and every
        branch looked that up in components/schemas and found nothing. It is
        why the adyen and sendgrid response controls read found+undecidable."""
        old = doc({"ListCompanyResponse": {"type": "object", "properties": {
                       "_links": {"type": "object"},
                       "data": {"type": "string"}}}},
                  {"/companies": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/ListCompanyResponse"})}}})
        new = doc({"ListCompanyResponse": {"type": "object", "properties": {
                       "data": {"type": "string"}}}},
                  {"/companies": {"get": {"responses": resp(
                      {"$ref": "#/components/schemas/ListCompanyResponse"})}}})
        verdict, why = check(
            finding("response_field_removed",
                    subject="<ListCompanyResponse>._links",
                    root_cause="", op_key="GET /companies", status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)


class TestRequestBodyNowRequired(unittest.TestCase):
    def test_a_body_that_became_required_is_confirmed(self):
        old = doc({}, {"/things": {"post": {"requestBody": {
            "content": {"application/json": {"schema": {"type": "object"}}}}}}})
        new = doc({}, {"/things": {"post": {"requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}}}}}})
        verdict, why = check(
            finding("request_body_now_required", subject="body",
                    root_cause="body", op_key="POST /things"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_body_that_is_still_optional_is_refuted(self):
        body = {"content": {"application/json": {"schema": {"type": "object"}}}}
        old = doc({}, {"/things": {"post": {"requestBody": body}}})
        new = doc({}, {"/things": {"post": {"requestBody": dict(body)}}})
        verdict, why = check(
            finding("request_body_now_required", subject="body",
                    root_cause="body", op_key="POST /things"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_the_required_flag_is_read_through_a_reference(self):
        """`requestBody` is routinely a $ref and `required` lives on the
        TARGET. Reading the flag off the reference object sees nothing and
        refutes every one of them."""
        old = doc({}, {"/things": {"post": {"requestBody": {
            "$ref": "#/components/requestBodies/Body"}}}})
        old["components"]["requestBodies"] = {"Body": {
            "content": {"application/json": {"schema": {"type": "object"}}}}}
        new = doc({}, {"/things": {"post": {"requestBody": {
            "$ref": "#/components/requestBodies/Body"}}}})
        new["components"]["requestBodies"] = {"Body": {
            "required": True,
            "content": {"application/json": {"schema": {"type": "object"}}}}}
        verdict, why = check(
            finding("request_body_now_required", subject="body",
                    root_cause="body", op_key="POST /things"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)


class TestServerUrlChanged(unittest.TestCase):
    def test_a_base_url_move_with_no_overlap_is_confirmed(self):
        old = doc()
        old["servers"] = [{"url": "https://paltokenization-test.adyen.com/x"}]
        new = doc()
        new["servers"] = [{"url": "https://pal-test.adyen.com/y"}]
        verdict, why = check(
            finding("server_url_changed", subject="<server>",
                    root_cause="server", op_key="GET /"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_overlapping_base_url_set_is_refuted(self):
        old = doc()
        old["servers"] = [{"url": "https://api.example.com"}]
        new = doc()
        new["servers"] = [{"url": "https://api.example.com"},
                          {"url": "https://eu.example.com"}]
        verdict, why = check(
            finding("server_url_changed", subject="<server>",
                    root_cause="server", op_key="GET /"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_templated_url_is_expanded_before_comparing(self):
        """Parameterising a URL that did not move is notation, not a
        relocation -- the same mistake as a path parameter rename."""
        old = doc()
        old["servers"] = [{"url": "https://eu.example.com"}]
        new = doc()
        new["servers"] = [{"url": "https://{region}.example.com",
                           "variables": {"region": {"default": "eu"}}}]
        verdict, why = check(
            finding("server_url_changed", subject="<server>",
                    root_cause="server", op_key="GET /"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_missing_servers_block_is_UNDECIDABLE_not_refuted(self):
        old = doc()
        new = doc()
        new["servers"] = [{"url": "https://api.example.com"}]
        verdict, why = check(
            finding("server_url_changed", subject="<server>",
                    root_cause="server", op_key="GET /"), old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)

class TestSchemaFieldTypeChanged(unittest.TestCase):
    """The checker has to READ an `allOf`, not fall past it.

    It recognised a single-arm `allOf` and nothing else, so
    `{"allOf": [{"$ref": X}, {"description": ...}]}` -- the only way to attach
    prose to a reference in OpenAPI 3.0 -- came out as ("scalar", None, None),
    this checker's way of saying it saw nothing at all. That answer was then
    compared for EQUALITY: two of them REFUTED a finding, and one against a
    resolved shape CONFIRMED one. Both readings shipped, on 344 findings, and
    both were the checker reporting its own blindness as a verdict.
    """

    def _f(self, old_prop, new_prop, extra_old=None, extra_new=None):
        old_schemas = {"Card": {"type": "object",
                                "properties": {"src": old_prop}}}
        new_schemas = {"Card": {"type": "object",
                                "properties": {"src": new_prop}}}
        old_schemas.update(extra_old or {})
        new_schemas.update(extra_new or {})
        return (finding("schema_field_type_changed", root_cause="Card.src",
                        subject="Card.src"),
                doc(old_schemas), doc(new_schemas))

    def test_prose_wrapped_in_an_allof_is_refuted_on_its_merits(self):
        bank = {"Bank": {"type": "object",
                         "properties": {"id": {"type": "string"}}}}
        f, old, new = self._f(
            {"$ref": "#/components/schemas/Bank", "description": "src"},
            {"allOf": [{"$ref": "#/components/schemas/Bank"},
                       {"description": "src", "deprecated": True}]},
            bank, bank)
        verdict, why = check(f, old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)
        self.assertIn("Bank" if "Bank" in why else "object", why)

    def test_an_allof_that_really_gains_a_field_is_confirmed(self):
        bank = {"Bank": {"type": "object",
                         "properties": {"id": {"type": "string"}}}}
        f, old, new = self._f(
            {"allOf": [{"$ref": "#/components/schemas/Bank"}]},
            {"allOf": [{"$ref": "#/components/schemas/Bank"},
                       {"type": "object",
                        "properties": {"extra": {"type": "string"}}}]},
            bank, bank)
        verdict, why = check(f, old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_two_unresolvable_shapes_are_undecidable_not_refuted(self):
        """A refuter that knows nothing about either side has decided nothing.

        `{}` on both sides says the same thing twice: not that they agree, but
        that this checker cannot see them. Reporting REFUTED there is the same
        defect as a suppressor whose precondition holds for every input.
        """
        f, old, new = self._f({"externalRef": "a"}, {"externalRef": "b"})
        verdict, why = check(f, old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)

    def test_an_unreadable_new_side_is_undecidable_not_confirmed(self):
        f, old, new = self._f({"type": "string"}, {"externalRef": "b"})
        verdict, why = check(f, old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)

    def test_a_real_type_change_is_still_confirmed(self):
        f, old, new = self._f({"type": "string"}, {"type": "integer"})
        verdict, why = check(f, old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)


if __name__ == "__main__":
    unittest.main()
