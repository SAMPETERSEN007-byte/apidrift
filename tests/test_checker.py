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


class TestUncollapsedFindingsAreStillAddressable(unittest.TestCase):
    """`root_cause` is only set by `collapse()`.

    Anything that did not go through it -- an injected control, a finding on a
    single operation -- arrives with an empty `root_cause` and its address in
    `subject`. Taking the leaf from `root_cause` alone yielded the empty string
    and refuted a break the control had just injected, reporting
    "`` required old=False new=False". Caught by `vendor_control.py`, which is
    the entire reason to inject a break whose answer is known.
    """

    def test_a_top_level_required_field_with_no_root_cause_is_confirmed(self):
        body = {"type": "object", "properties": {"To": {"type": "string"}}}
        added = {"type": "object",
                 "properties": {"To": {"type": "string"},
                                "control_field": {"type": "string"}},
                 "required": ["control_field"]}
        old = doc({}, {"/things": {"post": {"requestBody": {"content": {
            "application/json": {"schema": body}}}, "responses": resp({})}}})
        new = doc({}, {"/things": {"post": {"requestBody": {"content": {
            "application/json": {"schema": added}}}, "responses": resp({})}}})
        verdict, why = check(
            finding("request_field_added_required", subject="control_field",
                    root_cause="", op_key="POST /things"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_finding_naming_no_field_at_all_is_undecidable(self):
        """The control. Empty means unknown, and unknown is not 'refuted'."""
        old = doc({}, {"/things": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"type": "object"}}}},
            "responses": resp({})}}})
        verdict, _ = check(
            finding("request_field_added_required", subject="", root_cause="",
                    op_key="POST /things"), old, old, [], [])
        self.assertEqual(UNDECIDABLE, verdict)


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

class TestResponseFieldRemovedAsksTheCallersQuestion(unittest.TestCase):
    """Layer 3 must be able to refute this class WITHOUT the engine's help.

    Every suppression added to the engine for it is paired with a case here, and
    each one is decided from the raw document by a resolver this file owns. If
    disabling the engine's half left these green, the two would be one opinion
    with two names -- which is the defect this project has shipped five times.
    """

    def _op(self, schema, status="200"):
        return {"/things": {"get": {"responses": resp(schema, status)}}}

    def test_a_genuinely_removed_field_is_confirmed(self):
        """The control. `stripe token.card.iin`, in miniature."""
        old = doc({}, self._op({"type": "object", "properties": {
            "card": {"type": "object", "properties": {"iin": {"type": "string"}}}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "card": {"type": "object", "properties": {"last4": {"type": "string"}}}}}))
        verdict, why = check(
            finding("response_field_removed", subject="card.iin",
                    root_cause="card.iin", status="200"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_collapsed_nullability_wrapper_is_refuted(self):
        """`oneOf: [null, X]` -> `$ref X`. Discord, across its whole spec."""
        theme = {"type": "object", "properties": {"hue": {"type": "string"}}}
        old = doc({"Theme": theme}, self._op({"type": "object", "properties": {
            "theme": {"oneOf": [{"type": "null"},
                                {"$ref": "#/components/schemas/Theme"}]}}}))
        new = doc({"Theme": theme}, self._op({"type": "object", "properties": {
            "theme": {"$ref": "#/components/schemas/Theme"}}}))
        verdict, why = check(
            finding("response_field_removed", subject="theme<Theme>",
                    root_cause="Theme", status="200"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_renamed_schema_behind_the_wrapper_is_refuted(self):
        """OpenAI: `Conversation-2` -> `ResponseConversation`, byte-identical."""
        body = {"type": "object", "properties": {"id": {"type": "string"}},
                "required": ["id"]}
        old = doc({"Conversation-2": body}, self._op({
            "type": "object", "properties": {"conversation": {
                "anyOf": [{"$ref": "#/components/schemas/Conversation-2"},
                          {"type": "null"}]}}}))
        new = doc({"ResponseConversation": body}, self._op({
            "type": "object", "properties": {"conversation": {
                "anyOf": [{"$ref": "#/components/schemas/ResponseConversation"},
                          {"type": "null"}]}}}))
        verdict, why = check(
            finding("response_field_removed",
                    subject="conversation<Conversation-2>",
                    root_cause="Conversation-2", status="200"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_response_arm_removal_is_confirmed(self):
        """The control that stops the arm rule being a deletion.

        Discord's 200 for `GET /guilds/{id}/auto-moderation/rules` swapped
        `SpamLinkRuleResponse` for `UserProfileRuleResponse`. The two carry the
        SAME property names and differ only in the value `trigger_type` is
        pinned to, so a check on names alone refutes a real break.
        """
        def rule(value):
            return {"type": "object", "properties": {
                "id": {"type": "string"},
                "trigger_type": {"type": "integer", "enum": [value]}}}
        old = doc({"SpamLinkRuleResponse": rule(2), "KeywordRuleResponse": rule(1)},
                  self._op({"type": "array", "items": {"oneOf": [
                      {"$ref": "#/components/schemas/KeywordRuleResponse"},
                      {"$ref": "#/components/schemas/SpamLinkRuleResponse"}]}}))
        new = doc({"UserProfileRuleResponse": rule(4), "KeywordRuleResponse": rule(1)},
                  self._op({"type": "array", "items": {"oneOf": [
                      {"$ref": "#/components/schemas/KeywordRuleResponse"},
                      {"$ref": "#/components/schemas/UserProfileRuleResponse"}]}}))
        verdict, why = check(
            finding("response_field_removed", subject="[]<SpamLinkRuleResponse>",
                    root_cause="SpamLinkRuleResponse", status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_arm_replaced_by_a_SMALLER_shape_is_confirmed(self):
        """The property-set half of the arm rule, on its own.

        `test_response_arm_removal_is_confirmed` is decided by the pinned
        `trigger_type` values, so it stays green even if the superset test is
        deleted. Here the names alone settle it: the new arm cannot deliver
        `name`.
        """
        old = doc({"Full": {"type": "object", "properties": {
                       "id": {"type": "string"}, "name": {"type": "string"}}},
                   "Other": {"type": "object", "properties": {
                       "kind": {"type": "string"}}}},
                  self._op({"oneOf": [{"$ref": "#/components/schemas/Full"},
                                      {"$ref": "#/components/schemas/Other"}]}))
        new = doc({"Slim": {"type": "object", "properties": {
                       "id": {"type": "string"}}},
                   "Other": {"type": "object", "properties": {
                       "kind": {"type": "string"}}}},
                  self._op({"oneOf": [{"$ref": "#/components/schemas/Slim"},
                                      {"$ref": "#/components/schemas/Other"}]}))
        verdict, why = check(
            finding("response_field_removed", subject="<Full>",
                    root_cause="Full", status="200"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_union_collapsed_onto_a_covering_object_is_refuted(self):
        """Adyen merged `[Iban, USLocal]` into one object carrying both."""
        old = doc({"Iban": {"type": "object", "properties": {
                       "iban": {"type": "string"}}},
                   "USLocal": {"type": "object", "properties": {
                       "routingNumber": {"type": "string"}}}},
                  self._op({"type": "object", "properties": {"bankAccount": {
                      "oneOf": [{"$ref": "#/components/schemas/Iban"},
                                {"$ref": "#/components/schemas/USLocal"}]}}}))
        new = doc({"BankAccountDetails": {"type": "object", "properties": {
                       "iban": {"type": "string"},
                       "routingNumber": {"type": "string"}}}},
                  self._op({"type": "object", "properties": {"bankAccount": {
                      "$ref": "#/components/schemas/BankAccountDetails"}}}))
        verdict, why = check(
            finding("response_field_removed", subject="bankAccount<Iban>",
                    root_cause="Iban", status="200"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_field_promised_by_only_ONE_new_arm_is_confirmed(self):
        """A union is not an `allOf`.

        Cloudflare widened an Access policy's `result` to
        `anyOf[app_policy, infra_policy]`. Nine names live in both arms and
        seven only in the first; a walk that returns the first arm that has the
        field calls all sixteen safe.
        """
        old = doc({}, self._op({"type": "object", "properties": {
            "result": {"type": "object", "properties": {
                "id": {"type": "string"}, "precedence": {"type": "integer"}}}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "result": {"anyOf": [
                {"type": "object", "properties": {
                    "id": {"type": "string"}, "precedence": {"type": "integer"}}},
                {"type": "object", "properties": {"id": {"type": "string"}}}]}}}))
        confirmed, why = check(
            finding("response_field_removed", subject="result.precedence",
                    root_cause="result.precedence", status="200"), old, new, [], [])
        self.assertEqual(CONFIRMED, confirmed, why)
        refuted, why = check(
            finding("response_field_removed", subject="result.id",
                    root_cause="result.id", status="200"), old, new, [], [])
        self.assertEqual(REFUTED, refuted, why)

    def test_a_oneOf_of_const_values_is_one_scalar_not_alternatives(self):
        """Discord documents `ForumLayout` as `type: integer` + `oneOf` consts.

        Read as three alternatives, each arm declares no type at all, so the
        old `integer` matches none of them and an untouched field is CONFIRMED
        as removed. Over-confirming is the same defect as over-refuting: a
        verdict the document does not support.
        """
        layout = {"type": "integer", "oneOf": [
            {"title": "DEFAULT", "const": 0}, {"title": "LIST", "const": 1}]}
        old = doc({"ForumLayout": layout}, self._op({
            "type": "object", "properties": {"layout": {
                "oneOf": [{"type": "null"},
                          {"$ref": "#/components/schemas/ForumLayout"}]}}}))
        new = doc({"ForumLayout": layout}, self._op({
            "type": "object", "properties": {
                "layout": {"$ref": "#/components/schemas/ForumLayout"}}}))
        verdict, why = check(
            finding("response_field_removed", subject="layout<ForumLayout>",
                    root_cause="ForumLayout", status="200"), old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_dotted_schema_name_is_read_from_the_BRACKETS(self):
        """Twilio names schemas `messaging.v1.service.us_app_to_person`.

        Splitting `root_cause` on "." makes the head `messaging`, which is not a
        schema and not a property, so the finding was UNDECIDABLE -- 33 of them
        on one operation. The subject keeps the brackets the engine wrote.
        """
        person = {"type": "object", "properties": {"sid": {"type": "string"}}}
        old = doc({"messaging.v1.person": person},
                  self._op({"$ref": "#/components/schemas/messaging.v1.person"}))
        new = doc({"messaging.v1.person": {"type": "object",
                                           "properties": {"other": {"type": "string"}}}},
                  self._op({"$ref": "#/components/schemas/messaging.v1.person"}))
        verdict, why = check(
            finding("response_field_removed",
                    subject="<messaging.v1.person>.sid",
                    root_cause="messaging.v1.person.sid", status="200"),
            old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)
        self.assertNotIn("not a named schema", why)

    def test_a_free_form_object_is_UNDECIDABLE_not_confirmed(self):
        """Sentry replaced a declared `metadata` union with `{"type":"object"}`.

        Nothing in that document says whether `filename` still arrives. A
        verdict either way would be read off a premise that holds vacuously.
        """
        old = doc({}, self._op({"type": "object", "properties": {
            "metadata": {"type": "object", "properties": {
                "filename": {"type": "string"}}}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "metadata": {"type": "object", "additionalProperties": {}}}}))
        verdict, why = check(
            finding("response_field_removed", subject="metadata.filename",
                    root_cause="metadata.filename", status="200"), old, new, [], [])
        self.assertEqual(UNDECIDABLE, verdict, why)

    def test_a_CLOSED_empty_object_is_confirmed_not_abstained(self):
        """The other spelling, and the control on the rule above.

        Cloudflare's `DELETE .../ai-search/tokens/{id}` answers
        `{"type": "object", "additionalProperties": false}` where nine fields
        used to be. That document says explicitly that nothing else arrives.
        """
        old = doc({}, self._op({"type": "object", "properties": {
            "result": {"type": "object", "properties": {"id": {"type": "string"}}}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "result": {"type": "object", "additionalProperties": False}}}))
        verdict, why = check(
            finding("response_field_removed", subject="result.id",
                    root_cause="result.id", status="200"), old, new, [], [])
        self.assertEqual(CONFIRMED, verdict, why)

    def test_a_response_that_is_a_ref_into_components_responses_resolves(self):
        """PayPal and Cloudflare both write `responses: {default: {$ref: ...}}`.

        That pointer goes to `components/responses`, not `components/schemas`.
        Taking the basename and looking it up among the schemas found nothing,
        so the body was unresolvable on both sides and the check fell through to
        "is `error_400` still a schema?" -- the spec author's question, and the
        sixth time this checker has agreed with the engine by asking it.
        """
        old = doc({"error_400": {"type": "object", "properties": {
            "debug_id": {"type": "string"}, "name": {"type": "string"}}}},
            {"/things": {"get": {"responses": {
                "default": {"$ref": "#/components/responses/default"}}}}})
        old["components"]["responses"] = {"default": {"content": {
            "application/json": {"schema": {"oneOf": [
                {"$ref": "#/components/schemas/error_400"}]}}}}}
        new = doc({"error": {"type": "object", "properties": {
            "debug_id": {"type": "string"}, "name": {"type": "string"}}}},
            {"/things": {"get": {"responses": {
                "default": {"$ref": "#/components/responses/default_response"}}}}})
        new["components"]["responses"] = {"default_response": {"content": {
            "application/json": {"schema": {
                "$ref": "#/components/schemas/error"}}}}}
        verdict, why = check(
            finding("response_field_removed", subject="<error_400>.debug_id",
                    root_cause="error_400.debug_id", status="default"),
            old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)


class TestRequiredInsideANewParent(unittest.TestCase):
    def _op(self, schema):
        return {"/things": {"post": {
            "requestBody": {"content": {"application/json": {"schema": schema}}},
            "responses": resp({"type": "object"})}}}

    def test_a_requirement_inside_a_brand_new_object_is_refuted(self):
        old = doc({}, self._op({"type": "object",
                                "properties": {"amount": {"type": "integer"}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "amount": {"type": "integer"},
            "limits": {"type": "object",
                       "properties": {"accounts": {"type": "integer"}},
                       "required": ["accounts"]}}}))
        verdict, why = check(
            finding("request_field_added_required", subject="limits.accounts",
                    root_cause="limits.accounts", op_key="POST /things"),
            old, new, [], [])
        self.assertEqual(REFUTED, verdict, why)

    def test_a_requirement_added_to_an_EXISTING_object_is_confirmed(self):
        old = doc({}, self._op({"type": "object", "properties": {
            "limits": {"type": "object",
                       "properties": {"accounts": {"type": "integer"}}}}}))
        new = doc({}, self._op({"type": "object", "properties": {
            "limits": {"type": "object",
                       "properties": {"accounts": {"type": "integer"}},
                       "required": ["accounts"]}}}))
        verdict, why = check(
            finding("request_field_added_required", subject="limits.accounts",
                    root_cause="limits.accounts", op_key="POST /things"),
            old, new, [], [])
class TestNewlyRequired(unittest.TestCase):
    """The checker asked the ENGINE's question here: "does `leaf` appear in a
    `required:` array at the one node my dotted path reaches?"

    Sixth instance of the shared question, and its symptoms ran both ways: 103
    of 158 findings in this class came back "could not resolve the parent
    object" -- undecidable because the path carried a SCHEMA name the walk
    tried to follow as a property -- while the ones it did decide included both
    false confirmations (Cloudflare's renamed union arms) and false refutations
    (anything composed with `allOf`, whose obligations it never merged).
    """

    def _op(self, schema):
        return {"/things": {"post": {
            "requestBody": {"required": True,
                            "content": {"application/json": {"schema": schema}}},
            "responses": resp({"type": "object"})}}}

    def _obj(self, props, required):
        return {"type": "object", "properties": props, "required": required}

    def _check(self, old_schema, new_schema, subject, schemas=None):
        return check(finding("request_field_added_required", subject=subject,
                             root_cause=subject, op_key="POST /things"),
                     doc(schemas, self._op(old_schema)),
                     doc(schemas, self._op(new_schema)), [], [])

    def test_a_requirement_inside_a_NEW_object_is_refuted(self):
        verdict, why = self._check(
            self._obj({"amount": {"type": "integer"}}, ["amount"]),
            self._obj({"amount": {"type": "integer"},
                       "limits": self._obj({"accounts": {"type": "integer"}},
                                           ["accounts"])}, ["amount"]),
            "limits.accounts")
        self.assertEqual(REFUTED, verdict, why)
        self.assertIn("does not exist in the OLD", why)

    def test_a_requirement_added_to_an_EXISTING_object_is_confirmed(self):
        """The control. Without it the rule above is a deletion."""
        verdict, why = self._check(
            self._obj({"limits": self._obj({"accounts": {"type": "integer"}}, [])}, []),
            self._obj({"limits": self._obj({"accounts": {"type": "integer"}},
                                           ["accounts"])}, []),
            "limits.accounts")
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_obligation_carried_through_allOf_is_seen(self):
        """Cloudflare's `PUT /accounts/{id}/workers/domains` new body is
        `allOf: [workers_Domain, {required: [hostname, service]}]`. Reading the
        root's own `required` array finds nothing there, so three real breaks
        -- `cert_id`, `id`, `zone_name` -- were REFUTED as "required new=False".
        """
        schemas = {"Domain": self._obj({"cert_id": {"type": "string"}},
                                       ["cert_id"])}
        verdict, why = self._check(
            self._obj({"zone_id": {"type": "string"}}, ["zone_id"]),
            {"allOf": [{"$ref": "#/components/schemas/Domain"},
                       {"type": "object", "required": ["zone_id"]}]},
            "cert_id", schemas=schemas)
        self.assertEqual(CONFIRMED, verdict, why)

    def test_an_obligation_every_union_arm_ALREADY_had_is_refuted(self):
        """Cloudflare renamed all thirteen identity-provider arms in one
        release and added a fourteenth. Every arm required `config` before and
        after, so no body changed status -- only the flattener's key did."""
        arm = self._obj({"config": {"type": "object"}}, ["config"])
        schemas = {"AzureAD": arm, "AzureADV2": dict(arm), "Cloudflare": dict(arm)}
        verdict, why = self._check(
            {"anyOf": [{"$ref": "#/components/schemas/AzureAD"}]},
            {"anyOf": [{"$ref": "#/components/schemas/AzureADV2"},
                       {"$ref": "#/components/schemas/Cloudflare"}]},
            "<identity-providers><AzureADV2>.config", schemas=schemas)
        self.assertEqual(REFUTED, verdict, why)
        self.assertIn("ALREADY required", why)

    def test_an_obligation_only_ONE_new_arm_carries_is_UNDECIDABLE(self):
        """Not refuted. `anyOf` is a disjunction, so a name required by one arm
        is not required of the body -- but the caller who was using THAT arm
        does break, and deciding it needs an old-arm/new-arm correspondence the
        documents do not state. Over-refuting is over-confirming with the sign
        flipped.
        """
        schemas = {"Loose": self._obj({"id": {"type": "string"}}, []),
                   "Strict": self._obj({"id": {"type": "string"}}, ["id"])}
        verdict, why = self._check(
            {"anyOf": [{"$ref": "#/components/schemas/Loose"}]},
            {"anyOf": [{"$ref": "#/components/schemas/Strict"},
                       {"$ref": "#/components/schemas/Loose"}]},
            "<shape-abc>.id", schemas=schemas)
        self.assertEqual(UNDECIDABLE, verdict, why)

    def test_a_schema_qualified_path_still_resolves(self):
        """`<CheckoutForwardRequest>.amount.currency` is the flattener's name
        for the property `amount.currency`. Walking the angle-bracketed segment
        as a property name found nothing and returned UNDECIDABLE for 103 of
        the 158 findings in this class -- undecidable for a purely notational
        reason, which is not a measurement of anything.
        """
        body = {"$ref": "#/components/schemas/Req"}
        schemas_old = {"Req": self._obj(
            {"amount": self._obj({"value": {"type": "integer"}}, [])}, [])}
        schemas_new = {"Req": self._obj(
            {"amount": self._obj({"value": {"type": "integer"},
                                  "currency": {"type": "string"}},
                                 ["currency"])}, [])}
        verdict, why = check(
            finding("request_field_added_required",
                    subject="<Req>.amount.currency",
                    root_cause="Req.amount.currency", op_key="POST /things"),
            doc(schemas_old, self._op(body)), doc(schemas_new, self._op(body)),
            [], [])
        self.assertEqual(CONFIRMED, verdict, why)


if __name__ == "__main__":
    unittest.main()
