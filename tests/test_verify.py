"""Tests for turning a code-search candidate into a PROVEN lead.

Two adversarial audits refuted nine of ten leads each. The second named the
reason: verification established co-location, never dependence. Every refuted
case from both audits appears below as a rule, alongside the positive cases
that must keep passing.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apidrift.diff import BREAKING, Finding
from apidrift.verify import (CONFIRMED, NOT_AUTHOR_CODE, NO_DEPENDENCE,
                             NO_VENDOR, UNPROVEN, find_vendor_evidence,
                             lexical_sites, python_sites, verify_source)
from apidrift.vendors import get

STRIPE = get("stripe")


def finding(kind="schema_field_removed", subject="card.iin",
            path="/v1/customers", method="get", ops=(), sigs=(), leaves=()):
    return Finding(kind=kind, severity=BREAKING, op_key=f"{method.upper()} {path}",
                   path=path, method=method, detail="", subject=subject,
                   root_cause=subject, affected_ops=list(ops),
                   signatures=list(sigs), leaf_fields=list(leaves))


def verdict_of(source, finding_obj, vendor=STRIPE, path="app.py"):
    return verify_source(source, path, finding_obj, vendor)[0]


class TestProvenDependence(unittest.TestCase):
    """A lead must show the code depends on what changed."""

    def test_a_read_traced_to_a_vendor_call_is_proven(self):
        source = ('import stripe\n'
                  'def show(cid):\n'
                  '    card = stripe.Customer.retrieve(cid).default_source\n'
                  '    return card.iin\n')
        verdict, reason, _, sites = verify_source(source, "app.py", finding(), STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertIn("stripe.Customer.retrieve", reason)
        self.assertTrue(sites[0].chain, "a proof must carry its reasoning")

    def test_a_read_off_a_parameter_needs_the_carrying_operation(self):
        """Most reads happen on a parameter, whose origin is in the caller."""
        source = ('import discord\n'
                  'async def go(self, gid):\n'
                  '    r = Route("GET", "/guilds/{guild_id}/channels")\n'
                  '    ch = await self.request(r)\n'
                  '    return ch.icon_emoji\n')
        f = finding(subject="GuildChannelResponse.icon_emoji",
                    path="/guilds/{guild_id}/channels",
                    ops=["GET /guilds/{guild_id}/channels"])
        self.assertEqual(verdict_of(source, f, get("discord")), CONFIRMED)

    def test_reading_the_field_while_calling_something_else_is_not_dependence(self):
        source = ('import discord\n'
                  'async def go(self, gid):\n'
                  '    r = Route("DELETE", "/guilds/{guild_id}/members/{uid}")\n'
                  '    ch = await self.request(r)\n'
                  '    return ch.icon_emoji\n')
        f = finding(subject="GuildChannelResponse.icon_emoji",
                    path="/guilds/{guild_id}/channels",
                    ops=["GET /guilds/{guild_id}/channels"])
        self.assertEqual(verdict_of(source, f, get("discord")), NO_DEPENDENCE)

    def test_an_sdk_call_reaches_an_operation_that_names_no_path(self):
        source = ('import stripe\n'
                  'stripe.checkout.Session.create(subscription_data={"trial": 7})\n')
        f = finding(kind="schema_field_added_required",
                    subject="CheckoutSession.day_of_month",
                    path="/v1/checkout/sessions", method="post",
                    sigs=["stripe.checkout."])
        self.assertEqual(verdict_of(source, f), CONFIRMED)

    def test_a_caller_that_already_supplies_the_field_is_not_a_lead(self):
        source = ('import stripe\n'
                  'stripe.checkout.Session.create(day_of_month=1)\n')
        f = finding(kind="schema_field_added_required",
                    subject="CheckoutSession.day_of_month",
                    path="/v1/checkout/sessions", method="post",
                    sigs=["stripe.checkout."])
        self.assertEqual(verdict_of(source, f), NO_DEPENDENCE)


class TestAuditedRefutations(unittest.TestCase):
    """Every case a skeptic refuted, kept as a rule."""

    def test_a_docstring_mention_is_not_dependence(self):
        source = ('"""Card model. Stores BIN/IIN and iin notes."""\n'
                  'import stripe\n')
        self.assertEqual(verdict_of(source, finding()), NO_DEPENDENCE)

    def test_a_field_name_in_the_repos_own_schema_is_not_dependence(self):
        """quay's Swagger literal described quay's own API, not Stripe's."""
        source = ('import stripe\n'
                  'schemas = {"UserCard": {"description": "d", "iin": "x"}}\n')
        self.assertEqual(verdict_of(source, finding()), NO_DEPENDENCE)

    def test_a_defaults_table_is_not_a_read(self):
        source = ('import openai\n'
                  'DEFAULTS = {"prompt_cache_key": None}\n')
        f = finding(subject="CreateChatCompletionResponse.prompt_cache_key",
                    path="/chat/completions")
        self.assertEqual(verdict_of(source, f, get("openai")), NO_DEPENDENCE)

    def test_pop_is_not_a_use(self):
        source = ('import openai\n'
                  'payload.pop("safety_identifier", None)\n')
        f = finding(subject="CreateChatCompletionRequest.safety_identifier",
                    path="/chat/completions")
        self.assertEqual(verdict_of(source, f, get("openai")), NO_DEPENDENCE)

    def test_a_sibling_route_sharing_a_prefix_is_not_a_match(self):
        """`/guilds` matched kick and ban routes for a bulk-ban change."""
        source = ('import discord\n'
                  'r = Route("DELETE", "/guilds/{guild_id}/members/{user_id}")\n')
        f = finding(kind="endpoint_removed", subject="/guilds/{guild_id}/bulk-ban",
                    path="/guilds/{guild_id}/bulk-ban", method="post")
        self.assertEqual(verdict_of(source, f, get("discord")), NO_DEPENDENCE)

    def test_the_same_path_with_a_different_method_is_not_a_match(self):
        """A path can be shared by operations that differ only by verb."""
        source = ('import discord\n'
                  'r = Route("GET", "/guilds/{guild_id}/bulk-ban")\n')
        f = finding(kind="endpoint_removed", subject="/guilds/{guild_id}/bulk-ban",
                    path="/guilds/{guild_id}/bulk-ban", method="post")
        self.assertEqual(verdict_of(source, f, get("discord")), NO_DEPENDENCE)

    def test_the_same_path_with_the_right_method_is_a_match(self):
        source = ('import discord\n'
                  'r = Route("POST", "/guilds/{guild_id}/bulk-ban")\n')
        f = finding(kind="endpoint_removed", subject="/guilds/{guild_id}/bulk-ban",
                    path="/guilds/{guild_id}/bulk-ban", method="post")
        self.assertEqual(verdict_of(source, f, get("discord")), CONFIRMED)

    def test_a_sibling_sub_resource_is_not_a_match(self):
        """/Recall and /Events share `/v1/Stores` and are different operations."""
        source = ('import twilio\n'
                  'r = post(f"{BASE}/v1/Stores/{s}/Profiles/{p}/Recall")\n')
        f = finding(kind="endpoint_removed",
                    subject="/v1/Stores/{storeId}/Profiles/{profileId}/Events",
                    path="/v1/Stores/{storeId}/Profiles/{profileId}/Events",
                    method="post")
        self.assertEqual(verdict_of(source, f, get("twilio")), NO_DEPENDENCE)

    def test_the_right_sub_resource_is_a_match(self):
        source = ('import twilio\n'
                  'r = post(f"{BASE}/v1/Stores/{s}/Profiles/{p}/Events")\n')
        f = finding(kind="endpoint_removed",
                    subject="/v1/Stores/{storeId}/Profiles/{profileId}/Events",
                    path="/v1/Stores/{storeId}/Profiles/{profileId}/Events",
                    method="post")
        self.assertEqual(verdict_of(source, f, get("twilio")), CONFIRMED)

    def test_an_endpoint_quoted_in_prose_is_not_a_call(self):
        source = ('import twilio\n'
                  'st.caption("Runs POST /v1/Stores/x/Events and returns rows")\n')
        f = finding(kind="endpoint_removed", subject="/v1/Stores/{s}/Events",
                    path="/v1/Stores/{s}/Events", method="post")
        self.assertEqual(verdict_of(source, f, get("twilio")), NO_DEPENDENCE)

    def test_generated_code_is_rejected_before_anything_else(self):
        source = ('# File generated from our OpenAPI spec by Castiron.\n'
                  'import stripe\n'
                  'def show(c):\n'
                  '    card = stripe.Customer.retrieve(c)\n'
                  '    return card.iin\n')
        self.assertEqual(verdict_of(source, finding()), NOT_AUTHOR_CODE)

    def test_openapi_generator_header_is_rejected(self):
        source = ('"""The Plaid API\n\n'
                  '    Generated by: https://openapi-generator.tech\n"""\n'
                  'import plaid\n')
        self.assertEqual(verdict_of(source, finding(), get("plaid")),
                         NOT_AUTHOR_CODE)


class TestVendorEvidence(unittest.TestCase):
    def test_a_field_change_needs_the_vendor_in_the_file(self):
        source = 'def parse_iban(record):\n    return record.iin\n'
        self.assertEqual(verdict_of(source, finding()), NO_VENDOR)

    def test_evidence_needs_a_word_boundary(self):
        self.assertEqual(
            find_vendor_evidence(
                "from some_pkg.config import OpenAICompatibleConfig\n",
                get("openai")),
            "", "a longer identifier is not an import of the vendor")
        self.assertEqual(
            find_vendor_evidence("import openai\n", get("openai")),
            "import openai")


class TestEvidenceIsLanguageAware(unittest.TestCase):
    """Every marker in the registry is PYTHON-shaped.

    JavaScript writes the module name in quotes, so
    `import { Resend } from 'resend'` matched NOTHING for resend, openai,
    cloudflare, box, telnyx and most of the rest. Stripe passed only by
    accident: `import Stripe` contains `import stripe` once lowercased. The
    consequence was not a weaker proof -- files were rejected at this gate and
    never examined, so a TypeScript repo full of Resend calls reported "no
    impact" having looked at nothing.
    """

    def test_an_es_module_import_is_evidence(self):
        for key, package in (("resend", "resend"), ("plaid", "plaid"),
                             ("openai", "openai"), ("telnyx", "telnyx")):
            source = f"import {{ X }} from '{package}';\n"
            self.assertTrue(
                find_vendor_evidence(source, get(key), "a.ts"),
                f"{key}: an ES-module import of its own SDK is evidence")

    def test_a_scoped_package_and_a_subpath_are_evidence(self):
        self.assertTrue(find_vendor_evidence(
            'import { Client } from "@hubspot/api-client";\n',
            get("hubspot"), "a.ts"))
        self.assertTrue(find_vendor_evidence(
            "import x from '@sentry/node/esm';\n", get("sentry"), "a.ts"))

    def test_require_is_evidence(self):
        self.assertTrue(find_vendor_evidence(
            "const { Resend } = require('resend');\n", get("resend"), "a.js"))

    def test_an_unrelated_package_is_not_evidence(self):
        """The control. Admitting every JS file would move the failure from
        'never looked' to 'looked at everything', which is the co-location
        mistake two audits already refuted nine leads for."""
        self.assertEqual("", find_vendor_evidence(
            "import { Resend } from 'not-resend-at-all';\n",
            get("resend"), "a.ts"))
        self.assertEqual("", find_vendor_evidence(
            "// we should use resend one day\n", get("resend"), "a.ts"))

    def test_python_files_are_unaffected(self):
        self.assertEqual("", find_vendor_evidence(
            "import { X } from 'resend';\n", get("resend"), "a.py"),
            "the JavaScript forms must not leak into the Python gate")


class TestUnprovableLanguages(unittest.TestCase):
    """An unproven lead is an unmeasured claim, not a weaker one."""

    def test_javascript_that_really_reads_the_field_is_confirmed(self):
        """This used to assert UNPROVEN, and it was right to: nothing parsed
        JavaScript. Now something does, and this source is a complete proof --
        the client is required from `stripe`, the call is assigned to `c`, and
        `iin` is read off `c`. Asserting UNPROVEN here now would be asserting
        that the tool must ignore what it can see."""
        source = ('const stripe = require("stripe")(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        verdict, _, _, sites = verify_source(source, "pay.js", finding(), STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(3, sites[0].line, "and it cites the line of the read")

    def test_javascript_with_the_vendor_but_no_dependence_is_not_confirmed(self):
        """The invariant the test above used to carry. Co-location is not
        dependence in any language, and being able to READ JavaScript is not a
        licence to convict it."""
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.email;\n')
        verdict, reason, _, _ = verify_source(source, "pay.js", finding(), STRIPE)
        self.assertNotEqual(verdict, CONFIRMED, reason)

    def test_a_pinned_api_version_is_not_affected(self):
        """`new Stripe(k, { apiVersion: '...' })` pins the caller to a version
        the change did not touch. Named as an open blind spot for months and
        never modelled; real code pins in exactly this position."""
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k, { apiVersion: "2024-06-20" });\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        verdict, reason, _, _ = verify_source(source, "pay.ts", finding(), STRIPE)
        self.assertNotEqual(verdict, CONFIRMED)
        self.assertIn("pins the API version", reason)

    def test_a_READ_does_not_prove_a_REQUEST_side_change(self):
        """Direction is not decoration: an object key is how you SEND a field
        and a property access is how you READ one. Confusing the two is a
        gated false-positive class -- it is why `phasehq/console` was reported
        broken by a request-side change it only read the response of.

        The finding here is REQUEST-side and the file only ever reads `iin`
        off the response. Written the other way round -- a request-side file
        against a response-side finding -- the test passes whether the
        direction check exists or not, because the read simply is not there.
        """
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        verdict, reason, _, _ = verify_source(
            source, "pay.ts", finding(kind="request_field_removed"), STRIPE)
        self.assertNotEqual(verdict, CONFIRMED, reason)
        self.assertIn("never sends", reason)

    def test_a_read_of_a_generic_name_on_UNRELATED_data_is_not_dependence(self):
        """The defect this test exists for, taken verbatim from real code.

        Langfuse's `_app.tsx` was reported as depending on Sentry's replay
        endpoint because it reads `error.name` off a DOMException. Twenty-seven
        impacts across three real repositories were this: `.name`, `.id`,
        `.user` read off NextAuth sessions, DOM exceptions and PostHog calls.

        Co-location is not dependence. It took three adversarial audits to
        remove that from the Python prover and I reintroduced it here by
        implementing only half its contract -- a read, without the call to an
        operation that carries the field.
        """
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'try { risky(); } catch (error) {\n'
                  '  if (error.iin === "NotFound") { return null; }\n'
                  '}\n')
        verdict, reason, _, _ = verify_source(source, "app.ts", finding(), STRIPE)
        self.assertNotEqual(verdict, CONFIRMED, reason)
        self.assertIn("never calls an operation that carries it", reason)

    def test_a_read_TRACED_to_a_vendor_call_is_still_dependence(self):
        """The control. The fix must remove coincidence, not evidence."""
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        verdict, reason, _, sites = verify_source(
            source, "app.ts", finding(), STRIPE)
        self.assertEqual(CONFIRMED, verdict, reason)
        self.assertIn("came from", " ".join(sites[0].chain))

    def test_a_traced_read_stands_ALONE_when_the_path_does_not_match(self):
        """The case where tracing is the only route left.

        The value demonstrably came from this vendor and the changed field is
        read off it. That is dependence end to end, and it does not need the
        path matcher to agree -- which matters, because the path here belongs
        to a different resource than the SDK chain names. Written this way on
        purpose: with the call and the finding on the same resource, route 2
        also succeeds and the two are indistinguishable.
        """
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        elsewhere = finding(path="/v1/issuing/cards", method="post")
        verdict, reason, _, _ = verify_source(
            source, "app.ts", elsewhere, STRIPE)
        self.assertEqual(CONFIRMED, verdict, reason)

    def test_javascript_this_cannot_read_is_unproven_not_clean(self):
        """An unterminated string means the tokeniser stopped early. A file
        read halfway is not a file that was checked."""
        source = ('import Stripe from "stripe";\n'
                  "const s = 'oops\n"
                  'const c = await stripe.customers.retrieve(id);\n')
        verdict, reason, _, _ = verify_source(source, "pay.js", finding(), STRIPE)
        self.assertEqual(verdict, UNPROVEN)
        self.assertIn("unreadable", reason)

    def test_an_unknown_language_is_also_unproven(self):
        self.assertEqual(verdict_of("card.iin", finding(), path="main.rs"),
                         UNPROVEN)


class TestSiteHelpers(unittest.TestCase):
    """The lower-level scanners still behave, and are still used for reporting."""

    def test_docstring_prose_is_never_a_python_site(self):
        sites, error = python_sites('"""iin notes"""\n', "iin")
        self.assertIsNone(error)
        self.assertEqual(sites, [])

    def test_get_is_a_use_and_pop_is_not(self):
        self.assertEqual(
            [s.kind for s in python_sites('x = p.get("iin")\n', "iin")[0]],
            ["dict_get"])
        self.assertEqual(python_sites('p.pop("iin", None)\n', "iin")[0], [])

    def test_unparseable_python_is_reported_not_swallowed(self):
        source = 'import stripe\ndef broken(:\n'
        verdict, reason, _, _ = verify_source(source, "x.py", finding(), STRIPE)
        self.assertEqual(verdict, NO_DEPENDENCE)
        self.assertIn("unparseable", reason)

    def test_lexical_scanning_strips_comments(self):
        self.assertEqual(lexical_sites("// card.iin\n", "iin"), [])
        self.assertTrue(lexical_sites("return card.iin;\n", "iin"))


class TestProvenanceAtLeadTime(unittest.TestCase):
    """The vendor's own SDK must never reach a fetch."""

    def test_vendor_owned_repo_is_rejected_without_fetching(self):
        from apidrift.verify import verify_candidate
        result = verify_candidate("openai/openai-python", "src/openai/x.py",
                                  "https://example.invalid", finding(),
                                  get("openai"))
        self.assertEqual(result.verdict, NOT_AUTHOR_CODE)
        self.assertFalse(result.is_lead)

    def test_vendored_dependency_path_is_rejected_without_fetching(self):
        from apidrift.verify import verify_candidate
        result = verify_candidate("someone/app",
                                  "terraform/lambda_function/plaid/model/x.py",
                                  "https://example.invalid", finding(),
                                  get("plaid"))
        self.assertEqual(result.verdict, NOT_AUTHOR_CODE)

    def test_an_ordinary_repo_is_not_rejected_on_provenance(self):
        from apidrift.classify import classify
        self.assertTrue(
            classify("caesar4321/Confio", "twilio",
                     "backend/twilio_verify.py").is_outreach_target)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestPathAnchoring(unittest.TestCase):
    """A caller of something else is worse than a caller we miss."""

    def test_a_router_prefix_is_not_a_call_to_the_vendor(self):
        source = ('import twilio\n'
                  'router = APIRouter(prefix="/communications", tags=["x"])\n')
        f = finding(kind="endpoint_removed",
                    subject="/v2/Conversations/{sid}/Communications",
                    path="/v2/Conversations/{sid}/Communications", method="get")
        self.assertEqual(verdict_of(source, f, get("twilio")), NO_DEPENDENCE)

    def test_a_served_route_is_not_a_call_to_the_vendor(self):
        source = ('import twilio\n'
                  '@app.get("/v2/Conversations/{sid}/Communications")\n'
                  'def handler(sid):\n    return []\n')
        f = finding(kind="endpoint_removed",
                    subject="/v2/Conversations/{sid}/Communications",
                    path="/v2/Conversations/{sid}/Communications", method="get")
        self.assertEqual(verdict_of(source, f, get("twilio")), NO_DEPENDENCE)

    def test_a_partial_path_does_not_match_a_longer_template(self):
        from apidrift.dependence import paths_match
        self.assertFalse(
            paths_match("/v2/Conversations/{sid}/Communications", "/communications"))

    def test_a_base_url_carried_in_a_variable_still_matches(self):
        from apidrift.dependence import paths_match
        self.assertTrue(
            paths_match("/v1/Stores/{s}/Profiles/{p}/Events",
                        "{}/v1/Stores/{}/Profiles/{}/Events"))

    def test_an_endpoint_subject_is_not_read_as_a_field_name(self):
        from apidrift.dependence import _leaf_of
        f = finding(kind="endpoint_removed", subject="/guilds/{g}/bulk-ban",
                    path="/guilds/{g}/bulk-ban")
        self.assertEqual(_leaf_of(f), "")
        self.assertEqual(_leaf_of(finding(subject="Card.iin")), "iin")


class TestWholeSchemaVersusField(unittest.TestCase):
    """Deleting a schema and deleting a field are different claims.

    A caller never writes `LinkSessionProtectResult` -- schema names are
    OpenAPI-internal -- so demanding they name it rejected every genuine
    caller. But reaching the operation is not enough either: the third
    adversarial audit refuted seven of ten leads that reached the operation
    and never touched the deleted schema. What a caller DOES write is the
    schema's field names, so those carry the proof.
    """

    PLAID_CALLER = ('import plaid\n'
                    'def check(self, d):\n'
                    '    return self.api(path="/link/token/get", data=d)\n')

    READS_A_FIELD = ('import plaid\n'
                     'def check(self, d):\n'
                     '    r = self.api(path="/link/token/get", data=d)\n'
                     '    return r["protect_decision"]\n')

    LEAVES = ("protect_decision", "risk_reasons")

    def test_reaching_the_operation_alone_is_not_enough(self):
        """The exact shape of seven of ten third-audit refutations."""
        f = finding(kind="schema_removed", subject="LinkSessionProtectResult",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"], leaves=self.LEAVES)
        verdict, reason, _, _ = verify_source(
            self.PLAID_CALLER, "app.py", f, get("plaid"))
        self.assertEqual(verdict, NO_DEPENDENCE)
        self.assertIn("reads no field of the deleted schema", reason)

    def test_a_deleted_schema_is_proven_by_reading_one_of_its_fields(self):
        f = finding(kind="schema_removed", subject="LinkSessionProtectResult",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"], leaves=self.LEAVES)
        verdict, _, _, sites = verify_source(
            self.READS_A_FIELD, "app.py", f, get("plaid"))
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(sites[0].line, 4)

    def test_a_read_without_a_call_to_the_operation_is_not_enough(self):
        """Symmetry: the field read has to sit with a call that carried it."""
        source = ('import plaid\n'
                  'def show(r):\n'
                  '    return r["protect_decision"]\n')
        f = finding(kind="schema_removed", subject="LinkSessionProtectResult",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"], leaves=self.LEAVES)
        self.assertEqual(verdict_of(source, f, get("plaid")), NO_DEPENDENCE)

    def test_a_schema_of_only_generic_fields_cannot_be_proven(self):
        """`d.get("status")` is written by code that never heard of the schema.

        Rejecting is the honest answer: an unprovable lead is an unmeasured
        claim, not a weaker one.
        """
        source = ('import plaid\n'
                  'def check(self, d):\n'
                  '    r = self.api(path="/link/token/get", data=d)\n'
                  '    return r["status"]\n')
        f = finding(kind="schema_removed", subject="Anon",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"], leaves=("id", "status"))
        verdict, reason, _, _ = verify_source(source, "app.py", f, get("plaid"))
        self.assertEqual(verdict, NO_DEPENDENCE)
        self.assertIn("no field distinctive enough", reason)

    def test_an_operation_level_change_still_needs_only_the_call(self):
        """The new rule is scoped to schema_removed, not to every endpoint kind."""
        f = finding(kind="endpoint_removed", subject="/link/token/get",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"])
        self.assertEqual(verdict_of(self.PLAID_CALLER, f, get("plaid")), CONFIRMED)

    def test_a_deleted_field_still_needs_the_field(self):
        f = finding(kind="schema_field_removed",
                    subject="LinkSessionGetResponse.protect_results",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"])
        self.assertEqual(verdict_of(self.PLAID_CALLER, f, get("plaid")),
                         NO_DEPENDENCE)

    def test_a_body_argument_stands_in_for_an_unstated_verb(self):
        """`self.api(path=..., data=d)` names no verb but is plainly a write."""
        from apidrift.dependence import _method_of
        import ast
        node = next(n for n in ast.walk(ast.parse('self.api(path="/x", data=d)'))
                    if isinstance(n, ast.Call))
        self.assertIn("post", _method_of(node))

    def test_a_bare_path_list_does_not_stand_in_for_a_verb(self):
        from apidrift.dependence import _method_of
        import ast
        node = next(n for n in ast.walk(
            ast.parse('pytest.mark.parametrize("p", ["/x"])'))
            if isinstance(n, ast.Call))
        self.assertEqual(_method_of(node), set())

    def test_a_deleted_schema_still_needs_the_right_operation(self):
        source = ('import plaid\n'
                  'def check(self, d):\n'
                  '    return self.api(path="/item/get", data=d)\n')
        f = finding(kind="schema_removed", subject="LinkSessionProtectResult",
                    path="/link/token/get", method="post",
                    ops=["POST /link/token/get"])
        self.assertEqual(verdict_of(source, f, get("plaid")), NO_DEPENDENCE)


class TestASentFieldIsAlsoDependence(unittest.TestCase):
    """`reasoning={"effort": "low"}` is a keyword argument, not a read.

    The send route used to be reachable only when the finding's KIND contained
    the word "request", which is a guess about the schema's direction. OpenAI's
    request body is assembled from `ResponseProperties`, so every caller
    passing a removed request field was scored unaffected. The spec knows which
    direction a schema travels; the kind's spelling does not.
    """

    SENDER = ('import openai\n'
              'client = openai.OpenAI()\n'
              'response = client.responses.create(\n'
              '    model="gpt-5",\n'
              '    reasoning={"effort": "low"},\n'
              ')\n')

    def _finding(self):
        f = finding(kind="schema_field_removed",
                    subject="ResponseProperties.reasoning",
                    path="/responses", method="post",
                    ops=["POST /responses"],
                    sigs=["client.responses.", ".responses.create"])
        f.in_request = True
        return f

    def test_a_sent_field_on_a_request_schema_is_proven(self):
        verdict, _, _, sites = verify_source(
            self.SENDER, "app.py", self._finding(), get("openai"))
        self.assertEqual(verdict, CONFIRMED)

    def test_a_send_is_cited_at_the_line_the_field_is_on(self):
        """A call opening on line 3 must not be cited for a field on line 5."""
        _, _, _, sites = verify_source(
            self.SENDER, "app.py", self._finding(), get("openai"))
        self.assertEqual(sites[0].line, 5)
        self.assertIn("reasoning", sites[0].text)

    def test_a_file_that_never_sends_it_is_not_affected(self):
        source = ('import openai\n'
                  'client = openai.OpenAI()\n'
                  'r = client.responses.create(model="gpt-5")\n')
        self.assertEqual(
            verdict_of(source, self._finding(), get("openai")), NO_DEPENDENCE)


class TestDirection(unittest.TestCase):
    """The same name on the way out and on the way back are two fields.

    `verify._sites_matching_direction` encoded roughly this rule and was called
    by nothing after the dependence rewrite, so direction read as handled while
    prove() ignored it. Found live in a scan of phasehq/console, whose
    `subscription.get("cancel_at")` — a READ off a response — was reported as
    broken by Stripe retyping `cancel_at` in the subscription-create REQUEST
    body. That is the first failure mode the first adversarial audit named.
    """

    READER = ('import stripe\n'
              'def show(sid):\n'
              '    subscription = stripe.Subscription.retrieve(sid)\n'
              '    return subscription.get("cancel_at")\n')

    SENDER = ('import stripe\n'
              'def cancel(sid, when):\n'
              '    return stripe.Subscription.modify(sid, cancel_at=when)\n')

    def _request_change(self):
        return finding(kind="request_field_type_changed", subject="cancel_at",
                       path="/v1/subscriptions", method="post",
                       ops=["POST /v1/subscriptions"],
                       sigs=["stripe.subscriptions.", "stripe.Subscription."])

    def _response_change(self):
        f = finding(kind="schema_field_removed", subject="Subscription.cancel_at",
                    path="/v1/subscriptions", method="post",
                    ops=["POST /v1/subscriptions"],
                    sigs=["stripe.subscriptions.", "stripe.Subscription."])
        f.in_response = True
        return f

    def test_a_read_does_not_prove_a_request_side_change(self):
        verdict, reason, _, _ = verify_source(
            self.READER, "app.py", self._request_change(), STRIPE)
        self.assertEqual(verdict, NO_DEPENDENCE)
        self.assertIn("the change is to what callers SEND", reason)

    def test_a_send_does_prove_a_request_side_change(self):
        self.assertEqual(
            verdict_of(self.SENDER, self._request_change(), STRIPE), CONFIRMED)

    def test_a_send_does_not_prove_a_response_side_change(self):
        verdict, reason, _, _ = verify_source(
            self.SENDER, "app.py", self._response_change(), STRIPE)
        self.assertEqual(verdict, NO_DEPENDENCE)
        self.assertIn("the change is to what callers RECEIVE", reason)

    def test_a_read_does_prove_a_response_side_change(self):
        self.assertEqual(
            verdict_of(self.READER, self._response_change(), STRIPE), CONFIRMED)


class TestPathsAreNotSelfIdentifying(unittest.TestCase):
    """`/v2/conversations` is Twilio's, and also plenty of other people's."""

    PARAMETRIZE = ('import pytest\n'
                   '@pytest.mark.parametrize("p", ["/api/v2/conversations/{}"])\n'
                   'def test_routes(p):\n    assert p\n')

    def test_a_repos_own_route_is_not_a_vendor_call(self):
        f = finding(kind="endpoint_moved",
                    subject="/v2/Conversations/{sid}",
                    path="/v2/Conversations/{sid}", method="delete")
        self.assertEqual(verdict_of(self.PARAMETRIZE, f, get("twilio")),
                         NO_VENDOR)

    def test_the_same_path_with_the_vendor_present_is_still_checked(self):
        source = 'import twilio\n' + self.PARAMETRIZE
        f = finding(kind="endpoint_moved",
                    subject="/v2/Conversations/{sid}",
                    path="/v2/Conversations/{sid}", method="delete")
        # Vendor evidence passes, but the method is wrong, so still no proof.
        self.assertEqual(verdict_of(source, f, get("twilio")), NO_DEPENDENCE)


class TestProofNamesTheMatchedOperation(unittest.TestCase):
    def test_the_chain_states_which_operation_was_called(self):
        source = ('import twilio\n'
                  'r = requests.post(f"{BASE}/v2/Services/{sid}/Verifications")\n')
        f = finding(kind="security_requirement_added", subject="security",
                    path="/v2/Services/{Sid}", method="delete",
                    ops=["DELETE /v2/Services/{Sid}",
                         "POST /v2/Services/{ServiceSid}/Verifications"])
        verdict, reason, _, sites = verify_source(source, "v.py", f, get("twilio"))
        self.assertEqual(verdict, CONFIRMED)
        chain = " ".join(sites[0].chain)
        self.assertIn("which is `POST", chain,
                      "the proof must state the operation actually called")
        self.assertNotIn("DELETE /v2/Services/{Sid}", chain,
                         "and not the representative operation")


class TestIncompletePathLiterals(unittest.TestCase):
    def test_a_trailing_slash_marks_an_incomplete_path(self):
        from apidrift.dependence import paths_match
        self.assertFalse(
            paths_match("/v2/Services", "https://verify.twilio.com/v2/Services/"),
            "the caller concatenates onto this prefix, so the real path is longer")

    def test_a_complete_path_still_matches(self):
        from apidrift.dependence import paths_match
        self.assertTrue(
            paths_match("/v2/Services", "https://verify.twilio.com/v2/Services"))


class TestVendoredLibraryCopies(unittest.TestCase):
    """A checked-in copy of the library carries the library's own licence."""

    DISCORD_PY = ('# The MIT License (MIT)\n'
                  '# Copyright (c) 2015-present Rapptz\n'
                  'import discord\n'
                  'def delete_template(self, gid, code):\n'
                  '    return self.request(Route("DELETE", '
                  '"/guilds/{guild_id}/templates/{code}"))\n')

    def test_a_library_dump_is_not_author_code(self):
        f = finding(kind="schema_removed", subject="IconEmojiResponse",
                    path="/guilds/{guild_id}/templates/{code}", method="delete")
        for path in ("discord/http.py", "generic_modules/discord/http.py"):
            with self.subTest(path=path):
                verdict, reason, _, _ = verify_source(
                    self.DISCORD_PY, path, f, get("discord"))
                self.assertEqual(verdict, NOT_AUTHOR_CODE)
                self.assertIn("copy of the library", reason)

    def test_the_authors_own_file_in_a_vendor_named_dir_is_kept(self):
        from apidrift.verify import looks_vendored_library
        self.assertEqual(
            looks_vendored_library("const x = 1;\n",
                                   ".claude/skills/stripe/query.mjs",
                                   get("stripe")), "")

    def test_a_licence_outside_a_vendor_directory_is_not_vendoring(self):
        from apidrift.verify import looks_vendored_library
        self.assertEqual(
            looks_vendored_library("# Copyright (c) 2024 acme\n",
                                   "app/services/billing.py", get("stripe")), "")


class TestASendNeedsAVendorReceiver(unittest.TestCase):
    """A keyword argument only SENDS something if the vendor receives it.

    phasehq/console builds its own GraphQL type with
    `StripeSubscriptionDetails(cancel_at=...)`. Matching any call at all read
    that as a Stripe request body, and Stripe retyping `cancel_at` in
    subscription-create was reported as breaking it. The proximity heuristic
    this replaced was inert precisely when it was needed: it only applied once
    a path literal had been found, so an SDK caller -- who writes no path --
    was never filtered.
    """

    OWN_CONSTRUCTOR = ('import stripe\n'
                       'def show(sid):\n'
                       '    sub = stripe.Subscription.retrieve(sid)\n'
                       '    return Details(\n'
                       '        cancel_at=str(sub.get("cancel_at")),\n'
                       '    )\n')

    VENDOR_CALL = ('import stripe\n'
                   'def cancel(sid, when):\n'
                   '    return stripe.Subscription.modify(\n'
                   '        sid,\n'
                   '        cancel_at=when,\n'
                   '    )\n')

    BODY_DICT = ('import requests\n'
                 'def cancel(sid, when):\n'
                 '    body = {"cancel_at": when}\n'
                 '    return requests.post(\n'
                 '        "https://api.stripe.com/v1/subscriptions",\n'
                 '        json=body,\n'
                 '    )\n')

    def _finding(self):
        return finding(kind="request_field_type_changed", subject="cancel_at",
                       path="/v1/subscriptions", method="post",
                       ops=["POST /v1/subscriptions"],
                       sigs=["stripe.Subscription.", "stripe.subscriptions."])

    def test_a_keyword_on_the_repos_own_constructor_is_not_a_send(self):
        self.assertEqual(
            verdict_of(self.OWN_CONSTRUCTOR, self._finding(), STRIPE),
            NO_DEPENDENCE)

    def test_a_keyword_on_a_vendor_call_is_a_send(self):
        verdict, _, _, sites = verify_source(
            self.VENDOR_CALL, "app.py", self._finding(), STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(sites[0].line, 5)

    def test_a_body_dict_built_in_a_variable_is_still_a_send(self):
        """`body = {...}` then `json=body` is the ordinary request shape."""
        verdict, _, _, sites = verify_source(
            self.BODY_DICT, "app.py", self._finding(), STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(sites[0].line, 3)


class TestAWrittenHostIsDecisive(unittest.TestCase):
    """`paths_match` is end-anchored, and that makes it host-blind.

    The anchoring exists for a good reason: `f"{BASE}/v1/charges"` has to match
    when the host lives in a variable. The cost is that
    `paths_match("/v1/charges", "https://internal.acme.io/v1/charges")` is
    True, and vendor evidence is only ever established file-wide — so any file
    importing stripe anywhere had its own internal service read as a Stripe
    call. A host the caller wrote down is decisive; an absent one is not.
    """

    def _finding(self):
        return finding(kind="endpoint_removed", subject="/v1/charges",
                       path="/v1/charges", method="post",
                       ops=["POST /v1/charges"])

    def test_another_service_sharing_the_tail_path_is_not_the_vendor(self):
        source = ('import stripe\n'
                  'import requests\n'
                  'def internal(body):\n'
                  '    return requests.post("https://internal.acme.io/v1/charges",\n'
                  '                         json=body)\n')
        self.assertEqual(verdict_of(source, self._finding(), STRIPE),
                         NO_DEPENDENCE)

    def test_the_vendors_own_host_still_matches(self):
        source = ('import stripe\n'
                  'import requests\n'
                  'def charge(body):\n'
                  '    return requests.post("https://api.stripe.com/v1/charges",\n'
                  '                         json=body)\n')
        self.assertEqual(verdict_of(source, self._finding(), STRIPE), CONFIRMED)

    def test_an_absent_host_is_not_decisive_either_way(self):
        """The whole reason the matcher is end-anchored."""
        source = ('import stripe\n'
                  'import requests\n'
                  'BASE = os.environ["STRIPE_BASE"]\n'
                  'def charge(body):\n'
                  '    return requests.post(f"{BASE}/v1/charges", json=body)\n')
        self.assertEqual(verdict_of(source, self._finding(), STRIPE), CONFIRMED)

    def test_an_interpolated_url_cannot_smuggle_a_foreign_host_past(self):
        """An f-string yields its inner Constants as separate candidates.

        So `f"https://internal.acme.io{suffix}/v1/charges"` offered a bare
        `/v1/charges` with the host nowhere in sight, and a per-literal host
        check was bypassed by every interpolated URL. Hosts are judged for the
        whole call.
        """
        source = ('import stripe\n'
                  'import requests\n'
                  'def internal(suffix, body):\n'
                  '    return requests.post(\n'
                  '        f"https://internal.acme.io{suffix}/v1/charges", json=body)\n')
        self.assertEqual(verdict_of(source, self._finding(), STRIPE),
                         NO_DEPENDENCE)

    def test_an_interpolated_host_is_unknowable_and_so_not_rejected(self):
        source = ('import stripe\n'
                  'import requests\n'
                  'def charge(host, body):\n'
                  '    return requests.post(f"https://{host}/v1/charges", json=body)\n')
        self.assertEqual(verdict_of(source, self._finding(), STRIPE), CONFIRMED)


class TestAReadIsAPositionNotAWord(unittest.TestCase):
    """A word is not a field. `subscription.currency` is not `coupon.currency`.

    Measured 2026-08-21 by scanning 22 real repositories at a three-year
    window -- the first time the scanner was ever pointed at a window long
    enough to fire. It produced thirteen impacts and twelve of them were this:
    a read matched on its LEAF NAME while sitting somewhere the change never
    touched. Every case below is verbatim from that run, with the source line
    that produced it.

    Seventh instance of this project's recurring defect and the first inside
    the PROVER rather than the checker. The prover asked "is this identifier
    read off something from this vendor?"; the caller's question is "is the
    value I read the value that changed?".
    """

    def _js(self, source, finding_obj):
        return verify_source(source, "billing.ts", finding_obj, STRIPE)

    FORMBRICKS = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k, { apiVersion: undefined });\n'
                  'const subscription = await stripe.subscriptions.retrieve(id);\n'
                  'const currency = subscription.currency ?? "usd";\n')

    LANGFUSE = ('import Stripe from "stripe";\n'
                'const stripe = new Stripe(k);\n'
                'const subscription = await stripe.subscriptions.retrieve(id);\n'
                'const start = subscription.current_period_start * 1000;\n'
                'const who = subscription.customer?.id;\n')

    def test_currency_on_a_subscription_is_not_currency_on_a_coupon(self):
        """formbricks create-setup-checkout-session.ts:31, four times over."""
        removed = finding(kind="response_field_removed",
                          subject="<deleted_discount>.coupon.currency",
                          path="/v1/customers/{customer}/discount",
                          method="delete",
                          ops=("DELETE /v1/customers/{customer}/discount",))
        verdict, reason, _, _ = self._js(self.FORMBRICKS, removed)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_customer_on_a_subscription_is_not_customer_on_a_discount(self):
        """langfuse handleCloudSpendAlertJob.ts:118."""
        removed = finding(kind="response_field_removed",
                          subject="<invoice>.discount.customer",
                          path="/v1/invoices/{invoice}", method="get",
                          ops=("GET /v1/invoices/{invoice}",))
        verdict, reason, _, _ = self._js(self.LANGFUSE, removed)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_position_decides_even_when_the_operation_IS_reached(self):
        """The case reach cannot catch, which is why both questions are asked.

        `subscription.discount.customer` genuinely touches the subscription
        operations this file calls. Only position refutes it.
        """
        removed = finding(kind="schema_field_removed",
                          subject="subscription.discount.customer",
                          path="/v1/subscriptions/{subscription_exposed_id}",
                          method="get",
                          ops=("GET /v1/subscriptions/{subscription_exposed_id}",))
        verdict, reason, _, _ = self._js(self.LANGFUSE, removed)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_id_off_a_customer_is_not_id_off_a_price(self):
        """langfuse:120. `id` is the most reusable word in any API."""
        removed = finding(kind="response_field_removed",
                          subject="<invoiceitem>.price.id",
                          path="/v1/invoiceitems/{invoiceitem}", method="get",
                          ops=("GET /v1/invoiceitems/{invoiceitem}",))
        verdict, reason, _, _ = self._js(self.LANGFUSE, removed)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_the_one_that_is_REAL_still_confirms(self):
        """The control, and the reason this is a filter and not a deletion.

        Stripe removed `current_period_start` from the subscription object and
        moved it onto the subscription ITEM. Langfuse's cloud spend alerts read
        it off the subscription; the line computes `new Date(undefined * 1000)`
        today. Hand-verified against `stripe/openapi` HEAD on 2026-08-21:
        absent from `subscription`, present on `subscription_item`.
        """
        removed = finding(kind="schema_field_removed",
                          subject="subscription.current_period_start",
                          path="/v1/accounts/{account}", method="delete",
                          ops=("GET /v1/subscriptions/{subscription_exposed_id}",))
        verdict, reason, _, proofs = self._js(self.LANGFUSE, removed)
        self.assertEqual(CONFIRMED, verdict, reason)
        self.assertTrue(any(p.line == 4 for p in proofs),
                        [(p.line, p.text) for p in proofs])

    def test_a_read_at_the_named_position_confirms(self):
        """Position REQUIRES the ancestry; it does not forbid the finding."""
        source = ('import Stripe from "stripe";\n'
                  'const stripe = new Stripe(k);\n'
                  'const inv = await stripe.invoices.retrieve(id);\n'
                  'return inv.discount.customer;\n')
        removed = finding(kind="response_field_removed",
                          subject="<invoice>.discount.customer",
                          path="/v1/invoices/{invoice}", method="get",
                          ops=("GET /v1/invoices/{invoice}",))
        verdict, reason, _, _ = verify_source(source, "billing.ts", removed, STRIPE)
        self.assertEqual(CONFIRMED, verdict, reason)

    def test_reach_abstains_rather_than_refusing_a_truncated_list(self):
        """`affected_ops` caps at 200 while `card.iin` touches 551.

        Answering "not reached" from a list known to be partial manufactures a
        false negative out of a display cap, and nothing downstream can see it.
        """
        from apidrift.js_dependence import _chain_reaches_change
        partial = finding(kind="schema_field_removed", subject="card.iin",
                          ops=("POST /v1/issuing/cards",))
        partial.affected_op_count = 551
        self.assertTrue(_chain_reaches_change(
            ("stripe", "subscriptions", "retrieve"), partial))
        partial.affected_op_count = 1
        self.assertFalse(_chain_reaches_change(
            ("stripe", "subscriptions", "retrieve"), partial))


class TestSubjectAncestry(unittest.TestCase):
    """The subject's grammar decides what a caller writes, and the KIND
    decides the grammar. Getting it backwards makes the check vacuous on
    exactly the population it exists for."""

    def test_a_schema_finding_writes_its_schema_name_bare(self):
        from apidrift.dependence import subject_ancestry
        self.assertEqual((), subject_ancestry(finding(
            kind="schema_field_removed",
            subject="subscription.current_period_start")))
        self.assertEqual(("discount",), subject_ancestry(finding(
            kind="schema_field_removed",
            subject="subscription.discount.customer")))

    def test_a_response_finding_brackets_it_and_wire_subject_removes_it(self):
        from apidrift.dependence import subject_ancestry
        self.assertEqual(("discount",), subject_ancestry(finding(
            kind="response_field_removed",
            subject="<invoice>.discount.customer")))
        self.assertEqual((), subject_ancestry(finding(
            kind="response_field_removed", subject="<invoice>.customer")))

    def test_an_endpoint_subject_is_a_path_and_carries_no_ancestry(self):
        from apidrift.dependence import subject_ancestry
        self.assertEqual((), subject_ancestry(finding(
            kind="endpoint_removed", subject="/guilds/{id}/bulk-ban")))

    def test_a_reached_operation_is_required_when_the_list_is_complete(self):
        """Reach must be able to say NO, or it is decoration.

        The complement of the abstention test above: with a complete list, a
        call that reaches none of the changed operations is not a proof.
        """
        from apidrift.js_dependence import _chain_reaches_change
        complete = finding(kind="response_field_removed",
                           subject="<invoice>.discount.customer",
                           ops=("GET /v1/invoices/{invoice}",))
        complete.affected_op_count = 1
        self.assertFalse(_chain_reaches_change(
            ("stripe", "subscriptions", "retrieve"), complete))
        self.assertTrue(_chain_reaches_change(
            ("stripe", "invoices", "retrieve"), complete))

    def test_a_python_caller_walking_a_body_by_subscript_is_positioned(self):
        """`body["discount"]["customer"]` is a position, not two words.

        Subscripts and `.get()` are how a Python caller walks a JSON body, so
        a chain that stopped at the first `[` could not see where a read sits
        -- and would then accept every read of the leaf anywhere in the file.
        """
        from apidrift.dependence import read_position
        import ast
        tree = ast.parse('x = body["discount"]["customer"]\n'
                         'y = body.get("coupon", {}).get("currency")\n')
        positions = [read_position(n) for n in ast.walk(tree)
                     if isinstance(n, (ast.Subscript, ast.Call))]
        self.assertIn(("body", "discount", "customer"), positions)
        self.assertIn(("body", "coupon", "currency"), positions)

        source = ('import stripe\n'
                  'inv = stripe.Invoice.retrieve(i)\n'
                  'who = inv["discount"]["customer"]\n'
                  'cur = inv["currency"]\n')
        removed = finding(kind="response_field_removed",
                          subject="<invoice>.discount.customer",
                          path="/v1/invoices/{invoice}", method="get",
                          ops=("GET /v1/invoices/{invoice}",))
        verdict, reason, _, proofs = verify_source(source, "bill.py", removed, STRIPE)
        self.assertEqual(CONFIRMED, verdict, reason)
        self.assertEqual([3], [p.line for p in proofs])


class TestAMemberChainNeedsProvenance(unittest.TestCase):
    """A chain is a vendor call only if its ROOT came from the vendor.

    The largest defect the fourth adversarial audit found (2026-08-21, 74
    impacts across 22 real repositories). `find_sdk_calls` matched any member
    chain whose spelling began with one of the finding's idioms, so ordinary
    local objects were reported as API calls — and, worse, were then used as
    the ANCHOR that turned an unrelated field read into an impact.

    JavaScript never had this hole: `_vendor_bindings` requires the root be
    imported from one of the vendor's SDK packages. These are the same gate in
    Python's terms, and every case is verbatim from the audit.

    🚨 Every fixture carries `import stripe`. Without it `verify_source` stops
    at NO_VENDOR and never reaches `prove()`, so these tests passed while the
    gate they exist for was switched off — which the mutation harness caught
    and a green suite did not.
    """

    ENDPOINT = dict(kind="endpoint_removed", subject="/projects/{project_id}/collaborators",
                    path="/projects/{project_id}/collaborators", method="get")

    def _endpoint_finding(self, sigs):
        return finding(sigs=sigs, ops=("GET /projects/{project_id}/collaborators",),
                       **self.ENDPOINT)

    def test_a_local_list_append_is_not_an_api_call(self):
        """onyx utils.py:244 — `collaborators` is a `List[UserInfo]`."""
        source = ("import stripe\n"
                  "\n"
                  "def gather():\n"
                  "    collaborators = []\n"
                  "    collaborators.append(info)\n"
                  "    return collaborators\n")
        verdict, reason, _, _ = verify_source(
            source, "utils.py", self._endpoint_finding(("collaborators",)), STRIPE)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_a_dict_get_is_not_an_api_call(self):
        """posthog github_integration_base.py:140 — `permissions` is a dict."""
        source = ("import stripe\n"
                  "\n"
                  "def check(repo):\n"
                  "    permissions = repo.get('permissions')\n"
                  "    return permissions.get('push')\n")
        verdict, reason, _, _ = verify_source(
            source, "base.py", self._endpoint_finding(("permissions",)), STRIPE)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_the_standard_library_is_not_an_api_call(self):
        """posthog github_grants.py:110 — `secrets` is the stdlib module,
        reported three times over as GitHub's environment-secret endpoints."""
        source = ("import secrets\n"
                  "import stripe\n"
                  "\n"
                  "def make():\n"
                  "    return secrets.token_urlsafe(32)\n")
        verdict, reason, _, _ = verify_source(
            source, "grants.py", self._endpoint_finding(("secrets.",)), STRIPE)
        self.assertNotEqual(CONFIRMED, verdict, reason)

    def test_a_real_sdk_chain_still_proves_the_call(self):
        """The control. The gate must remove coincidence, not evidence."""
        source = ("import stripe\n"
                  "def load(i):\n"
                  "    return stripe.checkout.Session.create(i)\n")
        from apidrift.dependence import find_sdk_calls, _assignments_of
        import ast
        tree = ast.parse(source)
        proofs = find_sdk_calls(tree, ["stripe.checkout"], source.splitlines(),
                                STRIPE, _assignments_of(tree))
        self.assertEqual(1, len(proofs), proofs)

    def test_a_client_traced_through_an_assignment_still_proves_it(self):
        """Provenance is not spelling: the root may be any local name."""
        source = ("import stripe\n"
                  "client = stripe.StripeClient(key)\n"
                  "def load(i):\n"
                  "    return client.checkout.sessions.create(i)\n")
        from apidrift.dependence import find_sdk_calls, _assignments_of
        import ast
        tree = ast.parse(source)
        proofs = find_sdk_calls(tree, ["client.checkout"], source.splitlines(),
                                STRIPE, _assignments_of(tree))
        self.assertEqual(1, len(proofs), proofs)

    def test_without_a_vendor_nothing_is_proven(self):
        """An unprovenanced chain is what this function must stop accepting,
        so the vendor-less call returns nothing rather than everything."""
        from apidrift.dependence import find_sdk_calls
        import ast
        source = "collaborators.append(x)\n"
        self.assertEqual([], find_sdk_calls(ast.parse(source), ["collaborators"],
                                            source.splitlines()))
