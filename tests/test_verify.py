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
            path="/v1/customers", method="get", ops=(), sigs=()):
    return Finding(kind=kind, severity=BREAKING, op_key=f"{method.upper()} {path}",
                   path=path, method=method, detail="", subject=subject,
                   root_cause=subject, affected_ops=list(ops),
                   signatures=list(sigs))


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


class TestUnprovableLanguages(unittest.TestCase):
    """An unproven lead is an unmeasured claim, not a weaker one."""

    def test_javascript_is_unproven_not_likely(self):
        source = ('const stripe = require("stripe")(k);\n'
                  'const c = await stripe.customers.retrieve(id);\n'
                  'return c.iin;\n')
        verdict, reason, _, _ = verify_source(source, "pay.js", finding(), STRIPE)
        self.assertEqual(verdict, UNPROVEN)
        self.assertIn("only Python is parsed", reason)

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
