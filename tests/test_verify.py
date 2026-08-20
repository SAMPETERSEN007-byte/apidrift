"""Tests for the candidate->lead verification pass.

The headline case is the one that actually happened: the first Stripe `iin`
code-search hit this project produced was a line of prose inside a docstring.
Any verifier that cannot reject that is worthless.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apidrift.diff import BREAKING, Finding
from apidrift.verify import (CONFIRMED, ERROR, LIKELY, NOT_AUTHOR_CODE,
                             NO_SITE, NO_VENDOR, UNSUPPORTED, lexical_sites,
                             python_sites, target_symbol, verify_source)
from apidrift.vendors import get

STRIPE = get("stripe")


def finding(kind="response_field_removed", subject="card.iin", path="/v1/customers"):
    return Finding(kind=kind, severity=BREAKING, op_key=f"GET {path}", path=path,
                   method="get", detail="", subject=subject, root_cause=subject)


DOCSTRING_FILE = '''
"""Card model.

Stores the last four digits, the network, and issuer metadata.
Cardholder name, BIN/IIN and iin are not persisted.
"""
import stripe


class Card:
    def __init__(self, brand):
        self.brand = brand
'''

REAL_USE_FILE = '''
import stripe

def show(customer_id):
    card = stripe.Customer.retrieve(customer_id).default_source
    return {"brand": card.brand, "issuer": card.iin}
'''

DICT_USE_FILE = '''
import stripe

def show(card):
    return card["iin"], card.get("iin", "")
'''

NO_VENDOR_FILE = '''
def parse_iban(record):
    return record.iin
'''

MIGRATED_FILE = '''
import stripe

stripe.checkout.Session.create(
    subscription_data={"billing_cycle_anchor_config": {"day_of_month": 1}},
)
'''

JS_FILE = '''
const stripe = require('stripe')(config.stripeSecret);
// the iin field used to be here
async function show(id) {
  const card = await stripe.customers.retrieveSource(id);
  return card.iin;
}
'''

JS_COMMENT_ONLY = '''
const stripe = require('stripe')(config.stripeSecret);
// we no longer read card.iin anywhere
/* iin: removed in 2026 */
async function show(id) { return 1; }
'''


class TestPythonSiteDetection(unittest.TestCase):
    def test_docstring_mention_is_not_a_site(self):
        sites, error = python_sites(DOCSTRING_FILE, "iin")
        self.assertIsNone(error)
        self.assertEqual(sites, [], "prose inside a docstring is not a call site")

    def test_attribute_access_is_a_site(self):
        sites, _ = python_sites(REAL_USE_FILE, "iin")
        self.assertEqual([s.kind for s in sites], ["attribute"])

    def test_subscript_and_get_are_sites(self):
        sites, _ = python_sites(DICT_USE_FILE, "iin")
        self.assertEqual({s.kind for s in sites}, {"subscript", "dict_get"})

    def test_unparseable_source_errors_rather_than_crashing(self):
        sites, error = python_sites("def broken(:\n", "iin")
        self.assertEqual(sites, [])
        self.assertIsNotNone(error)


class TestVerdicts(unittest.TestCase):
    def test_docstring_candidate_is_rejected(self):
        verdict, reason, _, _ = verify_source(
            DOCSTRING_FILE, "models.py", finding(), STRIPE)
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("prose", reason)

    def test_real_use_is_confirmed(self):
        verdict, _, evidence, sites = verify_source(
            REAL_USE_FILE, "app.py", finding(), STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(evidence, "import stripe")
        self.assertEqual(sites[0].line, 6)

    def test_symbol_without_vendor_evidence_is_rejected(self):
        verdict, reason, _, _ = verify_source(
            NO_VENDOR_FILE, "iban.py", finding(), STRIPE)
        self.assertEqual(verdict, NO_VENDOR)
        self.assertIn("Stripe", reason)

    def test_already_migrated_caller_is_not_a_lead(self):
        f = finding(kind="request_field_added_required",
                    subject="subscription_data.billing_cycle_anchor_config.day_of_month",
                    path="/v1/checkout/sessions")
        verdict, reason, _, _ = verify_source(MIGRATED_FILE, "pay.py", f, STRIPE)
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("migrated", reason)

    def test_caller_missing_the_new_required_field_is_a_lead(self):
        """The break is the ABSENCE of the field — these are the real victims."""
        source = (
            "import stripe\n"
            "stripe.checkout.Session.create(subscription_data={'trial': 7})\n"
        )
        f = finding(kind="request_field_added_required",
                    subject="subscription_data.billing_cycle_anchor_config.day_of_month",
                    path="/v1/checkout/sessions")
        verdict, reason, _, sites = verify_source(source, "pay.py", f, STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertIn("without required", reason)
        self.assertTrue(sites)

    def test_caller_of_a_different_endpoint_is_not_a_lead(self):
        source = "import stripe\nstripe.Refund.create(charge='ch_1')\n"
        f = finding(kind="request_field_added_required",
                    subject="subscription_data.billing_cycle_anchor_config.day_of_month",
                    path="/v1/checkout/sessions")
        verdict, reason, _, _ = verify_source(source, "pay.py", f, STRIPE)
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("does not call", reason)

    def test_javascript_is_likely_not_confirmed(self):
        verdict, _, _, sites = verify_source(JS_FILE, "pay.js", finding(), STRIPE)
        self.assertEqual(verdict, LIKELY, "an unparsed language cannot be confirmed")
        self.assertTrue(sites)

    def test_javascript_comment_only_is_rejected(self):
        verdict, _, _, _ = verify_source(JS_COMMENT_ONLY, "pay.js", finding(), STRIPE)
        self.assertEqual(verdict, NO_SITE)

    def test_unknown_language_is_unsupported_not_confirmed(self):
        verdict, _, _, _ = verify_source(
            "card.iin\nimport stripe", "main.rs", finding(), STRIPE)
        self.assertEqual(verdict, UNSUPPORTED)

    def test_endpoint_removal_verifies_on_the_path(self):
        f = finding(kind="endpoint_removed", subject="/v1/old_thing",
                    path="/v1/old_thing")
        src = 'import requests\nrequests.get("https://api.stripe.com/v1/old_thing")\n'
        verdict, _, _, sites = verify_source(src, "x.py", f, STRIPE)
        self.assertEqual(verdict, CONFIRMED)
        self.assertTrue(sites)


class TestEndpointVerification(unittest.TestCase):
    """Half the first real lead list was prose describing an endpoint."""

    ENDPOINT_DOCSTRING = '''
"""Twilio helper.

- Verify send: POST /v2/Services/{service_sid}/Verifications
"""
import twilio


def send():
    return None
'''

    ENDPOINT_COMMENT = '''
import twilio
# for endpoints on /v2/Services the root-relative path is used
def send():
    return None
'''

    ENDPOINT_REAL = '''
import twilio
import requests

def send(service_sid):
    url = f"https://verify.twilio.com/v2/Services/{service_sid}/Verifications"
    return requests.post(url)
'''

    def _run(self, source):
        f = finding(kind="security_requirement_added", subject="/v2/Services",
                    path="/v2/Services")
        return verify_source(source, "twilio_verify.py", f, get("twilio"))

    def test_docstring_endpoint_mention_is_rejected(self):
        verdict, reason, _, _ = self._run(self.ENDPOINT_DOCSTRING)
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("docstring", reason)

    def test_comment_endpoint_mention_is_rejected(self):
        verdict, _, _, _ = self._run(self.ENDPOINT_COMMENT)
        self.assertEqual(verdict, NO_SITE)

    def test_fstring_url_construction_is_confirmed(self):
        verdict, _, _, sites = self._run(self.ENDPOINT_REAL)
        self.assertEqual(verdict, CONFIRMED)
        self.assertEqual(sites[0].line, 6)


class TestTargetExtraction(unittest.TestCase):
    def test_field_change_targets_the_leaf(self):
        self.assertEqual(target_symbol(finding()), ("iin", "presence"))

    def test_required_field_uses_absence_mode(self):
        f = finding(kind="request_field_added_required", subject="Rule.frequency")
        self.assertEqual(target_symbol(f), ("frequency", "absence"))

    def test_endpoint_change_targets_the_path(self):
        f = finding(kind="endpoint_removed", path="/v1/cards/{id}")
        self.assertEqual(target_symbol(f), ("/v1/cards", "endpoint"))


class TestLexical(unittest.TestCase):
    def test_comments_are_stripped_before_matching(self):
        self.assertEqual(lexical_sites("// card.iin\n", "iin"), [])

    def test_url_scheme_is_not_treated_as_a_comment(self):
        # `//` inside https:// once truncated every line holding a URL.
        sites = lexical_sites('fetch("https://api.stripe.com/v1/x").then(c => c.iin);\n', "iin")
        self.assertTrue(sites, "the https:// scheme swallowed the rest of the line")

    def test_block_comment_preserves_line_numbers(self):
        # Deleting a block comment outright shifts every later line, so the
        # reported line number points at the wrong code.
        source = (
            "const c = load();\n"
            "/* a comment\n"
            "   spanning\n"
            "   several lines */\n"
            "return c.iin;\n"
        )
        sites = lexical_sites(source, "iin")
        self.assertEqual([s.line for s in sites], [5])
        self.assertIn("c.iin", sites[0].text)

    def test_property_access_matches(self):
        sites = lexical_sites("return card.iin;\n", "iin")
        self.assertEqual([s.kind for s in sites], ["property"])


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestAuditFindings(unittest.TestCase):
    """Regressions for the six failure modes an adversarial audit found.

    Nine of ten sampled leads were refuted. Each test below is one of the
    reasons a skeptic gave, turned into a rule.
    """

    GENERATED = '''
# File generated from our OpenAPI spec by Castiron. See CONTRIBUTING.md.
import stripe

def show(card):
    return card.iin
'''

    OPENAPI_GENERATED = '''
"""The Plaid API

    The version of the OpenAPI document: 2020-09-14
    Generated by: https://openapi-generator.tech
"""
import plaid

attribute_map = {"value": "value"}
'''

    DEFAULTS_TABLE = '''
import openai

DEFAULTS = {
    "prompt_cache_key": None,
    "temperature": 1.0,
}
'''

    WRONG_ENDPOINT = '''
import discord

def kick(guild_id, user_id):
    return Route("DELETE", "/guilds/{guild_id}/members/{user_id}")
'''

    def test_vendor_generated_sdk_is_rejected(self):
        verdict, reason, _, _ = verify_source(
            self.GENERATED, "input_tokens.py", finding(), STRIPE)
        self.assertEqual(verdict, NOT_AUTHOR_CODE)
        self.assertIn("generated", reason)

    def test_openapi_generator_header_is_rejected(self):
        f = finding(subject="FDXInitiatorFiAttribute.value")
        verdict, _, _, _ = verify_source(
            self.OPENAPI_GENERATED, "model.py", f, get("plaid"))
        self.assertEqual(verdict, NOT_AUTHOR_CODE)

    def test_a_defaults_table_is_not_a_read_of_a_response_field(self):
        f = finding(kind="schema_field_removed",
                    subject="CreateChatCompletionResponse.prompt_cache_key")
        verdict, reason, _, _ = verify_source(
            self.DEFAULTS_TABLE, "constants.py", f, get("openai"))
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("declaration", reason)

    def test_calling_a_shared_prefix_without_the_field_is_rejected(self):
        # `/guilds` matches kick and ban routes; the change is icon_emoji.
        f = finding(kind="schema_removed", subject="IconEmojiResponse",
                    path="/guilds/{guild_id}/auto-moderation/rules")
        f.root_cause = "IconEmojiResponse"
        verdict, reason, _, _ = verify_source(
            self.WRONG_ENDPOINT, "http.py", f, get("discord"))
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("never names", reason)

    def test_a_file_that_does_name_the_field_still_passes(self):
        source = ('import discord\n'
                  'def go(c):\n'
                  '    return c.icon_emoji\n')
        f = finding(kind="schema_field_removed",
                    subject="GuildChannelResponse.icon_emoji",
                    path="/guilds/{guild_id}/channels")
        verdict, _, _, sites = verify_source(source, "bot.py", f, get("discord"))
        self.assertEqual(verdict, CONFIRMED)
        self.assertTrue(sites)


class TestProvenanceAtLeadTime(unittest.TestCase):
    """The vendor's own SDK must never reach a fetch, let alone a lead."""

    def test_vendor_owned_repo_is_rejected_without_fetching(self):
        from apidrift.verify import verify_candidate
        result = verify_candidate("openai/openai-python",
                                  "src/openai/resources/responses.py",
                                  "https://example.invalid", finding(),
                                  get("openai"))
        self.assertEqual(result.verdict, NOT_AUTHOR_CODE)
        self.assertFalse(result.is_lead)
        # Either rule may fire first; both are correct rejections.
        self.assertTrue(
            "openai org" in result.reason or "copy of the openai" in result.reason,
            result.reason)

    def test_a_vendor_repo_is_rejected_on_the_org_alone(self):
        from apidrift.classify import classify, VENDOR_OWNED
        self.assertEqual(
            classify("openai/openai-python", "openai", "README.md").kind,
            VENDOR_OWNED)

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


class TestPathRuleIsShared(unittest.TestCase):
    """Prospecting and verification must agree on what path to look for.

    They did not: prospecting searched `/bulk-ban` while verification accepted
    any file containing `/guilds`, so a removed 204 on bulk-ban was confirmed
    against a GET of /users/@me/guilds.
    """

    def test_verification_uses_the_distinctive_run(self):
        f = finding(kind="response_status_removed", subject="204",
                    path="/guilds/{guild_id}/bulk-ban")
        f.root_cause = "204"
        symbol, mode = target_symbol(f)
        self.assertEqual(mode, "endpoint")
        self.assertEqual(symbol, "/bulk-ban")

    def test_a_different_guild_route_is_not_a_match(self):
        source = ('import discord\n'
                  'async def guilds(self):\n'
                  '    return await self._request("GET", "/users/@me/guilds")\n')
        f = finding(kind="response_status_removed", subject="204",
                    path="/guilds/{guild_id}/bulk-ban")
        f.root_cause = "204"
        verdict, _, _, _ = verify_source(source, "rest_client.py", f,
                                         get("discord"))
        self.assertEqual(verdict, NO_SITE)

    def test_the_actual_route_still_matches(self):
        source = ('import discord\n'
                  'async def bulk_ban(self, gid):\n'
                  '    return await self._request("POST", f"/guilds/{gid}/bulk-ban")\n')
        f = finding(kind="response_status_removed", subject="204",
                    path="/guilds/{guild_id}/bulk-ban")
        f.root_cause = "204"
        verdict, _, _, _ = verify_source(source, "rest_client.py", f,
                                         get("discord"))
        self.assertEqual(verdict, CONFIRMED)


class TestIdentifierGateScope(unittest.TestCase):
    """Demand an identifier only when the caller could plausibly write it."""

    def test_a_status_code_is_not_demanded(self):
        from apidrift.verify import _named_identifier
        f = finding(kind="response_status_removed", subject="204")
        f.root_cause = "204"
        self.assertEqual(_named_identifier(f), "")

    def test_a_path_fragment_is_not_demanded(self):
        from apidrift.verify import _named_identifier
        f = finding(kind="endpoint_removed", subject="/v1/old_thing")
        f.root_cause = "/v1/old_thing"
        self.assertEqual(_named_identifier(f), "")

    def test_a_field_name_is_demanded(self):
        from apidrift.verify import _named_identifier
        f = finding(subject="GuildChannelResponse.icon_emoji")
        f.root_cause = "GuildChannelResponse.icon_emoji"
        self.assertEqual(_named_identifier(f), "icon_emoji")


class TestHyphenatedIdentifiers(unittest.TestCase):
    def test_a_hyphenated_schema_name_is_demanded(self):
        from apidrift.verify import _named_identifier
        f = finding(kind="schema_removed", subject="Conversation-2")
        f.root_cause = "Conversation-2"
        self.assertEqual(_named_identifier(f), "Conversation-2")

    def test_a_file_that_never_names_it_is_rejected(self):
        f = finding(kind="schema_removed", subject="Conversation-2",
                    path="/responses")
        f.root_cause = "Conversation-2"
        source = ('import openai\n'
                  'def t():\n'
                  '    return client.post("/responses", json={})\n')
        verdict, reason, _, _ = verify_source(source, "test_x.py", f,
                                              get("openai"))
        self.assertEqual(verdict, NO_SITE)
        self.assertIn("never names", reason)
