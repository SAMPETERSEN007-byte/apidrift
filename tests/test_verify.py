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
from apidrift.verify import (CONFIRMED, ERROR, LIKELY, NO_SITE, NO_VENDOR,
                             UNSUPPORTED, lexical_sites, python_sites,
                             target_symbol, verify_source)
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
