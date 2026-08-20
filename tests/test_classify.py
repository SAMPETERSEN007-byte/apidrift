"""Tests for lead classification. The vendor's own SDK is not a sales lead."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apidrift.classify import (CORPUS, ECOSYSTEM, INTEGRATOR, VENDOR_OWNED,
                               VENDORED, classify, dedupe_by_repo,
                               is_vendored_path, partition)


class TestClassify(unittest.TestCase):
    def test_vendor_own_sdk_is_excluded(self):
        self.assertEqual(classify("stripe/stripe-python", "stripe").kind, VENDOR_OWNED)
        self.assertEqual(classify("openai/openai-python", "openai").kind, VENDOR_OWNED)
        self.assertEqual(classify("twilio/twilio-agent-connect-python", "twilio").kind,
                         VENDOR_OWNED)

    def test_other_vendors_org_is_not_owned(self):
        # plaid/plaid-python is Plaid's, but from Stripe's point of view it is not.
        self.assertNotEqual(classify("plaid/plaid-python", "stripe").kind, VENDOR_OWNED)

    def test_dataset_dump_is_corpus(self):
        self.assertEqual(classify("AA-Turner/top-pypi-sdists-2000", "stripe").kind, CORPUS)

    def test_vendored_dependency_tree_is_corpus(self):
        self.assertEqual(classify("AmIgOs434/node_modules", "openai").kind, CORPUS)
        self.assertEqual(classify("someone/vendor", "openai").kind, CORPUS)

    def test_js_discord_libraries_are_ecosystem(self):
        for repo in ("abalabahaha/eris", "acode/discord-api-gen"):
            with self.subTest(repo=repo):
                self.assertEqual(classify(repo, "discord").kind, ECOSYSTEM)

    def test_third_party_sdk_is_ecosystem(self):
        for repo in ("DisnakeDev/disnake", "AlexFlipnote/discord.http",
                     "EpikCord/EpikCord.py", "BerriAI/litellm",
                     "adrienverge/localstripe"):
            with self.subTest(repo=repo):
                self.assertEqual(classify(repo, "discord").kind, ECOSYSTEM)

    def test_application_code_is_an_integrator(self):
        for repo in ("caesar4321/Confio", "PostHog/posthog",
                     "fintradeeu/fintrade-backend"):
            with self.subTest(repo=repo):
                self.assertEqual(classify(repo, "twilio").kind, INTEGRATOR)

    def test_only_ecosystem_and_integrators_are_outreach_targets(self):
        self.assertTrue(classify("caesar4321/Confio", "twilio").is_outreach_target)
        self.assertTrue(classify("DisnakeDev/disnake", "discord").is_outreach_target)
        self.assertFalse(classify("stripe/stripe-python", "stripe").is_outreach_target)
        self.assertFalse(classify("x/top-pypi-sdists-2000", "stripe").is_outreach_target)


class TestVendoredPaths(unittest.TestCase):
    """A match inside site-packages is the vendor's own SDK, not a call site."""

    VENDORED = (
        "venv/Lib/site-packages/stripe/_payment_record.py",
        "Backend/env/lib/python3.11/site-packages/stripe/x.py",
        ".venv/lib/site-packages/stripe/y.py",
        "lambda-layer/python/stripe/z.py",
        "functions/_layers/stripe/python/stripe/a.py",
        "layers/common/python/stripe/b.py",
        "node_modules/openai/index.js",
        "vendor/plaid/client.rb",
    )
    AUTHORED = (
        "app/services/billing.py",
        "src/twilio_verify.py",
        "backend/plaid_field_index.py",
    )

    def test_vendored_paths_are_detected(self):
        for path in self.VENDORED:
            with self.subTest(path=path):
                self.assertTrue(is_vendored_path(path))

    def test_authored_paths_are_not_flagged(self):
        for path in self.AUTHORED:
            with self.subTest(path=path):
                self.assertFalse(is_vendored_path(path))

    def test_vendored_sdk_path_is_not_author_code(self):
        result = classify("someone/app", "stripe",
                          "venv/Lib/site-packages/stripe/_payment_record.py")
        self.assertEqual(result.kind, VENDORED)
        self.assertFalse(result.is_outreach_target)

    def test_same_repo_with_authored_path_is_an_integrator(self):
        result = classify("someone/app", "stripe", "app/services/billing.py")
        self.assertEqual(result.kind, INTEGRATOR)
        self.assertTrue(result.is_outreach_target)


class TestPartitionAndDedupe(unittest.TestCase):
    LEADS = [
        {"repo": "stripe/stripe-python", "file": "stripe/x.py", "sites": [{}]},
        {"repo": "caesar4321/Confio", "file": "app/pay.py", "sites": [{}]},
        {"repo": "caesar4321/Confio", "file": "app/pay.py", "sites": [{}, {}, {}]},
        {"repo": "BerriAI/litellm", "file": "litellm/main.py", "sites": [{}]},
    ]

    def test_partition_buckets_every_lead(self):
        buckets = partition(self.LEADS, "stripe")
        self.assertEqual(sum(len(v) for v in buckets.values()), len(self.LEADS))
        self.assertEqual(len(buckets[VENDOR_OWNED]), 1)

    def test_partition_annotates_reason(self):
        buckets = partition(self.LEADS, "stripe")
        self.assertIn("stripe org", buckets[VENDOR_OWNED][0]["lead_reason"])

    def test_dedupe_keeps_the_richest_row_per_repo(self):
        deduped = dedupe_by_repo(self.LEADS)
        self.assertEqual(len(deduped), 3)
        confio = next(l for l in deduped if l["repo"] == "caesar4321/Confio")
        self.assertEqual(len(confio["sites"]), 3, "kept the row with the most sites")


if __name__ == "__main__":
    unittest.main(verbosity=2)
