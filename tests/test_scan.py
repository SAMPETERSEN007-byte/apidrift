"""Tests for the local-repository scan.

The sweep and the scan share an engine and differ in vantage point, and the
prefilter is the only new logic that can silently lose a real impact. Its
contract is one-sided: it may say "possible" about a file that turns out not to
matter, and it may never say "impossible" about a file `prove()` would accept.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from apidrift.diff import BREAKING, Finding
from apidrift.scan import (SKIP_DIRS, ScanResult, can_possibly_match,
                           candidate_files, detect_vendors, to_text)
from apidrift.vendors import get


def finding(kind="schema_field_removed", subject="card.iin",
            path="/v1/customers", method="get", ops=(), sigs=()):
    return Finding(kind=kind, severity=BREAKING, op_key=f"{method.upper()} {path}",
                   path=path, method=method, detail="", subject=subject,
                   root_cause=subject, affected_ops=list(ops),
                   signatures=list(sigs))


class TestPrefilterIsSound(unittest.TestCase):
    """A cheap "no" that is ever wrong turns a scan into a false all-clear."""

    def test_a_field_change_needs_the_field_name(self):
        self.assertFalse(can_possibly_match("x = 1\n", finding()))
        self.assertTrue(can_possibly_match("v = card.iin\n", finding()))

    def test_a_field_name_is_matched_across_naming_conventions(self):
        f = finding(subject="Card.stored_credential_usage")
        self.assertTrue(can_possibly_match("d['storedCredentialUsage']\n", f))
        self.assertTrue(can_possibly_match("d['stored_credential_usage']\n", f))

    def test_an_endpoint_change_needs_one_static_segment(self):
        f = finding(kind="endpoint_removed", subject="/v1/subscriptions/{id}",
                    path="/v1/subscriptions/{id}", method="delete",
                    ops=["DELETE /v1/subscriptions/{id}"])
        self.assertFalse(can_possibly_match("requests.get('/v1/charges')\n", f))
        self.assertTrue(
            can_possibly_match("requests.delete('/v1/subscriptions/x')\n", f))

    def test_an_sdk_idiom_alone_is_enough_for_an_endpoint_change(self):
        """A caller using the SDK writes no path at all.

        The idiom must be spelled differently from the path segment, or the
        segment check covers for the idiom check and neither is really tested:
        `stripe.subscriptions.` contains `subscriptions`, but
        `stripe.PaymentIntent.` does not contain `payment_intents`.
        """
        f = finding(kind="endpoint_removed", subject="/v1/payment_intents/{id}",
                    path="/v1/payment_intents/{id}", method="post",
                    ops=["POST /v1/payment_intents/{id}"],
                    sigs=["stripe.PaymentIntent."])
        self.assertFalse(can_possibly_match("stripe.Charge.create()\n", f))
        self.assertTrue(
            can_possibly_match("stripe.PaymentIntent.cancel(i)\n", f))

    def test_a_path_with_nothing_distinctive_is_never_filtered_out(self):
        """`/v2/{Sid}` has no searchable segment, so the filter must abstain."""
        f = finding(kind="endpoint_removed", subject="/v2/{Sid}",
                    path="/v2/{Sid}", method="get", ops=["GET /v2/{Sid}"])
        self.assertTrue(can_possibly_match("nothing here\n", f))

    def test_a_generic_subject_does_not_filter_a_field_change(self):
        """`id` is not distinctive enough to demand; abstaining is correct."""
        self.assertTrue(can_possibly_match("x = 1\n", finding(subject="Foo.id")))


class TestTheWalk(unittest.TestCase):

    def _repo(self, tmp: str) -> Path:
        root = Path(tmp)
        (root / "app").mkdir()
        (root / ".venv" / "lib").mkdir(parents=True)
        (root / "node_modules").mkdir()
        (root / "app" / "billing.py").write_text(
            "import stripe\nc = stripe.Customer.retrieve(i)\n")
        (root / "app" / "notes.md").write_text("# not python\n")
        # Only SKIP_DIRS excludes this one: a Django migration is machine-
        # written Python that carries no venv or vendor marker.
        (root / "app" / "migrations").mkdir()
        (root / "app" / "migrations" / "0001_initial.py").write_text(
            "import stripe\n")
        (root / ".venv" / "lib" / "_card.py").write_text("import stripe\n")
        (root / "node_modules" / "x.py").write_text("import stripe\n")
        return root

    def test_dependency_copies_are_not_this_repos_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            files = candidate_files(root, ["stripe"])
            names = {p.name for p in files}
            self.assertEqual(names, {"billing.py"})
            for skipped in (".venv", "node_modules"):
                self.assertIn(skipped, SKIP_DIRS)

    def test_only_vendors_the_repo_actually_calls_are_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp)
            files = candidate_files(root, ["stripe", "plaid"])
            by_vendor, read = detect_vendors(root, files, ["stripe", "plaid"])
            self.assertEqual(read, 1)
            self.assertIn("stripe", by_vendor)
            self.assertNotIn("plaid", by_vendor)
            self.assertEqual(by_vendor["stripe"][0][0], "app/billing.py")


class TestOutput(unittest.TestCase):

    def test_a_clean_scan_says_how_much_was_checked(self):
        """"No impacts" is only meaningful next to the size of the search."""
        result = ScanResult(root="/r", findings_considered=84)
        text = to_text(result)
        self.assertIn("84 breaking changes checked", text)
        self.assertIn("clean", text)


if __name__ == "__main__":
    unittest.main()
