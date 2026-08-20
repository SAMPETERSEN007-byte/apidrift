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
from apidrift.scan import (SKIP_DIRS, Impact, ScanResult,
                           can_possibly_match, candidate_files,
                           detect_vendors, to_text,
                           unmeasurable_callers)
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
        result = ScanResult(root="/r", findings_considered=84,
                            vendors_detected={"stripe": 3})
        text = to_text(result)
        self.assertIn("84 breaking changes checked", text)
        self.assertIn("clean", text)


if __name__ == "__main__":
    unittest.main()


class TestUnmeasuredIsNotClean(unittest.TestCase):
    """Zero results is a failed measurement until something says otherwise.

    A repo whose only Stripe caller was `src/pay.ts` was told
    "clean — 0 breaking changes checked", exit 0, while a sibling TypeScript
    file called a Plaid endpoint that had been deleted in the same window.
    Dependence is provable in Python only; every other language is UNMEASURED,
    and the word "clean" must never be printed over one.
    """

    def _repo(self, tmp: str, python: bool, typescript: bool) -> Path:
        root = Path(tmp)
        (root / "src").mkdir()
        if python:
            (root / "src" / "billing.py").write_text(
                "import stripe\nc = stripe.Customer.retrieve(i)\n")
        if typescript:
            (root / "src" / "pay.ts").write_text(
                'import Stripe from "stripe";\n'
                'stripe.subscriptions.update(id, { cancel_at: t });\n')
        return root

    def test_a_typescript_caller_is_counted_as_unmeasured(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp, python=False, typescript=True)
            found = unmeasurable_callers(root, ["stripe", "plaid"])
            self.assertEqual(found, {"stripe": {"TypeScript": 1}})

    def test_the_word_clean_is_never_printed_over_an_unmeasured_language(self):
        result = ScanResult(root="/r", findings_considered=64,
                            vendors_detected={"stripe": 1},
                            unmeasured={"stripe": {"TypeScript": 1}})
        text = to_text(result)
        # The bare all-clear, not the substring: "NOT clean-checked" is fine.
        self.assertNotIn("apidrift: clean", text)
        self.assertIn("NOT clean-checked", text)
        self.assertIn("UNMEASURED", text)
        self.assertIn("not the same as unaffected", text)

    def test_a_python_only_repo_with_no_impact_is_still_allowed_to_be_clean(self):
        """The control. Over-warning makes the warning worthless."""
        result = ScanResult(root="/r", findings_considered=64,
                            vendors_detected={"stripe": 1})
        self.assertIn("apidrift: clean", to_text(result))

    def test_a_repo_calling_no_known_vendor_says_nothing_was_checked(self):
        """Distinct from clean: there was no measurement to pass."""
        text = to_text(ScanResult(root="/r", findings_considered=64))
        self.assertIn("nothing was checked", text)
        self.assertNotIn("apidrift: clean", text)

    def test_an_unmeasured_language_is_reported_alongside_a_real_impact(self):
        result = ScanResult(root="/r", findings_considered=64,
                            vendors_detected={"stripe": 1},
                            unmeasured={"stripe": {"Go": 2}})
        result.impacts.append(Impact(
            vendor="stripe", vendor_name="Stripe", file="a.py", line=1,
            kind="endpoint_removed", label="endpoint removed",
            severity=BREAKING, subject="/v1/x", detail="", old="", new="",
            operation="POST /v1/x"))
        text = to_text(result)
        self.assertIn("1 breaking change(s) land", text)
        self.assertIn("2 Go", text)


class TestShortHistoryIsNotSafety(unittest.TestCase):
    """A spec that did not exist at the start of the window hides everything.

    OpenAI's repo held only a LICENSE 180 days ago; the spec landed 2026-05-13.
    Asked for 180 days it reported ZERO breaking changes — while the same
    vendor over 90 days reports sixteen. Nothing was wrong with the diff: there
    was simply nothing behind the file to compare, and silence read as safety.
    Third time this shape has appeared, after the unparsed languages and the
    repo that called no vendor at all.
    """

    def test_a_quiet_result_over_unseen_history_is_not_called_clean(self):
        result = ScanResult(root="/r", findings_considered=0,
                            vendors_detected={"openai": 4},
                            short_history={"openai": ["openapi.yaml"]})
        text = to_text(result)
        self.assertNotIn("apidrift: clean", text)
        self.assertIn("SHORTER HISTORY THAN REQUESTED", text)
        self.assertIn("unseen, not safe", text)

    def test_full_history_with_no_impact_is_still_clean(self):
        """The control. Over-warning makes the warning worthless."""
        result = ScanResult(root="/r", findings_considered=64,
                            vendors_detected={"openai": 4})
        self.assertIn("apidrift: clean", to_text(result))
