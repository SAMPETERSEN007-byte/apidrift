"""Tests for query construction and finding ranking."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apidrift.diff import BREAKING, Finding
from apidrift.prospect import build_query, rank_findings, searchability
from apidrift.vendors import get


def finding(kind="response_field_removed", subject="Card.iin",
            path="/v1/customers", occurrences=1):
    return Finding(kind=kind, severity=BREAKING, op_key=f"GET {path}", path=path,
                   method="get", detail="", subject=subject, root_cause=subject,
                   occurrences=occurrences)


class TestSearchability(unittest.TestCase):
    """Ranking by fan-out left 29 real Discord findings unsearched."""

    def test_distinctive_identifier_outranks_common_word(self):
        distinctive = finding(subject="SpamLinkRuleResponse", occurrences=2)
        common = finding(subject="RecurrenceRule.frequency", occurrences=6)
        self.assertGreater(searchability(distinctive), searchability(common))

    def test_weak_tokens_are_penalised_below_zero(self):
        for word in ("id", "type", "name", "data", "status"):
            with self.subTest(word=word):
                self.assertLess(searchability(finding(subject=f"X.{word}")), 0)

    def test_compound_identifiers_score_well(self):
        self.assertGreaterEqual(
            searchability(finding(subject="GuildChannelResponse.hd_streaming_buyer_id")), 5)

    def test_endpoint_changes_get_a_bonus(self):
        endpoint = finding(kind="endpoint_removed", subject="/v1/old",
                           path="/v1/old_thing")
        field = finding(subject="X.abcd")
        self.assertGreater(searchability(endpoint), searchability(field))

    def test_ranking_puts_searchable_before_high_fanout(self):
        findings = [
            finding(subject="RecurrenceRule.day", occurrences=99),
            finding(subject="SpamLinkRuleResponse", occurrences=1),
        ]
        ranked = rank_findings(findings)
        self.assertEqual(ranked[0].root_cause, "SpamLinkRuleResponse")


class TestQueryConstruction(unittest.TestCase):
    def test_field_and_path_are_conjoined(self):
        query = build_query(finding(), get("stripe"), "python")
        self.assertIn('"iin"', query)
        self.assertIn('"/v1/customers"', query)
        self.assertIn("language:python", query)

    def test_newly_required_field_searches_the_endpoint_not_the_field(self):
        # The break is the field's ABSENCE, so searching for it finds only
        # the callers who are already fine.
        f = finding(kind="request_field_added_required", subject="Rule.frequency",
                    path="/v1/checkout/sessions")
        query = build_query(f, get("stripe"), "python")
        self.assertNotIn('"frequency"', query)
        self.assertIn('"/v1/checkout/sessions"', query)

    def test_weak_leaf_falls_back_to_the_path(self):
        f = finding(subject="Thing.id", path="/v1/customers")
        query = build_query(f, get("stripe"), "python")
        self.assertNotIn('"id"', query)
        self.assertIn('"/v1/customers"', query)


if __name__ == "__main__":
    unittest.main(verbosity=2)
