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


class TestKindCoverage(unittest.TestCase):
    """Every kind the engine emits must be classified by exactly one rule.

    Three modules previously kept private copies of these lists, and none of
    them was updated when the schema-level kinds were introduced, so every
    `schema_*` finding silently fell through to a default.
    """

    def test_every_emitted_kind_is_classified(self):
        import json
        from pathlib import Path
        from apidrift.diff import ABSENCE_KINDS, ENDPOINT_KINDS, FIELD_KINDS

        findings_path = Path(__file__).resolve().parent.parent / "out" / "findings.json"
        if not findings_path.exists():
            self.skipTest("no findings.json; run the CLI first")
        emitted = {f["kind"] for entry in json.load(open(findings_path))
                   for f in entry["findings"]}
        known = ENDPOINT_KINDS | ABSENCE_KINDS | FIELD_KINDS
        unclassified = emitted - known
        self.assertEqual(unclassified, set(),
                         f"kinds with no search or verify rule: {sorted(unclassified)}")

    def test_the_classes_do_not_overlap(self):
        from apidrift.diff import ABSENCE_KINDS, ENDPOINT_KINDS, FIELD_KINDS
        self.assertEqual(ENDPOINT_KINDS & ABSENCE_KINDS, set())
        self.assertEqual(ENDPOINT_KINDS & FIELD_KINDS, set())
        self.assertEqual(ABSENCE_KINDS & FIELD_KINDS, set())


class TestPseudoPaths(unittest.TestCase):
    """A schema finding's carrier path is not a URL."""

    def _schema_finding(self, ops=()):
        return Finding(
            kind="schema_field_removed", severity=BREAKING,
            op_key="GET #/components/schemas/SpamLinkRuleResponse",
            path="#/components/schemas/SpamLinkRuleResponse", method="get",
            detail="", subject="SpamLinkRuleResponse.creator_id",
            root_cause="SpamLinkRuleResponse.creator_id",
            affected_ops=list(ops),
        )

    def test_pseudo_path_is_never_searched_as_a_url(self):
        query = build_query(self._schema_finding(), get("discord"), "python")
        self.assertNotIn("#/components", query)

    def test_a_real_affected_operation_is_preferred(self):
        query = build_query(
            self._schema_finding(["GET /guilds/{id}/auto-moderation/rules"]),
            get("discord"), "python")
        self.assertIn("/guilds", query)

    def test_schema_name_is_the_fallback_when_no_endpoint_exists(self):
        f = self._schema_finding()
        f.subject = f.root_cause = "SpamLinkRuleResponse.id"   # weak leaf
        query = build_query(f, get("discord"), "python")
        self.assertIn("SpamLinkRuleResponse", query)


class TestPseudoPathRendering(unittest.TestCase):
    def test_signatures_never_contain_a_json_pointer(self):
        from apidrift.signatures import build_signatures
        f = Finding(kind="schema_field_removed", severity=BREAKING,
                    op_key="GET #/components/schemas/Foo",
                    path="#/components/schemas/Foo", method="get", detail="",
                    subject="Foo.bar", root_cause="Foo.bar")
        for sig in build_signatures(f, get("stripe")):
            self.assertNotIn("#/components", sig)


class TestGrepIsRunnable(unittest.TestCase):
    """A command we print must actually run when pasted."""

    def test_quoted_signatures_do_not_break_the_shell(self):
        import subprocess
        from apidrift.signatures import build_grep
        cmd = build_grep(['ResponsesClientEventResponseCreate', '"service_tier"',
                          "'service_tier'", "service_tier="])
        self.assertNotIn("'service_tier'", cmd)
        # Parse it the way a shell would; a quoting error raises here.
        import shlex
        parts = shlex.split(cmd)
        self.assertEqual(parts[0], "rg")
        self.assertIn("-e", parts)

    def test_pattern_is_valid_regex(self):
        import re
        from apidrift.signatures import build_grep
        import shlex
        cmd = build_grep(['/v1/customers/{customer}', '"iin"', 'stripe.customers.'])
        pattern = shlex.split(cmd)[shlex.split(cmd).index("-e") + 1]
        re.compile(pattern)   # raises if the escaping is wrong


class TestEveryPrintedCommandIsValid(unittest.TestCase):
    """Every command in the report must survive a paste into a shell."""

    def test_all_report_commands_parse_and_compile(self):
        import re
        import shlex
        from pathlib import Path

        report = Path(__file__).resolve().parent.parent / "out" / "report.md"
        if not report.exists():
            self.skipTest("no report.md; run the CLI first")
        commands = [line for line in report.read_text().splitlines()
                    if line.startswith("rg -n")]
        self.assertGreater(len(commands), 0, "report contains no commands to check")
        for command in commands:
            with self.subTest(command=command[:70]):
                parts = shlex.split(command)          # raises on bad quoting
                pattern = parts[parts.index("-e") + 1]
                re.compile(pattern)                    # raises on bad escaping
                self.assertNotIn("#/components", pattern,
                                 "a JSON pointer is not a call site")


class TestLabels(unittest.TestCase):
    def test_every_emitted_kind_has_a_human_label(self):
        import json
        from pathlib import Path
        from apidrift.diff import KIND_LABEL

        findings_path = Path(__file__).resolve().parent.parent / "out" / "findings.json"
        if not findings_path.exists():
            self.skipTest("no findings.json; run the CLI first")
        emitted = {f["kind"] for entry in json.load(open(findings_path))
                   for f in entry["findings"]}
        missing = emitted - set(KIND_LABEL)
        self.assertEqual(missing, set(), f"kinds with no reader-facing label: {sorted(missing)}")
