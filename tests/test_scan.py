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

    def test_typescript_is_no_longer_unmeasured(self):
        """TypeScript is PROVEN now, so counting it as unmeasured would
        double-report it: once as an impact and once as a blind spot."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._repo(tmp, python=False, typescript=True)
            self.assertEqual({}, unmeasurable_callers(root, ["stripe", "plaid"]))

    def test_a_language_that_is_still_unparsed_is_counted(self):
        """The invariant the TypeScript test used to carry, moved to a language
        that is still unreadable. It must not disappear along with the blind
        spot it happened to be written against -- Go, Ruby and the rest are
        exactly as unmeasured as TypeScript was."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "pay.go").write_text(
                'import "github.com/stripe/stripe-go"\n'
                '// api.stripe.com\n')
            found = unmeasurable_callers(root, ["stripe", "plaid"])
            self.assertEqual({"stripe": {"Go": 1}}, found)

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


class TestOpportunitiesSayWhatWasRejected(unittest.TestCase):
    """Twelve honest suggestions read as noise when the actionable ones are
    not accounted for.

    A developer shown `account_capabilities.bizum_payments` and nothing else
    concludes the tool cannot tell a decision from a notification, and mutes
    it. The count that was CONSIDERED and did not reach them is the sentence
    that makes the rest trustworthy.
    """

    def _result(self, **kw):
        base = dict(root="/r", vendors_detected={"stripe": 1},
                    findings_considered=1, additions_considered=154,
                    additions_by_kind={"endpoint_added": 3,
                                       "response_field_added": 151})
        base.update(kw)
        return ScanResult(**base)

    def test_actionable_additions_that_reached_nobody_are_stated(self):
        text = to_text(self._result())
        self.assertIn("0 of 3", text)
        self.assertIn("resources this repo does not call", text)

    def test_a_passive_field_is_not_called_something_to_adopt(self):
        opportunity = Impact(
            vendor="stripe", vendor_name="Stripe", file="a.ts", line=9,
            kind="response_field_added", label="new field in a response",
            severity="additive", subject="checkout.session.managed_payments",
            detail="", old="", new="", operation="")
        text = to_text(self._result(opportunities=[opportunity]))
        self.assertIn("Arrives on its own", text)
        self.assertNotIn("Worth a decision — 1", text)

    def test_a_new_endpoint_is_ranked_above_a_response_field(self):
        endpoint = Impact(
            vendor="stripe", vendor_name="Stripe", file="a.ts", line=3,
            kind="endpoint_added", label="new endpoint", severity="additive",
            subject="/v1/payment_records", detail="", old="", new="", operation="")
        passive = Impact(
            vendor="stripe", vendor_name="Stripe", file="a.ts", line=9,
            kind="response_field_added", label="new field in a response",
            severity="additive", subject="x.y", detail="", old="", new="", operation="")
        text = to_text(self._result(opportunities=[endpoint, passive]))
        self.assertLess(text.index("/v1/payment_records"), text.index("x.y"),
                        "a decision must be shown before a notification")


class TestScanControlFixtureIsAGenuineDependence(unittest.TestCase):
    """The recall control must inject a read at the position the subject names.

    It did not. Stripe's `<radar.payment_evaluation>.insights.card_issuer_decline`
    produced `record.card_issuer_decline`, which is not a read of that field at
    all, and the control passed for exactly as long as the prover shared the
    mistake. It went SILENT the day the prover learned that a read is a position
    and not a word — a control that picks its stimulus the way the mechanism
    under test would is not measuring that mechanism.
    """

    def _control(self):
        import importlib.util
        from pathlib import Path as _P
        root = _P(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "scan_control", root / "tools" / "scan_control.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_scan_control_fixture_reads_the_full_wire_path(self):
        import tempfile
        from pathlib import Path as _P
        sc = self._control()
        case = {
            "finding": {"subject": "<radar.payment_evaluation>.insights.card_issuer_decline"},
            "leaf": "card_issuer_decline",
            "wire_path": sc._wire_path(
                "<radar.payment_evaluation>.insights.card_issuer_decline"),
            "resource": "payment_evaluations",
            "path": "/v1/radar/payment_evaluations",
            "method": "get",
        }
        tmp = _P(tempfile.mkdtemp())
        sc._write_fixture(tmp, "stripe", case)
        python = (tmp / "src" / "app.py").read_text()
        typescript = (tmp / "src" / "app.ts").read_text()
        self.assertIn("record.insights.card_issuer_decline", python)
        self.assertIn("record.insights.card_issuer_decline", typescript)

    def test_the_wire_path_drops_only_the_schema_annotations(self):
        sc = self._control()
        self.assertEqual(["insights", "card_issuer_decline"],
                         sc._wire_path("<radar.payment_evaluation>.insights.card_issuer_decline"))
        self.assertEqual(["rule", "item_id"],
                         sc._wire_path("<TransactionsRulesCreateResponse>.rule.item_id"))


class TestADatedApiVersionIsNotHead(unittest.TestCase):
    """A caller on a pinned SDK does not meet HEAD, so HEAD's drift is silent
    about it. Reported as UNMEASURED — never as clean, never as broken.

    This refuted the most convincing impact this tool ever produced. Langfuse
    reads `subscription.current_period_start` at
    `handleCloudSpendAlertJob.ts:96`; Stripe removed it from the subscription
    object in `2025-03-31.basil`; `stripe-node@17.4.0` sends
    `2024-11-20.acacia` and Stripe still serves that shape. Two independent
    auditors killed the claim on 2026-08-21 and both were right.
    """

    def test_an_es_import_of_the_sdk_counts_as_pinned(self):
        from apidrift.scan import reaches_through_sdk
        from apidrift.vendors import get
        self.assertTrue(reaches_through_sdk(
            'import Stripe from "stripe";\nconst s = new Stripe(k);\n', get("stripe")))

    def test_a_python_import_of_the_sdk_counts_as_pinned(self):
        from apidrift.scan import reaches_through_sdk
        from apidrift.vendors import get
        self.assertTrue(reaches_through_sdk(
            "import stripe\nstripe.Charge.list()\n", get("stripe")))
        self.assertTrue(reaches_through_sdk(
            "from stripe import Charge\n", get("stripe")))

    def test_raw_http_is_NOT_pinned(self):
        """A caller writing its own request sends no version header and gets
        the account default, so that one really can drift."""
        from apidrift.scan import reaches_through_sdk
        from apidrift.vendors import get
        self.assertFalse(reaches_through_sdk(
            'await fetch("https://api.stripe.com/v1/charges")\n', get("stripe")))

    def test_an_unversioned_vendor_is_never_pinned(self):
        """GitHub serves one version of its REST API to everybody."""
        from apidrift.scan import reaches_through_sdk
        from apidrift.vendors import get
        self.assertFalse(get("github").versioned)

    def test_the_method_call_marker_is_not_an_import(self):
        """The first version of this asked whether any evidence marker was in
        the source. Stripe's markers include `"stripe."` — a method call — so
        the check passed straight over the case it was written for."""
        from apidrift.scan import reaches_through_sdk
        from apidrift.vendors import get
        self.assertFalse(reaches_through_sdk(
            "const total = stripe.total + 1\n", get("stripe")))


class TestTestFilesAreNotTheProduct(unittest.TestCase):
    """A vendor URL inside a `parametrize` decorator is not a broken build."""

    def test_incidental_paths_are_recognised(self):
        from apidrift.scan import _is_incidental
        for path in ("tests/test_klaviyo.py", "src/foo/tests/test_x.py",
                     "docs/example.py", "examples/demo.ts", "pkg/x_test.py"):
            self.assertTrue(_is_incidental(path), path)
        for path in ("src/billing/charge.py", "worker/src/jobs/spend.ts",
                     "app/latest/handler.ts"):
            self.assertFalse(_is_incidental(path), path)


class TestPinnedAndIncidentalEndToEnd(unittest.TestCase):
    """The two splits, exercised through `scan_repo` rather than a predicate.

    A unit test of the predicate cannot show that the RESULT changed, and the
    result is the product: what lands in `impacts` is what fails a build and
    what would go into a pull request.

    Runs against a SYNTHETIC two-commit vendor repo, not the real Stripe cache.
    The first version of these tests diffed Stripe's 8 MB spec three times and
    took layer 1 from 0.14s to 10s -- which would have put layer 2, the
    mutation harness, at a quarter of an hour. A gate nobody runs is not a gate.
    """

    @classmethod
    def setUpClass(cls):
        import json as _json
        import subprocess
        import tempfile
        from pathlib import Path as _P
        from apidrift.vendors import VENDORS, Vendor

        cls._cache = _P(tempfile.mkdtemp(prefix="apidrift-fakevendor-"))
        repo = cls._cache / "fake_vendor"
        repo.mkdir(parents=True)

        def git(*args, when=None):
            import os
            env = dict(os.environ)
            if when:
                # BOTH dates. `git commit --date` sets only the AUTHOR date and
                # `commit_before` reads the COMMITTER date, so a fixture built
                # with --date alone lands every commit at "now" and the window
                # is empty.
                env["GIT_AUTHOR_DATE"] = when
                env["GIT_COMMITTER_DATE"] = when
            subprocess.run(["git", "-C", str(repo), *args], check=True, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def spec(with_field):
            insights = {"type": "object", "properties": {}}
            if with_field:
                insights["properties"]["card_issuer_decline"] = {"type": "string"}
            return {
                "openapi": "3.0.0", "info": {"title": "Fake", "version": "1"},
                "components": {
                    "securitySchemes": {"basic": {"type": "http"}},
                    "schemas": {"evaluation": {"type": "object", "properties": {
                        "insights": insights}}}},
                "paths": {"/v1/evaluations/{id}": {"get": {
                    "operationId": "getEvaluation",
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok", "content": {
                        "application/json": {"schema": {
                            "$ref": "#/components/schemas/evaluation"}}}}}}}},
            }

        git("init", "-q")
        git("config", "user.email", "t@t"); git("config", "user.name", "t")
        (repo / "openapi.json").write_text(_json.dumps(spec(True)))
        git("add", "openapi.json")
        git("commit", "-q", "-m", "before", when="2026-01-01T00:00:00+0000")
        (repo / "openapi.json").write_text(_json.dumps(spec(False)))
        git("add", "openapi.json")
        git("commit", "-q", "-m", "after", when="2026-08-01T00:00:00+0000")

        cls._key = "fakevendor"
        cls._added = Vendor(
            key=cls._key, name="FakeVendor", repo="fake/vendor",
            spec_path="openapi.json", docs_url="https://example.invalid",
            version_prefixes=("/v1",), versioned=True,
            evidence=("import fakevendor", "from fakevendor",
                      "api.fakevendor.com", "FAKEVENDOR_KEY"))
        VENDORS[cls._key] = cls._added
        from apidrift import js_dependence
        js_dependence._SDK_PACKAGES[cls._key] = ("fakevendor",)

    @classmethod
    def tearDownClass(cls):
        import shutil
        from apidrift.vendors import VENDORS
        VENDORS.pop(cls._key, None)
        shutil.rmtree(cls._cache, ignore_errors=True)

    def _repo(self, files):
        import tempfile
        from pathlib import Path as _P
        root = _P(tempfile.mkdtemp(prefix="apidrift-split-"))
        for rel, text in files.items():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text)
        return root

    def _scan(self, files):
        from apidrift.scan import scan_repo
        return scan_repo(root=self._repo(files), since="2026-03-01",
                         vendor_keys=[self._key], cache_dir=self._cache,
                         fetch=False, asof="2026-08-21", window_days=180,
                         progress=None)

    RAW = ('import requests\n'
           '\n'
           'def load(i):\n'
           '    record = requests.get(\n'
           '        "https://api.fakevendor.com/v1/evaluations/%s" % i\n'
           '    ).json()\n'
           '    return record["insights"]["card_issuer_decline"]\n')

    SDK = ('import fakevendor\n'
           '\n'
           'def load(i):\n'
           '    record = fakevendor.evaluations.retrieve(i)\n'
           '    return record.insights.card_issuer_decline\n')

    def test_a_raw_http_caller_IS_judged(self):
        """The control, and it must come first: if this does not fire, the two
        tests below prove nothing, because everything would be quiet anyway."""
        result = self._scan({"src/app.py": self.RAW})
        self.assertEqual(1, len(result.impacts),
                         [(i.file, i.subject) for i in result.impacts])
        self.assertEqual("src/app.py", result.impacts[0].file)
        self.assertEqual({}, result.pinned)

    def test_the_pin_names_the_declared_release(self):
        """The end-to-end half: the release reaches the REPORT, not just the
        helper. A number computed and not printed is a number nobody acts on."""
        result = self._scan({"src/app.py": self.SDK,
                             "requirements.txt": "fakevendor==3.2.1\n"})
        self.assertEqual("fakevendor==3.2.1",
                         result.pinned_versions.get(self._key))
        from apidrift.scan import to_text
        self.assertIn("fakevendor==3.2.1", to_text(result))

    def test_a_pinned_sdk_caller_is_unmeasured_not_broken(self):
        result = self._scan({"src/app.py": self.SDK})
        self.assertEqual([], result.impacts,
                         [(i.file, i.subject) for i in result.impacts])
        self.assertIn(self._key, result.pinned)
        self.assertIn("src/app.py", result.pinned[self._key])
        from apidrift.scan import to_text
        self.assertIn("NOT clean-checked", to_text(result))

    def test_a_test_file_impact_is_split_out_of_the_exit_status(self):
        result = self._scan({"tests/test_app.py": self.RAW})
        self.assertEqual([], result.impacts,
                         "a test file must never fail the build")
        self.assertEqual(1, len(result.incidental),
                         "…but it must still be reported")
        from apidrift.scan import to_text
        self.assertIn("IN TEST / EXAMPLE / DOC FILES", to_text(result))


class TestWhichVendorsServeDatedVersions(unittest.TestCase):
    """Which vendors are marked `versioned` is a claim about the world, and it
    decides whether a whole class of impact may be reported at all.

    Each of these sends a dated version from its SDK, so a caller on that SDK
    meets the version the SDK shipped with and not HEAD. Unmarking one puts
    every SDK caller of it back in the impact list, which is what produced the
    most convincing false positive this tool has ever emitted.
    """

    def test_the_dated_version_vendors_are_marked(self):
        from apidrift.vendors import VENDORS
        for key in ("stripe", "plaid", "klaviyo", "square"):
            self.assertTrue(VENDORS[key].versioned,
                            f"{key} serves dated API versions")

    def test_vendors_that_serve_one_version_to_everybody_are_not(self):
        """The control: this must not become a blanket. GitHub, OpenAI, Twilio
        and Discord serve a single current API, so their callers really can
        drift and must still be judged."""
        from apidrift.vendors import VENDORS
        for key in ("github", "openai", "twilio", "discord", "sentry"):
            self.assertFalse(VENDORS[key].versioned,
                             f"{key} does not serve dated API versions")


class TestThePinReportsWhichRelease(unittest.TestCase):
    """"You are pinned" is not actionable; "pinned to stripe@^17.4.0" is.

    That number is the input to the only question that matters for a
    dated-version vendor — what changed BETWEEN two API versions — and it is
    the number that changes on the day the break actually arrives.
    """

    def _root(self, files):
        import tempfile
        from pathlib import Path as _P
        root = _P(tempfile.mkdtemp(prefix="apidrift-pinver-"))
        for name, text in files.items():
            (root / name).write_text(text)
        return root

    def test_package_json_dependency(self):
        import json as _json
        from apidrift.scan import pinned_sdk_version
        from apidrift.vendors import get
        root = self._root({"package.json": _json.dumps(
            {"dependencies": {"next": "15", "stripe": "^17.4.0"}})})
        self.assertEqual("stripe@^17.4.0", pinned_sdk_version(root, get("stripe")))

    def test_requirements_txt(self):
        from apidrift.scan import pinned_sdk_version
        from apidrift.vendors import get
        root = self._root({"requirements.txt": "django==5.0\nstripe==11.6.0\n"})
        self.assertEqual("stripe==11.6.0", pinned_sdk_version(root, get("stripe")))

    def test_a_repo_declaring_nothing_says_nothing(self):
        """No version is better than a wrong one: the range is reported
        verbatim, never resolved against a registry this tool cannot see."""
        from apidrift.scan import pinned_sdk_version
        from apidrift.vendors import get
        root = self._root({"package.json": '{"dependencies": {"next": "15"}}'})
        self.assertEqual("", pinned_sdk_version(root, get("stripe")))

    def test_a_similarly_named_package_is_not_the_sdk(self):
        import json as _json
        from apidrift.scan import pinned_sdk_version
        from apidrift.vendors import get
        root = self._root({"package.json": _json.dumps(
            {"dependencies": {"stripe-terminal-react": "1.0.0"}})})
        self.assertEqual("", pinned_sdk_version(root, get("stripe")))
