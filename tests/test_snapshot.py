"""The recorder for vendors who publish a spec and no history.

History cannot be fetched for these, only accumulated, so the clock has to
start before anyone needs it. Everything here was written after the FIRST real
run, which is also when most of it turned out to be necessary: the validator
rejected three valid specs, one source refuses this client outright, and one
would have stored a four-megabyte blob every day forever.
"""
from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

from apidrift.snapshot import (DEAD, LIVE, STALE, Outcome, Source, SourceBlocked,
                               Store, canonical, digest, fetch,
                               looks_like_a_spec, report, take)

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "t", "version": "1"},
    "paths": {"/a": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


class TestValidity(unittest.TestCase):
    def test_html_is_named_as_html_not_merely_rejected(self):
        """Four vendors answer 200 with an error page. A status code is not
        evidence, and an invalid record is worse than a gap because a gap is
        visible.

        The assertion is on the REASON, deliberately. Parsing rejects an HTML
        page too -- it is not a mapping -- so a test that only checked
        "rejected" passed with the HTML branch deleted and killed no mutation.
        What the fast path buys is that the operator reading the daily report
        is told the server returned a web page, which is a different problem
        from a malformed spec and has a different fix.
        """
        for body in (b"<!DOCTYPE html><html>", b"  <html>nope</html>"):
            self.assertEqual("HTML, not a spec", looks_like_a_spec(body, "openapi"))

    def test_a_marker_beyond_the_first_400_bytes_is_still_a_spec(self):
        """The regression this file exists for. The first validator scanned the
        leading 400 bytes for a marker word and the first real run rejected
        THREE valid specs -- Increase at 4.1 MB, Gemini and Slack -- because
        their marker sits further in. Gemini is the pointed one: Google
        randomises JSON key order per response, so WHERE a key appears is not a
        property of the document at all."""
        padded = {"description": "x" * 5000, **SPEC}
        self.assertEqual("", looks_like_a_spec(
            json.dumps(padded).encode(), "openapi"))

    def test_valid_json_that_is_not_a_spec_is_rejected(self):
        """Parsing is not enough; an error envelope parses perfectly."""
        body = json.dumps({"error": "not found", "code": 404}).encode()
        self.assertIn("no openapi root key", looks_like_a_spec(body, "openapi"))

    def test_yaml_with_a_bare_equals_scalar_parses(self):
        """Zendesk's oas.yaml contains a bare `=`, which YAML 1.1 resolves to
        `tag:yaml.org,2002:value`. PyYAML's SafeLoader has no constructor for
        it and raises, so a good 1.7 MB spec was rejected as neither JSON nor
        YAML."""
        body = b"openapi: 3.0.0\npaths: {}\nweird: =\n"
        self.assertEqual("", looks_like_a_spec(body, "openapi"))

    def test_an_empty_body_is_rejected(self):
        self.assertEqual("empty body", looks_like_a_spec(b"", "openapi"))


class TestCanonicalForm(unittest.TestCase):
    """Three vendors defeat naive hashing in three different ways, and the
    change detector has to survive all of them while still moving when the
    contract does."""

    def test_key_order_does_not_move_the_digest(self):
        """Google re-serialises the Gemini discovery document with randomised
        key order on every request: two back-to-back fetches of the same
        366,943 bytes produced different digests and 15,413 changed lines."""
        a = json.dumps(SPEC, sort_keys=True).encode()
        b = json.dumps(SPEC, sort_keys=False,
                       separators=(", ", ": ")).encode()
        self.assertNotEqual(a, b)
        self.assertEqual(digest(a, "openapi"), digest(b, "openapi"))

    def test_an_example_changing_does_not_move_the_digest(self):
        """Avalara regenerates every example value per request."""
        a = dict(SPEC, components={"schemas": {"X": {"example": "one"}}})
        b = dict(SPEC, components={"schemas": {"X": {"example": "two"}}})
        self.assertEqual(digest(json.dumps(a).encode(), "openapi"),
                         digest(json.dumps(b).encode(), "openapi"))

    def test_a_fresh_uuid_or_timestamp_does_not_move_the_digest(self):
        """Measured on Avalara after examples were stripped: one difference
        remained, an OAuth `authorizationUrl` carrying a fresh `nonce` GUID.
        That is not a mistake, it is what a nonce is for."""
        url = "https://id.example.com/authorize?nonce={}&t={}"
        a = dict(SPEC, servers=[{"url": url.format(
            "0bf262ed-7a33-4cce-bfde-0549fecf9018", "2026-08-20T23:16:53.2179669Z")}])
        b = dict(SPEC, servers=[{"url": url.format(
            "a7bdf4ac-1c6d-4998-8573-19a7e5083c9f", "2026-08-20T23:17:11.5372597Z")}])
        self.assertEqual(digest(json.dumps(a).encode(), "openapi"),
                         digest(json.dumps(b).encode(), "openapi"))

    def test_a_real_contract_change_STILL_moves_the_digest(self):
        """The control. Every test above makes the detector less sensitive, and
        a detector that has been made insensitive to everything reports a clean
        archive forever."""
        b = json.loads(json.dumps(SPEC))
        del b["paths"]["/a"]
        self.assertNotEqual(digest(json.dumps(SPEC).encode(), "openapi"),
                            digest(json.dumps(b).encode(), "openapi"))

    def test_an_unparseable_body_is_compared_as_written(self):
        self.assertEqual(canonical(b"\xff\xfe not json", "openapi"),
                         b"\xff\xfe not json")


class TestStore(unittest.TestCase):
    def test_an_unchanged_day_costs_nothing_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp))
            body = json.dumps(SPEC).encode()
            first, _ = store.put("v", body, "openapi", "2026-08-20")
            second, _ = store.put("v", body, "openapi", "2026-08-21")
            self.assertTrue(first)
            self.assertFalse(second, "an unchanged body must not be stored again")
            self.assertEqual(1, len(store.index("v")))

    def test_a_changed_body_is_stored_and_indexed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp))
            store.put("v", json.dumps(SPEC).encode(), "openapi", "2026-08-20")
            changed = json.loads(json.dumps(SPEC))
            changed["paths"]["/b"] = {"get": {"responses": {}}}
            stored, _ = store.put("v", json.dumps(changed).encode(),
                                  "openapi", "2026-08-21")
            self.assertTrue(stored)
            self.assertEqual(2, len(store.index("v")))


class TestTake(unittest.TestCase):
    def test_an_invalid_body_is_never_stored(self):
        """A gap in the archive is visible. A bad record is not."""
        import apidrift.snapshot as snap
        real = snap.fetch
        snap.fetch = lambda url: b"<!DOCTYPE html><html>404</html>"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                store = Store(Path(tmp))
                out = take(Source("v", "V", "https://example.test/s.json"),
                           store, "2026-08-20")
                self.assertEqual("invalid", out.status)
                self.assertEqual([], store.index("v"))
        finally:
            snap.fetch = real

    def test_a_refusal_is_its_own_state_not_an_error(self):
        """Salesforce answers 403 to this fetcher with or without a Referer. A
        durable refusal and a flaky network are the same word in a log and need
        opposite responses: one is retried tomorrow, the other needs a human to
        find another route."""
        import apidrift.snapshot as snap
        real = snap.fetch

        def refuse(url):
            raise SourceBlocked("HTTP 403 — the server refuses this client")

        snap.fetch = refuse
        try:
            with tempfile.TemporaryDirectory() as tmp:
                out = take(Source("v", "V", "https://example.test/s.json"),
                           Store(Path(tmp)), "2026-08-20")
                self.assertEqual("blocked", out.status)
        finally:
            snap.fetch = real


class TestReport(unittest.TestCase):
    def test_a_quiet_dead_source_is_never_an_all_clear(self):
        """"Unchanged" from a live source and "unchanged" from a source that
        has not moved since 2021 are the same word for two different facts."""
        with tempfile.TemporaryDirectory() as tmp:
            text = report([Outcome("postmark", "unchanged")], Path(tmp),
                          "2026-08-20")
            self.assertIn("NOT AN ALL-CLEAR", text)
            self.assertIn("DEAD SOURCE", text)

    def test_a_quiet_live_source_is_reported_plainly(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = report([Outcome("notion", "unchanged")], Path(tmp),
                          "2026-08-20")
            self.assertNotIn("NOT AN ALL-CLEAR", text)

    def test_every_registered_source_states_its_liveness_evidence(self):
        """A label with no measurement behind it is an opinion."""
        from apidrift.snapshot import SOURCES
        for source in SOURCES:
            if source.liveness != LIVE:
                self.assertTrue(
                    source.liveness_evidence,
                    f"{source.key} is marked {source.liveness} with no evidence")


class TestFetchClassification(unittest.TestCase):
    def test_a_403_is_a_refusal_and_a_500_is_not(self):
        import apidrift.snapshot as snap
        real = snap.urllib.request.urlopen

        def raise_status(code):
            def opener(request, timeout=None):
                raise urllib.error.HTTPError(
                    request.full_url, code, "no", {}, None)
            return opener

        try:
            snap.urllib.request.urlopen = raise_status(403)
            with self.assertRaises(SourceBlocked):
                fetch("https://example.test/s.json")
            snap.urllib.request.urlopen = raise_status(500)
            with self.assertRaises(Exception) as ctx:
                fetch("https://example.test/s.json")
            self.assertNotIsInstance(ctx.exception, SourceBlocked)
        finally:
            snap.urllib.request.urlopen = real


if __name__ == "__main__":
    unittest.main()
