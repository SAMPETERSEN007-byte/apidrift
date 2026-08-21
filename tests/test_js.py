"""Tests for the JavaScript/TypeScript reader.

Dependence was provable in Python only. Measured across eight real
repositories, every file calling a tracked vendor was TypeScript, so the
product's entire output was an apology. This is the reader that fixes that, and
the thing it must never do is invent a call site: a fabricated proof is worse
than a missing one, so anything unreadable has to SAY it is unreadable.
"""
from __future__ import annotations

import unittest

from apidrift.js import (UnreadableSource, Token, analyse, tokenize)


def kinds_of(source):
    return [(t.kind, t.text) for t in tokenize(source)]


class TestTokenizer(unittest.TestCase):
    def test_a_regex_literal_is_not_division(self):
        tokens = tokenize("const re = /ab+c/gi; const x = a / b;")
        texts = [t.text for t in tokens if t.kind == "regex"]
        self.assertEqual(["/ab+c/gi"], texts)

    def test_division_is_not_a_regex(self):
        """The other half. A tokeniser that reads `/` as a regex after a value
        swallows the rest of the line and every call site in it.

        Every kind of value that can precede a division is covered, because
        each is a separate branch of the decision: an identifier, a number, a
        closing paren, and a string.
        """
        for expression in ("const r = total / count;",
                           "const r = 10 / 2;",
                           "const r = (a + b) / c;",
                           "const r = arr[0] / 2;",
                           "const r = 'x'.length / 2;"):
            source = expression + " foo(bar);"
            tokens = tokenize(source)
            self.assertEqual([], [t for t in tokens if t.kind == "regex"],
                             f"a regex was read out of: {expression}")
            self.assertIn("foo", [t.text for t in tokens], expression)

    def test_a_nested_template_literal_closes_correctly(self):
        tokens = tokenize("const s = `a ${ `b ${c}` } d`; call(x);")
        self.assertIn("call", [t.text for t in tokens])

    def test_a_comment_containing_a_quote_does_not_open_a_string(self):
        tokens = tokenize("// it's fine\ncall(x);")
        self.assertIn("call", [t.text for t in tokens])

    def test_an_unterminated_string_is_reported_not_guessed(self):
        with self.assertRaises(UnreadableSource):
            tokenize("const a = 'oops\nconst b = 2;")

    def test_an_unterminated_template_is_reported(self):
        with self.assertRaises(UnreadableSource):
            tokenize("const a = `oops;")

    def test_an_unterminated_block_comment_is_reported(self):
        with self.assertRaises(UnreadableSource):
            tokenize("/* forever\ncall(x);")


class TestImports(unittest.TestCase):
    def test_default_named_and_namespace_imports(self):
        module = analyse(
            "import Stripe from 'stripe';\n"
            "import { Resend } from 'resend';\n"
            "import * as fs from 'node:fs';\n")
        self.assertEqual("stripe", module.imports["Stripe"])
        self.assertEqual("resend", module.imports["Resend"])
        self.assertEqual("node:fs", module.imports["fs"])

    def test_an_aliased_import_records_the_LOCAL_name(self):
        module = analyse("import { Resend as Mailer } from 'resend';")
        self.assertEqual({"Mailer": "resend"}, module.imports)

    def test_require_is_an_import(self):
        module = analyse("const Stripe = require('stripe');")
        self.assertEqual("stripe", module.imports["Stripe"])

    def test_import_meta_is_not_an_import_declaration(self):
        """`import.meta.env` and `import('x')` are not declarations. Walking
        forward from them to the next string harvested whatever was nearby: a
        base URL and five Stripe price placeholders were recorded as modules."""
        module = analyse(
            "const url = import.meta.env.PUBLIC_BASE_URL || 'https://x.app';\n"
            "const KEY = import.meta.env.PRICE || 'price_placeholder';\n")
        self.assertEqual({}, module.imports)


class TestCallSites(unittest.TestCase):
    SOURCE = (
        "import Stripe from 'stripe';\n"
        "const stripe = new Stripe(key, { apiVersion: '2025-01-27.acacia' });\n"
        "const session = await stripe.checkout.sessions.create({\n"
        "  customer: id, mode: 'subscription', line_items: items,\n"
        "});\n"
        "console.log(session.payment_intent);\n"
    )

    def test_a_member_chain_call_is_found_whole(self):
        module = analyse(self.SOURCE)
        chains = {".".join(c.chain) for c in module.calls}
        self.assertIn("stripe.checkout.sessions.create", chains)

    def test_the_constructor_binding_is_recorded(self):
        module = analyse(self.SOURCE)
        self.assertEqual("Stripe", module.constructed["stripe"])

    def test_object_argument_keys_are_what_the_caller_SENDS(self):
        module = analyse(self.SOURCE)
        call = next(c for c in module.calls
                    if c.chain == ("stripe", "checkout", "sessions", "create"))
        self.assertEqual({"customer", "mode", "line_items"}, set(call.arg_keys))

    def test_an_awaited_call_is_still_bound_to_its_variable(self):
        """`await` sits between the `=` and the call in nearly all real code.
        Without stepping over it every awaited call came back unbound, and no
        read could be traced to the call that produced it."""
        module = analyse(self.SOURCE)
        call = next(c for c in module.calls
                    if c.chain == ("stripe", "checkout", "sessions", "create"))
        self.assertEqual("session", call.assigned_to)

    def test_a_property_read_is_recorded_against_its_base(self):
        module = analyse(self.SOURCE)
        reads = {(r.base, r.path) for r in module.reads}
        self.assertIn(("session", ("payment_intent",)), reads)

    def test_a_call_is_not_also_recorded_as_a_read(self):
        module = analyse("const x = client.things.list();")
        self.assertEqual([], [r for r in module.reads if r.base == "client"])

    def test_optional_chaining_reads_are_found(self):
        module = analyse("const v = resp?.data?.card?.iin;")
        reads = {(r.base, r.path) for r in module.reads}
        self.assertIn(("resp", ("data", "card", "iin")), reads)


class TestVersionPins(unittest.TestCase):
    """An SDK constructed with an explicit API version is PINNED, and a caller
    on an older version is not affected by a change to the latest. Named as an
    open blind spot and never modelled; real code pins in exactly this spot."""

    def test_an_apiVersion_option_is_a_pin(self):
        module = analyse(
            "const stripe = new Stripe(k, { apiVersion: '2025-01-27.acacia' });")
        self.assertEqual([("Stripe", "2025-01-27.acacia", 1)], module.version_pins)

    def test_no_option_is_no_pin(self):
        module = analyse("const stripe = new Stripe(k);")
        self.assertEqual([], module.version_pins)


class TestRealWorldShapes(unittest.TestCase):
    def test_jsx_does_not_swallow_the_file(self):
        """A `/` after `<` must not open a regular expression that runs to the
        end of the file and hides every call in it."""
        module = analyse(
            "export const C = () => <div className='a'>hi</div>;\n"
            "const s = await stripe.customers.create({ email });\n")
        chains = {".".join(c.chain) for c in module.calls}
        self.assertIn("stripe.customers.create", chains)

    def test_a_fetch_url_is_kept_as_a_string_argument(self):
        module = analyse(
            "await fetch('https://api.resend.com/emails', "
            "{ method: 'POST', body: x });")
        call = next(c for c in module.calls if c.chain == ("fetch",))
        self.assertIn("https://api.resend.com/emails", call.arg_strings)
        self.assertIn("method", call.arg_keys)


if __name__ == "__main__":
    unittest.main()
