"""Read JavaScript and TypeScript well enough to prove dependence in it.

Dependence was provable in Python only, and that is not a footnote -- it is the
product. Measured on eight real repositories: the only files that call a
tracked vendor are TypeScript, so the tool's entire output was an apology. A
scan that says "8 files call these APIs in a language this tool cannot parse"
is honest and worth nothing.

This is a tokeniser plus a targeted extractor, not a parser. Proving dependence
needs five things and no more:

  * what a module was imported AS            `import Stripe from 'stripe'`
  * what a constructor was bound TO          `const stripe = new Stripe(key)`
  * member chains that are CALLED            `stripe.checkout.sessions.create({...})`
  * the KEYS of an object argument           what the caller SENDS
  * property reads off a call's result       what the caller READS

Everything else in the language is skipped on purpose. The failure mode that
matters is not missing a construct; it is mis-reading one and reporting a call
site that is not there. So the tokeniser reports UNTERMINATED state -- a string,
template, comment or regular expression that never closes -- and a file in that
state is UNMEASURED, never clean. A file this cannot read is a file it says it
cannot read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------

NAME, NUMBER, STRING, TEMPLATE, REGEX, PUNCT, KEYWORD = (
    "name", "number", "string", "template", "regex", "punct", "keyword")

KEYWORDS = frozenset("""
await break case catch class const continue debugger default delete do else
enum export extends false finally for function if implements import in
instanceof interface let new null package private protected public return
static super switch this throw true try type typeof var void while with yield
as from of satisfies keyof readonly declare namespace abstract asserts infer is
""".split())

# A `/` is a regular expression when an expression cannot continue, and a
# division sign when it can. The distinction is decided by the token before it:
# after a value you divide, after an operator or `(` you match.
_VALUE_ENDERS = frozenset({")", "]", "}", "++", "--"})
_REGEX_OK_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
    "throw", "case", "do", "else", "yield", "await"})

_PUNCTUATION = sorted(
    ["...", "===", "!==", "**=", "<<=", ">>=", ">>>", "&&=", "||=", "??=",
     "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=",
     "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>", "</", "/>",
     "{", "}", "(", ")", "[", "]", ";", ",", "<", ">", "+", "-", "*", "/",
     "%", "&", "|", "^", "!", "~", "?", ":", "=", ".", "@", "#"],
    key=len, reverse=True)

_NAME_START = re.compile(r"[A-Za-z_$]")
_NAME_BODY = re.compile(r"[A-Za-z0-9_$]*")
_NUMBER = re.compile(r"(?:0[xXbBoO][0-9a-fA-F_]+|[0-9][0-9_]*(?:\.[0-9_]*)?"
                     r"(?:[eE][+-]?[0-9]+)?|\.[0-9][0-9_]*)n?")


class UnreadableSource(RuntimeError):
    """The tokeniser reached the end of the file inside something unclosed.

    Raised rather than papered over: a half-read file yields call sites that do
    not exist, and a fabricated call site is worse than a missing one.
    """


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int


def tokenize(source: str) -> List[Token]:
    out: List[Token] = []
    index, line, size = 0, 1, len(source)
    last_significant: Optional[Token] = None

    def regex_allowed() -> bool:
        if last_significant is None:
            return True
        if last_significant.kind in (NUMBER, STRING, TEMPLATE, REGEX):
            return False
        if last_significant.kind == NAME:
            return False
        if last_significant.kind == KEYWORD:
            return last_significant.text in _REGEX_OK_KEYWORDS
        return last_significant.text not in _VALUE_ENDERS

    while index < size:
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in " \t\r\f\v ﻿":
            index += 1
            continue
        # comments
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = size if end < 0 else end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise UnreadableSource(f"unterminated block comment at line {line}")
            line += source.count("\n", index, end)
            index = end + 2
            continue
        # strings
        if char in "\"'":
            index, line, text = _read_string(source, index, line, char)
            token = Token(STRING, text, line)
            out.append(token)
            last_significant = token
            continue
        if char == "`":
            start_line = line
            index, line, text = _read_template(source, index, line)
            token = Token(TEMPLATE, text, start_line)
            out.append(token)
            last_significant = token
            continue
        if char == "<" and regex_allowed() and _jsx_starts_here(source, index):
            # JSX. Its TEXT children are prose, not code: `We've just migrated`
            # opens a string that never closes, and the tokeniser correctly
            # reported the file unreadable -- correctly, and uselessly, because
            # React components are exactly the TypeScript that calls these APIs.
            #
            # `regex_allowed()` is the discriminator, and it is the right one:
            # JSX only appears where an expression may START (`return <div>`,
            # `= <div>`, `(<div>`), while a comparison or a generic
            # (`a < b`, `Array<string>`) only appears after a value, where it
            # is False. Nothing else in the language is `<` in that position.
            index, line = _skip_jsx(source, index, line, out)
            last_significant = out[-1] if out else last_significant
            continue
        if char == "/" and regex_allowed():
            try:
                index, text = _read_regex(source, index)
            except UnreadableSource:
                raise
            token = Token(REGEX, text, line)
            out.append(token)
            last_significant = token
            continue
        if _NAME_START.match(char):
            match = _NAME_BODY.match(source, index + 1)
            word = char + (match.group(0) if match else "")
            index += len(word)
            token = Token(KEYWORD if word in KEYWORDS else NAME, word, line)
            out.append(token)
            last_significant = token
            continue
        number = _NUMBER.match(source, index)
        if number and char.isdigit() or (char == "." and number):
            index += len(number.group(0))
            token = Token(NUMBER, number.group(0), line)
            out.append(token)
            last_significant = token
            continue
        for symbol in _PUNCTUATION:
            if source.startswith(symbol, index):
                index += len(symbol)
                token = Token(PUNCT, symbol, line)
                out.append(token)
                last_significant = token
                break
        else:
            index += 1          # a character this does not model; skip it
    return out


_JSX_TAG_START = re.compile(r"<\s*(?:>|[A-Za-z_$][A-Za-z0-9_$.:-]*)")


def _jsx_starts_here(source: str, index: int) -> bool:
    """Is this `<` opening a JSX element rather than a comparison?

    Requires a tag name or a fragment immediately after it. `< 5` is not JSX.
    """
    return bool(_JSX_TAG_START.match(source, index))


def _skip_jsx(source: str, index: int, line: int,
              out: List[Token]) -> Tuple[int, int]:
    """Consume a JSX element, tokenising only the CODE inside it.

    Attribute values and `{...}` children are real expressions and are handed
    back to the tokeniser; tag names and text children are skipped. Depth is
    tracked so nested elements close correctly, and an element that never
    closes still raises rather than silently ending the file early.
    """
    depth = 0
    size = len(source)
    while index < size:
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if source.startswith("</", index):
            end = source.find(">", index)
            if end < 0:
                raise UnreadableSource(f"unterminated JSX element at line {line}")
            line += source.count("\n", index, end)
            index = end + 1
            depth -= 1
            if depth <= 0:
                return index, line
            continue
        if char == "<" and _jsx_starts_here(source, index):
            index, line, self_closing = _skip_jsx_tag(source, index, line, out)
            if not self_closing:
                depth += 1
            elif depth == 0:
                return index, line
            continue
        if char == "{":
            index, line = _tokenize_embedded(source, index, line, out)
            continue
        index += 1          # text child: prose, not code
    raise UnreadableSource(f"unterminated JSX element at line {line}")


def _skip_jsx_tag(source: str, index: int, line: int,
                  out: List[Token]) -> Tuple[int, int, bool]:
    """Consume `<Tag attr="x" other={expr}>`. Returns (index, line, self_closing)."""
    index += 1
    size = len(source)
    while index < size:
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in "\"'":
            index, line, _ = _read_string(source, index, line, char)
            continue
        if char == "{":
            index, line = _tokenize_embedded(source, index, line, out)
            continue
        if source.startswith("/>", index):
            return index + 2, line, True
        if char == ">":
            return index + 1, line, False
        index += 1
    raise UnreadableSource(f"unterminated JSX tag at line {line}")


def _tokenize_embedded(source: str, index: int, line: int,
                       out: List[Token]) -> Tuple[int, int]:
    """A `{...}` expression inside JSX: real code, tokenised as such."""
    depth = 0
    start = index
    size = len(source)
    while index < size:
        char = source[index]
        if char == "\n":
            line += 1
        elif char in "\"'":
            index, line, _ = _read_string(source, index, line, char, strict=False)
            continue
        elif char == "`":
            index, line, _ = _read_template(source, index, line)
            continue
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                inner = source[start + 1:index]
                # Line numbers inside the expression are relative to the
                # expression, so they are re-based onto the file.
                base = line - inner.count("\n")
                for token in tokenize(inner):
                    out.append(Token(token.kind, token.text,
                                     token.line + base - 1))
                return index + 1, line
        index += 1
    raise UnreadableSource(f"unterminated JSX expression at line {line}")


def _read_string(source: str, index: int, line: int, quote: str,
                 strict: bool = True) -> Tuple[int, int, str]:
    start = index
    index += 1
    chunks: List[str] = []
    while index < len(source):
        char = source[index]
        if char == "\\":
            chunks.append(source[index:index + 2])
            index += 2
            continue
        if char == quote:
            return index + 1, line, "".join(chunks)
        if char == "\n":
            # A newline inside a normal string is a syntax error in JS; treat
            # it as unreadable rather than guessing where the string ended.
            #
            # Except when only SCANNING for a matching brace. JSX text is
            # prose -- `We've just migrated` -- and every apostrophe in it
            # looks like a quote to a scanner that is not parsing. The
            # guarantee is not weakened by this: the recursive tokenise of the
            # same region is strict and still raises, so an actually
            # unterminated string inside the expression is still caught. This
            # only stops the SCANNER mistaking an apostrophe for one.
            if strict:
                raise UnreadableSource(f"unterminated string at line {line}")
            return start + 1, line, ""
        chunks.append(char)
        index += 1
    if strict:
        raise UnreadableSource(f"unterminated string at line {line}")
    return start + 1, line, ""


def _read_template(source: str, index: int, line: int) -> Tuple[int, int, str]:
    """Template literals nest: `${ `inner` }` is legal and common."""
    index += 1
    depth = 0
    chunks: List[str] = []
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n":
            line += 1
            index += 1
            continue
        if depth == 0 and char == "`":
            return index + 1, line, "".join(chunks)
        if depth == 0 and source.startswith("${", index):
            depth += 1
            index += 2
            continue
        if depth:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            elif char == "`":
                index, line, _ = _read_template(source, index, line)
                continue
            index += 1
            continue
        chunks.append(char)
        index += 1
    raise UnreadableSource(f"unterminated template literal at line {line}")


def _read_regex(source: str, index: int) -> Tuple[int, str]:
    start = index
    index += 1
    in_class = False
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "\n":
            raise UnreadableSource("unterminated regular expression")
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(source) and source[index].isalpha():
                index += 1
            return index, source[start:index]
        index += 1
    raise UnreadableSource("unterminated regular expression")


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

@dataclass
class CallSite:
    """A member chain that is being CALLED, with what was passed to it."""
    chain: Tuple[str, ...]
    line: int
    arg_keys: Tuple[str, ...] = ()          # keys of an object literal argument
    arg_strings: Tuple[str, ...] = ()       # string literals passed
    assigned_to: str = ""                   # `const x = ...`


@dataclass
class Read:
    base: str
    path: Tuple[str, ...]
    line: int


@dataclass
class Module:
    imports: Dict[str, str] = field(default_factory=dict)      # local -> module
    constructed: Dict[str, str] = field(default_factory=dict)  # var -> class
    calls: List[CallSite] = field(default_factory=list)
    reads: List[Read] = field(default_factory=list)
    version_pins: List[Tuple[str, str, int]] = field(default_factory=list)

    def modules(self) -> Set[str]:
        return set(self.imports.values())


_VERSION_KEYS = frozenset({"apiVersion", "api_version", "Stripe-Version",
                           "version", "anthropic-version"})


def _chain_before(tokens: Sequence[Token], index: int) -> Tuple[Tuple[str, ...], int]:
    """Walk backwards from a `(` collecting `a.b.c`. Returns (chain, start)."""
    parts: List[str] = []
    position = index
    while position >= 0:
        token = tokens[position]
        if token.kind in (NAME, KEYWORD) and (
                not parts or tokens[position + 1].text in (".", "?.")):
            parts.append(token.text)
            position -= 1
            if position >= 0 and tokens[position].text in (".", "?."):
                position -= 1
                continue
            break
        break
    parts.reverse()
    return tuple(parts), position


def _object_keys(tokens: Sequence[Token], index: int,
                 key_depth: int = 2) -> Tuple[Tuple[str, ...], int]:
    """Keys of the object literals passed inside the call starting at `(`.

    `key_depth` is 2 because the scan starts on the opening PAREN: the object
    literal's own braces are the second level. Reading keys at depth 1 finds
    nothing at all, which is what it did -- every `arg_keys` came back empty
    and with it every request-side direction check.
    """
    keys: List[str] = []
    depth = 0
    position = index
    while position < len(tokens):
        text = tokens[position].text
        if text in ("{", "[", "("):
            depth += 1
        elif text in ("}", "]", ")"):
            depth -= 1
            if depth == 0:
                return tuple(keys), position
        elif depth == key_depth and tokens[position].kind in (NAME, STRING, KEYWORD):
            following = tokens[position + 1] if position + 1 < len(tokens) else None
            if following is not None and following.text == ":":
                keys.append(tokens[position].text)
        position += 1
    return tuple(keys), position


def analyse(source: str) -> Module:
    """Extract the five things a dependence proof needs. Raises on unreadable."""
    tokens = tokenize(source)
    module = Module()
    total = len(tokens)

    for index, token in enumerate(tokens):
        text = token.text
        # ---- imports -------------------------------------------------------
        if token.kind == KEYWORD and text == "import":
            following = tokens[index + 1].text if index + 1 < total else ""
            # `import.meta.env` and `import('x')` are not import DECLARATIONS.
            # Walking forward from them to the next string literal harvested
            # whatever happened to be nearby: a base URL and five Stripe price
            # placeholders were recorded as imported modules.
            if following in (".", "("):
                continue
            _collect_import(tokens, index, module)
            continue
        if token.kind == NAME and text == "require" and index + 2 < total \
                and tokens[index + 1].text == "(" \
                and tokens[index + 2].kind == STRING:
            target = _binding_before(tokens, index)
            if target:
                module.imports[target] = tokens[index + 2].text
            continue
        # ---- construction --------------------------------------------------
        if token.kind == KEYWORD and text == "new" and index + 1 < total \
                and tokens[index + 1].kind == NAME:
            target = _binding_before(tokens, index)
            if target:
                module.constructed[target] = tokens[index + 1].text
            if index + 2 < total and tokens[index + 2].text == "(":
                keys, _ = _object_keys(tokens, index + 2)
                _record_pins(tokens, index + 2, keys, tokens[index + 1].text, module)
            continue
            continue
        # ---- calls ---------------------------------------------------------
        if text == "(" and index > 0 and tokens[index - 1].kind in (NAME, KEYWORD):
            chain, _ = _chain_before(tokens, index - 1)
            if len(chain) < 1:
                continue
            keys, end = _object_keys(tokens, index)
            strings = tuple(
                t.text for t in tokens[index:min(end + 1, total)] if t.kind == STRING)
            module.calls.append(CallSite(
                chain=chain, line=token.line, arg_keys=keys,
                arg_strings=strings,
                assigned_to=_binding_before(tokens, index - (2 * len(chain) - 1)),
            ))
            continue
        # ---- property reads -------------------------------------------------
        if text in (".", "?.") and index > 0 and index + 1 < total \
                and tokens[index - 1].kind == NAME \
                and tokens[index + 1].kind == NAME:
            following = tokens[index + 2].text if index + 2 < total else ""
            if following == "(":
                continue          # that is a call, recorded above
            path: List[str] = [tokens[index + 1].text]
            position = index + 2
            is_call = False
            while position + 1 < total and tokens[position].text in (".", "?.") \
                    and tokens[position + 1].kind == NAME:
                if position + 2 < total and tokens[position + 2].text == "(":
                    # `client.things.list()` -- the whole chain is a CALL, and
                    # `things` is a segment of it, not something read off
                    # `client`. Recording the truncated prefix as a read
                    # invents a field access that never happens, which is the
                    # one thing this reader must not do.
                    is_call = True
                    break
                path.append(tokens[position + 1].text)
                position += 2
            if not is_call:
                module.reads.append(
                    Read(base=tokens[index - 1].text, path=tuple(path),
                         line=token.line))
    return module


def _collect_import(tokens: Sequence[Token], index: int, module: Module) -> None:
    """`import X from 'm'`, `import {A as B} from 'm'`, `import * as N from 'm'`."""
    names: List[str] = []
    position = index + 1
    source_module = ""
    while position < len(tokens):
        token = tokens[position]
        if token.kind == STRING:
            source_module = token.text
            break
        if token.text == ";":
            break
        if token.kind == NAME:
            after = tokens[position + 1].text if position + 1 < len(tokens) else ""
            if after == "as" or (position > index + 1
                                 and tokens[position - 1].text == "as"):
                if tokens[position - 1].text == "as":
                    names.append(token.text)
            else:
                names.append(token.text)
        position += 1
    if not source_module:
        return
    for name in names:
        module.imports[name] = source_module


def _binding_before(tokens: Sequence[Token], index: int) -> str:
    """`const NAME = <here>` -- the variable this expression is bound to.

    `await` sits between the `=` and the expression in most real code
    (`const session = await stripe.checkout.sessions.create(...)`), so it is
    stepped over; without that every awaited call -- which is nearly all of
    them -- came back unbound and no read could be traced to its source.
    """
    position = index - 1
    while position >= 0 and tokens[position].kind == KEYWORD \
            and tokens[position].text == "await":
        position -= 1
    if position >= 1 and tokens[position].text == "=" \
            and tokens[position - 1].kind == NAME:
        return tokens[position - 1].text
    return ""


def _record_pins(tokens: Sequence[Token], index: int, keys: Sequence[str],
                 class_name: str, module: Module) -> None:
    """An SDK constructed with an explicit API version is PINNED.

    Not modelled anywhere until now, and named as an open blind spot: a caller
    on an older Stripe version is not affected by a change to the latest, and
    real code pins in exactly this position --
    `new Stripe(key, { apiVersion: '2025-01-27.acacia' })`.
    """
    if not any(key in _VERSION_KEYS for key in keys):
        return
    depth, position = 0, index
    while position < len(tokens):
        text = tokens[position].text
        if text in ("{", "[", "("):
            depth += 1
        elif text in ("}", "]", ")"):
            depth -= 1
            if depth == 0:
                return
        elif tokens[position].text in _VERSION_KEYS and position + 2 < len(tokens) \
                and tokens[position + 1].text == ":" \
                and tokens[position + 2].kind == STRING:
            module.version_pins.append(
                (class_name, tokens[position + 2].text, tokens[position].line))
        position += 1
