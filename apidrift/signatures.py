"""Turn a spec finding into the literal strings a customer's codebase contains.

This is what makes the diff actionable: a changelog says "Stripe removed
`/v1/charges`", a signature says "here is the exact ripgrep that finds every
repo about to break".
"""
from __future__ import annotations

import re
from typing import Iterable, List, Sequence

from .diff import Finding
from .vendors import Vendor

_PLACEHOLDER = re.compile(r"\{[^}]+\}")
_NON_WORD = re.compile(r"[^A-Za-z0-9]+")


def _snake(text: str) -> str:
    text = _NON_WORD.sub("_", text)
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return re.sub(r"_+", "_", text).strip("_").lower()


def _camel(text: str) -> str:
    parts = [p for p in _snake(text).split("_") if p]
    if not parts:
        return ""
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def _pascal(text: str) -> str:
    return "".join(p.capitalize() for p in _snake(text).split("_") if p)


def _strip_version(path: str, vendor: Vendor) -> str:
    for prefix in vendor.version_prefixes:
        if path.startswith(prefix):
            return path[len(prefix):] or "/"
    return path


def _resource_segments(path: str, vendor: Vendor) -> List[str]:
    stripped = _strip_version(path, vendor)
    segs = [s for s in stripped.split("/") if s and not s.startswith("{")]
    # Twilio paths end in `.json`
    return [s[:-5] if s.endswith(".json") else s for s in segs]


def _sdk_names(finding: Finding, vendor: Vendor) -> List[str]:
    segs = _resource_segments(finding.path, vendor)
    op_id = finding.operation_id or ""
    names: List[str] = []

    if vendor.sdk_style == "stripe" and segs:
        resource = segs[0]
        names += [
            f"stripe.{resource}.",                 # node / python v12+
            f"stripe.{_pascal(resource.rstrip('s'))}.",  # python legacy: stripe.Charge.
            f"Stripe::{_pascal(resource.rstrip('s'))}.",  # ruby
        ]
    elif vendor.sdk_style == "openai":
        chain = ".".join(_snake(s) for s in segs)
        if chain:
            names += [f"client.{chain}.", f"openai.{chain}.", f".{chain}.create"]
        if op_id:
            names.append(_pascal(op_id.replace("create", "", 1)))
    elif vendor.sdk_style == "plaid":
        if op_id:
            names += [f"{_snake(op_id)}(", f"{_camel(op_id)}("]
        if segs:
            names.append(f"{_snake('_'.join(segs))}(")
    elif vendor.sdk_style == "twilio":
        if segs:
            names += [f"client.{_snake(segs[-1])}", f".{_camel(segs[-1])}("]
    elif segs:
        names.append(f"{_snake(segs[-1])}(")

    if op_id:
        names += [op_id, _snake(op_id), _camel(op_id)]
    return names


def build_signatures(finding: Finding, vendor: Vendor) -> List[str]:
    """Ordered, de-duplicated list of literals to search customer code for."""
    sigs: List[str] = []

    raw = finding.path
    if raw and raw != "/":
        sigs.append(raw)
        stripped = _strip_version(raw, vendor)
        if stripped != raw:
            sigs.append(stripped)
        # A templated path is never written literally; the static prefix is.
        if "{" in raw:
            prefix = raw.split("{", 1)[0].rstrip("/")
            if prefix and prefix not in sigs:
                sigs.append(prefix)

    sigs.extend(_sdk_names(finding, vendor))

    # Param/field-level findings: the identifier itself is the strongest signal.
    field_kinds = (
        "param_removed", "param_now_required", "param_type_changed",
        "param_added_required", "param_deprecated",
        "request_enum_value_removed", "response_enum_value_removed",
        "response_enum_value_added",
        "request_field_removed", "response_field_removed",
        "request_field_type_changed", "response_field_type_changed",
        "request_field_now_required", "request_field_added_required",
        "response_field_now_nullable",
    )
    if finding.kind in field_kinds and finding.subject:
        leaf = finding.subject.split(".")[-1].replace("[]", "")
        if leaf and not leaf.startswith("<"):
            sigs += [f'"{leaf}"', f"'{leaf}'", f"{leaf}="]

    seen, out = set(), []
    for s in sigs:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _rg_escape(text: str) -> str:
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", text)


def build_grep(signatures: Sequence[str], limit: int = 4) -> str:
    picked = [s for s in signatures if len(s) > 3][:limit]
    if not picked:
        return ""
    pattern = "|".join(_rg_escape(s) for s in picked)
    return f"rg -n --hidden -g '!node_modules' -e '{pattern}'"


def build_github_search(signatures: Sequence[str], vendor: Vendor) -> str:
    for sig in signatures:
        if len(sig) > 6 and " " not in sig:
            langs = " ".join(f"language:{lang}" for lang in vendor.languages[:3])
            return f'https://github.com/search?type=code&q={_quote(sig)}+{_quote(langs)}'
    return ""


def _quote(text: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(text)


def annotate(findings: Iterable[Finding], vendor: Vendor) -> None:
    """Attach signatures / grep / code-search URL to each finding in place."""
    for finding in findings:
        finding.signatures = build_signatures(finding, vendor)
        finding.grep = build_grep(finding.signatures)
        finding.github_search = build_github_search(finding.signatures, vendor)
