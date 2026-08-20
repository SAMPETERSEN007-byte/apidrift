"""Classify a verified lead by who actually owns the breaking code.

A verified call site is not automatically an outreach target. Three kinds of
repository show up in the results and they are not interchangeable:

  * the vendor's own repos -- their SDK, their samples, their test fixtures.
    Telling Stripe that `stripe/stripe-python` calls Stripe is noise.
  * ecosystem repos -- third-party SDKs, wrappers, proxies and mock servers.
    These are the highest-leverage contacts, because everything downstream of
    them breaks too, but they are a different conversation than a customer.
  * integrators -- an application calling the API to do its job. The customer.

Mirrors and dataset dumps are excluded outright: they contain a copy of someone
else's code and represent nobody.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VENDOR_OWNED = "vendor_owned"
ECOSYSTEM = "ecosystem"
INTEGRATOR = "integrator"
CORPUS = "corpus"

# GitHub orgs each vendor controls. A hit here is the vendor's own code.
VENDOR_ORGS: Dict[str, Tuple[str, ...]] = {
    "stripe": ("stripe", "stripe-samples", "stripe-archive"),
    "openai": ("openai", "openai-labs"),
    "twilio": ("twilio", "twilio-labs", "twilio-samples"),
    "plaid": ("plaid",),
    "discord": ("discord", "discordapp", "discord-net"),
}

# Repos that are a copy of the world rather than a participant in it.
_CORPUS_PATTERNS = (
    r"top-pypi", r"sdists", r"pypi-mirror", r"\bmirror\b", r"^awesome-",
    r"allpythoncontent", r"pyreco", r"-dataset$", r"^dataset-", r"code-corpus",
    r"the-stack", r"github-crawl",
)

# Names that mark a third-party SDK, wrapper, proxy or test double.
_ECOSYSTEM_PATTERNS = (
    r"\.py$", r"\.js$", r"\.http$", r"-sdk$", r"^sdk-", r"-client$", r"^client-",
    r"-wrapper$", r"-api$", r"^api-", r"-mock$", r"^mock-", r"local[a-z]+$",
    r"-proxy$", r"^proxy-", r"-bindings$", r"litellm", r"aisuite",
)

# Well-known ecosystem projects whose names give nothing away.
_KNOWN_ECOSYSTEM = frozenset({
    "disnake", "pycord", "nextcord", "hikari", "interactions.py", "discord.py",
    "epikcord.py", "discord.http", "litellm", "aisuite", "localstripe",
    "openworker", "uni-api", "agents", "dspy", "langchain", "llamaindex",
})


@dataclass
class Classification:
    kind: str
    reason: str

    @property
    def is_outreach_target(self) -> bool:
        return self.kind in (ECOSYSTEM, INTEGRATOR)


def _matches(patterns: Tuple[str, ...], text: str) -> Optional[str]:
    for pattern in patterns:
        if re.search(pattern, text, re.I):
            return pattern
    return None


def classify(repo: str, vendor_key: str) -> Classification:
    """`repo` is an `owner/name` slug."""
    owner, _, name = repo.partition("/")
    owner_l, name_l = owner.lower(), name.lower()

    if owner_l in VENDOR_ORGS.get(vendor_key, ()):
        return Classification(VENDOR_OWNED, f"`{owner}` is a {vendor_key} org")

    hit = _matches(_CORPUS_PATTERNS, name_l)
    if hit:
        return Classification(CORPUS, f"name matches corpus pattern /{hit}/")

    if name_l in _KNOWN_ECOSYSTEM:
        return Classification(ECOSYSTEM, "known third-party SDK or wrapper")

    hit = _matches(_ECOSYSTEM_PATTERNS, name_l)
    if hit:
        return Classification(ECOSYSTEM, f"name matches SDK pattern /{hit}/")

    return Classification(INTEGRATOR, "application code calling the API")


def partition(leads: List[dict], vendor_key: str) -> Dict[str, List[dict]]:
    """Split leads into buckets, annotating each with why it landed there."""
    buckets: Dict[str, List[dict]] = {
        INTEGRATOR: [], ECOSYSTEM: [], VENDOR_OWNED: [], CORPUS: [],
    }
    for lead in leads:
        result = classify(lead["repo"], vendor_key)
        enriched = dict(lead)
        enriched["lead_kind"] = result.kind
        enriched["lead_reason"] = result.reason
        buckets[result.kind].append(enriched)
    return buckets


def dedupe_by_repo(leads: List[dict]) -> List[dict]:
    """One row per repository -- the strongest site stands for the repo."""
    best: Dict[str, dict] = {}
    for lead in leads:
        existing = best.get(lead["repo"])
        if existing is None or len(lead.get("sites") or []) > len(existing.get("sites") or []):
            best[lead["repo"]] = lead
    return sorted(best.values(), key=lambda l: l["repo"].lower())
