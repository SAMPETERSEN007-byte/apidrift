"""Registry of API vendors whose OpenAPI spec is published in a public git repo."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class Vendor:
    key: str
    name: str
    repo: str                  # github org/name
    spec_path: str             # glob matched against the repo tree (fnmatch)
    docs_url: str
    # Language ecosystems whose SDKs wrap this API, used for code-search queries.
    languages: Tuple[str, ...] = ("python", "javascript", "typescript", "go", "ruby")
    # Path prefix stripped before deriving SDK-style call names.
    version_prefixes: Tuple[str, ...] = ()
    sdk_style: str = "generic"  # generic | stripe | openai | plaid | twilio | discord


VENDORS: Dict[str, Vendor] = {
    "stripe": Vendor(
        key="stripe",
        name="Stripe",
        repo="stripe/openapi",
        spec_path="openapi/spec3.json",
        docs_url="https://docs.stripe.com/api",
        version_prefixes=("/v1", "/v2"),
        sdk_style="stripe",
    ),
    "openai": Vendor(
        key="openai",
        name="OpenAI",
        repo="openai/openai-openapi",
        spec_path="openapi.yaml",
        docs_url="https://platform.openai.com/docs/api-reference",
        version_prefixes=("/v1",),
        sdk_style="openai",
    ),
    "twilio": Vendor(
        key="twilio",
        name="Twilio (all products)",
        repo="twilio/twilio-oai",
        spec_path="spec/json/twilio_*.json",
        docs_url="https://www.twilio.com/docs/usage/api",
        version_prefixes=("/2010-04-01",),
        sdk_style="twilio",
    ),
    "plaid": Vendor(
        key="plaid",
        name="Plaid",
        repo="plaid/plaid-openapi",
        spec_path="2020-09-14.yml",
        docs_url="https://plaid.com/docs/api",
        sdk_style="plaid",
    ),
    "discord": Vendor(
        key="discord",
        name="Discord",
        repo="discord/discord-api-spec",
        spec_path="specs/openapi.json",
        docs_url="https://discord.com/developers/docs",
        version_prefixes=("/v10", "/v9"),
        sdk_style="discord",
    ),
}

DEFAULT_VENDORS: List[str] = ["stripe", "openai", "twilio", "plaid", "discord"]


def get(key: str) -> Vendor:
    try:
        return VENDORS[key]
    except KeyError:
        raise SystemExit(
            f"unknown vendor '{key}'. known: {', '.join(sorted(VENDORS))}"
        ) from None
