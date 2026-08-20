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
    # Literals that tie a source file to THIS vendor's API. Without one of
    # these, a matching symbol is a coincidence, not a customer.
    evidence: Tuple[str, ...] = ()


VENDORS: Dict[str, Vendor] = {
    # ---------------------------------------------------------------------
    # Added 2026-08-20 after surveying 42 paid API vendors. These need only a
    # repo and a path: 41 of 42 publish a machine-readable spec and the tool
    # was reading 5 of them.
    #
    # `evidence` is the precision-critical field, not `repo`. Without a marker
    # tying a file to THIS vendor, a matching path is a coincidence. Keep them
    # specific: `github.` matches everything, `api.github.com` does not.
    # ---------------------------------------------------------------------
    "square": Vendor(
        key="square", name="Square", repo="square/connect-api-specification",
        spec_path="api.json", docs_url="https://developer.squareup.com/reference/square",
        version_prefixes=("/v2",),
        evidence=("import square", "from square", "require('square')", 'require("square")',
                  "connect.squareup.com", "squareup.com", "SQUARE_ACCESS_TOKEN"),
    ),
    "paypal": Vendor(
        key="paypal", name="PayPal", repo="paypal/paypal-rest-api-specifications",
        spec_path="openapi/*.json", docs_url="https://developer.paypal.com/api/rest/",
        version_prefixes=("/v1", "/v2", "/v3"),
        evidence=("paypalrestsdk", "from paypal", "import paypal",
                  "api-m.paypal.com", "api.paypal.com", "PAYPAL_CLIENT_ID",
                  "PAYPAL_SECRET"),
    ),
    "sendgrid": Vendor(
        key="sendgrid", name="SendGrid", repo="twilio/sendgrid-oai",
        spec_path="spec/json/tsg_*_v3.json", docs_url="https://www.twilio.com/docs/sendgrid/api-reference",
        version_prefixes=("/v3",),
        evidence=("import sendgrid", "from sendgrid", "require('@sendgrid",
                  'require("@sendgrid', "api.sendgrid.com", "SENDGRID_API_KEY"),
    ),
    "resend": Vendor(
        key="resend", name="Resend", repo="resend/resend-openapi",
        spec_path="resend.json", docs_url="https://resend.com/docs/api-reference",
        evidence=("import resend", "from resend", "require('resend')",
                  'require("resend")', "api.resend.com", "RESEND_API_KEY"),
    ),
    "cohere": Vendor(
        key="cohere", name="Cohere", repo="cohere-ai/cohere-developer-experience",
        spec_path="cohere-openapi.yaml", docs_url="https://docs.cohere.com/reference/about",
        version_prefixes=("/v1", "/v2"),
        evidence=("import cohere", "from cohere", "require('cohere-ai')",
                  'require("cohere-ai")', "api.cohere.com", "api.cohere.ai",
                  "COHERE_API_KEY"),
    ),
    "mistral": Vendor(
        key="mistral", name="Mistral", repo="mistralai/platform-docs-public",
        spec_path="openapi-public-doc.yaml", docs_url="https://docs.mistral.ai/api/",
        version_prefixes=("/v1",),
        evidence=("mistralai", "from mistral", "api.mistral.ai", "MISTRAL_API_KEY"),
    ),
    "klaviyo": Vendor(
        key="klaviyo", name="Klaviyo", repo="klaviyo/openapi",
        spec_path="openapi/stable.json", docs_url="https://developers.klaviyo.com/en/reference/api_overview",
        version_prefixes=("/api",),
        evidence=("import klaviyo", "from klaviyo", "klaviyo-api",
                  "a.klaviyo.com", "KLAVIYO_API_KEY", "KLAVIYO_PRIVATE_KEY"),
    ),
    "intercom": Vendor(
        key="intercom", name="Intercom", repo="intercom/Intercom-OpenAPI",
        # Pinned to one version on purpose: the repo carries 2.7 through 2.16
        # side by side, and globbing them would diff Intercom against itself.
        spec_path="descriptions/2.16/api.intercom.io.yaml",
        docs_url="https://developers.intercom.com/docs/references/rest-api/",
        evidence=("import intercom", "from intercom", "intercom-client",
                  "api.intercom.io", "INTERCOM_ACCESS_TOKEN", "INTERCOM_TOKEN"),
    ),
    "cloudflare": Vendor(
        key="cloudflare", name="Cloudflare", repo="cloudflare/api-schemas",
        spec_path="openapi.json", docs_url="https://developers.cloudflare.com/api/",
        version_prefixes=("/client/v4",),
        evidence=("import cloudflare", "from cloudflare", "require('cloudflare')",
                  'require("cloudflare")', "api.cloudflare.com",
                  "CLOUDFLARE_API_TOKEN", "CF_API_TOKEN"),
    ),
    "github": Vendor(
        key="github", name="GitHub", repo="github/rest-api-description",
        spec_path="descriptions/api.github.com/api.github.com.json",
        docs_url="https://docs.github.com/en/rest",
        evidence=("api.github.com", "from github import", "import PyGithub",
                  "@octokit", "GITHUB_TOKEN", "GH_TOKEN"),
    ),
    "vercel": Vendor(
        key="vercel", name="Vercel", repo="vercel/sdk",
        spec_path="vercel-spec.json", docs_url="https://vercel.com/docs/rest-api",
        version_prefixes=("/v1", "/v2", "/v6", "/v9", "/v13"),
        evidence=("api.vercel.com", "@vercel/sdk", "VERCEL_TOKEN",
                  "VERCEL_API_TOKEN"),
    ),
    "datadog": Vendor(
        key="datadog", name="Datadog", repo="DataDog/datadog-api-client-go",
        spec_path=".generator/schemas/v2/openapi.yaml",
        docs_url="https://docs.datadoghq.com/api/latest/",
        version_prefixes=("/api/v1", "/api/v2"),
        evidence=("import datadog", "from datadog", "datadog_api_client",
                  "api.datadoghq.com", "DD_API_KEY", "DATADOG_API_KEY"),
    ),
    "sentry": Vendor(
        key="sentry", name="Sentry", repo="getsentry/sentry-api-schema",
        spec_path="openapi-derefed.json", docs_url="https://docs.sentry.io/api/",
        version_prefixes=("/api/0",),
        evidence=("import sentry_sdk", "from sentry_sdk", "sentry.io/api",
                  "SENTRY_AUTH_TOKEN", "SENTRY_DSN"),
    ),
    "auth0": Vendor(
        key="auth0", name="Auth0", repo="auth0/docs-v2",
        spec_path="main/docs/oas/management/v2/management-api-oas.json",
        docs_url="https://auth0.com/docs/api/management/v2",
        version_prefixes=("/api/v2",),
        evidence=("import auth0", "from auth0", "auth0-python", "auth0.com/api",
                  "AUTH0_DOMAIN", "AUTH0_CLIENT_SECRET"),
    ),
    "modern_treasury": Vendor(
        key="modern_treasury", name="Modern Treasury",
        repo="Modern-Treasury/modern-treasury-openapi",
        spec_path="openapi/mt_openapi_spec_v1.yaml",
        docs_url="https://docs.moderntreasury.com/reference",
        version_prefixes=("/api",),
        evidence=("modern_treasury", "modern-treasury", "app.moderntreasury.com",
                  "MODERN_TREASURY_API_KEY"),
    ),
    "column": Vendor(
        key="column", name="Column", repo="column/openapi",
        spec_path="openapi.yaml", docs_url="https://column.com/docs/api",
        evidence=("api.column.com", "COLUMN_API_KEY"),
    ),
    "adyen": Vendor(
        key="adyen", name="Adyen", repo="Adyen/adyen-openapi",
        # 129 per-service, per-version files. A new API version arrives as a
        # NEW FILE, which is why spec_added exists.
        spec_path="json/*.json", docs_url="https://docs.adyen.com/api-explorer/",
        evidence=("import Adyen", "from Adyen", "@adyen/api-library",
                  "checkout-test.adyen.com", "adyen.com/v", "ADYEN_API_KEY"),
    ),

    "stripe": Vendor(
        key="stripe",
        name="Stripe",
        repo="stripe/openapi",
        spec_path="openapi/spec3.json",
        docs_url="https://docs.stripe.com/api",
        version_prefixes=("/v1", "/v2"),
        sdk_style="stripe",
        evidence=("import stripe", "from stripe", "require('stripe')", 'require("stripe")', "api.stripe.com", "STRIPE_SECRET", "STRIPE_API_KEY", "stripe."),
    ),
    "openai": Vendor(
        key="openai",
        name="OpenAI",
        repo="openai/openai-openapi",
        spec_path="openapi.yaml",
        docs_url="https://platform.openai.com/docs/api-reference",
        version_prefixes=("/v1",),
        sdk_style="openai",
        evidence=("import openai", "from openai", "require('openai')", 'require("openai")', "api.openai.com", "OPENAI_API_KEY", "openai."),
    ),
    "twilio": Vendor(
        key="twilio",
        name="Twilio (all products)",
        repo="twilio/twilio-oai",
        spec_path="spec/json/twilio_*.json",
        docs_url="https://www.twilio.com/docs/usage/api",
        version_prefixes=("/2010-04-01",),
        sdk_style="twilio",
        evidence=("import twilio", "from twilio", "require('twilio')", 'require("twilio")', "api.twilio.com", "TWILIO_AUTH_TOKEN", "TWILIO_ACCOUNT_SID"),
    ),
    "plaid": Vendor(
        key="plaid",
        name="Plaid",
        repo="plaid/plaid-openapi",
        spec_path="2020-09-14.yml",
        docs_url="https://plaid.com/docs/api",
        sdk_style="plaid",
        evidence=("import plaid", "from plaid", "require('plaid')", 'require("plaid")', "plaid.com", "PLAID_SECRET", "PLAID_CLIENT_ID"),
    ),
    "discord": Vendor(
        key="discord",
        name="Discord",
        repo="discord/discord-api-spec",
        spec_path="specs/openapi.json",
        docs_url="https://discord.com/developers/docs",
        version_prefixes=("/v10", "/v9"),
        sdk_style="discord",
        evidence=("import discord", "from discord", "require('discord", "discord.com/api", "DISCORD_TOKEN", "DISCORD_BOT_TOKEN", "discordapp.com/api"),
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
