"""Record a vendor's spec daily when they don't publish its history.

Two thirds of the paid API vendors surveyed keep their spec in a public git
repo, which hands you every past version for free. The other third publish a
perfectly good spec at a stable URL and no history at all. For those, the past
is not something you can fetch — it is something you must have been recording.

So this starts the clock. It is deliberately dumb: fetch, canonicalise, hash,
store only when the hash moved. The whole cohort is about 27 MB a day raw and
well under 250 MB in the first year once unchanged days dedupe away.

The failure mode that matters is not missing a fetch. It is storing something
that is not a spec and never noticing: four vendors in the survey return HTTP
200 with an HTML error page, and Salesforce serves a 12 KB 404 shell to the
wrong Referer. A status code is not evidence. Every snapshot is validated
before it is kept.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

UA = "apidrift-snapshotter/1.0 (+https://github.com/apidrift)"
TIMEOUT = 60
MAX_BYTES = 64 * 1024 * 1024


class SnapshotError(RuntimeError):
    pass


@dataclass(frozen=True)
class Source:
    """A spec that must be recorded because nobody else is recording it."""
    key: str
    name: str
    url: str
    fmt: str = "openapi"        # openapi | swagger2 | discovery | graphql
    note: str = ""


# Verified reachable 2026-08-20. Ordered by how fast they actually change, so
# the ones that pay off first are obvious.
SOURCES: Tuple[Source, ...] = (
    Source("increase", "Increase", "https://increase.com/openapi.json",
           note="regenerated sub-daily; first diff in 1-2 days"),
    Source("zendesk", "Zendesk Support", "https://developer.zendesk.com/zendesk/oas.yaml",
           note="sub-daily. YAML 1.2 - a bare `=` scalar breaks PyYAML SafeLoader"),
    Source("checkout_com", "Checkout.com", "https://api-reference.checkout.com/v1/swagger.json",
           note="changes every few days; supports conditional GET"),
    Source("salesforce", "Salesforce Connect REST",
           "https://developer.salesforce.com/static/connectrest/connect-rest-api/connect-rest-api-core/connect-rest-api-core.json",
           note="Referer-gated. A spoofed browser UA gets a 12KB 404 HTML page with status 200"),
    Source("gemini", "Google Gemini",
           "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta",
           fmt="discovery",
           note="JSON key order is randomised per response - MUST canonicalise or every day is a false positive"),
    Source("elevenlabs", "ElevenLabs", "https://api.elevenlabs.io/openapi.json"),
    Source("notion", "Notion", "https://developers.notion.com/openapi.json"),
    Source("shippo", "Shippo", "https://docs.goshippo.com/spec/shippoapi/public-api.yaml"),
    Source("avalara", "Avalara AvaTax", "https://rest.avatax.com/swagger/v2/swagger.json",
           fmt="swagger2"),
    Source("slack", "Slack", "https://api.slack.com/specs/openapi/v2/slack_web.json",
           fmt="swagger2",
           note="STALE SOURCE: 1 change in 2.6 years. Absence of change here is not signal"),
    Source("postmark", "Postmark", "https://postmarkapp.com/swagger/server.yml",
           fmt="swagger2",
           note="DEAD SOURCE: 0 changes in 5y7m, byte-identical to its 2021-01-19 archive"),
)


# --------------------------------------------------------------------------
# validity
# --------------------------------------------------------------------------

def looks_like_a_spec(body: bytes, fmt: str) -> str:
    """Return an error string, or "" when the body really is a spec.

    A status code is not evidence. Slack returns 200 with a 43 KB HTML page for
    three different wrong paths; Salesforce returns a 404 shell to the wrong
    Referer. A cron that trusts the status archives those daily and looks
    perfectly healthy while recording nothing.
    """
    if not body:
        return "empty body"
    head = body[:400].lstrip()
    if head[:1] in (b"<",) or head[:9].lower() == b"<!doctype":
        return "HTML, not a spec"
    if len(body) > MAX_BYTES:
        return f"implausibly large ({len(body)} bytes)"
    text = head.decode("utf-8", "replace").lower()
    if fmt == "graphql":
        return "" if ("type " in text or "schema" in text) else "no SDL markers"
    markers = {
        "openapi": ("openapi", "swagger", "paths"),
        "swagger2": ("swagger", "openapi", "paths"),
        "discovery": ("discoveryversion", "kind", "baseurl", "rootUrl".lower()),
    }[fmt]
    if not any(m in text for m in markers):
        return f"no {fmt} marker in the first 400 bytes"
    return ""


def canonical(body: bytes, fmt: str) -> bytes:
    """A byte form that is stable when the content is.

    Google re-serialises the Gemini discovery document with randomised key
    order on every request: two back-to-back fetches of the same 366,943 bytes
    produced different digests and 15,413 changed lines. Hashing the raw bytes
    would report a change every single day, for every vendor that does this.
    """
    if fmt == "graphql":
        return b"\n".join(line.rstrip() for line in body.splitlines()) + b"\n"
    try:
        parsed = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body          # YAML and anything else: compare as written
    return json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(body: bytes, fmt: str) -> str:
    return hashlib.sha256(canonical(body, fmt)).hexdigest()


# --------------------------------------------------------------------------
# the store
# --------------------------------------------------------------------------

@dataclass
class Store:
    """Content-addressed, one directory per vendor, gzipped.

    Only a changed digest is written, so an unchanged day costs one HTTP
    request and nothing on disk. The index is plain JSON so it stays readable
    without this code.
    """
    root: Path

    def _dir(self, key: str) -> Path:
        d = self.root / key
        d.mkdir(parents=True, exist_ok=True)
        return d

    def index_path(self, key: str) -> Path:
        return self._dir(key) / "index.json"

    def index(self, key: str) -> List[Dict[str, str]]:
        path = self.index_path(key)
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text())
        except ValueError:
            return []

    def latest_digest(self, key: str) -> Optional[str]:
        entries = self.index(key)
        return entries[-1]["digest"] if entries else None

    def put(self, key: str, body: bytes, fmt: str, when: str) -> Tuple[bool, str]:
        """Store the body if its content differs from the last one kept."""
        sha = digest(body, fmt)
        if sha == self.latest_digest(key):
            return False, sha
        blob = self._dir(key) / f"{sha[:16]}.gz"
        if not blob.exists():
            blob.write_bytes(gzip.compress(body, 6))
        entries = self.index(key)
        entries.append({"date": when, "digest": sha, "blob": blob.name,
                        "bytes": str(len(body))})
        self.index_path(key).write_text(json.dumps(entries, indent=1))
        return True, sha

    def read(self, key: str, entry: Dict[str, str]) -> bytes:
        return gzip.decompress((self._dir(key) / entry["blob"]).read_bytes())


# --------------------------------------------------------------------------
# fetching
# --------------------------------------------------------------------------

def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json, application/yaml, text/yaml, */*",
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as exc:
        raise SnapshotError(f"{type(exc).__name__}: {exc}"[:200]) from exc


@dataclass
class Outcome:
    key: str
    status: str      # stored | unchanged | invalid | error
    detail: str = ""
    sha: str = ""
    size: int = 0


def take(source: Source, store: Store, today: str) -> Outcome:
    try:
        body = fetch(source.url)
    except SnapshotError as exc:
        return Outcome(source.key, "error", str(exc))
    problem = looks_like_a_spec(body, source.fmt)
    if problem:
        # Never stored. An invalid snapshot in the archive is worse than a gap,
        # because a gap is visible and a bad record is not.
        return Outcome(source.key, "invalid", problem, size=len(body))
    stored, sha = store.put(source.key, body, source.fmt, today)
    return Outcome(source.key, "stored" if stored else "unchanged",
                   source.note, sha=sha, size=len(body))


def run(store_root: Path, today: str,
        only: Optional[List[str]] = None) -> List[Outcome]:
    store = Store(store_root)
    chosen = [s for s in SOURCES if not only or s.key in only]
    return [take(s, store, today) for s in chosen]
