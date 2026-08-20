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

import datetime as dt
import gzip
import hashlib
import json
import re
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


# How much this source has actually moved, measured -- not guessed. A source
# that never changes and a source that is being watched correctly produce the
# SAME output ("no new snapshot"), and the difference matters enormously: one
# means nothing happened, the other means nothing has happened for years and a
# quiet result here is worth nothing. Prose in a `note` cannot be checked by
# code; this can.
LIVE = "live"
STALE = "stale"     # changes, but so rarely that silence carries no information
DEAD = "dead"       # measured as not having changed in years


@dataclass(frozen=True)
class Source:
    """A spec that must be recorded because nobody else is recording it."""
    key: str
    name: str
    url: str
    fmt: str = "openapi"        # openapi | swagger2 | discovery | graphql
    note: str = ""
    liveness: str = LIVE
    # What the liveness claim is based on. A label with no measurement behind
    # it is an opinion.
    liveness_evidence: str = ""


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
           fmt="swagger2", liveness=STALE,
           liveness_evidence="1 change in 2.6 years (measured 2026-08-20)",
           note="Absence of change here is not signal"),
    Source("postmark", "Postmark", "https://postmarkapp.com/swagger/server.yml",
           fmt="swagger2", liveness=DEAD,
           liveness_evidence="0 changes in 5y7m; byte-identical to its "
                             "2021-01-19 Wayback archive (measured 2026-08-20)",
           note="Do not read silence here as a clean result"),
)


# --------------------------------------------------------------------------
# validity
# --------------------------------------------------------------------------

def _build_yaml_loader():
    """SafeLoader plus the one YAML 1.1 tag that real specs still emit.

    Zendesk's `oas.yaml` contains a bare `=` scalar, which YAML 1.1 resolves to
    `tag:yaml.org,2002:value`. PyYAML's SafeLoader has no constructor for it and
    raises, so a perfectly good 1.7 MB spec was rejected as "neither JSON nor
    YAML". Reading it as the plain string it looks like is what every other
    consumer of that document does.
    """
    import yaml

    class SpecLoader(yaml.SafeLoader):
        pass

    SpecLoader.add_constructor(
        "tag:yaml.org,2002:value",
        lambda loader, node: loader.construct_scalar(node))
    return SpecLoader


try:
    _SpecYamlLoader = _build_yaml_loader()
except ImportError:                                        # pragma: no cover
    _SpecYamlLoader = None

# Top-level keys that mean "this really is the kind of document it claims to
# be". Checked after PARSING, because where a key appears in the byte stream is
# not a property of the document.
_ROOT_MARKERS = {
    "openapi": ("openapi", "swagger", "paths"),
    "swagger2": ("swagger", "openapi", "paths"),
    "discovery": ("discoveryVersion", "rootUrl", "baseUrl", "kind"),
}


def looks_like_a_spec(body: bytes, fmt: str) -> str:
    """Return an error string, or "" when the body really is a spec.

    A status code is not evidence. Slack returns 200 with a 43 KB HTML page for
    three different wrong paths; Salesforce returns a 404 shell to the wrong
    Referer. A cron that trusts the status archives those daily and looks
    perfectly healthy while recording nothing.

    The first version of this scanned the leading 400 bytes for a marker word,
    and the first real run rejected THREE VALID SPECS -- Increase (4.1 MB),
    Google Gemini and Slack -- because their marker simply appears later in the
    file. Gemini is the pointed one: Google randomises JSON key order on every
    response, which is the exact hazard the canonicaliser exists for, and it
    defeats any check that cares where a key sits in the byte stream. Rejecting
    a real spec is the same class of failure as storing a fake one, and a
    validator that has to be right about BOTH cannot be a substring search.

    So: cheap reject for HTML, then parse, then look at the ROOT keys.
    """
    if not body:
        return "empty body"
    if len(body) > MAX_BYTES:
        return f"implausibly large ({len(body)} bytes)"
    head = body[:400].lstrip()
    if head[:1] == b"<" or head[:9].lower() == b"<!doctype":
        return "HTML, not a spec"
    if fmt == "graphql":
        text = body[:4000].decode("utf-8", "replace")
        return "" if ("type " in text or "schema" in text) else "no SDL markers"

    doc, problem = _parse(body)
    if problem:
        return problem
    if not isinstance(doc, dict):
        return f"parsed as {type(doc).__name__}, not a document"
    present = [m for m in _ROOT_MARKERS[fmt] if m in doc]
    if not present:
        return (f"parsed, but no {fmt} root key "
                f"({', '.join(_ROOT_MARKERS[fmt])}) among {len(doc)} keys")
    return ""


def _parse(body: bytes):
    """(document, error). JSON first; YAML only if the payload is not JSON."""
    try:
        return json.loads(body), ""
    except UnicodeDecodeError:
        return None, "not valid UTF-8"
    except ValueError:
        pass
    try:
        import yaml
    except ImportError:                                    # pragma: no cover
        return None, "not JSON, and PyYAML is unavailable to try YAML"
    try:
        return yaml.load(body, Loader=_SpecYamlLoader), ""
    except yaml.YAMLError as exc:
        return None, f"parses as neither JSON nor YAML: {str(exc)[:90]}"


# Keys whose value is documentation, not contract. Nothing a caller must send
# or can read is decided by an example, and several vendors regenerate them on
# every request.
_VOLATILE_KEYS = ("example", "examples")

# Values that are unique BY CONSTRUCTION, wherever they appear. A key list
# would have to be extended every time a vendor invents a new field to put a
# GUID in, and would fail silently until someone noticed the archive growing --
# the same shape as a config entry naming something that does not exist. This
# neutralises the value instead of guessing the key.
#
# Measured on Avalara: after examples were stripped, one difference remained --
# `securityDefinitions.OauthSecurity.authorizationUrl` embeds a fresh `nonce`
# GUID on every request, which is not a mistake, it is what a nonce is for.
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?")


def _stabilise(text: str) -> str:
    return _TIMESTAMP.sub("<timestamp>", _UUID.sub("<uuid>", text))


def _strip_volatile(node):
    """Drop example payloads, recursively.

    Measured, not assumed: two back-to-back fetches of Avalara's 3.95 MB
    swagger.json differ, and every differing location is an `example` --
    `exportedAt` timestamps a second apart, freshly minted GUIDs for
    `documentCode`, `ruleId`, `ruleExecutionId`. Sorting keys does not touch
    that, so Avalara would have reported a change every day forever and stored
    a 4 MB blob each time. The stored bytes still contain everything; only the
    CHANGE DETECTOR ignores examples.
    """
    if isinstance(node, dict):
        return {k: _strip_volatile(v) for k, v in node.items()
                if k not in _VOLATILE_KEYS}
    if isinstance(node, list):
        return [_strip_volatile(v) for v in node]
    if isinstance(node, str):
        return _stabilise(node)
    return node


def canonical(body: bytes, fmt: str) -> bytes:
    """A byte form that is stable when the CONTRACT is.

    Two vendors already defeat naive hashing, in two different ways:

    Google re-serialises the Gemini discovery document with randomised key
    order on every request -- two back-to-back fetches of the same 366,943
    bytes produced different digests and 15,413 changed lines. Sorting keys
    fixes that.

    Avalara regenerates every `example` value per request -- timestamps and
    GUIDs. Sorting keys does not fix that at all, because the values really do
    differ. Examples are documentation, so they are dropped before hashing.
    """
    if fmt == "graphql":
        return b"\n".join(line.rstrip() for line in body.splitlines()) + b"\n"
    parsed, _ = _parse(body)
    if parsed is None:
        return body          # unparseable: compare as written
    return json.dumps(_strip_volatile(parsed), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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

class SourceBlocked(SnapshotError):
    """The server refused us, and will go on refusing us.

    A durable refusal and a flaky network are the same word in a log and need
    opposite responses: one is retried tomorrow, the other needs a human to
    find another route to the document. Salesforce answers 403 to this fetcher
    with or without a Referer, so leaving it as a generic `error` would put an
    unfixable red line in every daily run until it stopped being read.
    """


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json, application/yaml, text/yaml, */*",
    })
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403, 404, 410):
            raise SourceBlocked(
                f"HTTP {exc.code} — the server refuses this client; a retry "
                f"tomorrow will not change that") from exc
        raise SnapshotError(f"HTTPError: {exc}"[:200]) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise SnapshotError(f"{type(exc).__name__}: {exc}"[:200]) from exc


@dataclass
class Outcome:
    key: str
    status: str      # stored | unchanged | invalid | blocked | error
    detail: str = ""
    sha: str = ""
    size: int = 0


def take(source: Source, store: Store, today: str) -> Outcome:
    try:
        body = fetch(source.url)
    except SourceBlocked as exc:
        return Outcome(source.key, "blocked", str(exc))
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


def age_in_days(store: Store, key: str, today: str) -> Optional[int]:
    """Days since this source last CHANGED, or None if never recorded."""
    entries = store.index(key)
    if not entries:
        return None
    try:
        last = dt.date.fromisoformat(entries[-1]["date"])
        return (dt.date.fromisoformat(today) - last).days
    except (ValueError, KeyError):
        return None


def report(outcomes: List[Outcome], store_root: Path, today: str) -> str:
    """What the archive holds, and what a quiet source actually means.

    "unchanged" from a live source and "unchanged" from a source that has not
    moved since 2021 are the same word for two completely different facts. The
    second must never read as an all-clear, so the liveness label travels with
    every row and the summary counts them separately.
    """
    store = Store(store_root)
    by_key = {s.key: s for s in SOURCES}
    lines = [f"apidrift snapshot — {today}", ""]
    width = max((len(o.key) for o in outcomes), default=8)
    for out in outcomes:
        source = by_key.get(out.key)
        live = source.liveness if source else LIVE
        age = age_in_days(store, out.key, today)
        seen = "never recorded" if age is None else f"last change {age}d ago"
        flag = "" if live == LIVE else f"  [{live.upper()} SOURCE]"
        size = f"{out.size:,}b" if out.size else "-"
        lines.append(f"  {out.key:<{width}}  {out.status:<9} {size:>12}  "
                     f"{seen}{flag}")
        if out.status in ("invalid", "error", "blocked"):
            lines.append(f"  {'':<{width}}  └─ {out.detail}")
    counts: Dict[str, int] = {}
    for out in outcomes:
        counts[out.status] = counts.get(out.status, 0) + 1
    lines += ["", "  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))]

    quiet = [o for o in outcomes if o.status == "unchanged"
             and (by_key.get(o.key) or Source("", "", "")).liveness != LIVE]
    if quiet:
        lines += ["", "  NOT AN ALL-CLEAR — these sources are known not to move, "
                      "so an unchanged day from them carries no information:"]
        for out in quiet:
            source = by_key[out.key]
            lines.append(f"    {source.name}: {source.liveness_evidence}")
    blocked = [o for o in outcomes if o.status == "blocked"]
    if blocked:
        lines += ["", f"  {len(blocked)} source(s) REFUSE this client outright. "
                      f"Retrying tomorrow will not help — these need another "
                      f"route to the document, not another attempt."]
    bad = [o for o in outcomes if o.status in ("invalid", "error")]
    if bad:
        lines += ["", f"  {len(bad)} source(s) recorded NOTHING today. A gap is "
                      f"visible; a bad record is not, so nothing was stored."]
    return "\n".join(lines) + "\n"
