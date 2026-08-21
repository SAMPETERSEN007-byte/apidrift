# apidrift

Semantic OpenAPI breaking-change engine. It diffs a vendor's published spec
across a time window, decides which changes can actually break a caller, and
proves — per file, per line — which of them land on real code.

Two vantage points, and the difference is the whole product:

- `apidrift` (the report) — what changed across the tracked vendors. A claim
  about a **spec diff**. 46/46 on the five default vendors; **92.1% across all
  31** (1332/1447, 172 undecidable over 1619 breaking findings), re-measured
  2026-08-21. The two numbers are not in conflict — the first was never a
  statement about the engine. Every all-vendor number this project has claimed
  went DOWN when the checker stopped sharing the engine's blind spots:
  96.3% → 67.8% → 96.7% → 77.8% → 92.1%. Each drop is the checker learning to
  decide findings nobody had checked; see defects 5 and 6 below.
- `apidrift scan PATH` (the CI gate) — which of those changes break code in a
  repository you have a checkout of. A claim about a **repo**. Dependence is
  proven in Python AND TypeScript/JavaScript.
  🚨 **The "zero impacts" this line used to boast was a WINDOW ARTEFACT.**
  `--days` defaults to 90 and integration code is written once and left; at a
  1095-day window the same 22 repositories produced **414 impacts**. A fourth
  adversarial audit sampled 74 of them and **0 were real** — 66 false, 8 in
  test files. See "The fourth audit" below. Impact precision was 0% while
  finding precision was 100%, because nothing had ever measured the difference
  between a claim about a SPEC and a claim about a REPO.

Three adversarial audits refuted 9, 9 and 10 of 10 cold leads. The engine was
never the problem; the vantage point was. Proving `card.iin` is read off a
Stripe response is intractable from one file of a repo you cannot see, and
tractable when you have the checkout. `scan` is that pivot, and it is where the
product now lives.

**State:** branch `scan-your-own-repo`, no remote, one dependency (PyYAML).
**32 vendors registered, 13 snapshot sources.** `tools/vendor_check.py`: 31
diff, 1 (column) has history shorter than the window, 0 fail.
`tools/vendor_control.py`: **235 controls fire across all 32 vendors, 0 missed**
— eight injections each, which is what makes a zero count a measurement. `main` is behind — do not merge to it casually, the
branch is the work.

---

## `./gate.sh` is the only acceptable proof of correctness

Nothing else counts. Not "tests pass", not "it ran", not a green diff. Six
layers, each asking a question none of the others asks:

| # | Layer | Question | Baseline (2026-08-21) |
|---|-------|----------|----------------------|
| 1 | unit tests | does the code do what it says? | 478 tests |
| 2 | mutation testing | do the tests fail when the code is wrong? | 259/259 killed |
| 3 | end-to-end | does the pipeline still produce output? | `out/report.md` |
| 4 | precision audit | are the FINDINGS real, per the RAW specs? | 32/32 breaking, 63/63 potentially |
| 5 | lead standing | are the LEADS real, per the last audit? | 0/10 — NOT sendable |
| 6 | recall controls | can the instrument still FIRE at all? | 36 fired, 0 missed; scan FIRED/PINNED |

🚨 **Nothing in these six layers measures an IMPACT.** Layer 4 audits findings
against the raw spec and layer 6 proves the scanner can fire on a fixture. The
claim `scan` actually ships — "this change lands on THIS line of YOUR repo" —
was unmeasured until 2026-08-21, and when it was measured it was 0%.

🚨 **3 runs before 4 because 4 audits the file 3 writes.** Ordered the other way
the audit read the PREVIOUS run's findings, so after an engine change the first
gate run scored output from code that no longer existed. A freshness check
pointed at the wrong artifact is worse than no check.

🚨 **Layer 6 is the only one that asks about RECALL.** Layers 1–5 all get
quieter as the engine gets more conservative: a suppressor that silenced every
finding would sail through all five, because precision on zero findings is
undefined rather than zero. It injects a break whose answer is known — into each
vendor's real spec, and into a fixture repo in both languages — and requires it
to be found. Adding it caught an evidence prefilter that rejected every
TypeScript file before it was examined while layers 1–5 stayed green.

The precision audit is the one that mattered first: layers 1 and 2 were green
while 86% of findings were fabricated by an asymmetric depth cap. Layer 5 exists
because a green gate on the rest was compatible with a lead list where nine of
ten sampled entries were refuted — nothing measured leads, so nothing reported
them.

### 🚨 `./gate.sh` exits **3**, and 3 is the healthy state

```
GATE GREEN for findings — LEADS NOT SENDABLE
exit 3
```

That is correct and expected. **Do not "fix" it.** Exit 3 means the engine is
verified and the outreach list is not, which is exactly true. The exit codes:

- `0` — everything green **and** leads cleared by an audit. Has never happened.
- `1` — a real failure in layers 1–4. This is the one to fix.
- `3` — findings green, leads blocked by `lead_audit.json`. Steady state.

`lead_audit.json` is tracked in git and read by layer 5. **Only an actual
adversarial audit may update it.** Editing `standing.sendable` by hand to make
the gate go green is forging the one record that stops bad outreach shipping.

---

## Doctrine

Three rules. Every one was bought with a defect that shipped.

**1. Every finding must be independently decidable.** A finding you cannot
confirm or refute against the raw spec is not a weaker finding — it is not a
finding. `measure_precision.py` reports UNDECIDABLE as its own bucket and
excludes it from the ratio rather than counting it as a pass. 46/46 means
forty-six decided and forty-six confirmed, not "46 of the ones we liked".
Across all 31 vendors 172 findings are still UNDECIDABLE and 115 are REFUTED —
together the honest measure of how much of the engine is unaudited or wrong.
Vendors with no findings in the window have no precision measurement and print
as UNMEASURED, which is not a pass — but every one of them now has a firing
control in `tools/vendor_control.py`, so their zero is a measurement.

**2. A test is worthless until you have watched it fail.** Every new test gets
a mutation in `tests/mutation_check.py`. Three times a test was written that
could never have failed: a description-only edit never enters a comparison
branch, so the guard was never reached and every needle stayed green. The
invariant had to move to `_field_shape`, where the comparison actually happens.
If you cannot make the mutation kill the test, the test is testing nothing.

**3. The checker must never ask the same question as the engine.** This has
been the recurring defect — **six separate times**, each reported as a
precision it did not have:

- *security* — OpenAPI `security` is a list of ALTERNATIVES; both engine and
  checker flattened it to a set of scheme names, so adding an alternative
  scored as breaking. Twilio kept every caller working; 9 operations were
  scored breaking.
- *schema relocation* — the checker asked "is the field still in this schema?",
  the same schema-level question the engine asked. OpenAI moved
  `ResponseProperties.reasoning` to another arm of the same `allOf` while
  `POST /responses` accepted it throughout. 5 of 84.
- *path-parameter rename* — the checker asked the spec author's question ("did
  the path string change?"), true for a rename. `{Sid}` → `{id}` produces
  byte-identical URLs. 19 of 84.
- *`scan` impacts* — the checker shared the engine's notion of a request-side
  change. 4 classes, all gated.
- *schema removal* — **the big one, 2026-08-20.** `schema_removed` was 1007 of
  the 2766 breaking findings across all 21 vendors, 36% of the population, and
  the checker confirmed 1007 of 1007. Its test was `name in schemas_of(old) and
  name not in schemas_of(new)` — literally the engine's own question. Asked the
  caller's way, **694 of 1007 are refuted.** All-vendor precision was never
  96.3%; it was 67.8%.
- *response field removal, the FALL-THROUGH*, **2026-08-21.** The operation-level
  branch could not parse a subject whose head is a schema name — Twilio and
  Stripe put dots inside schema names, Klaviyo's are truncated to 48 characters
  on the way in, and a `$ref` into `components/responses` was looked up among
  the SCHEMAS and resolved to nothing. With no body on either side the check
  fell through to `resolve_root`, which asks "is `error_400` still a schema?" —
  the spec author's question again. PayPal collapsed `error_default`'s nine
  same-shaped arms into one `error` object carrying every field: **48 findings
  on one operation, all confirmed, none real.** OpenAI renaming
  `Conversation-2` to `ResponseConversation` — byte-identical bodies — was
  confirmed the same way, inside the five-vendor gate. 139 more of the class
  were UNDECIDABLE for the same parsing reason and had never been checked at
  all. Asked the caller's way, `response_field_removed` is 386/478 with 74
  undecidable, not 411/424 with 139.

**3a. The checker itself is tested now, and it was not.** `measure_precision.py`
is layer 3 and it found every large defect this engine has had, while having
zero tests and zero mutations of its own. `tests/test_checker.py` pins thirty of
its decisions and nineteen mutations target it. Reverting `schema_removed` to the
engine's question, deleting the dereferenced-document control, or refuting a
path parameter's TYPE change on positionality all go red. A silent break in the
checker makes layer 3 report 100% while checking nothing.

**3b. A refuter whose precondition holds for 100% of inputs is a broken
instrument, not a result.** The first version of the new `unreachable` rule
refuted any schema with no `$ref` pointing at it. Sentry's
`openapi-derefed.json` contains **zero** occurrences of `"$ref"` in 3.2 MB, so
that was vacuously true of all 157 of its schemas, and it would have deleted a
real break — `DetailedOrganizationSerializerWithProjectsAndTeams` is verbatim
the 200 body of a PUT that still exists and lost seven required response
properties. Engine and checker now **count the linking constructs first and
abstain when there are none**, in their own separate states. Same shape as
"zero results is a failed measurement", applied to a suppressor instead of a
search — and it is why a new suppressor gets an adversarial audit, not just a
test.

**3c. Abstaining is honest, and it is still not an answer.** That control left
all 25 of Sentry's `schema_removed` findings UNDECIDABLE — printed, counted,
and decided by nobody. A dereferenced document has a second key into the very
same caller's question: **body identity instead of reference identity.** Every
one of Sentry's 157 schemas appears VERBATIM somewhere under `paths`, because
the `components` table is a parallel copy of bodies the operations also write
out. Asked that way the class decides completely — 25 → 2 findings, 0
undecidable:

- 22 are carried only by operations that were REMOVED in the same change, and
  `endpoint_removed` reports each of those on its own.
- `Organization` is inlined at ten sites and all ten still carry the identical
  body: the vestigial table entry went, the wire did not move.
- `DetailedOrganizationSerializerWithProjectsAndTeams` and `AutofixRequest`
  survive, and the independent checker CONFIRMS both.

Engine side: `loader.dereferenced_schema_roots()` builds the same
`reachable`/`rooted_at`/request/response maps by matching schema BODIES inside
operation subtrees, and is applied **only** when reference-based discovery
returned nothing — where references exist they are exact and cheaper, and a
body that merely coincides with a schema nobody named must not invent
reachability. Checker side: `check_schema_removed_dereferenced()` walks the
raw document for verbatim occurrences with its own walker and its own control
(how many named schemas appear inline at all). Independence measured, not
asserted: **with `_removal_is_observable` forced to `(True, "")` the engine
emits all 25 and the checker refutes exactly 23 unaided, confirming exactly
the 2 the engine keeps.**

The morning of 2026-08-20 claimed 84/84 = 100%. It was really **64/84 = 76%**.
Mutation-verified end to end: with all four suppressions disabled the engine
emits 86 and the independent checker refutes 22 unaided.

**When you add a suppressor to the engine, the checker must be able to refute
that class on its own, from the RAW document, with its own resolver.** If
disabling the engine's suppression does not make the checker start refuting,
you have built one opinion with two names.

**Corollary — zero results is a failed measurement until something says
otherwise.** Three separate instances in one day, all shaped identically:
a repo whose only callers were TypeScript was told "clean" because detection
walks `.py`; a repo calling no known vendor was told "clean" because nothing
was checked; a vendor whose git history was younger than the window was told
"clean" because there was nothing behind the file. Every step true, every
conclusion a lie. Every negative result needs a control that fires — the Plaid
fixture control still exits 1 at the right line, which is what makes "0 impacts
across 22 repos" a measurement.

---

## The six false-positive classes — gated, do not reintroduce

Found by adversarial audits of the **lead** pipeline. Each has a gate and tests;
every case a skeptic refuted is now a test.

| # | Class | What it looked like | Gate |
|---|-------|--------------------|------|
| 1 | **URL prefix, not the operation** | `discord.py` flagged because `http.py` "calls /guilds at 98 sites" — kick/ban/bulk-ban — for a change to a channel icon field returning zero hits | a named field's identifier must appear in the file, any casing; paths compared segment-wise, a literal segment must be matched by a literal, never a caller's variable |
| 2 | **Vendor-owned / generated SDK** | `openai/openai-python`, `plaid/plaid-python` — telling OpenAI their own codegen is broken by their own spec | provenance rejected **before** a fetch is spent; generator headers rejected outright (`classify.py:92 is_generated_path`, `verify.py:88 looks_generated`) |
| 3 | **Declaration, not a call** | cited line was the `{` opening a defaults table or a generated type map | sites filtered by the **direction** of the change — a dict key is how you SEND a field, not how you READ one (`dependence.py:595 directions`) |
| 4 | **Changed field absent from the repo** | field never appears anywhere in the file | identifier check, same gate as #1 |
| 5 | **Vendored dependency trees** | `terraform/lambda_function/plaid/model/...` — a pip tree committed into a Lambda bundle, no venv marker, no leading underscore | vendor package dir + generated client layout (`model/`, `api_resources/`, `resources/`) counts as vendored (`classify.py:61 is_vendored_path`) |
| 6 | **Line numbers from another revision** | a lead quoted a kick route at a line holding something else | every lead carries the **blob sha** of the file it was read from |

🚨 **Closing all six did not move the refutation rate.** Second audit: 9/10
again. The gates changed *why* leads died, not *how often*. Root cause named
only then: verification proved **co-location** and never **dependence**. That
is the lesson — gating symptoms one at a time can leave the rate untouched
while feeling like progress.

Dependence is now proven by one of three routes (`dependence.py:655 prove`):
the value traced back to a vendor call and the changed field read off it; a
call to an operation carrying the changed schema plus a read of the field; or,
for an operation change, a call reaching it by method and full path template.
SDK calls count — `stripe.checkout.Session.create(...)` reaches
`POST /v1/checkout/sessions` without the path ever appearing.

`prove()` and `prove_relevance()` are deliberately separate functions.
`prove()` **refuses** to accept reaching an operation as evidence of a break —
that refusal cleared the standing audit blocker. `prove_relevance()` accepts
exactly that, because nobody can depend on something that did not exist yet.
For an addition, reach is not a weak substitute for proof; it IS the proof.
**Do not merge them.** Sharing one function puts the two one edit away from
collapsing into each other.

### The `schema_removed` suppressors — four questions, never one

A schema NAME never reaches the wire, the same fact that made a field moving
between schemas a non-event and a path-parameter rename a non-event. It was
never applied to the schema itself. Each class is decided by a **different**
question so no two can collapse into one opinion:

| Reason | Question | Measured |
|---|---|---|
| `unreachable` | does any operation reach it? | measured where the document links schemas OR inlines them — see below |
| `relocated` | does every place that pointed at it still present the same shape? | Klaviyo 208 inlined enums |
| `renamed` | does every operation that named it now name a schema of identical shape? | Cloudflare 191 bulk-renamed envelopes |
| `subsumed` | is every route in through another schema removed in the same change? | PayPal `error_409`, one restructure reported 92 times |

🚨 **`not direct` on the subsumption rule is load-bearing.** An operation that
names a schema itself can observe its removal whatever happened to the schema's
other parents. Without it PayPal's `error_400/401/403/404/409/422/500` all
vanish — each is a status-coded response body on live operations *and* an arm
of `error_default` — along with 20 Cloudflare request-surface schemas.

🚨 **Every suppressor has a mutation in BOTH directions.** Disable it and the
"not a break" test goes red; make it fire unconditionally and the "still a
break" test goes red. A suppressor with only the first half is a deletion
nobody is checking.

🚨 **`tools/vendor_control.py` now injects a `schema_removed` into all 22
vendors' real specs** — until 2026-08-20 these four suppressors had NO recall
control at all, only precision measurements, which is exactly the shape that
lets a suppressor eat a real break unnoticed. **121 controls fire, 0 MISSED.**
It picks its target from the RAW document, never from the engine's
reachability maps: a control that chooses its stimulus with the mechanism
under test degrades to `n/a` precisely when that mechanism breaks, and "could
not run" is not "passed". It demands the removal stay VISIBLE at the operation
that carried it, not that it carry a particular LABEL — Sentry's
`AutofixPostResponse` surfaces as `response_field_removed` on the same
operation, which is a more precise description of the same break.

**Two recall holes it found on its first run, both pre-existing, both now
closed and both measured to change nothing across the 21 real windows:**

- *auth0, MISSED outright.* `_operation_field_names` merged request and
  response names, so replacing `AddOrganizationConnectionRequestContent` with
  a bare string read as "all four names are still there" — they were, in the
  201 RESPONSE. A whole schema travels ONE way; both the name test and the
  rename test now ask about that way (`_operation_field_names_where`).
- *the same shape in `_renamed_at_roots`.* A request body "renamed" to a
  shape-identical RESPONSE schema on the same operation is not a rename.

### Three more `schema_removed` refutations closed, and one attempt reverted

The 10 refuted became **7** (klaviyo 3 → 1, paypal 1 → 0), by two questions
`_shape_at_parents` could not previously ask:

- **the schema sits at an array's `items`.** Klaviyo's `Constant_contactEnum`
  is never a property's TYPE, so a loop reading only `field.type` compared
  nothing. It also needed `Field.item_enum`: `items: {type: string, enum: [x]}`
  flattened to plain `"string"`, which made a named element enum and its
  inlined body compare unequal — and made a NARROWING of one invisible. That
  second half found a real Twilio break the engine had been missing
  (`use_case_categories`), CONFIRMED by the checker.
- **a pure inlining whose ELEMENT separately changed.** PayPal inlined
  `billing_cycle_list` at the identical property while editing
  `billing_cycle`, which the array points AT. Resolving one level further
  mixed the two; `_view_notation`/`_field_notation` ask the narrower question,
  and the element's change is still its own finding against its own schema.

🚨 **The `truncated` abstention was narrowed and MEASURED UNSAFE — reverted.**
Deciding the class whenever every contributed name was found (on the true
observation that truncation can only HIDE a name) removed 60 findings,
**49 of which the independent checker had CONFIRMED** — PayPal 73 → 35,
Cloudflare 31 → 13. All-vendor precision rose to 97.7% *by deleting real
breaks*, the worst outcome available here. The comment in `diff.py` says so at
the line. Do not re-apply it without a measurement showing those 49 are false.

### And four more on the `scan` side
All refuted by hand against source + raw spec, all gated: a read proving a
*request-side* change (phasehq/console); a keyword argument on the repo's OWN
constructor counted as a request body (phasehq/console); and two of the same in
autoevals/agentops.

---

## Known blind spots — `lead_audit.json` → `scan_standing.known_blind_spots`

Written down so they live in the repo and not in whoever last read the code.
These are **open**, not fixed:

1. ~~**Dependence is provable in Python only.**~~ **CLOSED 2026-08-21** —
   `apidrift/js.py` + `js_dependence.py` prove it in TypeScript and JavaScript
   too, JSX included (181/181 real files on this machine readable). Every OTHER
   language is still COUNTED and reported as UNMEASURED, never silently passed
   as clean. The word "clean" cannot be printed while any exist.
   🚨 Shipping this reintroduced co-location as dependence — 27 impacts across
   three real repositories, all false, because the JS prover implemented only
   half of `prove()`'s contract (a read, without the call to an operation
   carrying the field). `tools/corpus_scan.py` exists to stop that recurring.
2. ~~**API version pinning is not modelled at all.**~~ **CLOSED for JS/TS** —
   `new Stripe(k, { apiVersion: '...' })` is read as a pin and the file is not
   affected by a change to the current version. Still unmodelled in Python.
3. **The relocation suppressor consults a field map flattened at `MAX_DEPTH=2`**,
   so it cannot see a name nested deeper and **abstains silently** rather than
   marking the finding unchecked.
4. **The spec cache is not fetched by default** — a scan can run against a
   stale clone. `--fetch` is opt-in.
5. **`_Assignments` is one flat module-level dict**, so def-use tracing is
   scope-blind and flow-insensitive across function boundaries.

Two more in `standing.also_open`: `operation_reached()` stops at the first
affected operation with a hit *in list order*, so an alphabetically earlier
DELETE whose response is discarded beats a GET whose response is deserialized;
and a lead's `breaks_on` names the finding's representative operation while its
proof names the operation the file actually calls, with nothing stating the two
are related — that misled three auditors who had the repo, the spec and the
source in front of them.

---

## The fourth audit — 2026-08-21, and the first ever aimed at IMPACTS

Three audits had attacked LEADS. `pr_blocker` had demanded a fourth that
sampled IMPACTS from `scan.py` against real repositories. It ran
(`wf_ffc26e20-6f4`): 22 repos at 1095 days → 295 impacts → 74 sampled,
stratified over every `(kind, vendor)` pair, thirteen independent skeptics with
two more refuting anything that survived.

**74 audited. 0 REAL. 66 FALSE. 8 TEST_ONLY. 0 UNDECIDABLE.**

Five classes closed, each with its own question and its own two-way mutation.

| Class | n/74 | What it looked like | Gate |
|---|---:|---|---|
| **a read is a POSITION, not a word** | 21 | `subscription.currency` returned as a read of `<deleted_discount>.coupon.currency` | `read_sits_where_subject_says` (the subject's wire ancestry must appear, in order, ahead of the leaf) **and** `_chain_reaches_change` (the traced call must reach an operation the change touches) |
| **a member chain needs provenance** | ~13 | `collaborators.append(info)` on a local list reported as "the SDK form of" `GET /projects/{id}/collaborators`; `secrets.token_urlsafe(32)` reported as GitHub's secret endpoints | `find_sdk_calls` requires `call_reaches_vendor` on the chain's root — the gate JS always had |
| **a dated API version is not HEAD** | 3 | langfuse reading `subscription.current_period_start` on `stripe-node@17.4.0`, which sends `2024-11-20.acacia` | `Vendor.versioned` + `ScanResult.pinned`; SDK callers UNMEASURED, raw-HTTP callers still judged |
| **`nullable` vs `anyOf: [T, null]`** | 1 | OpenAI's 3.0→3.1 migration; two fields alone were 75 of the 295 | `loader._nullable_wrapper_payload` in the schema view |
| **a spec that documented no auth** | 2 | OpenAI's 2023 doc declared no `securitySchemes`; the 2026 one does | count the old document's schemes, abstain at zero |

Test-file impacts are split into `ScanResult.incidental` and out of the exit
status entirely — reported, never counted.

🚨 **The audit refuted my own best finding, and it was right.** The langfuse
`current_period_start` impact re-derives perfectly against the raw Stripe spec
and is still not a break, because the SDK pins the version. A correct spec fact
is not a correct claim about a repository. That is the whole lesson of this
audit in one line.

🚨 **Both new controls had been built on the bug they were meant to catch.**
`scan_control` wrote `record.card_issuer_decline` for a subject of
`<radar.payment_evaluation>.insights.card_issuer_decline` — not a read of that
field at all — and it passed for exactly as long as the prover shared the
mistake. It also accepted ANY breaking impact on the fixture file, so the
TypeScript half reported FIRED on a fixture whose read was in the wrong place,
carried by an unrelated finding.

🚨 **Teaching the engine 3.1's dialect made layer 4 DROP to 79.4%**, because the
checker's own nullability resolver knew two spellings of three, and REFUTED six
more properties it could not locate (`CreateResponse` →
`CreateModelResponseProperties` → `ModelResponseProperties` is two `allOf` arms
deep and it followed one). A property you cannot locate is UNDECIDABLE. Fixed in
the checker's own walker, from the raw document: 63/63.

### The window is the wrong default and has NOT been changed

`--days 90` on code written years ago is why this tool found nothing for a day
and read it as precision. 90 days → 0 impacts across 22 repos; 1095 days → 414.
The default is still 90 **on purpose**: a longer window multiplies a population
that is not yet audited clean. Change it after a fifth audit, not before.

---

## `pr_enabled: false`

Recorded in `lead_audit.json` → `scan_standing`. **There is no write path in
this tool and there should not be one** until a fourth adversarial audit samples
IMPACTS from `scan.py` against real repositories.

Opening a pull request into someone else's repository is a larger outward-facing
act than sending an email, and `gate.sh` already refuses to let the email ship.

🚨 **The fourth audit has now RUN, and it is the reason to keep this false, not
the reason to flip it.** It found nothing to open a PR about: 74 impacts
sampled, 0 real. Five classes are closed since, and a SMALLER population is not
a MEASURED one. A fifth audit must sample what survives the fixes — and it must
include raw-HTTP callers specifically, because pinning removed every SDK caller
of the biggest vendor from the judgeable population and nobody has checked what
is left.

Do not add a PR path, an auto-commit, or an email send. Do not flip
`sendable`. Those are Sam's calls after an audit, not a coding decision.

---

## Commands

```bash
./gate.sh                                          # the only proof. expect exit 3
./.venv/bin/python -m unittest discover -s tests   # layer 1 —  0.1s (436 tests)
./.venv/bin/python tests/mutation_check.py         # layer 2 — ~90s (238 mutations)
./.venv/bin/python tools/vendor_control.py         # layer 6 — inject a KNOWN break, all 32
./.venv/bin/python tools/scan_control.py --asof 2026-08-21
./.venv/bin/python tools/corpus_scan.py --corpus /tmp/corpus --asof 2026-08-21
./.venv/bin/python tools/vendor_probe.py candidates.json   # before registering a vendor
./.venv/bin/python tests/measure_precision.py --sample 1000 --severity breaking
                                                   # layer 3 — 12.6s per severity
./.venv/bin/python tests/measure_precision.py --findings out_all/findings.json \
    --sample 5000 --severity breaking --by-vendor   # ALL vendors, per-vendor
./.venv/bin/python tools/vendor_check.py --days 180 --asof 2026-08-20
./.venv/bin/python -m apidrift.cli --vendors all --days 180 --asof 2026-08-20 --out out_all
./.venv/bin/python -m apidrift.cli snapshot        # the URL-only cohort
./.venv/bin/python -m apidrift.cli --days 90 --quiet
                                                   # layer 4 — 18.2s
./.venv/bin/python -m apidrift.cli scan ~/somerepo --days 30
./.venv/bin/python -m apidrift.cli scan ~/somerepo --opportunities
```

### 🚨 129 findings are refuted, and the count went UP because the checker got sharper

Recorded in `lead_audit.json → scan_standing.open_false_positive_classes` with
the mechanism for each. As of 2026-08-21, re-measured over all 21 vendors:
`response_field_removed` 92, `schema_removed` 10, `request_field_added_required`
8, `schema_field_type_changed` 8, `request_field_now_required` 4,
`request_field_type_changed` 3, `schema_field_removed` 2,
`response_field_type_changed` 2, `endpoint_removed` 0.

**Reading that as a regression would be the wrong reading.** The previous list
said `response_field_removed` 13 over a class where **139 findings had never
been checked**; the checker now decides 65 of those and refutes 84 it used to
confirm. Ten of the original 13 are gone at the engine (nullability wrappers,
root markers), and what remains is one mechanism, named and unfixed:

🚨 **A response position that GAINS union arms.** Twilio repointed a 200 body
from `us_app_to_person` to a `oneOf` of it and a v2 superset; Cloudflare widened
an Access policy `result` to `anyOf[app_policy, infra_policy]`; PayPal replaced
`oneOf[error_400 … error_500]` with one `error` object carrying every field.
Every old key moves, so every field reads as removed, while a field present in
EVERY new arm is still guaranteed. 89 of the 92. **No engine fix is proposed**:
the only rule that decides it is "does every alternative still promise this
field", which is exactly the question the checker asks, and building it twice is
how this project shipped the same defect six times. The checker catching them is
worth more than the engine and the checker agreeing.

Three adversarial audits diagnosed the first three correctly — every raw-spec
claim they made re-derived — and **all three of their proposed fixes measured as
unsafe**. One dropped all-vendor precision to 77.3% and refuted
`stripe token.card.iin`, this repo's canonical real break. Do not apply a
diagnosis without measuring the fix; on this class a correct diagnosis and a
correct remedy came apart three times out of three.

**The whole gate is ~65 seconds.** There is no reason to skip it or to run a
subset and call it verified. Layer 1 is essentially free (0.1s) — run it after
every edit; run the full gate before every commit.

`gate.sh` has been mutation-tested as a whole: injecting one failing assertion
makes it print `GATE RED` and exit 1. It can go red, so green means something.

Use `./.venv/bin/python`, the interpreter `gate.sh` and every tool here use.
Bare `python3` currently happens to work — `/usr/bin/python3` shims to Xcode's
interpreter, which bundles PyYAML 6.0.3 — but that is an accident of this Mac's
toolchain, not a property of the project, and an Xcode or `xcode-select` change
takes it away silently.

`--asof ISO_DATE` pins "today", which is how a run is made reproducible.

Vendor keys: `stripe openai twilio plaid discord` are the report's DEFAULT five
(verified); `--vendors all` reaches all 22, of which 20 work. Note `scan`
defaults to **all** vendors, the report to the five.

`scan` flags worth knowing:

- `--opportunities` — the additive half. Over the same window and the same five
  vendors: **112 new operations and 332 new optional fields against 64 breaking
  changes.** The additive surface is ~5× the breaking one, every repo scanned
  has something in it, and almost none has a break. Never affects exit status:
  nothing in it is broken. This is the half with a customer.
- `--exit-zero` — always exit 0. For a CI job that should report without
  failing the build.
- `--opportunity-limit N` — cap the adoption list; `0` = no cap. What gets
  dropped is always stated rather than silently truncated.
- `--format text|markdown|json`.

## Working rules for this repo

- **Never let layer 3 regress.** A change that improves recall and drops
  precision is a change that fabricates findings. Precision first, always.
- **A suppressor needs a mutation.** Add it to `mutation_check.py` in the same
  commit, and check that disabling the engine's half makes the checker refute
  the class unaided.
- **Cloudflare's 983 breaking changes in 180 days is almost certainly wrong**
  and must not be believed until `measure_precision.py` has run against it.
  They regenerate several times a day — exactly the shape that produced phantom
  findings before.
- **`apidrift snapshot` runs daily** (launchd `com.claudebot.apidrift-snapshot`,
  05:17, log `~/Library/Logs/apidrift-snapshot.log`). 11 sources registered, 10
  fetch and store, 1 (Salesforce) is `blocked` — 403 with or without a Referer,
  its own state and deliberately not a run failure.
  🚨 **The change detector is deliberately insensitive to three things and must
  stay sensitive to everything else**: key order (Gemini randomises it per
  response), `example` values, and UUIDs/ISO timestamps anywhere (Avalara
  regenerates every example GUID *and* embeds a fresh OAuth `nonce`, so it would
  have stored 4 MB every day forever). Four controls hold this together and all
  four must pass: two fetches of Avalara agree; two of Gemini agree while their
  raw bytes differ; an example-only change does NOT move the digest; a dropped
  endpoint DOES. The fourth is not optional — a detector made insensitive to
  everything reports a clean archive forever.
  🚨 **Slack and Postmark are labelled `stale` and `dead` with the measurement
  attached** (1 change in 2.6y; 0 in 5y7m). An unchanged day from either carries
  no information and the report says so under its own heading. Never let their
  silence read as an all-clear.
- **Commit messages carry the reasoning.** They are the design record for this
  project and several were the only place a defect was ever explained. Keep
  writing them that way: what was wrong, what it looked like, why the previous
  code believed itself, and the test/mutation counts.
