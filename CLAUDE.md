# apidrift

Semantic OpenAPI breaking-change engine. It diffs a vendor's published spec
across a time window, decides which changes can actually break a caller, and
proves — per file, per line — which of them land on real code.

Two vantage points, and the difference is the whole product:

- `apidrift` (the report) — what changed across the tracked vendors. A claim
  about a **spec diff**. Verified at 64/64.
- `apidrift scan PATH` (the CI gate) — which of those changes break code in a
  repository you have a checkout of. A claim about a **repo**. Zero impacts
  across 22 real repos, which is a measurement, not an absence.

Three adversarial audits refuted 9, 9 and 10 of 10 cold leads. The engine was
never the problem; the vantage point was. Proving `card.iin` is read off a
Stripe response is intractable from one file of a repo you cannot see, and
tractable when you have the checkout. `scan` is that pivot, and it is where the
product now lives.

**State:** branch `scan-your-own-repo`, no remote, one dependency (PyYAML),
9.8k lines. 22 vendors registered, 20 verified working. `main` is behind — do
not merge to it casually, the branch is the work.

---

## `./gate.sh` is the only acceptable proof of correctness

Nothing else counts. Not "tests pass", not "it ran", not a green diff. Five
layers, each asking a question none of the others asks:

| # | Layer | Question | Baseline (2026-08-20) |
|---|-------|----------|----------------------|
| 1 | unit tests | does the code do what it says? | 212 tests |
| 2 | mutation testing | do the tests fail when the code is wrong? | 93/93 killed |
| 3 | precision audit | are the FINDINGS real, per the RAW specs? | 64/64 breaking, 67/67 potentially |
| 4 | end-to-end | does the pipeline still produce output? | `out/report.md` |
| 5 | lead standing | are the LEADS real, per the last audit? | 0/10 — NOT sendable |

Layer 3 is the one that mattered first: layers 1 and 2 were green while 86% of
findings were fabricated by an asymmetric depth cap. Layer 5 exists because a
green gate on 1–4 was compatible with a lead list where nine of ten sampled
entries were refuted — nothing measured leads, so nothing reported them.

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
excludes it from the ratio rather than counting it as a pass. 64/64 means
sixty-four decided and sixty-four confirmed, not "64 of the ones we liked".

**2. A test is worthless until you have watched it fail.** Every new test gets
a mutation in `tests/mutation_check.py`. Three times a test was written that
could never have failed: a description-only edit never enters a comparison
branch, so the guard was never reached and every needle stayed green. The
invariant had to move to `_field_shape`, where the comparison actually happens.
If you cannot make the mutation kill the test, the test is testing nothing.

**3. The checker must never ask the same question as the engine.** This has
been the recurring defect — **four separate times**, each reported as 100%
precision:

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

### And four more on the `scan` side
All refuted by hand against source + raw spec, all gated: a read proving a
*request-side* change (phasehq/console); a keyword argument on the repo's OWN
constructor counted as a request body (phasehq/console); and two of the same in
autoevals/agentops.

---

## Known blind spots — `lead_audit.json` → `scan_standing.known_blind_spots`

Written down so they live in the repo and not in whoever last read the code.
These are **open**, not fixed:

1. **Dependence is provable in Python only.** Callers in other languages are
   COUNTED and reported as UNMEASURED, never silently passed as clean. The word
   "clean" cannot be printed while any exist. A third state — "nothing was
   checked" — is separate from "clean" and must not be dressed as it.
2. **API version pinning is not modelled at all.** A caller pinned to an older
   Stripe/Plaid version is not affected by a change to the latest, and nothing
   looks for a pin.
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

## `pr_enabled: false`

Recorded in `lead_audit.json` → `scan_standing`. **There is no write path in
this tool and there should not be one** until a fourth adversarial audit samples
IMPACTS from `scan.py` against real repositories.

Opening a pull request into someone else's repository is a larger outward-facing
act than sending an email, and `gate.sh` already refuses to let the email ship.
The `schema_removed` blocker fix **is implemented** in `dependence.py` — a proof
now requires a read of one of the deleted schema's own field names, and generic
names cannot carry it — but it is **NOT YET AUDITED**, so `lead_precision` and
`sendable` stay where they are.

Do not add a PR path, an auto-commit, or an email send. Do not flip
`sendable`. Those are Sam's calls after an audit, not a coding decision.

---

## Commands

```bash
./gate.sh                                          # the only proof. ~65s. expect exit 3
./.venv/bin/python -m unittest discover -s tests   # layer 1 —  0.1s (212 tests)
./.venv/bin/python tests/mutation_check.py         # layer 2 — 21.7s (93 mutations)
./.venv/bin/python tests/measure_precision.py --sample 1000 --severity breaking
                                                   # layer 3 — 12.6s per severity
./.venv/bin/python -m apidrift.cli --days 90 --quiet
                                                   # layer 4 — 18.2s
./.venv/bin/python -m apidrift.cli scan ~/somerepo --days 30
./.venv/bin/python -m apidrift.cli scan ~/somerepo --opportunities
```

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
- **`apidrift/snapshot.py` has NEVER BEEN RUN.** It records the 14 vendors who
  publish a spec but no history. Two hazards are already encoded from the
  survey: Google randomises JSON key order per response (raw-byte hashing would
  report a change every day forever), and four vendors return HTTP 200 with an
  HTML error page (every body is validated before storage). A gap in the
  archive is visible; a bad record is not.
- **Commit messages carry the reasoning.** They are the design record for this
  project and several were the only place a defect was ever explained. Keep
  writing them that way: what was wrong, what it looked like, why the previous
  code believed itself, and the test/mutation counts.
