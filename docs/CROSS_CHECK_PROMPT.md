# Independent audit request: kill, pivot, or continue?

You are auditing a solo founder's project to decide whether it should continue,
change shape, or be abandoned. Another AI has been building it and is the source
of the summary below — treat that as a conflict of interest and weight the
evidence accordingly.

**Before you answer, search the web.** Several of the questions below turn on
what already exists commercially, and a confident answer without checking is
worse than no answer.

**Do not be agreeable.** The person asking is 18, working alone, has shipped
three products with zero paying customers between them, and has roughly four
weeks before a move that ends focused work. A diplomatic answer that lets a dead
project continue costs him a month. If the honest answer is "abandon this",
say that in the first line. Do not hedge with "it depends." Give a verdict.

---

## What the project is

`apidrift` — a semantic OpenAPI breaking-change engine, ~8,800 lines of Python,
one dependency, 81 commits, started 2026-08-19 (three days ago). Never pushed to
any remote. Never deployed. No landing page, no pricing page, no users, no
outreach ever sent, $0 revenue.

It does two things:

1. **The report** — diffs a vendor's published OpenAPI spec across a time window
   and reports which changes could break a caller. 32 vendors tracked
   (Stripe, OpenAI, GitHub, Twilio, Plaid, Cloudflare, PayPal, Klaviyo, …).
2. **The scan** — `apidrift scan ~/myrepo` claims which of those changes break
   code in a specific repository, per file and per line, with a proof chain.
   Intended as a CI gate.

It was positioned against Y Combinator's Fall-2026 request-for-startups item
"Self-Maintaining APIs."

## What has actually been measured

The engine's **spec-diff** claims are well verified. A six-layer test gate:
487 unit tests, 264/264 mutation tests killed, an independent precision checker,
and recall controls. Precision on spec-diff findings: 100% on the 5-vendor gate
population, 92.1% (1332/1447) across all 32 vendors. That number reached 92.1%
via 96.3% → 67.8% → 96.7% → 77.8% → 92.1%, each drop being the checker learning
to decide findings nobody had checked.

The **product** claims have failed every test they have ever been given:

- **Cold-outreach leads** ("your public repo is broken by this vendor change"):
  three separate adversarial audits refuted **9/10, 9/10 and 10/10** sampled
  leads. Lead precision stands at 0/10. Outreach has never been sent because a
  gate blocks it.
- **Repo scanning**: 22 real open-source products that genuinely call these
  vendors were scanned. At the default 90-day window: **0 impacts**. That was
  read as precision for a day. At a 3-year window: 414 impacts. A fourth
  adversarial audit sampled 74 of them, stratified, with independent skeptics
  and two refuters per surviving claim:

  > **74 impacts audited. 0 real. 66 false. 8 in test files.**
  > Impact precision **0%** — in the same run where spec-diff precision was 100%.

- **The structural finding.** For any vendor that serves *dated API versions*
  (Stripe, Plaid, Klaviyo, Square), the caller's SDK pins the version it shipped
  with, so the vendor keeps serving the old shape. A diff of the vendor's spec
  at HEAD therefore says nothing about a caller on an SDK. Verified concretely:
  `stripe-node` v17.4.0 sends `Stripe-Version: 2024-11-20.acacia`, v18.5.0 sends
  `2025-08-27.basil`, v19.0.0 sends `2025-09-30.clover`. The single most
  convincing "break" the tool ever produced — a real company reading a field
  Stripe genuinely removed — is not a break, because their SDK is pinned behind
  the removal. **281 of the corpus's files are pinned this way.**
- Six false-positive classes were then fixed, taking 414 impacts down to 65.
  Those 65 have **not** been audited. The two largest remaining clusters were
  both already judged false by the audit.
- A separate, independently written tool (`oasdiff`, 1.3k stars) was run on the
  same Stripe spec pair as a cross-check. It emitted **577,044** breaking
  changes where apidrift emitted 4. Filtering its two noisiest rule types left
  10, of which 4 were distinct, and hand-checking those found **2 genuine gaps
  in apidrift** and 1 severity disagreement.
- Performance: scanning one large repository (PostHog) takes **16 minutes 39
  seconds**.
- Base rates from the data: across the 5 primary vendors in 90 days there were
  45 breaking changes, versus 112 new endpoints and 332 new optional fields.
  The additive surface is roughly 5× the breaking one.

## The pivot currently proposed

Because SDK callers are pinned, the break is real but its *trigger* is the
dependency upgrade, not the spec edit. So: when a developer bumps
`stripe-node` from 17 to 19, diff the API version the old SDK pinned against the
one the new SDK pins, and report which lines of their code break. The mapping
from SDK release to API version is mechanically readable from each SDK's source.
The claim is that Dependabot/Renovate open that upgrade PR and say nothing about
which of your lines break.

## The founder's wider situation

- Solo, 18, ships fast, has shipped and launched before.
- Two other live products: a consumer web product at $29 one-off (live, **zero**
  customers, ~$15 of ads spent, and the one live campaign is optimising for
  traffic rather than purchases), and an iOS app (184 installs, 0 subscriptions,
  $4.20 lifetime revenue).
- Stated goal: **first paying customer as fast as possible.**
- Roughly four weeks of focused time remain.

---

## What I want from you

Answer these directly. Lead with the verdict.

1. **Verdict: continue / pivot / abandon.** One line, first line of your reply.
2. **Is the proposed pivot (SDK-upgrade diff) a real product with a real
   buyer?** Research before answering: does Stripe already ship upgrade guides
   or codemods that cover this? Do Stainless or Speakeasy (SDK generators), or
   Optic, oasdiff, openapi-changes, Dependabot, Renovate, or anyone else already
   do it? How often does a team actually bump a major SDK version — is the pain
   frequent enough to be a purchase? Who signs the invoice, and what would they
   pay?
3. **Is the whole category wrong?** Consider seriously that four adversarial
   audits returning 0/10, 0/10, 0/10 and 0/74 is the market telling him breaking
   changes are too rare and too well-handled by vendors to be a product. If so,
   say it plainly.
4. **The strongest argument for abandoning.** Make it properly, not as a
   formality.
5. **The strongest argument for continuing.** Same standard.
6. **What is the highest-expected-value use of the next four weeks?** It does
   not have to be this project. He has a live product with zero customers, which
   may mean the portfolio's bottleneck is distribution rather than product. If
   the answer is "stop building and go sell what already exists," say so.
7. **What has the building AI missed?** It has been inside this for three days
   and is the author of every number above. Name the blind spot.

Be specific and be brief. Prefer numbers and named companies to adjectives.
Where you are uncertain, say so and say what evidence would resolve it — do not
pad. If you find the summary above internally inconsistent or self-serving,
attack it; that is a useful result.
