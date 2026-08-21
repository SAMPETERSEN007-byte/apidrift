# apidrift is shelved — 2026-08-21

Do not restart this without meeting the resume condition at the bottom. The
engine is good. The engine was never the problem.

## The one experiment that ends it

apidrift's most convincing output was: langfuse reads
`subscription.current_period_start`, which Stripe removed. The proposed pivot
was to report that at the moment a team bumps their SDK across the version
boundary.

The TypeScript compiler already does it, reproducibly:

```
/tmp/tsctest, one file containing langfuse's exact line

stripe@17.4.0 (2024-11-20.acacia) → tsc exit 0, compiles
stripe@19.0.0 (2025-09-30.clover) → tsc: error TS2339:
    Property 'current_period_start' does not exist on type 'Response<Subscription>'
                                                                      0.43 seconds
```

Same finding. 0.43s versus apidrift's 16m39s on PostHog. Zero false positives
versus 0/74 real. Free, and already inside a build every TypeScript team runs.

A typed SDK ships types generated from the same spec apidrift diffs. Diffing the
spec to predict what the types will say is doing the compiler's job, worse and
later. This was visible in this project's own audit output — a refuter wrote
"the v17.4.0 type definitions still declare `current_period_start: number`,
which is why the file typechecks" — and nobody drew the conclusion for a day.

## The rest of the case, briefly

- **Four adversarial audits, four near-zero results.** Leads: 9/10, 9/10, 10/10
  refuted. Impacts: 74 sampled, **0 real**.
- **The base rate is against it.** 5 vendors / 90 days: 45 breaking changes vs
  444 additive. 22 real repos at a 90-day window: 0 impacts.
- **Vendors already solved it.** Dated version headers plus pinned SDK releases
  mean a vendor-side change never reaches a caller unannounced. The break only
  ever arrives when the caller chooses to upgrade — see above for who catches it
  then.
- **A funded competitor died.** `opticdev/optic`, 1,535 stars, archived
  2026-01-08.
- **The exact pitch is already taken.** `mendapi/mendapi` — "Dependabot for
  APIs — detect upstream API breaking changes, scan your codebase for impact,
  generate the fix PR." Created 2026-07-28. Tiny (1 star), but there.
- **Wrong sales motion for the deadline.** CI tooling needs trust, security
  review and team approval. The goal was a paying customer inside four weeks.

## What is actually worth keeping

The **spec-diff half** is verified and genuinely good: 100% precision on the
5-vendor gate population, 92.1% across all 32 vendors, 487 tests, 264/264
mutations, six gate layers plus an independent oracle. If a use ever appears for
"what did this vendor change, decided correctly", it is here and it works.

The **repo-scanning half** is the part that measured 0%. It is the part the
business depended on.

## Resume condition

Restart only if **a specific person offers to pay for a specific output**, in
writing, having seen a sample. Not on a new idea for the engine. Not on a
technical improvement. Not on a YC RFS line item. Four adversarial audits and
one 0.43-second compiler run say the demand is not there; only a buyer
overturns that.
