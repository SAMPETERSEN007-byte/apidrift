---
name: audit-impacts
description: Run the adversarial audit of scan.py IMPACTS against real repos and raw specs — stratified sample, independent skeptics, two refuters per surviving claim. Use before changing pr_enabled or sendable, and after any change that moves the impact population.
---

# audit-impacts

The gate has six layers and **none of them measures an impact.** Layer 4 audits
findings against the raw spec; layer 6 proves the scanner can fire on a fixture.
The claim `scan` actually ships — "this change lands on THIS line of YOUR repo"
— went unmeasured until 2026-08-21, and when it was measured it was **0%**:

> 74 impacts audited. 0 REAL. 66 FALSE. 8 TEST_ONLY. 0 UNDECIDABLE.

The findings engine measured 100% in the same run. A claim about a SPEC and a
claim about a REPO are different claims and one is not evidence for the other.

## Run it

1. Sweep the corpus (`corpus-sweep` skill) to produce `sweep_after.json`.
2. Build a stratified sample — up to 6 per `(kind, vendor)` pair, max 3 per repo
   per stratum, `audit_id` assigned in order — and write it to
   `audit_sample.json`.
3. Edit the `SAMPLE` path and `N` in `audit.js`, then
   `Workflow({scriptPath: ".claude/skills/audit-impacts/audit.js"})`.

The script fans out ~13 skeptics over batches of 6, sends every claim that
survives to two more refuters with different lenses (the code path, the spec
document), and synthesises the mechanisms with counts.

## Rules that make the number mean something

🚨 **Auditors must read the RAW document, never the engine's summary.**
`tools/spec_snapshot.py <vendor> <old-date> <new-date>` extracts both ends to
`/tmp/apidrift-audit/`. It parses nothing and decides nothing; an auditor using
the engine's own resolver inherits the engine's blind spots, which is this
project's most-repeated defect.

🚨 **Refute by default.** Three prior audits refuted 9/10, 9/10 and 10/10. The
base rate of these claims being wrong is high.

🚨 **REAL requires both halves**: the production line whose behaviour changes,
and the raw-spec fact that makes it so. Either alone is not a finding.

🚨 **`TEST_ONLY` and `UNDECIDABLE` are their own buckets and are excluded from
the ratio**, never counted as passes.

## What the audit found that nothing else could

- **A read is a position, not a word.** `subscription.currency` returned as a
  read of `<deleted_discount>.coupon.currency`. 21 of 74.
- **A member chain needs provenance.** A local list's `.append` reported as "the
  SDK form of" a GitHub endpoint; the `secrets` stdlib module reported three
  times as GitHub's secret endpoints.
- **A dated API version is not HEAD.** The most convincing impact this tool has
  ever produced — langfuse reading a field Stripe really removed — is not a
  break, because `stripe-node@17.4.0` sends `2024-11-20.acacia`. Both refuters
  killed it and both were right. **A correct spec fact is not a correct claim
  about a repository.**

## Before you touch `pr_enabled` or `sendable`

🚨 **A smaller population is not a measured one.** Every class closed since the
fourth audit removes members of the sample it was drawn from, so the surviving
population is unaudited. A fifth audit must sample what survives — and must
include raw-HTTP callers specifically, because pinning removed every SDK caller
of the biggest vendor from the judgeable population.

Record the result in `lead_audit.json → scan_standing.audits`. Editing that file
to make the gate go green forges the one record that stops bad outreach
shipping.
