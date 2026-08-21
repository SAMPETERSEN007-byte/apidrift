export const meta = {
  name: 'apidrift-impact-audit',
  description: 'Adversarially audit scan.py IMPACTS against real repos and raw specs',
  phases: [
    { title: 'Audit', detail: 'independent skeptics, ~6 impacts each, refute by default' },
    { title: 'Refute', detail: 'every impact called REAL gets two more skeptics' },
    { title: 'Synthesize', detail: 'name and count the false-positive mechanisms' },
  ],
}

const SAMPLE = '/private/tmp/claude-501/-Users-claudebot/9000cc67-1430-4d31-81d0-5e019b47d967/scratchpad/audit_sample.json'

const BRIEF = `
You are auditing a static-analysis tool called apidrift. It claims that a
breaking change in a third-party vendor's OpenAPI spec lands on a specific
LINE of a specific repository. Your job is to REFUTE those claims.

Context you must internalise before judging anything:
- Three previous audits of this tool's output refuted 9/10, 9/10 and 10/10
  claims. The base rate of these claims being wrong is HIGH. Default to FALSE.
- The single most common failure is CO-LOCATION masquerading as DEPENDENCE:
  the tool found the right WORD in the file, at the wrong PLACE. Example
  already fixed: it reported \`subscription.currency\` as a read of
  \`deleted_discount.coupon.currency\`. Same word, different object.
- The second most common failure: a change that is not breaking for a READER.
  A response type WIDENING (string -> string|array, or a oneOf gaining an arm)
  does not break code that reads the old shape when the old shape is still one
  of the alternatives. A field becoming OPTIONAL in a request is not breaking.
  A new OPTIONAL request field is not breaking. Adding an alternative
  security scheme (OpenAPI \`security\` is a list of ALTERNATIVES) is not breaking.
- The third: the cited line is in a TEST, fixture, example, mock or doc file.
  Say so explicitly — it is a distinct verdict reason from a wrong claim.
- The fourth: the code PINS an API version, or the repo vendors a copy of
  someone else's SDK, or the file is machine-generated.

How to check a claim. You have a shell.

1. Read the source. \`sed -n 'START,ENDp' <abs_path>\` around the cited line,
   generously (±30 lines) and follow the variable back to where it was assigned.
   The question is: does THIS line read/send the exact field named in
   \`subject\`, off an object that is the thing \`subject\` names?
2. Read the RAW spec at both ends of the window. Do NOT trust the tool's
   summary. Run:
     cd /Users/claudebot/apidrift && ./.venv/bin/python tools/spec_snapshot.py <vendor> <old-date> <new-date>
   using the dates in the impact's \`spec_window\`. It writes the raw spec files
   to /tmp/apidrift-audit/<vendor>/old/ and .../new/. Then grep/parse them
   yourself (python3 with json/yaml is available at
   /Users/claudebot/apidrift/.venv/bin/python) and answer: was the thing
   actually removed/retyped, and would a caller reading the OLD shape now break?
3. Only then decide.

A claim is REAL only if you can state BOTH:
  (a) the exact production line whose behaviour changes, and what it evaluates
      to now versus before, and
  (b) the exact spec fact, quoted from the raw document, that makes it so.
If you cannot produce both, it is not REAL.

Verdicts:
  REAL        - both (a) and (b), and the file is production code.
  FALSE       - you can show why it is not a break.
  TEST_ONLY   - the claim may be technically true but the cited file is a
                test/fixture/example/mock/doc.
  UNDECIDABLE - you genuinely could not resolve it. Use sparingly and say what
                blocked you. This is NOT a pass.

For every FALSE, give a short lowercase snake_case \`mechanism\` slug naming the
GENERAL rule the tool broke (e.g. \`response_type_widened\`,
\`read_at_wrong_position\`, \`security_alternative_added\`,
\`request_field_optional\`, \`field_still_present_in_new_spec\`,
\`operation_still_exists\`). Reuse slugs across impacts where the mechanism is
the same — the count per mechanism is the point of this audit.

Be exact and be brief. Do not hedge. Your output is a data record.
`

const VERDICT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['results'],
  properties: {
    results: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['audit_id', 'verdict', 'reason'],
        properties: {
          audit_id: { type: 'string' },
          verdict: { enum: ['REAL', 'FALSE', 'TEST_ONLY', 'UNDECIDABLE'] },
          mechanism: { type: 'string', description: 'snake_case slug, required when FALSE' },
          reason: { type: 'string', description: 'one or two sentences, concrete' },
          source_fact: { type: 'string', description: 'the code fact, with the line' },
          spec_fact: { type: 'string', description: 'the spec fact, quoted from the raw document' },
        },
      },
    },
  },
}

const REFUTE_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: ['audit_id', 'refuted', 'reason'],
  properties: {
    audit_id: { type: 'string' },
    refuted: { type: 'boolean' },
    mechanism: { type: 'string' },
    reason: { type: 'string' },
  },
}

// ---- slice the sample into batches -------------------------------------
const N = 74
const BATCH = 6
const batches = []
for (let start = 1; start <= N; start += BATCH) {
  const ids = []
  for (let i = start; i < start + BATCH && i <= N; i++) {
    ids.push('I' + String(i).padStart(3, '0'))
  }
  batches.push(ids)
}
log(`auditing ${N} impacts in ${batches.length} batches`)

phase('Audit')
const audited = await parallel(batches.map((ids, n) => () =>
  agent(
    `${BRIEF}

The impact records are in ${SAMPLE} (a JSON array). Read it and work ONLY on
these audit_ids: ${ids.join(', ')}.

Each record has: audit_id, repo, file, abs_path, line, kind, label, subject,
detail, old, new, operation, chain (the tool's own claimed proof), text (the
cited source line), vendor, spec_window.

Treat \`chain\` as the tool's ARGUMENT, not as evidence. Attack it.

Return one result object per audit_id, all ${ids.length} of them.`,
    { label: `audit:${n + 1}`, phase: 'Audit', schema: VERDICT_SCHEMA, effort: 'high' })
))

const flat = audited.filter(Boolean).flatMap(r => r.results || [])
log(`first pass: ${flat.length} verdicts`)

// ---- everything called REAL gets two more skeptics ----------------------
phase('Refute')
const claimed = flat.filter(r => r.verdict === 'REAL')
log(`${claimed.length} claimed REAL — sending each to two independent refuters`)

const refutations = await parallel(claimed.flatMap(r =>
  ['the code path', 'the spec document'].map(lens => () =>
    agent(
      `${BRIEF}

A previous auditor examined ONE impact and concluded it is a REAL break.
Your job is to REFUTE that conclusion. Assume it is wrong until you cannot
make it wrong. Attack specifically through **${lens}**.

The impact record is audit_id ${r.audit_id} in ${SAMPLE} — read it there.

The previous auditor's claim:
  reason      : ${r.reason}
  source fact : ${r.source_fact || '(none given)'}
  spec fact   : ${r.spec_fact || '(none given)'}

Re-derive everything yourself from the source and the RAW spec. Do not take
the previous auditor's facts on trust; several of this project's audits have
made raw-spec claims that did not re-derive.

Set refuted=true if the break is not real, or the cited file is not production
code, or the claimed spec fact does not hold in the raw document. Set
refuted=false ONLY if you independently reproduced both halves of the proof.`,
      { label: `refute:${r.audit_id}:${lens.split(' ')[1]}`, phase: 'Refute',
        schema: REFUTE_SCHEMA, effort: 'high' })
  )
))

const votes = {}
for (const v of refutations.filter(Boolean)) {
  votes[v.audit_id] = votes[v.audit_id] || []
  votes[v.audit_id].push(v)
}
const survived = claimed.filter(r =>
  (votes[r.audit_id] || []).filter(v => v.refuted).length === 0)
const killed = claimed.filter(r =>
  (votes[r.audit_id] || []).filter(v => v.refuted).length > 0)
log(`${survived.length} of ${claimed.length} REAL claims survived both refuters`)

phase('Synthesize')
const summary = await agent(
  `You are writing the standing record of an adversarial audit of a static
analysis tool. Be exact, be brief, and do not flatter the tool.

First-pass verdicts (JSON):
${JSON.stringify(flat)}

Refuter votes on the claims that said REAL (JSON):
${JSON.stringify(refutations.filter(Boolean))}

Produce:
1. counts by verdict, and precision computed as
   survived_REAL / (survived_REAL + FALSE + refuted_REAL), with TEST_ONLY and
   UNDECIDABLE reported as their OWN buckets and EXCLUDED from the ratio.
   Say explicitly how many were excluded.
2. the false-positive mechanisms, each with a count, ordered by count,
   each with one sentence stating the general rule the tool broke.
3. the impacts that survived both refuters, with repo, file:line, subject, and
   a one-line statement of the break — these are the only ones anybody may act on.
4. the single highest-value engine fix, and what it would cost in recall.
Return it as compact markdown.`,
  { label: 'synthesize', phase: 'Synthesize', effort: 'high' })

return {
  counts: {
    audited: flat.length,
    real_claimed: claimed.length,
    real_survived: survived.length,
    real_refuted: killed.length,
    false: flat.filter(r => r.verdict === 'FALSE').length,
    test_only: flat.filter(r => r.verdict === 'TEST_ONLY').length,
    undecidable: flat.filter(r => r.verdict === 'UNDECIDABLE').length,
  },
  survived,
  verdicts: flat,
  refutations: refutations.filter(Boolean),
  summary,
}
