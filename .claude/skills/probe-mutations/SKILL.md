---
name: probe-mutations
description: Apply each mutation in tests/mutation_check.py one at a time and report which tests ACTUALLY go red. Use when adding a mutation, when the gate reports SURVIVED or STALE, or before trusting a new mutation's expectation list.
---

# probe-mutations

`mutation_check.py` requires **every** test named in a mutation's `expect` list
to go red. An over-broad list therefore reports `SURVIVED` on a mutation that
was killed, and sends you hunting for coverage that already exists.

On 2026-08-21 four of eight new mutations reported SURVIVED for exactly that
reason, and two more survived for a real one — tests that passed without ever
reaching the code under test, because their fixtures carried no vendor evidence
and `verify_source` stopped at `NO_VENDOR` first. A green suite never mentions
either.

## Run it

```bash
cd ~/apidrift && ./.venv/bin/python .claude/skills/probe-mutations/probe.py "substring of the mutation name"
```

With no argument it probes every mutation, which takes as long as the full
harness. Pass one or more name substrings to probe a few.

For each it prints `KILLED` / `SURVIVED` / `STALE` and, decisively, **the exact
set of tests that went red**. Copy that set into the mutation's `expect` list.

## How to read the result

| Result | Meaning | Fix |
|---|---|---|
| `KILLED` + red set matches `expect` | the behaviour is covered | nothing |
| `SURVIVED`, red set NON-empty | the expectation is too broad | narrow `expect` to the red set |
| `SURVIVED`, `red: nothing` | **the behaviour is genuinely untested** | write a test, then re-probe |
| `STALE` | the needle moved under it, so nothing was mutated | repair the needle |

🚨 **`SURVIVED` with an empty red set is the only one that means what the gate
says it means.** Treating the other two as missing coverage wastes the time this
skill exists to save.

🚨 **Never widen a test to make a mutation pass.** A mutation that two checks
both catch will only redden one test — that overlap is a MEASUREMENT that both
checks earn their place, not a defect. The 2026-08-21 positional filter is the
worked example: reach already refuted three of its four cases.

🚨 **Address-reuse mutations cannot be probed reliably.** An `id()`-keyed cache
failed the suite on one run and passed on the next. Assert the KEY, not a forced
collision — a coin flip is not a gate.
