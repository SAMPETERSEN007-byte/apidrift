---
name: corpus-sweep
description: Scan every repo in /tmp/corpus with apidrift and write one JSON of all impacts, for before/after comparison. Use when changing the prover, a suppressor, or anything that can move the impact count.
---

# corpus-sweep

The only way to know what an engine change did to REAL output. The unit suite
and the gate both stayed green through a change that took the corpus from 414
impacts to 65, and through the change that put them there in the first place.

## Run it

```bash
cd /tmp && /Users/claudebot/apidrift/.venv/bin/python \
  /Users/claudebot/apidrift/.claude/skills/corpus-sweep/sweep.py \
  /Users/claudebot/apidrift 1095 /tmp/sweep_after.json
```

Arguments: the apidrift checkout to run, the window in days, the destination.
Six workers. Prints one line per repo and a total.

## Getting an honest BEFORE

🚨 **Do not edit the tree while a sweep runs.** Each repo is a fresh subprocess,
so repos scanned after an edit use the new code and the run is a silent mix of
two engines. That happened on 2026-08-21 and the whole sweep had to be redone.

Use a detached worktree for the baseline:

```bash
git -C ~/apidrift worktree add /tmp/apidrift-before HEAD --detach
ln -sfn ~/apidrift/.cache /tmp/apidrift-before/.cache   # the caches are large
```

Then sweep `/tmp/apidrift-before` and `~/apidrift` and diff the two JSONs.
Remove the worktree afterwards (`git worktree remove --force`).

## The corpus

22 real products that genuinely call tracked vendors, cloned `--depth 1` into
`/tmp/corpus`. `tools/corpus_scan.py` names four of them and holds a
hand-verified baseline; this sweep is the wider, unbaselined version.

## Reading it

- 🚨 **The window is the first thing to check, not the count.** `--days 90` on
  code written years ago produced 0 impacts across all 22 and that was read as
  precision for a day. 1095 days on the same repos produced 414.
- 🚨 **A smaller count is not a better engine.** It is a claim that needs the
  `audit-impacts` skill run against it, one impact at a time.
- Watch `pinned_files` and `incidental_count` as well as `impact_count`: work
  moving into those buckets is the tool declining to answer, which is a
  different thing from finding nothing.
- posthog alone takes ~17 minutes. Budget for it or exclude it while iterating.
