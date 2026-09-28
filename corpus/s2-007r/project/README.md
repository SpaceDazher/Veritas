# THE ONE PROJECT of S2-007R (issue SpaceDazher/Veritas#45)

A three-task, deterministic, dependency-free Node project. It exists so that a
comparison between two executor configurations is a comparison of *the same
bytes* every time: `project_digest` is the sha256 of the sorted
`relative path -> {bytes, sha256}` map, and anyone with a clean checkout can
recompute it.

```
node corpus/s2-007r/project/verify.mjs <task_id>   # exit 0 = the task's criterion is met
node --test corpus/s2-007r/project/src/calc.test.js # the five pre-existing tests
```

## The three tasks

| id | task | the oracle checks |
| --- | --- | --- |
| `T1` | fix the off-by-one in `sumRange(lo, hi)` in `src/calc.js` | `calc.test.js` passes AND `sumRange(1, 4) === 10` (inclusive of `hi`) |
| `T2` | implement the two functions `src/parse.js` documents and does not define | `parse.test.js` passes AND `parsePairs('a=1,b=2')` deep-equals `{a:'1', b:'2'}` |
| `T3` | behaviour-preserving refactor of `src/calc.js` (no behaviour may change) | the `T1` criterion AND the `T2` criterion still hold, i.e. the refactor is a no-op on observable behaviour |

No task needs a network, a credential, a dependency or a model. `verify.mjs` is
the single deterministic oracle every measurement of SPEC §5 is computed from,
and it is the same oracle before and after a run, which is what makes
measurement 6 (regression rate) recomputable.

## Why it is in the repository and not in /tmp

Round 1 of this ticket created the fixture ad hoc under `/tmp`, which made the
comparison's `project_digest` unrecomputable by anyone who was not the machine
that ran it. It is tracked here instead, and `scripts/s2-007r-run.mjs`
materialises a FRESH copy per run into the workspace root, so run N+1 never
inherits run N's edits and the copy's digest is compared with the source's.
