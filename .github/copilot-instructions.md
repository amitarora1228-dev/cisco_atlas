---
applyTo: "**"
---

# ATLAS

Full working instructions are in [`AGENTS.md`](../AGENTS.md) at the repository
root. Read it. The points below are the ones that cause real damage when missed.

## Read the state, then update it

Read [`docs/STATE.md`](../docs/STATE.md) before starting: it holds current
status, known limitations and the traps already paid for.

**Update it in the same change that makes it out of date** - when you finish or
abandon work, discover a limitation, hit a trap, take a decision, or move the
head commit. Do this without being asked. Delete what has stopped being true; a
stale state document is worse than none, because it is believed.

## Evidence or nothing

A finding must cite what produced it. Where the inputs cannot answer a question,
say so instead of guessing. Correlated findings must cite both the declared and
the observed side. Most of this product's value is in what it refuses to claim.

## Never commit evidence

Captures, HARs, TLS key logs and DART bundles are ignored at the repository root
and CI fails if one appears. A capture plus its key log decrypts the session it
recorded; real DART bundles here have contained employee email addresses and
internal hostnames. Git history is permanent - sanitising later does not work.

## Wrap the engines, do not rewrite them

Move engine nodes rather than rebuilding them so their listeners survive; hand
files to each engine's own file input; drive its real controls from proxies. Both
engines carry validated detection logic that is expensive to re-derive and easy
to lose silently.

## Verify against reality

Run it and check the served file, the rendered DOM, the actual response. When a
change appears to have no effect, suspect a stale cache or a missing restart
before editing the code again - uvicorn does not use `--reload`, and Jinja caches
templates. State measured numbers, not estimates, and correct your own earlier
claims plainly when they turn out to be wrong.

## Before calling something done

`pytest -q` and `ruff check packages/atlas_core apps tools` must both be clean.
If you changed behaviour a test asserted, update the test and say so - a
deliberate contract change and a regression look identical in a diff.

## Before committing - mandatory, in this order

Nothing is committed until all four are done, and they are part of the change
rather than paperwork that follows it. A record written later is written from
memory, which is what this discipline exists to replace.

1. **Update [`CHANGELOG.md`](../CHANGELOG.md)** - what changed and why it
   mattered, with measured numbers, recording what was verified rather than
   intended.
2. **Update the documentation the change makes untrue** - always
   [`docs/STATE.md`](../docs/STATE.md), plus whatever else describes the
   behaviour you altered.
3. **Re-examine [`docs/IMPROVEMENTS.md`](../docs/IMPROVEMENTS.md)** - delete what
   you fixed, add what you revealed, including weaknesses you chose not to
   address or introduced. Every entry cites its evidence.
4. **Run the gates above.**

Delete what has stopped being true. A stale record is worse than none, because
it is believed.

