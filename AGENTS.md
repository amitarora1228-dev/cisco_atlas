# Working on ATLAS

Instructions for any agent or engineer working in this repository. They are not
optional and they are not a style guide - each one exists because ignoring it
has already caused a real failure here.

---

## 1. Read the state, then update it

**Before you start:** read [`docs/STATE.md`](docs/STATE.md). It says what exists,
where each piece stands, what is known to be broken, and the traps that have
already cost time.

**Before you finish:** update it. In the same change, not afterwards, and not
only when someone asks.

Update it when you:

- finish or abandon a piece of work
- discover a limitation or a bug you are not fixing now
- hit a trap worth recording so the next person does not repeat it
- take a decision that constrains later work
- change the head commit

**Delete what has stopped being true.** A stale state document is worse than no
document, because it is believed.

---

## 2. What this project is trying to become

Two engines - a packet-capture analyzer and a Cisco DART bundle analyzer - are
being merged into one tool. Two things define the destination:

1. **100 % unification.** Today they share a page, a header, a rail and an
   Analyze button but still render their own results. The end state is one
   findings model, one severity scale, one report, with the engines reduced to
   analysis libraries behind a single interface.
2. **Correlation that makes each engine smarter than it is alone.** The bundle
   knows what was *configured*; the capture knows what *happened*. Where they
   disagree is a finding neither could produce by itself. See
   [`docs/PHASE2_CORRELATION.md`](docs/PHASE2_CORRELATION.md).

---

## 3. The rule that governs the product

> **Evidence or nothing.** A finding must cite what produced it. Where the inputs
> cannot answer a question, say so instead of guessing.

This is enforced in code, not merely documented: confidence is capped where a
conclusion is not provable, percentages are withheld when the populations being
compared are not comparable, and detectors are suppressed when other evidence in
the same input contradicts them.

Correlated findings extend it - they must cite **both** sides, so a reader can
see which half is measurement and which half is declaration.

Most of this product's value is in what it refuses to claim. Do not add a finding
that sounds confident and cannot be defended from the input.

---

## 4. Wrap the engines; do not rewrite them

Both engines carry validated detection logic that is expensive to re-derive and
easy to lose silently. The shell therefore **rearranges what already exists**:

- **Move** engine nodes rather than rebuilding them - a moved node keeps its
  event listeners, so the control still works with no change to that engine's
  code.
- Hand files to each engine's **own** `<input type=file>` so its existing
  handlers, validation and analysis flow run untouched.
- Drive an engine's real controls from **proxies**; do not relocate the controls
  themselves.

If a change requires editing an engine's internals, say so explicitly and explain
why wrapping was not enough.

---

## 5. Never commit evidence

Packet captures, HARs, TLS key logs and DART bundles are ignored at the
repository root, and CI fails the build if one appears.

They are not merely large. A capture plus its key log decrypts the session it
recorded; a HAR carries full HTTP traffic including headers and cookies; a DART
bundle carries endpoint and organisation identifiers, and real ones here have
contained employee email addresses and internal hostnames.

**Git history is permanent.** "Sanitise it later" does not work for anything
already pushed. This has happened once on this branch already.

---

## 6. Verify against reality, not against your own code

- Run it. Check the served file, the rendered DOM, the actual response.
- When something appears to have no effect, suspect a cache or a restart before
  changing the code again. Both have wasted time here.
- State measured numbers, not estimates.
- If you were wrong earlier, correct it plainly in the same place you said it.

---

## 7. Practical traps

The full list is in [`docs/STATE.md`](docs/STATE.md) §6. The ones that catch
people most often:

- **Restart after Python changes** - uvicorn does not use `--reload`.
- **Restart after template changes** - Jinja caches compiled templates.
- **Shell assets are cache-busted by modification time**; browsers will happily
  serve a stale stylesheet otherwise.
- **Shell CSS loads after the engines**, because both were written assuming they
  own the document. One engine also uses `!important`.
- **A new finding category must be registered in all five `CLASSIFICATION_*`
  tables** in the capture engine, or it is computed and never displayed. This has
  shipped twice.
- **PowerShell mangles quotes in commit messages** - use `git commit -F <file>`.

---

## 8. Before you call something done

```powershell
& .venv\Scripts\python.exe -m pytest -q
& .venv\Scripts\python.exe -m ruff check packages\atlas_core apps tools
```

Both must be clean. If you changed behaviour that a test asserted, update the
test **and say so** - a deliberately changed contract and a regression look
identical in a diff, and only one of them is acceptable.
