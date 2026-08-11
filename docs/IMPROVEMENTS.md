# Where ATLAS should improve next

A standing list of what is worth improving, why, and what it would cost. Kept
current alongside [`CHANGELOG.md`](../CHANGELOG.md) and
[`STATE.md`](STATE.md) - see [`AGENTS.md`](../AGENTS.md) for the rule.

**Every entry cites the evidence that produced it.** Where a claim rests on a
single observation, or on reasoning rather than measurement, it says so. An
improvement list built on impressions is how work gets done in the wrong order.

Ordered by the ratio of harm done to effort required.

---

## 1. Concurrent analyses serialise, and the UI cannot say so

**Evidence.** Measured: the YouTube capture alone completes in ~6 s. Alongside a
full bundle analysis the pair takes two to three minutes, during which both
panes show static "Analysing…" text. Both requests return 200 and both panes
render correctly - it is a throughput problem, not a failure. Server process
observed at 88.6 % CPU throughout, single process, no children.

**Why it matters most.** This has already been reported twice as "it is not
working". A wait with no progress is indistinguishable from a hang, and the
first instinct is to reload - which throws away the work and starts it again.

**Options, cheapest first.**

1. ~~**Say what is happening.**~~ **Done.** The notice names what is in flight
   and ticks an elapsed time, so a long run is no longer indistinguishable from
   a hang. It is not per-check progress - it does not say *which* check is
   running or how many remain - so the wait is still opaque, only visibly
   alive.
2. **Report real progress**, check by check, which needs a progress channel
   from the server rather than a client-side timer.
3. **Do the CPU-bound work off the event loop** in a process pool, so the two
   analyses genuinely run in parallel rather than contending.
4. **Stream results as they arrive** instead of one response at the end.

**Recommendation:** measure whether the elapsed-time notice alone closes the
complaint before paying for (3). It is the real fix but a much larger change,
and it is worth knowing whether the problem was the duration or the silence.

---

## 2. The bundle engine re-extracts the archive on every check

**Evidence.** Recorded in STATE.md at ~1.3 s per check, and the dominant cost of
a run-everything. It scales with bundle size; the 358 MB test bundle is slow.

**Why it matters.** It is also the largest contributor to problem 1 above, so
fixing it improves both.

**What it needs.** Separating extraction from analysis inside the engine, so one
upload is unpacked once and every check reads the same tree. This means editing
engine internals rather than wrapping them, which AGENTS.md §4 requires be
called out explicitly - it should be done deliberately, with the golden tests in
place first.

---

## 3. JA3/JA3S fingerprinting is permanently dark on this machine

**Evidence.** Wireshark 3.4.7 installed; `tls.handshake.ja3` and `ja3s` arrived
in 3.6. The analysis no longer fails - the fields are dropped and a note names
them - but the JA3S clustering check for a shared TLS terminator produces
nothing.

**Why it matters.** The silence of a detector is not evidence of absence, and
the note says so. But an interception signal that cannot run is a real gap in
coverage, not merely a cosmetic one.

**What it needs.** Upgrading Wireshark past 3.6 on the deployment host. Nothing
in the code changes; the probe picks the fields up automatically. The deployment
image should pin a minimum version so this cannot silently regress.

---

## 4. `network_info` findings are computed and never displayed

**Evidence.** The category is missing from the capture engine's five
`CLASSIFICATION_*` tables, so its findings are computed, returned by the API,
and dropped by the UI.

**Why it matters.** This exact failure has shipped twice. It is silent by
construction: the API is correct, the analysis is correct, and only the screen
is wrong.

**What it needs.** Registering the category - and, more usefully, a test that
asserts every category the engine can emit appears in all five tables, so the
third occurrence is caught by CI rather than by a user.

---

## 5. Correlation coverage is bounded by how the agent logs

**Evidence.** 680 of 688 host-named lines in the test bundle were error level.
With trace-level logging off the agent records the destination mainly when it
has a problem to report. On the YouTube session, HAR hosts and ZTA-named hosts
had **no** overlap: those flows were steered - 127 loopback flows with SNI prove
it - but nothing failed at the ZTA layer, so no host-named line exists.

**Why it matters.** The tool states this honestly in a note, and a test asserts
the note. But it means the flow view is a list of *problem* flows, and a reader
who wants "show me every flow" will not get it from these inputs.

**Options.**

- Document, in the UI, that enabling ZTA trace-level logging before reproducing
  an issue produces materially better correlation. This is guidance, not code.
- Investigate whether any other file in the bundle names successful flows.
  **Not yet checked** - this is a hypothesis, not a finding.

---

## 6. The engines still render their own results

**Evidence.** STATE.md §2: the destination is one findings model, one severity
scale, one report, with the engines reduced to analysis libraries. Today they
share a page, a header, a rail, an Analyze button and now a report - but each
still builds its own results DOM.

**Why it matters.** Every cross-cutting feature so far - the unified report, the
correlation view, the rail highlight - has had to work around this. The cost is
paid again on each new feature.

**What it needs.** A shared findings schema both engines emit, then one
renderer. Large, and worth doing only when the next cross-cutting feature would
otherwise pay the tax a fourth time.

---

## 7. Testing gaps that let real bugs through

**Evidence.** Six bugs reached the user during recent work that a test could
have caught: the `offsetParent` visibility guard, the HAR-only rows, the stale
cache-buster, the bundle-only view, the Report view being unreachable without a
capture, and a run displaying the previous run's results. All are frontend
behaviour in the shell seam; the suite is 55 tests and entirely Python.

**Why it matters.** The pattern is now unmistakable - the engines are tested,
the *shell* that composes them is not, and every one of those bugs lived in the
seam. Two were the same shape: a shell contribution rendered into a subtree the
engine keeps hidden. Two more were state surviving longer than the run that
produced it.

**What it needs.** A small browser-level test covering the paths a user actually
takes: each artefact alone, each pair, all three, and each rail destination
after each. It does not need to assert appearance, only that results become
**visible** - zero height is a recurring failure mode - that no path leaves the
reader on a page with nothing on it, and that **no run displays output from the
previous one**.

---

## 8. Smaller items

| Item | Evidence | Effort |
|---|---|---|
| Tailwind loads from a CDN | Console warns it is not for production | Small |
| Three fonts load from Google | STATE.md limitation 5 | Small |
| `_regress_baseline.json` is stale | STATE.md limitation 7 | Small |
| VPN, Umbrella, UZTNA, EDLP modules unimplemented | Rail entries exist; no analysis behind them | Large |
| A HAR remains in git history at `6bd709c` | Removed in `df16b9e`, blob still reachable; needs a force push, not done unilaterally | Decision needed |

---

## What is deliberately *not* on this list

- **Making correlation claim more.** The refusals - unmeasured clock offsets,
  ambiguous joins, hosts with no handshake - are the product working correctly.
  Several would look better as confident output and would be wrong.
- **Removing the notes.** They are the least popular part of the output and the
  most defensible.
