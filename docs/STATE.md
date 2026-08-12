# ATLAS — project state

**This is the living state of the project. Read it first. Update it before you
finish.** It is the one place that says what exists, where each thing stands, and
what is known to be broken. If it disagrees with any other document, this file is
right and the other one is stale.

**Last updated:** 2026-08-11 · branch `main` · head `452ca7e` (snapshot-led bundle results, one view at a time)

---

## 1. What ATLAS is

One tool that diagnoses a Cisco endpoint from **both sides at once**:

| Engine | Input | Answers |
|---|---|---|
| **Traffic capture** (`packages/capture_inspector`) | PCAP/PCAPNG, HAR, optional TLS key log | What the endpoint **actually did** on the wire |
| **Endpoint bundle** (`packages/darthawk`) | Cisco DART ZIP | What the endpoint is **configured** to do, and what its software reported |

The bundle knows *intent and internal state*; the capture knows *what happened*.
Neither is sufficient alone, and that asymmetry is the entire product thesis.

### Where this is going

1. **100 % unification.** Today the two engines share a page, a header, a rail and
   an Analyze button, but still render their own results. The end state is one
   findings model, one severity scale, one report - the engines become analysis
   libraries behind a single interface, not two frontends in a trench coat.
2. **Correlation makes each engine smarter than it is alone.** Not a bolt-on
   feature: the capture can tell the bundle whether what it *believes* happened
   actually left the machine, and the bundle can tell the capture what was
   *supposed* to happen so an absence becomes a finding instead of a shrug. Full
   catalogue in [PHASE2_CORRELATION.md](PHASE2_CORRELATION.md).

**The principle both engines are built on, which unification must not dilute:**

> Evidence or nothing. A finding must cite what produced it. Where the inputs
> cannot answer a question, say so instead of guessing.

Correlated findings extend it: they must cite **both** sides, so a reader can see
which half is measurement and which half is declaration. `CorrelatedFinding`
enforces that at construction.

---

## 2. How it is put together

```
packages/
  capture_inspector/   FastAPI (ASGI). 26 modules, ~8.5k lines. Needs tshark.
  darthawk/            Flask (WSGI). 1 module, 8801 lines. Pure Python.
  atlas_core/          Shared facts + correlation. Phase 2 lives here.
apps/web/
  main.py              ASGI shell. Mounts both engines, serves the workspace.
  shell/workspace.py   Composes both engines into one document.
  shell/static/        atlas-tokens.css, atlas-shell.*, atlas-workspace.*
tests/                 unit / integration / golden
tools/                 ui_inventory.py and field scripts
deploy/atlas.service   systemd unit for the Linux host
docs/                  this file and the plans
```

### Why both engines still exist as-is

They were measured to be **accidentally compatible**, so neither frontend had to
be rewritten:

- **0 element-id collisions** (156 bundle ids vs 66 capture ids)
- **0 top-level JavaScript name collisions** (1 vs 58)

Porting one UI into the other would have meant re-deriving ~443 KB of frontend
logic across six analysis modules. That is where capability disappears quietly,
so it was rejected.

### How the workspace works

`/` composes one document: both engines' markup, styles and scripts, wrapped in
the ATLAS shell. The shell then **rearranges what already exists** rather than
rebuilding it:

- It **moves** engine nodes into the shared header and rail. Moving a node keeps
  its event listeners, so each control still works with no change to either
  engine's JavaScript.
- It hands files to each engine's **own** `<input type=file>`, so that engine's
  existing change handler, validation and analysis flow run untouched.
- Module choices in the rail are **proxies** that drive the engine's real radios.

If you are tempted to move or rewrite an engine's markup: don't. Wrap it.

### Run-everything results view (summary mode)

`renderBundleResults` in `atlas-workspace.js` used to insert its section above the
bundle engine's own upload page, which stayed visible underneath — two entry
points stacked on one document, reading as two different tools. It now puts
`is-summary` on `#atlas-engine-bundle`, and one CSS rule hides every direct child
except the results section. Nothing is removed or moved, so the engine's form,
file input and handlers are untouched; the class is dropped again by the
"Open bundle tool" button, by any rail module proxy, and by the Bundle analysis
rail entry.

The list itself is grouped by **the question each check asks**, because output
means opposite things across checks and a flat list of eight equal rows let a
2 812-line statistics dump and a 17-line setting read identically. The server
tags every check in `_BUNDLE_MATRIX` with a kind, fixed beside the declaration,
so the tag describes the check and asserts nothing about the bundle:

| Kind | Checks | Output means |
|---|---|---|
| `errors` | Enrollment Errors | a failure was reported |
| `mixed` | Configuration Sync, Server Connectivity Errors | nothing on its own - read the text |
| `state` | TND, User Pause, Inclusions/Exclusions, Duo Desktop | the configuration found |
| `logs` | Event Viewer Logs | log text carried through as-is |

**The two `mixed` entries are the trap.** Both are named like error checks and
were first tagged as such. Checked against a real bundle, neither is:
Configuration Sync returns a statistics report (100 requests, 100 successful,
`Failures since last successful sync: 0`) and Server Connectivity Errors always
prints `Proxy Connectivity: Ok` plus flow counts before any error lines. Both
produce output on a healthy client, so counting them would have made the verdict
banner announce "2 checks reported problems" on a bundle where none were
reported. Do not re-tag a check from its name - run it and read the output.

The verdict banner counts `errors` only, and when clear it says so without
claiming health. A check whose text is exactly `No matching logs found.` is
counted as **nothing found**, not as a finding. Only an `errors` check that
actually reported something gets a coloured accent or opens unasked; line counts
measure verbosity, not importance, so they are muted rather than headlined.

**The snapshot is the verdict, not our banner.** The bundle engine already builds
a ZTA Health Snapshot from the same upload, and it interprets - verdict,
severity, what it means, impact, suggested next steps, grouped plain-English
evidence. Showing our check list above it produced two answers to one question,
and on the test bundle they disagreed: the snapshot read *Degraded - review User
Pause* while our list read *no problems reported*. So `renderBundleResults` now
**moves** `#ztaSummaryPanel` to the top of the results and folds all eight checks
into one collapsed `All checks and full output`. Our banner survives only as the
fallback for a bundle the snapshot cannot speak for.

The snapshot node is moved, never rebuilt, so the engine's listeners survive, and
it is put back before the results are cleared and whenever summary mode is
dropped - clearing `innerHTML` with the node adopted would destroy it. The
checks are still worth keeping: the snapshot does not cover **Inclusions or
Exclusions, Duo Desktop or Event Viewer Logs**, and carries no full text.

**One view at a time, in both directions.** Summary mode hid the engine's page,
but leaving summary mode did not hide the results, so a stale results header sat
above a fresh form - the stacked-pages problem again, smaller. Results are now
hidden whenever `is-summary` is off. They are hidden, never discarded: a
`has-results` class puts a single **Back to summary** bar at the top of the
engine page, so clicking a rail module cannot lose a finished analysis.

---

## 3. Running it

```powershell
.\run.ps1          # Windows
./run.sh           # macOS / Linux
```

Both create the venv, install pinned dependencies, check for tshark and serve on
<http://127.0.0.1:8000>. Their argument syntax differs: `.\run.ps1 -Port 9000`
against `ATLAS_PORT=9000 ./run.sh`, and the host is `-BindHost` against a
positional argument. See the README for per-platform prerequisites.

Three things make the tree work on both platforms; do not undo them without a
replacement:

- **`.gitattributes`** pins `*.sh` to LF. A shell script checked out with CRLF
  dies on macOS with `bad interpreter: /usr/bin/env bash^M`.
- **`run.sh` is mode 100755.** It was committed 100644 once, which is a
  permission-denied on any Unix clone.
- **Both launchers uninstall `python-evtx`** before installing. `pyevtx-rs`
  replaced it, and the two cannot coexist on a case-insensitive filesystem -
  Windows, and macOS by default - because they install as `Evtx` and `evtx`.
  pip will not remove the old one just because it left `requirements.txt`.

macOS needs the Wireshark **formula**, not the cask: the cask leaves tshark
inside the app bundle and off PATH. `find_tshark()` checks the bundle path as a
fallback, but PATH is the supported arrangement.

| Path | What |
|---|---|
| `/` | The unified workspace |
| `/capture/`, `/bundle/` | Each engine standalone (still works) |
| `/healthz` | Engines, tshark version, degraded features |
| `/atlas/api/bundle/analyze-all` | Runs every applicable bundle check from one upload |
| `/atlas/api/correlate` | Joins a bundle, a capture and a HAR into one account of a session. Every artefact optional; uploads deleted when the request finishes |

```powershell
& .venv\Scripts\python.exe -m pytest -q
& .venv\Scripts\python.exe -m ruff check packages\atlas_core apps tools
```

**55 tests pass, lint clean** as of the head commit.

---

## 4. Where each piece stands

| Area | State |
|---|---|
| Monorepo layout, both engines mounted | **Done** |
| Container removal, host deployment, systemd | **Done** |
| Design tokens, shared header, unified rail | **Done** |
| One evidence step (PCAP + HAR + DART bundle) | **Done** |
| One Analyze button driving both engines | **Done** |
| Run-everything bundle analysis, single upload | **Done** |
| Run-everything results view (summary mode) | **Done** — see below |
| Rename to ATLAS (user-facing) | **Done** |
| Identity join (org ID) in `atlas_core` | **Done**, unproven against a real bundle |
| Flow-level correlation (bundle + capture + HAR) | **Done** — see below. Proven against a real three-artefact session |
| Time alignment between log and packet clocks | **Done for connections whose handshake was captured** — derived, reported as an upper bound, never silently applied |
| Unified findings model | **Not started** — the keystone for Phase 2 |
| Structured result contract for the bundle engine | **Not started** — blocks everything above |
| Auth, tenant isolation, retention | **Not started** — required before hosting |

---

## 4a. Flow-level correlation

`packages/atlas_core/atlas_core/flows.py`, exposed at `POST /atlas/api/correlate`
and rendered by the **Correlation** rail entry. It answers, for one browsing
session, what no single artefact can:

- **Which hosts were steered through the agent and which went direct.** Read from
  the wire: a TLS handshake to the agent's local listener means steered, one
  straight to the peer means direct. A host with no captured handshake is
  reported as *not determined*, never assumed direct.
- **Which connections the agent and the capture both saw.** Joined on connection
  identity, so no clock is involved and the join is exact.
- **What the browser experienced on top of them** — requests, status codes and
  failures, attached last because the browser's account is the least
  authoritative about what reached the network.

### The join keys

| Join | Key | Strength |
|---|---|---|
| Agent log ↔ capture | `<proto>_<srcport>__<dstip>:<dstport>` from the ZTA log | **Exact** — connection identity |
| Destination ↔ everything | `<proto>:<srcport>__<host>` from the ZTA log | **Exact** on the source port, **observed** on the name |
| App flow ↔ tunnel | HTTP/2 `stream=N` written at the same instant on both lines | **Associated** — stream numbers restart per connection |
| Capture ↔ HAR | TLS SNI on the wire vs the HAR's host | **Observed** |
| Tunnel ↔ request | time and multiplexing | **Associated** — many hosts share one tunnel, so a request cannot be attributed to a particular tunnel |

These are not presented as equal, in the UI or the payload.

### Following one flow end to end

The ZTA log writes **two** differently punctuated identifiers, and only one of
them was being read at first:

| Written by | Shape | Names |
|---|---|---|
| `AppSocketTransport::*` | `tcp:50299__enroll.cisco.com 12899BF0 stream=1` | the destination the application asked for |
| `Http2MuxTransport::*` | `http2_50300__54.225.88.226:443 15D54BAC stream=1` | the headend the tunnel reached |

Because ZTA steers on rules written against hosts and addresses, a matched rule
means the agent knows the destination by the name the application used — which
is the name the HAR knows, beside the source port the capture saw. That is the
chain: **HAR host → source port → capture flow → stream → tunnel**, with the
agent's own close reason attached. Measured on the test bundle: 340 intercepted
flows named, 269 tied to a tunnel, and the two that fall inside the capture
window tied to it exactly —
`crl.prod.cagenerator.pki.strln.net` → port 59897 → `127.0.0.1:59897 →
127.0.0.1:52555` (14 packets) → `http2_59898__54.225.88.226:443` stream 1.

**The caveat that must always travel with it:** 680 of 688 host-named lines in
that bundle were error level. With trace-level logging off the agent records the
destination mainly when it has a problem to report, so this is a list of flows
it had trouble with. A destination absent from it is one the agent logged no
problem for — **not** one known to have worked. That sentence is emitted as a
note on every run, and a test asserts it.

### Two things it deliberately does not do

- **It does not hardcode a vendor synthetic-IP range.** A server address is
  called synthetic because it appears in the HAR and never appears as a peer in
  the capture — provable from the inputs, and it does not break when the range
  changes.
- **It does not apply the clock offset.** The offset is reported with the basis
  that produced it, including how many connections it was derived from, because
  an offset from one connection deserves less trust than one from twenty.

### Measured on a real session (YouTube, three artefacts)

19 hosts, 18 steered, 1 direct, 5 tunnels matched, 162 requests, 9 failures;
offset at most 5.888 s from 1 handshake-captured connection. The finding neither
engine could produce alone: two `googlevideo.com` CDN hosts were steered and
returned **403/502 for every request, 0 bytes**, while `accounts.youtube.com`
reached its peer directly. That is a correlation, not a cause, and is presented
as one.

### How it is started

Analyze runs correlation itself whenever **two or more** artefacts are loaded -
supplying more than one is the reason to correlate, so it should not need a
second click. Two are enough because the engine states what the missing third
could not answer rather than refusing to run.

It does not switch to the result. Analyze leaves the view exactly where it was:
the capture, bundle and correlation results are each built into their own panel
and stay there, and a notice names where the cross-artefact answer will be. The
notice is repeated on completion, because the bundle engine clears it when its
own results land and a pointer nobody saw is the same as no pointer.

---

## 5. Known limitations and open problems

Ordered by how likely they are to bite.

1. **The bundle engine re-extracts the archive on every check.** Around 1.3 s per
   check, and now the dominant cost of a run-everything. It scales with bundle
   size, so the 358 MB test bundle will be slow. Fixing it means separating
   extraction from analysis inside the engine.
2. **`/atlas/api/bundle/analyze-all` has no test.** Verified by hand against a
   real bundle only.
3. **VPN, Umbrella, UZTNA and EDLP are not implemented** in the bundle engine.
   They are accepted and return only a payload-received line; the route still
   carries a placeholder where the parsing would go. Only **ZTA** and **Duo
   Desktop** do real work. They are excluded from run-everything for that reason.
4. **Tailwind loads from a CDN at runtime** (`cdn.tailwindcss.com`), which
   Tailwind itself warns is not for production, and which is a network dependency
   at page load. Preflight is disabled; a scoped compatibility layer in the bundle
   engine's CSS restores what its markup relied on.
5. **Three font families load from Google** (Inter; Orbitron and Rajdhani).
   Typography is the largest remaining visual divergence.
6. **`network_info` is not registered** in the capture engine's
   `CLASSIFICATION_*` tables, so its findings are computed, returned by the API,
   and never rendered.
7. **`_regress_baseline.json` is stale.**
8. **The UI surface guard has a blind spot**: it records ids, control names,
   radio values, select options and button labels. An element with no id that is
   not a form control - the user badge, for instance - can vanish without failing
   a test.
9. **Analysing a capture and a bundle together is slow, and looks hung.** Both
   analyses are CPU-bound Python in one server process, so they serialise. The
   YouTube capture alone finishes in about 6 s; alongside a full bundle analysis
   the pair takes two to three minutes, during which both panes sit on their
   "Analysing…" text with no progress. Measured, not estimated - both requests
   do complete and both panes render correctly. It is a throughput problem, not
   a failure, and there is no progress reporting to say so.
10. **A HAR was committed and pushed** in `6bd709c` and removed in `df16b9e`. The
   blob is still reachable in history; removing it needs a force push, which has
   not been done unilaterally. That bundle output contained a real employee email
   address and internal AD hostnames.
11. **JA3/JA3S fingerprinting does not run on Wireshark below 3.6**, which is
    what is installed here (3.4.7). The analysis no longer fails because of it -
    the fields are dropped and a note says so - but the JA3S clustering check
    for a shared TLS terminator produces nothing, and its silence must not be
    read as evidence of no interception.

## EVTX parsing, and a wrong turn worth remembering

`Check Event Viewer Logs` used to take **114.6 s** while every other check ran in
0.8-2.2 s. The cost was `python-evtx`, a pure-Python parser, over 45.8 MB of
Windows event logs.

The first attempt was to **drop the check from run-everything**. That was wrong.
It bought a headline speed-up by doing less work, which is not an optimisation -
it removed a diagnostic capability and reported the result as a 12x win. Capping
records was rejected correctly (at a 2000 cap the ZTA channel spends its budget on
Information records and never reaches its errors, and Warning/Error/Critical drops
from 1000 to 343), but excluding the check loses *all* 1000. Comparing two ways of
losing data and picking one was the mistake; neither was acceptable.

The actual fix was to **replace the parser**. `pyevtx-rs` (PyPI `evtx`) parses the
same files with a Rust backend:

| | python-evtx | pyevtx-rs |
|---|---|---|
| 45.8 MB, 12 files | **147.6 s** | **0.5 s** |
| Records | 62 264 | 62 264 |
| Warning/Error/Critical | 4 231 | 4 231 |

Verified identical on event id, level, channel and timestamp across all 62 264
records. Run-everything now runs **all 8 checks in 9.8 s** with the full 1000
events and the true System error count of 131.

Two things to know before touching this:

- **The two packages cannot coexist on Windows.** `evtx` and `Evtx` are the same
  directory name; python-evtx raises on import if both are present.
  `resolve_evtx_reader()` prefers the Rust parser and falls back to the pure
  Python one, so either alone works.
- **`normalize_event_time` now converts to naive UTC, not local.** EVTX
  `SystemTime` is UTC; python-evtx emits it naive while pyevtx-rs appends `Z`.
  Converting tz-aware values to local time - which the old code did - would have
  shifted every Rust-parsed event by the host's offset and quietly broken time
  correlation.

---

## 6. Traps that have already cost time

Every one of these was a real failure here, not a hypothetical.

- **Restart after Python changes.** uvicorn does not run with `--reload`.
- **Jinja caches templates.** Editing a `.html` in the bundle engine does nothing
  until the server restarts. A change can silently *appear* to have no effect.
- **Browsers cache the shell CSS.** Shell assets now carry a modification-time
  query for exactly this reason. If an edit seems to do nothing, check the served
  file before changing the code again.
- **Shell CSS must load after the engines.** Both were written assuming they own
  the document.
- **The bundle engine uses `!important`** in places, which beats specificity and
  load order alike.
- **The engines use root-relative API paths** because standalone they own the
  origin. Under a mount they 404. A fetch shim in the workspace rewrites them.
- **`url_for` renders root-relative outside the mount**, so composed pages must
  prefix the bundle engine's assets or every one of them 404s while the engine
  still looks present.
- **A new finding category must be registered in all five `CLASSIFICATION_*`
  tables** in the capture engine or it is computed and never displayed. This has
  shipped twice.
- **tshark rejects the whole run if any one `-e` field is unknown to it.** Not a
  degraded result - no result at all. `tls.handshake.ja3` and `ja3s` arrived in
  Wireshark 3.6, so on the 3.4 build in use *every* capture failed with "Some
  fields aren't valid". The field list is now probed against the installed
  binary (`pcap.supported_fields`, cached per executable, ~0.7 s once) and
  unknown fields are dropped with a note naming the check that could not run.
  Do not add a field without remembering that the deployed Wireshark version is
  a deployment concern, not a constant.
- **The ZTA agent logs flow IDs under three prefixes, not one.** `tcp_`, `tls_`
  *and* `http2_`. Grepping only `tcp_` finds nothing interesting, because the
  multiplexed tunnel — where the errors live — is only ever `http2_`. This cost
  two failed hypotheses before the log was actually read.
- **Ephemeral source ports are reused.** A ZTA log spanning two days will offer a
  day-old connection with the same source port and destination as a captured
  flow. Correlation splits log lines into episodes on a 5-minute gap and refuses
  a match outside a 15-minute tolerance, *counting the refusals into a visible
  note*. Without this the derived clock offset went to −2434 s.
- **A clock offset is only sound where the handshake was captured.** A long-lived
  flow already in progress when the capture started has a first captured packet
  that is not the connection start; including it put the offset at −122 s.
- **A capture flow's direction is not given by its first captured packet.** When
  the first packet is server→client the source port reads 443 and every join
  fails. A SYN-without-ACK anchors the client; with no handshake, the lower port
  is the listener.
- **`offsetParent` is not a visibility test inside the workspace.** The shell
  hides whichever engine is not active with `display:none` on the engine root. A
  descendant of a hidden ancestor still reports its *own* computed display
  correctly, but its `offsetParent` is `null` because nothing is laid out. The
  shell's `needsCheckOption()` used `offsetParent` to decide whether the bundle
  engine was showing ZTA check options; with the capture engine active it always
  concluded there were none, dispatched the engine's own form submit, and the
  engine answered with the modal *"Please select one ZTA analysis check
  option."* — the exact dialog the guard existed to prevent. Walk the ancestor
  chain with `getComputedStyle` instead (`shownByEngine`); it does not depend on
  layout.
- **Moving an engine panel is not the same as moving the rail highlight.** For a
  while Analyze jumped to the bundle engine while the rail still read `Inspect`,
  so the navigation and the content disagreed about where the user was. Panel
  visibility and rail state are now changed together in `showEngine`, and every
  rail item carries `data-engine` so the highlight can be found from the panel.
  An item already pointing at the target engine is left alone - the capture
  engine has seven views of its own, and re-selecting the first would throw the
  reader back to `Inspect` on every switch.
- **A hand-written `?v=` stamp is not a cache-buster.** The capture engine's
  markup carried `?v=20260651`, a constant, so browsers served a cached
  `app.js` after every edit and the edit looked like it had had no effect. Both
  places that emit that markup — the engine's own page and `capture_document`
  in the shell, which composes the document itself and never passes through the
  engine's view — now restamp with the file's modification time.
- **Two engines each shipped their own exporter, and under ATLAS neither could
  see the whole run.** The bundle engine's wrote a header and then
  `(no detailed output captured)` - 293 bytes - because `currentReportText()`
  reads its own `#resultContent` pane while the whole-bundle analysis renders
  into the shell's `#atlas-bundle-results`. There is now one report: the shell
  contributes the sections the capture engine cannot know about, and both
  existing buttons are redirected to it rather than a third being added. It is
  built from the DOM at the moment of export, so it cannot describe a different
  run than the one on screen. Measured: 641,914 characters against 293, opening
  with the filenames of every artefact analysed.
- **Not moving the view has a mirror-image failure.** Analyze was changed to stop
  jumping to the bundle engine, because that hid the capture analysis the same
  click had started. With a bundle as the *only* artefact that produced the
  opposite bug: the analysis ran, rendered 387,299 characters into a panel the
  reader was not looking at, and cleared its own notice - indistinguishable from
  nothing having happened. The rule is now conditional: take the view only when
  there is no other result to hide behind it.
- **The capture engine's "views" are scroll targets on one page, not views.**
  Its nav handlers call `scrollIntoView` on a section and refuse outright when
  the engine has no results of its own: `if (!resultsReady()) {
  scrollToEl("sec-evidence"); return; }`. Anything the shell adds to that page
  must either satisfy `resultsReady()` or take the click over before the
  engine sees it - a capture-phase listener on `document` runs before any
  listener on the button itself, which avoids two handlers racing.
- **`#sec-report` lives inside `#results`, which is hidden until a capture is
  analysed.** Content appended there is rendered, reports a computed `display`
  of `block`, returns its full text from `innerText`, and has zero height.
  Anything that must be visible without a capture belongs outside that subtree.
- **`requestAnimationFrame` is throttled in a background tab**, so deferring
  work to a frame is not deterministic and cannot be verified in the browser
  harness. To scroll to something just revealed, force the reflow synchronously
  by reading a layout property (`void node.offsetHeight`) instead.
- **Smooth scrolling does not animate in the headless harness.** A
  `scrollIntoView({behavior: "smooth"})` leaves `scrollY` at 0 there while
  working normally in a real browser. Assert that the call was made and its
  target, not the final scroll position.
- **A filename label is not a record of what is loaded.** Every evidence tile's
  label is written by a `change` or `drop` handler and by nothing else, so it
  reports the last interaction rather than the state of the input. Browsers
  restore file input selections across a reload - Firefox does, Chromium does
  not, which is why the browser harness cannot reproduce it - so an input can
  hold a capture while its tile reads "no file selected", and a correct
  correlation over three artefacts looks invented. Labels are synced from the
  inputs at startup and each tile has a Remove control. Anything reasoning
  about what is loaded must read `input.files`, never the label.
- **`innerText` omits collapsed `<details>`, and its fallback hides the fact.**
  It returns what is rendered, so text inside a closed `<details>` is missing -
  which made an export from the bundle page 1,695 characters instead of 387,331.
  Worse, the same call on an element inside a `display:none` subtree falls back
  to `textContent` and returns everything, so a measurement taken while the
  block was hidden looked correct and hid the bug. Use `readableText`, which
  opens collapsed sections, reads, and restores them.
- **PowerShell breaks on quotes in commit messages.** Use `git commit -F <file>`.
- **`.Length` on `curl.exe` output counts lines, not bytes.**
- **Never commit evidence.** Captures, HARs, key logs and DART bundles are all
  ignored at the repository root, and CI fails the build if one appears. Git
  history is permanent - "sanitise later" does not work.

---

## 7. Decisions taken

| Decision | Consequence |
|---|---|
| Hosted (SaaS/PaaS) rather than local-only | Supersedes the capture engine's "nothing is uploaded" principle. Auth, tenant isolation, encryption, retention and audit logging become design requirements, not follow-ups |
| No containers; run on the host | systemd carries the isolation an image would have provided. Wireshark version is a deployment concern |
| macOS + Windows launchers now, Linux in production | CI covers all three |
| Keep both engines, wrap rather than rewrite | Preserves validated detection logic |
| Colour foundation from Cisco Magnetic; information architecture from the bundle engine | The palette is the real Cisco design system; the grouped rail is the better structure |
| Internal identifiers keep their old names | Renaming `DARTHAWK_*`, `darthawkTheme` and package names touches imports and stored user preferences for no visible gain |
| Correlation reuses the files already chosen in "Provide evidence" | A second set of inputs would let the two drift apart, and a correlation run against different files than the analysis above it would be quietly wrong |
| Correlation uploads are deleted when the request finishes | A capture and a bundle together identify an endpoint, and with a key log would decrypt the session they recorded. Nothing is retained |

Full reasoning in [ASSESSMENT.md](ASSESSMENT.md) §10.

---

## 8. Where to look

| Document | Contents |
|---|---|
| **This file** | Current state. Always read first, always update last |
| [ASSESSMENT.md](ASSESSMENT.md) | Platform comparison, unification strategy, decisions and their consequences |
| [PHASE1_UNIFICATION.md](PHASE1_UNIFICATION.md) | The UI unification plan and its measurements |
| [PHASE2_CORRELATION.md](PHASE2_CORRELATION.md) | What correlation makes possible, in dependency order |
| [`packages/capture_inspector/docs/DETECTION.md`](../packages/capture_inspector/docs/DETECTION.md) | Every capture detector: what it detects, how, and what it cannot see |
| [`packages/capture_inspector/docs/HANDOFF.md`](../packages/capture_inspector/docs/HANDOFF.md) | Capture engine internals |

---

## 9. Keeping this file true

This file is only useful if it is current. See [`AGENTS.md`](../AGENTS.md) at the
repository root for the rule, which applies to every agent and every human:

> Update this file in the same change that makes it out of date. Not afterwards,
> and not only when asked.

Specifically, update it when you: finish or abandon a piece of work, discover a
limitation, hit a trap worth recording, take a decision, or change what the head
commit is. Delete anything that has stopped being true - a stale state document
is worse than none, because it is believed.

This file is one of three that must be current before anything is committed. The
other two are [`CHANGELOG.md`](../CHANGELOG.md), which records what changed and
whether it was verified, and [`IMPROVEMENTS.md`](IMPROVEMENTS.md), which records
what is still worth fixing and the evidence for it. `AGENTS.md` §9 has the order.
