# Changelog

Every change to ATLAS is recorded here before it is committed. This is a record
of *what changed and why it mattered*, written for someone who was not in the
room - not a restatement of the diff.

Entries state measured numbers, never estimates, and record what was **verified**
rather than what was intended. A change that was not checked against reality says
so.

For current status, known limitations and traps, see [`docs/STATE.md`](docs/STATE.md).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet publish versioned releases, so changes are grouped
under `[Unreleased]` until one is cut.

---

## [Unreleased]

### Added

- **A flow timeline for each correlated flow**, drawn as the capture engine
  draws a connection: a two-column fact grid, the artefact chain, then a ladder
  between two lifelines. The rows are the agent's own log lines **in order, not
  packets** - the correlation never reads individual packets - so the lifelines
  are the leg facing the application and the leg facing Secure Access, taken
  from the subsystem the agent named on each line. The diagram says that on
  screen rather than letting a familiar shape imply a packet capture. Verified:
  four ordered lines with alternating sides, endpoints "application · port
  59682" and the tunnel, error rows marked.
- **A Remove control on every evidence tile.** There was no way to take a file
  back once chosen, which is what made a browser-restored selection feel like
  the tool inventing data: the file was genuinely still attached and could not
  be detached. Verified: removing the capture clears its input and label and
  leaves the bundle untouched.
- **A running analysis now says it is still running.** The notice was written
  once - "This can take a minute" - and then never changed, so a two-to-three
  minute concurrent run was indistinguishable from a hang. It has been reported
  as one three times. The notice now names what is in flight and ticks an
  elapsed time. That is not progress and does not claim to be; it shows the run
  is alive. Verified: 0:02 through 0:24 on a bundle-only run, cleared when the
  results rendered.
- **Flow-level correlation across a DART bundle, a packet capture and a HAR**
  (`packages/atlas_core/atlas_core/flows.py`, `POST /atlas/api/correlate`).
  Joins the three artefacts into one session view: which hostnames were steered
  and which went direct, which tunnels carried them, and what the agent reported
  about each. Two join strengths are carried through to the UI so an association
  is never read as a measurement. Measured on a real three-artefact session: 19
  hosts, 18 steered, 1 direct, 5 tunnels matched, 162 requests, 9 failures.
- **Intercepted flows, end to end.** The ZTA log writes two differently
  punctuated flow identifiers and only one was being read. The host-named form,
  `tcp:50299__enroll.cisco.com stream=1`, names the destination the application
  asked for - the only place any artefact states both a recognisable destination
  and the source port that leads into the capture. All 2,180 lines of that form
  were previously invisible. Each flow is now followed HAR host -> source port ->
  captured connection -> HTTP/2 stream -> tunnel -> close reason, with every hop
  labelled by the artefact it came from. Measured: 340 flows named, 269 tied to a
  tunnel, and the two inside the capture window tied exactly.
- **One report for the whole workspace.** The Report view and both existing
  export buttons now emit a single report covering the capture, the bundle and
  the correlation, opening with the filenames of every artefact it was made from.
  Measured: 641,914 characters against the previous 293.
- **Correlation runs from Analyze** whenever two or more artefacts are loaded,
  rather than requiring a second click in another view.
- **tshark field capability probe** (`capture_inspector.pcap.supported_fields`).
  Unknown fields are dropped and named in a note instead of failing the run.

### Changed

- **Correlated flows are presented as a flow table**, the way the capture engine
  presents its own: same columns, same severity pills, same expand-for-detail,
  same "Show only problems" and filter - and reusing that engine's classes
  rather than inventing a second style for the same idea. A reader who has
  learned one table has learned both. The chain, the join bases and the agent's
  own error lines moved into the expanded row. Verified on a capture plus
  bundle: 340 flows, 200 rows shown worst-first, filtering to "msn" leaves 15,
  the expanded row carries all four hops, and the engine's styling applies
  natively.
- **A reload now starts over.** Firefox restores file input selections across a
  reload, the way it restores text typed into a field; Chromium does not, which
  is why the browser harness could not see it. The result was a half-state - the
  files survived but their results did not - so an apparently empty page would
  analyse artefacts the reader believed they had never supplied. Showing the
  restored files rather than hiding them was the first attempt and was not
  enough: reported three times. Selections are now dropped at startup. Nothing
  is lost that a reload was not already discarding, and Remove takes a file back
  without one. Verified: two files loaded, reload leaves zero and both tiles
  read "no file selected".
- **Analyze no longer moves the view** when doing so would hide a result the same
  click produced - but it does land on the bundle results when the bundle is the
  only artefact supplied, because there is then nothing to hide.
- **The Analyze notice names the artefacts** instead of counting them. A file
  input keeps its selection until the page reloads, so "3 artefacts" could be
  true while the user believed they had supplied one.
- **Correlation refuses ambiguous joins rather than guessing.** Two captured
  flows claiming one source port produce no join and a counted note. The
  app-flow to tunnel join is bounded to one second, which cut ambiguous cases
  from 163 to 23.

### Fixed

- **Exporting from the Bundle analysis page produced an almost empty report.**
  `innerText` returns only what is *rendered*, and the bundle output sits almost
  entirely inside a collapsed `<details>` ("All checks and full output"), so the
  export was 1,695 characters. The 387,719 measured earlier was itself
  misleading: that read happened while the block was in a hidden subtree, where
  `innerText` falls back to `textContent` and quietly returns everything. The
  reader now opens collapsed sections, reads them, and restores them exactly as
  they were. Verified from the Bundle analysis page: 1,695 to 387,331
  characters, containing the evidence header, the bundle section and the
  individual checks, with all nine `<details>` still closed afterwards.
- **A new run showed the previous run's results.** Nothing was cleared when
  Analyze started, so analysing a bundle after a capture left the capture's
  findings, its correlation and its notice on screen - output describing
  artefacts the current run never touched. Reported as "not sure how it is
  showing this data". Everything a run will not produce is now removed before
  it starts. Verified: 200 flow rows from a capture disappear the moment a
  bundle-only run begins, and the report then contains only the bundle.
- **Filename labels could disagree with the files actually loaded.** Each label
  is written by a `change` or `drop` handler and by nothing else, so it
  describes the last interaction rather than the state of the input. Browsers
  restore file input selections across a reload, which leaves a capture in the
  input while the tile reads "no file selected" - and a correlation honestly
  reporting "capture + bundle + har" beside two tiles claiming nothing was
  chosen. The labels are now synced from the inputs at startup; the files are
  real and are not discarded. **Not verified against the browser that restores
  them:** Chromium, which the test harness drives, does not restore file
  inputs, so only the divergence this produces was reproduced, not the restore
  itself.
- **The Report view was unreachable without a capture.** Two causes, both
  found by measurement. The engine treats its views as scroll targets on one
  long page and its Report handler returns the reader to the evidence card
  unless *it* has analysed a capture; and the shell's report block was being
  rendered inside `#sec-report`, which sits inside `#results`, which the engine
  keeps hidden until then - so it was present with 387,541 characters of
  content and zero height. The block now lives outside that subtree, carries
  its own Download button when there is no capture, and the shell takes over
  the Report click only when the engine would have refused. Verified: bundle
  alone now scrolls to a rendered report (scrollY 1739, section on screen,
  387,719 characters exported); with a capture the engine's own handler still
  runs and targets `sec-report`, unchanged.
- **Every capture failed on Wireshark below 3.6.** `tls.handshake.ja3` and
  `ja3s` arrived in 3.6; tshark rejects the entire run if any one `-e` field is
  unknown, so the 3.4.7 build in use returned "Some fields aren't valid" for
  every capture. Verified after the fix: 14,491 packets parsed, exactly the two
  fields dropped and 83 kept, 63 findings, HTTP 200 in 6.2 s.
- **A HAR-only analysis listed nothing but failures.** `_har_rows` sent only
  `har.failed`, so a 158-entry HAR arrived as 19 rows, all errors, while the
  table offered a "Show only problems" control with nothing to filter. Now 19
  problems and 81 successes on the first page, 19 when ticked.
- **The capture engine's assets were never cache-busted.** The markup carried a
  hand-written `?v=20260651` that does not change when the file does, so
  browsers served a stale `app.js` after every edit. Both emitters now stamp
  with the file's modification time.
- **The bundle engine raised "Please select one ZTA analysis check option"** on
  a workflow that deliberately never asks that question. The guard used
  `offsetParent` to test visibility, which is `null` for everything inside the
  hidden engine regardless of what the engine intends.
- **A bundle-only analysis appeared to do nothing.** It rendered 387,299
  characters into a panel the reader was not looking at, then cleared its own
  notice.

### Documentation

- `docs/STATE.md` records the correlation join keys, the two deliberate
  refusals, and seven traps paid for during this work.
- This changelog added, along with the rule in [`AGENTS.md`](AGENTS.md) that
  requires it to be updated in the same change.
- `docs/IMPROVEMENTS.md` added: a standing, evidence-backed list of what should
  be improved next.

---

## Earlier work

Before this file existed, history was kept only in `docs/STATE.md` and in commit
messages, both of which remain accurate. Notable earlier changes, newest first:

- `452ca7e` Show one bundle view at a time, with a way back to the summary.
- `9b6033f` Let the ZTA Health Snapshot be the verdict, fold the checks beneath it.
- `b9d37e5` Group run-everything results by the question each check asks.
