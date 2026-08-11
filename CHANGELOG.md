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
