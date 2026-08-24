# ATLAS → BDB migration plan

Reference document. Written 2026-08-24, before any migration work started.
Everything here was verified against the BDB API docs, the BDB package list for
`python3.13`, the Full Stack tutorial PDF, and a Phase 0 spike run against real
captures. Where something is unverified it says so.

---

## 1. Why this is happening

Mandate: everything moves to BDB. Drivers are hosting, authentication and
sharing with the wider TAC team. Both engines and the correlation layer have to
come along.

## 2. Verdict

**Feasible.** The two risks that could have killed it are both closed:

* **Packet parsing without tshark** — BDB provides Python packages, not system
  binaries, so tshark is unavailable. A dpkt reimplementation was spiked and
  measured (see §6). It matches the production reader on structure and headers,
  and is *faster*.
* **UI hosting** — BDB serves task files as a CDN and runs arbitrary
  JavaScript. Atlas's vanilla-JS frontend is close to a drop-in fit.

The remaining work is known and bounded. The largest single item is a TLS
parser.

## 3. What BDB provides

| Capability | Mechanism |
|---|---|
| Static frontend hosting | Files in the task root, served at `/app/<task>` (deploy) and `/app_dev/<task>` (save) |
| Custom JS/CSS | Full ES modules. Harbor UI kit at `scripts.cisco.com/harborui/<ver>/` |
| Backend invocation | `POST /api/v2/jobs/<task>` (sync), `/async` + poll. Browser auth via same-origin `bdb_cookie` |
| Session state | User session folder `/api/v2/files` — 10 GB/file, persists across runs, tasks address it via `subPath` |
| File upload | `POST /api/v2/files{wildcard}`, `multipart/form-data`, 10 GB/file, up to 10 files per request |
| TAC integration | `GET /api/v2/attachments/{srId}/{filename}` pulls a case attachment straight into the session folder |
| Persistence | DBaaS (MongoDB, 256 MB), task storage (S3, `visibility=public`) |
| Code sync | Every task has an auto-created GitHub repo. `GET /api/v2/pushpull/pull/{task}` syncs commits into BDB |

Relevant packages present on `python3.13`: `dpkt 1.9.8`, `scapy 2.6.1`,
`haralyzer`, `python-evtx`, `lxml`, `pandas`, `plotly`, `libarchive-c`.

**Absent: Flask and FastAPI.** Also no `a2wsgi`. This is why the web layer
cannot come across unchanged.

## 4. Target architecture

Start as a **single task** with an `action` input (the EasyBEMS pattern): one
repo, one deploy, frontend and backend together. Split later if a task grows
unwieldy or hits a timeout — BDB supports cross-task imports
(`from task_atlas_core import ...`), so shared code need not be duplicated.

| Atlas today | On BDB |
|---|---|
| `apps/web/main.py` (FastAPI shell) | Gone. BDB serves the frontend |
| Capture Inspector static HTML/JS/CSS | Near drop-in to task root |
| `atlas-shell.*`, `atlas-tokens.css` | Drop-in |
| DartHawk Jinja2 templates + Flask | **Rewrite** — static HTML, rendering moved client-side |
| Routes `/upload`, `/flows`, `/flow` | `action` values on the task |
| `atlas_core` (facts, correlation, flows, path) | **Ports untouched** — no framework imports |
| In-memory LRU capture store | Session folder + `subPath` |
| Tailwind from `cdn.tailwindcss.com` | **Vendor as a task file** — fixes an existing defect too |
| tshark | dpkt (see §6) |

## 5. Task configuration

* **name**: `atlas` / `amarora2_atlas` — becomes the app URL
* **service**: `python3.13` (not 3.11 as the tutorial shows)
* **public**: **must be checked** or the web app will not serve
* **labels**: no `genai_tool` for now — deliberately deferred
* **inputs**: set via `bdb_update_task`, not by hand (`bdb.json` is not editable)
  * `action` — select: `analyze_bundle`, `capture_flows`, `flow_detail`, `correlate`
  * `bundle` — `inputFile`, the DART ZIP
  * `sub_path` — text, optional, points at a file already in the session folder

## 6. Phase 0 spike — what was measured

Harness lives in `tools/phase0/`: `dpkt_extractor.py`, `serialize.py`,
`compare.py` (field parity), `gate_e.py` (conclusion invariance). Run against
six real captures from `~/Downloads`.

**Result: viable.** dpkt is **2.5–9.6× faster** than tshark, so BDB job
timeouts are not a concern. Flow discovery, headers, ISN capture,
retransmission counters and HTTP all reach 100% on most captures. Path
stitching is near-invariant (557 vs 558 traces).

**Defects found and fixed during the spike** — all four were real:

1. **Orientation.** Absent a handshake the production reader takes *the lower
   port to be the listener*. Getting this wrong holds flows backwards, and
   source port is half the key the agent records, so the join silently fails.
   Fixed: Tier 1 went 63.9% → 100%.
2. **Port reuse.** A 5-tuple is a connection *slot*, not a connection. tshark
   reported 445 streams where the naive key found 218. Split on a fresh SYN
   carrying a different ISN.
3. **Gzipped captures.** tshark decompresses transparently; dpkt does not.
4. **`decode("idna")` on SNI.** Python's idna codec validates and raises on
   ordinary hostnames, and ignores `errors=`. A blanket `except Exception`
   swallowed it, yielding zero SNI while handshake detection still worked.

**Open work before Phase 2:**

* **TLS parser is the whole remaining problem.** Every Gate E failure traces to
  it. Needs ClientHello/ServerHello parsing with segment reassembly, and the
  negotiated version read from `supported_versions`/ServerHello rather than the
  record header (which says TLS 1.0 for compatibility).
* One gzipped capture opens and reports Ethernet encapsulation but yields 0
  flows. Unresolved.
* **The ISN cross-vantage join has never actually executed.** `proved_hops=0`
  for both readers — the FTD capture pair covers different client subnets and
  shares no traffic. Needs a genuine same-traffic pair. This matters for the
  migration *and* for the patent draft, where it is the strongest claim.

**Known capability loss: TLS keylog decryption.** tshark does it with the full
Wireshark TLS stack; nothing in pure Python comes close. Confirm this is
acceptable rather than discovering it mid-Phase-2.

## 7. Sequence

0. **Vertical slice first** — DART bundle in, health snapshot rendered. No
   tshark needed, reuses `analyze_*_runtime()` unchanged, and exercises every
   platform mechanism at once: upload, task invocation, CDN-hosted frontend,
   JSON round-trip, rendering. If this works the rest is repetition.
1. Finish the TLS parser; re-run Gate E until session correlation is invariant.
2. Port the capture engine behind the existing `Packet` / `WireFlow` contracts.
3. Move correlation and path stitching across (should be a no-op).
4. DartHawk template rewrite.

## 8. Workflow for moving the code

1. Create the task in BDB (creation is not available through the agent tooling).
2. BDB auto-provisions a GitHub repo for it. Confirm access with
   `GET /api/v2/git/<task>/user/<uid>`; grant with the matching `POST` if needed.
3. Clone that repo. It is **separate from** `github.com/amarora2_cisco/Atlas`,
   which stays as the upstream source of truth.
4. Port code in, commit, push.
5. `GET /api/v2/pushpull/pull/<task>` to sync into BDB.
6. Save → `/app_dev/<task>`. Deploy → `/app/<task>`.

## 9. Still unconfirmed

* Job execution timeout. dpkt's speed (§6) makes this unlikely to bite, but it is
  not yet measured.
* Whether the BDB task repo or the existing Atlas repo becomes the long-term
  home. Worth deciding deliberately, but not before the slice proves out.

**Resolved 2026-08-24 — upload is not a risk.** `POST /api/v2/files{wildcard}`
takes ordinary `multipart/form-data` with a **10 GB per-file limit**, against
bundles and captures of 50–500 MB. No chunked-upload workstream is needed. Up
to 10 files per request; folders are created as needed; a `.downloading` suffix
marks a transfer in progress and a repeat upload of the same name within 10
seconds is refused. Returns `204`.

The browser flow is a plain `FormData` POST to the session folder, followed by a
job invocation that addresses the file by `sub_path` — so the artefact is
uploaded once and every later drill-down refers to it by path. That is better
than the current in-memory LRU store, which evicts.
