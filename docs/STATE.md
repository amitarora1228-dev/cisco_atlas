# ATLAS — project state

**This is the living state of the project. Read it first. Update it before you
finish.** It is the one place that says what exists, where each thing stands, and
what is known to be broken. If it disagrees with any other document, this file is
right and the other one is stale.

**Last updated:** 2026-08-10 · branch `atlas-architecture` · head `abb33fa`

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

---

## 3. Running it

```powershell
.\run.ps1          # Windows
./run.sh           # macOS / Linux
```

Both create the venv, install pinned dependencies, check for tshark and serve on
<http://127.0.0.1:8000>.

| Path | What |
|---|---|
| `/` | The unified workspace |
| `/capture/`, `/bundle/` | Each engine standalone (still works) |
| `/healthz` | Engines, tshark version, degraded features |
| `/atlas/api/bundle/analyze-all` | Runs every applicable bundle check from one upload |

```powershell
& .venv\Scripts\python.exe -m pytest -q
& .venv\Scripts\python.exe -m ruff check packages\atlas_core apps tools
```

**29 tests pass, lint clean** as of the head commit.

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
| Rename to ATLAS (user-facing) | **Done** |
| Identity join (org ID) in `atlas_core` | **Done**, unproven against a real bundle |
| Unified findings model | **Not started** — the keystone for Phase 2 |
| Structured result contract for the bundle engine | **Not started** — blocks everything above |
| Time alignment between log and packet clocks | **Not started** — highest leverage |
| Auth, tenant isolation, retention | **Not started** — required before hosting |

---

## 5. Known limitations and open problems

Ordered by how likely they are to bite.

1. **Bundle analysis re-extracts the archive per check.** A run-everything is 8
   extractions: 105 s on an 18.5 MB bundle, and it scales with size - the 358 MB
   test bundle will be slow. Fixing it means separating extraction from analysis
   inside the bundle engine.
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
9. **A HAR was committed and pushed** in `6bd709c` and removed in `df16b9e`. The
   blob is still reachable in history; removing it needs a force push, which has
   not been done unilaterally. That bundle output contained a real employee email
   address and internal AD hostnames.

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
