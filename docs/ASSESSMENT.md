# Project ATLAS — Platform Assessment and Unification Plan

**Status:** analysis only. **No change has been made to either platform.**
Open questions in §10 are blocking; they are listed so the plan is not built on
assumptions.

**Date:** 2026-08-10
**Workspace:** `c:\DEV Copilot\Project ATLAS`
**Repository under analysis:** `amarora2_cisco/Atlas`, branch `add-tls-inspector`

---

## 1. Scope and method

Two platforms were reviewed directly from source in this workspace, not from
memory or documentation alone:

| Platform | Purpose | Location on branch |
|---|---|---|
| **DartHawk** | Analyzes Cisco DART ZIP bundles (endpoint diagnostic archives) | repository root |
| **Capture Inspector** (TLS_Inspector) | Analyzes PCAP/PCAPNG + HAR + optional TLS key log | `tls-inspector/` |

Method: read dependency manifests, deployment descriptors, route tables, module
inventory and the existing documentation set (`tls-inspector/docs/`: HANDOFF,
DETECTION, ARCHITECTURE, MODULES, plus CHANGELOG). Metrics below were measured,
not estimated.

---

## 2. Platform A — Capture Inspector (TLS_Inspector)

**What it is.** A strictly local analyzer that turns a packet capture into an
evidence-backed diagnosis of TLS decryption, certificates, DNS, proxy/SWG
steering, SASE behaviour and network health.

| Attribute | Value |
|---|---|
| Framework | FastAPI 0.115.6 (ASGI) on uvicorn 0.34.0 |
| Dependencies | 4, **exactly pinned** (`==`) |
| External binary | **tshark (Wireshark CLI) — required** |
| Code | 8 491 lines across **26 modules** under `app/` |
| UI | Static SPA: `index.html` + `app.js` + `style.css`, driven by `fetch` |
| API | `POST /api/analyze`, `GET /api/health`, `GET /api/report` |
| Deployment | Local desktop. PowerShell launcher, `.bat`, and a compiled `.exe` control panel |
| OS posture | **Windows-first** (PowerShell tooling, packaged exe) |
| Privacy | **100 % local. Nothing is uploaded.** Stated as a core product principle |
| Documentation | Extensive: HANDOFF, DETECTION (per-detector catalog), ARCHITECTURE, MODULES, CHANGELOG |

**Governing principle (from `docs/HANDOFF.md` §1):** *evidence or nothing* — a
finding must cite the on-wire fact that produced it, and where the capture cannot
answer a question the tool says so rather than guessing. This is enforced in code
via confidence caps, withheld percentages and explicit suppression guards.

**Strengths:** deep modular separation (orchestrator contains no detection logic);
a written detector contract; a documented list of its own blind spots; a
regression harness concept already present.

**Weaknesses:** Windows-coupled launch tooling; one detection category
(`network_info`) computed but never rendered; regression baseline stale; no unit
test suite (`_gold_test.py` is a scratch script with hardcoded local paths, not a
test).

---

## 3. Platform B — DartHawk

**What it is.** A Flask web tool that ingests a Cisco DART bundle and extracts
endpoint configuration and diagnostic state: ZTA enrollment, certificate and SAML
enrollment traces, organisation IDs, Secure Client version, OS, bundle timezone,
module logs and Duo Desktop health.

| Attribute | Value |
|---|---|
| Framework | Flask ≥3.0 (WSGI) on gunicorn |
| Dependencies | 4, **version ranges** (`>=,<`) — includes `python-evtx` (Windows Event Log parsing) and `tzlocal` |
| External binary | **None** — pure Python |
| Code | 8 801 lines in **1 module** (`darthawk.py`) |
| UI | Jinja2 server-rendered: `templates/base.html`, `index.html`, `features.html` + `static/` |
| API | `GET /`, `GET /features`, `POST /inspect-bundle`, `POST /analyze`, `POST /feedback` |
| Deployment | **Dockerfile (python:3.12-slim) + Procfile** — container and PaaS capable |
| OS posture | **Cross-platform**; README documents macOS; auto-opens a browser locally |
| Privacy | Deployable as a hosted service; `/feedback` **sends email with attachments** via SMTP |
| Configuration | Environment variables (`DARTHAWK_*`) |

**Strengths:** no binary dependency, so it containerises cleanly; already has a
production-shaped deployment story (gunicorn, Docker, Procfile); rich DART domain
extraction; configuration externalised to environment variables.

**Weaknesses:** single 8 801-line module — no separable detection layer, hard to
unit test; no test suite; dependency ranges rather than pins.

### 3.1 Two findings that matter for CI/CD

1. **Runtime dependency installation.** `ensure_runtime_dependencies()` runs
   `pip install` at import time, **enabled by default**
   (`DARTHAWK_AUTO_INSTALL=1`), and bootstraps `ensurepip`. This is convenient
   for a desktop user and problematic for a pipeline: builds stop being
   reproducible, application start acquires a network dependency, and it creates
   a supply-chain surface at runtime rather than at build time. It is redundant
   inside the container, where dependencies are already installed at build.
   **Recommendation: keep the convenience path, but make it opt-in and skip it
   automatically when running under a container or CI.**

2. **Secrets handling is correct — no change needed.** SMTP host, username and
   password are read from environment variables with empty defaults; nothing is
   hardcoded. The only hardcoded value is a default recipient address, which is
   not a secret. This posture should be preserved and extended to the unified
   product.

---

## 4. Architecture comparison

The two systems are near-identical in size and **opposite in almost every
structural decision**:

| Axis | Capture Inspector | DartHawk | Divergence |
|---|---|---|---|
| Size | 8 491 lines / 26 modules | 8 801 lines / 1 module | Same scale, opposite organisation |
| Web stack | FastAPI (ASGI) | Flask (WSGI) | Different concurrency model |
| Server | uvicorn | gunicorn | — |
| UI | Static SPA + `fetch` | Jinja2 server-rendered | Different rendering model |
| Packaging | Windows `.exe` + PowerShell | Docker + Procfile | Desktop vs service |
| External binary | tshark **required** | none | Blocks a pure-container build |
| Dependency policy | exact pins | ranges | Must be unified |
| Python target | 3.10-compatible venv | 3.12-slim image | Must be unified |
| Config | function arguments / form flags | `DARTHAWK_*` env vars | Must be unified |
| Privacy posture | strictly local, no egress | hostable, SMTP egress | **Conflict — see §10.1** |

**Reading:** this is a genuinely mixed-architecture estate, not a cosmetic
difference. Any plan that assumes "merge the code" underestimates it.

**The one thing that is *not* a real obstacle:** ASGI/WSGI coexistence. A Flask
WSGI application can be mounted inside a Starlette/FastAPI ASGI application
(`asgiref.wsgi.WsgiToAsgi`, or `a2wsgi`). The HTTP layer can therefore be unified
**without rewriting either framework**. This is what makes a staged strategy
viable rather than a rewrite.

---

## 5. Functional overlap, gaps and complementarity

### 5.1 Overlap — genuinely small

| Area | Overlap |
|---|---|
| Web upload + result rendering | Both accept a large file and render a report. Shell-level duplication only |
| Cisco Secure Client domain | Both reason about the same endpoint agent, from different evidence |
| Report/export | Both produce human-readable output |

**There is no duplicated detection logic.** The two analyze disjoint input types.
Consolidation savings come from the shell (upload, layout, export, packaging,
deployment), not from the analysis engines.

### 5.2 Complementarity — the actual reason to unify

They answer **different halves of the same question**:

- DartHawk describes what the endpoint is **configured** to do, and what its
  software **reported about itself** — authoritative on intent, versions,
  profiles, local state.
- Capture Inspector describes what the endpoint **actually did on the wire** —
  authoritative on behaviour, blind to intent.

The unifying capability is therefore **configuration-versus-behaviour
contradiction detection**, documented in `tls-inspector/docs/HANDOFF.md` §11.4,
with a validated reference case in §8b.

### 5.3 Correlation keys — partially confirmed in code

`HANDOFF.md` §11.5 proposed join keys before DartHawk's source was available.
Four are now **confirmed to exist already** on the DartHawk side:

| Join key | DartHawk implementation | Capture Inspector side |
|---|---|---|
| Umbrella organisation ID | `extract_org_ids_from_enrollments()` | roaming `STARTMSG` |
| Bundle timezone / clock base | `resolve_bundle_timezone()`, `extract_bundle_timezone_name()` | pcapng frame timestamps |
| Secure Client version | `extract_cisco_secure_client_version_from_bundle()` | not available from packets |
| Endpoint OS | `extract_operating_system_from_bundle()` | TTL-based estimate only |

The timezone functions are the most valuable: cross-dataset time correlation was
flagged as the principal risk in §11.5, and DartHawk already resolves the bundle
clock base. **Still unverified:** VPN profile split-tunnel lists, adapter/route
inventory, and certificate trust store — these must be confirmed against a real
bundle before any correlated detector is written.

### 5.4 Gaps common to both

| Gap | Capture Inspector | DartHawk |
|---|---|---|
| Automated test suite | none (scratch script only) | none found |
| CI pipeline | none | none |
| Linting / formatting gate | none | none |
| Dependency pinning | exact | ranges |
| Structured logging | ad hoc | ad hoc |
| Versioning / release process | none | none |

Neither platform currently has a pipeline. Project ATLAS is therefore not a
migration of an existing CI/CD setup — it is the first one.

---

## 6. Unification strategy — options considered

| Option | Description | Assessment |
|---|---|---|
| **A. Rewrite one into the other** | Port DartHawk to FastAPI, or Capture Inspector to Flask | **Rejected.** ~8.5 k lines of validated domain logic per side; re-deriving it risks losing correctness that was established empirically |
| **B. Monorepo, two engines, one shell** | Keep both analysis engines intact as packages; unify HTTP shell, UI, packaging, CI; add a correlation layer above both | **Recommended** |
| **C. Keep separate, add a third correlator** | Two deployments plus a service that consumes both outputs | Preserves the split; triples the operational surface |
| **D. Full rewrite** | New codebase from both | **Rejected.** Discards the documented detector contract and the blind-spot catalogue, which are the product's differentiator |

### 6.1 Recommended target structure

```
Project ATLAS/
  atlas/                          # the repository
    packages/
      capture_inspector/          # today's tls-inspector/app  (engine, unchanged)
      darthawk/                   # today's darthawk.py, progressively split
      atlas_core/                 # shared: models, correlation, evidence contract
    apps/
      web/                        # single HTTP shell + unified UI
    tests/
      unit/  integration/  golden/
    .github/workflows/            # CI pipeline
    docs/
```

**Sequencing principle:** *no behaviour change and no code move in the same
step.* Each engine is first wrapped and covered by golden tests, and only then
relocated.

### 6.2 Phased path

| Phase | Goal | Exit criterion |
|---|---|---|
| **0. Baseline** | Golden-output tests for both engines against known inputs | Both engines produce byte-stable output on a fixed sample set |
| **1. Pipeline** | CI: lint, test, build, on every PR | Red build blocks merge |
| **2. Contract** | Freeze each engine's output as a versioned schema | `AnalysisResult` and the DartHawk result documented and validated |
| **3. Shell + async** | One HTTP app; DartHawk mounted as WSGI under ASGI; **analysis moved to a job worker** (§11.1); one UI shell | Both analyses reachable from one URL, engines untouched, no analysis inside a request |
| **4. Correlation** | `atlas_core` correlator: config-vs-behaviour findings | First cross-dataset finding citing both sources |
| **5. Structure** | Split `darthawk.py` into modules behind its now-tested contract | No output change; tests green |

Phase 0 is mandatory before anything else. Without golden tests there is no way
to prove a refactor changed nothing — and the primary risk in this consolidation
is silently degrading detections that were validated empirically.

---

## 7. CI/CD design

### 7.1 Pipeline stages

| Stage | Content | Gate |
|---|---|---|
| Lint | `ruff` (format + lint), single config | Blocking |
| Unit | Per-package tests, no I/O, no fixtures over 1 MB | Blocking |
| Golden | Both engines against committed sample inputs; compare normalised output | Blocking |
| Build | Clean-machine install from pinned requirements, then start the app and probe both engines | Blocking |
| Launchers | `run.ps1` and `run.sh` parse-checked on Windows and macOS | Blocking |
| Security | Dependency audit (`pip-audit`), reject committed capture/key material | Blocking on high severity |
| Publish | Tagged release: source tree + launchers | Manual approval |

There is no image build stage. ATLAS is deployed onto the host (§10.5), so the
artifact under test is the **install itself** - a virtualenv built from pinned
requirements and started exactly as production starts it.

### 7.2 Decisions the pipeline forces

1. **Pin every dependency exactly**, both packages, one requirements file per
   package.
2. **Single Python version** across engines, CI and the production host.
3. **Remove runtime `pip install` from the application start path** (§3.1).
   Installation belongs to `run.ps1` / `run.sh` and to the deployment procedure,
   never to application start-up. `DARTHAWK_AUTO_INSTALL=0` is set by the shell
   before DartHawk is imported.
4. **Build matrix must cover Windows, macOS and Linux**, because the estate is
   mixed: desktop launchers for the first two, systemd on the third.
5. **tshark is an external runtime dependency that nothing pins for us.** Since
   there is no image, CI installs it explicitly and the application reports its
   version at `/healthz`; a missing tshark is logged as an error at start-up
   rather than silently disabling packet analysis.

### 7.3 Test data — a governance problem, not a technical one

Golden tests need real inputs, and both input types are **sensitive**: packet
captures can contain live traffic and TLS key material; DART bundles contain
endpoint identifiers, organisation IDs and logs. Capture Inspector's
`.gitignore` already blocks captures, HARs and key logs from the repository, and
CI fails the build if any are ever committed.

**Therefore:** golden fixtures must be either sanitised, synthetic, or stored
outside the repository and referenced by hash. See §10.3.

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Refactor silently degrades a validated detector | High — correctness is the product | Phase 0 golden tests before any move |
| Privacy posture conflict resolved implicitly | High — a local-only tool becoming hostable changes its threat model | Resolved explicitly in §10.1; requirements listed there |
| **tshark version drift or absence** | Medium — findings depend on tshark field output, and absence disables packet analysis *silently* | Version reported at `/healthz`; error logged at start-up; installed by the deployment procedure. Mitigated in practice by single-instance deployment (§10.5) |
| Monolith split introduces regressions | Medium | Split only after the contract is frozen and tested (Phase 5) |
| Sensitive fixtures committed | High | Sanitised/synthetic fixtures; ignore rules at repository root; CI rejects capture and key material |
| Detector category not registered | Medium — finding computed but invisible | Known trap, documented in HANDOFF §7.1; add a CI check asserting every emitted category is registered |

---

## 9. Immediate opportunities (independent of unification)

These are worth doing regardless of which strategy is chosen:

1. Register the `network_info` category so its findings become visible.
2. Re-baseline the stale regression file.
3. Replace `_gold_test.py` with a real test.
4. Make DartHawk's runtime auto-install opt-in.
5. Unify dependency pinning policy.
6. Add a CI check for the category-registration trap.

---

## 10. Decisions taken

The blocking questions in the first revision of this document have been answered.
They are recorded here as decisions, with the consequences each one creates.

### 10.1 Target model: SaaS / PaaS — **decided**

> ATLAS is delivered as a hosted service. Changing Capture Inspector's local-only
> model for the unification is accepted. Both platforms unify, each fills the
> other's gaps, and the product improves on top of the combined capability.

**This supersedes Capture Inspector's "100 % local, nothing is uploaded"
product principle.** That principle is stated in `tls-inspector/docs/HANDOFF.md`
§1 and must be rewritten there rather than left contradicting the delivered
system.

**What does not change:** the *evidence* principle — a finding must cite the
on-wire fact that produced it, and the tool says so when a question is
unanswerable. That is about correctness, not about locality, and it remains the
differentiator.

**What this decision creates.** Hosting means packet captures, TLS key logs and
DART bundles leave the analyst's machine and are processed on shared
infrastructure. These are among the most sensitive artifacts in networking: a
capture plus its key log fully decrypts the session it recorded, and a DART
bundle carries endpoint and organisation identifiers. The following stop being
optional and become **requirements of the design**, not follow-up work:

| Requirement | Reason |
|---|---|
| Authentication and authorisation | The service is multi-user by definition |
| Tenant isolation of uploads and results | One customer's capture must never be reachable from another's session |
| Encryption in transit and at rest | Uploads contain traffic and key material |
| Defined retention and deletion, enforced automatically | Indefinite retention of captures is not defensible |
| Secrets from the environment, never in the repository | Already DartHawk's posture (§3.1); extend to the whole product |
| Audit logging of upload, access and deletion | Required to answer "who saw this capture" |
| Upload size and rate limiting | Current limits are 1 GB (Capture Inspector) and 1.5 GB (DartHawk) per request |

### 10.2 Operating systems — **decided**

> Launchers for **macOS and Windows** for now. **Linux is the production hosting
> target**, and will become the only one later.

Consequence: CI must cover three operating systems - desktop launchers for two,
and the Linux install path that production uses. Capture Inspector's
PowerShell/`.exe` tooling is Windows-only by design and now has a macOS/Linux
equivalent in `run.sh`; both are transitional.

### 10.3 Test fixtures — **decided, with a constraint added**

> Commit what does not matter for now; perform the sanitisation pass afterwards.

Accepted for **non-sensitive** fixtures, which unblocks Phase 0 immediately.

**Constraint that must hold regardless:** TLS key logs and captures containing
real user traffic must not enter the repository at any point. Git history is
permanent — a file removed in a later commit remains retrievable, so "sanitise
later" does not work for anything already pushed. Capture Inspector's
`.gitignore` already blocks `*.pcap`, `*.pcapng`, `*.har`, `*.keys`, `*.keylog`
and key-log patterns; those rules stay in force and are promoted to the
repository root.

**Practical sequence:** start Phase 0 with synthetic and already-public captures,
plus DART bundles confirmed to contain no customer data. Anything uncertain waits
for the sanitisation pass rather than being committed provisionally.

### 10.4 Deployment mechanism: no containers — **decided**

> Move away from Docker. Run both platforms unified as one application, directly
> on the host. Single instance; no multi-instance deployment.

**Removed:** `Dockerfile` (root, and the unified one drafted for `deploy/`),
`docker-compose.yml`, `.dockerignore`, `Procfile`. The root `Dockerfile` and
`Procfile` were in any case **already broken** after the restructure - both still
referenced `darthawk:app` at the repository root and a root `requirements.txt`
that no longer exists.

**Replaced with:**

| Concern | Container did it | Now done by |
|---|---|---|
| Dependency install | image build | `run.ps1` / `run.sh`, and the deploy procedure |
| tshark provisioning | `apt-get` in the image | host prerequisite; version surfaced at `/healthz` |
| Process supervision | container runtime | `systemd` (`deploy/atlas.service`) |
| Unprivileged execution | `USER atlas` | `User=atlas` + systemd sandboxing |
| Filesystem confinement | image layers | `ProtectSystem=strict`, `ReadWritePaths` |
| Resource limits | container limits | `MemoryMax`, `TasksMax` |
| Health check | `HEALTHCHECK` | `/healthz` + `Restart=on-failure` |

**What this costs, stated honestly:** the Wireshark version is no longer pinned
alongside the code, so it becomes part of the deployment procedure rather than
part of the artifact (§11.2). With a single instance this is manageable; it would
not be across a fleet.

**Consistency note:** §10.1 records SaaS/PaaS as the target model. That decision
concerns *who the software serves* - a hosted, multi-user service rather than a
local desktop tool - and it stands. This decision concerns *how it is packaged*,
and the two are independent: a hosted service supervised by systemd on one Linux
host satisfies both. The security requirements listed in §10.1 are unaffected and
still outstanding.

### 10.5 Still open

Not blocking Phase 0, but needed before Phase 3:

- **Ownership and branch policy.** Atlas is owned by `amarora2_cisco`; Capture
  Inspector originates from `jmorenoc_cisco`. Who approves merges to `main`, and
  should branch protection be enabled before the pipeline is relied upon?
- **DartHawk's single-file design** — deliberate or incidental? If deliberate,
  Phase 5 is dropped.
- **First correlated finding to target.** The validated VPNaaS
  double-interception case (`HANDOFF.md` §8b) is the strongest candidate:
  evidence for both the good and the bad state already exists.
- **Naming** — is ATLAS the product or the programme, and do the two engines keep
  their identities in the UI?

---

## 11. Consequences of the SaaS decision on the architecture

Two issues follow directly from §10.1 and change the target design. Neither was
visible while both tools were desktop applications.

### 11.1 Synchronous analysis does not survive hosting

Both platforms analyse **inside the HTTP request**. DartHawk's own deployment
descriptors show the strain already: `--timeout 120` with 2 workers × 4 threads.
Capture Inspector accepts captures up to 1 GB and shells out to tshark for the
full decode.

On shared infrastructure this fails in a predictable way: one large upload
occupies a worker for minutes, concurrent users queue behind it, and platform
routers terminate long requests regardless of the application timeout.

**Required change:** move analysis to an **asynchronous job model** — upload
returns a job identifier, a worker processes it, the client polls or is notified.
This is a structural change to both engines' entry points, though **not** to the
engines themselves: Capture Inspector's documented integration boundary
(`analyze.analyze()` → `AnalysisResult`) is already a pure function of its
inputs, which is exactly what a job worker needs. DartHawk's entry points need
the equivalent seam introduced.

This should be decided in Phase 3, not deferred, because retrofitting async after
the unified shell exists means rewriting it twice.

### 11.2 tshark is an unpinned runtime dependency

Capture Inspector shells out to tshark for every packet decode, and its findings
depend on tshark's field output. With no image, **nothing pins the Wireshark
version** - that becomes part of the deployment procedure.

The practical risk is lower than it first appears, because ATLAS is a single
instance on a single host (§10.5): there is no fleet for versions to drift
across. The real hazard is different and worse - `find_tshark()` **degrades
silently**. When tshark is absent, Capture Inspector skips packet analysis and
returns a result that looks like a capture containing nothing of interest.

**Implemented:** the unified shell reports tshark's presence, path and version at
`/healthz`, logs an error at start-up when it is missing, and both launchers
print the detected version before starting. CI asserts that the running
application actually detects tshark, so a packaging regression fails the build.

tshark also parses uploaded files, which are hostile input by definition. The
isolation an image would have provided is declared instead in
`deploy/atlas.service`: unprivileged user, `ProtectSystem=strict`,
`NoNewPrivileges`, `PrivateTmp`, a single writable path for uploads, and memory
and task ceilings so one large capture cannot take the host down.

---

## 12. What has been done so far

- `Project ATLAS` workspace created at `c:\DEV Copilot\Project ATLAS`.
- Repository cloned to `Project ATLAS/atlas`, on branch `add-tls-inspector`.
- Both platforms reviewed from source; every metric in this document is measured.
- Architectural decisions recorded in §10.
- **No file in either platform has been modified.**
