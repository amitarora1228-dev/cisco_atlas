# ATLAS — Phase 1 Unification Plan

**Status:** plan only. No structural change has been made. Section 7 lists
questions that should be answered before execution.

**Naming note:** the product is *DartHawk* (from Cisco DART bundles), not
"Darkhawk". Used consistently below.

---

## 1. Summary of both platforms

Measured from source, not estimated.

| | Capture Inspector | DartHawk |
|---|---|---|
| Purpose | PCAP/PCAPNG + HAR analysis: TLS, certs, DNS, proxy/SWG, network health | Cisco DART ZIP bundle analysis: ZTA/VPN/Umbrella/UZTNA/EDLP/Duo diagnostics |
| Backend | FastAPI (ASGI), 26 modules, 8 491 lines | Flask (WSGI), 1 module, 8 801 lines |
| UI delivery | Static SPA (`index.html` + `fetch`) | Jinja2 server-rendered templates |
| HTML | 25.1 KB | 47.6 KB |
| CSS | 61.8 KB bespoke | 35.7 KB custom **+ Tailwind via CDN** |
| JS | 81.3 KB | 398.7 KB + 44.4 KB (`flow-utils.js`) |
| Navigation | Left rail: Inspect / Flows / Hosts / Certs / DNS / Report / Learn | Module rail: ZTA / VPN / Umbrella / UZTNA / EDLP / Duo Desktop |
| Chrome | Header with logo, tshark status, help, avatar | Top toolbar: Read Me / Feedback / Darker Theme |
| Theming | Single theme | Light + "darker", persisted in `localStorage` |
| External runtime deps | Google Fonts (Inter) | **`https://cdn.tailwindcss.com`** |
| Output | Structured `AnalysisResult` → findings with severity + evidence | `{message, module, details}` where `details` is narrative text, plus per-check structured payloads |

### The difference that matters most

The two have **opposite interaction models**:

- **Capture Inspector is batch.** Upload once, every detector runs, results are
  browsed across fixed views. The user chooses nothing about the analysis.
- **DartHawk is query-driven.** The user picks a module, then an access mode,
  then a specific check, then filters, then submits. Each run answers one
  question.

This is not a styling difference and cannot be resolved by CSS. It is the
central design problem of a single dashboard, and Section 4 addresses it
directly.

### Current integration state

Both already run in one process behind one origin (`/capture`, `/bundle`), each
on its own framework, via a WSGI-to-ASGI adapter. DartHawk is therefore
*already* a Python module inside the ATLAS application. What Phase 1 adds is
making it a **module of the user experience**, which is a different job.

---

## 2. Recommended unification strategy

### Options considered

| Option | Description | Verdict |
|---|---|---|
| **A. Port DartHawk's UI into Capture Inspector's SPA** | Rewrite 443 KB of JS into the existing design system | **Rejected.** That JS encodes DartHawk's entire interaction and rendering logic for six modules and ~10 check types. Re-deriving it is where capability gets lost silently, and the brief forbids that |
| **B. Shared chrome, engines in iframes** | One ATLAS header/nav, each engine in an iframe | **Rejected.** Zero risk, but also not unification. Breaks deep links, duplicate scrollbars, and blocks Phase 2 correlation from ever sharing state |
| **C. Shared shell + design tokens + progressive convergence** | One ATLAS shell owns chrome, routing and theme. Each engine keeps its markup and JS, retargeted onto shared CSS custom properties. Components converge over time | **Recommended** |
| **D. Full rewrite of both** | New unified frontend | **Rejected.** Discards two working products to solve a styling problem |

### Why C is safe here — and the evidence for it

Two measurements make C viable rather than aspirational:

1. **Zero element-ID collisions.** 156 IDs in DartHawk's markup, 66 in Capture
   Inspector's, **no overlap**. The two DOMs can coexist in one document without
   renaming anything.
2. **Only one hard CSS blocker exists**, and it is one line of configuration —
   see below.

### The single blocking issue: Tailwind preflight

DartHawk loads `https://cdn.tailwindcss.com` with **no configuration**, so
Tailwind's *preflight* is active. Preflight is a global reset: it restyles
`html`, `body`, headings, lists, form controls and more, unscoped. Put both UIs
in one document as-is and **Capture Inspector's styling is destroyed**.

The fix is surgical:

```html
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config = { corePlugins: { preflight: false } };</script>
```

DartHawk's own `app.css` must then supply whatever reset its markup actually
relied upon. This needs verifying visually, not assuming — see Section 5, Step 1.

**Separately:** the Tailwind Play CDN is explicitly documented as *not for
production* — it compiles CSS in the browser on every page load. It is also a
runtime network dependency, the same class of problem as the `pip install` at
application start-up that we already removed. **Recommendation: vendor Tailwind
locally.** This is independent of unification and worth doing regardless.

---

## 3. Proposed ATLAS structure

Backend layout is already in place and needs no further restructuring for
Phase 1:

```
packages/
  capture_inspector/     PCAP/HAR engine          (unchanged)
  darthawk/              DART bundle engine        (unchanged)
  atlas_core/            shared facts + correlation (Phase 2 lives here)
apps/
  web/
    main.py              ASGI shell, mounts both engines
    shell/               NEW - the ATLAS dashboard
      templates/         shell chrome
      static/
        atlas-tokens.css NEW - design tokens, single source of visual truth
        atlas-shell.css  NEW - header, nav, layout
        atlas-shell.js   NEW - routing, theme, module registry
```

### Module registry

Each analysis surface registers itself rather than being hardcoded in the shell.
This is what makes "preserve everything" achievable and keeps Phase 2 additive:

| Field | Purpose |
|---|---|
| `id` | `capture`, `bundle` |
| `label`, `icon` | Navigation presentation |
| `accepts` | File extensions the module handles (`.pcap/.pcapng/.har` vs `.zip`) |
| `mount` | URL prefix it is served from |
| `views` | Its own sub-navigation, contributed to the shell rail |

`accepts` is what later allows one upload control to route by file type without
the shell knowing anything about either engine.

### Naming

- Product name: **ATLAS**
- Capture Inspector becomes the **Traffic Capture** module
- DartHawk becomes the **Endpoint Bundle** module

Internal package names (`capture_inspector`, `darthawk`) should **not** be
renamed in Phase 1. Renaming them touches every import, every doc reference and
the entire detection catalog, for zero user-visible benefit. Display names are a
presentation concern; keep them there.

---

## 4. UI/UX unification plan

### Layer 1 — Design tokens (the mechanism for visual consistency)

One `atlas-tokens.css` defines colour, spacing, radius, typography and elevation
as CSS custom properties. Both stylesheets are then retargeted onto them:

```css
/* before */  background: #0b1220;
/* after  */  background: var(--atlas-surface-1);
```

This is the highest-value, lowest-risk step: it produces genuine visual
consistency **without touching a single line of markup or JS in either engine**,
and it is reversible per-declaration.

### Layer 2 — Shared chrome

One header and one navigation rail, owned by the shell:

```
┌──────────────────────────────────────────────────────────────┐
│  ATLAS            [health: tshark ready]   Theme  Help  User  │
├──────────┬───────────────────────────────────────────────────┤
│ ANALYSIS │                                                    │
│  Traffic │                                                    │
│  Bundle  │              active module renders here            │
│          │                                                    │
│ TRAFFIC  │   (module contributes its own sub-navigation)      │
│  Flows   │                                                    │
│  Hosts   │                                                    │
│  Certs   │                                                    │
│  DNS     │                                                    │
│  Report  │                                                    │
└──────────┴───────────────────────────────────────────────────┘
```

The rail is two-level: **module** at the top, that module's **views** beneath.
Capture Inspector's existing seven views and DartHawk's module rail both become
contributions to this structure rather than competing navigations.

DartHawk's Read Me / Feedback / Theme toolbar moves into the shell header, so
there is one place for global controls.

### Layer 3 — Reconciling the two interaction models

This is the real design work. Capture Inspector runs everything on upload;
DartHawk asks the user what to check. Forcing either into the other's shape
would break a working workflow.

**Proposed resolution — one upload, deferred questions:**

1. **One drop zone** accepts any supported artifact. File type selects the
   module (`.zip` → Bundle, `.pcap/.pcapng/.har` → Traffic). The user no longer
   picks a module manually; the file already says which one it is.
2. **Traffic** proceeds exactly as today — analysis runs immediately.
3. **Bundle** proceeds to its existing module/check selection, unchanged, now
   presented as step 2 of the same flow rather than a separate page.
4. Results render in the shell with a consistent results frame.

This preserves DartHawk's query-driven model completely — it simply stops being
the *first* thing the user sees. Nothing is removed; one step is reordered.

### Layer 4 — Convergence (ongoing, not Phase 1)

Once tokens and chrome are shared, individual components can migrate to shared
patterns opportunistically. Explicitly **not** a Phase 1 deliverable.

---

## 5. Phase 1 implementation plan

Ordered so that the riskiest reversible thing happens first and every step is
independently verifiable.

| Step | Work | Verification | Risk |
|---|---|---|---|
| **0. Baseline** | Capture reference screenshots of every view in both UIs, and record current behaviour | A visual record exists to diff against | none |
| **1. Neutralise Tailwind preflight** | Add the config; vendor Tailwind locally | DartHawk renders **identically** to the Step 0 baseline | **highest — do it first, alone** |
| **2. Design tokens** | Add `atlas-tokens.css`; retarget both stylesheets | Both UIs render with no unintended change | low, reversible |
| **3. Shell chrome** | Header, two-level rail, theme control, module registry | Both modules reachable; all views present | medium |
| **4. Mount modules in the shell** | Serve both inside the shell layout | Every Step 0 view still reachable and functional | medium |
| **5. Unified upload** | One drop zone routing by file type | Both artifact types analyse correctly end to end | medium |
| **6. Rename to ATLAS** | Display names, titles, logo, docs | No functional change | low |

**Step 1 must ship alone.** It is the only step that can break DartHawk's entire
appearance, and isolating it means a regression has exactly one possible cause.

### Definition of done for Phase 1

- Every view in both Step 0 screenshots is reachable and functional
- No capability removed from either engine
- One header, one navigation, one theme, one upload entry point
- No new runtime network dependency
- Tests and lint green; CI smoke test passes

---

## 6. Risks, dependencies and assumptions

### Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Tailwind preflight removal changes DartHawk's appearance** | High — its markup may depend on the reset | Step 1 in isolation, diffed against Step 0 screenshots |
| **443 KB of DartHawk JS has undocumented DOM assumptions** | High — moving markup into a shell could silently break handlers | Do not restructure its markup in Phase 1. Wrap, do not rewrite |
| **No automated UI tests exist for either platform** | High — regressions are invisible until a human looks | Step 0 screenshots are the only safety net available; consider adding smoke tests for key flows |
| **Two independent theme systems** | Medium | Shell owns theme; DartHawk's `localStorage` key is migrated, not duplicated |
| **Capture Inspector's `?v=` cache-bust is manual** | Medium — stale assets look like bugs | Automate the cache-bust in the shell build |
| **Query-driven workflow feels buried behind upload** | Medium — a usability regression for DartHawk users | Validate step 3 of Section 4 with an actual DartHawk user before building it |

### Dependencies

- **A real DART bundle** for end-to-end verification. Still outstanding, and it
  also blocks validating the Phase 2 identity join against production data.
- A representative PCAP for the traffic module (available).
- Access to someone who uses DartHawk regularly, for Step 5 validation.

### Assumptions — flag any that are wrong

1. Both UIs' current behaviour is considered correct; Phase 1 changes appearance
   and navigation, not analysis.
2. DartHawk's six modules and all check types stay exactly as they are.
3. Browser support is modern evergreen only.
4. No authentication is in scope for Phase 1 (still outstanding from the SaaS
   decision, and tracked separately in `ASSESSMENT.md` section 10.1).
5. "Module inside ATLAS" means a UI module; the Python packaging is already done.

---

## 7. Clarifying questions before execution

1. **Tailwind.** May DartHawk's markup be modified where preflight removal
   changes its appearance, or must its rendering stay pixel-identical? This
   determines whether Step 1 is an hour or a week.

2. **Visual direction.** Should ATLAS adopt Capture Inspector's design language,
   DartHawk's, or a new one? Both are Cisco-branded but differ in palette,
   density and typography.

3. **The upload flow.** Is "one drop zone, file type selects the module"
   acceptable to DartHawk's regular users, who currently choose a module first?
   This is the one change that alters an established workflow.

4. **Theme.** Keep DartHawk's light/darker toggle for the whole of ATLAS, or
   standardise on one theme?

5. **Feedback endpoint.** DartHawk's `/feedback` emails a fixed default
   recipient. Does it stay, and should it be ATLAS-branded?

6. **Scope boundary.** Is the unified upload (Step 5) in Phase 1, or is Phase 1
   complete at shared chrome and navigation, with upload unification deferred?

7. **DartHawk ownership.** Is there an owner who must review UI changes to it
   before merge?
