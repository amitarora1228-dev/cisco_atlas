# ATLAS documentation

**Start with [STATE.md](STATE.md).** It is the living state of the project: what
exists, where each piece stands, what is known to be broken, and the traps that
have already cost time. It is kept current as work happens - see
[`AGENTS.md`](../AGENTS.md) for the rule that requires it.

| Document | Read it when |
|---|---|
| **[STATE.md](STATE.md)** | Always, first. And update it before you finish |
| [ASSESSMENT.md](ASSESSMENT.md) | You need the platform comparison, the unification strategy, or *why* a decision was taken and what it committed us to |
| [PHASE1_UNIFICATION.md](PHASE1_UNIFICATION.md) | You are working on the shared UI, and want the measurements the plan rests on |
| [PHASE2_CORRELATION.md](PHASE2_CORRELATION.md) | You are building correlation, or deciding what to build next |

## Engine documentation

Each engine keeps its own reference material.

| Document | Contents |
|---|---|
| [`capture_inspector/docs/DETECTION.md`](../packages/capture_inspector/docs/DETECTION.md) | The authoritative detector catalog: what each one detects, the exact on-wire signal, and what it cannot see |
| [`capture_inspector/docs/HANDOFF.md`](../packages/capture_inspector/docs/HANDOFF.md) | Capture engine internals, its data model, and the traps found building it |
| [`capture_inspector/docs/ARCHITECTURE.md`](../packages/capture_inspector/docs/ARCHITECTURE.md) | Capture engine layout and pipeline |
| [`capture_inspector/docs/MODULES.md`](../packages/capture_inspector/docs/MODULES.md) | Module-by-module reference |
| [`capture_inspector/docs/VALIDATION_GAPS.md`](../packages/capture_inspector/docs/VALIDATION_GAPS.md) | What has not been validated, and why that matters |
| [`darthawk/README.md`](../packages/darthawk/README.md) | Running the bundle engine standalone |

## The two things that govern everything

**Evidence or nothing.** A finding must cite what produced it; where the inputs
cannot answer a question, the tool says so instead of guessing. Correlated
findings must cite both the declared and the observed side.

**Never commit evidence.** Captures, HARs, key logs and DART bundles are ignored
at the repository root and CI fails if one appears. Git history is permanent.
