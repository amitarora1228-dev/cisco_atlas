# Project ATLAS

Unified Cisco endpoint and network diagnostics. ATLAS combines two analysis
engines behind one web interface:

| Engine | Input | Answers |
|---|---|---|
| **DartHawk** | Cisco DART ZIP bundle | What the endpoint is **configured** to do, and what its software reported about itself |
| **Capture Inspector** | PCAP/PCAPNG, HAR, optional TLS key log | What the endpoint **actually did** on the wire |

Separately, each answers half a question. Together they answer the one that
matters: **does observed behaviour match declared configuration?** Neither tool
can produce that answer alone - a capture cannot cite a configuration profile,
and a bundle cannot observe the wire.

> **Working on this project?** Read [`docs/STATE.md`](docs/STATE.md) first - it
> holds current status, known limitations and the traps already paid for - and
> [`AGENTS.md`](AGENTS.md) for how to work here. Both are kept current as work
> happens rather than on request.

## Requirements

- **Python 3.10+** (3.12 is what CI and production use)
- **tshark** (Wireshark CLI) - required only for packet capture analysis.
  Without it, DART bundle analysis still works; ATLAS reports the degraded state
  at `/healthz` rather than failing quietly.

ATLAS runs directly on the host. There is no container.

## Run it

**Windows**

```powershell
.\run.ps1
```

**macOS / Linux**

```bash
./run.sh
```

Both scripts create the virtualenv, install pinned dependencies, check for
tshark and start the server on <http://127.0.0.1:8000>.

| Path | What |
|---|---|
| `/` | redirects to the bundle analyzer |
| `/bundle/` | DartHawk - DART bundle analysis |
| `/capture/` | Capture Inspector - packet capture analysis |
| `/healthz` | liveness, loaded engines, tshark version, degraded features |

## Layout

```
packages/
  capture_inspector/   PCAP/HAR engine (FastAPI). Detection logic, framework-independent core
  darthawk/            DART bundle engine (Flask). Templates and static assets travel with it
  atlas_core/          Shared models and the cross-engine correlation layer
apps/
  web/                 The unified shell. Mounts both engines behind one origin
tests/
  unit/ integration/ golden/
deploy/                systemd unit for the Linux production host
tools/                 Field scripts and maintenance utilities
docs/                  Assessment, architecture and the unification plan
```

Each engine keeps its own framework and routes. Capture Inspector is ASGI and is
mounted natively; DartHawk is WSGI and is mounted through an adapter. This is
deliberate - it lets the two unify in stages instead of requiring a rewrite, so
neither engine's validated detection logic has to be re-derived.

## Production

ATLAS is deployed onto a Linux host and supervised by systemd. See
[`deploy/atlas.service`](deploy/atlas.service), which contains both the install
steps and the sandboxing settings.

ATLAS binds to `127.0.0.1`. **Terminate TLS and authenticate in a reverse proxy
in front of it.** Uploads are packet captures and DART bundles: a capture
combined with its key log fully decrypts the session it recorded, and a bundle
carries endpoint and organisation identifiers. Neither should be reachable
without authentication.

## Development

```bash
pip install -r requirements-dev.txt
ruff check . && ruff format --check .
pytest -m "not golden"     # unit and integration
pytest -m golden           # engine output regression
```

CI runs lint, tests, a dependency audit, a clean-machine install smoke test, and
a launcher syntax check on Windows and macOS. It also fails the build if capture
or key material is ever committed.

## Documentation

| Document | Contents |
|---|---|
| [`docs/STATE.md`](docs/STATE.md) | **Living project state** — status, known limitations, traps. Read first, update last |
| [`AGENTS.md`](AGENTS.md) | How to work in this repository |
| [`docs/README.md`](docs/README.md) | Documentation index |
| [`docs/ASSESSMENT.md`](docs/ASSESSMENT.md) | Platform comparison, unification strategy, decisions taken |
| [`docs/PHASE2_CORRELATION.md`](docs/PHASE2_CORRELATION.md) | What correlation makes possible, in dependency order |
| [`packages/capture_inspector/docs/DETECTION.md`](packages/capture_inspector/docs/DETECTION.md) | Per-detector catalog: what each detects, how, and what it cannot see |
| [`packages/darthawk/README.md`](packages/darthawk/README.md) | Running the bundle engine standalone |

## The principle that governs both engines

> **Evidence or nothing.** A finding must cite what produced it. Where the input
> cannot answer a question, the tool says so instead of guessing.

This is enforced in code, not merely documented: confidence is capped where a
conclusion is not provable, percentages are withheld when the populations being
compared are not comparable, and detectors are suppressed when other evidence in
the same input contradicts them. Preserve this. Much of the value is in what the
tool refuses to claim.
