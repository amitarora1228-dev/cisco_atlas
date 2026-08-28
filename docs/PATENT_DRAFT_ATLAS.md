# ATLAS — Technical Draft for Patent Consideration

**Status:** working draft, not a filing. Technical description only.
**Scope:** the ATLAS correlation layer (`packages/atlas_core`).
**Relationship to prior document:** `packages/capture_inspector/docs/PATENT_DISCLOSURE.md`
covers single-artefact packet analysis (interception detection, block-page
classification, pinning suppression). This draft covers what that document does
not: correlating *multiple independent artefacts* into a single account of one
session. The two are complementary and should be assessed together.

---

## 1. What the system does

ATLAS ingests diagnostic artefacts that are normally read separately by a human
expert — a Cisco DART support bundle, one or more packet captures taken at
different points on the path, and optionally a browser HAR — and produces a
single reconciled account of a network session.

The organising idea is a division between two kinds of evidence:

| Artefact | Evidence class | Answers |
|---|---|---|
| DART bundle | **Declaration** | What the endpoint was configured to do, and what its software reported about itself |
| Packet capture | **Measurement** | What the endpoint actually did on the wire |
| HAR | **Application view** | What the browser believed it requested and received |

Each is individually misleading. A HAR records a *synthetic* server address when
the endpoint is steered — an address that exists nowhere on the network. A
capture of a steered session shows two legs, one carrying the real TLS SNI to a
local listener and one encrypted tunnel that names no hosts. A bundle knows which
connections the agent handled but has no idea which website any of them was.

The value is not in analysing any one of them better. It is in detecting **where
the declaration and the measurement disagree**, which neither artefact can
establish alone.

---

## 2. Mechanisms worth examining for novelty

### 2.1 Evidence-typed findings with enforced dual citation

Findings are not free-form. Each correlated finding carries an explicit
`Assertion` type:

- `PRESENCE` — something was observed. Self-proving; reportable unconditionally.
- `ABSENCE` — something was *not* observed. Ambiguous by nature: "no traffic
  reached the proxy" is a fault only if steering was expected. The system
  therefore **refuses to raise an absence claim without a declared expectation**
  to test it against.
- `CONTRADICTION` — declaration and measurement disagree.

Every `Evidence` object is bound to the source that produced it
(`CAPTURE` or `BUNDLE`) and carries a locator — a file path inside the bundle, or
a capture frame/flow key. A `CorrelatedFinding` validates at construction that it
cites **both** a declared and an observed side, so a reader can always see which
half is measurement and which half is claim. This is a structural guarantee, not
a documentation convention.

The distinguishing property against generic log-correlation prior art: the system
encodes *epistemic status* as a first-class type and enforces it mechanically,
rather than emitting undifferentiated "events" and leaving interpretation to the
reader.

### 2.2 Graded join strength, never collapsed

Links between artefacts are labelled with how they were established, and the
label survives into the output:

- **`EXACT`** — The agent names each connection it handles as
  `<proto>_<srcport>__<dstip>:<dstport>` (prefixes `tcp_`, `tls_`, `http2_`).
  That string is a complete TCP connection identity, so matching it against a
  capture requires no clock and admits no ambiguity.
- **`OBSERVED`** — A hostname seen in TLS SNI on the wire, matched to the same
  hostname in the HAR. The wire is the measurement.
- **`ASSOCIATED`** — Anything resting on time or on HTTP/2 multiplexing. Many
  browser requests share one tunnel connection, so a request cannot be attributed
  to a specific tunnel flow.

An association is never rendered as proof. Most correlation tooling presents a
single confidence score or none at all; the claim here is the taxonomy plus the
guarantee that a weaker join cannot be silently promoted.

### 2.3 Connection-identity episode splitting

A ZTA agent log routinely spans days, and ephemeral source ports are reused
within that span. A connection identity is therefore unique only inside a time
window. The system splits an identity's log lines wherever the agent fell silent
for longer than a threshold (currently 5 minutes) and treats each run as a
separate connection.

Without this, port reuse silently merges unrelated connections into one — a
failure mode that produces confident, wrong correlations rather than obvious
errors.

### 2.4 Initial-sequence-number path stitching (strongest candidate)

When captures are taken at several points along a path
(`client — Zproxy — FWaaS — CNHE — FTD — resource`), reconstructing which
observations belong to the same transaction is normally guesswork. ATLAS
separates devices by what they do to a connection:

- A **forwarding** device (an FTD routing traffic, a NAT) passes the TCP sequence
  number through untouched. NAT rewrites addresses and ports but *never* sequence
  numbers. The same connection observed from two vantage points therefore carries
  the **same initial sequence number**, which is an exact join that survives
  address translation.

- A **proxy** (Zproxy, FWaaS, ASAc, a resource connector) terminates the client's
  connection and opens its own — new sequence number, new ports, often a new
  source address. No packet is shared, so no exact join exists. These legs are
  associated by named destination and position in time only, inside a bounded
  window (currently 8 s), and reported as association.

Two consequences that appear to be the most defensible material here:

1. **The join doubles as a clock measurement.** Because a sequence-number match
   identifies *the same packet* observed twice, it directly yields the clock
   offset between two capture devices — something no other signal in the system
   can provide. Offsets are only trusted when several connections agree
   (minimum 3 samples) and are rejected beyond 12 hours, so a coincidence of
   ports cannot masquerade as a measurement.

2. **Hop order is inferred, not supplied.** Where a proxy joins two legs, both
   captures contain that proxy's own address — once as a destination, once as a
   source. That shared address is the pivot from which the chain is ordered. The
   operator is not asked to declare the topology.

The system also reports what it *cannot* prove: where a device log (FTD/ASAc
connection events carrying the NAT translation directly) would join more strongly
than a capture pair, the absence is recorded in `notes` rather than filled in
with a guess.

### 2.5 Signature folding and benign-signal suppression

Raw endpoint logs are folded into counted signatures before presentation:
timestamps, file/line references, IP addresses, hex identifiers and numeric
literals are masked to produce a normal form, and near-identical lines collapse
into `N× <signature>`.

Separately, broad detectors are paired with benign-line filters. A regex for
connectivity errors also matches periodic status lines such as
`Server connectivity: Ok` — which, surfaced as a headline count, produced "120
issues" that were all healthy. Suppressing known-benign forms *before* counting
is what makes an automatically generated severity count trustworthy enough to
show an operator.

---

## 3. Reduction to practice

Working implementation, in production use for Cisco TAC escalations:

| Component | Role | Lines |
|---|---|---|
| `packages/darthawk` | Bundle engine (declaration) | ~9,000 Py + ~7,500 JS |
| `packages/capture_inspector` | Capture/HAR engine (measurement) | ~5,500 Py |
| `packages/atlas_core/flows.py` | Three-artefact flow correlation | ~2,360 |
| `packages/atlas_core/path.py` | Multi-vantage path stitching | ~560 |
| `packages/atlas_core/{facts,correlation}.py` | Shared fact vocabulary, evidence model | — |

Approximately 35,000 lines of application code with golden and integration test
coverage (`tests/test_flow_correlation.py`, `tests/test_connection_story.py`).

---

## 4. Honest prior-art positioning

To be worked through with counsel, but stated plainly now so review does not
discover it later:

**Not novel on its own:** log aggregation and correlation generally; packet
capture analysis (Wireshark and every derivative); parsing vendor support
bundles; clustering similar log lines; timeline visualisation.

**Where the argument has to live:** the combination of (a) explicit
declaration-versus-measurement typing with mechanically enforced dual citation,
(b) a join-strength taxonomy that structurally prevents association being
reported as proof, and (c) sequence-number-based multi-vantage stitching that
simultaneously yields path order and inter-device clock offset.

**Candid ranking of the candidates:**

1. §2.4 ISN stitching + derived clock offset — strongest; concrete, measurable,
   non-obvious, and hard to reach accidentally.
2. §2.1 evidence typing with enforced dual citation — good, if framed as a
   mechanism rather than a methodology.
3. §2.3 episode splitting — narrow but genuinely non-obvious; likely a dependent
   claim.
4. §2.2 join taxonomy — supports 1 and 2; probably not standalone.
5. §2.5 folding/suppression — useful, but closest to existing log-clustering art.

**Substrate, not invention** — must not be claimed: DART bundle collection,
tshark, the Secure Client log format, TLS/TCP behaviour itself.

---

## 5. Open questions before anything is filed

- Ownership and process: this is Cisco work product; it routes through Cisco's
  invention disclosure process, not a direct filing.
- Prior disclosure: has ATLAS been shown outside Cisco, demoed to customers, or
  described in a TechZone article? Public disclosure timing affects filing.
- Overlap with the existing `capture_inspector` disclosure — file jointly or
  separately?
- Whether any of the above is already covered by existing Cisco patents in the
  SSE/telemetry space.
