# ATLAS Phase 2 — Correlation opportunities

**Status:** forward-looking notes. Nothing here is implemented except the
identity join (§2.1). This is a catalogue of what becomes possible once both
engines' output sits in one model, written while the integration was fresh.

**Principle that governs all of it** — inherited from the capture engine and
non-negotiable in correlated findings:

> A finding must cite what produced it. Where the inputs cannot answer a
> question, say so instead of guessing.

Extended for two sources:

> A correlated finding must cite **both** sides, so a reader can see which half
> is measurement and which half is declaration. `CorrelatedFinding` enforces this
> at construction.

---

## 1. What each engine knows

The two observe **different halves of the same endpoint**. Neither is sufficient
alone, and that asymmetry is the whole opportunity.

| Endpoint bundle (declared / self-reported) | Traffic capture (observed) |
|---|---|
| Organisation ID, Secure Client version, OS | TLS interception, re-signed certificates, issuer |
| Bundle timezone and log timeframe | Frame timestamps, flow durations |
| ZTA enrolment: user, method, time | DNS queries, answers, block pages |
| Trusted Network Detection state | Whether traffic was actually steered |
| Configuration sync state | Which ingress/region traffic reached |
| Server-connectivity events, with causes | TCP resets, retransmissions, zero-window |
| Flows the agent *believes* it handled | Flows that actually left the machine |
| Duo Desktop posture, health | Latency, MTU, QUIC, asymmetric routing |
| Event Viewer entries | Per-interface pathing |

**The rule of thumb:** the bundle knows *intent and internal state*; the capture
knows *what happened on the wire*. Wherever those two describe the same event,
there is a correlation - and wherever they disagree, there is a finding neither
tool could produce alone.

---

## 2. Correlations, by value

### 2.1 Identity join — **implemented**

Organisation ID from the bundle's enrolment records against the org encoded in
the roaming agent's bound SWG proxy hostname.

Runs before everything else and gates it: correlating a bundle from one machine
against a capture from another produces confident nonsense. Mismatch is reported
at high severity and stops further correlation. A missing org on either side
stays silent - unanswerable is not the same as disagreeing.

### 2.2 Time alignment — **highest leverage, not implemented**

The bundle carries its own timezone (`resolve_bundle_timezone`,
`extract_bundle_timezone_name`); the capture carries absolute frame timestamps.
Aligning them puts **log events and packets on one timeline**.

Almost every correlation below depends on this, so it should be built first.

**Caveat that must be preserved:** the two clocks come from different sources and
may differ in offset and resolution. Alignment is *correlation, never proof*, and
the established offset should be recorded and shown, not assumed to be zero.

### 2.3 Agent belief vs wire reality

The bundle lists flows the agent believes it handled - destination, port, time,
disposition. The capture holds the packets. Joining on 5-tuple plus time answers
a question neither can answer alone:

- The agent logged a flow as steered. **Did it leave the machine, and by which
  path?**
- The agent logged nothing. **Did traffic go direct without the agent seeing it?**

This is the general form of the validated VPNaaS double-interception case: the
agent reported healthy steering while its egress was being swallowed by a VPN
tunnel. Its own telemetry could not see it; a multi-interface capture could.

### 2.4 Server-connectivity events ↔ transport failures

The bundle groups reachability and reconnect events by cause, including
headend/tunnel unreachable. The capture shows resets, retransmissions, handshake
failures and zero-window to those same addresses.

Correlated, these become **cause and effect in one statement** rather than two
independent complaints: *"the agent logged N headend-unreachable events; the
capture shows the TCP connections behind them failing at time T with X."*

### 2.5 Enrolment failures ↔ TLS and certificate evidence

The bundle records SAML and certificate enrolment attempts and their failures.
The capture records certificate validation failures, unknown-CA alerts, resets
after ServerHello and DNS blocks.

An enrolment failure whose cause is invisible in the logs is frequently visible
on the wire - a re-signed certificate the endpoint did not trust, or a blocked
name lookup.

### 2.6 Trusted Network Detection ↔ observed steering

TND state is a *declaration* of which network the agent believed it was on.
Steering behaviour is *observed*. When TND says trusted (steering suppressed) and
the capture shows traffic reaching an SWG ingress - or the reverse - that is a
contradiction worth reporting.

### 2.7 Configuration sync ↔ policy behaviour

A stale or failed config sync in the bundle explains unexpected steering, block
pages or destinations in the capture. Without the bundle the behaviour looks
arbitrary; without the capture the stale config looks harmless.

### 2.8 Configured resolver ↔ resolver actually used

The bundle holds DNS configuration; the capture shows which resolver received
the queries, and whether they were encrypted. Divergence explains both
unexpected inspection gaps and unexpected blocks.

### 2.9 Ingress region ↔ expected geography

The capture identifies which Secure Access ingress and region traffic reached
(`lookup_ingress_region`). The bundle supplies the organisation and the endpoint
context. Together they can flag traffic egressing from an unexpected region, and
the latency that follows from it.

### 2.10 Version ↔ known defects

Secure Client version comes from the bundle. Observed behaviour comes from the
capture. Tying a symptom to a version - and to a minimum fixed release - is only
possible with both.

---

## 3. Improvements this enables

Beyond individual correlations, several product-level gains only become possible
once both outputs share one model.

### 3.1 One findings list

Both engines currently produce separate outputs: the capture engine returns
structured findings with severity and evidence; the bundle engine returns a
narrative report plus per-check payloads. **A single severity scale and a single
ordered list** is the prerequisite for everything else, and the bundle side needs
a structured result contract before it can join.

### 3.2 One timeline

With §2.2 solved, a single chronological view of log events and packet events is
the single most explanatory artifact this product could offer. Most endpoint
diagnosis is ultimately "what happened, in what order".

### 3.3 Evidence provenance in the UI

Every correlated finding cites a declared fact and an observed fact. Showing
those side by side - *this is what was configured, this is what happened* - is
what makes the conclusion checkable rather than trusted.

### 3.4 Per-finding confidence

`confidence` is currently a single result-level value (Low/Medium/High) for the
whole capture analysis. Correlated findings vary widely in strength: an exact
identity match is not the same as a time-window association. Confidence should
become per-finding before correlation output grows.

### 3.5 Presence and absence remain asymmetric

Presence proves itself and can be reported unconditionally. Absence is ambiguous
- "no traffic reached an ingress" is a fault only if steering was expected. With
two sources this gets *better*: the bundle can supply the expectation that makes
an absence claim legitimate, instead of asking the operator to declare it.

### 3.6 Deployment profile becomes detectable

The capture engine currently asks the operator whether a tunnel is involved. The
bundle knows the adapter inventory and profile. That replaces a self-declared
checkbox with parsed configuration - which must itself still be cross-checked
against the wire, never trusted outright.

---

## 4. Sequencing

Ordered by dependency, not by appeal.

| Order | Work | Why first |
|---|---|---|
| 1 | Structured result contract for the bundle engine | Nothing can correlate against a narrative string |
| 2 | Time alignment (§2.2) | Most correlations below depend on it |
| 3 | Unified findings model (§3.1) | Gives correlated findings somewhere to live |
| 4 | Agent belief vs wire reality (§2.3) | Highest diagnostic value; reference case already validated |
| 5 | Server connectivity (§2.4), enrolment (§2.5) | Reuse the timeline from step 2 |
| 6 | TND, config sync, resolver, region (§2.6-2.9) | Same pattern, lower individual value |

---

## 5. Traps to carry forward

Learned during the Phase 1 integration; all cost real time.

- **Clock sources differ.** Never assume both are UTC. Establish and display the
  offset.
- **Agent telemetry can be confidently wrong.** The validated VPNaaS case had the
  agent reporting healthy steering while its traffic was being encapsulated. Do
  not treat a self-report as ground truth just because it is structured.
- **Cumulative counters are not period counters.** The roaming agent's totals are
  cumulative since it started; they cannot be compared against a capture window.
- **Populations must match before ratios are computed.** Steered counts HTTP and
  HTTPS only; bypassed also counts internal hosts and non-proxyable protocols.
- **A destination only counts when a session actually happened.** Stray packets
  on a port invent destinations.
- **Correlation is not proof.** Time-window joins must be labelled as
  correlation, exactly as the capture engine already labels its own.
