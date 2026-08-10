# Invention Disclosure (Cisco Internal) — Patent-Potential Assessment

> **Disclaimer / honesty note.** I am not a patent attorney and this is not a
> legal opinion or a freedom-to-operate/patentability determination. This is a
> **technical** novelty and non-obviousness assessment intended to seed a formal
> Cisco Invention Disclosure and to help you decide what to route to Cisco IP
> counsel. A professional **prior-art search** and attorney review are required
> before any filing decision. Several building blocks below are known prior art
> (called out explicitly); the potential novelty lies in specific mechanisms and
> their combination.

---

## 1. Administrative

| Field | Value |
|---|---|
| **Proposed title** | Passive reconstruction and vendor attribution of on-device and in-network TLS interception from a single packet capture |
| **Inventor(s)** | _(to be completed)_ |
| **Business unit** | Cisco Secure Access / SSE |
| **Product embodiment** | Capture Inspector (local PCAP/HAR TLS diagnostic tool) |
| **Date of conception** | _(to be completed)_ |
| **Reduction to practice** | Yes — working implementation (this repository). |
| **Prior public disclosure?** | _(confirm none before filing)_ |

---

## 2. Problem statement

Diagnosing why an HTTPS connection fails, is blocked, or is being inspected in a
SASE/SWG deployment is hard because:

- The interesting evidence is **encrypted** (TLS 1.3 hides certificates; DLP/AI
  verdicts ride inside TLS; QUIC bypasses TCP inspection).
- Interception can happen **on the endpoint** (roaming client / AV web-shield /
  local MITM) or **in the network** (SWG), and today the two are hard to tell
  apart from a capture.
- Existing tools (Wireshark, NetworkMiner) surface raw facts but do not
  **reconstruct the interception path**, **attribute the vendor**, or
  **translate** the result into an actionable, honest verdict.

The invention analyzes a single, ordinary packet capture (no agent
instrumentation, no server cooperation) and produces a vendor-attributed,
evidence-cited diagnosis — including the reconstructed local→internet
interception chain.

---

## 3. Summary of the invention

A method and system that, from a passive PCAP/HAR:

1. Detects **on-device TLS interception** by observing a **loopback** TLS flow
   bearing a **re-signed certificate**, recovers the true destination from the
   re-signed certificate's Subject/SAN even when the loopback leg carries no
   SNI/DNS, **attributes the responsible agent/vendor** from the issuer, and
   **stitches the loopback leg to its outbound leg** (same host, bounded time
   window) to reconstruct the two-hop interception chain.
2. Classifies **Cisco Secure Access enforcement** from the wire using a
   **dual-layer block-page model** (DNS-layer anycast IPs whose value encodes the
   category, plus a web-layer block-page range) and **recovers the blocked
   destination** by temporal correlation to the real domain requested moments
   earlier.
3. Suppresses **false-positive certificate-pinning** verdicts using
   **completion evidence** on the same host (TLS 1.3-aware).
4. Combines **positive PKI fingerprint matching** (exact SA Root CA
   SHA-256/SKI) with heuristic issuer text under an **opt-in vendor mode**, so
   the same engine runs vendor-neutral or Cisco-aware.

---

## 4. Detailed description of the novel mechanisms (candidate claims)

### Claim candidate A — Vendor-agnostic on-device interception detection + chain reconstruction (**strongest**)
*Implementation: `app/findings/interception.py::_local_interception_findings`.*

1. Identify TLS flows where either endpoint is a **loopback** address
   (127.0.0.1 / ::1) **and** whose leaf certificate is **re-signed by an
   interception CA** (issuer heuristics + positive PKI match). Because both ends
   of a loopback flow are the same host, this **proves local decryption**.
2. When the loopback leg lacks SNI/DNS (resumed session, listener socket),
   **recover the real destination hostname from the re-signed leaf certificate's
   Subject CN / SAN** — an artifact only a *decrypting* agent produces (it must
   name the real site to re-sign it).
3. **Attribute the vendor/agent** from the certificate issuer text, with an
   explicit "unrecognized interception CA" bucket so unknown vendors are still
   surfaced.
4. **Reconstruct the interception chain**: correlate each loopback leg to the
   nearest **non-loopback** flow to the **same recovered host** within a bounded
   time window (implementation: ±10 s), and cross-link the two legs so the full
   endpoint→internet path is exposed.

*Why potentially novel:* passive, agentless detection of **endpoint** TLS MITM
(not just network MITM), **hostname recovery from the re-signed cert**, and
**two-leg chain reconstruction with vendor attribution** appear to go beyond
generic "corporate CA seen" detection.

### Claim candidate B — Dual-layer, self-describing block-page classification with destination recovery
*Implementation: `app/dns_analysis.py`, `app/analyze.py::_correlate_web_blocks`,
`app/engine.py::_flow_findings`.*

1. Map **DNS-layer anycast block IPs** where the **IP value itself encodes the
   block category** (malware/phishing/C2/content/domain-list) to a human reason.
2. Recognize the distinct **web-layer** block-page range as a post-decryption
   policy block (URL/content/app-control/**DLP**/**AI-guardrail**).
3. Because the web-layer block hides its reason, **recover the blocked
   destination** by correlating to the real domain requested within a preceding
   time window.

### Claim candidate C — Completion-evidence suppression of false-positive pinning (TLS 1.3-aware)
*Implementation: `app/analyze.py::_suppress_pinning_on_trusted_hosts`.*

Retain a pinning signal (RST after ServerHello/Certificate) **only** for hosts
that **never** completed any connection, using **graceful-FIN (fin_count ≥ 2)**
as the completion proof where TLS 1.3 hides handshake-complete/app-data. This
distinguishes true pinning (rejects *every* connection) from transient teardown.

### Claim candidate D — Opt-in vendor mode fusing positive PKI fingerprints with issuer heuristics
*Implementation: `app/certs.py` (SA Root CA SHA-256/SKI) + `context.py` mode
flags.* One engine yields either a vendor-neutral or a Cisco-attributed verdict.

### Claim candidate E — SWG ingress region-flap detection
*Implementation: `app/dns_analysis.py` proxy-hostname `proxy_responses`.* Detect
a single SWG proxy hostname resolving to **different regions/countries** across a
capture (breaks proxy affinity).

### Claim candidate F — JA3S clustering as SWG re-encryption evidence
*Implementation: `app/findings/interception.py::_ja3s_findings`.* One
server-side TLS fingerprint fronting many unrelated destinations ⇒ single TLS
terminator. **Prior-art heavy** (see §6); include only as part of a broader
combination claim, with the CDN caveat.

---

## 5. Advantages

- **Agentless & passive** — no endpoint instrumentation, no server cooperation,
  works from an ordinary capture.
- **Distinguishes endpoint vs. network interception** and **attributes vendor**.
- **Evidence-cited & honest** — states blind spots (DLP encrypted, QUIC, TLS 1.3
  without key log) rather than guessing; reduces false positives via completion
  guards.
- **Actionable** — translates raw TLS/TCP facts into plain-language impact and
  remediation.

---

## 6. Prior art and distinctions (be explicit with counsel)

| Known prior art | What it does | How the candidates differ |
|---|---|---|
| **JA3 / JA3S** (Salesforce, open source) | TLS client/server fingerprinting. | Candidate F uses JA3S but is **not** the novelty; the novel work is A–C. |
| **Wireshark / tshark** | Decodes packets, shows certs/alerts. | It surfaces facts; it does not reconstruct chains, attribute vendors, recover blocked domains, or guard pinning false positives. |
| **NetworkMiner and similar** | Passive host/cert extraction. | No loopback-based **on-device** interception proof, cert-Subject host recovery, or chain reconstruction. |
| **SASE/SWG telemetry (Umbrella/Secure Access dashboards)** | Server-side logs of blocks/decryption. | The candidates work **client-side from a capture**, without backend logs. |
| **Existing MITM/proxy detectors** | Detect "a corporate CA is present." | Candidate A adds loopback locality proof, vendor attribution incl. unknown vendors, cert-based host recovery, and two-leg chain stitching. |

A formal prior-art search (patents + academic + vendor docs) is required. Cisco
Secure Access block-IP semantics are documented publicly, so Claim B's novelty
likely rests on the **combination** (encoding-aware mapping + web-layer
distinction + temporal destination recovery), not the IP list itself.

---

## 7. Novelty / non-obviousness — candid ranking

| Candidate | Novelty (my estimate) | Notes |
|---|---|---|
| **A** on-device interception + chain reconstruction | **High** | Most defensible; recommend prioritizing. |
| **B** dual-layer block-page + destination recovery | **Medium–High** | Strongest as a combination claim. |
| **C** pinning false-positive suppression | **Medium** | Elegant; check for prior heuristics. |
| **D** opt-in positive-PKI + heuristic fusion | **Low–Medium** | Likely a dependent claim. |
| **E** ingress region-flap | **Medium** | Narrow but concrete; verify prior art. |
| **F** JA3S clustering | **Low** | Prior-art heavy; combination only. |

---

## 8. Enablement / reduction to practice

A complete, working implementation exists in this repository (see
[MODULES.md](MODULES.md)). The specific code paths are cited per candidate above,
which supports enablement and an early conception/reduction-to-practice date.
Preserve dated commit history as corroboration.

---

## 9. Recommended next steps

1. Route this disclosure to **Cisco IP counsel / the invention-disclosure
   committee**; do not publicly disclose (blog/talk/OSS release) before they
   advise, to preserve rights.
2. Commission a **professional prior-art search** focused on candidates **A** and
   **B**.
3. Consider drafting **A** as the independent claim with **B–E** as dependent
   claims of a single application.
4. Confirm no prior public disclosure and record inventor names + dates.
