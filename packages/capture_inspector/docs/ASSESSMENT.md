# Detection Capability Assessment — Capture Inspector

> Structured assessment of the current detection state and the path toward a
> professional-grade network detection and diagnostic tool.
>
> **Scope note.** This tool analyzes a *single-vantage-point* endpoint capture
> (PCAP/PCAPNG/HAR), optionally with a TLS key log. Everything below is bounded
> by what one capture point can prove. Claims are labelled **standards-based**,
> **heuristic**, **implementation-specific**, or **vendor-specific**, and
> anything unproven is called out explicitly.

---

## 1. Executive Summary

Capture Inspector today detects roughly **20 finding categories** spanning
TLS/certificate posture, SSE/SWG policy and steering, DNS health, and
network/transport health, plus a Hosts inventory view. Its distinctive strength
is not raw coverage but an **honesty contract**: every detector documents *how*
it fires and *what it cannot see*, false-positive suppression guards are
first-class code, and percentages that mix populations are deliberately
withheld.

Measured against a professional-grade bar, the tool sits at an estimated
**Maturity Level 3 of 5** ("Documented & Referenced"), moving toward Level 4
("Validated & Measured"). The core engineering is sound and unusually honest.
The three things holding it below Level 4 are:

1. **No numeric confidence model.** Confidence is expressed in prose and a
   severity enum, not a traceable score.
2. **The deployment/vantage point is declared by the operator, not detected.**
   A wrong `sa_tunnel` answer yields a confident wrong number; VPNaaS captures
   are not guarded and would falsely report 100 % bypass.
3. **Two hygiene defects:** one detector (`network_info`) is computed but never
   rendered because its category is unregistered, and the regression baseline is
   stale.

None of these require large rewrites. They are scoped as **discovery tasks** in
§7–§8 rather than implemented here.

---

## 2. Current Detection Coverage

Status legend: **F** fully detected · **P** partially detected · **I** inferred
indirectly · **N** not yet implemented. "Basis" = standards-based (S),
heuristic (H), implementation-specific (Impl), vendor-specific (V).

### Connectivity / reachability
| Issue | Status | Basis | Notes |
|---|---|---|---|
| TCP connection refused / reset (RST) | F | S | RFC 9293 |
| No TLS response (ClientHello, no ServerHello) | F | S | Split: internal host → `network`; internet → `tls_handshake` |
| One-way / one-armed capture | P | H | Flagged, not repaired — tells the operator the capture is partial |
| Silent black-hole (no packets at all) | N | — | Absence cannot be distinguished from "not in capture" |

### DNS
| DNS RCODE errors (NXDOMAIN/SERVFAIL/REFUSED/FORMERR/NOTIMP) | F | S | RFC 1035 / RFC 6895 |
| NODATA / no-answer | F | S | RFC 2308 |
| DNS-layer security block (category encoded in anycast IP) | F | V | Cisco Secure Access / Umbrella |
| SWG proxy region-flapping (affinity break) | I | H | Heuristic + GeoIP |
| Encrypted-DNS (DoH/DoT) query *contents* | N | — | Inherent limit — inside TLS |

### Routing / BGP
| Asymmetric routing (ACKed-but-never-captured segments) | P | H | Proof tier from `tcp.analysis.ack_lost_segment` |
| BGP / control-plane routing events | N | — | Out of scope for a host-side capture (no routing plane visible) |

### MTU / fragmentation
| ICMP PMTUD black-hole ("frag needed" / Packet-Too-Big) | F | S | RFC 1191 / RFC 8201 / RFC 792 / RFC 4443 |
| TCP MSS clamp (reduced effective path MTU) | F | S | RFC 6691 / RFC 879 |
| Secure Access tunnel MTU 1390 / MSS 1350 band | P | V | Cisco vendor baseline (SA mode only) |

### TLS / certificate
| TLS interception by SWG/proxy (re-signed cert / CA breadth / JA3S) | F | Mixed | RFC 5280 + JA3S (H) |
| **Local endpoint-agent interception (loopback re-signed cert)** | F | H (novel) | Original technique |
| Corporate-CA-not-trusted (`unknown_ca`) | P | S | RFC 8446 alert — needs alert on the wire |
| Certificate pinning (RST after ServerHello, no close) | I | H | Behavioral inference, capped Medium |
| Public-cert problems (expired / not-yet-valid / name / chain) | F | S | RFC 5280 / RFC 6125→9525 |
| TLS version / cipher / handshake / fatal alert | F | S | RFC 8446 / RFC 5246 |
| HelloRetryRequest extra round trip | F | S | RFC 8446 §4.1.3 (exact Random match) |
| ECH GREASE present | P | S | RFC 8701; real ECH (draft) not parsed |

### Tunnel / VPN
| Explicit-proxy CONNECT tunnel (established / not decrypted) | F | S | RFC 9110 §9.3.6 |
| Inner-TLS recovery inside CONNECT (with key log) | F | S | RFC 8446 |
| ZTNA Private Access via CGNAT 100.64/10 | F | Mixed | RFC 6598 range + Cisco mapping (V) |
| Site-to-site / VPNaaS vantage detection | N | — | **Gap** — see §5 |

### Proxy / SSE
| Web-layer SWG block (`block.sse.cisco.com`, JWT reason) | F | V | Cisco + RFC 7519 (JWT) |
| Proxy errors 4xx/5xx/407 | F | S | RFC 9110 |
| `Via`-header steering evidence | F | S | RFC 9110 §7.6.1 |
| alt-svc (HTTP/3 advertisement) stripped by proxy | F | S | RFC 7838 |
| HTTP/1.1 downgrade through proxy | F | S | RFC 9110 / RFC 9113 |
| PAC/WPAD auto-config failure/use | F | Impl | No RFC — Netscape PAC / expired WPAD draft |
| SWG steering coverage (per-destination, per-category) | F | H | Original methodology |
| Roaming module STARTMSG self-report | F | V | Cisco proprietary, empirically decoded |

### Latency / performance
| Slow DNS / connect / TLS / TTFB | F | S | Timing markers (PCAP/HAR) |
| Receive-window-limited throughput (window/RTT ceiling) | F | S | RFC 9293 + RFC 7323 (BDP) |
| Bottleneck attribution (idle vs active time budget) | F | H (novel) | Original operational heuristic |
| Geo-egress added latency (SWG region from `Via`) | P | S/V | RFC 9110 + Cisco region map |

### Packet loss
| Retransmissions / lost segments / dup-ACK / zero-window | F | S | RFC 9293 (Wireshark expert heuristics) |
| Duplicate multi-interface capture (phantom loss) | F | H (novel) | Suppresses false retransmissions |
| Segmentation-offload capture point (TSO/LSO/GSO artifacts) | F | H (novel) | "Impossibility" proof; suppresses fake reordering |
| Network-quality verdict per destination (RTT / jitter / real loss) | P | H | **Computed but not rendered — see §5/§8** |

### Asymmetric flows
| ACKed-unseen proof tier + one-way flows | F | H | See Routing above |

### Authentication / identity network symptoms
| Proxy-auth required (407) | P | S | Detected as a proxy error, not framed as identity |
| TLS `CertificateRequest` / mutual-TLS prompts | N | — | Not surfaced |
| Kerberos / NTLM / SAML network-level failures | N | — | Not implemented |

---

## 3. Detection Technique Inventory

Each technique: **purpose · issue(s) · logic · status · limitations · source**.
Techniques marked **[UNDOCUMENTED]** exist in code but had no formal reference in
the catalog before this assessment; a proposed source is given in §4/Appendix A.

### T1 — Re-signed leaf certificate detection
- **Purpose:** identify active SSL decryption by a middlebox.
- **Detects:** `interception`, `cert_trust`.
- **Logic:** parse leaf X.509; flag `looks_like_proxy_ca` when the issuer text
  matches known middlebox vendors; exclude public CAs.
- **Status:** F. **Limits:** unavailable on TLS 1.3 without a key log (cert
  encrypted). **Source:** RFC 5280 (X.509); issuer list = vendor-specific (H).

### T2 — Corporate-CA breadth
- **Purpose:** confirm decryption is systemic, not a single site.
- **Logic:** accumulate `corporate_ca_orgs`; one CA signing many leaves ⇒ active
  decryption. **Status:** F. **Source:** RFC 5280 + operational (H).

### T3 — JA3S clustering **[UNDOCUMENTED in a standard]**
- **Purpose:** detect one TLS terminator fronting many destinations (proxy),
  even on TLS 1.3.
- **Logic:** group flows by JA3S; ≥5 distinct destinations on one fingerprint ⇒
  shared terminator. **Status:** F. **Limits:** a shared CDN produces the same
  shape (stated in the finding). **Source:** JA3/JA3S (Althouse/Salesforce, open
  spec; successor JA4+ by FoxIO) — no RFC; community de-facto standard.

### T4 — Local endpoint-agent interception (loopback) **[UNDOCUMENTED / NOVEL]**
- **Purpose:** prove a decrypting agent on *this* device.
- **Logic:** a TLS flow on loopback (127.0.0.1/::1) whose leaf is re-signed by an
  interception CA — both ends are the same machine, so decryption is local. Host
  recovered from the re-signed cert Subject/SAN; loopback leg correlated to its
  outbound leg (±10 s). **Status:** F. **Limits:** needs a visible re-signed
  cert; chain correlation is probabilistic, not cryptographic. **Source:**
  original ("both-ends reasoning"); grounded in RFC 5280 + loopback semantics
  RFC 1122 §3.2.1.3 / RFC 6890.

### T5 — Pinning inference
- **Purpose:** flag an app rejecting the re-signed cert.
- **Logic:** abrupt TCP RST after ServerHello/Certificate with no graceful
  FIN/close; suppressed for any host that completed elsewhere
  (`fin_count ≥ 2`). **Status:** I (capped Medium). **Limits:** not provable
  from a capture. **Source:** RFC 9293 (TCP close semantics); pinning concept
  historically RFC 7469 (HPKP, deprecated). Behavioral (H).

### T6 — Public-certificate validation
- **Logic:** expiry / not-yet-valid / SNI name-mismatch / broken chain via
  `certs.py`. **Status:** F. **Source:** RFC 5280, RFC 6125 (obsoleted by
  RFC 9525, 2025), RFC 6066 (SNI).

### T7 — TLS handshake/version/alert analysis
- **Logic:** parse ClientHello/ServerHello, negotiated version/cipher, fatal
  alerts (`tlsconst.py`); GREASE ignored. **Status:** F. **Source:** RFC 8446,
  RFC 5246, RFC 8701 (GREASE).

### T8 — HelloRetryRequest detection
- **Logic:** ServerHello Random == fixed constant `cf21ad74…c8a8339c`; report
  offered vs forced key-share group; post-quantum→classical fallback called out.
  **Status:** F (exact match). **Source:** RFC 8446 §4.1.3; PQ groups
  draft-ietf-tls-hybrid-design, draft-kwiatkowski-tls-ecdhe-mlkem.

### T9 — DNS-layer security block classification
- **Logic:** destination is a Secure Access block anycast IP
  (146.112.61.113–119 / 2620:119:18::…); **category encoded in the IP**.
  **Status:** F. **Source:** Cisco Secure Access / Umbrella documentation (V);
  partly empirically confirmed.

### T10 — Web-layer SWG block + JWT decode
- **Logic:** redirect to `block.sse.cisco.com`; decode `blockinfo` JWT *payload*
  (no key needed) for rule id / DLP file names; policy family from path segment.
  **Status:** F. **Limits:** block *reason* not in the IP; only from the redirect
  (HAR) or the block IP (PCAP). **Source:** Cisco (V) + RFC 7519 (JWT).

### T11 — DNS health (RCODE / NODATA / no-answer)
- **Logic:** `analyze_dns` classifies RCODEs; PTR NXDOMAIN treated as noise.
  **Status:** F. **Source:** RFC 1035, RFC 2308, RFC 6895.

### T12 — SWG proxy region-flapping
- **Logic:** the same SWG proxy hostname resolving to IPs in different
  regions over the capture ⇒ affinity break. **Status:** I. **Source:** GeoIP
  (MaxMind) + operational (H); proxy hostnames vendor-specific.

### T13 — CGNAT / ZTNA Private Access tagging
- **Logic:** endpoint in 100.64.0.0/10 ⇒ Zero-Trust proxy path; SIA verdicts
  suppressed. **Status:** F. **Source:** RFC 6598 (Shared Address Space) +
  Cisco mapping (V).

### T14 — Internal (private→private) suppression
- **Logic:** both endpoints private ⇒ not SIA; suppress SWG/pinning verdicts.
  **Status:** F. **Source:** RFC 1918, RFC 4193, RFC 3927, RFC 4291.

### T15 — QUIC / HTTP-3 bypass
- **Logic:** UDP/443 QUIC long-header ⇒ un-inspected by TCP-based SWG.
  **Status:** F (detect), I (bypass interpretation). **Source:** RFC 9000,
  RFC 9001.

### T16 — CONNECT tunnel recognition
- **Logic:** explicit-proxy CONNECT; inner TLS recovered with a key log.
  **Status:** F. **Source:** RFC 9110 §9.3.6.

### T17 — HAR proxy evidence (Via / alt-svc / HTTP-1.1)
- **Logic:** `Via` from SA nodes; stripped alt-svc; forced HTTP/1.1. **Status:**
  F. **Source:** RFC 9110 §7.6.1, RFC 7838, RFC 9113.

### T18 — TCP transport health
- **Logic:** retransmissions / lost / out-of-order / dup-ACK / zero-window from
  `tcp.analysis.*`. **Status:** F. **Limits:** `lost_segment` ratio swings with
  the capture point — never used as a portable metric. **Source:** RFC 9293;
  detection heuristics are Wireshark expert-info (Impl).

### T19 — ICMP PMTUD black-hole
- **Logic:** ICMP Type 3 Code 4 / ICMPv6 Type 2; read next-hop MTU (RFC 1191
  field). **Status:** F. **Source:** RFC 1191, RFC 8201, RFC 792, RFC 4443;
  see also RFC 4821 (PLPMTUD).

### T20 — MSS clamp / SA tunnel MTU
- **Logic:** client SYN MSS ≤ 1400 across ≥2 dests ⇒ reduced path MTU
  (eff = MSS+40); SA mode compares against 1350. **Status:** F. **Source:**
  RFC 6691, RFC 879; SA baseline vendor-specific.

### T21 — Duplicate multi-interface capture **[UNDOCUMENTED / NOVEL]**
- **Logic:** the same (stream, seq, len) segment on ≥2 `frame.interface_id` ⇒
  duplicate; suppress phantom retransmissions. **Status:** F. **Source:**
  original; PCAPNG interface model draft-ietf-opsawg-pcapng.

### T22 — Segmentation-offload capture point **[UNDOCUMENTED / NOVEL]**
- **Logic:** a segment larger than the largest MSS negotiated on its own
  connection cannot have crossed the wire ⇒ capture is above the NIC with
  TSO/LSO/GSO pending; suppress reassembly-artifact reordering. Guards: SYN
  required, loopback excluded, ≥2× MSS. **Status:** F. **Source:** original
  ("impossibility argument"); MSS RFC 9293/6691 + OS offload documentation.

### T23 — Asymmetric-routing proof
- **Logic:** `tcp.analysis.ack_lost_segment` (ACK for never-captured data) =
  proof tier; one-way established flows = hedged tier. **Status:** F/P.
  **Source:** RFC 9293; detection via Wireshark expert-info (H).

### T24 — Receive-window-limited throughput
- **Logic:** `tcp.analysis.window_full` ⇒ ceiling of window/RTT (not loss, not
  zero-window). **Status:** F. **Source:** RFC 9293, RFC 7323 (window scaling /
  BDP).

### T25 — Bottleneck attribution **[UNDOCUMENTED / NOVEL]**
- **Logic:** split capture into idle vs active; attribute each ≥0.5 s pause to
  the side that broke the silence; rank dominant limit (loss→idle→zero-window→
  rwnd); loss judged as a rate, withheld on unreliable captures. **Status:** F.
  **Source:** original operational heuristic; grounded in TCP flow-control
  (RFC 9293) and BDP theory.

### T26 — Network-quality verdict per destination **[UNDOCUMENTED + DEFECT]**
- **Logic:** per-destination RTT, RTT variation, spurious-corrected real loss,
  unconfirmed reverse-path loss. **Status:** P — **computed but never rendered**
  (`network_info` category unregistered). **Source:** operational; jitter
  concept RFC 3550 §A.8.

### T27 — Host fingerprinting (TTL/hop, open ports)
- **Logic:** TTL/hop-limit → hop distance + OS family (all labelled `(est.)`);
  confirmed-open ports from observed SYN-ACK. **Status:** P (estimated).
  **Source:** TTL RFC 791 / hop-limit RFC 8200; passive-OS-fingerprinting is
  heuristic (p0f; Lippmann et al., "Passive OS fingerprinting", 2003).

### T28 — Latency timing (DNS/connect/TLS/TTFB)
- **Logic:** timing markers from handshake packets (PCAP) and HAR timings.
  **Status:** F. **Source:** W3C HAR 1.2 spec (HAR) + protocol timing (not an
  RFC).

### T29 — PAC/WPAD analysis
- **Logic:** WPAD DNS resolution + PAC/WPAD fetch success/failure. **Status:**
  F. **Source:** no RFC — Netscape PAC spec, expired draft-ietf-wrec-wpad-01
  (Impl / de-facto).

---

## 4. Standards and Reference Mapping

Classification of each technique's foundation:

- **Standards-based (RFC/IETF/W3C):** T5(partial), T6, T7, T8, T11, T13(range),
  T14, T15, T16, T17, T18(concept), T19, T20(core), T23(concept), T24, T27(field
  only), T28(HAR).
- **Vendor technical documentation:** T9, T10, T12(names), T13(mapping),
  T20(SA baseline), roaming/STARTMSG, SA region map. Source = Cisco Secure
  Access / Umbrella docs; several are **empirically confirmed** rather than
  publicly documented (flagged as needing validation).
- **Heuristic / operational:** T3, T5, T12, T23, T27.
- **Novel / original (need formalization):** T4, T21, T22, T25, T26. These are
  the tool's differentiators; §Appendix B tracks their formalization.

Every RFC-backed technique above already cites an exact section where one exists
(e.g. RFC 8446 §4.1.3 for HelloRetryRequest, RFC 1191 for the ICMP next-hop MTU
field). The **vendor** and **novel** techniques are the ones whose traceability
is weakest and should be prioritized for a written reference (§7).

---

## 5. Missing Capabilities (Gap Analysis)

Prioritized by *practical value × diagnostic impact ÷ implementation difficulty*.
Modern enterprise relevance (Secure Access, VPNaaS, roaming, SSE/SASE, DNS
security, ZTNA) noted per row.

| # | Missing capability | Value | Difficulty | Impact | Relevance |
|---|---|---|---|---|---|
| G1 | **Automatic capture vantage-point detection** (physical NIC / tunnel adapter / loopback) from `frame.interface_id` + PCAPNG interface link-types, replacing the `sa_tunnel` checkbox | High | High | High | VPNaaS, SASE, roaming |
| G2 | **VPNaaS guard** — traffic on a tunnel adapter to real origins currently would falsely report 100 % bypass | High | Medium | High | VPNaaS |
| G3 | **Numeric confidence scoring** (per finding, traceable inputs) | High | Medium | High (explainability) | all |
| G4 | **Register `network_info`** so the network-quality verdict is visible | High | Low | Medium | all |
| G5 | **VPNaaS + roaming-client conflict** (SWG-bound packets on the VPN adapter instead of the NIC = VPN swallowing roaming traffic) | High | Medium | High | VPNaaS + roaming |
| G6 | **ZTNA internet-access signature** — currently unknown | Medium | Unknown (requires validation) | Medium | ZTNA |
| G7 | **Real ECH parsing** (not just GREASE) | Medium | Medium | Low–Med | SSE / privacy |
| G8 | **Identity/auth network symptoms** — 407 as identity, mutual-TLS CertificateRequest, Kerberos/NTLM failures | Medium | Medium | Medium | ZTNA, proxy |
| G9 | **Re-baseline the regression harness** | Medium | Low | Medium (quality) | maintainability |
| G10 | **BGP / routing-plane events** | Low | High | Low | *out of scope for a host capture — document as a non-goal* |

**Honest non-goals.** BGP and control-plane routing (G10) are not observable
from an endpoint capture and should be documented as out of scope rather than
promised. DoH/DoT query *contents* are inside TLS and cannot be recovered
without keys — an inherent limit, not a backlog item.

---

## 6. Maturity Assessment

**Proposed 5-level detection-maturity model:**

| Level | Name | Criteria |
|---|---|---|
| L1 | Ad-hoc | Detections exist but are undocumented and unguarded |
| L2 | Heuristic | Detections work; limits informal; false positives common |
| L3 | **Documented & Referenced** | Every detector states how it fires and what it cannot see; suppression guards exist; misleading metrics withheld |
| L4 | Validated & Measured | Numeric confidence per finding; automated regression on labelled captures; vantage point detected, not declared |
| L5 | Standards-aligned & Self-calibrating | Every technique tied to a formal reference; the tool infers deployment and adapts which questions it answers |

**Current level: L3, advancing to L4.**

**Strengths**
- Honesty contract: `docs/DETECTION.md` states *how* and *limit* for every
  category; the product value is the "what we cannot see" text.
- False-positive suppression is first-class (`_suppress_*`, graceful-close guard,
  duplicate/offload suppression).
- Novel, high-rigor techniques (T4, T21, T22, T25) use impossibility/both-ends
  reasoning rather than guesswork.
- Rates over raw counts; per-destination over per-connection; time-window
  correlations always labelled as correlation, never proof.

**Major gaps (to reach L4/L5)**
- **Explainability/traceability:** no numeric confidence; a finding's severity is
  an enum, not a scored, auditable value.
- **Detection coverage:** identity/auth symptoms and real ECH absent; vantage
  detection missing (biggest architectural gap).
- **Technical rigor / standards alignment:** the novel and vendor techniques lack
  a written external reference; some vendor facts are empirical.
- **Maintainability:** stale regression baseline; one unregistered category.
- **Packet-level evidence:** findings cite counts and example flow keys, but there
  is no per-finding link back to exact frame numbers for audit.

---

## 7. Prioritized Recommendations

**Immediate (days, low risk, mostly hygiene) — discovery tasks, not done here**
1. **G4** — register `network_info` in the five `CLASSIFICATION_*` tables so the
   network-quality verdict renders. (Small, but touches the UI pipeline —
   validate with `summary.tech_groups`.)
2. **G9** — re-baseline `_refactor_regress.py` and commit the new
   `_regress_baseline.json`.
3. **Documentation** — fold the novel techniques (T4/T21/T22/T25/T26) into
   `docs/DETECTION.md` with the references proposed in Appendix A, and record
   BGP/DoH-contents as explicit non-goals.

**Short term (weeks)**
4. **G3** — introduce a **numeric confidence model** (e.g. 0–100 with named
   inputs: signal strength, corroborating signals, capture-quality penalty). Map
   the existing severity enum onto it; keep the prose but make the number
   auditable.
5. **G2 + G5** — add a **VPNaaS guard** using `frame.interface_id` link-types so
   tunnel-adapter captures are not scored as 100 % bypass, and detect the
   VPN-swallows-roaming conflict.
6. **Packet-level evidence** — attach the exact frame numbers behind each finding
   so a reviewer can jump to them in Wireshark.

**Medium term (the architectural investment)**
7. **G1** — **capture vantage-point detection.** Classify each capture as
   physical-NIC-below-tunnel / tunnel-adapter / loopback / mixed from the PCAPNG
   interface table, and let it drive which questions the tool answers at all.
   This subsumes G2/G5/G6 and removes the `sa_tunnel` checkbox — the single
   highest-leverage change.
8. **G6/G8** — validate ZTNA-internet-access and identity/auth signatures against
   real captures before implementing (label as *requires validation* until then).

**Tying every technique to a legitimate source**
- Adopt the **catalog framework** in Appendix A as the single source of truth:
  every detector row must carry a reference class (RFC / IETF draft / vendor doc /
  paper / empirical) and, where empirical, a captured-evidence pointer. A CI
  check can fail the build if a `Finding.category` has no catalog entry — the same
  gap that hid `network_info`.

---

## 8. Proposed Next Steps

1. Review and accept this assessment and the maturity model.
2. Convert §5 gaps into tracked **discovery tasks** (no code yet), each with an
   acceptance test tied to a real capture in `samples/`.
3. Land the Immediate hygiene items (G4, G9, doc merge) as the first small PRs.
4. Prototype the numeric confidence model on one category end-to-end before
   rolling it out.
5. Design the vantage-point classifier (G1) as a spec first, validated against
   the known captures listed in `docs/HANDOFF.md`, then implement.

> Per the request, **no code was changed** in producing this document. All
> implementation items above are framed as discovery tasks.

---

## Appendix A — Technique → Reference Table

| ID | Technique | Class | Primary reference |
|---|---|---|---|
| T1 | Re-signed leaf cert | Standards + Vendor | RFC 5280; vendor issuer list |
| T2 | Corporate-CA breadth | Heuristic | RFC 5280 + operational |
| T3 | JA3S clustering | Community de-facto | JA3/JA3S (Salesforce); JA4+ (FoxIO) — no RFC |
| T4 | Loopback local interception | **Novel** | RFC 5280 + RFC 1122 §3.2.1.3 / RFC 6890 |
| T5 | Pinning inference | Heuristic | RFC 9293; (hist.) RFC 7469 |
| T6 | Public-cert validation | Standards | RFC 5280, RFC 6125→9525, RFC 6066 |
| T7 | TLS handshake/version/alert | Standards | RFC 8446, RFC 5246, RFC 8701 |
| T8 | HelloRetryRequest | Standards | RFC 8446 §4.1.3; PQ drafts |
| T9 | DNS-layer block IP class | Vendor | Cisco Secure Access / Umbrella |
| T10 | Web-layer SWG block + JWT | Vendor + Standards | Cisco; RFC 7519 |
| T11 | DNS RCODE/NODATA health | Standards | RFC 1035, RFC 2308, RFC 6895 |
| T12 | SWG region-flapping | Heuristic | GeoIP (MaxMind) + operational |
| T13 | CGNAT / ZTNA tagging | Standards + Vendor | RFC 6598 + Cisco |
| T14 | Internal-traffic suppression | Standards | RFC 1918, 4193, 3927, 4291 |
| T15 | QUIC/HTTP-3 bypass | Standards | RFC 9000, RFC 9001 |
| T16 | CONNECT tunnel | Standards | RFC 9110 §9.3.6 |
| T17 | HAR Via/alt-svc/H1.1 | Standards | RFC 9110 §7.6.1, RFC 7838, RFC 9113 |
| T18 | TCP transport health | Standards + Impl | RFC 9293; Wireshark expert-info |
| T19 | ICMP PMTUD | Standards | RFC 1191, 8201, 792, 4443; RFC 4821 |
| T20 | MSS clamp / SA MTU | Standards + Vendor | RFC 6691, 879; Cisco baseline |
| T21 | Duplicate-capture detection | **Novel** | draft-ietf-opsawg-pcapng |
| T22 | Segmentation-offload point | **Novel** | RFC 9293/6691 + OS offload docs |
| T23 | Asymmetric-routing proof | Heuristic | RFC 9293; Wireshark expert-info |
| T24 | Receive-window-limited | Standards | RFC 9293, RFC 7323 |
| T25 | Bottleneck attribution | **Novel** | RFC 9293 + BDP theory |
| T26 | Network-quality verdict | Heuristic | RFC 3550 §A.8 (jitter) |
| T27 | Host fingerprinting | Heuristic | RFC 791 / RFC 8200; p0f; Lippmann 2003 |
| T28 | Latency timing | Spec | W3C HAR 1.2 |
| T29 | PAC/WPAD | De-facto | Netscape PAC; expired WPAD draft |

## Appendix B — Undocumented Techniques Needing Formalization

Techniques that exist in code but had no external reference in the catalog. They
are the tool's differentiators and should each get a written rationale in
`docs/DETECTION.md`:

- **T4 Loopback local interception** — the novel core; formalize the both-ends
  argument citing RFC 1122/6890.
- **T21 Duplicate multi-interface capture** — cite the PCAPNG interface model.
- **T22 Segmentation-offload capture point** — write up the impossibility proof
  and the three guards.
- **T25 Bottleneck attribution** — document the idle-attribution rule and the
  loss-rate withholding.
- **T26 Network-quality verdict** — document *and* register the category (it is
  currently invisible).
- **T3 JA3S clustering** — record the JA3/JA4 provenance and the CDN caveat.
- **Vendor/empirical facts** (block-IP ranges, STARTMSG format, SWG proxy
  hostnames, SA MTU baseline) — mark which are Cisco-documented vs empirically
  derived, and attach a captured-evidence pointer for the empirical ones.

## Appendix C — High-Value References to Adopt

Standards already used implicitly that should be cited in the catalog, plus ones
worth adopting as coverage grows:

- **TLS:** RFC 8446 (1.3), RFC 5246 (1.2), RFC 8701 (GREASE), RFC 6066 (SNI),
  RFC 9525 (name matching, obsoletes 6125), draft-ietf-tls-esni (ECH),
  draft-ietf-tls-hybrid-design (PQ hybrids).
- **PKI:** RFC 5280 (X.509), RFC 6960 (OCSP) — for future revocation checks.
- **TCP/transport:** RFC 9293 (TCP), RFC 7323 (window scaling/timestamps),
  RFC 6691 / RFC 879 (MSS), RFC 5681 (congestion control) — for future
  loss-vs-congestion rigor.
- **PMTUD:** RFC 1191, RFC 8201, RFC 4821 (PLPMTUD), RFC 792, RFC 4443.
- **DNS:** RFC 1035, RFC 2308, RFC 6895, RFC 8484 (DoH), RFC 7858 (DoT),
  RFC 7871 (EDNS Client Subnet — relevant to region-flapping).
- **HTTP/proxy:** RFC 9110 (semantics), RFC 9113 (HTTP/2), RFC 9114 (HTTP/3),
  RFC 7838 (alt-svc), RFC 7519 (JWT).
- **QUIC:** RFC 9000, RFC 9001, RFC 8899 (DPLPMTUD for datagram transports).
- **Addressing:** RFC 1918, RFC 6598, RFC 4193, RFC 3927, RFC 4291, RFC 6890.
- **Capture format:** draft-ietf-opsawg-pcapng (interface/vantage metadata).
- **Fingerprinting (non-RFC):** JA3/JA3S (Salesforce), JA4+ (FoxIO); passive OS
  fingerprinting (p0f; Lippmann et al., 2003) — cite as heuristic, never as
  standards.
