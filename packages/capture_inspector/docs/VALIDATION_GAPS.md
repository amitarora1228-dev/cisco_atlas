# Validation & Coverage Gaps — toward a professional network diagnostic tool

> Companion to `docs/ASSESSMENT.md`. That document inventories what the tool
> **detects**; this one answers two different questions the way a pro tool must:
>
> 1. **What have we NOT validated?** — detectors that exist in code but were
>    never confirmed against a real, ground-truth capture.
> 2. **What should we validate / add** to diagnose *any* communication problem,
>    with emphasis on **tunnels/VPN** and **connection establishment**.
>
> Honesty rule: every row is labelled **Validated (real capture)**,
> **Synthetic/unit only**, **Never validated**, or **Not implemented**. Nothing
> is claimed as proven that was only reasoned about.

---

## 1. Validation status of what already exists

Based on the project's own validation notes. "Real" = confirmed on a named
capture; "Synthetic" = unit-tested or reasoned only; "Invisible" = code path the
UI never renders, so it has never been seen end-to-end.

| Detector | Validation status | What is still unproven |
|---|---|---|
| SWG interception (cert / CA breadth) | Real (DLP/SA captures) | — |
| JA3S clustering | Real (WEB DLP capture: 47+8 dests) | Behavior on a genuine multi-tenant CDN (false-positive shape) |
| **Local loopback interception (T4)** | Real (DLP TEST AND NAVEGATION) | Non-Cisco vendors (Zscaler ZCC, Netskope, AV shields) — only Cisco confirmed |
| Pinning inference | Real (Teams, composer BEFORE/AFTER) | A *confirmed-true* pin vs a benign RST — we never had ground truth that a host was actually pinned |
| Public-cert problems | Partial | Expired/name-mismatch not seen on a real capture recently; mostly unit-level |
| TLS version/alert | Real | Rare fatal alerts (e.g. `unknown_ca`) not observed live |
| **HelloRetryRequest** | Synthetic/limited | Exact-Random match is sound, but only one real PQ HRR flow seen |
| **ECH GREASE** | Real (present) | **Real ECH (encrypted ClientHelloInner) never parsed** |
| DNS RCODE health | Real (YTIssue) | REFUSED/FORMERR/NOTIMP paths not seen live |
| **SWG region-flapping (T12)** | **Synthetic only** | No real capture has ever contained the flapping pattern — pure synthetic validation |
| Web/DNS SWG block | Real (multiple DLP/malware captures) | — |
| Roaming STARTMSG | Real (QUIC-disable-LAN) | Format stability across Secure Client versions |
| CGNAT / ZTNA tagging | Real (SMON: 11 PA flows) | ZTNA *internet-access* pattern (unknown signature) |
| Internal-traffic suppression | Real (full harness, many captures) | — |
| QUIC bypass | Real | — |
| CONNECT tunnel + inner-TLS keylog | Partial | **Inner-TLS decryption never validated — no test key log ever available** |
| TCP transport health | Real (SMON) | — |
| **ICMP PMTUD (T19)** | **Synthetic only** | No capture in the corpus contains a real ICMP frag-needed / Packet-Too-Big |
| MSS clamp / SA tunnel MTU | Real (ip-set/not-set captures) | The `<1280` below-baseline severity band never triggered by real data |
| Duplicate multi-interface capture | Real (YTIssue, 3 ifaces) | — |
| **Segmentation offload (T22)** | Real (one Oracle upload) | Single capture only — needs more offloaded samples |
| Asymmetric-routing proof tier | **Negative only** (SMON = 0, correct) | **No real capture ever triggered the positive proof tier** |
| Receive-window-limited | Real (recent) | — |
| Bottleneck attribution | Real (recent) | Multi-cause captures where the ranking is ambiguous |
| **Network-quality verdict (T26)** | **Invisible** | Never rendered → never validated end-to-end (unregistered category) |
| **Host fingerprinting TTL/OS (T27)** | **Never validated** | OS-family guess never checked against a host of known OS |
| Latency (DNS/connect/TLS/TTFB) | Real (HAR + PCAP) | — |
| PAC/WPAD | Partial | Real WPAD-failure capture not confirmed |

**The eight that most need real ground truth:** T12 region-flapping, T19 ICMP
PMTUD, real ECH, inner-TLS keylog decryption, T22 offload (more samples),
asymmetric-routing positive tier, T26 network-quality (fix + validate), T27
OS fingerprinting.

---

## 2. Coverage gaps — problem classes a "diagnose anything" tool needs

Grouped by domain. Status = **Not implemented** unless noted. Columns: value ·
difficulty · enterprise relevance. Emphasis on tunnels/VPN and connection setup
per the request.

### 2.1 Tunnels / VPN — the biggest deliberate blind spot today

Today the tool treats a tunnel as **opaque** (CONNECT recognized; contents
encrypted). A pro tool must diagnose the **tunnel itself**, especially for
Secure Access (IPsec + SSL/DTLS) and modern SASE (MASQUE).

| Capability | Value | Diff | Relevance | Signal / reference |
|---|---|---|---|---|
| **IPsec/IKEv2 negotiation failures** (IKE_SA_INIT, IKE_AUTH, DH-group/proposal mismatch, rekey) | High | Med | Secure Access, S2S VPN | UDP 500/4500; RFC 7296 |
| **NAT-T detection & health** (IKE on UDP 4500, ESP-in-UDP) | High | Low | VPN behind NAT | RFC 3948 |
| **ESP flow visibility** (proto 50, SPI, replay, no-response) | Med | Med | IPsec | RFC 4303 |
| **DTLS tunnel (AnyConnect/Secure Client)** setup, DPD, rekey, fallback to TLS | High | Med | Secure Client | RFC 9147 / 6347 |
| **SSL-VPN (AnyConnect TLS) tunnel establishment & CSTP** | High | Med | Secure Client | Cisco (vendor) |
| **Tunnel MTU / fragmentation inside encapsulation** (double-encap, ESP overhead, DF handling) | High | Med | all VPN | RFC 4459; PMTUD refs |
| **MASQUE: CONNECT-UDP / CONNECT-IP** (modern SASE data plane) | Med | High | SASE future | RFC 9298 / 9484 / 9297 |
| **Split-tunnel vs full-tunnel determination** | High | Med | Secure Access | vantage-point (see ASSESSMENT G1) |
| **WireGuard / OpenVPN / GRE recognition** | Low | Med | mixed estates | WG whitepaper; RFC 2784 |
| **Dead-peer / keepalive / rekey storms** | Med | Med | VPN stability | per-protocol |

> This section alone is a large part of "analyze tunnel problems." None of it is
> implemented today — it is the clearest expansion axis.

### 2.2 Connection establishment / TCP path (partly covered, gaps remain)

| SYN with no SYN-ACK vs SYN-ACK-no-ACK (where the handshake dies) | High | Low | Standards | RFC 9293 |
| SYN-flood / half-open / SYN-retry backoff pattern | Med | Low | security/perf | RFC 9293 |
| ICMP unreachable classification (host/net/port/**admin-prohibited code 13**) | High | Low | firewall/ACL blocks | RFC 792 |
| RST injection / inline-blocking (censorship, IPS) vs genuine RST | Med | High | SSE/security | heuristic + RFC 9293 |
| TCP Fast Open, SACK, PAWS/timestamps adequacy | Low | Med | perf tuning | RFC 7413 / 2018 / 7323 |
| Retransmission-timeout vs fast-retransmit distinction, spurious (already partial) | Med | Med | perf | RFC 6298 / 5681 |
| ECN / CE marks, congestion vs loss, bufferbloat | Med | Med | perf | RFC 3168 / 9330 |

### 2.3 Application-layer protocols beyond HTTP/TLS/DNS

The tool is TLS/HTTP/DNS-centric. "Any communication problem" implies at least
recognizing failures in:

| SMB/CIFS (file shares), RDP, SSH | Med | Med | enterprise LAN | MS-SMB2 (V); RFC 4253 |
| SIP / RTP (VoIP quality: jitter, loss, MOS) | Med | High | UC/voice | RFC 3261 / 3550 |
| SMTP/IMAP, LDAP, NTP, SNMP, Kerberos | Low–Med | Med | infra | respective RFCs |
| Database protocols (TDS, Oracle, PG) reachability | Low | Med | app teams | vendor |

### 2.4 Identity / authentication network symptoms

| 802.1X / EAP failures | Med | Med | NAC/onboarding | RFC 3748 |
| RADIUS reject/timeout | Med | Low | AAA | RFC 2865 |
| Kerberos / NTLM auth failures on the wire | Med | Med | AD estates | RFC 4120 / MS-NLMP |
| TLS mutual-auth (`CertificateRequest`, client-cert absent) | Med | Low | ZTNA/mTLS | RFC 8446 |
| Proxy-auth (407) framed as *identity*, not just a proxy error | Low | Low | proxy | RFC 9110 |
| SAML/OAuth redirect chains (HAR) | Low | Med | SSO | OASIS / RFC 6749 |

### 2.5 L2 / L3 fundamentals (often the real root cause)

| ARP: duplicate IP, gratuitous ARP, ARP storm | Med | Low | LAN | RFC 826 |
| DHCP DORA failures / starvation / rogue server | Med | Low | onboarding | RFC 2131 |
| IPv6 NDP/RA/DAD, dual-stack & Happy-Eyeballs fallback | Med | Med | IPv6 estates | RFC 4861/4862/8305 |
| VLAN / STP / gateway reachability | Low | Med | LAN | IEEE 802.1 |

### 2.6 Routing / path

| TTL-based hop-distance & per-hop path change | Med | Med | routing | RFC 791/8200 |
| ICMP redirect / TTL-exceeded (traceroute-like reconstruction) | Med | Med | routing | RFC 792 |
| Path asymmetry beyond the ACK-unseen tier (multi-path) | Med | High | routing | heuristic |
| BGP / control-plane | — | — | **Non-goal** for host capture — document as out of scope |

### 2.7 Performance / quality (partially covered)

| Throughput / goodput calculation per flow | High | Low | perf | derived |
| Window-scaling adequacy vs BDP (numeric) | Med | Med | perf | RFC 7323 |
| Application think-time vs network time split (extends bottleneck attribution) | High | Med | perf | original |
| Clock-skew / capture-time integrity checks | Low | Low | data quality | pcapng |

---

## 3. Methodology gaps — how we should validate to be trustworthy

Detection coverage is only half of "professional." The other half is a
**repeatable validation discipline**. Today validation is ad-hoc and per-feature.

**What we should build (discovery tasks, not code here):**

1. **A labelled ground-truth capture corpus.** For every detector, at least one
   **positive** capture (the problem is truly present) and one **negative**
   (a look-alike that must NOT fire). Today several detectors have only a
   negative (asymmetric routing) or only synthetic (ICMP PMTUD, region-flap).
2. **Independent cross-validation as policy.** Every significant claim confirmed
   with a standalone `tshark -Y …` query first (already the informal practice —
   make it a required step recorded next to each detector).
3. **False-positive budget.** Run the whole suite against known-healthy captures
   and measure how many findings fire that shouldn't. A pro tool reports its own
   FP rate.
4. **Confidence calibration.** Once a numeric confidence exists (ASSESSMENT G3),
   check that high-confidence findings are actually right more often than
   low-confidence ones on the corpus.
5. **Regression on the corpus, not just signatures.** Extend `_refactor_regress`
   to assert *expected findings per labelled capture*, not only that the output
   didn't change.
6. **Version-drift watch for vendor/empirical facts.** STARTMSG format, block-IP
   ranges and SWG hostnames are empirical; pin them to a capture and re-check on
   new Secure Client versions.

---

## 4. Where to focus first (honest prioritization)

**Highest leverage for "diagnose tunnels & connections":**
1. **Capture vantage-point detection** (ASSESSMENT G1) — prerequisite for
   honestly analyzing anything tunneled; without it split/full-tunnel and VPNaaS
   are guesses.
2. **IKEv2/IPsec + DTLS tunnel-establishment diagnostics** (§2.1) — the single
   biggest coverage gap for Secure Access and S2S/VPNaaS.
3. **Connection-death localization + ICMP-unreachable classification** (§2.2) —
   cheap, high diagnostic value, standards-backed (RFC 792/9293).

**Highest leverage for trustworthiness:**
4. **Ground-truth corpus + FP budget** (§3.1, §3.3) — turns "validated
   synthetically" into "validated", which is exactly the current weak spot.

**Quick real-validation wins (close existing unknowns):**
5. Capture a real **ICMP frag-needed**, a real **asymmetric-routing** positive,
   and a **key-log-decrypted CONNECT** to validate T19, T23 and inner-TLS — three
   detectors currently proven only on paper.

---

## 5. Explicit non-goals (so we don't over-promise)

- **BGP / routing control plane** — not observable from an endpoint capture.
- **DoH/DoT query contents** — inside TLS; unrecoverable without keys.
- **Decrypting tunnel/QUIC payloads without a key log** — cryptographically
  impossible; we describe the envelope, never the contents.

These are limits of the vantage point, not backlog items.
