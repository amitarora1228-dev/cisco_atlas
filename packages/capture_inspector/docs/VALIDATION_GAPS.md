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

### 1.1 Cross-validation against tshark (2026-08-14)

Every counter, judgement and rule the engine produces was re-derived
independently with standalone `tshark -Y` queries and compared. The harnesses
live in `tools/_validate_*.py` and are re-runnable by anyone with Wireshark.

| Harness | What it proves | Checks | Result |
|---|---|---|---|
| `_validate_detection.py` | TCP/TLS counters equal tshark's own | 33 | 33/33 |
| `_validate_judgements.py` | interpretive calls: direction, blame, quality | 21 | 21/21 |
| `_validate_rules.py` | rule-based findings fire on the right flows | 23 | 23/23 |
| `_validate_deep.py` | inner-tunnel TLS, certs, JA3/JA3S, ECH, ALPN, CONNECT | 25 | 25/25 |
| **Total** | | **102** | **102/102** |

Corpus: `WEB DLP ETC ETC(1).pcapng` (46,884 packets, 937 TCP flows),
`Teams_troubleshooting.pcapng`, `YTIssue.pcapng`.

Two results are recorded here because they are easy to misread as bugs:

- **The inner SNI does not match the CONNECT target, and that is correct.** In
  the DLP capture all 178 CONNECT lines name an *address*, because the client
  resolved the name itself. The second-pass dissection recovers a hostname the
  tunnel line never stated — that is the whole value of the second pass. Where
  the CONNECT does name a host (YTIssue), the two agree 5/5.
- **Issuer names come from the DER, not from tshark's field columns.** The
  engine parses certificates directly, so it legitimately reports issuers that
  `tshark -e x509sat.*` does not expose. Ground truth for that check has to be
  tshark's full `-V` dissection.

Thirteen apparent engine failures were investigated during this exercise and
**twelve were defects in the harness, not in the engine** — a UDP/TCP stream-key
collision, `tcp.analysis.initial_rtt` counted per frame when tshark attaches it
to every frame of a stream, case sensitivity that RFC 4343 forbids, reverse-DNS
excluded by design, and the CONNECT/SNI misreading above.

The thirteenth was real, and is recorded in §2.11.

**What this does not prove:** that a detector is correct *in the field*. Only
that it agrees with tshark on the captures we hold.

### 1.2 Detectors that never fire, and thresholds that never trigger

Eleven of 69 detections produced no finding on any capture in this corpus:
TLS alerts, expired certificate, not-yet-valid certificate, certificate name
mismatch, weak TLS version, the asymmetric-routing positive tier, QUIC bypass,
PAC/WPAD success, Private Access, internal traffic, geo-egress latency. Code
that has never executed against real data is unproven regardless of how well it
reads.

The latency thresholds are a stronger case: they never fire at all.

| Capture | Metric | n | median | p95 | threshold | fired |
|---|---|---|---|---|---|---|
| WEB DLP | TCP handshake | 686 | 12 ms | 41 ms | 300 ms | 0 |
| WEB DLP | TLS setup | 197 | 47 ms | 63 ms | 600 ms | 0 |
| Teams | TCP handshake | 119 | 22 ms | 106 ms | 300 ms | 0 |
| Teams | TLS setup | 29 | 29 ms | 105 ms | 600 ms | 0 |
| YTIssue | TCP handshake | 5 | 9 ms | 10 ms | 300 ms | 0 |

The constants in `findings/latency.py` sit 7–25x above the p95 of every capture
we have. Being absolute, they are simultaneously too high for a healthy LAN and
too low for a satellite or long-haul link, where a 400 ms median would make
*every* flow fire. A threshold relative to the capture's own baseline would say
something; these say nothing.

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

### 2.8 Signals already present in our captures that we do not read

This section is different from the rest: nothing here is speculative. These
frames were counted in `WEB DLP ETC ETC(1).pcapng` with `tshark -Y`. The data is
in the file and the parser walks straight past it.

| Signal | Frames present | Why it matters | Reference |
|---|---|---|---|
| **HTTPS/SVCB resource record** | 4 | Carries the ECH configuration, ALPN and alternative port. When a client gets `ech=` here the SNI goes dark and Secure Access loses the destination — the exact mechanism that defeats SNI-based inspection | RFC 9460 |
| **TCP window scale** | 919 | Without the shift factor the advertised window we report is wrong, by up to 2^14. Bandwidth-delay-product analysis is impossible without it | RFC 7323 §2 |
| **SACK blocks** | 76 | States exactly which ranges were lost; D-SACK separates real loss from reordering, which our retransmission counters cannot | RFC 2018, RFC 2883 |
| **TLS session tickets** | 60 | If resumption never succeeds, every connection pays a full handshake — a systemic latency cause invisible today | RFC 5077, RFC 8446 §2.2 |
| **OCSP stapling requested (ext 5)** | 16 | When the proxy does not staple, the client fetches OCSP itself; if policy blocks that fetch the page stalls for seconds. A common and badly-diagnosed hang | RFC 6960, RFC 6066 §8, RFC 7633 |
| **DNS over TCP** | 12 | Fallback implies truncation, usually an EDNS0 or fragmentation problem | RFC 7766, RFC 6891 |

Closing these is cheap: the fields exist in tshark and the frames exist in the
corpus, so each one can be validated the day it is written.

### 2.9 Web-layer diagnostics missing for browser troubleshooting

The tool's stated purpose is web troubleshooting, so these deserve their own
list rather than being folded into the transport sections above.

| Capability | Value | Diff | Why it matters | Reference |
|---|---|---|---|---|
| **QUIC Initial ClientHello** | High | Low | Initial packets are protected with keys derived from a *published* salt, so SNI and ALPN are readable **without any secret**. We look only at `quic.header_form` and are blind to destinations we could simply read | RFC 9001 §5.2 |
| **Happy Eyeballs / dual-stack fallback** | High | Med | A slow-failing IPv6 path adds a fixed delay to every connection. Probably the most misdiagnosed cause of "the internet is slow" | RFC 8305 |
| **Incomplete certificate chain** | High | Low | A missing intermediate fails on some clients and not others — very common, and invisible today | RFC 5280 §6 |
| **Certificate name matching** | High | Low | The detector exists but has never fired, and the rules it was written against have since been superseded | RFC 9525 (obsoletes RFC 6125) |
| **Browser DoH / DoT** | High | Med | If the browser resolves over DoH, Umbrella is out of the DNS path entirely. Directly undermines a core Secure Access control | RFC 8484, RFC 7858, RFC 9250 |
| **HTTP/2 GOAWAY, RST_STREAM, SETTINGS** | High | Med | We extract only method, status and authority. A GOAWAY explains a whole session collapsing at once | RFC 9113 §6.4, §6.8 |
| **Alt-Svc** | Med | Low | How a server moves a client to HTTP/3 and out of inspection | RFC 7838 |
| **Captive portal** | Med | Low | Hotel and airport Wi-Fi breaks everything and looks exactly like an SSE fault | RFC 8908, RFC 7710 |
| **Endpoint clock skew** | Med | Low | A wrong clock invalidates every certificate at once. We now judge validity at capture time but never check the clock itself | RFC 5905 |
| **PMTUD blackhole** | High | Med | The connection establishes, then hangs on the first large transfer | RFC 2923, RFC 1191, RFC 8201 |
| **407 authentication loops** | Med | Low | We read the header but do not detect the loop | RFC 9110 §15.5.8 |
| **421 Misdirected Request / H2 coalescing** | Med | Med | A reused connection for another origin that the proxy then breaks | RFC 9110 §15.5.22, RFC 9113 §9.1.1 |
| **HSTS** | Low | Low | Explains forced redirects | RFC 6797 |
| **WebSocket upgrade failures** | Med | Low | Collaboration and SaaS apps | RFC 6455 |
| **Truncated responses** (Content-Length vs bytes) | Med | Med | DLP cutting a download mid-flight | RFC 9110 §8.6 |

### 2.11 One record per DNS name loses the disagreement between resolvers

Found by validation, 2026-08-14. `analyze_dns` keeps a single record per name,
so when two resolvers answer the same question differently only one answer
survives.

In `WEB DLP ETC ETC(1).pcapng`, `malware.com` was answered **NXDOMAIN by
127.0.0.1** — the Secure Client roaming module, blocking it — and **SERVFAIL by
8.8.8.8** on a direct query. The engine reports SERVFAIL and the block is lost.

The disagreement is the diagnosis. "The local roaming module blocked this name
while the external resolver did not" is precisely what a DNS-steering
investigation needs, and it is exactly what the current model discards. The fix
is to key DNS records by (name, resolver) rather than by name, which touches the
DNS model and the views that render it, so it is a change rather than a patch.

### 2.10 Two things we treat as standards that are not

- **ECH** is `draft-ietf-tls-esni`, not an RFC. We detect the GREASE
  advertisement (RFC 8701) and describe it as if the mechanism were settled.
  It is not, and its wire format can still change.
- **WPAD** was never standardised. `draft-ietf-wrec-wpad-01` expired in 1999 and
  PAC itself is a Netscape specification. Our WPAD detection is sound, but it
  rests on convention, not on a standard, and should say so.

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

---

## 6. End-to-end plan

Sequenced so that each stage is provable before the next one starts. Adding
capability on top of unproven detectors is the mistake this document exists to
prevent.

**Stage 0 — make the current claim reproducible.** *(done 2026-08-14)*
The four harnesses are committed. Anyone with Wireshark can re-derive the
95 checks in §1.1 rather than taking them on trust.

**Stage 1 — prove what already ships.**
Write synthetic flows for the eleven detectors in §1.2 that have never
executed. No new captures are needed: a crafted `Flow` exercises an expired
certificate or a fatal TLS alert perfectly well, and that is how the opaque
tunnel work was validated. Until this is done the tool has eleven code paths
whose first real execution would be at a customer.

**Stage 2 — make latency mean something.**
Replace the absolute constants with a comparison against the capture's own
distribution. §1.2 shows the current constants cannot fire; the fix is small and
self-validating, because the corpus immediately says whether the new rule
separates anything.

**Stage 3 — read the signals we already capture.**
The six families in §2.8, cheapest first: window scale and SACK (accuracy fixes
for numbers we already print), then session tickets, OCSP stapling, HTTPS/SVCB
and DNS-over-TCP. Every one can be validated the day it is written, because the
frames are already in the corpus.

**Stage 4 — close the web-layer gaps.**
From §2.9, in this order: QUIC Initial ClientHello (highest value per unit of
work — no secrets required), incomplete certificate chain, Happy Eyeballs,
HTTP/2 GOAWAY, browser DoH detection. These need new captures for positive
validation; see §7.

**Stage 5 — build the corpus and the false-positive budget.**
§3.1 and §3.3. This is what converts "agrees with tshark on three captures"
into "trustworthy", and it gates any claim about accuracy.

**Stage 6 — tunnels.**
§2.1 remains the largest deliberate blind spot, but it is last because it is
the only stage that cannot borrow validation from the existing corpus.

---

## 7. Deferred — blocked on information we do not have

Recorded rather than silently dropped. Each item names what would unblock it.

| Item | Blocked on | What would unblock it |
|---|---|---|
| Inner-TLS decryption inside CONNECT | No key log has ever been available | One capture taken with `SSLKEYLOGFILE` set through a proxy |
| Real ECH (not GREASE) | No capture contains a real encrypted ClientHelloInner | A capture against a host with ECH enabled and an `HTTPS` RR carrying `ech=` |
| ICMP PMTUD (T19) positive tier | Corpus contains zero frag-needed / Packet-Too-Big frames | A capture across a path with a reduced MTU |
| Asymmetric routing positive tier | Only the negative case has ever been seen | A capture from a genuinely asymmetric path |
| SWG region flapping (T12) | Pattern never observed live | A capture during an ingress change |
| OS fingerprinting (T27) | Never checked against a host of known OS | Captures from hosts whose OS is recorded at capture time |
| Latency thresholds on a slow link | Corpus is all sub-50 ms medians | One capture over satellite, long-haul or a congested link |
| QUIC bypass detection | The three captures in §1.1 contain no QUIC at all | A capture with HTTP/3 traffic present |
| Non-Cisco local interception | Only Cisco agents confirmed | Captures from endpoints running Zscaler ZCC, Netskope or an AV TLS shield |
| Certificate name mismatch / expiry | Never fired on real data | Synthetic coverage in Stage 1; real capture optional afterwards |

Two operational items are blocked on a decision rather than on data, and are
tracked in `docs/STATE.md`: the HAR blob carrying employee data in Git history,
which needs a coordinated history rewrite, and the stale `launchers/` directory.
