# Detection Catalog — how we detect, and how we do NOT

This document is the heart of the tool's honesty: for every capability it states
**what** is detected, **how** (the exact on-wire signal), and **the limits** —
what the mechanism cannot see and why. The limitations section at the end
collects the systemic blind spots.

Findings are grouped by `category`. Each category maps to a user-facing label,
a "why it was flagged" explanation, a real-world analogy, and remediation steps
(the `CLASSIFICATION_LABELS / _WHY / _EXAMPLE / _REMEDIATION` tables in
`analyze.py`).

---

## 1. TLS interception by an SWG / proxy (`interception`)

**What:** A middlebox is terminating TLS and re-encrypting it with a corporate
CA (SSL decryption / "man-in-the-middle for inspection").

**How we detect it — three independent signals:**

1. **Re-signed leaf certificate.** `certs.parse_cert_hex()` parses the leaf and
   flags `looks_like_proxy_ca` when the issuer text matches known middlebox
   vendors (Zscaler, Netskope, Palo Alto, Forcepoint, Blue Coat, Fortinet,
   Umbrella/Secure Access, mitmproxy, Squid…). Public-CA issuers are excluded so
   legitimate DigiCert/Amazon certs are never mislabeled. In Secure Access mode
   the Cisco SA Root CA is a **positive** match (exact SHA-256 fingerprint / SKI
   / self-signed CN), not just a heuristic.
2. **Corporate-CA breadth.** `analyze_flow()` accumulates `corporate_ca_orgs`;
   one corporate CA signing many distinct leaves is stated as active decryption.
3. **JA3S clustering** (`_ja3s_findings`, works even on TLS 1.3 with no key
   log). When a single server-side TLS fingerprint (JA3S) fronts **≥5 distinct
   destinations**, one TLS stack is terminating everything — the signature of a
   decrypting proxy.

**How we do NOT detect it / limits:**
- JA3S clustering can also be produced by a **shared CDN**; the finding text says
  to confirm the destinations are unrelated organizations.
- On **TLS 1.3 without a key log**, the certificate is encrypted, so signal (1)
  is unavailable and we fall back to JA3S/behavioral signals only.

---

## 2. Local (endpoint-agent) TLS interception (`local_interception`)

**What:** An agent **on this device** (SASE/SWG roaming client, AV web-shield,
or any local MITM proxy) decrypts TLS locally before it leaves the machine.

**How we detect it (`_local_interception_findings`) — this is the novel core:**
- A TLS flow on **loopback** (127.0.0.1 / ::1) whose leaf certificate is
  **re-signed by an interception CA** proves a local agent, because both ends of
  a loopback flow are the same machine.
- The **vendor is named from the issuer text** via `_LOCAL_AGENT_VENDORS`;
  unrecognized issuers are still reported ("an unrecognized interception CA") —
  precisely the unknown-vendor case worth surfacing.
- **Host recovery from the re-signed cert.** Loopback legs often carry no SNI/DNS
  (the roaming listener on 127.0.0.1:5002, resumed sessions). Because a
  decrypting agent re-signs with the **real destination name**, we recover the
  host from the leaf Subject CN / SAN (`_cert_host`).
- **Interception-chain correlation.** Each loopback leg is stitched to its
  probable **outbound leg** — the nearest non-loopback flow to the **same host**
  within `_CHAIN_WINDOW_S = 10 s`. The two flows are cross-linked
  (`chain_outbound_key` / `chain_loopback_key`) so the UI can draw the full
  local→internet interception path.

**How we do NOT detect it / limits:**
- Requires a **re-signed certificate to be visible** on the loopback leg. A
  failed handshake with no Certificate message yields no vendor and no chain.
- Chain correlation is **probabilistic** (host + ≤10 s proximity), not a proven
  packet linkage.

---

## 3. Certificate trust failures (`cert_trust`)

**What:** Decryption is active but the endpoint does not trust the proxy/SWG
signing CA (`unknown_ca`, `ERR_CERT_AUTHORITY_INVALID`).

**How:** TLS `unknown_ca` alert / HAR cert-authority errors combined with an
interception signal. **Limit:** needs the alert or HAR error on the wire; a
client that silently drops (no alert) surfaces instead as a network RST.

---

## 4. Certificate pinning (`pinning_signal`)

**What:** An app rejects the re-signed certificate and drops the connection.

**How:** Abrupt **TCP RST after ServerHello/Certificate** with **no graceful
FIN/close_notify** — or a client that completes the handshake through the
decrypting proxy then RSTs before sending any request (developer tools:
Composer/PHP, git, npm, pip, Java, curl that ship their own CA bundle).

**How we do NOT detect it / limits (explicit):**
- **Pinning cannot be proven from PCAP/HAR alone** — this is a behavioral
  inference and every finding says so (confidence ≤ Medium).
- **False-positive guard:** `_suppress_pinning_on_trusted_hosts()` removes the
  signal for any host that also **completed** a connection elsewhere (graceful
  FIN×2, or observed handshake-complete/app-data). Real pinning rejects *every*
  connection to the host, so an isolated RST is treated as a transient teardown
  (cancelled request, idle reset, capture cut-off). TLS 1.3-aware: it uses
  `fin_count >= 2` because handshake-complete/app-data cannot be observed there.

---

## 5. Public-certificate problems (`public_cert`)

**What/How:** Expired, not-yet-valid, name-mismatch or broken-chain on the real
server's own certificate (parsed by `certs.py`). **Limit:** only visible when
the certificate is on the wire (TLS ≤1.2, or TLS 1.3 with key log, or the inner
cert recovered from a decrypted CONNECT tunnel).

---

## 6. TLS version / cipher / handshake / alert (`tls_version`, `tls_handshake`, `tls_alert`)

**What/How:** Version-cipher mismatch, handshake started but no ServerHello
(failed/aborted), and fatal TLS alerts (mapped by `tlsconst.py`). GREASE values
(RFC 8701) are ignored. Post-quantum hybrid groups (X25519MLKEM768, etc.) are
named. **Limit:** a handshake that fails at the TCP layer (RST before
ClientHello) appears under `network`, not here.

### HelloRetryRequest — an extra round trip (reported under `latency`)

**What:** The server refused every `key_share` the client guessed and made it
send a second ClientHello with a group of the server's choosing. The handshake
still succeeds, so this is a **performance** finding, not a failure — hence
`latency`, not `tls_handshake`.

**How:** RFC 8446 §4.1.3 defines a HelloRetryRequest as a ServerHello whose
Random is the fixed constant
`cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c`. Matching
that value is **exact, not heuristic**. The groups offered in the first
ClientHello and the group the client was forced back to are both reported; when
the rejected offer was a post-quantum hybrid, the fallback to classical-only key
exchange is called out.

Because the HelloRetryRequest is itself handshake type 2, `tls_setup_ms` takes
the **last** ServerHello on such a flow — stopping at the first one would report
roughly half the true setup time.

**Limits:** the cost is stated as one extra round trip and, when the flow's RTT
is known, the approximate milliseconds. Why the server rejected the group is not
on the wire and is not guessed.

---

## 7. QUIC / HTTP-3 bypass (`quic`)

**What:** Traffic on **UDP/443 QUIC** likely bypassing TCP-based TLS inspection.

**How:** QUIC long-header / `quic` protocol detection in `enrich_flow`.

**How we do NOT detect it / limits:** QUIC payload is **not decrypted** — we can
say traffic went via QUIC and is un-inspected, but not what it carried.
Recommended remediation: block UDP/443 so browsers fall back to inspectable TCP.

---

## 8. Proxy / SWG blocks (`proxy`)

Three distinct block types are distinguished:

1. **DNS-layer block** — the flow connects to a Secure Access block-page anycast
   IP (`146.112.61.113-119` / `2620:119:18::…`). The **category is encoded in
   the IP** (`dns_analysis.BLOCK_PAGE_IPV4`): Malware, Phishing, C2 Callback,
   Content Category, Domain List, Security Integration.
2. **Web-layer (SWG) block** — the request is redirected to
   `block.sse.cisco.com` (`146.112.199.x`). This is a post-decryption block:
   URL/content category, application control, **DLP**, or an **AI-guardrail**
   rule. **Limit:** the block **reason is NOT encoded** in this IP — only the
   "web policy" family can be stated from the wire.
3. **Proxy errors** — 4xx/5xx and 407 proxy-auth on CONNECT/HTTP.
4. **HAR proxy evidence** (`_har_proxy_findings`) — responses carrying a `Via`
   header from Secure Access proxy nodes (confirms steering at request level),
   **QUIC/HTTP-3 `alt-svc` advertisements stripped by the proxy**, and an
   **HTTP/1.1 downgrade** where the origin normally serves HTTP/2. The last two
   are side effects of inspection worth naming, not faults.

**Domain recovery:** `_correlate_web_blocks()` names the real destination behind
the opaque block page by matching the domain requested ≤8 s before.

**How we do NOT detect it / limits:** these are Secure Access working as
designed, not faults — the summary explicitly frames them as enforcement, not
errors.

---

## 9. SWG steering coverage (`swg_coverage`)

**What/How:** Whether traffic is routed through the SWG (full / partial / zero
coverage), including the roaming module's own steered-vs-bypassed counters.
**Limit:** coverage is about routing, not a TLS fault; a bypass means policy /
decryption simply were not applied.

### Capture-derived coverage — `findings/steering.py`

The agent's self-reported totals cannot carry a percentage (see §14), so
coverage is also computed from the capture itself, **per category**, because
each is steered by a different mechanism and a device can have full coverage in
one and none in another:

| Category | What it is | Counted as |
|---|---|---|
| **Web** | TCP to 80/443/8080 toward a public host | the only population a web bypass can be measured against |
| **DNS** | resolution, steered by the roaming module's local listener | its own ratio |
| **Umbrella encrypted DNS** | port 443 to an Umbrella/OpenDNS resolver | neither web nor QUIC — it is the module forwarding intercepted queries upstream |
| **QUIC** | UDP/443 that is *not* that transport | un-inspectable by construction, so it counts as excluded |

**Counted per DESTINATION, not per connection.** The same host routinely opens
many connections and some take each path; a destination seen going through the
SWG even once was inspected, so only destinations **never** observed steered
count as excluded. Counting connections instead would report a host as bypassed
while that very host was being inspected on another connection. The number of
destinations seen on **both** paths is reported — it is a fact of the capture,
and why a host takes both is not visible on the wire and is not guessed.

**A destination only counts when a session actually happened** — a ClientHello,
a CONNECT or an HTTP request. Captures that start or end mid-conversation leave
addresses on port 443 with no handshake behind them, and treating those as
destinations invents traffic that was never inspected because it was never
requested.

**Excluded from every ratio:** private/RFC1918 and loopback destinations (the
SWG only handles internet-bound traffic), non-web ports, the steering
infrastructure itself, and local multicast name discovery (mDNS/LLMNR), which is
not resolution the module could steer.

**The exclusions are published, not hidden.** A `Traffic breakdown` finding
lists every category the capture was split into — web steered, web direct, DNS
intercepted, DNS sent elsewhere, Umbrella's encrypted-DNS channel, QUIC,
loopback, private, non-web, and web ports where no session was ever observed —
with the reason each one counts or does not. Without it the percentages are
unauditable: the reader cannot see what went into the denominator or what was
set aside, and would have to take both figures on trust.

**Limits:** in **site-to-site tunnel** mode the endpoint addresses the real
origin and encapsulation happens downstream, so steering leaves no trace a
host-side capture can see — the web verdict is **withheld** there rather than
reported as a total bypass. DNS is unaffected, since the local listener is
direct evidence either way.

---

## 10. Opaque tunnels (`tunnel`)

Explicit-proxy `CONNECT` tunnels are recognized and their establishment status
reported. With a key log, the **inner** TLS/cert is recovered (2nd pass).
Without it, the tunnel contents are end-to-end encrypted and reported as "not
decrypted".

---

## 11. DNS health (`dns`)

**What/How:** NXDOMAIN / SERVFAIL / REFUSED / FORMERR / NOTIMP, NODATA, and
queries that never received an answer (`dns_analysis.analyze_dns`). Reverse
(PTR) NXDOMAIN is treated as expected noise. Block-page answers are tagged
separately. SWG-proxy-hostname answers landing in **different regions** over the
capture are flagged as proxy region-flapping (breaks affinity).

**Limit:** encrypted DNS (DoH/DoT) content is not inspected; we recognize the
resolver by IP but not the queried names inside the encrypted channel.

---

## 12. Network / MTU / MSS (`network`)

**What/How:**
- `_network_health_findings` — packet loss, retransmissions, RSTs, zero-window.
- `_icmp_pmtud_findings` — ICMP "fragmentation needed" / Packet-Too-Big
  black-holes (PMTUD).
- `_mss_clamp_findings` / `_sa_tunnel_mtu_findings` — MSS clamp detection and (SA
  mode) the expected SA tunnel MTU 1390 / MSS 1350.
- `_duplicate_capture_findings` — detects the same traffic captured twice (e.g.
  span + host capture) and **suppresses** the resulting phantom retransmissions
  so they are not reported as loss.
- `_segmentation_offload_findings` — detects a capture taken on the **sending
  host, above the NIC**, while TCP segmentation offload (TSO/LSO/GSO) is still
  pending, and **suppresses** the reordering it fakes (see below).

**Receive-window limited (reported under `latency`).** `tcp.analysis.window_full`
means the sender exactly filled the receiver's advertised window and had to stop.
This is **not** loss and **not** a zero window (an application stall): the
receiver keeps reading, its window is simply smaller than the bandwidth-delay
product, capping the connection at window/RTT no matter how fast the link. It is
filed under `latency` precisely so it is never presented as "loss / MTU
blackhole / RST".

**Segmentation-offload capture point.** TCP may never place more bytes in a
segment than the peer advertised as its MSS, so a "segment" larger than the
largest MSS negotiated **on that same connection** cannot have existed on the
wire — it is the super-segment the OS handed to the NIC. Consequences, all
stated in the finding: packet counts and packet sizes are not what the network
carried, and the dissector's out-of-order / overlapping-segment events are
reassembly artifacts, so the out-of-order-only loss finding is suppressed. Byte
counts, RTT, the TLS handshake and genuine loss signals stay valid.

Three guards keep this exact rather than suspicious: flows whose **SYN was not
captured** are skipped (an unknown MSS cannot be guessed without manufacturing
the artifact), **loopback is excluded** (it never crosses a NIC, so its 64 KB
segments are normal), and the largest segment must be at least **2× the MSS**
(offload is only worth doing for more than one segment, so a payload marginally
over the MSS is far more likely a differing MSS on another SYN).

**How we do NOT detect it / limits:**
- **Asymmetric / one-armed captures** make loss counts unreliable;
  `_asymmetric_routing_findings` flags ACKed-but-unseen segments and one-way
  flows so the operator knows the capture is partial.

---

## 13. Latency (`latency`)

Slow DNS resolution, TCP connect, TLS setup and time-to-first-byte, computed
from handshake timing markers (PCAP) and HAR timing. Informational.

This category also carries the two **throughput/round-trip ceilings** that are
not failures and must never be presented as loss:

- **TLS HelloRetryRequest** — one extra round trip per affected connection
  (detected exactly; see §6).
- **TCP receive-window limited** — the sender filled the receiver's advertised
  window (see §12).

### Geo-egress latency (`_geo_egress_latency_findings`, HAR only)

**What:** Extra latency caused by egressing through an SWG node that is
geographically far from the user.

**How:** The egress region is read **authoritatively from the `Via` header**
(the Secure Access proxy node names carry their AWS region, e.g.
`m_proxy_prod_aws_ap-northeast-1_1_1n`) — never by geolocating an IP. It is then
corroborated with signals the **origin itself reveals**: Google's `cr=` country
parameter, a country-code TLD host (`google.co.jp`), or the egress IP a CDN
echoes back (`googlevideo ip=`).

**Limits:** severity is capped at **low** and the wording says *possible*,
because the capture cannot show where the user physically is. The tool reports
the egress geography and leaves the comparison to the operator.

---

## 13b. Network quality (`network_info`)

**What (`findings/quality.py`, `_network_quality_findings`):** A per-destination
verdict on whether there is a genuine network problem — the QoE-style view that
answers "is the network at fault, and where", separately from the raw counters
in §12.

**How — each metric chosen to be defensible across capture points:**
- **Network RTT** = `initial_rtt` (SYN → SYN/ACK). The cleanest per-flow network
  round trip. Deliberately **not** the mean `ack_rtt`, which is deflated by
  locally generated ACKs.
- **RTT variation** = population deviation of the per-ACK `ack_rtt` samples,
  requiring at least **8 samples** (below that a single local-ACK-versus-real-RTT
  pair fabricates enormous jitter). Called *RTT variation*, not "jitter", because
  what is measured is round-trip spread, not one-way RTP transit.
- **Real loss** = `retransmissions − spurious_retransmissions`, over a
  denominator of data segments (`tcp.len > 0`), needing ≥20 segments and ≥2 loss
  events before a percentage is stated. Thresholds: ≥0.5 % degraded, ≥2 % bad.
- **`tcp.analysis.lost_segment` is NEVER counted as loss.** Empirically its ratio
  to real retransmissions swings between 0.1× and 10× depending purely on where
  the capture was taken (endpoint captures with NIC offload manufacture phantom
  "lost" segments), so it is not comparable across captures.
- **Duplicate-ACKs with no matching retransmission** are reported separately as
  **unconfirmed** reverse-path loss or reordering — never as confirmed loss.

**Limits:** loopback flows are excluded (local IPC, not network). The healthy
verdict is only emitted with at least 3 real flows, so a two-flow capture does
not get a clean bill of health it cannot support.

**KNOWN GAP:** the `network_info` category is **not registered** in the
`CLASSIFICATION_*` tables in `analyze.py`, so these findings are returned by the
API but produce no tech-group and are **invisible in the UI**. See "Adding a
detector" in the handoff notes.

---

## 13c. PAC / WPAD proxy configuration (`proxy`)

**What (`findings/proxy_pac.py`):** A failed Web Proxy Auto-Discovery or PAC
fetch, which is a frequent reason traffic silently stops going through the SWG.

**How:** Browsers set to *Automatically detect settings* resolve `wpad.<domain>`
and fetch `http://wpad.<domain>/wpad.dat`. The detector flags a failed WPAD DNS
lookup and a failed/erroring PAC fetch. When that lookup fails the client falls
back to **DIRECT** — skipping the SWG entirely — or stalls.

**Limits:** it proves the PAC/WPAD mechanism failed, not that a specific flow
consequently bypassed the SWG; correlate with §9 coverage for that.

---

### Bottleneck attribution — where the time actually went

**What:** `findings/bottleneck.py` splits the captured period into **idle** and
**active** time and, when the evidence allows, names the single mechanism that
was limiting the transfer. Users report "it is slow" and every layer gets
blamed; the strongest answer this can give is often the negative one — long
stretches in which the network carried nothing, so whatever was being waited on,
it was not the wire.

**How:**

- **Idle time** is wall-clock time containing no packet from either side of any
  analysed conversation, in gaps of at least `_IDLE_GAP_S = 0.5 s` (below that
  the pause is ordinary request/response pacing). It is **measured, not
  modelled**.
- **Only conversation packets count.** Background link-layer chatter (ARP,
  broadcast, discovery) shares the wire but belongs to no conversation; letting
  it in would allow a stray frame to split a long pause in two or erase it, and
  it can never be attributed to a client or a server. It also fixes the reverse
  error: measuring against the full capture would score the time *before a
  conversation started* as if someone had been waiting.
- **Attribution.** Whoever sends the first packet after a pause is the side
  everything was waiting on, which makes the client/server split an attribution
  rather than a guess.
- **The dominant limit** is chosen by how conclusive the evidence is: real loss
  first (the only signal showing the *path* was the constraint), then idle time,
  then a zero window (receiving application not draining), then receive-window
  stalls.
- **Loss is judged as a rate**, never a raw count — a long capture accumulates
  events without the path being lossy. The threshold is
  `_LOSS_DOMINANT_PCT = 1 %` of data segments.

**How we do NOT detect it / limits:**
- **Why** an endpoint was idle is not knowable from a capture. The finding says
  the network was not the constraint; it does not claim the application was
  computing, reading a file, or waiting on a user or another service.
- The **real link capacity** cannot be derived without loss or a throughput
  plateau, so no "you could have gone N Mbps" claim is made.
- On captures whose loss counters are known unreliable (**duplicate interfaces**
  or a **host-side offloaded capture**, §12) the congestion verdict is
  **withheld entirely** rather than contradicting the finding that just
  explained why those counts are inflated.
- Captures shorter than `_MIN_SPAN_S = 1 s` produce nothing: the split would be
  decided by a handful of packets.

---

## 14. Cisco Secure Access-specific (SA mode only)

- **Roaming module** (`roaming`) — loopback DNS/web steering by the Secure Client
  roaming module, plus its clear-text `STARTMSG` self-report (bound SWG proxy +
  org, steered/bypassed counters).
- **Ingress health** — connections to published SA SWG ingress IPs/regions.
- **Private Access / ZTNA** (`private_access`) — either endpoint in the
  **100.64.0.0/10 CGNAT** pool marks the Zero-Trust proxy path to a private
  resource; SWG/decryption/pinning verdicts are deliberately **not** applied
  (they don't apply to arbitrary-protocol ZTNA tunnels).
- **Internal-traffic suppression** (`internal_traffic`) — private→private LAN
  flows never traverse the SWG, so SIA-level verdicts are suppressed to avoid
  false positives (with careful exceptions for CONNECT tunnels and the loopback
  roaming listener).

---

## Host fingerprinting (Hosts view)

**What/How (passive):**
- **TTL / hop-limit** captured from the server's packets (`ip.ttl` / `ipv6.hlim`).
- **Hop distance & OS estimate** via `_ttl_profile()`: nearest standard initial
  TTL (64→Linux/Unix/macOS, 128→Windows, 255→network device) minus the observed
  TTL gives hop count and an OS family.
- **Confirmed-open ports** from observed **SYN-ACK** (`server_synack`).
- **First/last seen** rendered as human-readable clock time + duration.

**How we do NOT detect it / limits (explicit):** OS/hop values are **estimates
labeled `(est.)`** — middleboxes and virtualization rewrite TTL, so they are
indicative, not authoritative. Loopback hosts suppress TTL/OS (meaningless
locally).

---

## Systemic limitations (the honest blind-spot list)

| Blind spot | Why | What we do instead |
|---|---|---|
| **DLP block reason** | The verdict is enforced *after* decryption; the block is a 302 to `block.sse` and any detail rides inside TLS. | Report the "web policy / DLP / AI-guardrail" family; recover the domain via time correlation; recommend HAR for request-level truth. |
| **Individual DLP blocks undercounted on the wire** | Multiple blocked requests can collapse onto one block-page connection. | State the family and count what is provable; lean on HAR. |
| **QUIC / UDP-443 payload** | Not TCP-TLS; not decrypted. | Flag as un-inspected bypass; recommend blocking UDP/443. |
| **TLS 1.3 certificate** | Encrypted unless a key log is supplied. | Use JA3S/behavioral signals; recover inner cert only with key log. |
| **Certificate pinning proof** | Not derivable from PCAP/HAR. | Behavioral inference, Medium confidence, completion-guard against false positives. |
| **Reduced (>80 MB) captures** | Only control frames decoded. | Set `reduced=True`; exclude bulk bytes from totals and say so. |
| **Asymmetric / one-armed capture** | Only one direction seen. | Detect and flag; treat loss counts as unreliable. |
| **Real on-wire packets in a host-side capture** | Segmentation offload means the NIC, not the OS, produced the actual packets — they are not in the file. | Detect the oversized super-segments, name the capture point, suppress the fake reordering, and keep only byte/RTT/handshake metrics. |
| **Why an endpoint was idle** | A capture can prove the network carried nothing; it cannot see the application computing, reading a file, or waiting on a user or another service. | Measure and attribute the idle time, state that the network was not the constraint, and stop there. |
| **TTL-based OS/hops** | TTL is rewritable. | Label `(est.)`. |
| **Encrypted DNS (DoH/DoT) names** | Names are inside TLS. | Recognize resolver by IP; do not fabricate queried names. |
| **Live certificate fetch** (`certfetch.py`) | Fetched now, not from the capture. | Kept clearly separate from capture evidence. |
