# HANDOFF — Capture Inspector (TLS_Inspector)

**Audience:** an engineer or LLM taking this codebase over, or **merging it into
another application**. It states what the system does, how each detection
actually works, what is deliberately NOT claimed, and the traps that will bite
you during a merge.

**Read this first, then `docs/DETECTION.md`.** This file is the map; that one is
the authoritative per-detector reference.

**Merging with a DART-bundle analyzer?** Read §11 first, then §8b–§8c for the
validated reference case that motivates it, then §12 for the data contract.

---

## 1. What the product is

A **100 % local** FastAPI web app that ingests a **PCAP/PCAPNG** and/or a **HAR**
(plus an optional **TLS key log**) and produces an evidence-based diagnosis of
TLS decryption, certificates, DNS, proxy/SWG, SASE behaviour and network health.

Nothing is uploaded anywhere. The only external dependency at runtime is
**tshark** (Wireshark CLI), which does all packet dissection.

**Vendor-agnostic by default.** Cisco Secure Access-specific intelligence is
opt-in via a `secure_access` flag; a second `sa_tunnel` flag marks a
site-to-site deployment. In agnostic mode the tool must not name a vendor.

### The one principle that governs every line of this codebase

> **Evidence or nothing.** A finding must cite what on the wire produced it. Where
> the capture cannot answer a question, the tool says so instead of guessing.

This is not a slogan — it is enforced in the code: pinning is capped at Medium
confidence because it is not provable; percentages are withheld when the
populations are not comparable; loss counters are suppressed when the capture
point makes them unreliable. **If you merge this into another app, preserve this
behaviour.** Most of the value is in what it refuses to claim.

---

## 2. Where the documentation lives

| File | Contents |
|---|---|
| `docs/README.md` | Documentation index + the honesty principles. |
| **`docs/DETECTION.md`** | **The authoritative catalog.** Every detector: *what*, *how* (exact on-wire signal), and *what it cannot see*. Sections §0–§14 + host fingerprinting + a systemic blind-spot table. |
| `docs/ARCHITECTURE.md` | System layout, pipeline, data model. |
| `docs/MODULES.md` | Module-by-module reference of every source file. |
| `docs/PATENT_DISCLOSURE.md` | Invention disclosure for the novel mechanisms (local-interception detection, etc.). |
| `CHANGELOG.md` | Dated record of fixes and new detections, **including the bugs found and how each was validated**. Read the latest entry — it documents several false positives that were caught and fixed. |
| `README.md` (root) | User-facing overview + how to run. |

---

## 3. Architecture and data flow

```
server.py  (FastAPI, POST /api/analyze)
    -> analyze.analyze(pcap_path, har_text, ctx, keylog_path)     # ORCHESTRATOR ONLY
        -> pcap.run_tshark()            # tshark -T json, explicit field list
        -> pcap.build_flows()           # group packets by tcp.stream / udp.stream
        -> engine.enrich_flow(flow)     # per-flow facts (TLS/TCP/QUIC/HTTP)
        -> engine.analyze_flow(flow)    # per-flow findings
        -> findings/*                   # capture-wide detectors, one module per domain
        -> analyze._correlate* / _classify / _summarize / _plain_summary
    -> JSON response  (or report.py for plain text)
```

### Key modules

| Module | Role |
|---|---|
| `app/server.py` | HTTP layer. Builds `AnalysisContext`, serialises `AnalysisResult` to JSON. Limits: PCAP/HAR 1 GB, key log 16 MB. |
| `app/analyze.py` | **Orchestrator only.** Correlation, classification, summaries, and the `CLASSIFICATION_*` tables. Contains no detection logic. |
| `app/context.py` | `AnalysisContext` (inputs/flags) and `AnalysisResult` (outputs). Separate module to break a circular import. |
| `app/pcap.py` | tshark invocation, the explicit `_FIELDS` list, `Flow` dataclass, flow assembly. |
| `app/engine.py` | Per-flow enrichment and per-flow findings. `Finding` and `FlowReport` dataclasses. |
| `app/findings/` | One module per detection domain (see §5). |
| `app/certs.py`, `certfetch.py` | X.509 parsing; optional live cert fetch (kept clearly separate from capture evidence). |
| `app/dns_analysis.py` | DNS records, block-page IP→category mapping, resolver identification. |
| `app/secure_access.py` | SA ingress IP list, CGNAT/private-IP helpers. |
| `app/har.py` | HAR parsing, block-page JWT decoding. |
| `app/static/` | UI (`index.html`, `app.js`, `style.css`). |

### Reduced mode

Above **80 MB** the PCAP is decoded with a display filter that keeps only
control frames (`REDUCE_FILTER`). TLS posture, certs, DNS, SNI, alerts and
severities stay accurate; **per-flow byte/packet totals read low** and
`result.reduced` is set so the UI and report say so.

---

## 4. The data model

- **`Flow`** (`pcap.py`) — one bidirectional conversation, keyed strictly by
  tshark `tcp.stream`/`udp.stream`. **No splitting, no merging**: a flow is 1:1
  with a real connection. Holds every per-flow field.
- **`Finding`** (`engine.py`) — `title`, `severity` (critical/high/medium/low/
  info), `category`, `detail`, `evidence[]`, optional `flow_key`, and
  `is_verdict` (marks a capture-wide finding that summarises others, so the
  headline states the conclusion rather than one of its inputs).
- **`FlowReport`** — a flow plus its parsed certs, TLS status and findings.
- **`AnalysisResult.all_findings`** — a live property merging per-flow findings,
  `signal_findings` (capture-wide) and `dns_findings`.

### Orphan / mid-stream flows

When the capture starts after the 3-way handshake there is no SYN to identify
the client. `build_flows` then applies a **lower-port-is-server** heuristic and
swaps endpoints if needed. Without this the client and server are reversed, and
byte direction and reset attribution invert with them.

---

## 5. What we detect — complete inventory

Full detail for every entry is in **`docs/DETECTION.md`**. Categories map to
user-facing labels via `CLASSIFICATION_LABELS` in `analyze.py`.

### TLS / certificates
| Category | Detects | Key limit |
|---|---|---|
| `interception` | SWG/proxy decrypting TLS: re-signed leaf cert, corporate-CA breadth, **JA3S clustering** (one server fingerprint fronting ≥5 destinations) | JA3S clustering can also be a shared CDN; on TLS 1.3 without a key log the cert is encrypted |
| `local_interception` | **An agent on THIS device decrypting TLS** — a loopback flow whose leaf is re-signed by an interception CA. Vendor named from the issuer; host recovered from the re-signed cert's Subject/SAN; loopback leg correlated to its outbound leg (±10 s) | Needs a visible re-signed cert; chain correlation is probabilistic, not cryptographic |
| `cert_trust` | Endpoint does not trust the proxy CA (`unknown_ca`, `ERR_CERT_AUTHORITY_INVALID`) | Needs the alert on the wire |
| `pinning_signal` | App rejects the re-signed cert: abrupt RST after ServerHello with no graceful close | **Not provable from a capture.** Capped at Medium. Suppressed for any host that completed a connection elsewhere |
| `public_cert` | Expired / not-yet-valid / name-mismatch / broken chain on the origin's own cert | Only when the cert is on the wire |
| `tls_version`, `tls_handshake`, `tls_alert` | Version-cipher mismatch, handshake with no ServerHello, fatal alerts | A TCP-layer failure appears under `network` |

### Policy / steering
| Category | Detects | Key limit |
|---|---|---|
| `proxy` | DNS-layer blocks (**category encoded in the anycast IP**), web-layer blocks via `block.sse.cisco.com`, 4xx/5xx/407, PAC/WPAD failures, HAR `Via`/alt-svc-stripping/HTTP-1.1-downgrade evidence | The web-layer block **reason is not in the IP** — only the policy family can be stated |
| `swg_coverage` | Ingress-IP coverage, plus **capture-derived inspection coverage** counted per destination and split into web / DNS / Umbrella encrypted-DNS / QUIC | Withheld entirely in site-to-site tunnel mode, where steering is invisible to a host capture |
| `roaming` | Roaming module loopback steering + its clear-text `STARTMSG` self-report (bound SWG proxy, org, counters) | Counters are **cumulative since agent start** and mix populations — see §7 |
| `private_access` | ZTNA via CGNAT **100.64.0.0/10** | SWG/pinning verdicts deliberately not applied to ZTNA tunnels |
| `internal_traffic` | private→private LAN flows; SIA verdicts suppressed | Loopback is excluded from this (it is the agent, not the LAN) |
| `quic` | UDP/443 QUIC bypassing TCP-based inspection | Payload not decrypted |
| `tunnel` | CONNECT tunnels; inner TLS recovered with a key log | Opaque without a key log |
| `dns` | NXDOMAIN/SERVFAIL/REFUSED/NODATA/no-answer, block-page answers, SWG proxy **region flapping** | DoH/DoT names are inside TLS |

### Network / transport
| Category | Detects | Key limit |
|---|---|---|
| `network` | Loss, retransmissions, RSTs, zero-window; **ICMP PMTUD**; **MSS clamp** and SA tunnel MTU 1390/MSS 1350; **duplicate multi-interface capture**; **segmentation offload (TSO/LSO/GSO) capture point** | Asymmetric captures make loss counts unreliable |
| `asymmetric_routing` | ACKed-but-never-captured segments (**proof tier**) and one-way flows (hedged) | Only fires with evidence |
| `latency` | Slow DNS/connect/TLS/TTFB; **HelloRetryRequest** extra round trip; **receive-window-limited** throughput; **bottleneck attribution** (idle vs active time budget, attributed to the side that broke the silence) | *Why* an endpoint was idle is unknowable from a capture |
| `network_info` | **Network-quality verdict per destination** (RTT, RTT variation, spurious-corrected real loss, unconfirmed reverse-path loss) | **Category is not registered → currently invisible in the UI.** See §8 |

### Host fingerprinting (Hosts view)
TTL/hop-limit → hop distance and OS family; confirmed-open ports from observed
SYN-ACK. **All OS/hop values are labelled `(est.)`** because TTL is rewritable.

---

## 6. Detection methods — the techniques worth knowing

1. **Exact protocol constants over heuristics.** A HelloRetryRequest is
   identified by the fixed RFC 8446 §4.1.3 Random
   (`cf21ad74…c8a8339c`) — an exact match, not an inference. Prefer this style.
2. **Impossibility arguments.** A TCP segment larger than the MSS the peer
   advertised *cannot* have existed on the wire, so its presence proves the
   capture was taken above the NIC with offload pending. Strong because it
   cannot be explained any other way.
3. **Both-ends reasoning.** A loopback flow has the same machine at both ends, so
   a re-signed certificate on it proves a **local** decrypting agent. This is the
   novel core of the tool.
4. **Cross-checking a claim against the same capture.** Loss counters are
   suppressed when the capture is duplicated or offloaded, because those make the
   counters untrustworthy — the report must never contradict itself.
5. **Rates, never raw counts.** A long capture accumulates events without being
   unhealthy. Loss is judged as a percentage of data segments.
6. **Per-destination, not per-connection**, wherever a host opens many
   connections that take different paths. Counting connections reports a host as
   bypassed while that same host is being inspected on another connection.
7. **Time-window correlation** for things the wire does not link: block page →
   real domain (≤8 s), loopback leg → outbound leg (≤10 s). Always labelled as
   correlation, never as proof.
8. **False-positive guards as first-class code.** `_suppress_*` functions exist
   specifically to remove signals that a second piece of evidence contradicts.

---

## 7. Traps that will bite you (learned the hard way)

Each of these was a real bug. They are in `CHANGELOG.md` with the evidence.

1. **A new category MUST be registered or it is invisible.** A `Finding` whose
   `category` is missing from `CLASSIFICATION_LABELS` produces no tech-group, and
   the UI renders **nothing** — the API returns it but the page never shows it.
   Register in **all five** tables in `analyze.py`: `CLASSIFICATION_LABELS`,
   `_WHY`, `_EXAMPLE`, `_REMEDIATION`, `_PLAIN_GROUP_NOTE`. Verify with
   `summary.tech_groups` in the JSON. **This has happened twice.**
2. **Report-view group cards are collapsed** unless severity is critical/high, so
   a low/info finding's title is not in the page text until expanded. Do not
   conclude "it is missing" from the rendered text alone.
3. **Python changes need a server restart.** uvicorn is not run with `--reload`;
   the process loads modules once. Static changes (`app.js`/`style.css`) need only
   a browser reload **plus a cache-bust bump** of the `?v=` query in
   `index.html` — without the bump the browser keeps the old file.
4. **`tcp.analysis.lost_segment` is not a portable loss metric.** Its ratio to
   real retransmissions swings 0.1×–10× purely with the capture point.
5. **Do not divide the roaming agent's counters.** "Steered" is HTTP+HTTPS only;
   "bypassed" also counts internal hosts and non-proxyable protocols. They are
   different populations and the counters are cumulative since the agent started.
6. **"Direct" does not mean "bypassed."** The same destination is frequently seen
   both through the proxy and directly; the mechanism is not visible on the wire.
7. **Do not count background frames as conversation.** ARP/broadcast will split
   or erase idle periods and can never be attributed to a client or server.
8. **A destination only counts when a session actually happened** (ClientHello,
   CONNECT or HTTP request). Stray packets on port 443 invent destinations.
9. **PowerShell 5.1**: no `&&`; `@(...).Count` for reliable counts. The venv
   interpreter is 3.10-compatible — no backslashes inside f-string expressions.
10. **Node is not installed.** Syntax-check `app.js` in the browser with
    `new Function(src)`; a single syntax error makes every function undefined.

---

## 8. Known gaps and open work

**Bugs / incomplete:**
- **`network_info` is unregistered** (§5) — `_network_quality_findings` output
  never reaches the UI. Fix by registering the category in the five tables.
- **`_regress_baseline.json` is stale.** The regression harness
  (`_refactor_regress.py baseline|check`) runs 8 captures × modes and compares a
  normalised signature. Recent intentional changes have not been re-baselined.

**Architectural gap — the biggest one for a merge:**

The tool asks the operator to declare the deployment (`sa_tunnel` checkbox)
instead of determining it. That does not scale, and a wrong answer yields a
confident wrong number. Different deployments produce completely different
captures:

| Deployment | Signature | Effect on metrics |
|---|---|---|
| SWG roaming | loopback listener; CONNECT to ingress | coverage measurable |
| Site-to-site tunnel | endpoint addresses real origins; encapsulation downstream | steering **invisible** — coverage withheld |
| VPNaaS (own adapter) | traffic on a tunnel interface to real origins | **would falsely report 100 % bypassed — not yet guarded** |
| ZTNA private access | CGNAT 100.64/10 | detected |
| ZTNA internet access | **signature unknown** | undetermined |

The unifying concept is the **capture vantage point** — physical NIC below a
tunnel, the tunnel adapter, both, or loopback. It determines which questions are
answerable *at all*. `frame.interface_id` is already captured (used only for
duplicate detection) and pcapng interface names/link types are available; this is
unused raw material.

### 8b. VPNaaS + roaming client — validated reference case

A combination worth detecting: **VPNaaS + roaming client**. If SWG-bound packets
appear on the VPN adapter rather than the physical NIC, the VPN is swallowing the
roaming traffic. This is **no longer hypothetical** — it was measured with tshark
on a matched GOOD/BAD pair of multi-interface captures of the same endpoint.

Both files carried three active interfaces: a physical NIC, an AnyConnect
adapter, and the loopback adapter. Packet counts per IP per interface:

| IP (role) | GOOD phys / tunnel | BAD phys / tunnel |
|---|---|---|
| SWG ingress A | **2611 / 0** | **0 / 432** |
| SWG ingress B (highest volume) | **1927 / 0** | **0 / 3186** |
| Umbrella resolver `208.67.222.222` | **372 / 0** | **0 / 116** |
| VPN headend | 0 | 6679 on physical (TLS encapsulation) |

The difference is **categorical, not a matter of degree**: in GOOD every
Umbrella-bound packet is on the physical NIC; in BAD every one is inside the
tunnel. Corroborated independently by three further signals:

- **CONNECT requests** — GOOD: 64 on the physical, 0 on the tunnel. BAD: 0 on the
  physical, 35 on the tunnel. CONNECT also *proves* an address is a forward proxy
  by behaviour, without consulting any IP list.
- **DNS** — GOOD: 237 queries on the physical (178 to the Umbrella resolver) plus
  37 on the tunnel to an internal corporate resolver, i.e. correct split DNS.
  BAD: only 24 on the physical and all of them multicast (mDNS/LLMNR), with 54
  Umbrella queries inside the tunnel.
- **Protocol stacks** — GOOD physical carries real application traffic
  (`ip:tcp:http:data`, `ip:udp:dns`). BAD physical carries `ip:tcp:tls` to a
  single peer (the encapsulated tunnel) and no application traffic in clear.

**The finding that matters for a merge:** the roaming agent's own `STARTMSG`
self-report looks *healthy in both captures* — same org, same bound SWG proxy,
steering counters increasing. The agent cannot observe that its egress is being
encapsulated downstream of itself. **Neither agent telemetry nor the cloud
dashboard can detect this misconfiguration**; only a capture that contains both
interfaces can. That asymmetry is the core value proposition.

### 8c. Identifying interface roles without asking the user

The blocker for automating the above is telling the physical NIC from the tunnel
adapter. Neither addressing nor naming solves it: in the reference captures both
interfaces held RFC 1918 addresses, and the pcapng interface **descriptions** were
`Ethernet0` (physical) and `Ethernet` (AnyConnect) — indistinguishable in
practice, and vendor-specific in general.

A link-layer discriminator does work, and held on both captures:

| Signal | Physical NIC | Tunnel adapter |
|---|---|---|
| ARP frames | 59 / 36 | **0 / 0** |
| LLDP frames | 39 / 25 | **0 / 0** |
| Distinct source MACs | 23 / 22 | **2 / 2** |

Rationale: a physical NIC sits on a multi-access broadcast segment (ARP per
RFC 826, LLDP per IEEE 802.1AB, many neighbours); a tunnel adapter is
point-to-point. Loopback is identified directly from its pcapng description.

**Two limits that must be respected:**

1. `REDUCE_FILTER` (§3) drops ARP and LLDP on captures above 80 MB, so the
   discriminator returns zero for *every* interface and would classify the
   physical NIC as a tunnel. It must fall back to **indeterminate**, never guess.
2. It is validated on two captures only. It identifies *shape*, not vendor.

**Therefore the double-interception finding must require two legs**: the shape leg
(an interface that looks like a tunnel) **and** an identity leg (what is inside it
is a *recognised* Secure Access ingress or resolver). The identity leg is what
makes the finding immune to a third-party firewall or VPN in the environment —
see §11.8. A purely shape-based version of this rule is **not** safe and was
deliberately rejected.

---

## 9. Running and testing

```powershell
cd "c:\DEV Copilot\TLS_Inspector"
$env:PYTHONIOENCODING="utf-8"
& ".venv\Scripts\python.exe" -m uvicorn app.server:app --host 127.0.0.1 --port 8000
```

- Health: `GET /api/health` (also reports the tshark path).
- Analyse: `POST /api/analyze`, multipart — `pcap`, `har`, `keylog` files and
  form flags `secure_access`, `sa_tunnel`, `resolve_certs`.
- Regression: `python _refactor_regress.py baseline` then `... check`.
- **Validate against tshark directly**, not only through this code. Every
  significant claim in the changelog was confirmed with an independent
  `tshark -Y ...` query first. Several bugs were found exactly this way.

---

## 10. If you are merging this into another app

Preserve, in priority order:

1. **The honesty contract.** Confidence caps, withheld percentages, suppression
   guards and the explicit "what we cannot see" text are the product. A merged UI
   that renders findings without their limits misrepresents them.
2. **`docs/DETECTION.md` as the contract.** Every detector's *how* and *limit*
   lives there. Keep it in step with the code; it is the reason the tool can be
   trusted.
3. **The category registration requirement** (§7.1) — the single most common way
   to silently lose a detector during integration.
4. **Severity semantics.** `info` is context, not "good"; `low` is a real but
   non-failing observation. The UI colours them accordingly (low is blue, not
   red) — a merged UI that maps `low` to a warning colour will report healthy
   captures as broken.
5. **`Finding.is_verdict`** — without it a summary finding loses the headline to
   one of its own inputs.

The cleanest integration boundary is `analyze.analyze()` → `AnalysisResult`.
Everything above it is transport and presentation; everything below is detection.

---

## 11. Merging with a DART-bundle analyzer

This section is written for the specific case of unifying this tool with an
application that ingests **Cisco DART bundles** (the diagnostic archive produced
by Cisco Secure Client / AnyConnect).

### 11.1 Why the two are complementary rather than overlapping

They answer **different halves of the same question**, and neither half is
sufficient alone:

- A **DART bundle** describes what the endpoint is **configured** to do, and what
  its software **reported about itself**. It is authoritative about intent,
  versions, profiles and local state.
- A **packet capture** describes what the endpoint **actually did on the wire**.
  It is authoritative about behaviour, and blind to intent.

The reference case in §8b is exactly this split. The capture proved the traffic
was being tunnelled; it could not prove what the administrator *meant* to happen.
The agent's own self-report — the closest thing to a DART signal available inside
a capture — said everything was fine.

### 11.2 What a DART bundle is expected to contain

> **Status: requires validation against a real bundle.** The list below is the
> expected content of a Secure Client DART archive and should be confirmed file
> by file before any parser is written. Do not implement against this table as if
> it were verified.

| Expected artefact | Why it matters here |
|---|---|
| `ipconfig /all`, `route print`, interface list | **Resolves the §8c problem directly.** Names the VPN adapter and its address range, so interface roles need no heuristic. |
| VPN profile XML (split-tunnel include/exclude lists) | States which destinations are *supposed* to bypass the tunnel — the intent half of §8b. |
| Umbrella `OrgInfo.json` (organisation ID, fingerprint, user ID) | Joins directly to the org ID this tool already extracts from the roaming `STARTMSG`. |
| Umbrella / SWG module configuration | The bound SWG proxy hostname, also present in `STARTMSG` and in capture DNS. |
| Secure Client and module versions / build numbers | Lets a finding be tied to a known defect or a minimum fixed release. |
| Agent logs (VPN agent, UI, roaming module) with timestamps | Can explain *why* an endpoint was idle — a blind spot this tool documents and cannot close from packets. |
| Windows event logs | Service restarts, driver faults, adapter state changes. |
| Certificate store / trust export | Confirms `cert_trust` findings against the actual trust store instead of inferring from a TLS alert. |
| Trusted Network Detection state, posture state | Explains why steering changed mid-capture. |

### 11.3 Capability matrix

| Question | Capture alone | DART alone | Merged |
|---|---|---|---|
| Is TLS being decrypted, and by whom | **Yes** (re-signed leaf, issuer, JA3S) | No | Yes |
| Is an agent on *this* device decrypting locally | **Yes** (loopback + re-signed cert) | Partially (module installed ≠ active) | Yes, confirmed both ways |
| Which destinations were actually inspected | **Yes** (per-destination coverage) | No | Yes |
| Which destinations were *meant* to be inspected | No | **Yes** (profile / exclusion lists) | **Yes — enables gap analysis** |
| Which interface is the VPN adapter | Heuristic only (§8c) | **Yes** (adapter list, routes) | Yes, deterministic |
| Is the endpoint's trust store missing the proxy CA | Only if a TLS alert appears | **Yes** (cert store) | Yes, confirmed |
| Packet loss, RTT, MTU, retransmission behaviour | **Yes** | No | Yes |
| Why an endpoint went idle | **No** (documented blind spot) | Possibly (agent logs) | Improved |
| Software version tied to a known defect | No | **Yes** | Yes |
| Did steering match configuration | No | No | **Yes — only the merge can answer this** |

### 11.4 The capability that only the merge creates

> **Configuration-versus-behaviour contradiction detection.**

Every row in the last column above is useful, but one is genuinely new: comparing
**declared intent** against **measured behaviour** and reporting the delta with
evidence from both sides.

This is also the correct resolution of the architectural gap in §8. Today the
tool asks the operator to declare the deployment via the `sa_tunnel` checkbox — a
declaration it cannot verify, where a wrong answer produces a confident wrong
number. A DART bundle replaces that self-declaration with **parsed configuration**
and, crucially, does so in a form that can itself be checked against the wire.

The governing rule, which is a direct extension of the honesty contract in §1:

> **A declaration — from a checkbox, a profile, or a log — is an input to be
> verified, never a conclusion.** The mismatch between what was declared and what
> was measured is the highest-value output of the merged tool.

The reason this matters is in §8b: in a misconfigured deployment the
administrator *believes* the configuration is correct. A merged tool that trusts
the DART profile and reports "split-tunnel exclusions configured — OK" would
reproduce the exact blindness that makes this class of fault survive in
production.

### 11.5 Correlation keys between the two datasets

These are the join keys that make a unified record possible. Each should be
validated against a real bundle before being relied on.

| Key | Capture side | DART side |
|---|---|---|
| Umbrella organisation ID | roaming `STARTMSG` | `OrgInfo.json` |
| Bound SWG proxy hostname | `STARTMSG`, DNS query names | SWG module config |
| VPN adapter name + address range | pcapng interface descriptions, per-interface source IPs | adapter list, `route print` |
| Local IP addresses | source IPs per interface | `ipconfig /all` |
| Device hostname | rarely present (NBNS/LLMNR/mDNS only) | system info |
| Interception CA subject / fingerprint | re-signed leaf issuer, `certs.py` | trust store export |
| Wall-clock time | pcapng frame timestamps | log timestamps |

**Trap — clock alignment.** Packet timestamps and agent log timestamps come from
different sources and may differ in timezone, resolution and offset. Correlating
events across the two datasets by time must be treated as **correlation, never
proof**, and labelled as such — consistent with §6.7. Establish and record the
offset explicitly rather than assuming both are UTC.

### 11.6 Worked example — what the merged tool would report

Using the validated BAD capture from §8b together with its (hypothetical) bundle:

1. **From DART:** the VPN profile declares split-tunnel exclusions for the Secure
   Access ingress ranges and resolvers; the VPN adapter is named and its address
   range is known; the Umbrella module is installed and enabled for org *N*.
2. **From the capture:** every packet to those same ingress addresses is on the
   VPN adapter; zero are on the physical NIC; the CONNECT requests that prove
   proxy steering are inside the tunnel; the Umbrella resolver is queried through
   the tunnel while the physical NIC carries only multicast name resolution.
3. **Merged finding:** *the configured exclusions are not in effect* — quoting the
   profile line that declares the exclusion **and** the per-interface packet
   counts that disprove it, with the org ID confirming both datasets describe the
   same endpoint.

Neither tool can produce that sentence alone. The capture cannot cite the
profile; the bundle cannot observe the wire.

### 11.7 Proposed unified architecture

Keep the two ingest paths separate and correlate above them. Do **not** interleave
DART parsing into the packet pipeline.

```
  PCAP/PCAPNG ──► analyze.analyze() ──► AnalysisResult   (behaviour, evidence-backed)
                                              │
  DART bundle ──► dart_parse()   ──► DartFacts│           (configuration + local state)
                                              ▼
                                     correlate(AnalysisResult, DartFacts)
                                              │
                                              ▼
                                   UnifiedResult  ──► UI / report
```

Design rules for the correlation layer:

- It **adds** findings; it must not silently rewrite findings from either side.
  A packet-derived finding keeps its own evidence and its own limits.
- Every correlated finding must cite **both** sources explicitly, so a reader can
  see which half is measurement and which half is declaration.
- It must degrade cleanly: capture only, bundle only, or both. With one input the
  merged findings are simply absent — not replaced by weaker guesses.
- The existing integration boundary (§10) is unchanged: `analyze.analyze()` →
  `AnalysisResult` stays the packet-side contract.

### 11.8 Rules the merged tool must not break

Beyond §10, these come from failures already made and corrected in this codebase:

1. **Never infer a vendor from shape — only from identity.** Shape-based signals
   (a loopback listener, a point-to-point adapter, a CONNECT request) can be
   produced by any third-party agent, VPN or firewall present in the environment.
   Identity-based signals (an IP in the published ingress list, the SWG proxy
   hostname pattern, the Secure Access root CA fingerprint, the roaming
   `STARTMSG`) cannot collide with another vendor. Verdicts require an identity
   leg; shape alone may only produce neutral context.
2. **Report unidentified interception rather than absorbing it.** If a decrypting
   CA is present that is neither Secure Access nor a recognised corporate CA, say
   so. Silently folding it into coverage numbers misattributes another product's
   behaviour to this one.
3. **Presence and absence are not symmetric.** Presence proves itself and can be
   reported in any mode; **absence is ambiguous** — "no traffic reached an
   ingress" is a fault only if steering was expected. Findings that assert absence
   or deficiency are the ones that legitimately require a declaration (checkbox or
   DART profile). Findings that assert presence should not be gated behind one.
4. **Do not expand the deployment taxonomy.** Deployment-specific knowledge
   belongs in individual detectors, not in a tree of modes. The double
   interception case in §8b is a *finding*, not a mode: it needs only recognised
   identity plus a multi-interface capture.
5. **Multi-interface captures are a precondition, not a preference.** Any question
   about tunnel-versus-direct pathing is unanswerable from a single-interface
   capture. Say so explicitly instead of assuming no tunnel exists.

### 11.9 Open questions to resolve with the DART side

Recorded so they are not silently assumed:

- **Bundle layout and file formats — unvalidated.** §11.2 is expectation, not
  fact. Confirm before writing a parser.
- **ZTNA internet-access signature is unknown** (§8). ZTNA private access is
  detected via CGNAT 100.64/10; the internet-access variant has no confirmed
  signature in this codebase.
- **The fallback deployment — agent disabled, VPNaaS handling everything — has
  not been observed.** It would show no roaming loopback activity at all, which a
  naive detector could report as "the agent is not working" when it is in fact the
  intended design. A capture of this case is needed before shipping any finding
  that asserts the agent is absent or inactive.
- **Do bundles reliably contain the VPN profile in effect**, as opposed to all
  installed profiles? A gap analysis is only valid against the profile that was
  actually applied.
- **Time base of agent logs** relative to packet timestamps (§11.5).

---

## 12. The integration surface — `POST /api/analyze` response

The exact top-level shape returned by `server.py`. This is the contract another
application consumes; verify against `server.py` when it changes.

| Key | Contents |
|---|---|
| `report_text` | Full plain-text report (`report.py`). |
| `reduced` | `true` when reduced mode was used (§3) — per-flow byte/packet totals read low. |
| `summary` | `diagnosis`, `confidence`, `classifications`, `primary_evidence`, `plain_summary`, `plain_impact`, `recommended_action`, `plain_scope`, `plain_secondary`, `tech_groups`. |
| `flows` | Per-flow rows: endpoints, SNI, TLS version, certs, error summary and that flow's findings. |
| `hosts` | Host inventory (TTL-derived hop distance and OS family, **all marked estimated**). |
| `har_entries`, `har_summary` | HAR rows and aggregate (`null` without a HAR). |
| `findings` | **Every** finding, capture-wide and per-flow: `title`, `severity`, `category`, `detail`, `evidence[]`, `flow_key`. |
| `correlations` | Time-window correlations (block page → domain, loopback leg → outbound leg). Correlation, not proof. |
| `notes` | Caveats, including the online-certificate-resolution disclaimer. |
| `capture_env` | Capture environment facts. |
| `decryption` | `null` unless a key log was supplied; then key-log usage and inner-TLS recovery counts. |
| `roaming_report` | Roaming `STARTMSG` self-report. **Gated on Secure Access mode.** Counters are cumulative since agent start — see §7.5. |
| `steering_coverage` | Capture-derived inspection coverage. **Deliberately not SA-gated.** |
| `dns` | `summary` plus every parsed DNS record. |

**Consumption notes for the merged application:**

- `confidence` is a **single result-level value** (`Low`/`Medium`/`High`), not
  per-finding. There is currently no per-technique confidence score; do not
  present one as if it existed.
- `severity` semantics are as in §10.4: `info` is context, `low` is real but
  non-failing. Mapping `low` to a warning colour reports healthy captures as
  broken.
- `is_verdict` is **not** serialised in the finding dictionary; it affects
  ordering server-side only. A merged UI that re-sorts findings can lose the
  headline to one of its own inputs.
- A finding whose `category` is absent from the `CLASSIFICATION_*` tables is
  returned in `findings` but produces **no** `tech_group`. Consuming `findings`
  directly is therefore *safer* than consuming `summary.tech_groups`, and is the
  recommended integration point.
