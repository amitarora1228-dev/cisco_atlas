# Changelog

All notable changes to Capture Inspector are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — 2026-08-01

Driven by a real host-to-host capture (a 16 MB TLS upload to an Oracle Cloud
Object Storage private endpoint) that the analyzer read incorrectly. The capture
exposed one false positive and three signals the engine could not see at all.

### Fixed

- **False "packet loss" on host-side captures.** A capture taken on the sending
  host before NIC segmentation offload reports super-segments (up to 24,444 bytes
  against a negotiated MSS of 1358) that the TCP dissector reassembles into
  apparent out-of-order events. With `0` retransmissions, `0` lost segments and
  `0` zero-window events, the engine still produced a `medium` "TCP packet loss /
  retransmissions (29 events)" finding and promoted it to the top-line diagnosis
  as *"Network-layer issue resembling a TLS failure … possible loss / MTU
  blackhole / RST"* — while the same report simultaneously stated *"Network
  quality: healthy — no packet loss"*. Out-of-order-only loss findings are now
  suppressed on offloaded captures, resolving the contradiction.
- **Post-quantum key-exchange groups shown as raw numbers.** `_named_group()`
  only mapped the hex spellings, but tshark prints these extensions in decimal,
  so a real `X25519MLKEM768` negotiation was reported as `4588`. Added the
  decimal spellings for X25519MLKEM768, X25519Kyber768, SecP256r1Kyber768 and
  the FFDHE groups.
- **`tls_setup_ms` halved on HelloRetryRequest flows.** A HelloRetryRequest is
  itself handshake type 2, and the timer stopped at the first one — reporting
  27 ms for handshakes that actually took 51 ms. On an HRR flow the timer now
  takes the last ServerHello.
- **Plain-language summary asserted a cause it could not know.** Any finding
  without a dedicated branch fell through to *"something interfered with a
  secure web connection"* — which flatly contradicted a speed finding, and was
  wrong for DNS and capture-quality findings too. The `latency` category now has
  its own wording (nothing failed; this is about speed), a congestion verdict no
  longer borrows the failed-handshake wording from the `network` branch, and the
  generic fallback states the finding instead of inventing a cause for it.
- **The Issue column contradicted the report.** On a host-side offloaded capture
  it printed a red `ooo ×25` for exactly the reordering the report had just
  explained was a reassembly artifact. Out-of-order is now omitted there (only
  when no real loss signal accompanies it), so the table and the findings agree.
- **The Issue column was written in shorthand.** `retx ×63`, `lost ×7`,
  `ooo ×265`, `zero-win ×1` meant nothing to anyone who did not already know the
  jargon. They now read "63 packet(s) sent again", "7 packet(s) lost",
  "265 packet(s) arrived out of order", "receiver full 1 time(s)".
- **Low-severity rows were painted red.** The Issue cell had only three tones
  (red / amber / grey), so a `low` finding — a slowdown, not a failure — was
  shown in red next to its own blue LOW pill. Low now uses the same blue.
- **The roaming panel divided two different populations and called the result
  "% of web bypassed".** The steered counters are explicitly HTTP and HTTPS,
  while the agent's own bypass description — printed in the same panel — covers
  internal/RFC1918 hosts and protocols it cannot proxy at all (QUIC/UDP). The
  panel therefore contradicted itself, and the resulting "92%" was the most
  prominent number on screen. The percentage is gone from both the finding and
  the UI, replaced by the one figure that genuinely belongs to the capture: how
  far the bypass counter moved while it was running. The three raw counters are
  now labelled "since agent start", because they are cumulative over the agent's
  whole lifetime and describe far more than the captured window (in the sample
  capture they total 5,367 connections against 174 actually present in the file).

### Added

- **Segmentation-offload capture-point detection**
  (`_segmentation_offload_findings` in `findings/network.py`). A TCP segment
  larger than the largest MSS negotiated on its own connection cannot have
  existed on the wire, so its presence proves the capture was taken on the
  sending host above the NIC with TSO/LSO/GSO still pending. The finding names
  the capture point and states the consequences: packet counts and sizes are not
  what the network carried, reordering events are reassembly artifacts, while
  byte counts, RTT, the TLS handshake and genuine loss signals remain valid.
  Three guards keep it exact rather than heuristic — flows whose SYN was not
  captured are skipped (an unknown MSS cannot be guessed without manufacturing
  the artifact), loopback is excluded (it never crosses a NIC), and the largest
  segment must be at least 2x the MSS.
- **TLS HelloRetryRequest detection** (category `latency`). Identified by the
  fixed RFC 8446 §4.1.3 ServerHello Random
  `cf21ad74…c8a8339c`, so the match is exact rather than inferred. Reports the
  key-share groups the client offered, the group it was forced back to, the cost
  of the extra round trip, and explicitly calls out a post-quantum hybrid being
  refused in favour of classical-only key exchange.
- **TCP receive-window-limited detection** (category `latency`), from
  `tcp.analysis.window_full`. Distinct from a zero window: the receiver keeps
  reading, but its window is smaller than the bandwidth-delay product, capping
  the connection at window/RTT regardless of available bandwidth.
- New `Flow` fields: `window_full`, `max_tcp_len`, `oversized_segments`,
  `hello_retry_request`, `hrr_offered_groups`, `hrr_selected_group`.
- New tshark fields: `tcp.analysis.window_full`, `tls.handshake.random`.
- **Bottleneck attribution** (`findings/bottleneck.py`). Splits the captured
  period into idle and active time and, when the evidence allows, names the one
  mechanism that was limiting the transfer. Idle time is measured (gaps of
  ≥ 0.5 s with no packet on any analysed conversation), and each pause is
  **attributed** to whichever side broke the silence — that side is the one
  everything was waiting on. The dominant limit is ranked by how conclusive the
  evidence is: real loss, then idle, then zero window, then receive-window
  stalls. Loss is judged as a **rate** (≥ 1 % of data segments), never a raw
  count, and the congestion verdict is **withheld entirely** on captures whose
  loss counters are known unreliable (duplicate interfaces or host-side
  offload), so the report cannot contradict itself.
- `Finding.is_verdict` — lets a capture-wide finding outrank, among equally
  severe findings, the per-flow findings it summarises, so the headline
  diagnosis states the conclusion rather than one of its inputs.
- **Capture-derived inspection coverage** (`findings/steering.py`). Replaces the
  removed agent-counter percentage with figures measured on the wire, split by
  category because each is steered by a different mechanism: **web** (TCP to
  80/443 toward a public host), **DNS** (its own ratio — a query can escape
  Umbrella while the web request that follows is still inspected), **Umbrella's
  encrypted DNS channel** (port 443 to an Umbrella resolver: neither web nor
  QUIC) and **QUIC** (UDP/443 that is not that channel, un-inspectable by
  construction). Counted per DESTINATION, since the same host opens many
  connections and some take each path — only destinations never once observed
  going through the SWG count as excluded, and the number seen on both paths is
  reported rather than explained away. A destination only counts when a session
  actually happened (ClientHello, CONNECT or HTTP request), private/loopback and
  non-web traffic is excluded, and the web verdict is withheld entirely in
  site-to-site tunnel mode, where steering is invisible to a host-side capture.
  On the sample capture this reports 6 % of web destinations and 5 % of DNS
  queries un-inspected, against the 92 % the old counter-based figure claimed.
  A companion `Traffic breakdown` finding publishes every category the capture
  was split into, including the excluded ones and why each was excluded, so the
  two percentages can be audited instead of taken on trust.
- **Non-failure slowdowns are now visible per flow.** A receive-window pause and
  a HelloRetryRequest produce no alert, no reset and no status code, so the flow
  table showed "—" and the operator could read that the capture was slow without
  ever seeing *which* connection was slow. Both now carry a blue `slow-tag`
  ("waiting on receiver ×N", "extra setup trip") in the Issue column with an
  explanatory tooltip, plus their own rows in the expanded flow detail. Blue,
  deliberately: amber and red are reserved for things that actually failed.
  `window_full`, `hello_retry_request`, `hrr_offered_groups` and
  `hrr_selected_group` are serialised per flow to support this.

### Changed

- **Documentation completed for a hand-over / merge.** Added
  `docs/HANDOFF.md` — the entry point for another team or tool taking this over:
  architecture, the full detector inventory, the detection techniques worth
  reusing, the traps that cause silent breakage, and the known gaps. Documented
  three detectors that had shipped without any entry in the detection catalog:
  the **network-quality verdict** (`findings/quality.py` — RTT, RTT variation,
  spurious-corrected loss, and why `lost_segment` is never counted), the
  **geo-egress latency** check (SWG region read from the `Via` header, not from
  geolocating an IP), and **PAC/WPAD** failures. Also recorded a real gap found
  while writing it: the `network_info` category is not registered in the
  `CLASSIFICATION_*` tables, so the network-quality findings are returned by the
  API but never rendered.

- **Finding explanations rewritten for a non-specialist reader.** The receive-window
  and HelloRetryRequest texts were accurate but unreadable ("a throughput ceiling
  of window/RTT", "redo the key exchange with secp256r1"). Each now leads with
  what happened in ordinary words, carries a concrete analogy (a funnel that must
  drain; trying the wrong key at a door and walking back for the right one),
  states the measured cost on this path, and ends with where the fix belongs.
  The evidence strings keep the exact technical values.
- Both new findings are filed under `latency` ("Slow performance / high
  latency") rather than `network` or `tls_handshake`. Neither is packet loss, an
  MTU blackhole, an RST, nor a handshake failure — filing them elsewhere would
  have produced the misleading classifications the previous behaviour showed.
- `_network_health_findings()` takes an `offloaded_capture` flag and, mirroring
  the existing duplicate-capture handling, suppresses the aggregate loss finding
  when nothing but out-of-order events is behind it, or downgrades it to `low`
  with an explicit caveat when real loss coexists.

### Validation

- Every signal was confirmed independently with `tshark` before being trusted,
  not just through the analyzer.
- During development the offload detector produced its own false positive: with
  no SYN captured it defaulted to a 1460-byte MSS and flagged legitimate 16 KB
  loopback segments. Fixed by requiring a known MSS, excluding loopback and
  adding the 2x threshold; the affected capture returned to zero detections.
- Regression harness (`_refactor_regress.py`) run across the full capture set.
  Remaining diffs are new true positives, verified on the wire — for example
  18 genuine HelloRetryRequest exchanges in `captura normal.pcapng` that were
  previously invisible.
- The bottleneck detector was corrected twice during development, both times
  after checking its output against `tshark` rather than trusting it: an
  absolute loss count was reporting healthy captures as congested (fixed by
  switching to a rate and honouring the unreliable-counter flags), and counting
  background ARP frames as conversation traffic scored a capture as 68 % idle
  when the conversations were in fact continuous — they simply had not started
  yet for most of the file.
- `_regress_baseline.json` is intentionally **not** regenerated; it needs to be
  re-baselined once these changes are accepted.
