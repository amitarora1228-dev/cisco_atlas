# Module Reference

Every source file under `app/`, its responsibility, and its key public
functions. Line counts are approximate and indicate relative size/complexity.

## Top-level engine

### `app/analyze.py` (~1200 lines) — Orchestrator
The central pipeline. Owns the classification vocabulary and the summarizers.
- **Classification tables** — `CLASSIFICATION_LABELS` (category → user label),
  `CLASSIFICATION_WHY` (why flagged), `CLASSIFICATION_EXAMPLE` (real-world
  analogy), `CLASSIFICATION_REMEDIATION` (fix steps). Categories: interception,
  local_interception, cert_trust, pinning_signal, public_cert, tls_version,
  tls_handshake, tls_alert, quic, proxy, swg_coverage, tunnel, network, dns,
  latency, roaming, private_access, asymmetric_routing, internal_traffic.
- `analyze(pcap_path, har_text, ctx, keylog_path)` — main entry; runs the full
  pipeline described in [ARCHITECTURE.md](ARCHITECTURE.md) §2.
- `_correlate_dns_to_flows()` — attach nearest preceding DNS lookup to each flow.
- `_matches_context()` — domain/src/dst filtering.
- `_correlate()` — HAR↔PCAP correlation (failures and proxied-OK CONNECTs).
- `_correlate_web_blocks()` — name the domain behind an opaque block page (≤8 s).
- `_suppress_pinning_on_trusted_hosts()` — false-positive guard for pinning.
- `_classify()` — build severity-ranked `tech_groups`; note corporate-CA breadth.
- `_summarize()` / `_plain_summary()` — technical verdict + plain-language
  narrative (success / pinning+interception / cert_trust / blocks / quic / proxy
  / swg_coverage / public_cert / tls_version / network / handshake).

### `app/engine.py` (~1030 lines) — Enrichment + per-flow analysis
- Data classes `Finding`, `FlowReport`.
- Helpers: `_l7_protocol` (name the app protocol), `_is_grease`, `_named_group`
  (incl. post-quantum hybrids, hex **and** decimal spellings), `_HRR_RANDOM`
  (the fixed RFC 8446 HelloRetryRequest Random), `_is_loopback`, `_pkt_is_c2s`
  (direction, loopback-aware).
- `enrich_flow(flow)` — extracts all TLS/TCP/QUIC/HTTP facts, directional
  byte/packet counters, **server TTL / SYN-ACK**, MSS, timing markers
  (`tcp_handshake_ms`, `tls_setup_ms` — HRR-aware, taking the last ServerHello),
  HelloRetryRequest + offered/forced key-share groups, `window_full` stalls,
  segmentation-offload evidence (`max_tcp_len`, `oversized_segments`),
  CONNECT-tunnel detection.
- `_timeline_entry` / `flow_timeline` — the per-packet ladder (head+tail
  summarized for long flows).
- `analyze_flow(flow, corporate_ca_orgs, secure_access_mode)` — parses certs,
  sets Private-Access/internal flags, calls `_set_tls_status` + `_flow_findings`.
- `_set_tls_status` — human-readable status (QUIC, CONNECT tunnel states, inner
  TLS decrypted/encrypted, handshake completeness).
- `_flow_findings` — per-flow findings incl. block-page IP correlation
  (DNS-layer + web-layer).

### `app/pcap.py` (~625 lines) — tshark decode + flow assembly
- `Packet` (with `.first`/`.all`), `Flow` dataclass (endpoints, TLS/TCP/QUIC
  fields, TTL/SYN-ACK, tunnel fields, chain cross-links).
- `_FIELDS` — the explicit tshark field list (includes `ip.ttl`, `ipv6.hlim`,
  `tcp.analysis.window_full`, `tls.handshake.random`).
- `REDUCE_FILTER`, `_LARGE_CAPTURE_BYTES` gate.
- `run_tshark(pcap, tshark_path, display_filter, keylog_file, reduce)`.
- `build_flows(packets)` — stream grouping; client = SYN sender + port heuristic.
- `run_tunnel_tls` / `merge_tunnel_tls` — 2nd-pass inner-TLS dissection of
  CONNECT tunnels.
- `extract_nrb_hosts`, `extract_capture_env`, `extract_roaming_report`.
- `_to_int` (hex-aware).

## Certificate & DNS intelligence

### `app/certs.py` (~180 lines) — X.509 analysis
- `SECURE_ACCESS_ROOT` (CN/SKI/SHA-256 of the Cisco SA Root CA) for positive
  matching. `_PUBLIC_CA_HINTS`, `_PROXY_CA_HINTS`, `_SECURE_ACCESS_HINTS`.
- `CertInfo` dataclass.
- `parse_cert_hex(hex)` — parse one DER cert; set `looks_like_proxy_ca`,
  `looks_like_public_ca`, `is_secure_access`, `is_secure_access_root`, expiry,
  self-signed, SAN, SKI, fingerprint.
- `analyze_leaf_chain(hexes)` → `(leaf, chain)`.

### `app/certfetch.py` (~58 lines) — Live certificate lookup
- `fetch_certificate(host, port)` — connects out to fetch the current cert
  (diagnostic aid, **kept separate from capture evidence**).

### `app/dns_analysis.py` (~260 lines) — DNS + block-page mapping
- `BLOCK_PAGE_IPV4` / `BLOCK_PAGE_IPV6` — anycast block IPs → category.
- `BLOCK_PAGE_DOMAINS`, `SWG_BLOCK_PAGE_PREFIXES` (`146.112.199.`),
  `SWG_PROXY_HOST_SUFFIXES`, `PUBLIC_DNS_RESOLVERS`, `RCODE_LABELS`.
- `block_category_for_ip`, `is_block_page_domain`, `is_swg_block_ip`,
  `is_swg_proxy_host`, `swg_proxy_org`, `dns_resolver_name`.
- `DnsRecord` dataclass; `analyze_dns(packets)` — build per-name records, tag
  blocks/failures, track SWG-proxy region flapping.

### `app/secure_access.py` (~114 lines) — SA IP/PKI awareness
- Loads published ingress IP list (`data/secure_access_ingress.json`).
- `lookup_ingress_region`, `is_secure_access_ingress`, `describe`.
- `is_private_access` (CGNAT 100.64.0.0/10 ZTNA), `PRIVATE_ACCESS_LABEL`.
- `is_internal_flow` / `_PRIVATE_NETS` — RFC1918/link-local/loopback/ULA/CGNAT.

### `app/tlsconst.py` (~109 lines) — TLS constants
- `HANDSHAKE_TYPES`, alert descriptions (`alert_desc`), version/cipher names.

## Finding detectors (`app/findings/`)

### `base.py` — shared helpers (`Finding` re-export, `_is_loopback_ip`, etc.).
### `interception.py` (~209) — `_ja3s_findings` (JA3S clustering, ≥5 dests) and
`_local_interception_findings` (loopback re-signed cert → local agent; vendor
from issuer; cert-Subject host recovery; ±10 s outbound-leg chain correlation).
### `network.py` (~540) — `_duplicate_capture_findings`,
`_suppress_dup_retransmission_findings`, `_segmentation_offload_findings`,
`_suppress_offload_reordering_findings`, `_network_health_findings`,
`_icmp_pmtud_findings`, `_sa_tunnel_mtu_findings`, `_mss_clamp_findings`,
`_asymmetric_routing_findings`.
### `dns.py` (~152) — `_dns_findings` (NXDOMAIN/SERVFAIL/REFUSED/NODATA,
block-page, region-flap).
### `roaming.py` (~196) — `_roaming_findings`, `_roaming_report_findings`,
`_ingress_health_findings`.
### `steering.py` (~230) — `_steering_coverage_findings` (capture-derived
inspection coverage, per destination, split into web / DNS / Umbrella encrypted
DNS / QUIC). Helpers `_dest_keys` (matches a CONNECT target by IP against the
same host's SNI), `_is_real_session`, `_is_umbrella_resolver`, `_is_multicast`.
### `access.py` (~64) — `_private_access_findings`, `_internal_traffic_findings`.
### `latency.py` (~89) — `_latency_findings_pcap`, `_latency_findings_har`,
`_geo_egress_latency_findings` (SWG egress region from the `Via` header,
corroborated by origin-revealed geography; `_AWS_REGION_GEO`, `_COUNTRY_NAME`).
### `quality.py` (~250) — `_network_quality_findings`: per-destination network
verdict (RTT from `initial_rtt`, RTT variation from `ack_rtt` deviation,
spurious-corrected real loss over data segments, dup-ACK-only reported as
UNCONFIRMED). Emits category `network_info`, which is **not registered** in the
`CLASSIFICATION_*` tables — so these findings never reach the UI.
### `bottleneck.py` (~200) — `_bottleneck_findings` (idle-vs-active time budget,
client/server attribution of each pause, and the dominant-limit verdict:
loss-rate / idle / zero-window / receive-window). Helpers `_conversation_packets`
(excludes background link-layer chatter), `_idle_gaps`, `_who_broke_silence`,
`_real_loss`.
### `proxy_pac.py` (~72) — `_pac_wpad_findings` (PAC/WPAD proxy config signals).
### `har_findings.py` (~204) — `_har_findings`, `_har_proxy_findings`.

## HAR & reporting

### `app/har.py` (~293) — `parse_har`, `HarEntry`, `HarResult`; request-level
truth (status codes, proxy errors, timing).
### `app/report.py` (~222) — text report generation.
### `app/context.py` (~75) — `AnalysisContext`, `AnalysisResult` (shared data
model, kept separate to avoid circular imports).

## Server & UI

### `app/server.py` (~615) — FastAPI app
- `/analyze` endpoint, request handling, JSON serialization.
- `_build_host_inventory(flows)` — per-host rollup (severity-ranked): identity,
  ports + **confirmed-open ports**, transports/protocols, **TTL/hop/OS estimate**
  (`_ttl_profile`), traffic totals, **first/last seen clock**, hostnames.
- `_primary_hostname`, `_ttl_profile`, `_HOST_SEV_RANK`.

### `app/static/` — Browser UI
- `index.html` — sections: Summary, Technical, Flows, Hosts, DNS, Certs; cache
  version markers on `style.css` + `app.js`.
- `app.js` — rendering: `renderHosts`, `renderHostTable`/`hostDetail` (host
  cards with grouped identity/network/crypto/cert/traffic/names), `seenWindow`
  (human-readable first/last seen), `connectionLadder` (per-packet timeline incl.
  interception-chain block), `fmtBytes`, `svgIcon`, `hostIcon`.
- `style.css` — layout incl. the Flows table column sizing.
