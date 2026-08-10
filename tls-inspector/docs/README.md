# Capture Inspector — Technical Documentation

Capture Inspector is a 100%-local FastAPI application that analyzes Wireshark
(**PCAP/PCAPNG**) captures and browser (**HAR**) logs to diagnose TLS
decryption, certificates, DNS, proxy/SWG and SASE behavior. It is
**vendor-agnostic by default** and enables **Cisco Secure Access**-specific
intelligence only when the operator opts in.

The engine is **evidence-based**: every finding carries the packet numbers,
timestamps and values it was derived from. Nothing is invented. Where the wire
does not contain enough information, the tool says so instead of guessing.

## Documentation map

| Document | Purpose |
|---|---|
| [HANDOFF.md](HANDOFF.md) | **Start here when taking the project over or merging it into another app.** What the system does, how each detection works, the traps that cause silent breakage, and the known gaps. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System layout, the end-to-end analysis pipeline, and the data model. |
| [DETECTION.md](DETECTION.md) | The full detection catalog: **what** we detect, **how** we detect it, and — just as important — **what we do NOT / cannot detect** and why. |
| [MODULES.md](MODULES.md) | Module-by-module reference for every source file and its responsibilities. |
| [PATENT_DISCLOSURE.md](PATENT_DISCLOSURE.md) | Cisco-style invention disclosure identifying the novel, potentially patentable mechanisms and their prior-art context. |
| [../CHANGELOG.md](../CHANGELOG.md) | Dated record of fixes, new detections and the evidence each change was validated against. |

## One-paragraph summary

The operator uploads a PCAP and/or HAR (plus optional context and an optional
TLS key log). The PCAP is decoded with `tshark` into a normalized packet
stream, grouped into bidirectional **flows**, and enriched with TLS/TCP/QUIC/HTTP
facts. A layered set of **finding detectors** then classifies TLS interception,
certificate problems, certificate pinning, proxy/SWG blocks, DNS failures,
network/MTU issues, latency, roaming-agent behavior, Zero-Trust/Private-Access
tunnels and more. Findings are correlated (DNS↔flow, HAR↔flow, block-page↔real
domain), de-duplicated, false-positive-guarded, then summarized into both a
**technical** breakdown and a **plain-language** executive narrative.

## Honesty principles baked into the product

- **Evidence or nothing.** A finding must cite on-wire evidence.
- **Say what we cannot see.** Encrypted DLP verdicts, QUIC, TLS 1.3 certs
  without a key log, and asymmetric captures are explicitly flagged as blind
  spots rather than silently omitted (see [DETECTION.md](DETECTION.md) §
  "Limitations").
- **Estimates are labeled.** TTL-based OS/hop guesses carry an `(est.)` tag.
- **Vendor-neutral unless told otherwise.** Vendor naming is opt-in.
