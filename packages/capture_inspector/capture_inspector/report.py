"""Render an AnalysisResult into the mandatory report text format."""
from __future__ import annotations

from .analyze import AnalysisResult
from .certs import evaluate_at
from .engine import FlowReport

BAR = "=" * 54


def _flow_block(fr: FlowReport) -> str:
    f = fr.flow
    cert = fr.leaf_cert
    _dns_name = (f.dns_lookup or {}).get("name")
    domain = f.sni or f.connect_target or (
        f"{_dns_name} (DNS)" if _dns_name else (
            f"{f.resolved_host} (NRB)" if f.resolved_host else "(none / encrypted)"))
    lines = [
        f"- Source IP:        {f.src_ip or '?'}:{f.src_port or '?'}",
        f"- Destination IP:   {f.dst_ip or '?'}:{f.dst_port or '?'}",
        f"- Domain/SNI:       {domain}",
        f"- Protocol:         {_protocol(fr)}",
        f"- TLS status:       {fr.tls_status}",
    ]
    if f.is_connect_tunnel:
        proxy_lbl = f.proxy_provider or "explicit proxy"
        lines.insert(2, f"- CONNECT target:   {f.connect_target or '?'}  (via {proxy_lbl} {f.proxy_ip or f.dst_ip or '?'})")
        if f.connect_status:
            lines.insert(3, f"- Tunnel response:  {f.connect_status} {f.connect_phrase or ''}".rstrip())
        if f.tunnel_client_hello or f.tunnel_server_hello:
            hs = "ClientHello+ServerHello" if f.tunnel_server_hello else "ClientHello only"
            sni_txt = f" SNI={f.tunnel_sni}" if f.tunnel_sni else ""
            lines.append(f"- Inner TLS:        {f.tunnel_tls_version or 'TLS'} ({hs}){sni_txt}")
            if f.tunnel_tls_version == "TLS 1.3":
                lines.append("                    (certificate encrypted in TLS 1.3 — not visible to passive capture)")
    elif f.proxy_provider:
        lines.insert(2, f"- Proxy identity:   {f.proxy_provider} [{f.dst_ip or '?'}]")
    if cert and not cert.parse_error:
        issuer = cert.issuer_cn or cert.issuer_org or "?"
        ca_kind = "PROXY/corporate CA" if cert.looks_like_proxy_ca else (
            "public CA" if cert.looks_like_public_ca else "unknown CA")
        window = evaluate_at(cert, f.packets[0].time_epoch if f.packets else None)
        state = {"expired": " | EXPIRED WHEN CAPTURED",
                 "not_yet_valid": " | NOT YET VALID WHEN CAPTURED"}.get(window.status, "")
        lines.append(
            f"- Certificate:      subject={cert.subject_cn or '?'} | issuer={issuer} "
            f"({ca_kind}) | valid {cert.not_before}\u2192{cert.not_after}"
            + state
        )
        if cert.san_dns:
            lines.append(f"                    SAN: {', '.join(cert.san_dns[:8])}"
                         + (" ..." if len(cert.san_dns) > 8 else ""))
    elif f.certificates_hex:
        lines.append("- Certificate:      present but could not be parsed")
    else:
        lines.append("- Certificate:      not observed (TLS 1.3 encrypts it, or none sent)")

    if f.cipher_suite:
        lines.append(f"- Cipher suite:     {f.cipher_suite}")
    if f.alpn:
        lines.append(f"- ALPN:             {', '.join(f.alpn)}")
    if f.offered_versions:
        lines.append(f"- TLS versions:     offered={', '.join(f.offered_versions)} negotiated={f.negotiated_version or '?'}")

    errs = []
    if f.alerts:
        errs += [f"{a['desc']}({a['level']})@pkt{a['packet']}" for a in f.alerts]
    if f.rst_count:
        errs.append(f"TCP RST x{f.rst_count}")
    if f.retransmissions:
        errs.append(f"retransmits x{f.retransmissions}")
    if f.lost_segments:
        errs.append(f"lost-segments x{f.lost_segments}")
    if f.out_of_order:
        errs.append(f"out-of-order x{f.out_of_order}")
    if f.zero_window:
        errs.append(f"zero-window x{f.zero_window}")
    lines.append(f"- Errors detected:  {', '.join(errs) if errs else 'none'}")

    if f.packets:
        lines.append(
            f"- Relevant packets: #{f.packets[0].number}–#{f.packets[-1].number} "
            f"(t={f.packets[0].time_relative:.3f}s → {f.packets[-1].time_relative:.3f}s, {len(f.packets)} pkts)"
        )
    return "\n".join(lines)


def _protocol(fr: FlowReport) -> str:
    f = fr.flow
    if f.is_quic:
        return "QUIC / HTTP3 (UDP/443)"
    parts = [f.transport.upper()]
    if f.client_hello or f.server_hello:
        parts.append("TLS")
    if f.http_requests or f.http_statuses:
        parts.append("HTTP")
    return " / ".join(parts)


def render_report(result: AnalysisResult) -> str:
    ctx = result.context
    out: list[str] = []

    # EXECUTIVE SUMMARY
    out.append(BAR)
    out.append("EXECUTIVE SUMMARY")
    out.append(BAR)
    if result.reduced:
        out.append("! REDUCED ANALYSIS — capture too large to decode in full. Only TLS/DTLS handshakes,")
        out.append("! DNS, QUIC setup, TCP control (SYN/FIN/RST) and ICMP frames were decoded. TLS posture,")
        out.append("! certificates, DNS and connection health are accurate; per-flow byte/packet totals exclude")
        out.append("! bulk payload (HTTP bodies, media) and therefore read low by design.")
        out.append("")
    out.append(f"- Most probable diagnosis: {result.summary_diagnosis}")
    out.append(f"- Confidence level: {result.confidence}")
    if result.primary_evidence:
        out.append("- Primary evidence:")
        for ev in result.primary_evidence:
            out.append(f"    • {ev}")
    else:
        out.append("- Primary evidence: (none — insufficient data)")
    if any([ctx.domain, ctx.platform, ctx.policy, ctx.expected, ctx.actual]):
        out.append("- Provided context:")
        for label, val in [
            ("Domain/App", ctx.domain), ("Platform", ctx.platform),
            ("Decryption policy", ctx.policy), ("Expected", ctx.expected),
            ("Actual", ctx.actual), ("Timestamp", ctx.timestamp),
        ]:
            if val:
                out.append(f"    • {label}: {val}")
    out.append("")

    # CAPTURE ENVIRONMENT (pcapng provenance)
    if result.capture_env:
        env = result.capture_env
        out.append(BAR)
        out.append("CAPTURE ENVIRONMENT")
        out.append(BAR)
        for label, key in [
            ("Sniffer OS", "os"), ("Capture application", "application"),
            ("Capture hardware", "hardware"), ("Interfaces", "interfaces"),
            ("Duration", "duration"),
        ]:
            if env.get(key):
                out.append(f"- {label}: {env[key]}")
        out.append("")

    # TECHNICAL FINDINGS
    out.append(BAR)
    out.append("TECHNICAL FINDINGS")
    out.append(BAR)
    if result.flow_reports:
        # Show flows that have findings first, then the rest (cap to keep readable)
        ranked = sorted(result.flow_reports, key=lambda fr: (0 if fr.findings else 1, -len(fr.flow.packets)))
        shown = ranked[:25]
        for i, fr in enumerate(shown, 1):
            out.append(f"\n[Flow {i}] {fr.flow.key}")
            out.append(_flow_block(fr))
            if fr.findings:
                out.append("  Findings:")
                for fnd in fr.findings:
                    out.append(f"    - ({fnd.severity.upper()}) {fnd.title}: {fnd.detail}")
        if len(ranked) > len(shown):
            out.append(f"\n(+{len(ranked) - len(shown)} additional flows not shown)")
    else:
        out.append("- No PCAP flows analyzed (no capture provided or no TCP/UDP traffic).")

    if result.har:
        out.append("")
        out.append(f"- HAR entries: {len(result.har.entries)} total, {len(result.har.failed)} failed/errored.")
        for e in result.har.failed[:20]:
            tag = e.error_label or f"HTTP {e.status}"
            out.append(f"    • {e.host}  [{tag}]  server_ip={e.server_ip or 'n/a'}  {e.url[:90]}")
    out.append("")

    # ISSUE CLASSIFICATION
    out.append(BAR)
    out.append("ISSUE CLASSIFICATION")
    out.append(BAR)
    for label in result.classifications:
        out.append(f"- [X] {label}")
    out.append("")

    # EVIDENCE
    out.append(BAR)
    out.append("EVIDENCE")
    out.append(BAR)
    findings = result.all_findings
    if findings:
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[x.severity]):
            loc = f" [{f.flow_key}]" if f.flow_key else ""
            out.append(f"- ({f.severity.upper()}){loc} {f.title}")
            for ev in f.evidence:
                out.append(f"      ↳ {ev}")
    else:
        out.append("- No concrete anomalies found in the supplied evidence.")
    if result.correlations:
        out.append("\n  PCAP ↔ HAR correlation:")
        for c in result.correlations[:20]:
            out.append(f"    • {c}")
    if result.notes:
        out.append("\n  Notes / data limitations:")
        for n in result.notes:
            out.append(f"    • {n}")
    out.append("")

    # RECOMMENDATIONS
    out.append(BAR)
    out.append("RECOMMENDATIONS")
    out.append(BAR)
    for rec in _recommendations(result):
        out.append(f"- {rec}")
    out.append("")

    return "\n".join(out)


def _recommendations(result: AnalysisResult) -> list[str]:
    cats = {f.category for f in result.all_findings}
    recs: list[str] = []
    has_quic = any(fr.flow.is_quic for fr in result.flow_reports)

    if "pinning_signal" in cats or "interception" in cats:
        recs.append("Configure an SSL decryption BYPASS for the affected FQDN(s)/domains — pinned apps cannot be re-signed.")
        recs.append("Ensure bypass/do-not-decrypt rules are evaluated BEFORE decryption policies (rule ordering).")
        recs.append("Compare direct (uninspected) access vs inspected access to the same destination to confirm pinning behavior.")
    if "cert_trust" in cats:
        recs.append("Deploy/trust the corporate proxy CA in the endpoint OS/browser trust store; verify the full chain is pushed.")
        recs.append("Validate the endpoint trust store actually contains the SWG root (apps using their own store need separate handling).")
    if "public_cert" in cats:
        recs.append("Validate the public certificate with: openssl s_client -connect <host>:443 -servername <host> (check dates, CN/SAN, chain).")
    if "tls_version" in cats:
        recs.append("Align TLS version/cipher policy between endpoint and proxy; avoid forcing deprecated TLS 1.0/1.1.")
    if has_quic or "quic" in cats:
        recs.append("Temporarily disable/block QUIC (UDP/443) to force TCP/443 and validate decryption or bypass behavior.")
    if "proxy" in cats:
        recs.append("Review Proxy/Firewall/SWG logs for the URL category, reputation block, or proxy-auth (407) cause.")
        recs.append("Verify SSL-bypass rules correctly match the destination, including wildcard, CDN and SNI-based domains.")
    if "network" in cats:
        recs.append("Investigate path MTU / MSS clamping and packet loss; test with reduced MSS to rule out an MTU blackhole.")
    if "dns" in cats:
        recs.append("Resolve the DNS failure first (name resolution) before attributing the issue to TLS.")

    # Always-useful baseline actions
    recs.append("Capture traffic on BOTH sides of the proxy (client↔proxy and proxy↔server) for a complete picture when possible.")
    recs.append("Anchor analysis to the exact failure timestamp to correlate DNS → TCP → TLS → proxy → HTTP layers.")
    if not result.flow_reports:
        recs.append("Provide a PCAP/PCAPNG capture — HAR alone cannot reveal TLS handshakes, certificates or alerts.")
    return recs
