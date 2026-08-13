"""Analysis orchestrator: runs PCAP + HAR engines, correlates, classifies."""
from __future__ import annotations

import os
import re
from collections import Counter
from typing import Optional

from .engine import Finding, FlowReport, analyze_flow, enrich_flow
from .dns_analysis import (
    DnsRecord, analyze_dns, dns_summary, is_block_page_domain, dns_resolver_name,
)
from .har import HarEntry, HarResult, parse_har
from .pcap import _FIELDS, Flow, build_flows, find_tshark, run_tshark, run_tunnel_tls, merge_tunnel_tls, extract_nrb_hosts, extract_capture_env, extract_roaming_report, unsupported_fields
from .context import AnalysisContext, AnalysisResult
from .findings.dns import _dns_findings
from .findings.roaming import _roaming_findings, _roaming_report_findings, _ingress_health_findings
from .findings.network import (
    _duplicate_capture_findings, _suppress_dup_retransmission_findings, _network_health_findings,
    _segmentation_offload_findings, _suppress_offload_reordering_findings,
    _icmp_pmtud_findings, _sa_tunnel_mtu_findings, _mss_clamp_findings, _asymmetric_routing_findings,
)
from .findings.quality import _network_quality_findings
from .findings.access import _private_access_findings, _internal_traffic_findings
from .findings.latency import _latency_findings_har, _latency_findings_pcap, _geo_egress_latency_findings
from .findings.bottleneck import _bottleneck_findings
from .findings.opaque import _capture_ruled_out, _opaque_tunnel_findings
from .findings.steering import _steering_coverage_findings
from .findings.interception import _ja3s_findings, _local_interception_findings
from .findings.proxy_pac import _pac_wpad_findings
from .findings.har_findings import _har_findings, _har_proxy_findings


# Captures larger than this are decoded in REDUCED mode (handshake/control/DNS
# frames only) so multi-hundred-MB files don't exhaust memory. See pcap.REDUCE_FILTER.
_LARGE_CAPTURE_BYTES = 80 * 1024 * 1024  # 80 MB


# Maps internal categories to the user-facing ISSUE CLASSIFICATION buckets.
CLASSIFICATION_LABELS = {
    "interception": "SSL decryption active (traffic intercepted)",
    "local_interception": "Local TLS interception on this device (endpoint agent)",
    "cert_trust": "Corporate CA not trusted",
    "pinning_signal": "Probable certificate pinning",
    "public_cert": "Public certificate issue",
    "tls_version": "TLS/cipher mismatch",
    "tls_handshake": "SSL decryption incompatibility",
    "tls_alert": "SSL decryption incompatibility",
    "quic": "QUIC/HTTP3 interference",
    "proxy": "Proxy/SWG blocking traffic",
    "swg_coverage": "Secure Access traffic steering",
    "swg_coverage_info": "What was inspected, and what could not be",
    "tunnel": "Explicit-proxy tunnel (HTTPS not decrypted)",
    "network": "TCP/MTU network issue",
    "dns": "DNS issue",
    "latency": "Slow performance / high latency",
    "roaming": "Secure Client Roaming module active (local interception)",
    "private_access": "Secure Access Private Access (Zero Trust / ZTNA)",
    "asymmetric_routing": "Asymmetric routing / one-armed capture",
    "internal_traffic": "Internal traffic (private \u2192 private, not SIA)",
}

# Why each category is flagged — shown in the Technical summary so the reader
# understands the reasoning, not just the label.
CLASSIFICATION_WHY = {
    "interception": (
        "A corporate/proxy CA re-signed the server certificates. That re-signing only "
        "happens when the SWG actively decrypts (man-in-the-middles) the TLS session."
    ),
    "local_interception": (
        "A TLS connection on loopback (127.0.0.1 / ::1) presented a re-signed certificate. "
        "Both ends of a loopback flow are the SAME machine, so an interception agent running "
        "ON THIS DEVICE is terminating and decrypting TLS before the traffic leaves the host. "
        "This is vendor-agnostic endpoint evidence — a SASE/SWG roaming client, an antivirus "
        "web-shield, or any local MITM proxy — and it can reveal inspection agents from other "
        "vendors that a passive in-path view would miss."
    ),
    "cert_trust": (
        "The endpoint was handed a certificate signed by a CA it does not trust "
        "(unknown_ca / ERR_CERT_AUTHORITY_INVALID), so it aborts the handshake. The "
        "proxy root CA is missing from the device trust store."
    ),
    "pinning_signal": (
        "The client tore down the connection (TCP RST / handshake abort) right after "
        "receiving a re-signed certificate. That is the classic signature of an app that "
        "pins the original certificate and refuses any substitute presented by the SWG."
    ),
    "public_cert": (
        "The server's own certificate has a problem — expired, name mismatch or a broken "
        "chain. This is a fault of the destination itself, independent of any inspection."
    ),
    "tls_version": (
        "The client and the server (or the inspection proxy) share no common TLS "
        "version/cipher, so they cannot agree on how to secure the session."
    ),
    "tls_handshake": (
        "The TLS handshake failed or a fatal alert was raised. Typically the inspection "
        "proxy and the endpoint disagree on handshake parameters (handshake_failure, "
        "protocol_version, unsupported extension)."
    ),
    "tls_alert": (
        "A fatal TLS alert was sent during setup, aborting the session before data could "
        "flow — usually a decryption/parameter incompatibility between the two sides."
    ),
    "quic": (
        "Traffic used QUIC (UDP/443). The TCP-based inspection never sees it, so this "
        "traffic bypasses TLS decryption and logging entirely."
    ),
    "proxy": (
        "The proxy/SWG returned an error or block (4xx/5xx, 407 proxy-auth, category or "
        "reputation block) before the request ever reached the origin server."
    ),
    "swg_coverage": (
        "This describes whether the device's HTTPS traffic is actually being routed through a "
        "Cisco Secure Access SWG ingress. Full coverage means every flow is steered through the "
        "SWG as intended; partial or zero coverage means some or all traffic is going DIRECT and "
        "escaping SWG policy, URL filtering and decryption."
    ),
    "swg_coverage_info": (
        "The full breakdown behind the coverage figures: every category the capture was split "
        "into, including the traffic deliberately left out of the percentages and the reason for "
        "each exclusion. It is here so the numbers can be checked rather than taken on trust — "
        "without it you cannot see what went into the denominator."
    ),
    "tunnel": (
        "Traffic went through an opaque HTTP CONNECT tunnel, so the payload was not "
        "decrypted and the inner certificate is invisible to passive capture."
    ),
    "network": (
        "Packet loss, resets or an MTU/MSS problem broke the connection at the network "
        "layer in a way that can masquerade as a TLS failure."
    ),
    "dns": (
        "Name resolution failed or was redirected (NXDOMAIN / SERVFAIL / Secure Access "
        "block page) before any TLS handshake could even start."
    ),
    "latency": (
        "Requests were slow: a timing phase (DNS, TCP connect, TLS handshake or server "
        "think-time/TTFB) took noticeably longer than expected. When a SWG re-terminates "
        "TLS, the extra hop and re-encryption show up as inflated connect/SSL/TTFB times."
    ),
    "roaming": (
        "Traffic was seen going to the loopback address (127.0.0.1) on the DNS/web ports "
        "(53, 80, 443, or the roaming client's DNS listener on 5002). The Cisco Secure Client "
        "Roaming Security module installs a local listener on loopback and redirects the device's "
        "DNS (and sometimes HTTP/HTTPS) through it, so it can apply Umbrella/Secure Access policy "
        "on- and off-network. Seeing this confirms the roaming agent is installed and steering "
        "traffic locally."
    ),
    "private_access": (
        "One endpoint is in the 100.64.0.0/10 CGNAT pool (RFC 6598) that Cisco Secure Access "
        "uses for client-based Zero Trust / Private Access (ZTNA). This is the Zero Trust proxy "
        "(ZPC) path to a private resource — it tunnels arbitrary protocols/ports, so it is NOT "
        "SWG/web traffic and TLS-decryption, web-policy and certificate-pinning verdicts do not "
        "apply to these flows."
    ),
    "asymmetric_routing": (
        "The capture acknowledges TCP data it never recorded being sent (or sees a connection in "
        "only one direction). The two directions of the connection are taking different paths, so "
        "this capture point only observes one of them — retransmission/loss counts on such flows "
        "are partly a capture artefact, not necessarily real network loss."
    ),
    "internal_traffic": (
        "Both endpoints are private/internal addresses (RFC 1918, link-local, loopback or IPv6 ULA), "
        "so the connection is private\u2192private LAN traffic. The Secure Access roaming agent only "
        "steers INTERNET-bound traffic through the SWG (SIA), so this traffic never passes through "
        "the proxy — TLS-decryption, web-policy and certificate-pinning verdicts do not apply."
    ),
}

# A concrete, real-world example of each error so a non-expert can picture it.
# Shown under the "why" so the reader can map the abstract category to something tangible.
CLASSIFICATION_EXAMPLE = {
    "interception": (
        "Example: you open https://www.google.com and the padlock shows the certificate was "
        "issued by \"Cisco Secure Access\" instead of \"Google Trust Services\" — the proxy "
        "opened the envelope, read it, and re-sealed it with its own stamp."
    ),
    "local_interception": (
        "Example: a program on your laptop connects to 127.0.0.1 and gets a certificate signed "
        "by \"Cisco Secure Access\" (or Zscaler, Netskope, an antivirus, mitmproxy…) — an agent "
        "installed on the machine is opening the traffic locally before it ever hits the network, "
        "like a mailroom that steams open every letter on your own desk."
    ),
    "cert_trust": (
        "Example: the browser shows \"Your connection is not private — NET::ERR_CERT_"
        "AUTHORITY_INVALID\" because the proxy's root certificate was never installed on this "
        "laptop, so the device doesn't recognise who signed the page."
    ),
    "pinning_signal": (
        "Example: the Microsoft Teams or banking app spins and then says \"can't connect\", "
        "while the same site works fine in the browser — the app was built to accept only its "
        "original certificate and rejects the proxy's substitute."
    ),
    "public_cert": (
        "Example: visiting https://expired.badssl.com shows \"certificate has expired\" — the "
        "fault is on the website itself, not on your network or the proxy."
    ),
    "tls_version": (
        "Example: an old payment terminal only speaks TLS 1.0, but the server now requires "
        "TLS 1.2+, so they hang up on each other — like two people with no language in common."
    ),
    "tls_handshake": (
        "Example: the connection drops during the initial \"hello\" with a handshake_failure "
        "alert — the two sides couldn't agree on the security parameters before any page loaded."
    ),
    "tls_alert": (
        "Example: right after starting, one side sends a fatal alert and slams the door — the "
        "browser shows \"connection reset\" before the website ever appears."
    ),
    "quic": (
        "Example: Chrome loads YouTube over QUIC (UDP/443), so the inspection proxy never sees "
        "that traffic — it's like mail going through a side door the security desk doesn't watch."
    ),
    "proxy": (
        "Example: instead of the real site you get a Cisco Secure Access block page saying "
        "\"This site is blocked by your organization\" (or a 403/407 error) — the proxy stopped "
        "the request before it left the building."
    ),
    "swg_coverage": (
        "Example: like a building where everyone is supposed to enter through the guarded front "
        "desk — full coverage means every visitor was checked in there; a bypass means someone "
        "slipped in through a side door without being checked."
    ),
    "swg_coverage_info": (
        "Example: the itemised receipt behind a total — it shows which lines were counted, which "
        "were set aside, and why, so you can verify the total instead of believing it."
    ),
    "tunnel": (
        "Example: the browser used HTTP CONNECT to tunnel HTTPS through the proxy, so the "
        "capture only shows an opaque pipe — like a sealed courier bag the camera can't see into."
    ),
    "network": (
        "Example: lots of retransmissions and resets, or an oversized packet that never fits "
        "through — the call keeps dropping because the line itself is bad, not the security."
    ),
    "dns": (
        "Example: typing the address returns \"server not found\" (NXDOMAIN) or silently lands "
        "on a Secure Access block page — the phone book gave the wrong number before dialling."
    ),
    "latency": (
        "Example: a page takes 4-5 seconds to start loading; the breakdown shows most of it was "
        "the TLS handshake and time-to-first-byte — like a parcel that spends most of its trip "
        "waiting at an extra checkpoint rather than in transit."
    ),
    "roaming": (
        "Example: every DNS lookup goes to 127.0.0.1:53 instead of your normal resolver — the "
        "Secure Client roaming agent is answering locally, like an in-house receptionist who "
        "intercepts every call before it leaves the building and applies company policy."
    ),
    "private_access": (
        "Example: a laptop reaches an internal app (e.g. 10.1.21.220) and the server sees the "
        "client as 100.105.44.4 — that 100.64/10 address is the Zero Trust proxy NATting the "
        "session, the same way a VPN concentrator hands out an internal pool address."
    ),
    "asymmetric_routing": (
        "Example: the capture shows the client ACKing page bytes 1–40000, but only bytes 1–20000 "
        "were ever seen on the wire — the rest came back on a different link the sniffer isn't on, "
        "like watching only the outbound lane of a divided highway."
    ),
    "internal_traffic": (
        "Example: a workstation (10.2.111.15) talks to an internal monitoring server (10.1.21.220) — "
        "both are inside the corporate LAN, so the traffic never leaves the building or reaches the "
        "Secure Access cloud proxy; any reset there is between the two internal hosts, not the SWG."
    ),
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# Concrete, actionable remediation steps per category. Ordered most-likely-fix
# first. Steps prefixed "Secure Access:" are Cisco SA-specific; the rest are
# vendor-agnostic and apply to any SWG/proxy. Kept honest: these are the standard
# levers to pull, NOT a guarantee — the capture shows symptoms, not root cause.
CLASSIFICATION_REMEDIATION = {
    "interception": [
        "Confirm this decryption is intended policy. If the destination should NOT be inspected (banking, health, or apps that pin), add it to the TLS decryption bypass / do-not-decrypt list.",
        "Ensure the proxy/SWG root CA is deployed to every client trust store (OS + browser + Java/NSS + app-specific stores) so re-signed certs are trusted.",
        "Secure Access: check the HTTPS Inspection policy — add the domain/category to 'Do Not Decrypt' if the app breaks under inspection.",
    ],
    "local_interception": [
        "This is an on-device inspection agent, not a network problem. Identify the agent from the certificate issuer (Cisco Secure Client, Zscaler ZCC, Netskope, AV web-shield, mitmproxy…).",
        "If it is unexpected, audit installed security software / browser extensions on the endpoint — a local MITM proxy re-signs TLS before it leaves the machine.",
        "For pinned apps that break, exclude them from the local agent's inspection scope.",
    ],
    "cert_trust": [
        "Install the proxy/SWG root CA into the failing endpoint's trust store — this is the direct fix for unknown_ca / ERR_CERT_AUTHORITY_INVALID.",
        "Verify the CA reaches every store the app uses: Windows/macOS system store, Firefox/NSS, Java cacerts, Node/Python cert bundles, and mobile MDM profiles.",
        "Confirm the CA is within its validity window and the full intermediate chain is being sent.",
    ],
    "pinning_signal": [
        "Do NOT decrypt pinned apps — add the destination to the TLS decryption bypass list; pinning cannot be satisfied by a re-signed cert.",
        "Identify the pinned app/host from the RST-after-certificate flow and bypass just that hostname/SNI to keep inspection everywhere else.",
        "Secure Access: add the host/category to 'Do Not Decrypt'. Common pinned apps: Teams, banking, Dropbox, some mobile SDKs.",
    ],
    "public_cert": [
        "This is a fault on the destination server, not your network — the site is serving an expired, name-mismatched or incomplete-chain certificate.",
        "Confirm by opening the site with inspection bypassed; if it still fails, the origin must fix/renew its certificate.",
        "If only the chain is incomplete, the server needs to send the missing intermediate(s).",
    ],
    "tls_version": [
        "Align the TLS version/cipher policy: the client and server (or the inspecting proxy) share no common protocol.",
        "Update the older side (legacy client or server) to support TLS 1.2+; or, if the proxy's cipher policy is too strict for a legacy origin, relax it for that destination.",
        "Secure Access: review the TLS version floor in the decryption policy against the destination's supported versions.",
    ],
    "tls_handshake": [
        "The handshake aborted (fatal alert / parameter mismatch). Capture with an SSLKEYLOGFILE to see the exact alert and negotiated parameters.",
        "Check for an unsupported extension or protocol-version mismatch between the endpoint and the inspecting proxy.",
        "If it only fails under inspection, bypass the destination to confirm the proxy is the incompatible party.",
    ],
    "tls_alert": [
        "Read the specific alert (decrypt_error, bad_certificate, protocol_version, certificate_required…) — it names the incompatibility.",
        "certificate_required usually means the origin wants a client certificate the proxy is not forwarding — bypass decryption for that host or configure client-cert passthrough.",
        "For decrypt_error/handshake_failure, treat as a version/cipher/extension mismatch and align policy.",
    ],
    "quic": [
        "QUIC (UDP/443) bypasses TCP-based TLS inspection and logging. To force inspection, block UDP/443 outbound so clients fall back to TCP/TLS over HTTP/2.",
        "Secure Access: enable the QUIC/HTTP3 control (block or steer UDP/443) so this traffic is not invisible to policy.",
        "If QUIC is intentionally allowed, accept that these flows are not decrypted or URL-logged.",
    ],
    "proxy": [
        "The proxy/SWG returned a block or error (4xx/5xx, 407, category/reputation block) before reaching the origin. Read the block reason/category.",
        "If wrongly blocked, adjust the web/URL-filtering policy or add an allow/exception for the destination.",
        "407 = proxy authentication required: fix the client's proxy credentials / auth method.",
    ],
    "swg_coverage": [
        "Partial or zero coverage means some traffic goes DIRECT, escaping policy. Verify the roaming client / PAC / tunnel is installed and steering on the affected endpoints.",
        "Secure Access: confirm the device is registered and the traffic-steering profile routes the intended ports/domains through the SWG ingress.",
        "Check for split-tunnel or local-domain exceptions that are letting traffic bypass the SWG.",
    ],
    "swg_coverage_info": [
        "Nothing to fix here — this is the arithmetic behind the coverage percentages.",
        "Use it to sanity-check them: if a category you expected to be inspected appears under the exclusions, that is the thing worth chasing.",
    ],
    "tunnel": [
        "Traffic used an opaque HTTP CONNECT tunnel, so the payload is not decrypted. If you need visibility, enable TLS decryption for the tunneled destination.",
        "Provide an SSLKEYLOGFILE to this tool to reveal the inner TLS handshake and certificate.",
    ],
    "network": [
        "Address the transport-layer problem (loss, resets, MTU/MSS) — it can masquerade as a TLS failure.",
        "For MTU/PMTUD black holes: clamp TCP MSS on the tunnel/edge, or lower the client MTU; ensure ICMP 'fragmentation needed' is not filtered.",
        "For heavy retransmissions/resets on one path, check for a firewall idle-timeout or an unstable hop before blaming TLS.",
    ],
    "dns": [
        "Resolution failed or was redirected before any TLS could start. Distinguish a real NXDOMAIN/SERVFAIL from a policy block page.",
        "If it's a block, adjust the DNS-layer policy/category or add an exception for the domain.",
        "Verify the client is using the intended resolver (roaming DNS listener vs corporate DNS vs public) and that split-DNS is correct for internal names.",
    ],
    "latency": [
        "Identify which phase is slow (DNS, TCP connect, TLS handshake, or server TTFB) — the fix differs per phase.",
        "Inflated TLS/connect times often come from the extra SWG re-termination hop or a distant ingress region; verify the client lands on the nearest ingress.",
        "High TTFB with fast connect points at the origin/app, not the network or proxy.",
    ],
    "roaming": [
        "Informational — the Secure Client roaming agent is installed and steering DNS/web locally. No fix needed unless steering is unintended.",
        "If local interception is unwanted on this endpoint, adjust the roaming/steering profile or uninstall the module.",
    ],
    "private_access": [
        "Informational — this is ZTNA / Private Access (100.64.0.0/10). TLS-decryption and web-policy verdicts do not apply to these tunneled flows.",
        "If a private app is unreachable, troubleshoot the ZTNA app definition, posture and connector reachability rather than SWG/TLS policy.",
    ],
    "asymmetric_routing": [
        "Capture artifact, not necessarily a real fault — this vantage point sees only one direction. Retransmission/loss counts here are unreliable.",
        "Re-capture at a symmetric point (both directions), or on the client itself, to get accurate flow health.",
    ],
    "internal_traffic": [
        "Informational — private\u2192private LAN traffic that never traverses the SWG. TLS-decryption and web-policy verdicts do not apply.",
        "If this flow has a problem, troubleshoot it as internal network/app connectivity, not as a Secure Access inspection issue.",
    ],
}



def _correlate_dns_to_flows(flows: list[Flow], records: list[DnsRecord]) -> None:
    """Attach to each flow the DNS lookup (seen earlier in the same capture) that
    resolved to its destination IP. When several names map to one IP (CDN/shared
    hosting) pick the lookup answered most recently BEFORE the connection started.
    Also backfills resolved_host so IP-only flows display the requested hostname."""
    by_ip: dict[str, list[DnsRecord]] = {}
    for rec in records:
        for ip in rec.addresses:
            by_ip.setdefault(ip, []).append(rec)
    if not by_ip:
        return

    for flow in flows:
        cands = by_ip.get(flow.dst_ip)
        if not cands:
            continue
        flow_start = flow.packets[0].time_relative if flow.packets else 0.0
        # Prefer the lookup answered just before the connection; fall back to the
        # earliest known lookup if none precedes it (clock skew / partial capture).
        best: Optional[DnsRecord] = None
        best_gap: Optional[float] = None
        for rec in cands:
            gap = flow_start - rec.first_seen
            if gap >= -1.0:  # answered before the flow (allow 1s skew)
                if best_gap is None or gap < best_gap:
                    best, best_gap = rec, gap
        if best is None:
            best = min(cands, key=lambda r: r.first_seen)

        flow.dns_lookup = {
            "name": best.name,
            "cnames": best.cnames,
            "addresses": best.addresses,
            "resolver": best.resolver,
            "resolver_name": dns_resolver_name(best.resolver),
            "query_time": best.first_seen,
            "response_time": best.response_time,
            "rcode": best.rcode,
            "blocked": best.blocked,
            "block_category": best.block_category,
        }
        if not flow.resolved_host:
            flow.resolved_host = best.name


def _matches_context(flow: Flow, ctx: AnalysisContext) -> bool:
    if ctx.domain and flow.sni:
        if ctx.domain.lower() not in flow.sni.lower():
            return False
    if ctx.src_ip and flow.src_ip and ctx.src_ip != flow.src_ip:
        return False
    if ctx.dst_ip and flow.dst_ip and ctx.dst_ip != flow.dst_ip:
        return False
    return True


def analyze(pcap_path: Optional[str], har_text: Optional[str], ctx: AnalysisContext,
            keylog_path: Optional[str] = None) -> AnalysisResult:
    result = AnalysisResult(context=ctx)

    # --- PCAP ---
    if pcap_path:
        if not find_tshark():
            result.notes.append("tshark not found — PCAP analysis skipped. Install Wireshark.")
        else:
            # Very large captures would produce gigabytes of tshark JSON and blow
            # up memory. Above ~80 MB we switch to a REDUCED decode that keeps only
            # handshake/control/DNS frames — the diagnostic signal survives, bulk
            # payload (HTTP bodies, media) is skipped.
            try:
                _size = os.path.getsize(pcap_path)
            except OSError:
                _size = 0
            reduce = _size > _LARGE_CAPTURE_BYTES
            result.reduced = reduce
            packets = run_tshark(pcap_path, keylog_file=keylog_path, reduce=reduce)
            # A field this Wireshark does not know is dropped rather than being
            # allowed to fail the whole run, but the detectors that depended on
            # it then cannot fire. Say so, so their silence is not read as a
            # clean result.
            _missing = unsupported_fields(find_tshark() or "", _FIELDS)
            if _missing:
                _note = (
                    "This Wireshark build does not provide " + ", ".join(sorted(_missing))
                    + ". Those fields were skipped so the rest of the capture could still "
                    "be analysed, but any check reading them did not run."
                )
                if any(f.endswith((".ja3", ".ja3s")) for f in _missing):
                    _note += (
                        " That means TLS fingerprinting, and with it the JA3S clustering "
                        "check for a shared TLS terminator, produced nothing here - absence "
                        "of that finding is not evidence there is no interception. JA3 "
                        "arrived in Wireshark 3.6."
                    )
                result.notes.append(_note)
            if reduce:
                result.notes.append(
                    f"Large capture ({_size // (1024 * 1024)} MB): analysed in REDUCED mode — only TLS/DTLS "
                    "handshakes, DNS, QUIC setup and TCP control (SYN/FIN/RST) and ICMP frames were decoded. "
                    "TLS posture, certificates, DNS and connection health are fully accurate; per-flow byte/packet "
                    "totals exclude bulk payload (HTTP bodies, media), so they read low by design."
                )
            flows = build_flows(packets)
            # PcapNG Name Resolution Block: IP->hostname map baked into the file
            # (lets us name encrypted/QUIC peers with no on-wire SNI/DNS).
            nrb_hosts = extract_nrb_hosts(pcap_path)
            result.capture_env = extract_capture_env(pcap_path)
            # Cisco Secure Client / Umbrella roaming module self-report (STARTMSG
            # on loopback IPC): the SWG proxy + org and steered/bypassed counters,
            # in clear. Independent of REDUCE_FILTER (its own targeted tshark pass).
            result.roaming_report = extract_roaming_report(pcap_path)
            corp_ca: Counter = Counter()
            # DNS layer: block-page mapping + resolution health.
            result.dns_records = analyze_dns(packets)
            result.dns_findings = _dns_findings(result.dns_records, ctx.secure_access_mode)
            for flow in flows:
                enrich_flow(flow)
                if nrb_hosts:
                    flow.resolved_host = nrb_hosts.get(flow.dst_ip) or nrb_hosts.get(flow.src_ip)
            # Tie each IP-only connection back to the DNS lookup that produced its
            # destination IP (the hostname the client actually requested).
            _correlate_dns_to_flows(flows, result.dns_records)
            # Proxy auto-config (PAC/WPAD) health — needs DNS + enriched HTTP.
            result.dns_findings.extend(_pac_wpad_findings(result.dns_records, flows))
            # Second pass: dissect TLS carried inside HTTP CONNECT tunnels and
            # merge the inner SNI/version/handshake onto the flows. With a keylog
            # file this also decrypts TLS 1.3 and reveals the inner certificate.
            if any(f.is_connect_tunnel for f in flows):
                merge_tunnel_tls(flows, run_tunnel_tls(pcap_path, keylog_file=keylog_path))
            if keylog_path:
                result.notes.append("TLS key log supplied — TLS 1.3 sessions decrypted where keys matched; "
                                    "inner certificates are shown when available.")
            # Filter to context if provided and matches exist
            relevant = [f for f in flows if _matches_context(f, ctx)]
            target_flows = relevant if (ctx.domain or ctx.src_ip or ctx.dst_ip) and relevant else flows
            for flow in target_flows:
                result.flow_reports.append(analyze_flow(flow, corp_ca, ctx.secure_access_mode))
            result.corporate_ca_orgs = corp_ca
            # --- Cisco Secure Access-specific intelligence (opt-in) ------------
            # OFF by default: these functions name the vendor / rely on SA IP and
            # PKI data, so they only run when the user confirmed they use Secure
            # Access. In agnostic mode they are skipped entirely (suppressed).
            if ctx.secure_access_mode:
                result.dns_findings.extend(_ingress_health_findings(target_flows, ctx.sa_tunnel))
                # Capture-derived steering coverage: what could have been
                # inspected versus what actually was, counted per destination and
                # split by category (web / DNS / Umbrella's encrypted DNS / QUIC)
                # instead of trusting the agent's own opaque totals.
                result.dns_findings.extend(_steering_coverage_findings(
                    target_flows, packets, sa_tunnel=ctx.sa_tunnel,
                    stats_out=result.steering_coverage))
                # Cisco Secure Client Roaming module: loopback DNS/web interception
                # is a device-wide behaviour, so scan all flows (not context-filtered).
                result.dns_findings.extend(_roaming_findings(flows, result.dns_records))
                # Roaming module self-report (STARTMSG): SWG proxy/org + steered vs
                # bypassed web-connection counters, read in clear from loopback IPC.
                result.dns_findings.extend(_roaming_report_findings(result.roaming_report))
            # JA3S clustering: one server-side fingerprint fronting many distinct
            # destinations = a single TLS terminator (proxy/SWG) re-encrypting
            # everything. Vendor-agnostic, so it always runs.
            result.signal_findings.extend(_ja3s_findings(target_flows))
            # Local interception agent: a loopback TLS flow with a re-signed cert
            # proves an on-device agent decrypting TLS (any vendor). Names the
            # vendor from the cert issuer + correlates the probable outbound leg.
            # Vendor-agnostic, always runs; needs flow_reports (for the cert).
            result.signal_findings.extend(_local_interception_findings(result.flow_reports))
            # Latency: slow TCP/TLS setup measured on the wire.
            result.signal_findings.extend(_latency_findings_pcap(target_flows))
            # Duplicate / multi-interface capture: the same packets recorded on
            # 2+ interfaces inflate retransmission counts. Detect it first so the
            # packet-loss finding below can be suppressed when it is just an
            # artifact.
            dup_findings, is_dup_capture = _duplicate_capture_findings(packets)
            result.signal_findings.extend(dup_findings)
            # When the capture is duplicated, the per-flow retransmission findings
            # produced by analyze_flow are also inflated artifacts — strip the ones
            # with no genuine loss behind them so they don't flood the report.
            if is_dup_capture:
                _suppress_dup_retransmission_findings(result.flow_reports)
            # Host-side capture with TCP segmentation offload still pending: the
            # recorded super-segments make the dissector report reordering that
            # never happened on the wire. Same treatment as a duplicate capture —
            # name the capture point, then strip the artifact-only loss findings.
            off_findings, is_offloaded = _segmentation_offload_findings(target_flows)
            result.signal_findings.extend(off_findings)
            if is_offloaded:
                _suppress_offload_reordering_findings(result.flow_reports)
            # Where the elapsed time actually went, and which mechanism (if any)
            # was the constraint. Must run AFTER the capture-quality flags above,
            # because it withholds the congestion verdict when those say the loss
            # counters cannot be trusted.
            result.signal_findings.extend(_bottleneck_findings(
                target_flows, packets, unreliable_loss=is_dup_capture or is_offloaded))
            # TCP transport health: packet loss / retransmissions aggregated
            # across all flows (independent of TLS/SWG policy).
            result.signal_findings.extend(_network_health_findings(
                target_flows, duplicate_capture=is_dup_capture, offloaded_capture=is_offloaded))
            # Per-destination network-quality verdict (RTT, RTT variation/jitter,
            # spurious-corrected real loss, dup-ACK-only reverse-path). Suppressed
            # on duplicate/multi-interface captures where loss counts are inflated.
            if not is_dup_capture:
                result.signal_findings.extend(_network_quality_findings(target_flows))
            # ICMP Path MTU Discovery: report any "fragmentation needed" errors
            # and the next-hop MTU they carry (RFC 1191) — proves PMTUD works and
            # reveals the tunnel's reduced MTU. Scans all packets, not just flows.
            result.signal_findings.extend(_icmp_pmtud_findings(packets))
            # Tunnels that were established, returned almost nothing and were
            # abandoned. The cause is inside the TLS and cannot be read, so this
            # reports the pattern and hands over what the capture DID rule out —
            # which is why it runs after the loss/latency/MTU checks above.
            result.signal_findings.extend(_opaque_tunnel_findings(
                target_flows, _capture_ruled_out(target_flows, is_dup_capture),
                result.flow_reports))
            # Reduced / clamped TCP MSS: the client advertising a uniformly low
            # MSS reveals a reduced path MTU even when no ICMP is present (RFC 879;
            # the MSS-clamping fallback when PMTUD/ICMP is blocked). When the user
            # confirmed this capture is through a Cisco Secure Access tunnel, the
            # SA-specific tunnel-MTU finding (expected 1390/1350 + UDP warnings)
            # SUPERSEDES the generic one.
            if ctx.sa_tunnel:
                result.signal_findings.extend(_sa_tunnel_mtu_findings(packets))
            else:
                result.signal_findings.extend(_mss_clamp_findings(packets))
            if ctx.secure_access_mode:
                # Cisco Secure Access Private Access (Zero Trust / ZTNA): tag flows
                # in the 100.64.0.0/10 CGNAT pool so they aren't mistaken for SWG
                # traffic.
                result.signal_findings.extend(_private_access_findings(target_flows))
                # Internal (private->private) LAN traffic: never goes through the
                # SWG (SIA), so SWG/decryption/web-policy/pinning verdicts do not
                # apply.
                result.signal_findings.extend(_internal_traffic_findings(target_flows))
            # Asymmetric routing / one-armed capture: only fires on hard proof
            # (ACKed-unseen segments or strictly one-way established flows).
            result.signal_findings.extend(_asymmetric_routing_findings(target_flows))
            if not packets:
                result.notes.append("PCAP parsed but contained no TCP/UDP packets to analyze.")

    # --- HAR ---
    if har_text:
        har = parse_har(har_text)
        result.har = har
        if har.parse_error:
            result.notes.append(har.parse_error)
        result.har_findings = _har_findings(har, ctx)
        result.har_findings.extend(_har_proxy_findings(har, ctx))
        # Latency: slow timing phases (DNS / connect / TLS / TTFB) from HAR timings.
        result.signal_findings.extend(_latency_findings_har(har))
        # Latency: possible detour cost when the SWG egress region is far from the user.
        result.signal_findings.extend(_geo_egress_latency_findings(har, ctx))

    # Honest scope note: a PCAP can only confirm the web/DLP blocks that left an
    # on-wire trace (a block.sse.cisco.com handshake). The actual block verdict —
    # the 302 redirect to block.sse + the blockinfo JWT — travels ENCRYPTED inside
    # the TLS session to the SWG, so individual DLP blocks are undercounted here.
    # Only add the note when the capture shows web-policy enforcement AND no HAR
    # was supplied (the HAR already carries the complete, decrypted list).
    if pcap_path:
        web_blocks = sum(1 for fr in result.flow_reports
                         if fr.block_category and "web policy" in fr.block_category.lower())
        har_has_blocks = any("block on" in f.title.lower() for f in result.har_findings)
        if web_blocks and not har_has_blocks:
            result.notes.append(
                "PCAP shows Secure Access web-policy enforcement, but individual DLP / web "
                "blocks are only partially visible on the wire: the block verdict (302 \u2192 "
                "block.sse.cisco.com + blockinfo JWT) is encrypted inside the TLS session to "
                "the SWG. Export the browser HAR for the complete, decrypted list of "
                "DLP-blocked requests."
            )

    _correlate(result)
    _correlate_web_blocks(result)
    _suppress_pinning_on_trusted_hosts(result)
    _classify(result)
    _summarize(result)
    return result


def _correlate_web_blocks(result: AnalysisResult) -> None:
    """Name the destination that triggered each Secure Access web-policy block.

    The block page (block.sse.cisco.com) carries no hint of WHAT was blocked, so
    we correlate it to the real domain the client requested immediately before it
    (the redirect chain happens within a fraction of a second). This turns an
    opaque "block page" finding into "grok.com blocked", which is what an analyst
    actually needs to see."""
    def _real_domain(fl: Flow) -> Optional[str]:
        host = fl.tunnel_sni or fl.sni or (fl.connect_target or "").rsplit(":", 1)[0]
        if not host:
            return None
        h = host.strip().lower().rstrip(".")
        if not h or is_block_page_domain(h) or ":" in h or not re.search(r"[a-z]", h):
            return None
        return h

    # Every flow that named a real destination, sorted by start time.
    domain_flows = sorted(
        ((fr.flow.start_time, d) for fr in result.flow_reports
         if (d := _real_domain(fr.flow))),
        key=lambda x: x[0])

    for fr in result.flow_reports:
        for f in fr.findings:
            if "blocked by secure access policy" not in f.title.lower():
                continue
            bt = fr.flow.start_time
            # Nearest real domain requested in the 8 s before the block page.
            preceding = [d for (t, d) in domain_flows if t < bt and bt - t <= 8.0]
            if not preceding:
                continue
            domain = preceding[-1]
            f.title = (f"Web request to {domain} blocked by Secure Access policy "
                       "(content / app control / DLP / AI guardrail) — block page")
            f.detail = (
                f"The request to {domain} was redirected to the Secure Access block page "
                "(block.sse.cisco.com, 146.112.199.x). The block is enforced AFTER TLS decryption, so it "
                "is a content/URL category, application-control, Data Loss Prevention (DLP), or AI-guardrail "
                f"rule. The user saw a block notification instead of reaching {domain}. Review the matching "
                "web-policy / DLP / AI-guardrail rule.")
            f.evidence = ([f"blocked destination: {domain} -> block.sse.cisco.com "
                           f"({fr.flow.connect_target or fr.flow.dst_ip})"] + f.evidence)


def _correlate(result: AnalysisResult) -> None:
    """Map HAR failures to PCAP flows by host/SNI and server IP, and align time."""
    if not result.har or not result.flow_reports:
        return
    flows_by_host: dict[str, list[FlowReport]] = {}
    flows_by_ip: dict[str, list[FlowReport]] = {}
    for fr in result.flow_reports:
        if fr.flow.sni:
            flows_by_host.setdefault(fr.flow.sni.lower(), []).append(fr)
        if fr.flow.dst_ip:
            flows_by_ip.setdefault(fr.flow.dst_ip, []).append(fr)

    for e in result.har.failed:
        match: Optional[FlowReport] = None
        if e.host and e.host.lower() in flows_by_host:
            match = flows_by_host[e.host.lower()][0]
        elif e.server_ip and e.server_ip in flows_by_ip:
            match = flows_by_ip[e.server_ip][0]
        if match:
            tls = match.tls_status
            result.correlations.append(
                f"HAR '{e.error_label or e.status}' on {e.host} ↔ PCAP flow {match.flow.key} "
                f"({match.flow.src_ip}→{match.flow.dst_ip}:{match.flow.dst_port}, {tls})."
            )
        elif e.host:
            result.correlations.append(
                f"HAR '{e.error_label or e.status}' on {e.host} — no matching PCAP flow "
                f"(possibly QUIC/different capture window or DNS-stage failure)."
            )

    # --- Proxied-OK correlation: map HAR requests to the CONNECT tunnel that
    # carried them, using real destination host + overlapping time window.
    # (Timestamp alone is ambiguous here — many simultaneous tunnels to the same
    # host — so we match on host AND time.)
    tunnels = [fr.flow for fr in result.flow_reports if fr.flow.is_connect_tunnel and fr.flow.connect_target]
    if not tunnels:
        return

    def _host_of(target: Optional[str]) -> str:
        return (target or "").rsplit(":", 1)[0].lower()

    tunnels_by_host: dict[str, list[Flow]] = {}
    for t in tunnels:
        tunnels_by_host.setdefault(_host_of(t.connect_target), []).append(t)

    # Group HAR entries by host
    har_by_host: dict[str, list[HarEntry]] = {}
    for e in result.har.entries:
        if e.host:
            har_by_host.setdefault(e.host.lower(), []).append(e)

    for host, t_list in tunnels_by_host.items():
        h_entries = har_by_host.get(host, [])
        if not h_entries:
            continue
        # window covering all tunnels to this host
        t_start = min(t.start_time for t in t_list)
        t_end = max(t.end_time for t in t_list)
        in_window = [e for e in h_entries if e.started and t_start - 2 <= e.started <= t_end + 2]
        keys = ", ".join(sorted(t.key for t in t_list))
        if in_window:
            result.correlations.append(
                f"{len(in_window)} HAR request(s) to {host} ↔ {len(t_list)} CONNECT tunnel(s) "
                f"[{keys}] active in the same window — browser requests rode inside the Secure Access tunnel(s)."
            )
        else:
            result.correlations.append(
                f"{len(h_entries)} HAR request(s) to {host} match CONNECT tunnel host [{keys}] "
                f"but fall outside the PCAP capture window (HAR continued after capture stopped)."
            )


def _suppress_pinning_on_trusted_hosts(result: AnalysisResult) -> None:
    """Drop 'TCP RST after ServerHello' pinning signals for a destination host
    that ALSO has a gracefully-completed connection elsewhere in the capture.

    RFC 8446 / RFC 9293 reasoning: if the client completed a TLS session to host
    X and closed it with an orderly FIN exchange (or exchanged application data),
    it demonstrably ACCEPTS X's certificate — including any re-signed cert from a
    decrypting SWG. A later reset to that same host therefore cannot be
    certificate pinning / certificate rejection; it is a transient teardown
    (cancelled request, connection reuse, idle reset, capture cut-off). Real
    certificate pinning is consistent — it rejects EVERY connection to the pinned
    host, never just some — so we keep the signal only for hosts where NO
    connection ever completed (e.g. a host every flow resets, like a pinned
    cisco.com under inspection or a package repo that breaks on every attempt)."""
    def host_of(fl: Flow) -> str:
        h = fl.sni or fl.tunnel_sni
        if not h and fl.connect_target:
            h = fl.connect_target.rsplit(":", 1)[0]
        h = h or fl.resolved_host or fl.dst_ip or ""
        return h.lower().strip("[]")

    completed: set[str] = set()
    for rep in result.flow_reports:
        fl = rep.flow
        # fin_count >= 2 (orderly four-way close) is the reliable completion proof
        # in TLS 1.3, where handshake_complete / app_data_seen cannot be observed.
        if fl.fin_count >= 2 or fl.handshake_complete or fl.app_data_seen:
            h = host_of(fl)
            if h:
                completed.add(h)

    if not completed:
        return
    title_prefix = "TCP RST after ServerHello/Certificate"
    for rep in result.flow_reports:
        if host_of(rep.flow) in completed:
            rep.findings = [f for f in rep.findings
                            if not (f.category == "pinning_signal"
                                    and f.title.startswith(title_prefix))]


def _classify(result: AnalysisResult) -> None:
    cats = Counter(f.category for f in result.all_findings)
    labels: list[str] = []
    for cat, _ in cats.most_common():
        label = CLASSIFICATION_LABELS.get(cat)
        if label and label not in labels:
            labels.append(label)
    if not labels:
        labels.append("Inconclusive")
    result.classifications = labels

    # Structured, severity-ranked breakdown grouped by display label so the
    # Technical summary can explain *why* each problem was flagged and colour it.
    groups: dict[str, dict] = {}
    for f in result.all_findings:
        label = CLASSIFICATION_LABELS.get(f.category)
        if not label:
            continue
        g = groups.get(label)
        if g is None:
            g = {
                "label": label,
                "category": f.category,
                "severity": f.severity,
                "count": 0,
                "flows": set(),
                "why": CLASSIFICATION_WHY.get(f.category, ""),
                "example": f.evidence[0] if f.evidence else "",
                "example_plain": CLASSIFICATION_EXAMPLE.get(f.category, ""),
                "remediation": CLASSIFICATION_REMEDIATION.get(f.category, []),
            }
            groups[label] = g
        g["count"] += 1
        if f.flow_key:
            g["flows"].add(f.flow_key)
        if _SEV_RANK.get(f.severity, 9) < _SEV_RANK.get(g["severity"], 9):
            g["severity"] = f.severity
            if f.evidence:
                g["example"] = f.evidence[0]
    ranked = sorted(groups.values(), key=lambda g: (_SEV_RANK.get(g["severity"], 9), -g["count"]))
    for g in ranked:
        g["flow_count"] = len(g["flows"])
        del g["flows"]
    result.tech_groups = ranked

    # Corporate CA detected across many distinct hosts -> strong interception signal
    if result.corporate_ca_orgs:
        org, count = result.corporate_ca_orgs.most_common(1)[0]
        result.notes.append(f"Corporate/middlebox CA '{org}' signed {count} leaf certificate(s) — active SSL decryption.")


def _summarize(result: AnalysisResult) -> None:
    findings = result.all_findings
    if not findings:
        result.summary_diagnosis = (
            "No TLS, certificate, proxy or network anomalies were detected in the provided data."
        )
        result.confidence = "Low" if not (result.flow_reports or result.har) else "Medium"
        result.plain_summary = (
            "Good news: nothing went wrong. The analysis looked at every connection in the capture and found "
            "no security-inspection, certificate, blocking, or network problems."
        )
        result.plain_impact = "No user impact \u2014 traffic flowed normally."
        result.recommended_action = "No action needed."
        n_flows = len(result.flow_reports)
        n_dns = len(result.dns_records)
        bits = []
        if n_flows:
            bits.append(f"{n_flows} network connection{'s' if n_flows != 1 else ''}")
        if n_dns:
            bits.append(f"{n_dns} DNS lookup{'s' if n_dns != 1 else ''}")
        if bits:
            result.plain_scope = "This capture contained " + (" and ".join(bits)) + ", all healthy."
        return

    # Severity-weighted pick of the dominant issue. Among equally severe
    # findings a capture-wide verdict outranks the per-flow findings it
    # summarises, so the headline is the conclusion and not one of its inputs.
    by_sev = sorted(findings, key=lambda f: (
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[f.severity],
        0 if getattr(f, "is_verdict", False) else 1,
    ))
    top = by_sev[0]

    # If every finding is informational (tunnel/coverage/interception notes) then
    # nothing actually failed — the capture is healthy. Don't echo an info finding
    # as if it were a verdict; report a clear SUCCESS instead. This is what keeps a
    # working capture (clean FIN close, app data transferred) from being described
    # like a problem.
    has_problem = any(
        f.severity in ("critical", "high", "medium", "low") for f in findings)
    if not has_problem:
        steered = any(f.category == "swg_coverage" for f in findings)
        intercepted = (any(f.category == "interception" for f in findings)
                       or bool(result.corporate_ca_orgs))
        verdict = ("All connections completed successfully — no TLS, certificate, proxy or "
                   "network problems were detected.")
        extras = []
        if steered:
            extras.append("all HTTPS traffic was steered through Secure Access")
        if intercepted:
            extras.append("Secure Access decrypted and re-signed the traffic for inspection and the "
                          "endpoints accepted the re-signed certificate")
        if extras:
            verdict += " (" + "; ".join(extras) + ")."
        result.summary_diagnosis = verdict
        result.confidence = "High"
        result.plain_summary = (
            "Good news: every secure connection in this capture finished normally. "
            + ("Cisco Secure Access is inspecting the traffic (it replaces each site's certificate "
               "with its own re-signed one), and the programs on this device trusted that inspection "
               "certificate, so nothing broke. " if intercepted else "")
            + "Downloads and page loads completed without being reset or blocked."
        )
        result.plain_impact = "No user impact — traffic flowed normally."
        result.recommended_action = "No action needed."
        n_flows = len(result.flow_reports)
        if n_flows:
            result.plain_scope = (f"This capture contained {n_flows} network "
                                  f"connection{'s' if n_flows != 1 else ''}, all healthy.")
        return

    # Pinning needs corroboration
    pinning = [f for f in findings if f.category == "pinning_signal"]
    cert_trust = [f for f in findings if f.category == "cert_trust"]
    interception = bool(result.corporate_ca_orgs) or any(f.category == "interception" for f in findings)
    # Intentional security-policy blocks (URL filtering / DNS-layer / block-page).
    # These are Secure Access doing its job, NOT a fault — recognise them so the
    # headline says "enforcement working" instead of mislabeling a block as a
    # generic "TLS handshake failure".
    web_policy_blocks = [f for f in findings if f.category == "proxy"
                         and "blocked by secure access policy" in f.title.lower()]
    sec_blocks = [f for f in findings if f.category == "proxy" and (
        "block-page" in f.title.lower() or "dns-blocked" in f.title.lower())]
    blocks = sec_blocks + web_policy_blocks

    if pinning and interception:
        # Name the destination(s) actually showing the pinning signal and scope it
        # against the healthy traffic, so an isolated reset (e.g. a single pinned
        # host such as cisco.com under inspection) does not read as if the whole
        # capture were broken.
        pin_hosts: list[str] = []
        n_pin_flows = 0
        for rep in result.flow_reports:
            if any(f.category == "pinning_signal" for f in rep.findings):
                n_pin_flows += 1
                h = rep.flow.sni or rep.flow.tunnel_sni or rep.flow.resolved_host
                if not h and rep.flow.connect_target:
                    h = rep.flow.connect_target.rsplit(":", 1)[0]
                h = h or rep.flow.dst_ip
                if h and h not in pin_hosts:
                    pin_hosts.append(h)
        total = len(result.flow_reports)
        host_txt = ", ".join(pin_hosts[:3]) if pin_hosts else "one or more endpoints"
        if len(pin_hosts) > 3:
            host_txt += f" (+{len(pin_hosts) - 3} more)"
        scope_txt = ""
        if total and n_pin_flows and (total - n_pin_flows) >= n_pin_flows:
            that = "that host" if len(pin_hosts) == 1 else "those hosts"
            scope_txt = (f" This affects {n_pin_flows} of {total} connections — the rest completed "
                         f"normally, so it is specific to {that}, not a capture-wide failure.")
        result.summary_diagnosis = (
            f"Probable certificate pinning on {host_txt}: traffic is being SSL-decrypted by a corporate "
            f"CA and the endpoint rejects the re-signed certificate (abrupt TCP RST with no graceful "
            f"FIN/FIN close).{scope_txt} Pinning cannot be proven from PCAP/HAR alone but the behavioral "
            f"pattern supports it."
        )
        result.confidence = "Medium"
    elif cert_trust and interception:
        result.summary_diagnosis = (
            "Corporate CA not trusted by the endpoint: SSL decryption is active but the client does not "
            "trust the proxy/SWG signing CA (unknown_ca / ERR_CERT_AUTHORITY_INVALID)."
        )
        result.confidence = "High"
    elif top.category == "pinning_signal" and top.title.startswith("Client reset the decrypted tunnel"):
        result.summary_diagnosis = (
            f"Application-layer certificate rejection through the decrypting proxy: {top.title}. The TLS "
            "handshake completed, but the client aborted (RST, no graceful FIN/close_notify) before sending "
            "any request — consistent with a developer tool that doesn't trust the SWG's re-signed "
            "certificate (its own CA bundle, or certificate pinning), which silently breaks downloads."
        )
        result.confidence = "Medium"
    elif blocks:
        threat_cats: list[str] = []
        for f in sec_blocks:
            if "\u2014" in f.title:  # em-dash precedes the threat category
                c = f.title.split("\u2014", 1)[1].strip()
                if c and c not in threat_cats:
                    threat_cats.append(c)
        dns_blocks = sum(1 for f in sec_blocks if "dns-blocked" in f.title.lower())
        sec_web_blocks = sum(1 for f in sec_blocks if "block-page" in f.title.lower())
        web_blocks = len(web_policy_blocks)
        # Name the destinations behind the web-policy blocks (correlated earlier).
        web_domains: list[str] = []
        for f in web_policy_blocks:
            m = re.search(r"web request to (\S+) blocked", f.title.lower())
            web_domains.append(m.group(1) if m else "(unknown destination)")
        wc = Counter(web_domains)
        _x = "\u00d7"
        web_list = ", ".join(f"{d}{(' ' + _x + str(n)) if n > 1 else ''}" for d, n in wc.items())
        # Build the scope phrase from whichever block types are present.
        scope_parts = []
        if dns_blocks:
            scope_parts.append(f"{dns_blocks} DNS lookup{'s' if dns_blocks != 1 else ''}")
        if sec_web_blocks:
            scope_parts.append(f"{sec_web_blocks} malware/C2 web connection{'s' if sec_web_blocks != 1 else ''}")
        if web_blocks:
            scope_parts.append(f"{web_blocks} HTTPS request{'s' if web_blocks != 1 else ''} by web policy "
                               f"({web_list})")
        scope_txt = "; ".join(scope_parts) if scope_parts else "several connections"
        cat_bits = []
        if threat_cats:
            cat_bits.append(", ".join(threat_cats))
        if web_blocks:
            cat_bits.append("web policy / DLP / AI guardrail")
        cat_txt = "; ".join(cat_bits) if cat_bits else "security policy"
        result.summary_diagnosis = (
            f"Cisco Secure Access is actively enforcing policy: it blocked {scope_txt} and redirected them "
            f"to its block page ({cat_txt}). This is the DNS-layer security and web-policy (SWG) protection "
            f"working as intended — not a fault."
        )
        result.confidence = "High"
        # Plain-language wording adapts to which kinds of blocks were seen.
        plain_bits = []
        if dns_blocks or sec_web_blocks:
            plain_bits.append(
                "stopped this device from reaching dangerous destinations "
                + (f"(categorised as {', '.join(threat_cats)})" if threat_cats else "(known-bad / test domains)"))
        if web_blocks:
            plain_bits.append(
                f"blocked {web_blocks} HTTPS request{'s' if web_blocks != 1 else ''} to {web_list} by web "
                "policy — content category, application control, Data Loss Prevention (DLP), or an "
                "AI-guardrail rule")
        result.plain_summary = (
            "During this capture, Cisco Secure Access "
            + " and ".join(plain_bits)
            + ". In each case it sent back a block page instead of letting the connection through. This is the "
            "security service doing exactly what it is meant to do."
        )
        impact_bits = []
        if dns_blocks or sec_web_blocks:
            impact_bits.append("the malicious/test destinations were stopped, protecting the user")
        if web_blocks:
            impact_bits.append("the user saw a block notification instead of the site/app they tried to use, "
                               "because it matched a web-policy / DLP / AI-guardrail rule")
        result.plain_impact = (
            (". ".join(b.capitalize() for b in impact_bits) if impact_bits else "Blocked traffic was stopped")
            + ". Normal browsing in the same capture continued to work."
        )
        result.recommended_action = (
            "No action needed if these blocks are expected. For the web-policy / DLP / AI-guardrail blocks, "
            "review the matching Secure Access rule (and the data identifier or AI-guardrail policy) to confirm "
            "it is intended; if a specific destination is legitimate, adjust the matching policy or destination list."
        )
        n_ok = sum(1 for r in result.flow_reports if not any(
            x.severity in ("critical", "high", "medium") for x in r.findings))
        result.plain_scope = (f"{len(blocks)} connection(s) were blocked by policy; the remaining "
                              f"~{n_ok} connection(s) completed normally.")
        result.primary_evidence = []
        for f in (web_policy_blocks + sec_blocks)[:5]:
            ev = f.evidence[0] if f.evidence else f.title
            result.primary_evidence.append(f"{f.title} — {ev}")
        return
    elif top.category == "quic":
        result.summary_diagnosis = (
            "QUIC/HTTP3 interference: traffic is using UDP/443 QUIC and likely bypassing TCP-based TLS "
            "inspection, masking the intended decryption/bypass behavior."
        )
        result.confidence = "Medium"
    elif top.category == "proxy":
        result.summary_diagnosis = (
            f"Proxy/SWG is blocking or failing the request ({top.title}). Likely policy, category, "
            "reputation or proxy-auth related rather than a TLS fault."
        )
        result.confidence = "Medium"
    elif top.category == "swg_coverage":
        result.summary_diagnosis = (
            f"Secure Access traffic-steering status: {top.title}. This is about whether traffic is "
            "routed through the SWG, not a TLS fault — a bypass means policy/decryption isn't applied."
        )
        result.confidence = "High"
    elif top.category in {"public_cert"}:
        result.summary_diagnosis = f"Public certificate problem: {top.title}."
        result.confidence = "High"
    elif top.category in {"tls_version"}:
        result.summary_diagnosis = f"TLS version/cipher mismatch: {top.title}."
        result.confidence = "Medium"
    elif top.category == "network":
        result.summary_diagnosis = (
            f"Network-layer issue resembling a TLS failure: {top.title} (possible loss / MTU blackhole / RST)."
        )
        result.confidence = "Medium"
    elif top.category in {"tls_handshake", "tls_alert"}:
        result.summary_diagnosis = f"TLS handshake failure: {top.title}."
        result.confidence = "Medium"
    else:
        result.summary_diagnosis = top.title
        result.confidence = "Medium"

    result.primary_evidence = []
    seen_ev: set[str] = set()
    for f in by_sev:
        if f.evidence:
            line = f"{f.title} — {f.evidence[0]}"
            if line not in seen_ev:
                seen_ev.add(line)
                result.primary_evidence.append(line)
        if len(result.primary_evidence) >= 4:
            break

    _plain_summary(result, top)


# Short plain-language one-liners for secondary issues listed in the exec summary.
_PLAIN_GROUP_NOTE = {
    "interception": "The company is also opening and re-sealing encrypted traffic for inspection on some sites.",
    "cert_trust": "Some sites show security warnings because this device doesn't trust the company's inspection certificate.",
    "pinning_signal": "At least one app refuses the company's inspection and drops its own connection.",
    "public_cert": "One or more websites have their own certificate problem (expired or mismatched).",
    "tls_version": "A device and a site couldn't agree on a common secure-connection method.",
    "tls_handshake": "Some secure connections failed while being set up.",
    "tls_alert": "Some secure connections were rejected during setup.",
    "quic": "Some traffic used a faster path (QUIC) that slips past the security inspection.",
    "proxy": "The security service blocked or errored on some requests.",
    "swg_coverage": "Some or all traffic is bypassing Secure Access and going direct to the internet.",
    "swg_coverage_info": "A category-by-category breakdown of the capture, showing how the coverage figures were reached.",
    "tunnel": "Some traffic went through an opaque tunnel that wasn't inspected.",
    "network": "Some connections failed at the network level (dropped or reset).",
    "dns": "Some website lookups failed or were redirected.",
    "roaming": "The Cisco Secure Client roaming agent is steering DNS/web traffic locally (loopback).",
    "local_interception": "An agent on this device is decrypting TLS locally (loopback) before it leaves the machine.",
}


# Plain-language translations keyed by the dominant finding category. Written for
# a reader with NO networking/TLS background: what happened, why it matters, and
# what to do — in everyday words, no jargon.
def _plain_summary(result: AnalysisResult, top: "Finding") -> None:
    cat = top.category
    n_flows = len(result.flow_reports)
    blocked = sum(1 for r in result.dns_records if r.blocked)
    interception = bool(result.corporate_ca_orgs) or any(f.category == "interception" for f in result.all_findings)

    # --- Scope sentence: what was actually examined (gives the summary substance) ---
    n_dns = len(result.dns_records)
    problem_flows = sum(1 for fr in result.flow_reports
                        if any(x.severity in ("critical", "high", "medium", "low") for x in fr.findings))
    n_har = len(result.har.failed) if result.har else 0
    scope_bits = []
    if n_flows:
        scope_bits.append(f"{n_flows} network connection{'s' if n_flows != 1 else ''}")
    if n_dns:
        scope_bits.append(f"{n_dns} DNS lookup{'s' if n_dns != 1 else ''}")
    if n_har:
        scope_bits.append(f"{n_har} failed browser request{'s' if n_har != 1 else ''}")
    if scope_bits:
        joined = scope_bits[0] if len(scope_bits) == 1 else (
            ", ".join(scope_bits[:-1]) + " and " + scope_bits[-1])
        prob = (f" Of those, {problem_flows} connection{'s' if problem_flows != 1 else ''} showed a problem."
                if problem_flows else " None of the connections showed a TLS-level problem.")
        result.plain_scope = f"This capture contained {joined}.{prob}"

    # --- Secondary issues: short plain notes for other distinct problem types ---
    secondary: list[str] = []
    seen_labels: set[str] = set()
    primary_label = CLASSIFICATION_LABELS.get(cat)
    for g in result.tech_groups:
        if g["label"] == primary_label or g["label"] in seen_labels:
            continue
        seen_labels.add(g["label"])
        plain = _PLAIN_GROUP_NOTE.get(g["category"])
        if plain:
            secondary.append(plain)
        if len(secondary) >= 3:
            break
    result.plain_secondary = secondary

    if blocked:
        names = ", ".join(r.name for r in result.dns_records if r.blocked)
        result.plain_summary = (
            f"Cisco Secure Access deliberately blocked access to {names}. When the computer asked "
            "\u201cwhere is this website?\u201d, Secure Access answered with its own block page instead of the "
            "real address, so the site never loaded. This is the security policy working as designed, not a "
            "broken connection."
        )
        result.plain_impact = ("The user sees a block or an error page for that site. Everything else keeps "
                               "working normally.")
        result.recommended_action = ("If the site should be allowed, change the rule in the Secure Access "
                                     "policy (the category or destination list that matched it). If the block "
                                     "is correct, no action is needed.")
        return

    if cat == "pinning_signal" and top.title.startswith("Client reset the decrypted tunnel"):
        tgt = ""
        # Pull the destination out of the finding title for a concrete message.
        try:
            tgt = top.title.split(" to ", 1)[1].split(" right after", 1)[0]
        except Exception:
            tgt = "the destination"
        result.plain_summary = (
            "Cisco Secure Access is decrypting this traffic for inspection, which means it replaces the "
            f"website\u2019s certificate with its own re-signed one. The program connecting to {tgt} (a developer "
            "tool such as Composer/PHP, git, npm, pip, Java or curl) completed the secure handshake but then "
            "refused that re-signed certificate and dropped the connection \u2014 so nothing was ever downloaded. "
            "These tools don\u2019t use the Windows certificate store; they ship their own list of trusted "
            "authorities, and the Secure Access authority isn\u2019t on it."
        )
        result.plain_impact = (f"Downloads or package installs from {tgt} fail through the proxy, even though "
                               "the user\u2019s browser and other sites keep working normally.")
        result.recommended_action = (
            f"Preferred, tool-agnostic fix: add {tgt} to a \u201cDo Not Decrypt\u201d / bypass rule in Secure Access so "
            "the tool sees the website\u2019s real certificate \u2014 this works no matter which program is failing. "
            "Alternatively, make the SPECIFIC tool trust the Secure Access root CA, but the setting differs per "
            "tool and you must first confirm which one is downloading: \u201copenssl.cafile\u201d in php.ini applies "
            "ONLY to PHP/Composer (getcomposer.org/doc/06-config.md#cafile); git uses http.sslCAInfo, npm uses "
            "cafile, Node uses NODE_EXTRA_CA_CERTS, pip uses --cert, Java uses keytool. Changing php.ini will not "
            "help a non-PHP tool. Note: if the tool uses strict certificate pinning, only the Do Not Decrypt "
            "option will work."
        )
        return

    if cat == "pinning_signal" and interception:
        result.plain_summary = (
            "The company is inspecting encrypted web traffic for security (it opens the \u201csealed envelope,\u201d "
            "checks it, and re-seals it). This particular app refuses to accept a re-sealed envelope \u2014 it only "
            "trusts the original \u2014 so it drops the connection. This protective behavior is called "
            "\u201ccertificate pinning.\u201d"
        )
        result.plain_impact = ("The affected app (often a banking, video, or mobile app) fails to connect or "
                               "load, while normal websites work fine.")
        result.recommended_action = ("Add this application/domain to the list that is allowed to skip "
                                     "inspection (a \u201cbypass\u201d or \u201cdo-not-decrypt\u201d rule) in Secure Access.")
        return

    if cat == "cert_trust" and interception:
        result.plain_summary = (
            "The company is inspecting encrypted web traffic for security. To do that it puts its own digital "
            "\u201cID card\u201d on each website. This computer doesn\u2019t recognize that company ID card as trusted, so "
            "the browser shows a security warning and refuses to continue."
        )
        result.plain_impact = ("The user sees \u201cyour connection is not private\u201d warnings on many or all HTTPS "
                               "sites.")
        result.recommended_action = ("Install the Cisco Secure Access root certificate on this computer (push it "
                                     "via your device-management tool so every machine trusts it).")
        return

    if cat == "quic":
        result.plain_summary = (
            "The browser is using a newer, faster way to connect (called QUIC). The security inspection only "
            "watches the traditional way, so this traffic is slipping past it un-inspected."
        )
        result.plain_impact = ("Some traffic isn\u2019t being filtered or logged by Secure Access, even though it "
                               "looks like it\u2019s working for the user.")
        result.recommended_action = ("Block the QUIC protocol (UDP port 443) on the network so browsers fall back "
                                     "to the standard connection that Secure Access can inspect.")
        return

    if cat == "proxy":
        result.plain_summary = (
            "Secure Access stopped this request before it reached the website \u2014 either because of a policy "
            "rule, the site\u2019s category/reputation, or a sign-in/authentication step that didn\u2019t complete."
        )
        result.plain_impact = "The user cannot reach the requested site and likely sees an error or block page."
        result.recommended_action = ("Check the Secure Access policy and activity log for this user and "
                                     "destination to see which rule stopped it, and adjust if it should be allowed.")
        return

    if cat == "swg_coverage":
        if top.severity == "info":
            result.plain_summary = (
                "All of the device\u2019s web traffic is going through Cisco Secure Access as intended \u2014 like "
                "everyone entering the building through the guarded front desk. Security policy, web filtering "
                "and inspection are being applied. This is healthy, expected behavior."
            )
            result.plain_impact = "No negative impact \u2014 it confirms the device is properly protected by Secure Access."
            result.recommended_action = "No action needed."
        else:
            result.plain_summary = (
                "Some or all of the device\u2019s web traffic is reaching the internet directly instead of going "
                "through Cisco Secure Access \u2014 like slipping in through a side door past the guarded front desk. "
                "For that traffic, no company web filtering, policy or inspection is applied."
            )
            result.plain_impact = ("The bypassing traffic is unprotected and invisible to Secure Access logging, "
                                   "even though it works for the user.")
            result.recommended_action = ("Check the proxy/PAC configuration, the Secure Client module state and any "
                                         "split-tunnel rules so all traffic is steered through Secure Access.")
        return

    if cat in ("public_cert",):
        result.plain_summary = (
            "The website\u2019s own security certificate (its digital ID) has a problem \u2014 for example it\u2019s expired "
            "or doesn\u2019t match the site name. This is an issue with the website itself, not with Secure Access."
        )
        result.plain_impact = "The browser warns the user that the site may not be safe."
        result.recommended_action = ("Confirm with the website owner; if it\u2019s an internal site, renew or fix its "
                                     "certificate.")
        return

    if cat == "network":
        # A congestion verdict is about a transfer that WORKED but was slowed by a
        # lossy path. The handshake wording below would describe a failure that
        # did not happen.
        if top.title.startswith("Dominant limit: lossy"):
            result.plain_summary = (
                "The connections worked, but the network path between the two sides was dropping packets, so "
                "data had to be sent again and again. Every side had to slow down to cope. This is a network "
                "quality problem — not a security, certificate or inspection problem."
            )
            result.plain_impact = ("Transfers and page loads are slower than the link should allow, and may "
                                   "stall intermittently.")
            result.recommended_action = ("Investigate the path itself: a congested or saturated link, a flaky "
                                         "connection, or an overloaded hop between the user and the destination.")
            return
        result.plain_summary = (
            "The connection is failing at the network level (packets are being lost or reset) in a way that can "
            "look like a security problem but isn\u2019t. The two sides couldn\u2019t complete the initial \u201chandshake.\u201d"
        )
        result.plain_impact = "Pages load slowly, time out, or fail intermittently."
        result.recommended_action = ("Check the network path \u2014 firewall rules, MTU/packet-size settings, or a "
                                     "flaky link between the user and Secure Access.")
        return

    if cat in ("tls_version", "tls_handshake", "tls_alert"):
        result.plain_summary = (
            "The user\u2019s device and the website (or the security inspection in between) couldn\u2019t agree on a "
            "common way to set up the secure connection, so the connection was dropped during setup."
        )
        result.plain_impact = "The site fails to load for the user."
        result.recommended_action = ("Review the decryption settings for this destination in Secure Access; an "
                                     "older device or a strict site may need a bypass or a settings adjustment.")
        return

    if cat == "latency":
        # Nothing here is a failure: the traffic worked, it was simply slower
        # than it could have been. Saying "something interfered with a secure
        # connection" would contradict the evidence.
        if top.title.startswith("Dominant limit: waiting on"):
            who = "the client" if "waiting on client" in top.title else (
                "the server" if "waiting on server" in top.title else "one of the two sides")
            result.plain_summary = (
                f"Nothing was wrong with the network. For a large part of the recording the connection sat "
                f"completely silent — no data was queued, lost or blocked, because there was simply nothing "
                f"to send. {who.capitalize()} was the side everyone was waiting on. In other words, the time "
                f"was spent inside an application, not on the wire."
            )
            result.plain_impact = ("The user experiences the delay as slowness, but speeding up the network "
                                   "would not shorten it.")
            result.recommended_action = (f"Look at what {who} was doing during the pause — the capture can prove "
                                         f"the network was idle, but not what {who} was busy with. Application "
                                         f"logs or profiling on that side are the next step.")
            return
        if top.title.startswith("Dominant limit: receiver buffer"):
            result.plain_summary = (
                "The transfer worked, but the receiving side kept announcing that it had no room left for more "
                "data — its application was not reading what had already arrived fast enough. The sender and "
                "the network were both ready and waiting."
            )
            result.plain_impact = "Transfers run slower than the link allows, in bursts and pauses."
            result.recommended_action = ("Investigate the receiving application or host: it is the component "
                                         "unable to keep up, not the network.")
            return
        result.plain_summary = (
            "Everything connected successfully — this is about speed, not failure. The traffic was held back by "
            "how the connection was set up or paced (extra round-trips during setup, or a transfer window too "
            "small for the distance), rather than by any security, certificate or blocking problem."
        )
        result.plain_impact = ("Pages and transfers feel slower than expected, but they complete and no error "
                              "is shown to the user.")
        result.recommended_action = ("Open the Technical summary for the exact limit that was measured; each "
                                     "finding states what capped the speed and what would lift it.")
        return

    if cat == "roaming":
        result.plain_summary = (
            "This device is running the Cisco Secure Client roaming agent. Instead of sending DNS (and, when web "
            "protection is on, web) traffic straight out, the agent catches it locally on the computer "
            "(address 127.0.0.1) and applies Umbrella / Secure Access policy first. This is normal, expected "
            "behavior \u2014 it\u2019s how protection keeps working whether the user is in the office or anywhere else."
        )
        result.plain_impact = ("No negative impact \u2014 it confirms the roaming protection is installed and active "
                               "on this device.")
        result.recommended_action = ("No action needed. If you expected this device to be protected by the "
                                     "roaming module, this confirms it is working.")
        return

    # Fallback / no findings.
    if not result.all_findings:
        result.plain_summary = (
            "Good news: nothing went wrong. The analysis looked at every connection in the capture and found "
            "no security-inspection, certificate, blocking, or network problems."
        )
        result.plain_impact = "No user impact \u2014 traffic flowed normally."
        result.recommended_action = "No action needed."
    else:
        # Reached only by categories with no plain-language branch of their own.
        # It must not assert a cause: naming one here (a secure connection being
        # interfered with) would be a guess, and is simply wrong whenever the
        # finding is about DNS, speed or capture quality.
        result.plain_summary = (
            f"The analysis reviewed {n_flows} connection(s) and the most significant thing it found was: "
            f"{top.title}. The finding itself explains what the capture shows."
        )
        result.plain_impact = ("See the finding below for the effect on the user \u2014 it is stated there rather "
                               "than assumed here.")
        result.recommended_action = ("Open the Technical summary below and the matching finding for the exact "
                                     "cause and fix.")
