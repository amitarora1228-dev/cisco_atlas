"""Core analysis engine: enriches flows from packet data and produces findings.

Covers TLS handshake analysis, certificate/CA inspection, TCP health, QUIC/HTTP3
detection, proxy/HTTP signals, certificate-pinning heuristics and the final
issue classification. Every finding carries supporting evidence (packet numbers,
timestamps, values) — nothing is invented.
"""
from __future__ import annotations

import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from .certs import CertInfo, analyze_leaf_chain, evaluate_at
from .pcap import Flow, Packet, _to_int
from . import tlsconst as T
from .secure_access import describe as describe_ingress, is_private_access, is_internal_flow
from .dns_analysis import (
    RCODE_LABELS,
    block_category_for_ip,
    dns_resolver_name,
    is_block_page_domain,
    is_swg_block_ip,
)


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Application-layer protocols we can name from tshark's frame.protocols string,
# in priority order (most specific / most useful first). Lets us describe an
# otherwise-opaque flow as "DNS", "QUIC", "OCSP", "NTP"... instead of "non-TLS".
_L7_PROTOCOLS = [
    ("mdns", "mDNS"), ("llmnr", "LLMNR"), ("nbns", "NBNS"), ("dns", "DNS"),
    ("dhcpv6", "DHCPv6"), ("dhcp", "DHCP"), ("bootp", "DHCP"),
    ("ssdp", "SSDP"), ("ntp", "NTP"), ("ocsp", "OCSP"),
    ("http2", "HTTP/2"), ("http3", "HTTP/3"), ("http", "HTTP"),
    ("quic", "QUIC"), ("tls", "TLS"), ("ssh", "SSH"),
    ("icmpv6", "ICMPv6"), ("icmp", "ICMP"), ("igmp", "IGMP"), ("arp", "ARP"),
]


def _l7_protocol(flow: "Flow") -> str | None:
    """Pick the most meaningful application protocol tshark saw on this flow."""
    seen: set[str] = set()
    for pkt in flow.packets:
        chain = pkt.first("frame.protocols")
        if chain:
            seen.update(chain.split(":"))
    for token, label in _L7_PROTOCOLS:
        if token in seen:
            return label
    return None


# One conversation can carry many lookups, and a resolver under load can carry a
# great many. Enough to show the pattern, bounded so a busy flow cannot grow the
# payload without limit.
_MAX_DNS_EXCHANGES = 12

# The query types worth naming. Anything else is shown by its numeric code.
_DNS_QTYPES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR",
               "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV",
               "43": "DS", "48": "DNSKEY", "64": "SVCB", "65": "HTTPS"}


def _dns_exchanges(flow: Flow) -> list[dict]:
    """What this flow asked the resolver, and what came back.

    Queries and answers are paired by transaction ID (RFC 1035 s4.1.1), which is
    what makes a request and its reply one exchange rather than two events. An
    entry with no rcode was never answered.
    """
    seen: dict[str, dict] = {}
    for pkt in flow.packets:
        name = pkt.first("dns.qry.name")
        if not name:
            continue
        # Fall back to the name when the ID is absent so a lone query still shows.
        txid = pkt.first("dns.id") or name
        entry = seen.get(txid)
        if entry is None:
            if len(seen) >= _MAX_DNS_EXCHANGES:
                continue
            entry = seen[txid] = {"name": name, "addresses": [], "cnames": [],
                                  "qtype": _DNS_QTYPES.get(
                                      (pkt.first("dns.qry.type") or "").split(",")[0],
                                      pkt.first("dns.qry.type") or "A"),
                                  "rcode": None, "answered": False}
        if pkt.first("dns.flags.response") != "1":
            continue
        entry["answered"] = True
        rcode = pkt.first("dns.flags.rcode")
        entry["rcode"] = _to_int(rcode) if rcode is not None else entry["rcode"]
        for key, bucket in (("dns.a", "addresses"), ("dns.aaaa", "addresses"),
                            ("dns.cname", "cnames")):
            for raw in pkt.all(key):
                for value in str(raw).split(","):
                    value = value.strip()
                    if value and value not in entry[bucket]:
                        entry[bucket].append(value)
    return list(seen.values())


# GREASE reserved values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa. They are
# deliberately random placeholders and must be ignored in version/cipher lists.
_GREASE = {f"0x{n:x}{n:x}" for n in
           (0x0a, 0x1a, 0x2a, 0x3a, 0x4a, 0x5a, 0x6a, 0x7a,
            0x8a, 0x9a, 0xaa, 0xba, 0xca, 0xda, 0xea, 0xfa)}


def _is_grease(value: str | None) -> bool:
    return bool(value) and value.lower() in _GREASE


# Named TLS supported-groups / key-exchange groups (RFC 8446 §4.2.7 + IANA),
# including the post-quantum hybrids now common in browsers. tshark may emit the
# value as decimal or 0x-hex, so we look both up.
_NAMED_GROUPS = {
    "0017": "secp256r1", "0018": "secp384r1", "0019": "secp521r1",
    "001d": "x25519", "001e": "x448",
    "0100": "ffdhe2048", "0101": "ffdhe3072", "0102": "ffdhe4096",
    "11ec": "X25519MLKEM768", "6399": "X25519Kyber768", "639a": "SecP256r1Kyber768",
    "23": "secp256r1", "24": "secp384r1", "25": "secp521r1",
    "29": "x25519", "30": "x448",
    # Decimal spellings of the post-quantum hybrids and FFDHE groups. tshark
    # prints these extensions in decimal, so without them a real X25519MLKEM768
    # negotiation would be reported as the bare number "4588".
    "4588": "X25519MLKEM768", "25497": "X25519Kyber768", "25498": "SecP256r1Kyber768",
    "256": "ffdhe2048", "257": "ffdhe3072", "258": "ffdhe4096",
}


def _named_group(val: str | None) -> str | None:
    if not val:
        return None
    hexkey = val.lower().removeprefix("0x")
    return _NAMED_GROUPS.get(hexkey) or _NAMED_GROUPS.get(val) or val


# RFC 8446 §4.1.3: a ServerHello carrying exactly this Random IS a
# HelloRetryRequest. The value is SHA-256("HelloRetryRequest") fixed by the spec,
# so matching it is exact, not heuristic.
_HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"


def _is_loopback(ip: str | None) -> bool:
    """True for IPv4/IPv6 loopback addresses (the local Secure Client roaming
    listener lives on 127.0.0.1, so its sockets must not be mistaken for
    on-the-wire connections)."""
    if not ip:
        return False
    return ip == "::1" or ip.startswith("127.")



@dataclass
class Finding:
    title: str
    severity: str                 # critical | high | medium | low | info
    category: str                 # maps to issue classification buckets
    detail: str
    evidence: list[str] = field(default_factory=list)
    flow_key: Optional[str] = None
    # Marks a finding that already SUMMARISES others of the same severity (for
    # example a capture-wide verdict whose per-flow findings are its own
    # components). Used only to break ties when picking the headline diagnosis,
    # so the summary states the conclusion rather than one of its inputs.
    is_verdict: bool = False


@dataclass
class FlowReport:
    flow: Flow
    leaf_cert: Optional[CertInfo] = None
    cert_chain: list[CertInfo] = field(default_factory=list)
    tls_status: str = "unknown"   # human-readable status
    # When the flow reached a Secure Access block page, the detected policy
    # category (e.g. "Malware", "Phishing", "Web policy (DLP / AI guardrail)").
    # Shown in the table instead of a misleading "TLS error" on the block-page
    # certificate.
    block_category: Optional[str] = None
    findings: list[Finding] = field(default_factory=list)


# --- Flow enrichment ---------------------------------------------------------

def _pkt_is_c2s(flow: Flow, pkt: Packet) -> bool:
    """True if this packet travels client -> server.

    Normally the client is the SYN sender (flow.src_ip), so a source-IP match
    decides direction. On LOOPBACK both endpoints share the same IP
    (127.0.0.1 / ::1), so the IP cannot disambiguate and every packet would look
    like c2s. In that case fall back to the source PORT: the client is the
    ephemeral SYN-sender port (flow.src_port)."""
    pkt_src = pkt.first("ip.src") or pkt.first("ipv6.src")
    if flow.src_ip and flow.dst_ip and flow.src_ip == flow.dst_ip and flow.src_port is not None:
        # Same-IP (loopback) — IP cannot disambiguate, use the source port.
        sport = _to_int(pkt.first("tcp.srcport"))
        if sport is None:
            sport = _to_int(pkt.first("udp.srcport"))
        if sport is not None:
            return sport == flow.src_port
    return bool(flow.src_ip and pkt_src == flow.src_ip)


def enrich_flow(flow: Flow) -> None:
    """Populate TLS / TCP / QUIC / HTTP derived fields on a flow."""
    offered_versions: set[str] = set()
    cert_hexes: list[str] = []
    # Key-share groups the client guessed BEFORE any HelloRetryRequest.
    _ks_groups_seen: list[str] = []

    for pkt in flow.packets:
        ht_names = [T.HANDSHAKE_TYPES.get(x) for x in pkt.all("tls.handshake.type")]
        is_server_hello = "ServerHello" in ht_names
        # TCP health
        if flow.transport == "tcp":
            if pkt.first("tcp.flags.reset") in ("1", "True"):
                flow.rst_count += 1
                # Track which side aborted: the SYN sender is the client (flow.src_ip).
                if _pkt_is_c2s(flow, pkt):
                    flow.client_reset = True
                else:
                    flow.server_reset = True
            if pkt.first("tcp.flags.syn") in ("1", "True"):
                flow.syn_count += 1
            if pkt.first("tcp.flags.fin") in ("1", "True"):
                flow.fin_count += 1
            if pkt.first("tcp.analysis.retransmission") is not None or \
               pkt.first("tcp.analysis.fast_retransmission") is not None or \
               pkt.first("tcp.analysis.spurious_retransmission") is not None:
                flow.retransmissions += 1
            # Track spurious (unnecessary) retransmissions separately so real loss
            # can be computed as retransmissions - spurious without changing the
            # legacy `retransmissions` total that existing findings rely on.
            if pkt.first("tcp.analysis.spurious_retransmission") is not None:
                flow.spurious_retransmissions += 1
            if pkt.first("tcp.analysis.lost_segment") is not None:
                flow.lost_segments += 1
            if pkt.first("tcp.analysis.out_of_order") is not None:
                flow.out_of_order += 1
            if pkt.first("tcp.analysis.duplicate_ack") is not None:
                flow.dup_acks += 1
            if pkt.first("tcp.analysis.zero_window") is not None:
                flow.zero_window += 1
            if pkt.first("tcp.analysis.window_full") is not None:
                flow.window_full += 1
            if pkt.first("tcp.analysis.ack_lost_segment") is not None:
                flow.ack_lost_segment += 1
            # Passive network-quality inputs (network RTT, RTT variation, loss
            # denominator). initial_rtt is present once per flow; ack_rtt recurs.
            _ir = pkt.first("tcp.analysis.initial_rtt")
            if _ir is not None and flow.initial_rtt_ms is None:
                try:
                    flow.initial_rtt_ms = round(float(str(_ir).split(",")[0]) * 1000.0, 2)
                except (TypeError, ValueError):
                    pass
            _ar = pkt.first("tcp.analysis.ack_rtt")
            if _ar is not None:
                try:
                    flow.ack_rtt_samples.append(float(str(_ar).split(",")[0]) * 1000.0)
                except (TypeError, ValueError):
                    pass
            _tl = _to_int(pkt.first("tcp.len"))
            if _tl and _tl > 0:
                flow.data_segments += 1
                if _tl > flow.max_tcp_len:
                    flow.max_tcp_len = _tl
            mss = _to_int(pkt.first("tcp.options.mss_val"))
            if mss is not None:
                flow.mss_values.append(mss)
                # The client's OWN advertised MSS = the SYN it sent as initiator
                # (syn=1, ack=0, src == flow.src_ip). Server SYN-ACK carries the
                # server's MSS, which is not what reveals the client path MTU.
                if (flow.client_mss is None
                        and pkt.first("tcp.flags.syn") in ("1", "True")
                        and pkt.first("tcp.flags.ack") not in ("1", "True")
                        and (pkt.first("ip.src") or pkt.first("ipv6.src")) == flow.src_ip):
                    flow.client_mss = mss

        # Directional packet/byte counts. The client is the SYN sender
        # (flow.src_ip); loopback is disambiguated by port via _pkt_is_c2s.
        if flow.transport == "tcp":
            nbytes = _to_int(pkt.first("tcp.len")) or 0
        else:
            nbytes = _to_int(pkt.first("udp.length")) or 0
        if flow.src_ip:
            if _pkt_is_c2s(flow, pkt):
                flow.pkts_c2s += 1
                flow.bytes_c2s += nbytes
            else:
                flow.pkts_s2c += 1
                flow.bytes_s2c += nbytes
                # First server->client packet: capture the remote host's IP TTL /
                # IPv6 hop-limit (reveals hop distance + a coarse OS guess).
                if flow.server_ttl is None:
                    ttl = _to_int(pkt.first("ip.ttl"))
                    if ttl is None:
                        ttl = _to_int(pkt.first("ipv6.hlim"))
                    if ttl is not None:
                        flow.server_ttl = ttl
                # A SYN/ACK from the server confirms the port was open/reachable.
                if (flow.transport == "tcp"
                        and pkt.first("tcp.flags.syn") in ("1", "True")
                        and pkt.first("tcp.flags.ack") in ("1", "True")):
                    flow.server_synack = True

        # QUIC detection
        if pkt.first("quic.header_form") is not None or "quic" in (pkt.first("frame.protocols") or ""):
            flow.is_quic = True

        # TLS handshake messages
        for ht in pkt.all("tls.handshake.type"):
            name = T.HANDSHAKE_TYPES.get(ht)
            if name == "ClientHello":
                flow.client_hello = True
            elif name == "ServerHello":
                flow.server_hello = True
            elif name == "Finished":
                flow.handshake_complete = True

        # Application-data records (content_type 23) prove the handshake finished,
        # which matters for TLS 1.2 where the Finished message itself is encrypted.
        for ct in pkt.all("tls.record.content_type"):
            if ct == "23":
                flow.app_data_seen = True

        sni = pkt.first("tls.handshake.extensions_server_name")
        if sni and not flow.sni:
            flow.sni = sni

        for a in pkt.all("tls.handshake.extensions_alpn_str"):
            if a and a not in flow.alpn:
                flow.alpn.append(a)

        # Negotiated version: prefer supported_versions (TLS1.3) then handshake.version
        for sv in pkt.all("tls.handshake.extensions.supported_version"):
            if _is_grease(sv):
                continue
            vn = T.version_name(sv)
            if vn:
                offered_versions.add(vn)
                # In a ServerHello, the supported_versions value IS the negotiated version
                if is_server_hello:
                    flow.negotiated_version = vn
        hv = pkt.first("tls.handshake.version")
        if hv and not _is_grease(hv):
            vn = T.version_name(hv)
            if vn:
                # Legacy ServerHello version (only trust if no supported_versions seen)
                if is_server_hello and not flow.negotiated_version:
                    flow.negotiated_version = vn
                offered_versions.add(vn)

        # Cipher: take the single suite chosen in the ServerHello (skip GREASE)
        cs = pkt.first("tls.handshake.ciphersuite")
        if cs and not _is_grease(cs) and (is_server_hello or not flow.cipher_suite):
            if is_server_hello or flow.cipher_suite is None:
                flow.cipher_suite = T.CIPHER_SUITES.get(cs, cs)

        for c in pkt.all("tls.handshake.certificate"):
            if c:
                cert_hexes.append(c)

        # Passive TLS fingerprints (visible even on TLS 1.3). JA3 is on the
        # ClientHello, JA3S on the ServerHello. Key-exchange group: the server
        # picks one in its key_share, which is the negotiated group.
        j3 = pkt.first("tls.handshake.ja3")
        if j3 and not flow.ja3:
            flow.ja3 = j3
        j3s = pkt.first("tls.handshake.ja3s")
        if j3s and is_server_hello and not flow.ja3s:
            flow.ja3s = j3s
        ksg = pkt.first("tls.handshake.extensions_key_share_group")
        if ksg and not _is_grease(ksg) and (is_server_hello or not flow.key_share_group):
            flow.key_share_group = _named_group(ksg)

        # HelloRetryRequest (RFC 8446 §4.1.4). It is carried as a ServerHello
        # whose Random is a fixed SHA-256 constant, so it is identified by that
        # value rather than by a message type of its own.
        if is_server_hello and not flow.hello_retry_request:
            rnd = (pkt.first("tls.handshake.random") or "").replace(":", "").lower()
            if rnd == _HRR_RANDOM:
                flow.hello_retry_request = True
                # What the rejected first ClientHello had guessed.
                flow.hrr_offered_groups = [
                    g for g in (_named_group(x) for x in _ks_groups_seen) if g
                ]
        # Key-share groups the CLIENT offered, in order, so the pre- and
        # post-HelloRetryRequest guesses can be compared.
        if "ClientHello" in ht_names:
            for x in pkt.all("tls.handshake.extensions_key_share_group"):
                for part in str(x).split(","):
                    part = part.strip()
                    if part and not _is_grease(part):
                        if flow.hello_retry_request:
                            flow.hrr_selected_group = _named_group(part)
                        elif part not in _ks_groups_seen:
                            _ks_groups_seen.append(part)

        # ECH extension
        for ext in pkt.all("tls.handshake.extension.type"):
            if ext in T.ECH_EXTENSION_TYPES:
                flow.has_ech = True

        # TLS alerts
        levels = pkt.all("tls.alert_message.level")
        descs = pkt.all("tls.alert_message.desc")
        for i, d in enumerate(descs):
            lvl = levels[i] if i < len(levels) else None
            flow.alerts.append({
                "packet": str(pkt.number),
                "time": f"{pkt.time_relative:.6f}",
                "level": T.alert_level(lvl) or "?",
                "desc": T.alert_desc(d) or d,
            })

        # HTTP / proxy
        method = pkt.first("http.request.method")
        if method:
            uri = pkt.first("http.request.full_uri") or pkt.first("http.request.uri")
            flow.http_requests.append({
                "packet": pkt.number,
                "method": method,
                "uri": uri,
                "host": pkt.first("http.host"),
            })
            # Explicit-proxy HTTP CONNECT tunnel: the client asks the proxy to
            # open a raw tunnel to the real destination (host:port).
            if method.upper() == "CONNECT":
                flow.is_connect_tunnel = True
                if uri and not flow.connect_target:
                    flow.connect_target = uri
                # The peer the client is connecting to here is the proxy itself.
                if not flow.proxy_ip:
                    flow.proxy_ip = pkt.first("ip.dst")
        code = pkt.first("http.response.code")
        if code:
            flow.http_statuses.append(code)
            # First response on a CONNECT stream is the tunnel-establishment status.
            if flow.is_connect_tunnel and flow.connect_status is None:
                flow.connect_status = code
                flow.connect_phrase = pkt.first("http.response.phrase")
        h2status = pkt.first("http2.headers.status")
        if h2status:
            flow.http_statuses.append(h2status)
        h2method = pkt.first("http2.headers.method")
        if h2method:
            flow.http_requests.append({
                "packet": pkt.number,
                "method": h2method,
                "uri": pkt.first("http2.headers.authority"),
                "host": pkt.first("http2.headers.authority"),
            })

    flow.offered_versions = sorted(offered_versions)
    if cert_hexes:
        flow.certificates_hex = cert_hexes

    # Segments larger than any MSS negotiated on this connection cannot have
    # existed on the wire: TCP may never send more than the peer advertised. They
    # are TSO/LSO/GSO super-segments, seen only because the capture was taken on
    # the host above the NIC that still has to split them. Comparing against the
    # LARGEST advertised MSS keeps this conservative (no false positives).
    #
    # Two deliberate exclusions: a flow whose SYN was not captured has no known
    # MSS, and guessing one would manufacture the very artifact we are looking
    # for; and loopback never traverses a NIC, so its 64 KB segments are normal
    # rather than pending offload.
    #
    # The 2x threshold is what makes this proof rather than suspicion: offloading
    # is only worth doing when the OS hands the card MORE than one segment, so a
    # genuine super-segment always holds at least two MSS-sized chunks. A payload
    # only marginally above the MSS is far more likely to be a differing MSS on
    # another SYN of the same conversation.
    if (flow.transport == "tcp" and flow.max_tcp_len and flow.mss_values
            and not _is_loopback(flow.src_ip) and not _is_loopback(flow.dst_ip)):
        mss_cap = max(flow.mss_values)
        if flow.max_tcp_len >= 2 * mss_cap:
            flow.oversized_segments = sum(
                1 for pkt in flow.packets
                if (_to_int(pkt.first("tcp.len")) or 0) > mss_cap
            )

    # Describe the flow even when there's no TLS: detected L7 protocol, the
    # cleartext DNS query name (if any), and whether either endpoint is a known
    # public DNS resolver (so DoH/DoT on 443/853 is still recognised as DNS).
    flow.l7_protocol = _l7_protocol(flow)
    for pkt in flow.packets:
        q = pkt.first("dns.qry.name")
        if q:
            flow.dns_query = q
            break
    flow.dns_exchanges = _dns_exchanges(flow)
    flow.dns_resolver = dns_resolver_name(flow.dst_ip) or dns_resolver_name(flow.src_ip)

    # Latency markers. TCP handshake RTT = client SYN (syn=1, ack=0) -> server
    # SYN/ACK (syn=1, ack=1). TLS setup = ClientHello -> ServerHello.
    t_syn = t_synack = t_ch = t_sh = None
    for pkt in flow.packets:
        if flow.transport == "tcp":
            syn = pkt.first("tcp.flags.syn") in ("1", "True")
            ack = pkt.first("tcp.flags.ack") in ("1", "True")
            if syn and not ack and t_syn is None:
                t_syn = pkt.time_relative
            elif syn and ack and t_synack is None:
                t_synack = pkt.time_relative
        types = pkt.all("tls.handshake.type")
        if t_ch is None and "1" in types:
            t_ch = pkt.time_relative
        if "2" in types:
            # A HelloRetryRequest is also handshake type 2, but it does not end
            # the negotiation — the client must send a second ClientHello and
            # wait for the real ServerHello. Stopping at the first type 2 would
            # report roughly half the true setup time, so on an HRR flow we take
            # the LAST one.
            if t_sh is None or flow.hello_retry_request:
                t_sh = pkt.time_relative
    if t_syn is not None and t_synack is not None and t_synack >= t_syn:
        flow.tcp_handshake_ms = round((t_synack - t_syn) * 1000.0, 1)
    if t_ch is not None and t_sh is not None and t_sh >= t_ch:
        flow.tls_setup_ms = round((t_sh - t_ch) * 1000.0, 1)



# --- Connection ladder (per-packet timeline) ---------------------------------

def _timeline_entry(flow: Flow, pkt: Packet) -> dict:
    """Turn one packet into a compact, human-readable ladder event."""
    direction = "c2s" if _pkt_is_c2s(flow, pkt) else "s2c"

    syn = pkt.first("tcp.flags.syn") in ("1", "True")
    ack = pkt.first("tcp.flags.ack") in ("1", "True")
    fin = pkt.first("tcp.flags.fin") in ("1", "True")
    rst = pkt.first("tcp.flags.reset") in ("1", "True")
    nbytes = _to_int(pkt.first("tcp.len")) or _to_int(pkt.first("udp.length")) or 0

    ht = [T.HANDSHAKE_TYPES.get(x) for x in pkt.all("tls.handshake.type")]
    ht = [h for h in ht if h]
    descs = pkt.all("tls.alert_message.desc")

    if ht:
        label, kind = ", ".join(dict.fromkeys(ht)), "tls"
    elif descs:
        label = "Alert: " + ", ".join(T.alert_desc(d) or d for d in descs)
        kind = "alert"
    elif rst:
        label, kind = "RST", "rst"
    elif syn and ack:
        label, kind = "SYN/ACK", "synack"
    elif syn:
        label, kind = "SYN", "syn"
    elif fin:
        label, kind = "FIN", "fin"
    elif nbytes > 0:
        label, kind = f"Data {nbytes}B", "data"
    elif ack:
        label, kind = "ACK", "ack"
    else:
        label, kind = "\u2014", "ack"

    suffix = []
    if rst and kind != "rst":
        suffix.append("RST")
    if fin and kind != "fin":
        suffix.append("FIN")
    if suffix:
        label = f"{label} +{'/'.join(suffix)}"

    anomalies = []
    if (pkt.first("tcp.analysis.retransmission") is not None
            or pkt.first("tcp.analysis.fast_retransmission") is not None
            or pkt.first("tcp.analysis.spurious_retransmission") is not None):
        anomalies.append("retransmission")
    if pkt.first("tcp.analysis.lost_segment") is not None:
        anomalies.append("lost segment")
    if pkt.first("tcp.analysis.out_of_order") is not None:
        anomalies.append("out-of-order")
    if pkt.first("tcp.analysis.duplicate_ack") is not None:
        anomalies.append("duplicate ACK")
    if pkt.first("tcp.analysis.zero_window") is not None:
        anomalies.append("zero window")
    if pkt.first("tcp.analysis.ack_lost_segment") is not None:
        anomalies.append("ACKed unseen segment")

    return {
        "n": pkt.number,
        "t": round(pkt.time_relative, 4),
        "dir": direction,
        "label": label,
        "bytes": nbytes,
        "kind": kind,
        "anomalies": anomalies,
    }


def flow_timeline(flow: Flow, head: int = 120, tail: int = 60) -> dict:
    """Build the left<->right packet ladder for a flow. Long flows are summarised
    (first ``head`` + last ``tail`` events) so the connection's open AND close
    stay visible; the omitted middle is reported as a gap marker."""
    events = [_timeline_entry(flow, p) for p in flow.packets]
    total = len(events)
    if total <= head + tail + 10:
        return {"events": events, "total": total, "omitted": 0}
    kept = events[:head] + [{"gap": total - head - tail}] + events[total - tail:]
    return {"events": kept, "total": total, "omitted": total - head - tail}


# --- Connection story (the ladder, grouped by layer and explained) ------------
#
# flow_timeline() says what crossed the wire. This says what it meant, in the
# order an engineer reads a connection: did the name resolve, did the socket
# open, did the encryption negotiate. It adds no new measurement - every step
# carries the frame number it came from, so any line can be checked in Wireshark.

def _ms(a: float | None, b: float | None) -> float | None:
    if a is None or b is None or b < a:
        return None
    return round((b - a) * 1000, 1)


def _fact(label: str, value: Any, tone: str = "plain", note: str = "") -> dict:
    return {"label": label, "value": str(value), "tone": tone, "note": note}


def _human_bytes(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1000:
        return f"{n / 1000:.0f} KB"
    return f"{n} B"


def _story_dns_conversation(flow: Flow) -> dict | None:
    """This flow is the DNS conversation. Report each name it asked for and the
    addresses that came back - the answer an address-keyed correlation cannot
    give, because this flow's destination is the resolver, not the resolved host.
    """
    steps: list[dict] = []
    facts: list[dict] = []
    resolved = failed = silent = 0

    for ex in flow.dns_exchanges:
        name = ex.get("name") or "?"
        addrs = ex.get("addresses") or []
        rcode = ex.get("rcode")
        qtype = ex.get("qtype") or "A"
        steps.append({"dir": "c2s", "msg": f"Query {qtype}? {name}", "note": "", "bad": False})

        if not ex.get("answered"):
            silent += 1
            steps.append({"dir": "s2c", "msg": "No response",
                          "note": "the resolver never answered", "bad": True})
            facts.append(_fact(name, "no response", "bad"))
            continue

        if rcode:
            failed += 1
            label, why = RCODE_LABELS.get(rcode, (str(rcode), ""))
            steps.append({"dir": "s2c", "msg": f"Response {label}",
                          "note": why, "bad": True})
            facts.append(_fact(name, label, "bad", why))
            continue

        resolved += 1
        cnames = ex.get("cnames") or []
        # An AAAA with no answer is an ordinary NODATA on an IPv4-only name, and
        # a CNAME-only reply still resolved. Neither is worth flagging.
        empty_is_normal = qtype != "A" or bool(cnames)
        shown = ", ".join(addrs[:3]) + (f" (+{len(addrs) - 3} more)" if len(addrs) > 3 else "")
        steps.append({
            "dir": "s2c",
            "msg": f"Response {shown if addrs else 'no address'}",
            "ok_token": "rcode: NoError",
            "note": "" if addrs or empty_is_normal else "answered, but carried no address",
            "bad": False,
        })
        facts.append(_fact(
            f"{name} ({qtype})",
            ", ".join(addrs[:4]) + (f" (+{len(addrs) - 4})" if len(addrs) > 4 else "")
            if addrs else "no address",
            "plain" if addrs or empty_is_normal else "warn"))
        if cnames:
            facts.append(_fact(f"{name} via", " \u2192 ".join(cnames[:3])))

    if not steps:
        return None

    resolver = flow.dst_ip
    if resolver:
        named = dns_resolver_name(resolver)
        facts.insert(0, _fact(
            "Resolver", f"{resolver}{f' ({named})' if named else ''}",
            "warn" if _is_loopback(resolver) else "plain",
            "answered by software on this host, not a network resolver"
            if _is_loopback(resolver) else ""))

    total = resolved + failed + silent
    if silent:
        status, summary = "fail", f"{silent} of {total} unanswered"
    elif failed:
        status, summary = "fail", f"{failed} of {total} did not resolve"
    else:
        status, summary = "ok", f"resolved {resolved} name{'s' if resolved != 1 else ''}"
    return {"name": "DNS", "status": status, "summary": summary,
            "steps": steps, "facts": facts}


def _story_dns(flow: Flow) -> dict | None:
    # A flow that carries lookups is the conversation itself; dns_lookup is the
    # other direction, tying some other flow's address back to a name.
    if flow.dns_exchanges:
        return _story_dns_conversation(flow)

    lookup = flow.dns_lookup
    if not lookup:
        return None

    name = lookup.get("name") or ""
    addrs = lookup.get("addresses") or []
    rcode = lookup.get("rcode")
    elapsed = _ms(lookup.get("query_time"), lookup.get("response_time"))

    # This record was matched to the flow by address. When the request on the
    # connection names a different host - common on a shared block page, where
    # many names resolve to one address - the request is the authority and the
    # mismatch has to be said out loud rather than shown as a coincidence.
    asked = {r.get("host") for r in flow.http_requests if r.get("host")}
    conflict = name and asked and name not in asked
    mismatch = (f"Matched to this connection by address. The request on it asked for "
                f"{', '.join(sorted(asked)[:2])}, so several names share this address "
                f"and this record may describe a different one.") if conflict else ""

    steps = [{
        "dir": "c2s", "msg": f"Query A? {name}",
        "note": "asks for the server's address", "bad": False,
    }]

    if lookup.get("blocked"):
        category = lookup.get("block_category")
        steps.append({
            "dir": "s2c",
            "msg": f"Response {', '.join(addrs) if addrs else 'n/a'}",
            "note": "answered with a block address"
                    + (f" ({category})" if category else ""),
            "bad": True,
        })
        return {"name": "DNS", "status": "fail",
                "summary": "blocked by the resolver", "steps": steps, "why": mismatch}

    if rcode not in (None, 0, "0"):
        steps.append({"dir": "s2c", "msg": f"Response rcode: {rcode}",
                      "note": "the name did not resolve", "bad": True})
        return {"name": "DNS", "status": "fail",
                "summary": f"failed - rcode {rcode}", "steps": steps, "why": mismatch}

    steps.append({
        "dir": "s2c",
        "msg": f"Response {', '.join(addrs[:3]) if addrs else 'no address'}",
        "ok_token": "rcode: NoError",
        "note": "valid address returned", "bad": False,
    })

    facts = []
    resolver = lookup.get("resolver")
    if resolver:
        named = lookup.get("resolver_name")
        facts.append(_fact(
            "Resolver", f"{resolver}{f' ({named})' if named else ''}",
            "warn" if _is_loopback(resolver) else "plain",
            "answered by software on this host, not a network resolver"
            if _is_loopback(resolver) else ""))
    if len(addrs) > 1:
        facts.append(_fact("Addresses returned", len(addrs)))
    cnames = lookup.get("cnames") or []
    if cnames:
        facts.append(_fact("CNAME chain", " \u2192 ".join(cnames[:4])))

    summary = "resolved" + (f" \u00b7 {elapsed:g} ms" if elapsed is not None else "")
    return {"name": "DNS", "status": "ok" if addrs else "warn",
            "summary": summary, "steps": steps, "facts": facts, "why": mismatch}


def _story_tcp(flow: Flow, marks: list[tuple]) -> dict | None:
    if flow.transport != "tcp":
        return None

    syn = next((m for m in marks if m[1]["kind"] == "syn"), None)
    synack = next((m for m in marks if m[1]["kind"] == "synack"), None)
    steps: list[dict] = []

    if syn:
        steps.append({"dir": "c2s", "msg": "SYN", "pkt": syn[0].number,
                      "note": "client requests to open a connection", "bad": False})
    if synack:
        steps.append({"dir": "s2c", "msg": "SYN, ACK", "pkt": synack[0].number,
                      "note": "server agrees", "bad": False})
        first_ack = next(
            (m for m in marks
             if m[1]["kind"] == "ack" and m[1]["dir"] == "c2s"
             and m[0].time_relative >= synack[0].time_relative), None)
        if first_ack:
            steps.append({"dir": "c2s", "msg": "ACK", "pkt": first_ack[0].number,
                          "note": "connection established", "bad": False})

    if not steps:
        # Capture began mid-session: the open is simply not in this file.
        return {"name": "TCP", "status": "absent", "summary": "handshake not captured",
                "steps": [], "why": "This capture starts after the connection was "
                                    "already open, so the three-way handshake is not in it."}

    if not synack:
        return {"name": "TCP", "status": "fail",
                "summary": "no answer to SYN", "steps": steps,
                "why": "The server never completed the three-way handshake."}

    rtt = flow.tcp_handshake_ms
    summary = "connected \u00b7 3-way handshake" + (f", {rtt:g} ms" if rtt else "")

    # Health is only worth stating when it is not the boring answer: a clean
    # transport says nothing, a stalled or lossy one changes what you do next.
    facts = []
    if flow.initial_rtt_ms is not None:
        facts.append(_fact("Network round trip", f"{flow.initial_rtt_ms:g} ms"))
    if len(flow.ack_rtt_samples) > 1:
        spread = round(statistics.pstdev(flow.ack_rtt_samples), 1)
        facts.append(_fact(
            "Round-trip variation", f"\u00b1{spread:g} ms over {len(flow.ack_rtt_samples)} samples",
            "warn" if flow.initial_rtt_ms and spread > flow.initial_rtt_ms else "plain"))
    real_loss = flow.retransmissions - flow.spurious_retransmissions
    if real_loss > 0:
        # Only state a ratio when there is a denominator that can hold it;
        # retransmissions are counted per frame and can exceed the segments
        # carrying new payload.
        segments = flow.data_segments
        value = (f"{real_loss} of {segments} data segments"
                 if segments and segments >= real_loss else f"{real_loss} segment(s)")
        facts.append(_fact(
            "Retransmitted", value, "bad",
            "the sender had to repeat data that did not arrive"))
    if flow.lost_segments:
        facts.append(_fact("Segments the capture never saw", flow.lost_segments, "bad"))
    if flow.zero_window:
        facts.append(_fact(
            "Receiver stalled", f"{flow.zero_window} zero-window event(s)", "bad",
            "the receiver told the sender to stop - an application stall, not loss"))
    if flow.window_full:
        facts.append(_fact(
            "Receive window filled", f"{flow.window_full} time(s)", "warn",
            "throughput capped by window size, nothing lost"))
    if flow.ack_lost_segment:
        facts.append(_fact(
            "Acknowledged unseen data", flow.ack_lost_segment, "warn",
            "one direction travelled a path this capture point cannot see"))
    if flow.client_mss and flow.client_mss < 1460:
        facts.append(_fact(
            "Client MSS", f"{flow.client_mss} B", "warn",
            "below the 1460 B Ethernet default - something in the path adds overhead"))
    if flow.server_ttl is not None:
        hops = _estimated_hops(flow.server_ttl)
        facts.append(_fact(
            "Distance to peer",
            f"~{hops} hop(s)" if hops is not None else f"TTL {flow.server_ttl}",
            "plain", f"TTL {flow.server_ttl} on the way back"
            if hops is not None else ""))

    # A segment larger than the MSS the peer agreed to was never a wire frame:
    # the OS handed the NIC one buffer and the hardware split it. Packet counts
    # and per-packet timing on this flow describe the host, not the network.
    negotiated = min(flow.mss_values) if flow.mss_values else None
    if negotiated and flow.max_tcp_len > negotiated:
        facts.append(_fact(
            "Largest segment", f"{flow.max_tcp_len} B vs {negotiated} B agreed", "warn",
            "captured above the network card, so these are not individual "
            "wire frames - read packet counts and per-packet timing with that in mind"))

    if flow.rst_count:
        who = ("client" if flow.client_reset else
               "server" if flow.server_reset else "one side")
        facts.append(_fact("Closed by", f"reset from the {who}", "warn",
                           "an abrupt close, not a negotiated shutdown"))
    elif flow.fin_count:
        facts.append(_fact("Closed by", "FIN - orderly shutdown"))

    return {"name": "TCP", "status": "ok", "summary": summary, "steps": steps,
            "facts": facts}


def _story_tls(flow: Flow, marks: list[tuple], rep: Any = None) -> dict | None:
    hello = next((m for m in marks if "ClientHello" in m[1]["label"]), None)
    if hello is None:
        return None

    detail = []
    if flow.negotiated_version or flow.offered_versions:
        detail.append(flow.negotiated_version or "/".join(flow.offered_versions))
    if flow.alpn:
        detail.append("ALPN " + ", ".join(flow.alpn))
    if hello[1].get("bytes"):
        detail.append(f"{hello[1]['bytes']} B")

    # Collected with their packet time, then sorted: the sequence is the whole
    # argument, so a step shown out of order would misrepresent what happened.
    steps: list[tuple[float, dict]] = [(hello[0].time_relative, {
        "dir": "c2s", "msg": "ClientHello", "detail": " \u00b7 ".join(detail),
        "pkt": hello[0].number,
        "note": "proposes encryption, names the host it wants", "bad": False,
    })]

    after_hello = [m for m in marks if m[0].time_relative >= hello[0].time_relative]
    server_hello = next((m for m in after_hello if "ServerHello" in m[1]["label"]), None)
    if server_hello:
        steps.append((server_hello[0].time_relative, {
            "dir": server_hello[1]["dir"], "msg": "ServerHello",
            "pkt": server_hello[0].number,
            "note": "server picks the cipher and replies", "bad": False}))

    cert = next((m for m in after_hello
                 if "Certificate" in m[1]["label"] and m is not server_hello), None)
    if cert:
        steps.append((cert[0].time_relative, {
            "dir": cert[1]["dir"], "msg": "Certificate", "pkt": cert[0].number,
            "note": "server presents its certificate", "bad": False}))

    alert = next((m for m in marks if m[1]["kind"] == "alert"), None)
    rst = next((m for m in marks if m[1]["kind"] == "rst"), None)

    # An ACK from the server for the ClientHello, arriving before the server's
    # own reset, is the difference between "dropped in the path" and "read, then
    # refused". It only means that when the server is the one that reset.
    acked_hello = None
    if rst and rst[1]["dir"] == "s2c" and server_hello is None:
        acked_hello = next(
            (m for m in after_hello
             if m[1]["dir"] == "s2c" and m[1]["kind"] == "ack"
             and m[0].time_relative < rst[0].time_relative), None)
        if acked_hello:
            steps.append((acked_hello[0].time_relative, {
                "dir": "s2c", "msg": "ACK", "pkt": acked_hello[0].number,
                "note": "server confirms it received the ClientHello", "bad": False}))

    if alert:
        steps.append((alert[0].time_relative, {
            "dir": alert[1]["dir"], "msg": alert[1]["label"], "pkt": alert[0].number,
            "note": "the peer refused and said why", "bad": True}))

    if rst:
        gap = _ms(hello[0].time_relative, rst[0].time_relative)
        who = "client" if rst[1]["dir"] == "c2s" else "server"
        note = f"{who} tore the connection down"
        if gap is not None:
            note += f" {gap:g} ms after the ClientHello"
        if server_hello is None and alert is None:
            note += ". No ServerHello, no alert."
        steps.append((rst[0].time_relative,
                      {"dir": rst[1]["dir"], "msg": "RST", "pkt": rst[0].number,
                       "note": note, "bad": True}))

    ordered = [step for _, step in sorted(steps, key=lambda pair: pair[0])]

    facts = []
    if flow.has_ech:
        facts.append(_fact(
            "Encrypted ClientHello", "in use", "warn",
            "the requested hostname is encrypted, so this connection cannot be "
            "attributed to a site from the capture alone"))
    if flow.cipher_suite:
        facts.append(_fact("Cipher", flow.cipher_suite))
    if flow.key_share_group:
        facts.append(_fact("Key exchange", flow.key_share_group))
    if flow.tls_setup_ms is not None:
        tone, note = "plain", ""
        # TLS negotiation costs a couple of round trips. Far more than that,
        # against a fast socket, means something re-terminated the session.
        if flow.tcp_handshake_ms and flow.tls_setup_ms > flow.tcp_handshake_ms * 5:
            tone = "warn"
            note = (f"{flow.tls_setup_ms / flow.tcp_handshake_ms:.0f}x the TCP "
                    "handshake - the peer negotiated onward before answering")
        facts.append(_fact("TLS setup", f"{flow.tls_setup_ms:g} ms", tone, note))
    if flow.hello_retry_request:
        facts.append(_fact(
            "Retried key exchange",
            f"{'/'.join(flow.hrr_offered_groups) or 'first choice'} refused, "
            f"restarted with {flow.hrr_selected_group or 'another group'}",
            "warn", "costs one extra round trip"))
    if flow.ja3:
        facts.append(_fact("JA3 (client stack)", flow.ja3))
    if flow.ja3s:
        facts.append(_fact("JA3S (server stack)", flow.ja3s))

    cert = getattr(rep, "leaf_cert", None) if rep else None
    if cert and not getattr(cert, "parse_error", None):
        if cert.subject_cn:
            facts.append(_fact("Certificate subject", cert.subject_cn))
        issuer = cert.issuer_cn or cert.issuer_org
        if issuer:
            facts.append(_fact(
                "Issued by", issuer,
                "warn" if cert.looks_like_proxy_ca else "plain",
                "a locally trusted CA, not a public one - this session was "
                "decrypted and re-signed" if cert.looks_like_proxy_ca else ""))
        if cert.not_after:
            facts.extend(_cert_validity_facts(cert, flow))

    shape = {
        "steps": ordered,
        "facts": facts,
        "acked_hello": bool(acked_hello),
        "server_hello": bool(server_hello),
        "reset_by": (rst[1]["dir"] if rst else None),
        "alert_by": (alert[1]["dir"] if alert else None),
    }

    if alert:
        return {"name": "TLS", "status": "fail",
                "summary": "failed \u00b7 alert raised", **shape}
    if rst and not flow.handshake_complete:
        who = "client" if rst[1]["dir"] == "c2s" else "server"
        return {"name": "TLS", "status": "fail",
                "summary": f"failed \u00b7 reset by the {who}", **shape}
    if flow.handshake_complete:
        return {"name": "TLS", "status": "ok",
                "summary": "negotiated \u00b7 " + (flow.negotiated_version or "encrypted"),
                **shape}
    if not server_hello:
        return {"name": "TLS", "status": "warn",
                "summary": "no reply to ClientHello", **shape}
    return {"name": "TLS", "status": "ok", "summary": "negotiated", **shape}


def _story_tunnel(flow: Flow) -> dict | None:
    """The hop the connection was actually carried over, when there was one.

    A CONNECT tunnel or a local interception agent means the TLS above was
    negotiated with a middlebox, not with the destination. Without this the
    story would name the wrong peer.
    """
    if not (flow.is_connect_tunnel or flow.intercept_vendor or flow.chain_loopback_key):
        return None

    steps: list[dict] = []
    facts: list[dict] = []
    status = "ok"

    if flow.is_connect_tunnel:
        target = flow.connect_target or "the destination"
        steps.append({"dir": "c2s", "msg": f"CONNECT {target}",
                      "note": "asks the proxy to open a tunnel", "bad": False})
        code = flow.connect_status
        ok = str(code).startswith("2") if code else False
        steps.append({
            "dir": "s2c", "msg": f"{code or '?'} {flow.connect_phrase or ''}".strip(),
            "note": "tunnel established" if ok else "the proxy refused the tunnel",
            "bad": not ok,
        })
        if not ok:
            status = "fail"
        if flow.proxy_ip:
            facts.append(_fact("Proxy", flow.proxy_ip))
        if flow.tunnel_sni:
            facts.append(_fact(
                "Inner TLS", f"{flow.tunnel_sni}"
                + (f" \u00b7 {flow.tunnel_tls_version}" if flow.tunnel_tls_version else ""),
                "plain", "the session carried inside the tunnel"))

    if flow.intercept_vendor:
        facts.append(_fact(
            "Terminated locally by", flow.intercept_vendor, "warn",
            "this leg was decrypted on this machine before being sent on"))
        facts.append(_fact(
            "Outbound leg",
            flow.chain_outbound_key or "not captured",
            "plain" if flow.chain_outbound_key else "warn",
            "" if flow.chain_outbound_key
            else "the agent forwarded it on a path this capture did not see"))
    elif flow.chain_loopback_key:
        facts.append(_fact(
            "Decrypted copy seen on loopback", flow.chain_loopback_key, "warn",
            "correlated by hostname and time, not cryptographic proof"))

    summary = ("tunnel refused" if status == "fail"
               else "carried through an intermediary")
    return {"name": "TUNNEL", "status": status, "summary": summary,
            "steps": steps, "facts": facts}


def _story_data(flow: Flow) -> dict | None:
    """What the connection actually moved, once it was up."""
    down, up = flow.bytes_s2c or 0, flow.bytes_c2s or 0
    if not (down or up) or not flow.packets:
        return None

    duration = flow.packets[-1].time_relative - flow.packets[0].time_relative
    facts = [_fact("Transferred",
                   f"{_human_bytes(down)} in, {_human_bytes(up)} out")]
    if duration > 0.5:
        facts.append(_fact("Open for", f"{duration:.1f} s"))
        rate = down / duration
        tone = "bad" if (flow.zero_window and rate < 100_000) else "plain"
        facts.append(_fact(
            "Average inbound rate", f"{_human_bytes(int(rate))}/s", tone,
            "far below what this round trip allows - the receiver was the limit"
            if tone == "bad" else ""))
    if flow.data_segments:
        facts.append(_fact("Data segments", flow.data_segments))

    return {"name": "DATA", "status": "ok", "summary": "transfer observed",
            "steps": [], "facts": facts}


def _estimated_hops(ttl: int) -> int | None:
    """Distance to the peer, from how far its TTL has been decremented.

    Senders start at 64, 128 or 255; routers decrement once per hop. The nearest
    starting value above the observed TTL gives the hop count.
    """
    for start in (64, 128, 255):
        if ttl <= start:
            return start - ttl
    return None


def _story_http(flow: Flow) -> dict | None:
    """What the application actually asked for, and what it was told.

    This is the only layer that carries the server's own words. A 403 here is
    the block itself, not an inference drawn from an address.
    """
    requests = [r for r in flow.http_requests if (r.get("method") or "").upper() != "CONNECT"]
    statuses = [s for s in flow.http_statuses if s]
    if not requests and not statuses:
        return None

    steps: list[dict] = []
    for req in requests[:3]:
        target = req.get("uri") or req.get("host") or ""
        steps.append({
            "dir": "c2s", "msg": f"{req.get('method', 'GET')} {target}"[:120],
            "pkt": req.get("packet"),
            "note": "the request the application made", "bad": False,
        })

    worst = "ok"
    for code in statuses[:3]:
        first = code[:1]
        redirect = first == "3"
        bad = first in ("4", "5")
        note = {
            "403": "forbidden - the server refused this request outright",
            "407": "the proxy demands authentication",
            "451": "blocked for legal or policy reasons",
        }.get(code, "")
        if not note:
            if redirect:
                note = "redirected elsewhere - often to a block or captive page"
            elif bad:
                note = "the server rejected the request"
            else:
                note = "the request was served"
        steps.append({"dir": "s2c", "msg": f"HTTP {code}", "note": note, "bad": bad})
        if bad:
            worst = "fail"
        elif redirect and worst == "ok":
            worst = "warn"

    facts = []
    hosts = {r.get("host") for r in requests if r.get("host")}
    if hosts:
        facts.append(_fact("Requested host", ", ".join(sorted(hosts)[:3])))
    if len(requests) > 3 or len(statuses) > 3:
        facts.append(_fact("Exchanges on this connection",
                           f"{len(requests)} request(s), {len(statuses)} response(s)"))

    summary = {"fail": "the server refused", "warn": "redirected"}.get(
        worst, "served in the clear")
    return {"name": "HTTP", "status": worst, "summary": summary,
            "steps": steps, "facts": facts}


def _flow_moment(flow: Flow) -> float | None:
    """When the traffic happened - the only defensible clock for judging it."""
    return flow.packets[0].time_epoch if flow.packets else None


def _cert_validity_facts(cert: Any, flow: Flow) -> list[dict]:
    """State the certificate's validity window and whether it held at the time.

    Nothing is flagged for expiring "soon". Time remaining is not a defect, and
    it cannot be read without knowing the issuing policy: an interception proxy
    mints certificates with a five-day life, so one day left is that certificate
    working exactly as intended.
    """
    window = evaluate_at(cert, _flow_moment(flow))
    if window.not_after is None:
        return []

    span = (f"{window.not_before.date()} \u2192 {window.not_after.date()}"
            if window.not_before else f"until {window.not_after.date()}")
    if window.status == "unknown":
        return [_fact("Certificate validity", span)]

    if window.status == "expired":
        lasted = (f" It was issued for {window.lifetime_days} days."
                  if window.lifetime_days is not None else "")
        return [_fact(
            "Certificate validity", span, "bad",
            f"expired {window.days_outside} day(s) before this connection was made "
            f"on {window.at.date()}.{lasted} The client was offered a certificate "
            "that no longer validated, which on its own is enough for it to refuse "
            "the handshake - renewing it is the fix, nothing about the network is wrong")]

    if window.status == "not_yet_valid":
        return [_fact(
            "Certificate validity", span, "bad",
            f"not valid yet: it only became valid {window.days_outside} day(s) after "
            f"this connection on {window.at.date()}. Either the certificate was "
            "issued with a future start date or the endpoint's clock is behind, and "
            "a client rejects both the same way")]

    return [_fact("Certificate validity", span, "plain",
                  "valid when this connection was made")]


def _story_conclusion(flow: Flow, layers: list[dict]) -> dict:
    """State only what the captured packets support."""
    by_name = {layer["name"]: layer for layer in layers}
    dns, tcp, tls = by_name.get("DNS"), by_name.get("TCP"), by_name.get("TLS")
    http = by_name.get("HTTP")
    paragraphs: list[str] = []
    fix = ""

    dns_blocked = bool(dns and dns["status"] == "fail")
    tcp_ok = bool(tcp and tcp["status"] == "ok")

    if tcp_ok:
        rtt = flow.tcp_handshake_ms
        # After a DNS block the socket opens against the block page, so calling
        # the path to "this destination" healthy would name the wrong peer.
        where = "to the address that was returned" if dns_blocked else "to this destination"
        paragraphs.append(
            "The TCP connection opened normally"
            + (f" in {rtt:g} ms" if rtt else "")
            + (" and the name resolved first" if dns and dns["status"] == "ok" else "")
            + f" - the network path {where} is working.")

    # The server's own status code outranks anything inferred from an address.
    if http and http["status"] == "fail":
        codes = [s["msg"].replace("HTTP ", "") for s in http["steps"] if s.get("bad")]
        paragraphs.append(
            f"The server answered {', '.join(codes) or 'with an error'}. That is the "
            "refusal itself, stated by the server in plain HTTP - not an inference "
            "drawn from an address or a timing.")
        if dns_blocked:
            paragraphs.append(
                "The lookup was already answered with a block address, so the "
                "request reached a block page and that page refused it. Both "
                "layers agree.")
        fix = "This is a policy decision. Check the rule that matched this URL."

    elif dns_blocked:
        if tcp_ok:
            paragraphs.append(
                "The resolver did not hand back the real address for this name - "
                "it answered with a block address, and the connection that "
                "followed went to the block page rather than to the destination. "
                "A connection that succeeds is not the same as a request that was "
                "allowed.")
        else:
            paragraphs.append(
                "The failure is in name resolution: the connection never had a "
                "usable address to reach.")
        fix = "Check the DNS policy for this name before looking at the network."

    elif tcp and tcp["status"] == "fail":
        paragraphs.append(
            "The server never answered the SYN. From one capture point this cannot "
            "be separated into 'unreachable', 'filtered' or 'not listening' - only "
            "that no reply came back.")
        fix = "Confirm the destination is reachable and listening on this port."

    elif tls and tls["status"] == "fail":
        if tls.get("alert_by"):
            who = "client" if tls["alert_by"] == "c2s" else "server"
            paragraphs.append(
                f"The failure is entirely in the TLS layer, and the {who} said why - "
                "the alert above is its own stated reason for refusing.")
            fix = "Act on the alert reason; DNS and TCP need no changes."

        elif tls.get("reset_by") == "c2s" and tls.get("server_hello"):
            paragraphs.append(
                "The failure is in the TLS layer, and it was the CLIENT that reset. "
                "The server answered with its ServerHello, so the connection was "
                "torn down after the client had seen the server's reply - not "
                "because the server refused.")
            paragraphs.append(
                "A client that resets at this point has usually rejected what it "
                "was shown, most often the certificate. This capture proves the "
                "timing, not the motive: no alert was sent, so the client did not "
                "state a reason.")
            fix = ("Check the certificate the client was offered and the client's "
                   "trust store; the server answered normally.")

        elif tls.get("reset_by") == "c2s":
            paragraphs.append(
                "The client reset the connection after sending its ClientHello, "
                "before the server replied. The server was still silent, so nothing "
                "here shows the server refusing.")
            fix = "Look at the client: it abandoned the connection first."

        elif tls.get("acked_hello"):
            paragraphs.append(
                "The failure is entirely in the TLS layer. The order of the last "
                "packets is what matters: the server acknowledged the ClientHello "
                "before resetting. It received and read the hello, then chose to "
                "close. A firewall or routing problem drops packets silently - it "
                "does not acknowledge them first. This was a rejection, not a "
                "network fault.")
            paragraphs.append(
                "No ServerHello and no TLS alert were sent, so the peer gave no "
                "reason for the refusal.")
            fix = ("Check the policy on the device that terminated this connection; "
                   "DNS and TCP need no changes.")

        elif tls.get("server_hello"):
            paragraphs.append(
                "The server replied with its ServerHello and then reset the "
                "connection, so it abandoned a handshake it had already begun. No "
                "alert was sent, so it gave no reason.")
            fix = "Check the server or the device terminating TLS on its behalf."

        else:
            paragraphs.append(
                "The connection was reset after the ClientHello, and the reset was "
                "not preceded by an acknowledgement. This capture cannot tell "
                "whether the server refused or something in the path dropped it.")
            fix = "Capture at a second point to place where the reset originates."

    elif tls and tls["status"] == "ok":
        paragraphs.append(
            "Encryption negotiated successfully"
            + (f" using {flow.negotiated_version}" if flow.negotiated_version else "")
            + ". Nothing in the connection set-up failed.")

    elif tcp and tcp["status"] == "ok" and tls is None:
        paragraphs.append(
            "No TLS handshake was seen on this connection, so it was carried in "
            "the clear or the encryption began before the capture started.")

    if _is_loopback(flow.dst_ip):
        paragraphs.append(
            "Both endpoints are on 127.0.0.1: this connection never left the "
            "machine, so whatever answered it is software running on this host "
            "and not the remote destination.")

    return {"paragraphs": paragraphs, "fix": fix}


def connection_story(flow: Flow, rep: Any = None) -> dict | None:
    """The connection told as a sequence of layers, each with its own verdict.

    ``rep`` is the flow's analysis report when one exists; it only adds
    certificate facts, so the story still works without it.
    """
    if not flow.packets:
        return None

    marks = [(pkt, _timeline_entry(flow, pkt)) for pkt in flow.packets]
    layers = [layer for layer in (
        _story_dns(flow),
        _story_tcp(flow, marks),
        _story_tunnel(flow),
        _story_tls(flow, marks, rep),
        _story_http(flow),
        _story_data(flow),
    ) if layer]
    if not layers:
        return None

    server = flow.sni or flow.resolved_host or flow.dns_query or flow.dst_ip
    return {
        "client": {"addr": flow.src_ip or "client"},
        "server": {"host": server if server != flow.dst_ip else None,
                   "addr": flow.dst_ip or "server"},
        "layers": layers,
        "conclusion": _story_conclusion(flow, layers),
    }



# --- Per-flow analysis -------------------------------------------------------

def analyze_flow(flow: Flow, corporate_ca_orgs: Counter, secure_access_mode: bool = False) -> FlowReport:
    rep = FlowReport(flow=flow)

    # Identify known Cisco Secure Access SWG ingress endpoints. The IP the
    # client connects to (proxy_ip for CONNECT tunnels, otherwise dst_ip) is
    # checked against the published ingress list.
    flow.proxy_provider = describe_ingress(flow.proxy_ip or flow.dst_ip)

    # Private Access (Zero Trust / ZTNA): if either endpoint is in the
    # 100.64.0.0/10 CGNAT pool, this is the Secure Access Zero Trust proxy path
    # to a private resource, NOT SWG/web traffic. It tunnels arbitrary protocols,
    # so SWG/decryption/pinning verdicts must not be applied to it.
    flow.is_private_access = is_private_access(flow.src_ip) or is_private_access(flow.dst_ip)

    # Internal (private->private) traffic: when BOTH endpoints are private
    # (RFC 1918 LAN, link-local, loopback, IPv6 ULA or the CGNAT/ZTNA pool) the
    # flow never goes through the Secure Access SWG (SIA) — the roaming agent only
    # steers INTERNET-bound traffic. So SIA-level verdicts (TLS decryption,
    # web-policy, certificate-pinning) do not apply; flagging them here would be a
    # false positive.
    # EXCEPTION: an explicit-proxy HTTP CONNECT tunnel is INTERNET traffic even
    # when the proxy itself sits on a private IP — the real destination is the
    # CONNECT target (e.g. chatgpt.com), beyond the proxy. So a CONNECT tunnel is
    # never "internal", and SIA/decryption/pinning verdicts still apply to it.
    # EXCEPTION: loopback (127.0.0.1 / ::1) is NOT treated as internal here — it is
    # the Secure Client roaming module's local listener (the Secure Access agent
    # itself, which legitimately decrypts/steers), reported separately. Treating it
    # as plain internal LAN would wrongly suppress the agent's own evidence.
    flow.is_internal = (is_internal_flow(flow.src_ip, flow.dst_ip)
                        and not flow.is_connect_tunnel
                        and not (_is_loopback(flow.src_ip) or _is_loopback(flow.dst_ip)))

    # Certificate parsing
    if flow.certificates_hex:
        leaf, chain = analyze_leaf_chain(flow.certificates_hex)
        rep.leaf_cert = leaf
        rep.cert_chain = chain
        # Only count issuers that look like an interception/middlebox CA, so we
        # don't mislabel legitimate public CAs (e.g. Amazon, DigiCert) as proxies.
        if leaf and leaf.looks_like_proxy_ca and not leaf.looks_like_public_ca:
            org = leaf.issuer_org or leaf.issuer_cn
            if org:
                corporate_ca_orgs[org] += 1
    elif flow.tunnel_certificates_hex:
        # Inner certificate decrypted from inside a CONNECT tunnel (keylog file).
        leaf, chain = analyze_leaf_chain(flow.tunnel_certificates_hex)
        rep.leaf_cert = leaf
        rep.cert_chain = chain
        if leaf and leaf.looks_like_proxy_ca and not leaf.looks_like_public_ca:
            org = leaf.issuer_org or leaf.issuer_cn
            if org:
                corporate_ca_orgs[org] += 1

    _set_tls_status(flow, rep)
    _flow_findings(flow, rep, secure_access_mode)
    return rep


def _set_tls_status(flow: Flow, rep: FlowReport) -> None:
    if flow.is_quic:
        rep.tls_status = "QUIC/HTTP3 (UDP 443) — not TCP-TLS"
        return
    # Explicit-proxy HTTP CONNECT tunnel
    if flow.is_connect_tunnel:
        tgt = flow.connect_target or "destination"
        if flow.connect_status and flow.connect_status.startswith("2"):
            # Second-pass dissection may reveal the inner TLS handshake.
            if flow.tunnel_server_hello or flow.tunnel_client_hello:
                ver = flow.tunnel_tls_version or "TLS"
                sni = flow.tunnel_sni or (tgt.rsplit(":", 1)[0] if tgt else None)
                sni_txt = f", SNI={sni}" if sni else ""
                if flow.tunnel_server_hello:
                    # If a keylog decrypted the inner TLS 1.3, we now have the
                    # real certificate name — surface it instead of "encrypted".
                    if rep.leaf_cert and rep.leaf_cert.subject_cn:
                        cn = rep.leaf_cert.subject_cn
                        issuer = rep.leaf_cert.issuer_cn or rep.leaf_cert.issuer_org or "?"
                        rep.tls_status = (f"CONNECT tunnel to {tgt} — inner {ver} DECRYPTED"
                                          f"{sni_txt} — certificate CN={cn}, issued by {issuer}")
                    else:
                        note = "certificate used but encrypted by TLS 1.3 — not visible" if ver == "TLS 1.3" else "payload encrypted"
                        rep.tls_status = (f"CONNECT tunnel to {tgt} — inner {ver} handshake completed"
                                          f"{sni_txt} ({note})")
                else:
                    rep.tls_status = (f"CONNECT tunnel to {tgt} — inner {ver} ClientHello only"
                                      f"{sni_txt} (no ServerHello observed)")
            elif flow.client_hello or flow.server_hello or flow.app_data_seen:
                rep.tls_status = f"CONNECT tunnel to {tgt} established — end-to-end TLS (not decrypted)"
            else:
                rep.tls_status = f"CONNECT tunnel to {tgt} established (no payload captured)"
        elif flow.connect_status:
            rep.tls_status = f"CONNECT to {tgt} FAILED — proxy returned {flow.connect_status} {flow.connect_phrase or ''}".strip()
        else:
            rep.tls_status = f"CONNECT to {tgt} — no proxy response captured"
        return
    if not flow.client_hello and not flow.server_hello:
        if flow.transport == "tcp" and (flow.dst_port == 443 or flow.src_port == 443):
            rep.tls_status = "TCP/443 with no observed TLS handshake"
        else:
            rep.tls_status = "non-TLS"
        return
    if flow.client_hello and not flow.server_hello:
        rep.tls_status = "Handshake started, no ServerHello (failed/aborted)"
        return
    if flow.handshake_complete or flow.app_data_seen:
        rep.tls_status = f"TLS established ({flow.negotiated_version or 'version?'})"
    elif flow.server_hello:
        rep.tls_status = f"ServerHello seen, handshake not completed ({flow.negotiated_version or 'version?'})"
    else:
        rep.tls_status = "TLS partial"


def _flow_findings(flow: Flow, rep: FlowReport, secure_access_mode: bool = False) -> None:
    fk = flow.key
    dst = f"{flow.dst_ip}:{flow.dst_port}" if flow.dst_ip else "?"
    sni = flow.sni or flow.connect_target or "(no SNI)"

    # --- DNS↔TLS correlation: the flow connected to a Secure Access block-page IP ---
    block_cat = block_category_for_ip(flow.dst_ip) if flow.dst_ip else None
    if block_cat:
        rep.block_category = block_cat
        rep.findings.append(Finding(
            title=f"Connection to Secure Access block-page IP ({flow.dst_ip}) — {block_cat}",
            severity="high",
            category="proxy",
            detail=(f"The client opened a connection to {flow.dst_ip}, a Cisco Secure Access block-page "
                    f"address (category: {block_cat}). This confirms DNS-layer enforcement: the destination "
                    f"'{sni}' was resolved to the block page and the browser connected to it, so the user is "
                    f"being shown a block notification rather than the real site. Any TLS warning here is the "
                    f"block page's own certificate, not the real server's. Review the policy/category rule that "
                    f"matched this destination."),
            evidence=[f"flow dst={flow.dst_ip} sni={flow.sni or flow.connect_target} block={block_cat}"],
            flow_key=fk,
        ))

    # --- Web-layer (SWG) policy block: the request was sent to the Secure Access
    # block page block.sse.cisco.com (146.112.199.x). This is how an HTTPS request
    # blocked by WEB policy surfaces — URL filtering, content category, app
    # control, DLP, or an AI-guardrail rule. The block reason is not on the wire
    # (the block page is reached over its own TLS), so we report the family. ---
    ct_host = (flow.connect_target or "").rsplit(":", 1)[0]
    on_wire_block = (is_swg_block_ip(flow.dst_ip) or is_swg_block_ip(ct_host)
                     or is_block_page_domain(ct_host))
    sni_block = is_block_page_domain(flow.tunnel_sni) or is_block_page_domain(flow.sni)
    # Only flag the on-wire block page (146.112.199.x / a CONNECT to block.sse),
    # or an SNI block on a non-loopback flow. The local Secure Client roaming
    # listener mirrors the same block on 127.0.0.1, so without this guard every
    # block would be counted twice (loopback leg + on-wire leg).
    if on_wire_block or (sni_block and not _is_loopback(flow.dst_ip)):
        rep.block_category = "Web policy (content / app control / DLP / AI guardrail)"
        rep.findings.append(Finding(
            title="Web request blocked by Secure Access policy (DLP / content / app control / AI guardrail) — block page",
            severity="high",
            category="proxy",
            detail=("This connection was sent to the Secure Access block page "
                    "(block.sse.cisco.com, 146.112.199.x), which is where an HTTPS request blocked by WEB "
                    "policy is redirected. Unlike the DNS-layer malware/C2 block page, the reason is enforced "
                    "AFTER decryption, so it is a content/URL category, application-control, Data Loss "
                    "Prevention (DLP), or AI-guardrail rule. The user saw a block notification instead of the "
                    "site they requested. Check the web-policy / DLP / AI-guardrail rule that matched."),
            evidence=[f"block page reached: target={flow.connect_target or flow.dst_ip} "
                      f"inner_sni={flow.tunnel_sni or flow.sni}"],
            flow_key=fk,
        ))

    # --- Explicit-proxy HTTP CONNECT tunnel ---
    if flow.is_connect_tunnel:
        tgt = flow.connect_target or "(unknown)"
        status = flow.connect_status or "(no response)"
        proxy_label = flow.proxy_provider or f"explicit proxy {flow.proxy_ip or dst}"
        proxy_ref = flow.proxy_provider and f"{flow.proxy_provider} [{flow.proxy_ip or dst}]" or (flow.proxy_ip or dst)
        if flow.connect_status and not flow.connect_status.startswith("2"):
            # Tunnel refused/blocked by the proxy/SWG
            sev = "high"
            meaning = {
                "403": "Forbidden — blocked by SWG policy / URL category / reputation.",
                "407": "Proxy Authentication Required — client did not authenticate to the proxy.",
                "502": "Bad Gateway — proxy could not reach the upstream server.",
                "503": "Service Unavailable — proxy refused (policy or capacity).",
                "504": "Gateway Timeout — upstream did not respond in time.",
            }.get(flow.connect_status, f"Proxy returned {flow.connect_status}.")
            rep.findings.append(Finding(
                title=f"HTTP CONNECT to {tgt} blocked by {proxy_label} ({status})",
                severity=sev,
                category="proxy",
                detail=f"{proxy_ref} refused the CONNECT tunnel to {tgt}. {meaning}",
                evidence=[f"CONNECT {tgt} -> {status} {flow.connect_phrase or ''}".strip()],
                flow_key=fk,
            ))
        else:
            # Tunnel established. Inspect the inner TLS handshake (second pass).
            inner_ver = flow.tunnel_tls_version
            inner_sni = flow.tunnel_sni
            inner_seen = flow.tunnel_server_hello or flow.tunnel_client_hello
            decrypted = bool(rep.leaf_cert and rep.leaf_cert.looks_like_proxy_ca)
            # Surface any inner-TLS alerts inside the tunnel, but ignore the
            # benign ones that simply mark a normal shutdown. close_notify (0)
            # and user_canceled (90) are warning-level alerts that accompany a
            # CLEAN close, so flagging them would mislabel a successful
            # connection as a failure (false positive on healthy traffic).
            for al in flow.tunnel_alerts:
                desc = str(al.get("desc") or "").strip()
                if desc in ("0", "90") or "close" in desc.lower() or "cancel" in desc.lower():
                    continue
                a_sev = "high" if al.get("level") == "2" else "medium"
                rep.findings.append(Finding(
                    title=f"Inner-TLS alert inside tunnel to {tgt}",
                    severity=a_sev,
                    category="tls_alert",
                    detail=f"A TLS alert was observed inside the CONNECT tunnel to {tgt}.",
                    evidence=[f"alert level={al.get('level')} desc={al.get('desc')}"],
                    flow_key=fk,
                ))
            if decrypted:
                pass  # handled by cert-based interception findings elsewhere
            elif inner_seen:
                # We can see the inner TLS handshake (ClientHello/ServerHello) but
                # NOT the certificate — in TLS 1.3 the cert is encrypted, so this
                # does NOT let us prove whether the SWG is decrypting or not.
                is_tls13 = inner_ver == "TLS 1.3"
                cert_note = (
                    "A certificate IS exchanged on every TLS handshake, but TLS 1.3 sends the server "
                    "Certificate ENCRYPTED (right after the ServerHello, under the freshly negotiated key), "
                    "so a passive capture cannot read it — by design (RFC 8446). This is identical whether "
                    "SSL/file inspection is ON or OFF, so decryption vs. pass-through cannot be proven from "
                    "this PCAP alone. To reveal it you need the session keys (SSLKEYLOGFILE) or a capture taken "
                    "on the SWG itself."
                    if is_tls13 else
                    "no certificate message was captured in the dissected handshake"
                )
                title_note = (
                    "certificate exchanged but encrypted by TLS 1.3 (not visible to passive capture)"
                    if is_tls13 else "no certificate captured"
                )
                rep.findings.append(Finding(
                    title=f"CONNECT tunnel to {tgt} via {proxy_label} — inner {inner_ver or 'TLS'} handshake observed ({title_note})",
                    severity="info",
                    category="tunnel",
                    detail=(f"Client reached {tgt} through {proxy_ref} via HTTP CONNECT (status {status}). "
                            f"An inner {inner_ver or 'TLS'} handshake "
                            f"({'ClientHello+ServerHello' if flow.tunnel_server_hello else 'ClientHello'}"
                            f"{', SNI=' + inner_sni if inner_sni else ''}) was dissected inside the tunnel. "
                            f"{cert_note}"),
                    evidence=[f"CONNECT {tgt} -> {status} {flow.connect_phrase or ''}".strip(),
                              f"inner_tls={inner_ver or '?'} sni={inner_sni or '?'} "
                              f"client_hello={flow.tunnel_client_hello} server_hello={flow.tunnel_server_hello}"],
                    flow_key=fk,
                ))
            else:
                rep.findings.append(Finding(
                    title=f"CONNECT tunnel to {tgt} via {proxy_label} (not decrypted)",
                    severity="info",
                    category="tunnel",
                    detail=(f"Client reached {tgt} through {proxy_ref} using "
                            f"HTTP CONNECT (status {status}). No proxy/middlebox certificate was presented, so the "
                            f"TLS session is end-to-end between client and server — the SWG is tunnelling, not "
                            f"decrypting (consistent with SSL/file inspection being OFF for this destination)."),
                    evidence=[f"CONNECT {tgt} -> {status} {flow.connect_phrase or ''}".strip(),
                              f"proxy={proxy_ref} tls_handshake_seen={flow.client_hello or flow.server_hello}"],
                    flow_key=fk,
                ))

    # --- TLS alerts ---
    for al in flow.alerts:
        desc = al["desc"]
        sev = "high" if al["level"] == "fatal" else "medium"
        cat = "tls_alert"
        if desc in T.CERT_TRUST_ALERTS:
            cat = "cert_trust"
            sev = "high"
        rep.findings.append(Finding(
            title=f"TLS alert: {desc} ({al['level']})",
            severity=sev,
            category=cat,
            detail=f"A {al['level']} TLS alert '{desc}' was sent on flow to {dst} (SNI {sni}).",
            evidence=[f"packet #{al['packet']} @ t={al['time']}s, alert={desc}, level={al['level']}"],
            flow_key=fk,
        ))

    # --- Weak / mismatched version ---
    if flow.negotiated_version in T.WEAK_VERSIONS:
        rep.findings.append(Finding(
            title=f"Weak TLS version negotiated: {flow.negotiated_version}",
            severity="medium",
            category="tls_version",
            detail=f"The handshake to {sni} negotiated {flow.negotiated_version}, which is deprecated.",
            evidence=[f"negotiated={flow.negotiated_version}; offered={', '.join(flow.offered_versions) or 'n/a'}"],
            flow_key=fk,
        ))

    # --- Handshake failure pattern: ClientHello but no ServerHello ---
    if flow.client_hello and not flow.server_hello:
        rst_note = " followed by TCP RST" if flow.rst_count else ""
        if flow.is_internal:
            # Internal (private->private) traffic never passes through the SWG, so
            # this is the destination not answering (server down, firewall/ACL,
            # wrong port) — a connectivity issue, NOT a TLS-decryption mismatch.
            rep.findings.append(Finding(
                title="No TLS response from internal host (ClientHello, no ServerHello)",
                severity="medium",
                category="network",
                detail=(f"Client sent ClientHello to internal host {sni} ({dst}) but no ServerHello "
                        f"came back{rst_note}. On an internal (private\u2192private) flow this points to the "
                        f"destination not responding — server down, a firewall/ACL drop, or the wrong "
                        f"port — not TLS decryption (this traffic never goes through the Secure Access SWG)."),
                evidence=[
                    f"client_hello=yes server_hello=no internal=yes rst_count={flow.rst_count} retrans={flow.retransmissions}",
                ],
                flow_key=fk,
            ))
        else:
            rep.findings.append(Finding(
                title="Incomplete TLS handshake (no ServerHello)",
                severity="high",
                category="tls_handshake",
                detail=f"Client sent ClientHello to {sni} ({dst}) but no ServerHello was observed{rst_note}.",
                evidence=[
                    f"client_hello=yes server_hello=no rst_count={flow.rst_count} retrans={flow.retransmissions}",
                ],
                flow_key=fk,
            ))

    # --- Certificate findings ---
    leaf = rep.leaf_cert
    if leaf and not leaf.parse_error:
        # The "traffic is being decrypted by a proxy/SWG CA" verdict only makes
        # sense for INTERNET traffic that actually traverses the SWG. On internal
        # (private->private) flows — including the Secure Client roaming module's
        # loopback leg (127.0.0.1) — there is no SWG in the path, so this would be
        # a misleading SIA verdict (the roaming leg is already reported separately).
        if leaf.looks_like_proxy_ca and not flow.is_internal:
            rep.findings.append(Finding(
                title="Proxy/SWG corporate CA detected on leaf certificate",
                severity="info",
                category="interception",
                detail=(f"Leaf cert for {sni} is issued by '{leaf.issuer_cn or leaf.issuer_org}', "
                        f"which matches a known interception/middlebox CA — traffic is being decrypted."),
                evidence=[f"issuer_cn={leaf.issuer_cn} issuer_org={leaf.issuer_org} subject_cn={leaf.subject_cn}"],
                flow_key=fk,
            ))
        cert_window = evaluate_at(leaf, _flow_moment(flow))
        if cert_window.status == "expired":
            rep.findings.append(Finding(
                title="Server/leaf certificate is expired",
                severity="high",
                category="public_cert",
                detail=(f"The certificate presented for {sni} expired on "
                        f"{cert_window.not_after.date()}, "
                        f"{cert_window.days_outside} day(s) before this traffic was "
                        f"captured on {cert_window.at.date()}."),
                evidence=[f"not_after={leaf.not_after} captured_at={cert_window.at.isoformat()} "
                          f"subject_cn={leaf.subject_cn} "
                          f"issuer={leaf.issuer_cn or leaf.issuer_org}"],
                flow_key=fk,
            ))
        if cert_window.status == "not_yet_valid":
            rep.findings.append(Finding(
                title="Certificate not yet valid",
                severity="high",
                category="public_cert",
                detail=(f"The certificate for {sni} only became valid on "
                        f"{cert_window.not_before.date()}, "
                        f"{cert_window.days_outside} day(s) after this traffic was "
                        f"captured on {cert_window.at.date()}."),
                evidence=[f"not_before={leaf.not_before} captured_at={cert_window.at.isoformat()} "
                          f"subject_cn={leaf.subject_cn}"],
                flow_key=fk,
            ))
        # SNI vs certificate subject/SAN mismatch
        if flow.sni and (leaf.san_dns or leaf.subject_cn):
            if not _hostname_matches(flow.sni, leaf):
                rep.findings.append(Finding(
                    title="Certificate name does not match SNI",
                    severity="high",
                    category="public_cert",
                    detail=(f"SNI '{flow.sni}' is not covered by the certificate "
                            f"(CN={leaf.subject_cn}, SAN={', '.join(leaf.san_dns) or 'none'})."),
                    evidence=[f"sni={flow.sni} cn={leaf.subject_cn} san={leaf.san_dns}"],
                    flow_key=fk,
                ))

    # --- TCP RST after handshake bytes (pinning / policy reset signal) ---
    # NOTE: ignore loopback (127.0.0.1 / ::1) flows. The Cisco Secure Client
    # roaming module proxies HTTPS through a local loopback listener, and it tears
    # those local sockets down with a RST after a normal FIN — a benign teardown,
    # NOT certificate pinning. Flagging them produces false "pinning" verdicts on
    # sites that actually loaded fine (google, cnn, bbc, ...), so we require the
    # connection to be a real on-the-wire one.
    # Also skip Private Access (ZTNA) flows: a RST tearing down a protocol
    # tunneled through the Zero Trust proxy is a normal teardown of an arbitrary
    # app, not certificate pinning — and asymmetric routing can truncate the
    # capture. Flagging these as "pinning" is a false positive.
    # Likewise skip purely internal (private->private) flows: that traffic never
    # passes through the Secure Access SWG, so a RST there cannot be SWG
    # certificate pinning / policy reset — it is an internal app/firewall teardown.
    #
    # RFC 9293 (TCP) §3.5 — orderly vs abrupt termination. A genuine pinning /
    # policy reset shows up as a RST that REPLACES the graceful close: the peer
    # rejects the certificate and aborts before completing the handshake, with no
    # FIN exchange. If instead BOTH peers have already sent a FIN (fin_count >= 2),
    # the connection was closed in the normal four-way FIN handshake and the
    # trailing RST is benign teardown cleanup — TCP stacks routinely emit a RST
    # after close to discard the socket and skip the TIME_WAIT state (e.g.
    # SO_LINGER with a 0 timeout). This guard is essential for TLS 1.3: the
    # EncryptedExtensions/Certificate/CertVerify/Finished records are all encrypted
    # (RFC 8446), so we cannot observe handshake completion or application data
    # from a passive capture — the FIN/FIN exchange is then the ONLY reliable
    # on-the-wire proof that the connection actually succeeded. (Observed on
    # eu-teams.events.data.microsoft.com: full bidirectional data, FIN from both
    # sides, then a RST — a healthy Teams telemetry flow, not pinning.)
    on_wire = not (_is_loopback(flow.src_ip) or _is_loopback(flow.dst_ip))
    graceful_close = flow.fin_count >= 2
    if (flow.transport == "tcp" and flow.rst_count and flow.server_hello
            and not flow.handshake_complete and not flow.app_data_seen and on_wire
            and not graceful_close
            and not flow.is_private_access and not flow.is_internal):
        # Grade the signal by HOW abrupt the termination was (RFC 9293 §3.5):
        #   fin_count == 0 -> the RST fully replaced the close: strongest abort
        #                     signal (a clean pinning reject sends no FIN).
        #   fin_count == 1 -> one peer had already begun an orderly FIN close, so
        #                     the reset only aborted a half-closed connection:
        #                     weaker, lower-confidence (commonly a benign teardown
        #                     where the client RSTs after the server's FIN).
        partial_close = flow.fin_count == 1
        if partial_close:
            sev = "medium"
            close_note = ("one peer had already sent a FIN (a half-close was in progress), so this is a "
                          "weaker, lower-confidence signal than a pure reset")
        else:
            sev = "high"
            close_note = "no FIN was exchanged at all — the RST fully replaced the graceful close"
        rep.findings.append(Finding(
            title="TCP RST after ServerHello/Certificate (possible pinning or policy reset)",
            severity=sev,
            category="pinning_signal",
            detail=(f"Server presented hello/certificate for {sni} but the connection was reset "
                    f"without an orderly FIN/FIN close from both peers ({close_note}). An abrupt TCP "
                    f"RST instead of the normal graceful FIN/ACK shutdown is what you see when an app "
                    f"rejects the re-signed certificate (certificate pinning) or a middlebox policy "
                    f"resets the session (behavioral signal, not proof). A connection that both sides "
                    f"close with FIN before any RST is a normal teardown and is not flagged."),
            evidence=[f"server_hello=yes finished=no rst_count={flow.rst_count} fin_count={flow.fin_count}"],
            flow_key=fk,
        ))

    # --- TCP RST before the server responded (abrupt reject, not a graceful close) ---
    if (flow.transport == "tcp" and flow.rst_count and flow.client_hello
            and not flow.server_hello and not flow.app_data_seen):
        graceful = "no graceful FIN/ACK close was seen" if not flow.fin_count else "a FIN was also present"
        rep.findings.append(Finding(
            title="TLS connection reset before the server responded",
            severity="medium",
            category="network",
            detail=(f"The client sent its ClientHello for {sni}, but the connection was torn down with a "
                    f"TCP RST before any ServerHello came back ({graceful}). A reset at this point is an "
                    f"abrupt abort, not the normal graceful FIN/ACK teardown — it typically means an inline "
                    f"device (firewall / IPS / SWG) injected a reset to block the connection, or the server/"
                    f"upstream refused it. A healthy flow instead completes the handshake and later closes "
                    f"cleanly with FIN/ACK."),
            evidence=[f"client_hello=yes server_hello=no rst_count={flow.rst_count} fin_count={flow.fin_count}"],
            flow_key=fk,
        ))

    # --- CONNECT tunnel established, then client aborts right after TLS setup ---
    # The inner TLS handshake completed through a decrypting proxy, but the client
    # tore the connection down with a RST and NO graceful FIN / close_notify. This
    # is the classic signature of an application (composer, git, npm, pip, Java, Go,
    # curl with its own CA bundle, or cert pinning) that rejects the proxy's
    # re-signed certificate — which silently breaks repository/package downloads.
    # A clean HTTPS download through a decrypting proxy is torn down with a TLS
    # close_notify followed by FIN/FIN — never with a client RST. So a CLIENT
    # RST on an established, decrypting CONNECT tunnel is the abort signal,
    # regardless of any FIN flags (the OS still emits FINs while tearing the
    # socket down). We therefore do NOT require the absence of FINs here.
    if (flow.is_connect_tunnel and (flow.connect_status or "").startswith("2")
            and flow.tunnel_client_hello and flow.tunnel_server_hello
            and flow.rst_count and flow.client_reset):
        tgt = flow.connect_target or sni or "the destination"
        proxy_label = flow.proxy_provider or f"the proxy ({flow.proxy_ip or dst})"
        rep.findings.append(Finding(
            title=f"Client reset the decrypted tunnel to {tgt} right after TLS setup (likely certificate rejection)",
            severity="high",
            category="pinning_signal",
            detail=(f"The CONNECT tunnel to {tgt} via {proxy_label} was established and the inner "
                    f"{flow.tunnel_tls_version or 'TLS'} handshake completed, but the client then aborted with a "
                    f"TCP RST instead of a clean TLS close (close_notify), before transferring a real payload. "
                    f"Because {proxy_label} decrypts and re-signs the server certificate, this is the classic "
                    f"signature of an application that doesn't trust or that pins the original certificate — very "
                    f"common with package managers and dev tools (composer, git, npm, pip, Java, Go) that ship "
                    f"their own CA bundle instead of using the OS trust store. The TLS library accepts the "
                    f"handshake, but the application rejects the re-signed certificate and tears the connection "
                    f"down, so the repository/download never completes. Fix: prefer a do-not-decrypt / TLS-bypass "
                    f"rule for {tgt} in Secure Access (works regardless of the tool). Otherwise make the SPECIFIC "
                    f"tool trust the Secure Access root CA \u2014 the setting differs per tool (php.ini openssl.cafile "
                    f"for PHP/Composer only, git http.sslCAInfo, npm cafile, Node NODE_EXTRA_CA_CERTS, pip --cert, "
                    f"Java keytool), so confirm which tool is downloading first."),
            evidence=[f"connect={flow.connect_status} inner={flow.tunnel_tls_version} "
                      f"client_reset=yes rst={flow.rst_count} fin={flow.fin_count}"],
            flow_key=fk,
        ))

    # --- TCP health ---
    loss = flow.retransmissions + flow.lost_segments + flow.out_of_order
    if loss >= 3:
        parts = []
        if flow.retransmissions:
            parts.append(f"{flow.retransmissions} retransmission(s)")
        if flow.lost_segments:
            parts.append(f"{flow.lost_segments} lost segment(s)")
        if flow.out_of_order:
            parts.append(f"{flow.out_of_order} out-of-order")
        if flow.dup_acks:
            parts.append(f"{flow.dup_acks} duplicate-ACK(s)")
        breakdown = ", ".join(parts)
        rep.findings.append(Finding(
            title=f"TCP packet loss / retransmissions ({loss} event{'s' if loss != 1 else ''})",
            severity="medium",
            category="network",
            detail=(f"Connection to {dst} shows {breakdown}. This points to packet loss or a "
                    f"congested/lossy path (or an MTU blackhole if it stalls mid-handshake) — a network "
                    f"transport problem, independent of TLS/SWG policy."),
            evidence=[f"retransmissions={flow.retransmissions} lost_segments={flow.lost_segments} "
                      f"out_of_order={flow.out_of_order} dup_acks={flow.dup_acks} "
                      f"zero_window={flow.zero_window}"],
            flow_key=fk,
        ))
    if flow.zero_window:
        rep.findings.append(Finding(
            title=f"TCP zero-window events ({flow.zero_window})",
            severity="low",
            category="network",
            detail=f"Receiver advertised a zero window on flow to {dst}; possible application/buffer stall.",
            evidence=[f"zero_window={flow.zero_window}"],
            flow_key=fk,
        ))
    # Receive-window limited: the sender ran out of window, not out of bandwidth.
    # Distinct from a zero window (an application stall) — here the receiver is
    # still reading, its window is simply too small for the bandwidth-delay
    # product, capping this connection at window/RTT no matter how fast the link.
    if flow.window_full:
        rtt = flow.initial_rtt_ms or flow.tcp_handshake_ms
        pace = ""
        if rtt:
            pace = (f" Here the round trip to {dst} is about {rtt:.0f} ms, so each pause lasted roughly "
                    f"that long before sending could resume.")
        rep.findings.append(Finding(
            title=f"Slowed by a small receive window ({flow.window_full} pause{'s' if flow.window_full != 1 else ''})",
            severity="low",
            category="latency",
            detail=("The sender kept stopping and waiting, not because anything failed, but because the "
                    "receiver had told it how much data it was willing to hold at once — and that allowance "
                    "kept filling up. "
                    "Think of pouring water through a funnel: the tap is wide open and the pipe is clear, but "
                    "the funnel only holds so much, so you have to stop and let it drain before pouring again. "
                    "The funnel is the receiver's buffer. "
                    "The speed limit this creates is the size of that allowance divided by how long a round "
                    "trip takes, and no extra bandwidth can raise it — the sender is idle, waiting for "
                    "permission, not for capacity." + pace +
                    " It usually sorts itself out as the connection warms up, because the receiver grows the "
                    "allowance once it sees the link can handle more. If it keeps happening, the fixes are on "
                    "the RECEIVING side (a larger TCP receive buffer, or leaving window auto-tuning enabled), "
                    "or simply using several connections at once so each gets its own allowance. "
                    "Nothing here points at packet loss, TLS, or a security product."),
            evidence=[f"window_full={flow.window_full} "
                      f"initial_rtt_ms={flow.initial_rtt_ms} zero_window={flow.zero_window}"],
            flow_key=fk,
        ))
    # TLS 1.3 HelloRetryRequest: the server rejected every key_share the client
    # guessed, forcing a second ClientHello — one extra network round trip added
    # to every connection that hits it.
    if flow.hello_retry_request:
        offered = " or ".join(flow.hrr_offered_groups) or "the ones it tried"
        forced = flow.hrr_selected_group or "a different one"
        rtt = flow.initial_rtt_ms or flow.tcp_handshake_ms
        cost = (f" One round trip to {dst} takes about {rtt:.0f} ms, so that is roughly what this adds to "
                f"every connection that hits it." if rtt else "")
        downgrade = ""
        if any("MLKEM" in g or "Kyber" in g for g in flow.hrr_offered_groups):
            downgrade = (" Worth noting: the client's first choice was a post-quantum method (designed to stay "
                         "safe even against future quantum computers) and the server would not accept it, so "
                         "this connection ended up using classical encryption only. That is not a fault today, "
                         "but it is the kind of thing to track as post-quantum support rolls out.")
        rep.findings.append(Finding(
            title=f"Extra round trip while setting up TLS to {dst} (HelloRetryRequest)",
            severity="low",
            category="latency",
            detail=("Before any data can flow, the two sides must agree on how to scramble it. To save time "
                    "the client GUESSES which method the server will want and sends its half of the key with "
                    "the very first message. "
                    f"Here the guess was wrong: the client offered {offered}, the server refused and asked it "
                    f"to start over using {forced}. "
                    "Picture arriving at a locked door and trying the key you think fits — being told it is "
                    "the wrong one and having to walk back for the right key. You still get in, but you made "
                    "the trip twice. "
                    "The connection works perfectly; it is simply slower to establish, and it happens on every "
                    "new connection to this server, not just once." + cost + downgrade +
                    " The fix is to make the client's first guess match what the server actually prefers, "
                    "which removes the extra trip entirely."),
            evidence=[f"hello_retry_request=yes offered={flow.hrr_offered_groups} "
                      f"forced_to={flow.hrr_selected_group} tls_setup_ms={flow.tls_setup_ms}"],
            flow_key=fk,
        ))

    # --- QUIC / HTTP3 ---
    # Only relevant for INTERNET traffic: QUIC bypasses the SWG only when the SWG
    # is in the path. Internal (private->private) and ZTNA flows never traverse the
    # SWG, so internal QUIC/HTTP3 is just normal traffic, not a bypass.
    if flow.is_quic and not flow.is_internal and not flow.is_private_access:
        if secure_access_mode:
            rep.findings.append(Finding(
                title=f"QUIC / HTTP3 on UDP/443 to {sni or dst} — bypasses SWG TLS inspection",
                severity="medium",
                category="quic",
                detail=(f"This is a QUIC (HTTP/3) flow over UDP/443 to {sni or dst}. Secure Access SWG inspects "
                        f"TCP/443 TLS; QUIC rides on UDP and its handshake is encrypted, so it commonly slips past "
                        f"decryption and URL/category policy. If the browser falls back to QUIC, you may see traffic "
                        f"that should be blocked or decrypted go through untouched. Fix: block UDP/443 egress (or use "
                        f"the Secure Access firewall/QUIC control) so clients fall back to TCP/443 and the SWG can "
                        f"inspect them."),
                evidence=[f"transport=udp quic=yes sni={flow.sni} alpn={flow.alpn}"],
                flow_key=fk,
            ))
        else:
            rep.findings.append(Finding(
                title=f"QUIC / HTTP3 on UDP/443 to {sni or dst} — evades in-path TLS inspection",
                severity="medium",
                category="quic",
                detail=(f"This is a QUIC (HTTP/3) flow over UDP/443 to {sni or dst}. Any inline TLS inspection "
                        f"(proxy, firewall or IPS) that watches TCP/443 does not see QUIC: it rides on UDP and its "
                        f"handshake is encrypted, so it commonly slips past decryption and URL/category policy. If a "
                        f"browser falls back to QUIC, traffic that should be inspected can go through untouched. Fix: "
                        f"block UDP/443 egress so clients fall back to TCP/443, where inline inspection applies."),
                evidence=[f"transport=udp quic=yes sni={flow.sni} alpn={flow.alpn}"],
                flow_key=fk,
            ))

    # --- ECH ---
    # ECH only matters because it can hide the SNI from the SWG. On internal
    # (private->private) and ZTNA flows there is no SWG in the path, so ECH there
    # is irrelevant and reporting it would be misleading.
    if flow.has_ech and not flow.is_internal and not flow.is_private_access:
        # If we still see a real SNI, this is almost certainly ECH GREASE (a
        # decoy extension browsers send to normalise traffic) — nothing is
        # actually hidden. Only when the SNI is absent is the inner name truly
        # encrypted and invisible to the SWG.
        if flow.sni:
            rep.findings.append(Finding(
                title=f"ECH GREASE present on flow to {flow.sni} (SNI still visible)",
                severity="info",
                category="tls_handshake",
                detail=(f"The ClientHello to {flow.sni} carries an ECH (Encrypted Client Hello) extension, but "
                        f"the real SNI is still visible in clear text — so this is ECH GREASE, a decoy browsers "
                        f"send to blend traffic. "
                        + ("SNI-based SWG policy still works here. " if secure_access_mode
                           else "SNI-based inspection/policy still works here. ")
                        + "It becomes a problem only if the server later enables real ECH and the SNI disappears."),
                evidence=[f"tls extension type = encrypted_client_hello (0xfe0d), sni={flow.sni} visible"],
                flow_key=fk,
            ))
        else:
            rep.findings.append(Finding(
                title=(f"Encrypted Client Hello (ECH) to {dst} — real SNI hidden from the SWG" if secure_access_mode
                       else f"Encrypted Client Hello (ECH) to {dst} — real SNI hidden from in-path inspection"),
                severity="medium",
                category="tls_handshake",
                detail=(f"The ClientHello to {dst} carries an ECH extension and no clear-text SNI is present, so "
                        f"the real destination name is encrypted and invisible to passive inspection. Domain/URL-"
                        f"category filtering that relies on the SNI cannot see the true destination. If selective "
                        f"decryption or SNI-based policy is expected here, ECH defeats it. Consider disabling ECH "
                        f"via policy or blocking the resolvers that publish ECH keys if SNI visibility is required."),
                evidence=["tls extension type = encrypted_client_hello (0xfe0d), no clear-text SNI"],
                flow_key=fk,
            ))

    # --- Proxy/HTTP status codes (any 4xx/5xx on a proxied flow) ---
    seen_codes: set[str] = set()
    for code in flow.http_statuses:
        if not code or len(code) != 3 or code[0] not in ("4", "5"):
            continue
        if code in seen_codes:
            continue
        seen_codes.add(code)
        # 5xx and the proxy block/auth codes are hard failures; other 4xx are softer.
        sev = "high" if (code[0] == "5" or code in {"403", "407"}) else "medium"
        rep.findings.append(Finding(
            title=f"HTTP {code} on proxied flow",
            severity=sev,
            category="proxy",
            detail=_http_code_meaning(code, sni),
            evidence=[f"http status {code} on flow to {dst} (SNI {sni})"],
            flow_key=fk,
        ))


def _http_code_meaning(code: str, sni: str) -> str:
    meanings = {
        "400": f"Bad Request — the server or proxy rejected the request to {sni} as malformed.",
        "401": f"Unauthorized — {sni} requires authentication that was missing or rejected.",
        "403": f"Forbidden — proxy/SWG likely blocked the request to {sni} (policy / category / reputation).",
        "404": f"Not Found — {sni} returned no resource for this request (usually an origin issue, not the proxy).",
        "407": "Proxy Authentication Required — client failed or did not provide proxy credentials.",
        "408": f"Request Timeout — the client took too long to send the request to {sni}.",
        "429": f"Too Many Requests — {sni} is rate-limiting the client.",
        "500": f"Internal Server Error — {sni} or the proxy failed to process the request.",
        "502": f"Bad Gateway — proxy could not get a valid upstream response for {sni}.",
        "503": "Service Unavailable — proxy/upstream overloaded or policy-denied.",
        "504": f"Gateway Timeout — proxy did not receive a timely response from {sni}.",
    }
    if code in meanings:
        return meanings[code]
    if code.startswith("4"):
        return (f"HTTP {code} — client-side error for {sni}: the request was rejected "
                "(could be policy, authentication or a malformed request).")
    if code.startswith("5"):
        return (f"HTTP {code} — server/proxy-side error for {sni}: the upstream or the proxy "
                "failed to fulfil the request.")
    return f"HTTP {code} observed for {sni}."


def _hostname_matches(hostname: str, cert: CertInfo) -> bool:
    names = list(cert.san_dns)
    if cert.subject_cn:
        names.append(cert.subject_cn)
    host = hostname.lower().rstrip(".")
    for n in names:
        n = (n or "").lower().rstrip(".")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*."):
            suffix = n[1:]  # ".example.com"
            # wildcard matches exactly one left-most label
            if host.endswith(suffix) and host.count(".") == n.count("."):
                return True
    return False
