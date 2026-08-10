"""
tshark-based PCAP/PCAPNG parser.

This is the "best of the best" engine: it shells out to Wireshark's tshark to
dissect captures, then aggregates packets into TCP/UDP flows for downstream
TLS, TCP and QUIC analysis. Certificate bytes are extracted as hex so they can
be parsed precisely with the `cryptography` library (see certs.py).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional


# --- tshark discovery --------------------------------------------------------

_WINDOWS_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark() -> Optional[str]:
    """Locate the tshark executable, preferring PATH then known install dirs."""
    found = shutil.which("tshark")
    if found:
        return found
    for candidate in _WINDOWS_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


class TsharkNotFoundError(RuntimeError):
    pass


# Fields requested from tshark. Kept as a flat list of -e arguments; each maps
# to an array of strings in tshark's JSON output (-T json with -e fields).
_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "frame.time_relative",
    "frame.len",
    "frame.protocols",
    "frame.interface_id",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ipv6.src",
    "ipv6.dst",
    "ipv6.hlim",
    "tcp.stream",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.len",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.reset",
    "tcp.flags.fin",
    "tcp.flags.ack",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.ack_lost_segment",
    # Sender blocked because it has exactly filled the receiver's advertised
    # window: the connection is receive-window limited, not loss limited. A
    # throughput ceiling of window/RTT that no amount of bandwidth can exceed.
    "tcp.analysis.window_full",
    # Passive round-trip metrics. initial_rtt = the SYN->SYN/ACK handshake RTT
    # (the cleanest per-flow *network* RTT). ack_rtt = per-ACK round-trip samples
    # whose spread gives RTT variation (jitter). Both are cleartext transport
    # timings, visible even on fully encrypted (TLS 1.3 / QUIC) flows.
    "tcp.analysis.initial_rtt",
    "tcp.analysis.ack_rtt",
    "tcp.options.mss_val",
    "udp.stream",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    # ICMP / ICMPv6 errors. Type 3 Code 4 (IPv4) and Type 2 (ICMPv6) carry the
    # next-hop MTU used by Path MTU Discovery (RFC 1191 / RFC 8201). icmp.mtu and
    # icmpv6.mtu are that Next-Hop MTU field. The embedded original datagram's IP
    # header re-uses the ip.* / ipv6.* dissector, so ip.dst/ipv6.dst gain a 2nd
    # value = the destination that hit the MTU limit.
    "icmp.type",
    "icmp.code",
    "icmp.mtu",
    "icmpv6.type",
    "icmpv6.code",
    "icmpv6.mtu",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.flags.rcode",
    "dns.flags.response",
    "dns.qry.type",
    "dns.cname",
    "dns.time",
    "dns.id",
    # TLS
    "tls.record.version",
    "tls.record.content_type",
    "tls.handshake.type",
    "tls.handshake.version",
    # ServerHello Random. RFC 8446 §4.1.3 defines a fixed magic value that marks
    # the message as a HelloRetryRequest rather than a real ServerHello.
    "tls.handshake.random",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.ciphersuite",
    "tls.handshake.session_id",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.sig_hash_alg",
    "tls.handshake.extensions_key_share_group",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.ja3",
    "tls.handshake.ja3s",
    "tls.handshake.certificate",
    "tls.alert_message.level",
    "tls.alert_message.desc",
    # ECH (Encrypted Client Hello) extension type 0xfe0d
    "tls.handshake.extension.type",
    # QUIC (TLS inside QUIC is dissected via the standard tls.* fields above)
    "quic.header_form",
    "quic.long.packet_type",
    # HTTP / proxy
    "http.request.method",
    "http.request.full_uri",
    "http.request.uri",
    "http.host",
    "http.response.code",
    "http.response.phrase",
    "http.proxy_authenticate",
    "http.proxy_authorization",
    "http2.headers.method",
    "http2.headers.status",
    "http2.headers.authority",
]


@dataclass
class Packet:
    number: int
    time_epoch: float
    time_relative: float
    length: int
    raw: dict[str, Any] = field(default_factory=dict)

    def first(self, key: str) -> Optional[str]:
        vals = self.raw.get(key)
        if isinstance(vals, list) and vals:
            return vals[0]
        if isinstance(vals, str):
            return vals
        return None

    def all(self, key: str) -> list[str]:
        vals = self.raw.get(key)
        if isinstance(vals, list):
            return vals
        if isinstance(vals, str):
            return [vals]
        return []


def _to_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value, 0) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
    except (ValueError, TypeError):
        return None


# Display filter used to REDUCE very large captures to only the frames the
# analysis actually reads: TCP setup/teardown (SYN/FIN/RST), every TLS and DTLS
# record, all DNS, QUIC long-header (handshake) packets and ICMP errors. Bulk
# payload frames (plain HTTP bodies, RTP/screen-share media, pure ACKs) are
# dropped — they dominate the byte count but carry no diagnostic signal — so a
# 300 MB capture shrinks to a few % of its frames and becomes analysable in RAM.
REDUCE_FILTER = (
    "tcp.flags.syn==1 or tcp.flags.reset==1 or tcp.flags.fin==1 "
    "or tls or dns or icmp or icmpv6 or quic.long.packet_type or dtls"
)


def run_tshark(pcap_path: str, tshark_path: Optional[str] = None, display_filter: Optional[str] = None,
               keylog_file: Optional[str] = None, reduce: bool = False) -> list[Packet]:
    """Run tshark over the capture and return a list of Packet objects.

    If ``keylog_file`` (an SSLKEYLOGFILE) is provided, tshark is told to use it
    to DECRYPT TLS, which makes the real server certificate visible even for
    TLS 1.3 sessions.

    If ``reduce`` is set (used for very large captures) tshark applies
    :data:`REDUCE_FILTER` so only diagnostically-relevant frames are decoded,
    keeping the JSON small enough to parse in memory.
    """
    exe = tshark_path or find_tshark()
    if not exe:
        raise TsharkNotFoundError(
            "tshark (Wireshark CLI) was not found. Install Wireshark or add tshark to PATH."
        )

    cmd = [exe, "-r", pcap_path, "-T", "json", "-n"]
    if keylog_file and os.path.isfile(keylog_file):
        cmd += ["-o", f"tls.keylog_file:{keylog_file}"]
    if reduce and not display_filter:
        display_filter = REDUCE_FILTER
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in _FIELDS:
        cmd += ["-e", f]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()[:500]}")

    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse tshark JSON output: {exc}") from exc

    packets: list[Packet] = []
    for item in data:
        layers = item.get("_source", {}).get("layers", {})
        num = _to_int((layers.get("frame.number") or [None])[0]) or 0
        try:
            t_epoch = float((layers.get("frame.time_epoch") or ["0"])[0])
        except (ValueError, TypeError):
            t_epoch = 0.0
        try:
            t_rel = float((layers.get("frame.time_relative") or ["0"])[0])
        except (ValueError, TypeError):
            t_rel = 0.0
        length = _to_int((layers.get("frame.len") or ["0"])[0]) or 0
        packets.append(Packet(number=num, time_epoch=t_epoch, time_relative=t_rel, length=length, raw=layers))

    return packets


def extract_nrb_hosts(pcap_path: str, tshark_path: Optional[str] = None) -> dict[str, str]:
    """Return the IP->hostname map baked into the pcapng Name Resolution Block.

    PcapNG files store an NRB that Wireshark fills from the DNS answers seen in
    the capture (and any pre-resolved names). This lets us label a flow's peer
    by hostname even when the SNI is encrypted (ECH/QUIC) or no DNS query for it
    appears on the wire. Plain ``.pcap`` files have no NRB, so this returns {}.
    """
    exe = tshark_path or find_tshark()
    if not exe:
        return {}
    try:
        proc = subprocess.run(
            [exe, "-r", pcap_path, "-q", "-z", "hosts"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return {}
    hosts: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] and parts[1]:
            # Keep the first name seen for each IP (tshark lists primary first).
            hosts.setdefault(parts[0], parts[1])
    return hosts


def extract_capture_env(pcap_path: str, tshark_path: Optional[str] = None) -> dict[str, Any]:
    """Read capture-provenance metadata from a pcapng via ``capinfos``: the
    sniffer OS, the capturing application/version, the capture hardware and the
    number of interfaces. Returns {} for plain pcap or if capinfos is absent."""
    exe = tshark_path or find_tshark()
    capinfos = None
    if exe:
        cand = os.path.join(os.path.dirname(exe), "capinfos.exe" if os.name == "nt" else "capinfos")
        if os.path.isfile(cand):
            capinfos = cand
    if not capinfos:
        capinfos = shutil.which("capinfos")
    if not capinfos:
        return {}
    try:
        proc = subprocess.run(
            [capinfos, pcap_path],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return {}
    fields = {
        "Capture oper-sys": "os",
        "Capture application": "application",
        "Capture hardware": "hardware",
        "Number of interfaces in file": "interfaces",
        "Capture duration": "duration",
    }
    env: dict[str, Any] = {}
    for line in (proc.stdout or "").splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        key = fields.get(label.strip())
        if key and value.strip():
            env[key] = value.strip()
    return env


# Hex of the ASCII marker "STARTMSG" that prefixes the Cisco Secure Client /
# Umbrella roaming module's local status datagrams (a deadbeef-framed IPC blob
# sent over loopback UDP). The payload carries a cleartext JSON report.
_STARTMSG_HEX = "53:54:41:52:54:4d:53:47"


def extract_roaming_report(pcap_path: str, tshark_path: Optional[str] = None) -> Optional[dict[str, Any]]:
    """Extract the Cisco Secure Client / Umbrella roaming module's self-report.

    The roaming/web-protection component emits a periodic ``STARTMSG`` status
    datagram on loopback UDP whose payload is cleartext JSON, e.g.::

        {"version":1,
         "web_connections_info":{"http_connections":"54",
                                 "https_connections":"358",
                                 "bypassed_connections":"4914"},
         "umbrella_proxy":"swg-url-proxy-https-8332022.sseproxy.qq.opendns.com"}

    This is the agent reporting, in clear, which SWG/Secure Access proxy (and
    org) it is bound to and how many web connections it has steered through the
    SWG versus let bypass (go direct). We mine it directly from the wire instead
    of inferring it. Counters are cumulative since the agent started, so we keep
    the latest values plus the first/last bypassed count to show the trend.

    Returns ``None`` when no such datagram is present (most captures).
    """
    exe = tshark_path or find_tshark()
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "-r", pcap_path, "-Y", f"data.data contains {_STARTMSG_HEX}",
             "-T", "fields", "-e", "frame.time_relative", "-e", "data.data"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except OSError:
        return None

    samples: list[dict[str, Any]] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        hexstr = parts[-1].replace(":", "").strip()
        if not hexstr:
            continue
        try:
            raw = bytes.fromhex(hexstr)
        except ValueError:
            continue
        start = raw.find(b"{")
        end = raw.rfind(b"}")
        if start < 0 or end <= start:
            continue
        try:
            payload = json.loads(raw[start:end + 1].decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            continue
        try:
            t = float(parts[0])
        except (ValueError, IndexError):
            t = 0.0
        payload["_t"] = t
        samples.append(payload)

    if not samples:
        return None

    def _int(v: Any) -> Optional[int]:
        try:
            return int(str(v))
        except (TypeError, ValueError):
            return None

    last = samples[-1]
    info = last.get("web_connections_info") or {}
    bypassed_vals = [
        b for b in (_int((s.get("web_connections_info") or {}).get("bypassed_connections"))
                    for s in samples)
        if b is not None
    ]
    report: dict[str, Any] = {
        "umbrella_proxy": last.get("umbrella_proxy"),
        "version": last.get("version"),
        "http_connections": _int(info.get("http_connections")),
        "https_connections": _int(info.get("https_connections")),
        "bypassed_connections": _int(info.get("bypassed_connections")),
        "bypassed_first": bypassed_vals[0] if bypassed_vals else None,
        "bypassed_last": bypassed_vals[-1] if bypassed_vals else None,
        "samples": len(samples),
    }
    return report


@dataclass
class Flow:
    key: str                      # tcp.stream id or udp.stream id (prefixed)
    transport: str                # "tcp" or "udp"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packets: list[Packet] = field(default_factory=list)

    # Derived / analysis fields populated later
    sni: Optional[str] = None
    alpn: list[str] = field(default_factory=list)
    client_hello: bool = False
    server_hello: bool = False
    negotiated_version: Optional[str] = None
    offered_versions: list[str] = field(default_factory=list)
    cipher_suite: Optional[str] = None
    certificates_hex: list[str] = field(default_factory=list)
    # Passive TLS fingerprints (computed by tshark from the cleartext
    # ClientHello/ServerHello — visible even on TLS 1.3 where the payload is
    # encrypted). JA3 identifies the client TLS stack; JA3S the server stack.
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    key_share_group: Optional[str] = None     # negotiated key-exchange group, e.g. "x25519"
    # Detected application-layer protocol (from tshark frame.protocols) plus DNS
    # metadata, so even non-TLS flows get a meaningful description instead of a
    # blank "(no SNI) / non-TLS" row.
    l7_protocol: Optional[str] = None         # e.g. "DNS", "QUIC", "OCSP", "HTTP/2"
    dns_query: Optional[str] = None           # first queried name (cleartext DNS)
    dns_resolver: Optional[str] = None        # known public resolver name, if any
    resolved_host: Optional[str] = None       # hostname from the pcapng Name Resolution Block (NRB)
    # The DNS lookup (seen earlier in THIS capture) that resolved to dst_ip — ties
    # an IP-only connection back to the hostname the client actually requested.
    dns_lookup: Optional[dict[str, Any]] = None
    # Latency markers (milliseconds). tcp_handshake_ms = client SYN -> server
    # SYN/ACK (network round-trip to the peer). tls_setup_ms = ClientHello ->
    # ServerHello (TLS negotiation time, inflated when a SWG re-terminates TLS).
    tcp_handshake_ms: Optional[float] = None
    tls_setup_ms: Optional[float] = None
    alerts: list[dict[str, str]] = field(default_factory=list)
    rst_count: int = 0
    retransmissions: int = 0
    # Retransmissions that tshark judged UNNECESSARY (the original segment did
    # arrive). Tracked separately so real loss can be computed as
    # retransmissions - spurious_retransmissions, per the Wireshark TCP-analysis
    # methodology. Does NOT alter `retransmissions` (which keeps its legacy sum).
    spurious_retransmissions: int = 0
    lost_segments: int = 0
    out_of_order: int = 0
    dup_acks: int = 0
    zero_window: int = 0
    # Sender stalled against the receiver's advertised window (tshark
    # "TCP window specified by the receiver is now completely full"). Unlike a
    # zero window this is not an application stall: the receiver keeps reading,
    # but the window is too small for the bandwidth-delay product, capping
    # throughput at window/RTT.
    window_full: int = 0
    # Largest TCP payload seen in one captured "segment", and how many exceeded
    # the MSS the peer advertised. On a capture taken above the NIC these are
    # not real packets but TSO/LSO/GSO super-segments the hardware still has to
    # split, which is why they may be many times the MSS.
    max_tcp_len: int = 0
    oversized_segments: int = 0
    # Passive network-quality inputs. initial_rtt_ms = SYN->SYN/ACK network RTT.
    # ack_rtt_samples = per-ACK round-trip times (ms); their deviation is the
    # RTT variation (jitter). data_segments = TCP segments carrying payload
    # (tcp.len>0) = the honest denominator for a loss rate.
    initial_rtt_ms: Optional[float] = None
    ack_rtt_samples: list[float] = field(default_factory=list)
    data_segments: int = 0
    # ACKs for data the capture never saw being sent. The hallmark symptom of
    # asymmetric routing / a single-armed (SPAN) capture: we observe the
    # acknowledgement but not the acknowledged segment, so that direction flowed
    # on a path this capture point does not see.
    ack_lost_segment: int = 0
    # Directional packet/byte counts (client->server vs server->client), used to
    # detect one-way conversations.
    pkts_c2s: int = 0
    pkts_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    syn_count: int = 0
    fin_count: int = 0
    client_reset: bool = False
    server_reset: bool = False
    # IP TTL / IPv6 hop-limit observed on a server->client packet, and whether the
    # server completed the TCP handshake with a SYN/ACK. The TTL reveals the hop
    # distance to (and a coarse OS guess for) the remote host; a seen SYN/ACK
    # confirms the destination port was actually open and reachable.
    server_ttl: Optional[int] = None
    server_synack: bool = False
    mss_values: list[int] = field(default_factory=list)
    # MSS the initiator (flow.src_ip) advertised in its own SYN. Lower than the
    # 1460 standard => the path to this destination has a reduced MTU somewhere.
    client_mss: Optional[int] = None
    is_quic: bool = False
    has_ech: bool = False
    # TLS 1.3 HelloRetryRequest (RFC 8446 §4.1.4): the server refused every
    # key_share the client guessed and made it redo the exchange with a group of
    # the server's choosing, costing one extra round trip. hrr_offered_groups =
    # what the first ClientHello carried; hrr_selected_group = what the client
    # was forced back to.
    hello_retry_request: bool = False
    hrr_offered_groups: list[str] = field(default_factory=list)
    hrr_selected_group: Optional[str] = None
    app_data_seen: bool = False
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    http_statuses: list[str] = field(default_factory=list)
    handshake_complete: bool = False
    # Explicit-proxy / HTTP CONNECT tunnel
    is_connect_tunnel: bool = False
    connect_target: Optional[str] = None      # e.g. "chatgpt.com:443"
    connect_status: Optional[str] = None      # e.g. "200"
    connect_phrase: Optional[str] = None      # e.g. "Connection established"
    proxy_ip: Optional[str] = None            # the proxy the client talks to
    proxy_provider: Optional[str] = None      # e.g. "Cisco Secure Access SWG ingress (Germany)"
    is_private_access: bool = False           # endpoint in 100.64.0.0/10 CGNAT (ZTNA/Private Access)
    is_internal: bool = False                 # both endpoints private (private->private LAN/ZTNA, not SIA)
    # Local TLS interception chain (set by findings.interception._local_interception_findings).
    # A loopback leg re-signed by a local agent is the FIRST hop; its matched outbound
    # flow (same host, close in time) is the probable SECOND hop.
    intercept_vendor: Optional[str] = None    # this loopback leg is decrypted locally by this agent
    chain_outbound_key: Optional[str] = None  # on a loopback leg: key of the probable outbound leg
    chain_loopback_key: Optional[str] = None  # on an outbound leg: key of the loopback leg that mirrors it
    # Inner TLS observed INSIDE the CONNECT tunnel (second-pass dissection).
    # In TLS 1.3 the certificate is encrypted, so only ClientHello/ServerHello
    # and SNI are visible from a passive capture.
    tunnel_sni: Optional[str] = None
    tunnel_tls_version: Optional[str] = None
    tunnel_client_hello: bool = False
    tunnel_server_hello: bool = False
    tunnel_alerts: list[dict[str, Any]] = field(default_factory=list)
    # Inner certificate, only available when a keylog file decrypts TLS 1.3.
    tunnel_certificates_hex: list[str] = field(default_factory=list)

    @property
    def start_time(self) -> float:
        return self.packets[0].time_epoch if self.packets else 0.0

    @property
    def end_time(self) -> float:
        return self.packets[-1].time_epoch if self.packets else 0.0


def build_flows(packets: list[Packet]) -> list[Flow]:
    flows: dict[str, Flow] = {}
    syn_assigned: set[str] = set()

    for pkt in packets:
        tcp_stream = pkt.first("tcp.stream")
        udp_stream = pkt.first("udp.stream")

        if tcp_stream is not None:
            key = f"tcp-{tcp_stream}"
            transport = "tcp"
        elif udp_stream is not None:
            key = f"udp-{udp_stream}"
            transport = "udp"
        else:
            continue  # non TCP/UDP (e.g. pure DNS over something else) handled elsewhere

        flow = flows.get(key)
        if flow is None:
            flow = Flow(key=key, transport=transport)
            flows[key] = flow
        flow.packets.append(pkt)

        # Endpoints (set on first sighting; client is the SYN sender for TCP)
        src_ip = pkt.first("ip.src") or pkt.first("ipv6.src")
        dst_ip = pkt.first("ip.dst") or pkt.first("ipv6.dst")
        if transport == "tcp":
            sport = _to_int(pkt.first("tcp.srcport"))
            dport = _to_int(pkt.first("tcp.dstport"))
            syn = pkt.first("tcp.flags.syn")
            ack = pkt.first("tcp.flags.ack")
            # Identify client side from the initial SYN (syn=1, ack=0)
            if syn in ("1", "True") and ack in ("0", "False") and key not in syn_assigned:
                flow.src_ip, flow.dst_ip = src_ip, dst_ip
                flow.src_port, flow.dst_port = sport, dport
                syn_assigned.add(key)
        else:
            sport = _to_int(pkt.first("udp.srcport"))
            dport = _to_int(pkt.first("udp.dstport"))

        if flow.src_ip is None:
            flow.src_ip, flow.dst_ip = src_ip, dst_ip
            flow.src_port, flow.dst_port = sport, dport

    # Mid-stream (orphan) TCP flows: the capture began AFTER the 3-way handshake,
    # so we never saw the SYN and the "first packet seen" above may have picked the
    # SERVER as the source (servers often transmit first in a mid-stream capture),
    # which would reverse client/server, the c2s/s2c direction and the displayed
    # host. Recover the roles with the standard port heuristic: the lower /
    # well-known port (e.g. 443, 80) is the server and the high ephemeral port is
    # the client. If our provisional source holds the LOWER port, it is really the
    # server, so swap so that src_ip is the client (as it would be from a SYN).
    for flow in flows.values():
        if (flow.transport == "tcp" and flow.key not in syn_assigned
                and flow.src_port is not None and flow.dst_port is not None
                and flow.src_port < flow.dst_port):
            flow.src_ip, flow.dst_ip = flow.dst_ip, flow.src_ip
            flow.src_port, flow.dst_port = flow.dst_port, flow.src_port

    return list(flows.values())


# --- Second-pass: TLS dissection INSIDE HTTP CONNECT tunnels -----------------

_TUNNEL_TLS_FIELDS = [
    "tcp.stream",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.version",
    "tls.handshake.certificate",
    "tls.alert_message.level",
    "tls.alert_message.desc",
]


def run_tunnel_tls(pcap_path: str, tshark_path: Optional[str] = None,
                   keylog_file: Optional[str] = None) -> dict[str, dict[str, Any]]:
    """Second tshark pass that forces TLS dissection over port 443 with the HTTP
    dissector disabled, so the TLS handshake carried *inside* an HTTP CONNECT
    tunnel becomes visible (SNI, negotiated version, ClientHello/ServerHello,
    alerts). Returns a dict keyed by ``tcp-<stream>``.

    In TLS 1.3 the server Certificate is encrypted, so it is only visible when a
    matching ``keylog_file`` (SSLKEYLOGFILE) is supplied to decrypt the session.
    """
    exe = tshark_path or find_tshark()
    if not exe:
        return {}

    cmd = [exe, "-r", pcap_path, "-T", "json", "-n",
           "--disable-protocol", "http",
           "-d", "tcp.port==443,tls"]
    if keylog_file and os.path.isfile(keylog_file):
        cmd += ["-o", f"tls.keylog_file:{keylog_file}"]
    for f in _TUNNEL_TLS_FIELDS:
        cmd += ["-e", f]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        data = json.loads(proc.stdout or "[]")
    except (OSError, json.JSONDecodeError):
        return {}

    out: dict[str, dict[str, Any]] = {}
    for item in data:
        layers = item.get("_source", {}).get("layers", {})
        streams = layers.get("tcp.stream") or []
        if isinstance(streams, str):
            streams = [streams]
        if not streams:
            continue
        key = f"tcp-{streams[0]}"
        rec = out.setdefault(key, {
            "sni": None, "version": None,
            "client_hello": False, "server_hello": False, "alerts": [],
            "certificates_hex": [],
        })

        htypes = layers.get("tls.handshake.type") or []
        if isinstance(htypes, str):
            htypes = [htypes]
        if "1" in htypes:
            rec["client_hello"] = True
        if "2" in htypes:
            rec["server_hello"] = True

        certs = layers.get("tls.handshake.certificate")
        if certs:
            if isinstance(certs, str):
                certs = [certs]
            rec["certificates_hex"].extend(certs)

        sni = layers.get("tls.handshake.extensions_server_name")
        if sni:
            rec["sni"] = sni[0] if isinstance(sni, list) else sni

        sv = layers.get("tls.handshake.extensions.supported_version")
        if sv:
            sv_val = sv[-1] if isinstance(sv, list) else sv
            if sv_val == "0x0304" or "0x0304" in (sv if isinstance(sv, list) else [sv]):
                rec["version"] = "TLS 1.3"
            elif rec["version"] is None:
                rec["version"] = _tls_version_name(sv_val)

        lvls = layers.get("tls.alert_message.level") or []
        descs = layers.get("tls.alert_message.desc") or []
        if isinstance(lvls, str):
            lvls = [lvls]
        if isinstance(descs, str):
            descs = [descs]
        for i, lvl in enumerate(lvls):
            desc = descs[i] if i < len(descs) else None
            rec["alerts"].append({"level": lvl, "desc": desc})

    return out


def _tls_version_name(raw: Optional[str]) -> Optional[str]:
    return {
        "0x0304": "TLS 1.3", "0x0303": "TLS 1.2",
        "0x0302": "TLS 1.1", "0x0301": "TLS 1.0",
    }.get(raw, raw)


def merge_tunnel_tls(flows: list[Flow], tunnel_data: dict[str, dict[str, Any]]) -> None:
    """Attach second-pass tunnel TLS info onto the matching flows by stream key."""
    for flow in flows:
        rec = tunnel_data.get(flow.key)
        if not rec:
            continue
        # Only meaningful for CONNECT tunnels (the main pass already dissects
        # direct TLS). Require at least a ClientHello to avoid noise.
        if not rec.get("client_hello"):
            continue
        flow.tunnel_client_hello = rec.get("client_hello", False)
        flow.tunnel_server_hello = rec.get("server_hello", False)
        flow.tunnel_sni = rec.get("sni")
        flow.tunnel_tls_version = rec.get("version")
        flow.tunnel_alerts = rec.get("alerts", [])
        flow.tunnel_certificates_hex = rec.get("certificates_hex", [])
