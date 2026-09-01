"""Flow-level correlation across a DART bundle, a packet capture and a HAR.

Each of the three artefacts holds a different, and individually misleading,
view of the same browsing session:

* The **HAR** knows hostnames, URLs, status codes and timings, but when the
  endpoint is steered it records a *synthetic* server address that exists
  nowhere on the network.
* The **capture** sees two legs: the browser talking to the agent's local
  listener (which carries the real TLS SNI) and the agent's tunnel to the
  headend (which is encrypted and names no hosts).
* The **bundle** knows what the agent believed it was doing, and identifies
  each connection it handled, but has no idea which website that was.

Joined, they answer a question none of them can answer alone: for this
hostname, was the flow steered or did it go direct, which tunnel carried it,
and what did the agent report about that tunnel.

Two join keys are used, and they are **not** of equal strength. The module
records which one produced each link so a reader is never invited to treat an
association as a measurement:

``JoinStrength.EXACT``
    The agent names connections as ``<proto>_<srcport>__<dstip>:<dstport>``
    (prefixes ``tcp_``, ``tls_``, ``http2_``). That is a complete TCP
    connection identity, so matching it against the capture needs no clock and
    admits no ambiguity.

``JoinStrength.OBSERVED``
    A hostname seen in TLS SNI on the wire, matched to the same hostname in the
    HAR. The wire is the measurement.

``JoinStrength.ASSOCIATED``
    Everything that rests on time or on HTTP/2 multiplexing. Many browser
    requests share one tunnel connection, so a request cannot be attributed to
    a specific tunnel flow. Reported as association, never as proof.
"""
from __future__ import annotations

import json
import os
import re
import statistics
import subprocess
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

_LOOPBACK = {"127.0.0.1", "::1"}

# A ZTA log routinely covers days, and ephemeral source ports are reused within
# that span. Connection identity is therefore unique only inside a window, so
# the agent's lines for one identity are split wherever it fell silent for
# longer than this - each run is treated as a separate connection.
_EPISODE_GAP = timedelta(minutes=5)

# How far apart a wire flow and an agent episode may start and still be taken
# for the same connection. Generous enough to absorb a modest clock difference
# between the two artefacts, far tighter than the reuse interval it guards.
_MATCH_TOLERANCE = timedelta(minutes=15)

# Both sides of the app-flow/tunnel join are written by the same process into
# the same file, for the same event, at the same instant. This does not need to
# absorb a clock difference - only the gap between two consecutive writes.
_STREAM_TOLERANCE = timedelta(seconds=1)

# The agent writes one of these prefixes depending on which transport handled
# the connection. Grepping only for "tcp_" silently misses every multiplexed
# tunnel, which is where the interesting events live.
_AGENT_FLOW_RE = re.compile(
    r"\b(?P<proto>tcp|tls|udp|http2)_(?P<sport>\d{1,5})__(?P<dip>[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(?P<dport>\d{1,5})\b"
)

# The agent writes a *second*, differently punctuated identifier for the flow
# between the application and its own listener - a colon instead of the first
# underscore, and the destination as the **name or address the application
# asked for** rather than the headend it was tunnelled to:
#
#     AppSocketTransport::handleClose() tcp:50299__enroll.cisco.com 12899BF0 stream=1
#
# This is the only place in any of the three artefacts where a destination the
# user recognises is stated by the agent itself, and it carries the source port
# that leads straight into the capture. Matching only the underscore form above
# misses it entirely.
_AGENT_APP_RE = re.compile(
    r"\b(?P<proto>tcp|tls|udp|http2):(?P<sport>\d{1,5})__(?P<dest>[A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9])"
)
_AGENT_STREAM_RE = re.compile(r"\bstream=(?P<stream>\d+)")
_AGENT_REASON_RE = re.compile(r"closing due to reason:\s*(?P<reason>[a-z_]+)")
_AGENT_METHOD_RE = re.compile(r"\b(?P<cls>[A-Za-z][A-Za-z0-9]*)::(?P<method>[A-Za-z0-9_]+)\(\)")

# Which side of the flow a log line is about. The agent names the subsystem it
# was in, and that is a fact rather than an inference: `AppSocket*` lines are
# about the socket facing the application, `NextTransport`/`Tunnel` lines are
# about the leg facing Secure Access. This is *not* packet direction - the
# correlation has no packet list - and the UI says so.
_APP_SIDE_HINTS = ("appsocket", "socketread", "socketwrite", "connecttimeout", "onapp")
_TUNNEL_SIDE_HINTS = ("nexttransport", "tunnel", "transportmgr", "http2", "proxy", "downstream")

# How many events a single flow contributes before the middle is elided. A
# reader needs the opening and the ending; the repetitive middle of a long
# flow is what makes a ladder unreadable.
_TIMELINE_EDGE = 18
_AGENT_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)")
_AGENT_LEVEL_RE = re.compile(r"\s(?P<level>[IWE])/\s")


class JoinStrength(str, Enum):
    """How a link between two artefacts was established."""

    EXACT = "exact"
    OBSERVED = "observed"
    ASSOCIATED = "associated"


class Steering(str, Enum):
    """What the wire says happened to a hostname's traffic."""

    STEERED = "steered"
    DIRECT = "direct"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class WireFlow:
    """One TCP connection as observed in the capture."""

    stream: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    sni: str | None = None
    packets: int = 0
    bytes: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    has_syn: bool = False
    """Whether the handshake was captured. If not, ``first_seen`` is when the
    capture began rather than when the connection opened."""
    isn: int | None = None
    """The client's raw initial sequence number, from the SYN.

    This is the one field that survives a hop unchanged. A router or firewall
    forwards the sequence number it was given, so the same connection seen at
    two vantage points carries the same ISN even through NAT, which rewrites
    addresses and ports but not sequence numbers. A proxy, by contrast,
    terminates the connection and opens a new one with an ISN of its own -
    which is how this tool tells forwarding and proxying apart rather than
    assuming which one a device does."""
    peer_isn: int | None = None
    """The server's initial sequence number, from the SYN/ACK."""
    rtts: tuple[float, ...] = ()
    """Round trips measured from ACKs arriving from the peer, in seconds.

    Only the peer's ACKs are counted. An ACK this machine sends measures how
    quickly its own stack replied to data that had already arrived - real, but
    microseconds, and with no network in it."""
    retransmissions: int = 0
    duplicate_acks: int = 0
    zero_windows: int = 0
    out_of_order: int = 0
    handshake_rtt: float | None = None
    """SYN to SYN/ACK, in seconds. The cleanest RTT there is, because it is one
    round trip with nothing else in flight - but only available when the
    handshake was captured."""
    head: tuple[tuple[float, str, int, str, int], ...] = ()
    tail: tuple[tuple[float, str, int, str, int], ...] = ()
    """The opening and closing packets of the connection, as
    ``(epoch, src_ip, src_port, kind, payload_bytes)``. An intercepted flow has
    a real client and a real server, so it has a real packet ladder - these are
    what draws it. The middle of a long flow is elided, and the count says so."""
    # What the connection said, summarised. Deliberately scalars and small
    # tuples: this model is held for every flow in a session, so it must not
    # grow with the number of packets.
    tls_version: str | None = None
    alpn: tuple[str, ...] = ()
    handshake_seen: tuple[str, ...] = ()
    """Which TLS handshake messages appeared, in order of first appearance."""
    tls_alerts: tuple[str, ...] = ()
    http_methods: tuple[str, ...] = ()
    http_statuses: tuple[str, ...] = ()
    first_uri: str | None = None
    client_bytes: int = 0
    server_bytes: int = 0
    """Payload each way. A connection that sends far more than it receives is
    doing something other than what it was opened for."""

    @property
    def is_loopback(self) -> bool:
        return self.src_ip in _LOOPBACK or self.dst_ip in _LOOPBACK

    @property
    def identity(self) -> tuple[int, str, int]:
        """The key the agent also records: source port plus destination."""
        return (self.src_port, self.dst_ip, self.dst_port)

    @property
    def label(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"


@dataclass(frozen=True)
class AgentFlow:
    """One connection the agent reported handling, from the ZTA log."""

    proto: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    lines: int = 0
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    streams: tuple[tuple[int, datetime], ...] = ()
    """``(stream id, when)`` for every HTTP/2 stream this tunnel was seen
    handling. An app flow names the stream it was given, and the two log lines
    are written at the same instant, so the pair identifies the tunnel far more
    tightly than the stream number alone - which restarts on every connection."""

    @property
    def identity(self) -> tuple[int, str, int]:
        return (self.src_port, self.dst_ip, self.dst_port)

    @property
    def label(self) -> str:
        return f"{self.proto}_{self.src_port}__{self.dst_ip}:{self.dst_port}"


@dataclass(frozen=True)
class AppFlow:
    """One connection the agent intercepted, named by the destination asked for.

    ZTA steers on rules written against hosts and addresses, so when a rule
    matches, the agent knows the destination by the name the application used
    and records it. That makes this the join the other two artefacts lack: the
    HAR knows the same name, and the source port here is the same source port
    the capture saw.
    """

    proto: str
    src_port: int
    dest: str
    stream: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    lines: int = 0
    reasons: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    error_lines: int = 0
    events: tuple[tuple[datetime | None, str, str, str], ...] = ()
    """Every line the agent wrote about this flow, in order, as
    ``(when, level, side, message)``. This is the only ordered record any
    artefact holds for an intercepted flow - the capture has packet counts but
    the correlation does not read individual packets."""

    @property
    def label(self) -> str:
        return f"{self.proto}:{self.src_port}__{self.dest}"


@dataclass(frozen=True)
class WebRequest:
    """One HTTP request as the browser recorded it."""

    url: str
    host: str | None
    method: str
    status: int | None
    server_ip: str | None
    started: datetime | None
    duration_ms: float | None
    bytes: int = 0
    page: str | None = None
    """The HAR page this request was loaded under.

    A site is not a host. Opening one page pulls in scripts, images and
    beacons from dozens of others, and the browser is the only artefact that
    knows which of them belonged to that page. Keeping the grouping means a
    question about a page can be answered as one, instead of being answered
    about the single host that happens to share its name."""

    @property
    def failed(self) -> bool:
        return self.status is not None and self.status >= 400


@dataclass
class HostCorrelation:
    """Everything the three artefacts say about one hostname."""

    host: str
    steering: Steering = Steering.UNKNOWN
    steering_basis: str = ""
    join_strength: JoinStrength = JoinStrength.ASSOCIATED
    requests: list[WebRequest] = field(default_factory=list)
    synthetic_ips: list[str] = field(default_factory=list)
    real_peers: list[str] = field(default_factory=list)
    local_flows: list[WireFlow] = field(default_factory=list)
    direct_flows: list[WireFlow] = field(default_factory=list)

    @property
    def request_count(self) -> int:
        return len(self.requests)

    @property
    def failures(self) -> list[WebRequest]:
        return [r for r in self.requests if r.failed]


@dataclass
class TunnelCorrelation:
    """One tunnel connection, seen from both the wire and the agent."""

    wire: WireFlow
    agent: AgentFlow
    strength: JoinStrength = JoinStrength.EXACT

    @property
    def identity(self) -> tuple[int, str, int]:
        return self.wire.identity


@dataclass
class FlowCorrelation:
    """One intercepted flow, followed across every artefact that saw it.

    This is the record the other views cannot produce: the destination the
    application asked for, what the agent did with that connection and why it
    ended, the packets that carry it, and what the browser got back.

    A flow exists if **any** artefact names it. Keying only on the agent's log
    lost every flow that worked: with trace logging off the agent writes the
    destination only when something goes wrong, so a capture full of loopback
    connections carrying a hostname - and a HAR full of requests to it -
    produced no flow at all. The agent's account is one source among three,
    not the price of admission.
    """

    destination: str
    src_port: int
    app: AppFlow | None = None
    wire: WireFlow | None = None
    wire_strength: JoinStrength = JoinStrength.ASSOCIATED
    wire_basis: str = ""
    tunnel: AgentFlow | None = None
    tunnel_basis: str = ""
    requests: list[WebRequest] = field(default_factory=list)
    intercepted_by: str = ""
    intercepted_basis: str = ""

    @property
    def failures(self) -> list[WebRequest]:
        return [r for r in self.requests if r.failed]

    @property
    def label(self) -> str:
        if self.app is not None:
            return self.app.label
        proto = "tls" if self.wire is not None and self.wire.sni else "tcp"
        return f"{proto}:{self.src_port}__{self.destination}"

    @property
    def severity(self) -> str:
        """Worst-first ordering, from what is actually recorded."""
        if (self.app is not None and self.app.reasons) or self.failures:
            return "problem"
        if self.app is not None and self.app.error_lines:
            return "warning"
        return "info"


@dataclass
class SessionCorrelation:
    """The joined result, plus an explicit record of what it could not answer."""

    hosts: list[HostCorrelation] = field(default_factory=list)
    tunnels: list[TunnelCorrelation] = field(default_factory=list)
    flows: list[FlowCorrelation] = field(default_factory=list)
    clock_offset: timedelta | None = None
    clock_offset_basis: str = ""
    notes: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)
    focus: str = ""
    """The hostname the operator named as affected, if any. Scopes the report."""

    @property
    def steered_hosts(self) -> list[HostCorrelation]:
        return [h for h in self.hosts if h.steering is Steering.STEERED]

    @property
    def direct_hosts(self) -> list[HostCorrelation]:
        return [h for h in self.hosts if h.steering is Steering.DIRECT]


# --- capture ---------------------------------------------------------------

_TSHARK_FIELDS = (
    "frame.time_epoch",
    "frame.len",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tls.handshake.extensions_server_name",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.len",
    "tcp.seq_raw",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.out_of_order",
    # What the packets actually said. Without these a ladder can only show that
    # bytes moved; with them the same single pass can say the handshake
    # completed, the peer refused, or the server answered 403.
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.record.version",
    # TLS 1.3 pins the legacy version field at 0x0303 for middlebox
    # compatibility, so reading only that would report every 1.3 session as
    # 1.2. The real answer is in the supported_versions extension.
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extensions_alpn_str",
    "tls.alert_message.desc",
    "http.request.method",
    "http.request.full_uri",
    "http.response.code",
)

_TLS_VERSIONS = {
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
}

# TLS handshake message numbers worth naming in a ladder (RFC 8446 B.3).
_TLS_HANDSHAKE = {
    "1": "clienthello",
    "2": "serverhello",
    "11": "certificate",
    "12": "serverkeyexchange",
    "14": "serverhellodone",
    "16": "clientkeyexchange",
    "20": "finished",
}

# How many packets of a connection are kept for its ladder, from each end. A
# 7,256-packet flow is not readable and not worth holding in memory; the
# opening and the ending are what a reader needs, and the elided middle is
# stated rather than dropped silently.
_PACKET_EDGE = 40


def extract_wire_flows(capture_path: str, tshark_path: str | None = None) -> list[WireFlow]:
    """Read TCP flows, with any TLS SNI, out of a capture.

    One pass over the capture. Flows are keyed by ``tcp.stream`` because it is
    stable across the capture's several link layers - a capture taken on the
    endpoint holds both the loopback leg to the agent and the physical leg to
    the network, and they must not be conflated.
    """
    from capture_inspector.pcap import find_tshark

    exe = tshark_path or find_tshark()
    if not exe:
        raise RuntimeError(
            "tshark (Wireshark CLI) was not found, so the capture cannot be read."
        )

    cmd = [exe, "-r", capture_path, "-Y", "tcp", "-T", "fields", "-E", "separator=/t"]
    for name in _TSHARK_FIELDS:
        cmd += ["-e", name]

    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, paths are ours
        cmd, capture_output=True, text=True, check=False
    )
    if completed.returncode != 0 and not completed.stdout:
        raise RuntimeError(f"tshark failed to read the capture: {completed.stderr.strip()[:400]}")

    building: dict[int, dict] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(_TSHARK_FIELDS):
            continue
        (
            epoch,
            length,
            src,
            dst,
            sport,
            dport,
            stream,
            sni,
            syn,
            ack,
            fin,
            rst,
            payload,
            seq_raw,
            ack_rtt,
            retrans,
            fast_retrans,
            dup_ack,
            zero_window,
            out_of_order,
            hs_type,
            hs_version,
            rec_version,
            supported_version,
            alpn,
            alert_desc,
            http_method,
            http_uri,
            http_code,
        ) = parts[: len(_TSHARK_FIELDS)]
        if not stream or not sport or not dport:
            continue
        try:
            key = int(stream)
            when = datetime.fromtimestamp(float(epoch)) if epoch else None
            size = int(length) if length else 0
        except ValueError:
            continue

        is_syn = syn in {"1", "True"} and ack not in {"1", "True"}
        is_ack = ack in {"1", "True"}
        try:
            payload_bytes = int(payload) if payload else 0
            moment = float(epoch) if epoch else 0.0
        except ValueError:
            payload_bytes = 0
            moment = 0.0

        # Name the packet by what it carried, not merely that it carried
        # something. A reader can act on "the server refused with a certificate
        # alert"; "Data 517B" tells them nothing.
        handshakes = [_TLS_HANDSHAKE[v] for v in hs_type.split(",")
                      if v.strip() in _TLS_HANDSHAKE for v in [v.strip()]]
        if rst in {"1", "True"}:
            kind = "rst"
        elif fin in {"1", "True"}:
            kind = "fin"
        elif is_syn:
            kind = "syn"
        elif syn in {"1", "True"} and is_ack:
            kind = "synack"
        elif alert_desc:
            kind = "alert"
        elif handshakes:
            kind = handshakes[0]
        elif http_code:
            kind = "http_response"
        elif http_method:
            kind = "http_request"
        elif payload_bytes:
            kind = "data"
        else:
            kind = "ack"

        rec = building.get(key)
        if rec is None:
            rec = {
                "src_ip": src,
                "src_port": int(sport),
                "dst_ip": dst,
                "dst_port": int(dport),
                "sni": None,
                "packets": 0,
                "bytes": 0,
                "first": when,
                "last": when,
                "anchored": False,
                "isn": None,
                "peer_isn": None,
                "rtts": [],
                "retrans": 0,
                "dup_ack": 0,
                "zero_window": 0,
                "out_of_order": 0,
                "syn_at": None,
                "synack_at": None,
                "tls_version": None,
                "alpn": [],
                "handshakes": [],
                "alerts": [],
                "methods": [],
                "statuses": [],
                "first_uri": None,
                "client_bytes": 0,
                "server_bytes": 0,
                "head": [],
                "tail": deque(maxlen=_PACKET_EDGE),
            }
            building[key] = rec

        # Getting direction right is not cosmetic: the source port is half the
        # key the agent records, so a flow held the wrong way round simply
        # fails to join. A SYN without an ACK names the client beyond doubt.
        # Captures often start mid-connection, though, so when no handshake was
        # recorded the lower port is taken to be the listener - true for both
        # 443 on the network and the agent's local listener.
        if is_syn and not rec["anchored"]:
            rec.update(
                src_ip=src, src_port=int(sport), dst_ip=dst, dst_port=int(dport), anchored=True
            )
        elif not rec["anchored"] and rec["src_port"] < rec["dst_port"]:
            rec.update(
                src_ip=rec["dst_ip"],
                src_port=rec["dst_port"],
                dst_ip=rec["src_ip"],
                dst_port=rec["src_port"],
            )
        rec["packets"] += 1
        rec["bytes"] += size
        if ack_rtt:
            try:
                # Keep who sent it. Wireshark attaches ack_rtt to every ACK,
                # including the ones this machine sends to acknowledge the
                # peer's data - those measure how fast the local stack replied,
                # which is microseconds and has no network in it. Only an ACK
                # arriving *from* the peer measures a round trip, and mixing
                # the two produced a median of 0.333 ms for a tunnel to a
                # headend across the internet.
                rec["rtts"].append((src, int(sport), float(ack_rtt)))
            except ValueError:
                pass
        if retrans or fast_retrans:
            rec["retrans"] += 1
        if dup_ack:
            rec["dup_ack"] += 1
        if zero_window:
            rec["zero_window"] += 1
        if out_of_order:
            rec["out_of_order"] += 1
        if kind == "syn" and rec["syn_at"] is None:
            rec["syn_at"] = moment
        elif kind == "synack" and rec["synack_at"] is None:
            rec["synack_at"] = moment
        if kind == "syn" and rec["isn"] is None and seq_raw:
            try:
                rec["isn"] = int(seq_raw)
            except ValueError:
                pass
        elif kind == "synack" and rec["peer_isn"] is None and seq_raw:
            try:
                rec["peer_isn"] = int(seq_raw)
            except ValueError:
                pass
        event = (moment, src, int(sport), kind, payload_bytes)
        if len(rec["head"]) < _PACKET_EDGE:
            rec["head"].append(event)
        else:
            rec["tail"].append(event)

        # Each list is capped: a connection can carry hundreds of requests and
        # this model is kept for every flow in the session.
        from_client = src == rec["src_ip"] and int(sport) == rec["src_port"]
        if payload_bytes:
            rec["client_bytes" if from_client else "server_bytes"] += payload_bytes
        for name in handshakes:
            if name not in rec["handshakes"] and len(rec["handshakes"]) < 12:
                rec["handshakes"].append(name)
        # The ServerHello's supported_version is the negotiated one; the legacy
        # field only says what the connection is compatible with.
        chosen = ""
        for token in (supported_version or "").split(","):
            token = token.strip().lower()
            if token in _TLS_VERSIONS:
                chosen = token
                break
        if not chosen:
            chosen = (hs_version or rec_version or "").split(",")[0].strip().lower()
        named = _TLS_VERSIONS.get(chosen)
        if named and (not rec["tls_version"] or named > rec["tls_version"]):
            rec["tls_version"] = named
        for token in (alpn or "").split(","):
            token = token.strip()
            if token and token not in rec["alpn"] and len(rec["alpn"]) < 4:
                rec["alpn"].append(token)
        for token in (alert_desc or "").split(","):
            token = token.strip()
            if token and len(rec["alerts"]) < 6:
                rec["alerts"].append(token)
        if http_method and len(rec["methods"]) < 6:
            rec["methods"].append(http_method.split(",")[0].strip())
        if http_code and len(rec["statuses"]) < 8:
            rec["statuses"].append(http_code.split(",")[0].strip())
        if http_uri and not rec["first_uri"]:
            rec["first_uri"] = http_uri.split(",")[0].strip()[:200]

        if sni and not rec["sni"]:
            rec["sni"] = sni.split(",")[0].strip()
        if when:
            if rec["first"] is None or when < rec["first"]:
                rec["first"] = when
            if rec["last"] is None or when > rec["last"]:
                rec["last"] = when

    return [
        WireFlow(
            stream=key,
            src_ip=rec["src_ip"],
            src_port=rec["src_port"],
            dst_ip=rec["dst_ip"],
            dst_port=rec["dst_port"],
            sni=rec["sni"],
            packets=rec["packets"],
            bytes=rec["bytes"],
            first_seen=rec["first"],
            last_seen=rec["last"],
            has_syn=rec["anchored"],
            isn=rec["isn"],
            peer_isn=rec["peer_isn"],
            rtts=tuple(
                value
                for who, port, value in rec["rtts"]
                if not (who == rec["src_ip"] and port == rec["src_port"])
            ),
            retransmissions=rec["retrans"],
            duplicate_acks=rec["dup_ack"],
            zero_windows=rec["zero_window"],
            out_of_order=rec["out_of_order"],
            handshake_rtt=(
                rec["synack_at"] - rec["syn_at"]
                if rec["syn_at"] is not None and rec["synack_at"] is not None
                else None
            ),
            head=tuple(rec["head"]),
            tail=tuple(rec["tail"]),
            tls_version=rec["tls_version"],
            alpn=tuple(rec["alpn"]),
            handshake_seen=tuple(rec["handshakes"]),
            tls_alerts=tuple(rec["alerts"]),
            http_methods=tuple(rec["methods"]),
            http_statuses=tuple(rec["statuses"]),
            first_uri=rec["first_uri"],
            client_bytes=rec["client_bytes"],
            server_bytes=rec["server_bytes"],
        )
        for key, rec in sorted(building.items())
    ]


# --- bundle ----------------------------------------------------------------


def find_zta_log(bundle_dir: str) -> str | None:
    """Locate the Zero Trust Access log inside an unpacked bundle."""
    for root, _dirs, files in os.walk(bundle_dir):
        if "zero trust access" not in root.lower():
            continue
        for name in files:
            if name.lower().startswith("zerotrustaccess") and name.lower().endswith(".txt"):
                return os.path.join(root, name)
    return None


def extract_agent_flows(zta_log_path: str) -> list[AgentFlow]:
    """Read the connections the agent reported handling.

    Timestamps in this log are **local time with no offset recorded**, so they
    are kept naive here. They are never used to establish a join; the join is
    made on connection identity, and the offset is derived afterwards from
    flows that matched.

    One identity may yield several results. Source ports are recycled, and a
    log covering days will show the same identity belonging to unrelated
    connections, so a run of activity separated by a long silence is reported
    as its own connection rather than merged into one implausibly long-lived
    flow.
    """
    episodes: dict[tuple[int, str, int], list[dict]] = defaultdict(list)

    with open(zta_log_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _AGENT_FLOW_RE.search(line)
            if not match:
                continue
            key = (int(match["sport"]), match["dip"], int(match["dport"]))

            when: datetime | None = None
            stamp = _AGENT_TS_RE.match(line)
            if stamp:
                text = stamp["ts"]
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                    try:
                        when = datetime.strptime(text, fmt)
                        break
                    except ValueError:
                        continue

            runs = episodes[key]
            rec = runs[-1] if runs else None
            if rec is None or (
                when is not None and rec["last"] is not None and when - rec["last"] > _EPISODE_GAP
            ):
                rec = {
                    "proto": match["proto"],
                    "first": when,
                    "last": when,
                    "lines": 0,
                    "errors": [],
                    "warnings": [],
                    "streams": [],
                }
                runs.append(rec)
            rec["lines"] += 1
            # http2 is the most specific transport the agent reports for a
            # connection; prefer it so the label matches what an engineer greps.
            if match["proto"] == "http2":
                rec["proto"] = "http2"
            if when:
                if rec["first"] is None or when < rec["first"]:
                    rec["first"] = when
                if rec["last"] is None or when > rec["last"]:
                    rec["last"] = when

            level = _AGENT_LEVEL_RE.search(line)
            if level:
                message = _summarise_agent_line(line)
                if level["level"] == "E" and message not in rec["errors"]:
                    rec["errors"].append(message)
                elif level["level"] == "W" and message not in rec["warnings"]:
                    rec["warnings"].append(message)

            stream = _AGENT_STREAM_RE.search(line)
            if stream and when is not None:
                rec["streams"].append((int(stream["stream"]), when))

    return [
        AgentFlow(
            proto=rec["proto"],
            src_port=key[0],
            dst_ip=key[1],
            dst_port=key[2],
            first_seen=rec["first"],
            last_seen=rec["last"],
            lines=rec["lines"],
            errors=tuple(rec["errors"][:6]),
            warnings=tuple(rec["warnings"][:6]),
            streams=tuple(rec["streams"]),
        )
        for key, runs in sorted(episodes.items())
        for rec in runs
    ]


def extract_app_flows(zta_log_path: str) -> list[AppFlow]:
    """Read the intercepted connections the agent named by destination.

    Split into episodes on the same reasoning as ``extract_agent_flows``: the
    key here is source port plus destination, and source ports are recycled.

    A caveat that must travel with every result read from these lines. With
    trace-level logging off - which is the default, and was the case in the
    bundle this was built against - the agent writes the destination name only
    when it has something to report about that flow. In the test bundle **680
    of 688** such lines were error level. So this is a list of flows the agent
    had trouble with, and a destination missing from it is a destination the
    agent logged no problem for, which is not the same as one that worked.
    """
    episodes: dict[tuple[int, str], list[dict]] = defaultdict(list)

    with open(zta_log_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = _AGENT_APP_RE.search(line)
            if not match:
                continue
            key = (int(match["sport"]), match["dest"])
            when = _agent_time(line)

            runs = episodes[key]
            rec = runs[-1] if runs else None
            if rec is None or (
                when is not None and rec["last"] is not None and when - rec["last"] > _EPISODE_GAP
            ):
                rec = {
                    "proto": match["proto"],
                    "stream": None,
                    "first": when,
                    "last": when,
                    "lines": 0,
                    "reasons": [],
                    "errors": [],
                    "error_lines": 0,
                    "events": [],
                }
                runs.append(rec)
            rec["lines"] += 1
            if when:
                if rec["first"] is None or when < rec["first"]:
                    rec["first"] = when
                if rec["last"] is None or when > rec["last"]:
                    rec["last"] = when

            stream = _AGENT_STREAM_RE.search(line)
            if stream and rec["stream"] is None:
                rec["stream"] = int(stream["stream"])

            reason = _AGENT_REASON_RE.search(line)
            if reason and reason["reason"] not in rec["reasons"]:
                rec["reasons"].append(reason["reason"])

            level = _AGENT_LEVEL_RE.search(line)
            if level and level["level"] == "E":
                rec["error_lines"] += 1
                message = _summarise_agent_line(line)
                if message not in rec["errors"]:
                    rec["errors"].append(message)

            rec["events"].append((
                when,
                level["level"] if level else "I",
                _agent_side(line),
                _summarise_agent_line(line),
            ))

    return [
        AppFlow(
            proto=rec["proto"],
            src_port=key[0],
            dest=key[1],
            stream=rec["stream"],
            first_seen=rec["first"],
            last_seen=rec["last"],
            lines=rec["lines"],
            reasons=tuple(rec["reasons"]),
            errors=tuple(rec["errors"][:6]),
            error_lines=rec["error_lines"],
            events=tuple(rec["events"]),
        )
        for key, runs in sorted(episodes.items())
        for rec in runs
    ]


def _agent_side(line: str) -> str:
    """Which leg of the flow this line is about, from the subsystem it names.

    The agent states the class and method it was in, so this reads a fact
    rather than guessing. The **method** is read first and the class second:
    every one of these lines comes from ``AppSocketTransport``, so matching the
    class would put the whole flow on one side and say nothing -
    ``handleNextTransportStateChange`` is about the tunnel leg however app-ish
    its class name looks.

    This is not packet direction. The correlation never reads packets, and a
    line saying the app socket closed is not a packet travelling anywhere.
    """
    match = _AGENT_METHOD_RE.search(line)
    method = match["method"].lower() if match else ""
    cls = match["cls"].lower() if match else line.lower()

    if any(hint in method for hint in _TUNNEL_SIDE_HINTS):
        return "tunnel"
    if any(hint in method for hint in _APP_SIDE_HINTS):
        return "app"
    if any(hint in cls for hint in _TUNNEL_SIDE_HINTS):
        return "tunnel"
    if any(hint in cls for hint in _APP_SIDE_HINTS):
        return "app"
    return "agent"


def _agent_time(line: str) -> datetime | None:
    """The naive local timestamp a ZTA line opens with, if it has one."""
    stamp = _AGENT_TS_RE.match(line)
    if not stamp:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(stamp["ts"], fmt)
        except ValueError:
            continue
    return None


def _summarise_agent_line(line: str) -> str:
    """Reduce a ZTA log line to the part an engineer would read.

    The prefix (timestamp, process, thread, file and line) is noise once the
    line has been attributed to a flow, and the flow identifier is already
    known from the record it is attached to.
    """
    text = line.strip()
    text = re.sub(r"^\d{4}-\d{2}-\d{2} [\d:.]+\s+", "", text)
    text = re.sub(r"^csc_zta_agent\[[^\]]*\]\s*", "", text)
    text = re.sub(r"^[IWE]/\s*", "", text)
    text = re.sub(r"^\S+\.cpp:\d+\s*", "", text)
    text = _AGENT_FLOW_RE.sub("", text)
    # The flow identifier is already the row this line is attached to, so
    # repeating it in every event leaves no room for what the line actually
    # says. Lambda suffixes are compiler noise for the same reason.
    text = _AGENT_APP_RE.sub("", text)
    text = re.sub(r"::<lambda[^>]*>", "", text)
    text = re.sub(r"\bstream=\d+\s*", "", text)
    text = re.sub(r"\b[0-9A-F]{8}\b", "", text)
    return re.sub(r"\s{2,}", " ", text).strip(" -")[:200]


# --- HAR -------------------------------------------------------------------


def extract_web_requests(har_path: str) -> list[WebRequest]:
    """Read the browser's own record of the session.

    Page membership is read from the HAR rather than guessed from hostnames.
    ``www.bbc.com`` and ``static.files.bbci.co.uk`` share no domain, and no
    string rule could tell that the second was loaded by the first - but the
    browser recorded it, so the browser is asked.
    """
    from urllib.parse import urlparse

    with open(har_path, encoding="utf-8", errors="replace") as handle:
        document = json.load(handle)

    log = document.get("log", {}) or {}
    page_urls: dict[str, str] = {}
    for page in log.get("pages", []) or []:
        page_id = page.get("id")
        if page_id:
            page_urls[str(page_id)] = str(page.get("title") or page.get("url") or "")

    entries = log.get("entries", []) or []
    requests: list[WebRequest] = []
    for entry in entries:
        request = entry.get("request", {}) or {}
        response = entry.get("response", {}) or {}
        url = str(request.get("url", ""))
        if not url:
            continue

        started = None
        raw_started = entry.get("startedDateTime")
        if raw_started:
            try:
                started = datetime.fromisoformat(str(raw_started).replace("Z", "+00:00"))
            except ValueError:
                started = None

        status = response.get("status")
        content = response.get("content", {}) or {}
        requests.append(
            WebRequest(
                url=url,
                host=urlparse(url).hostname,
                method=str(request.get("method", "")).upper() or "GET",
                status=int(status) if isinstance(status, int) and status else None,
                server_ip=(entry.get("serverIPAddress") or "").strip() or None,
                started=started,
                duration_ms=(
                    float(entry["time"]) if isinstance(entry.get("time"), int | float) else None
                ),
                bytes=int(content.get("size") or 0),
                page=page_urls.get(str(entry.get("pageref") or "")) or None,
            )
        )
    return requests


# --- the join --------------------------------------------------------------


def _pick_episode(
    candidates: list[AgentFlow], wire: WireFlow
) -> tuple[AgentFlow | None, int]:
    """Choose which logged connection a captured flow refers to.

    Matching identity alone is not enough once a log spans more than a few
    minutes, because the endpoint will have reused the port. The candidate
    closest in time is taken, and only if it starts within tolerance of the
    captured flow; otherwise the match is refused and counted, so a rejection
    is visible rather than silent.

    Returns the chosen connection, if any, and how many were rejected as reuse.
    """
    if wire.first_seen is None:
        # Without a time on the captured side there is nothing to discriminate
        # with, so a single unambiguous candidate is accepted and several are
        # not - guessing between them would be inventing a result.
        return (candidates[0], 0) if len(candidates) == 1 else (None, 0)

    timed = [c for c in candidates if c.first_seen is not None]
    if not timed:
        return (candidates[0], 0) if len(candidates) == 1 else (None, 0)

    best = min(timed, key=lambda c: abs(c.first_seen - wire.first_seen))
    if abs(best.first_seen - wire.first_seen) <= _MATCH_TOLERANCE:
        return best, len(timed) - 1
    return None, len(timed)


def unpack_bundle(bundle_path: str, work_dir: str) -> str:
    """Unpack a DART bundle for reading, refusing members that escape ``work_dir``."""
    from .facts import _safe_extract

    _safe_extract(bundle_path, work_dir)
    return work_dir


def _iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="milliseconds") if value else None


def normalise_host(value: str) -> str:
    """Reduce whatever was typed to a bare hostname.

    Operators paste what they have: a URL, a host:port, a trailing dot from a
    DNS tool. All three name the same host, and refusing to match them would
    make the focus look broken rather than strict.
    """
    text = (value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("[") and "]" in text:  # bracketed IPv6 literal
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text.rstrip(".")


def _matches_focus(candidate: str, focus: str) -> bool:
    """True when ``candidate`` names the focused host or something under it."""
    host = normalise_host(candidate)
    return bool(host) and (host == focus or host.endswith("." + focus))


def _connection_trace(
    flows: list[FlowCorrelation], scope: list[HostCorrelation], sources: dict[str, str]
) -> dict:
    """Follow one site through the three artefacts, in the order an engineer does.

    The browser says what was asked for. The agent says which connections it
    made to serve it, and - the part that makes the rest possible - the
    **source port** of each. The capture holds those ports. So the chain is not
    three separate tables that happen to be on one screen: each step hands the
    next one its key, and where a step cannot hand anything over, that is
    reported rather than skipped.

    The source port is the join because it is the only identifier all three can
    carry: the agent writes it, the capture sees it, and it is not rewritten in
    transit the way an address is.
    """
    requests_by_host = {entry.host: entry.requests for entry in scope}
    steered = [f for f in flows if f.app is not None]
    on_wire = [f for f in flows if f.wire is not None]
    ports = sorted({f.src_port for f in steered})
    matched_ports = sorted({f.src_port for f in steered if f.wire is not None})

    # When step 2 hands over ports that step 3 cannot find, the usual reason is
    # not that the join failed but that the two artefacts cover different
    # minutes. Saying so turns an empty column into an answer, and tells the
    # reader what to collect next.
    def _span(times: list[datetime]) -> tuple[datetime, datetime] | None:
        return (min(times), max(times)) if times else None

    agent_span = _span(
        [t for f in steered for t in (f.app.first_seen, f.app.last_seen) if t is not None]
    )
    wire_span = _span(
        [t for f in on_wire for t in (f.wire.first_seen, f.wire.last_seen) if t is not None]
    )
    window_note = ""
    if ports and not matched_ports and agent_span and wire_span:
        overlaps = agent_span[0] <= wire_span[1] and wire_span[0] <= agent_span[1]
        window_note = (
            "The agent's connections to these hosts ran "
            f"{agent_span[0].strftime('%H:%M:%S')}-{agent_span[1].strftime('%H:%M:%S')}, "
            f"while the connections in this capture span "
            f"{wire_span[0].strftime('%H:%M:%S')}-{wire_span[1].strftime('%H:%M:%S')}. "
            + (
                "The windows overlap, so the ports are genuinely absent rather than "
                "out of frame."
                if overlaps
                else "The windows do not overlap: the capture was taken after those "
                "connections had already happened, so no join to them is possible "
                "from these inputs. A capture covering that period would close this."
            )
        )

    steps = [
        {
            "n": 1,
            "source": "har",
            "title": "What the browser asked for",
            "found": bool(requests_by_host) and "har" in sources,
            "summary": (
                f"{sum(len(r) for r in requests_by_host.values())} request(s) across "
                f"{len(requests_by_host)} host(s)."
                if "har" in sources
                else "No HAR was supplied, so there is nothing to start from."
            ),
            "hands_over": (
                f"{len(requests_by_host)} hostname(s) to look for"
                if "har" in sources
                else ""
            ),
        },
        {
            "n": 2,
            "source": "bundle",
            "title": "What the agent did with it",
            "found": bool(steered),
            "summary": (
                f"The Zero Trust Access log names {len(steered)} connection(s) to these "
                f"hosts, on source port(s) {', '.join(str(p) for p in ports[:8])}"
                + (" and others." if len(ports) > 8 else ".")
                if steered
                else (
                    "The agent's log names no connection to any of these hosts, so it "
                    "hands no source port to the next step. It logs what it steers, so "
                    "this traffic was not carried over Zero Trust Access."
                    if "bundle" in sources
                    else "No DART bundle was supplied, so no source port comes from here."
                )
            ),
            "hands_over": f"{len(ports)} source port(s)" if steered else "",
        },
        {
            "n": 3,
            "source": "capture",
            "title": "What the wire shows",
            "found": bool(on_wire),
            "summary": (
                (
                    f"{len(matched_ports)} of the agent's {len(ports)} source port(s) appear "
                    f"in the capture. "
                    if ports
                    else ""
                )
                + f"{len(on_wire)} connection(s) here can be shown packet by packet."
                + (" " + window_note if window_note else "")
                if "capture" in sources
                else "No packet capture was supplied, so nothing can be shown packet by packet."
            ),
            "hands_over": "",
        },
    ]

    connections = []
    # Worst first, then whatever the most artefacts agree on: a reader opening
    # this has a complaint, not a survey.
    order = {"problem": 0, "warning": 1, "info": 2}
    for flow in sorted(
        flows,
        key=lambda f: (
            order[f.severity],
            -((f.app is not None) + (f.wire is not None)),
            f.destination,
            f.src_port,
        ),
    ):
        app, wire = flow.app, flow.wire
        requests = requests_by_host.get(flow.destination, [])
        statuses: dict[str, int] = {}
        for request in requests:
            key = str(request.status) if request.status else "no response"
            statuses[key] = statuses.get(key, 0) + 1

        if app is not None and wire is not None:
            outcome = "Followed through all three."
        elif app is not None:
            outcome = (
                "The agent handled it, but no connection from this port is in the "
                "capture - it happened outside the captured window."
            )
        elif wire is not None:
            outcome = (
                "The capture holds it and TLS named the host; the agent logged nothing "
                "about it, which with trace logging off is not a verdict either way."
            )
        else:
            outcome = "Named by the browser only."

        reason = (app.reasons[0] if app is not None and app.reasons else "")
        if reason:
            outcome = f"Ended on {reason}. " + outcome

        connections.append({
            "src_port": flow.src_port,
            "host": flow.destination,
            "severity": flow.severity,
            "outcome": outcome,
            "har": {
                "requests": len(requests),
                "statuses": statuses,
                # The browser records a host, not a port, so a request cannot be
                # tied to one connection when the host opened several.
                "per_host": True,
            },
            "zta": None if app is None else {
                "lines": app.lines,
                "error_lines": app.error_lines,
                "reasons": list(app.reasons),
                "errors": list(app.errors)[:3],
                "first_seen": _iso(app.first_seen),
                "last_seen": _iso(app.last_seen),
                "tunnel": flow.tunnel.label if flow.tunnel is not None else "",
            },
            "wire": None if wire is None else {
                "label": wire.label,
                "packets": wire.packets,
                "bytes": wire.bytes,
                "handshake_captured": wire.has_syn,
                "tls_version": wire.tls_version or "",
                "alerts": list(wire.tls_alerts),
                "retransmissions": wire.retransmissions,
                "zero_windows": wire.zero_windows,
                "first_seen": _iso(wire.first_seen),
                "rtt_ms": round(wire.handshake_rtt * 1000, 1) if wire.handshake_rtt else None,
            },
            "basis": [b for b in (flow.wire_basis, flow.tunnel_basis) if b],
        })

    return {"steps": steps, "connections": connections}


def focus_report(session: SessionCorrelation, focus: str) -> dict | None:
    """Answer one question - what happened to this site - from all three sides.

    Without this the correlation is a catalogue: everything every artefact saw,
    in the order it was found, with the thing the operator actually came to ask
    about somewhere in the middle. Naming it turns the same evidence into an
    answer.

    The unit of the answer is the **page**, not the hostname, because that is
    what was asked about. Opening ``www.bbc.com`` fetches from a dozen other
    hosts that share no domain with it, and reporting only the one host that
    matches the string produces a technically correct answer - one request,
    nothing on the wire - to a question nobody asked. Page membership is read
    from the HAR's own page grouping, so it is recorded rather than inferred.

    Every side reports even when it has nothing, because the absence is the
    finding as often as the presence is. A host with browser requests and no
    ZTA record was not steered - a fact about the configuration, not a gap in
    the tool - and saying nothing there is what makes a working correlation
    look broken.
    """
    host = normalise_host(focus)
    if not host:
        return None

    named = [h for h in session.hosts if _matches_focus(h.host, host)]

    # The page the operator named, as the browser recorded it. Matching on the
    # page's own URL keeps this evidence-based: no guess is made about which
    # hosts "belong" to a site.
    page_names = {
        request.page
        for entry in session.hosts
        for request in entry.requests
        if request.page and _matches_focus(normalise_host(request.page), host)
    }
    if page_names:
        scope = [
            entry
            for entry in session.hosts
            if any(r.page in page_names for r in entry.requests)
        ]
    else:
        scope = named

    scope_names = {entry.host for entry in scope}
    flows = [f for f in session.flows if normalise_host(f.destination) in scope_names]
    subject = sorted(page_names)[0] if page_names else host
    sides: list[dict] = []

    # --- the wire ---------------------------------------------------------
    local = sum(len(h.local_flows) for h in scope)
    direct = sum(len(h.direct_flows) for h in scope)
    if "capture" not in session.sources:
        sides.append({
            "source": "capture",
            "found": False,
            "summary": "No packet capture was supplied, so nothing was measured on the wire.",
        })
    elif local or direct:
        parts = []
        if local:
            parts.append(f"{local} connection(s) reached the agent's local listener")
        if direct:
            peers = sorted({f.dst_ip for h in scope for f in h.direct_flows})
            parts.append(f"{direct} went straight to {', '.join(peers[:3])}")
        sides.append({
            "source": "capture",
            "found": True,
            "summary": (
                f"TLS handshakes were captured for {len([h for h in scope if h.local_flows or h.direct_flows])} "
                f"of the {len(scope)} host(s) involved."
            ),
            "detail": "; ".join(parts),
        })
    else:
        sides.append({
            "source": "capture",
            "found": False,
            "summary": (
                "The capture holds no TLS handshake naming any of these hosts. Either "
                "they were reached outside the capture window, or the names were never "
                "sent in the clear."
            ),
        })

    # --- the browser ------------------------------------------------------
    requests = sum(h.request_count for h in scope)
    failures = sum(len(h.failures) for h in scope)
    if "har" not in session.sources:
        sides.append({
            "source": "har",
            "found": False,
            "summary": "No HAR was supplied, so the browser's own account is missing.",
        })
    elif requests:
        synthetic = sorted({ip for h in scope for ip in h.synthetic_ips})
        detail = f"{failures} of them failed" if failures else "none of them failed"
        if synthetic:
            detail += (
                f"; {len(synthetic)} of the addresses it recorded never appear on the "
                "wire, so those connections were intercepted locally"
            )
        sides.append({
            "source": "har",
            "found": True,
            "summary": (
                f"The browser made {requests} request(s) to {len(scope)} host(s) "
                f"while loading {subject}."
            ),
            "detail": detail,
        })
    else:
        sides.append({
            "source": "har",
            "found": False,
            "summary": f"The browser made no request to {host} in this HAR.",
        })

    # --- the agent --------------------------------------------------------
    #
    # This is the side the reader notices missing, so it never stays silent.
    # The ZTA log records the flows the agent *intercepted*; a host the policy
    # does not steer produces no line at all, and that is an answer.
    agent_flows = [f for f in flows if f.app is not None]
    problems = [f for f in agent_flows if f.severity == "problem"]
    steered_total = sum(1 for f in session.flows if f.app is not None)
    if "bundle" not in session.sources:
        sides.append({
            "source": "bundle",
            "found": False,
            "summary": "No DART bundle was supplied, so the agent's own account is missing.",
        })
    elif agent_flows:
        named_hosts = sorted({normalise_host(f.destination) for f in agent_flows})
        sides.append({
            "source": "bundle",
            "found": True,
            "summary": (
                f"The Zero Trust Access log records {len(agent_flows)} intercepted "
                f"flow(s) to {len(named_hosts)} of these hosts."
            ),
            "detail": (
                (f"{len(problems)} of them ended in an error. " if problems else "")
                + "Steered: "
                + ", ".join(named_hosts[:4])
                + (" and others" if len(named_hosts) > 4 else "")
            ),
        })
    elif steered_total:
        sides.append({
            "source": "bundle",
            "found": False,
            "summary": (
                f"The Zero Trust Access log records {steered_total} intercepted flow(s), "
                "none of them to these hosts."
            ),
            "detail": (
                "The agent only logs what it steers, so this traffic was not carried "
                "over Zero Trust Access. That is a statement about the steering policy, "
                "not a missing record."
            ),
        })
    else:
        sides.append({
            "source": "bundle",
            "found": False,
            "summary": (
                "The bundle holds no intercepted-flow records at all, so it cannot say "
                f"anything about {host}."
            ),
            "detail": (
                "Either the Zero Trust Access log is absent from the bundle or the agent "
                "steered nothing during the period it covers."
            ),
        })

    answered = any(side["found"] for side in sides)
    steered_hosts = [h for h in scope if h.steering is Steering.STEERED]
    if not answered:
        verdict = f"None of the supplied artefacts mentions {host}."
    elif problems:
        verdict = (
            f"Loading {subject} touched {len(scope)} host(s); {len(problems)} steered "
            "flow(s) ended in an error, and the agent's log names them."
        )
    elif agent_flows:
        verdict = (
            f"Loading {subject} touched {len(scope)} host(s); "
            f"{len(steered_hosts)} were steered through Zero Trust Access and completed."
        )
    elif steered_hosts:
        verdict = (
            f"Loading {subject} touched {len(scope)} host(s); the wire shows "
            f"{len(steered_hosts)} of them intercepted locally, but the bundle's log "
            "does not name them."
        )
    else:
        verdict = (
            f"Loading {subject} touched {len(scope)} host(s); none of them was steered "
            "through Zero Trust Access."
        )

    breakdown = sorted(
        (
            {
                "host": entry.host,
                "steering": entry.steering.value,
                "requests": entry.request_count,
                "failures": len(entry.failures),
                "agent_flows": sum(
                    1
                    for f in agent_flows
                    if normalise_host(f.destination) == normalise_host(entry.host)
                ),
                "problem_flows": sum(
                    1
                    for f in problems
                    if normalise_host(f.destination) == normalise_host(entry.host)
                ),
            }
            for entry in scope
        ),
        key=lambda row: (-row["problem_flows"], -row["agent_flows"], -row["requests"]),
    )

    return {
        "host": host,
        "requested": (focus or "").strip(),
        "subject": subject,
        "by_page": bool(page_names),
        "answered": answered,
        "verdict": verdict,
        "sides": sides,
        "scope_hosts": sorted(scope_names),
        "breakdown": breakdown,
        "trace": _connection_trace(flows, scope, session.sources),
        "host_count": len(scope),
        "flow_count": len(flows),
        "named_host_count": len(named),
    }


def as_payload(session: SessionCorrelation) -> dict:
    """Render the correlation for transport, keeping every claim attributable.

    Counts alone would strip the basis off each verdict, which is the one thing
    a reader needs in order to disagree with it, so the basis travels with the
    verdict rather than being reconstructed in the browser.
    """
    hosts = []
    for host in session.hosts:
        statuses: dict[str, int] = {}
        for request in host.requests:
            key = str(request.status) if request.status else "no response"
            statuses[key] = statuses.get(key, 0) + 1
        hosts.append(
            {
                "host": host.host,
                "steering": host.steering.value,
                "basis": host.steering_basis,
                "strength": host.join_strength.value,
                "requests": host.request_count,
                "failures": len(host.failures),
                "statuses": statuses,
                "bytes": sum(r.bytes for r in host.requests),
                "synthetic_ips": host.synthetic_ips,
                "real_peers": host.real_peers,
                "local_flows": len(host.local_flows),
                "direct_peers": sorted({f.dst_ip for f in host.direct_flows}),
                "first_request": _iso(
                    next((r.started for r in host.requests if r.started), None)
                ),
            }
        )

    tunnels = [
        {
            "label": tunnel.agent.label,
            "peer": f"{tunnel.wire.dst_ip}:{tunnel.wire.dst_port}",
            "src_port": tunnel.wire.src_port,
            "strength": tunnel.strength.value,
            "packets": tunnel.wire.packets,
            "bytes": tunnel.wire.bytes,
            "handshake_captured": tunnel.wire.has_syn,
            "agent_lines": tunnel.agent.lines,
            "errors": list(tunnel.agent.errors),
            "warnings": list(tunnel.agent.warnings),
            "wire_first_seen": _iso(tunnel.wire.first_seen),
            "agent_first_seen": _iso(tunnel.agent.first_seen),
        }
        for tunnel in sorted(session.tunnels, key=lambda t: -t.wire.bytes)
    ]

    unknown = [h for h in session.hosts if h.steering is Steering.UNKNOWN]
    clusters = _reason_clusters(session.flows)
    # A flow names its tunnel as the agent recorded it; the tunnel's own
    # connection - the one with a network in it - is on the correlated tunnel.
    tunnel_wires = {id(t.agent): t.wire for t in session.tunnels}
    return {
        "summary": {
            "hosts": len(session.hosts),
            "steered": len(session.steered_hosts),
            "direct": len(session.direct_hosts),
            "unknown": len(unknown),
            "tunnels": len(session.tunnels),
            "requests": sum(h.request_count for h in session.hosts),
            "failures": sum(len(h.failures) for h in session.hosts),
            "intercepted_flows": len(session.flows),
            "failing_flows": sum(1 for f in session.flows if f.severity == "problem"),
        },
        "clock": {
            "offset_seconds": (
                session.clock_offset.total_seconds() if session.clock_offset is not None else None
            ),
            "basis": session.clock_offset_basis,
        },
        "hosts": sorted(hosts, key=lambda h: (-h["requests"], h["host"])),
        "tunnels": tunnels,
        "flows": [_flow_payload(flow, clusters, tunnel_wires) for flow in session.flows],
        "notes": session.notes,
        "sources": session.sources,
        "focus": focus_report(session, session.focus),
    }


# What the agent's own close-reason token means. These describe the token, they
# do not diagnose the cause - the agent says what it did, not why the far end
# behaved as it did, and the difference matters when a reader acts on it.
# Below this many paired round trips, variation between them is noise rather
# than jitter, and reporting it would dress up nothing as a measurement.
_MIN_JITTER_SAMPLES = 5

_REASON_MEANING = {
    "connect_timeout": "the onward connection was not established before the agent gave up",
    "socket_read": "reading from the local application socket failed",
    "socket_write": "writing to the local application socket failed",
    "next_transport_state": "the transport underneath the flow changed state while it was open",
    "tunnel_connect": "the tunnel this flow needed could not be connected",
    "connect_transport": "the agent could not start the onward transport",
}

# What a reader might do next about each reason.
#
# This is the one place in this tool that is not derived from the inputs, and
# it is labelled as such wherever it is shown. It is general knowledge about
# what the token means and what usually explains it - deliberately phrased as
# things to check, never as a diagnosis, because the agent records what it did
# and not why the far end behaved as it did. The evidence-based half of the
# answer is computed separately, in ``_reason_clusters``.
_REASON_GUIDANCE = {
    "next_transport_state": {
        "causes": [
            "The tunnel underneath was rebuilt while the flow was open - a network change, "
            "roaming between Wi-Fi and wired, or a sleep/wake will all do this.",
            "The headend reset or migrated the connection carrying this flow.",
            "The agent re-evaluated steering mid-flow, for example after trusted-network "
            "detection changed its mind about the network.",
        ],
        "checks": [
            "Check the Server Connectivity and network-change events in the bundle around this "
            "timestamp.",
            "Ask whether the user moved network, docked or undocked, or resumed from sleep.",
        ],
    },
    "socket_read": {
        "causes": [
            "The local application closed the connection - a browser tab closed, a request "
            "cancelled, or the app timed out on its own.",
            "The application crashed or was killed while the flow was open.",
            "The agent could not read the request because the app never finished sending it.",
        ],
        "checks": [
            "Check whether the same destination succeeded on another flow moments later; a "
            "retry that worked points at the application, not the path.",
            "If a HAR was collected, look for the same request there and what the browser "
            "recorded for it.",
        ],
    },
    "socket_write": {
        "causes": [
            "The local application stopped reading the response and the agent could not hand "
            "it back.",
            "The application closed while a response was in flight.",
        ],
        "checks": [
            "Check whether the response was large or slow - an app that gives up mid-download "
            "looks exactly like this.",
        ],
    },
    "connect_timeout": {
        "causes": [
            "The private resource did not answer through the tunnel.",
            "The resource connector or CNHE in front of it was down or unreachable.",
            "Access policy did not permit this destination, and the connection was dropped "
            "rather than refused.",
        ],
        "checks": [
            "Confirm the resource is reachable from the connector's own network.",
            "Check the access policy for this destination and this user.",
            "Check whether every flow to this destination timed out, or only some - partial "
            "failure points at capacity or one unhealthy connector.",
        ],
    },
    "tunnel_connect": {
        "causes": [
            "The agent could not establish the tunnel it needed for this destination.",
            "Enrollment or posture was not in a state that permits the tunnel.",
        ],
        "checks": [
            "Check enrollment state and any enrollment errors in the bundle.",
            "Check that the ZTA network requirements are reachable on 443 (TCP and UDP): "
            "*.ztna.sse.cisco.com, *.zpc.sse.cisco.com, *.tia.sse.cisco.com.",
        ],
    },
    "connect_transport": {
        "causes": [
            "The onward transport could not be started - typically the headend connection was "
            "not available at that moment.",
        ],
        "checks": [
            "Check for server connectivity events in the bundle around this timestamp.",
        ],
    },
}

# How close in time two flows must fail for the failure to be worth calling
# shared. A minute is long enough to catch a tunnel rebuild taking several
# flows down with it, and short enough that two unrelated failures in a busy
# session are not reported as one event.
_REASON_CLUSTER_WINDOW = timedelta(seconds=60)


def _reason_clusters(flows: list[FlowCorrelation]) -> dict[int, dict]:
    """For each failing flow, how many others failed the same way at the same time.

    This is the part of the answer that *is* evidence. One flow closing with
    ``next_transport_state`` says almost nothing; fourteen closing that way
    inside a minute says the transport went away and took them all with it,
    which is a different problem with a different owner. Keyed by ``id`` so it
    can be attached without changing the flow objects.
    """
    failing = [
        (f, f.app.first_seen)
        for f in flows
        if f.app is not None and f.app.reasons and f.app.first_seen is not None
    ]
    clusters: dict[int, dict] = {}
    for flow, when in failing:
        for reason in flow.app.reasons:
            peers = [
                other
                for other, other_when in failing
                if other is not flow
                and reason in other.app.reasons
                and abs(other_when - when) <= _REASON_CLUSTER_WINDOW
            ]
            if not peers:
                continue
            destinations = sorted({p.destination for p in peers})
            clusters.setdefault(id(flow), {})[reason] = {
                "count": len(peers),
                "destinations": destinations[:6],
                "distinct_destinations": len(destinations),
            }
    return clusters


def _flow_quality(wire: WireFlow | None) -> dict | None:
    """RTT, jitter and loss signals for one connection - with their limits.

    Three refusals are built in, because each of them is a way this could
    mislead a reader who has every reason to trust it:

    * **A loopback leg is not the network.** Half the connections in an
      intercepted session run from the application to the agent's own listener
      on 127.0.0.1. Their RTT is a memory copy, sub-millisecond by
      construction, and reporting it as latency would make every session look
      excellent no matter how bad the path beyond the agent was. The tunnel
      carrying the flow is where the network actually is.
    * **Retransmissions are not a loss percentage.** One capture point cannot
      tell a packet lost before it from one lost after it, and a capture taken
      on the sending host sees its own retransmissions but not the drop. The
      count is reported as what it is - retransmissions observed - and never
      converted into a rate that would read as measured loss.
    * **Jitter needs samples.** Variation computed from two round trips is
      noise with a decimal point, so it is withheld below a handful.
    """
    if wire is None:
        return None

    samples = sorted(wire.rtts)
    quality: dict = {
        "loopback": wire.is_loopback,
        "packets": wire.packets,
        "retransmissions": wire.retransmissions,
        "duplicate_acks": wire.duplicate_acks,
        "zero_windows": wire.zero_windows,
        "out_of_order": wire.out_of_order,
        "rtt_samples": len(samples),
        "handshake_rtt_ms": round(wire.handshake_rtt * 1000, 3)
        if wire.handshake_rtt is not None
        else None,
        "rtt_min_ms": round(samples[0] * 1000, 3) if samples else None,
        "rtt_median_ms": round(statistics.median(samples) * 1000, 3) if samples else None,
        "rtt_max_ms": round(samples[-1] * 1000, 3) if samples else None,
        "jitter_ms": None,
        "notes": [],
    }

    # Jitter as mean deviation between consecutive round trips - the same idea
    # RFC 3550 uses for RTP, which is what an operator means by the word.
    if len(wire.rtts) >= _MIN_JITTER_SAMPLES:
        deltas = [
            abs(wire.rtts[i] - wire.rtts[i - 1]) for i in range(1, len(wire.rtts))
        ]
        quality["jitter_ms"] = round(statistics.fmean(deltas) * 1000, 3)
    elif samples:
        quality["notes"].append(
            f"Jitter needs several round trips to mean anything and this connection produced "
            f"{len(samples)}; it is not reported rather than computed from too little."
        )

    if wire.is_loopback:
        quality["notes"].append(
            "This leg runs to the agent's own listener on this machine, so its round-trip time "
            "is a memory copy and not a measure of the network. The tunnel carrying this flow "
            "is where the path can be measured."
        )
    if not wire.has_syn:
        quality["notes"].append(
            "The handshake was not captured, so the cleanest round-trip measurement - SYN to "
            "SYN/ACK, with nothing else in flight - is not available. The ACK figures are a "
            "distribution rather than the path's latency: they pair each ACK with the segment "
            "it acknowledged, which under-reads whenever the sender had already put several "
            "segments in flight."
        )
    if wire.retransmissions:
        quality["notes"].append(
            f"{wire.retransmissions} retransmission(s) were observed. This is not a loss "
            "percentage: one capture point cannot tell a packet lost before it from one lost "
            "after it, so the count is evidence of retransmission, not a measured loss rate."
        )
    if wire.zero_windows:
        quality["notes"].append(
            f"{wire.zero_windows} zero-window advertisement(s): a receiver told the sender to "
            "stop because its buffer was full. That is the receiving application not reading, "
            "which is a different problem from a slow network."
        )
    return quality


def _flow_payload(
    flow: FlowCorrelation,
    clusters: dict[int, dict] | None = None,
    tunnel_wires: dict[int, WireFlow] | None = None,
) -> dict:
    """One intercepted flow, with every claim carrying the artefact behind it."""
    app = flow.app
    statuses: dict[str, int] = {}
    for request in flow.requests:
        key = str(request.status) if request.status else "no response"
        statuses[key] = statuses.get(key, 0) + 1

    evidence = []
    if app is not None:
        evidence.append({"source": "bundle", "text": f"ZTA log names this flow {app.label}"})
    if flow.wire is not None:
        evidence.append({"source": "capture", "text": f"{flow.wire.label}, {flow.wire.packets} packet(s)"})
    if flow.tunnel is not None:
        evidence.append({"source": "bundle", "text": f"tunnel {flow.tunnel.label}"})
    if flow.requests:
        evidence.append({
            "source": "har",
            "text": f"{len(flow.requests)} browser request(s) to {flow.destination}",
        })

    return {
        "destination": flow.destination,
        "label": flow.label,
        "severity": flow.severity,
        "protocol": app.proto if app is not None else ("tls" if flow.wire and flow.wire.sni else "tcp"),
        "src_port": flow.src_port,
        "stream": app.stream if app is not None else None,
        "first_seen": _iso(app.first_seen if app is not None else (
            flow.wire.first_seen if flow.wire is not None else None
        )),
        "last_seen": _iso(app.last_seen if app is not None else (
            flow.wire.last_seen if flow.wire is not None else None
        )),
        "agent_lines": app.lines if app is not None else 0,
        "error_lines": app.error_lines if app is not None else 0,
        "reasons": list(app.reasons) if app is not None else [],
        "agent_errors": list(app.errors) if app is not None else [],
        "named_by": (
            "bundle" if app is not None
            else ("capture" if flow.wire is not None else "har")
        ),
        "intercepted_by": flow.intercepted_by,
        "intercepted_basis": flow.intercepted_basis,
        "wire": (
            {
                "label": flow.wire.label,
                "packets": flow.wire.packets,
                "bytes": flow.wire.bytes,
                "handshake_captured": flow.wire.has_syn,
                "sni": flow.wire.sni,
                "listener": f"{flow.wire.dst_ip}:{flow.wire.dst_port}",
            }
            if flow.wire is not None
            else None
        ),
        "wire_strength": flow.wire_strength.value if flow.wire is not None else None,
        "wire_basis": flow.wire_basis,
        "tunnel": flow.tunnel.label if flow.tunnel is not None else None,
        "tunnel_basis": flow.tunnel_basis,
        "requests": len(flow.requests),
        "failures": len(flow.failures),
        "statuses": statuses,
        "explanation": _explain_flow(flow),
        "evidence": evidence,
        "timeline": _flow_timeline(flow),
        "story": _flow_story(flow),
        "quality": _flow_quality(flow.wire),
        "tunnel_quality": _flow_quality(
            (tunnel_wires or {}).get(id(flow.tunnel)) if flow.tunnel is not None else None
        ),
        "guidance": [
            {
                "reason": reason,
                "meaning": _REASON_MEANING.get(reason, ""),
                "causes": _REASON_GUIDANCE.get(reason, {}).get("causes", []),
                "checks": _REASON_GUIDANCE.get(reason, {}).get("checks", []),
                "shared": (clusters or {}).get(id(flow), {}).get(reason),
            }
            for reason in (app.reasons if app is not None else ())
        ],
    }


_PACKET_LABELS = {
    "syn": "SYN",
    "synack": "SYN/ACK",
    "fin": "FIN",
    "rst": "RST",
    "ack": "ACK",
}


def _fact(label: str, value: object, tone: str = "plain", note: str = "") -> dict:
    return {"label": label, "value": str(value), "tone": tone, "note": note}


def _human_bytes(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1000:
        return f"{n / 1000:.0f} KB"
    return f"{n} B"


_STEP_NOTES = {
    "syn": "client requests to open a connection",
    "synack": "server agrees",
    "ack": "connection established",
    "clienthello": "proposes encryption, names the host it wants",
    "serverhello": "server picks the cipher and replies",
    "certificate": "server presents its certificate",
    "clientkeyexchange": "client sends its key material",
    "finished": "handshake complete",
    "alert": "the peer refused and said why",
    "http_request": "the request the application made",
    "http_response": "the server's answer",
    "fin": "orderly close",
    "rst": "connection torn down abruptly",
}


def _flow_story(flow: FlowCorrelation) -> dict | None:
    """The connection read as a sequence of layers, each with its own verdict.

    This is the correlation view's own story. It is built from the summarised
    ``WireFlow`` rather than from packets, so it covers what that model holds -
    TCP, the tunnel, TLS, HTTP and the transfer. There is no DNS layer here:
    name resolution is UDP and this pass reads TCP only, so claiming one would
    be inventing it.
    """
    wire = flow.wire
    if wire is None:
        return None

    events = list(wire.head) + list(wire.tail)
    by_kind = {kind for _t, _s, _p, kind, _b in events}
    start = events[0][0] if events else 0.0

    def steps_for(kinds: set[str]) -> list[dict]:
        out = []
        for moment, src_ip, src_port, kind, payload in events:
            if kind not in kinds:
                continue
            from_client = src_ip == wire.src_ip and src_port == wire.src_port
            label = _PACKET_LABELS.get(kind) or kind.replace("_", " ").title()
            if kind == "data":
                label = f"Data {payload}B"
            out.append({
                "dir": "c2s" if from_client else "s2c",
                "msg": label,
                "note": _STEP_NOTES.get(kind, ""),
                "bad": kind in {"rst", "alert"},
                "t": round(moment - start, 4),
            })
            if len(out) >= 8:
                break
        return out

    layers: list[dict] = []

    # --- TCP ---------------------------------------------------------------
    tcp_facts = []
    if wire.handshake_rtt is not None:
        tcp_facts.append(_fact("Network round trip", f"{wire.handshake_rtt * 1000:.1f} ms"))
    if len(wire.rtts) > 1:
        spread = statistics.pstdev(wire.rtts) * 1000
        tcp_facts.append(_fact(
            "Round-trip variation", f"\u00b1{spread:.1f} ms over {len(wire.rtts)} samples",
            "warn" if wire.handshake_rtt and spread > wire.handshake_rtt * 1000 else "plain"))
    if wire.retransmissions:
        tcp_facts.append(_fact("Retransmitted", f"{wire.retransmissions} segment(s)", "bad",
                               "the sender had to repeat data that did not arrive"))
    if wire.zero_windows:
        tcp_facts.append(_fact("Receiver stalled", f"{wire.zero_windows} zero-window event(s)",
                               "bad", "the receiver told the sender to stop"))
    if wire.duplicate_acks:
        tcp_facts.append(_fact("Duplicate ACKs", wire.duplicate_acks, "warn"))
    if wire.out_of_order:
        tcp_facts.append(_fact("Out of order", wire.out_of_order, "warn"))
    if "rst" in by_kind:
        tcp_facts.append(_fact("Closed by", "reset", "warn", "an abrupt close"))
    elif "fin" in by_kind:
        tcp_facts.append(_fact("Closed by", "FIN - orderly shutdown"))

    if not wire.has_syn:
        layers.append({"name": "TCP", "status": "absent", "steps": [], "facts": tcp_facts,
                       "summary": "handshake not captured",
                       "why": "This capture starts after the connection was already open."})
    else:
        rtt = f", {wire.handshake_rtt * 1000:.1f} ms" if wire.handshake_rtt else ""
        layers.append({"name": "TCP", "status": "ok", "facts": tcp_facts,
                       "summary": f"connected \u00b7 3-way handshake{rtt}",
                       "steps": steps_for({"syn", "synack"})})

    # --- TUNNEL ------------------------------------------------------------
    if "CONNECT" in wire.http_methods:
        ok = any(s.startswith("2") for s in wire.http_statuses)
        layers.append({
            "name": "TUNNEL", "status": "ok" if ok else "fail",
            "summary": "tunnel established" if ok else "the proxy refused the tunnel",
            "steps": steps_for({"http_request", "http_response"}),
            "facts": [_fact("Proxy", f"{wire.dst_ip}:{wire.dst_port}")]
                     + ([_fact("Requested", wire.first_uri)] if wire.first_uri else []),
        })

    # --- TLS ---------------------------------------------------------------
    if wire.handshake_seen or wire.tls_alerts:
        tls_facts = []
        if wire.tls_version:
            tls_facts.append(_fact("Version", wire.tls_version))
        if wire.alpn:
            tls_facts.append(_fact("ALPN", ", ".join(wire.alpn)))
        complete = "serverhello" in wire.handshake_seen
        if wire.tls_alerts:
            status, summary = "fail", "failed \u00b7 alert raised"
        elif not complete:
            status, summary = "warn", "no reply to ClientHello"
        else:
            status = "ok"
            summary = "negotiated \u00b7 " + (wire.tls_version or "encrypted")
        layers.append({
            "name": "TLS", "status": status, "summary": summary, "facts": tls_facts,
            "steps": steps_for({"clienthello", "serverhello", "certificate",
                                "clientkeyexchange", "finished", "alert"}),
        })

    # --- HTTP --------------------------------------------------------------
    plain_http = [s for s in wire.http_statuses if s]
    if plain_http and "CONNECT" not in wire.http_methods:
        worst = "ok"
        for code in plain_http:
            if code[:1] in ("4", "5"):
                worst = "fail"
            elif code[:1] == "3" and worst == "ok":
                worst = "warn"
        layers.append({
            "name": "HTTP", "status": worst,
            "summary": {"fail": "the server refused", "warn": "redirected"}.get(
                worst, "served in the clear"),
            "steps": steps_for({"http_request", "http_response"}),
            "facts": [_fact("Requested", wire.first_uri)] if wire.first_uri else [],
        })

    # --- DATA --------------------------------------------------------------
    if wire.client_bytes or wire.server_bytes:
        data_facts = [_fact("Transferred",
                            f"{_human_bytes(wire.server_bytes)} in, "
                            f"{_human_bytes(wire.client_bytes)} out")]
        if wire.first_seen and wire.last_seen:
            held = (wire.last_seen - wire.first_seen).total_seconds()
            if held > 0.5:
                data_facts.append(_fact("Open for", f"{held:.1f} s"))
        data_facts.append(_fact("Packets", wire.packets))
        layers.append({"name": "DATA", "status": "ok", "summary": "transfer observed",
                       "steps": [], "facts": data_facts})

    if not layers:
        return None

    return {
        "client": {"addr": f"{wire.src_ip}:{wire.src_port}"},
        "server": {"host": wire.sni or flow.destination, "addr": f"{wire.dst_ip}:{wire.dst_port}"},
        "layers": layers,
        "conclusion": _story_conclusion(flow, wire, layers),
    }


def _story_conclusion(flow: FlowCorrelation, wire: WireFlow, layers: list[dict]) -> dict:
    """State only what these summarised events support."""
    by_name = {layer["name"]: layer for layer in layers}
    paragraphs: list[str] = []
    fix = ""

    tcp = by_name.get("TCP")
    if tcp and tcp["status"] == "ok":
        rtt = f" in {wire.handshake_rtt * 1000:.1f} ms" if wire.handshake_rtt else ""
        paragraphs.append(f"The TCP connection opened normally{rtt} - the network path to "
                          "this destination is working.")

    tunnel, tls, http = by_name.get("TUNNEL"), by_name.get("TLS"), by_name.get("HTTP")
    if tunnel and tunnel["status"] == "fail":
        paragraphs.append("The intermediary refused to open the tunnel, so nothing beyond "
                          "it was ever attempted.")
        fix = "Check the policy on the proxy for this destination."
    elif http and http["status"] == "fail":
        codes = ", ".join(s for s in wire.http_statuses if s[:1] in ("4", "5"))
        paragraphs.append(f"The server answered {codes}. That is the refusal itself, stated "
                          "in plain HTTP rather than inferred.")
        fix = "This is a policy or application decision. Check the rule that matched this URL."
    elif tls and tls["status"] == "fail":
        paragraphs.append("The failure is in the TLS layer: the peer raised an alert, which "
                          "is its own stated reason for refusing.")
        fix = "Act on the alert reason; the network path is not at fault."
    elif tls and tls["status"] == "warn":
        paragraphs.append("The client sent a ClientHello and no ServerHello was seen in the "
                          "captured portion of this connection.")
    elif tls and tls["status"] == "ok":
        paragraphs.append("Encryption negotiated successfully"
                          + (f" using {wire.tls_version}" if wire.tls_version else "")
                          + ". Nothing in the connection set-up failed.")

    if wire.zero_windows:
        paragraphs.append("The receiver advertised a zero window: it told the sender to stop "
                          "because its buffer was full. That is an application stall, not loss.")

    paragraphs.append("This view reads the correlated summary of the connection, which holds "
                      "TCP, tunnel, TLS, HTTP and transfer. Name resolution is not in it - "
                      "DNS is UDP and this pass reads TCP only.")
    return {"paragraphs": paragraphs, "fix": fix}


def _flow_timeline(flow: FlowCorrelation) -> dict:
    """What happened on this flow, in order.

    An intercepted flow has a real client and a real server - the application
    on one side, the destination it asked for on the other - so where the
    capture holds that connection this is a **packet** ladder, drawn from the
    packets themselves.

    Where the capture does not hold it, there are no packets to draw and the
    agent's own log lines are shown instead. The two are never mixed and the
    payload says which it is, because a reader must not take a line the agent
    wrote for a packet that crossed the wire.
    """
    if flow.wire is not None and (flow.wire.head or flow.wire.tail):
        return _packet_timeline(flow.wire)
    if flow.app is not None:
        return _log_timeline(flow.app)
    return {"source": "none", "total": 0, "omitted": 0, "events": []}


def _packet_timeline(wire: WireFlow) -> dict:
    head = list(wire.head)
    tail = list(wire.tail)
    kept = len(head) + len(tail)
    omitted = max(wire.packets - kept, 0)
    start = head[0][0] if head else (tail[0][0] if tail else 0.0)

    rows = []
    for index, event in enumerate(head + tail):
        if omitted and index == len(head):
            rows.append({"gap": omitted})
        moment, src_ip, src_port, kind, payload = event
        rows.append({
            "t": round(moment - start, 4),
            "side": "client" if (src_ip == wire.src_ip and src_port == wire.src_port) else "server",
            "level": "E" if kind == "rst" else "I",
            "kind": kind,
            "label": _PACKET_LABELS.get(kind) or ("Data " + str(payload) + "B"),
        })
    return {"source": "packets", "total": wire.packets, "omitted": omitted, "events": rows}


def _log_timeline(app: AppFlow) -> dict:
    """The agent's own account, for a flow the capture does not hold."""
    events = list(app.events)
    if not events:
        return {"source": "log", "total": 0, "omitted": 0, "events": []}

    start = next((when for when, _level, _side, _text in events if when), None)
    omitted = 0
    if len(events) > _TIMELINE_EDGE * 2:
        omitted = len(events) - _TIMELINE_EDGE * 2
        events = events[:_TIMELINE_EDGE] + events[-_TIMELINE_EDGE:]

    rows = []
    for index, (when, level, side, text) in enumerate(events):
        if omitted and index == _TIMELINE_EDGE:
            rows.append({"gap": omitted})
        offset = None
        if when is not None and start is not None:
            offset = round((when - start).total_seconds(), 4)
        rows.append({
            "t": offset,
            "side": side,
            "level": level,
            "kind": "log",
            # The class is the same on every line of a flow, and the side chip
            # already says which subsystem it was. Leading with the method
            # leaves room for what the line actually reports.
            "label": re.sub(r"^[A-Za-z][A-Za-z0-9]*::", "", text),
        })
    return {"source": "log", "total": len(app.events), "omitted": omitted, "events": rows}


def _explain_flow(flow: FlowCorrelation) -> str:
    """Say what happened to this flow, in the order it happened.

    Every clause is drawn from a specific artefact, and nothing is added where
    an artefact is silent - a flow with no capture and no HAR reads shorter
    rather than reading as though more were known.
    """
    app = flow.app
    if app is not None:
        parts = [
            f"ZTA steering matched {app.dest}, so the agent intercepted the connection and "
            f"handled it on source port {app.src_port}"
        ]
    else:
        # Named by the capture alone. Saying the agent "intercepted" it would
        # be asserting something no artefact here states.
        parts = [
            f"The capture holds a connection from source port {flow.src_port} carrying TLS SNI "
            f"{flow.destination}"
        ]

    if flow.wire is not None:
        where = "the agent's local listener" if flow.wire.is_loopback else "the network"
        parts.append(
            f"the capture shows that connection to {where} at {flow.wire.label}, "
            f"{flow.wire.packets} packet(s)"
        )

    if flow.tunnel is not None and app is not None:
        parts.append(f"it was carried as stream {app.stream} on {flow.tunnel.label}")

    if app is not None and app.reasons:
        for reason in app.reasons:
            meaning = _REASON_MEANING.get(reason)
            parts.append(
                f"the agent closed it with reason '{reason}'"
                + (f" - {meaning}" if meaning else "")
            )
    elif app is not None and app.error_lines:
        parts.append(
            f"the agent logged {app.error_lines} error line(s) against it but recorded no "
            "close reason"
        )
    elif app is None:
        parts.append("the agent's log says nothing about it")

    if flow.failures:
        codes = sorted({str(r.status) for r in flow.failures if r.status})
        parts.append(
            f"the browser recorded {len(flow.failures)} failed request(s) to this destination"
            + (f" ({', '.join(codes)})" if codes else "")
        )
    elif flow.requests:
        parts.append(
            f"the browser's {len(flow.requests)} request(s) to this destination all returned a "
            "response"
        )

    return "; ".join(parts) + "."


def _derive_clock_offset(tunnels: Iterable[TunnelCorrelation]) -> tuple[timedelta | None, str]:
    """Measure the agent log's offset from the capture clock.

    The ZTA log records local time with no offset, so aligning it with a
    capture would otherwise be guesswork. Because tunnels are joined on
    connection identity rather than time, each matched tunnel yields an
    independent measurement of the offset.

    This is a measurement, not an assumption, and it is reported as such -
    including how many connections it rests on, since an offset derived from
    two connections deserves less weight than one derived from twenty.
    """
    samples: list[timedelta] = []
    skipped = 0
    for tunnel in tunnels:
        if not (tunnel.agent.first_seen and tunnel.wire.first_seen):
            continue
        # Only a captured handshake fixes when the connection actually opened.
        # A flow already in progress when the capture started would otherwise
        # contribute a difference that measures the capture's start time, not
        # any difference between the two clocks.
        if not tunnel.wire.has_syn:
            skipped += 1
            continue
        samples.append(tunnel.agent.first_seen - tunnel.wire.first_seen)

    if not samples:
        reason = (
            "No matched connection had its handshake captured, so the capture cannot say when "
            "any of them opened and no offset can be measured."
            if skipped
            else "No connection matched on both sides, so no offset could be measured."
        )
        return None, reason

    # The agent's first line about a connection cannot precede the connection
    # itself, but it may well follow it. Every sample is therefore the true
    # offset plus an unknown non-negative lag, which makes the smallest sample
    # the tightest available bound rather than the average being the best guess.
    samples.sort()
    basis = (
        f"Upper bound from {len(samples)} connection(s) whose handshake was captured and whose "
        f"identity the agent also logged; spread {samples[0].total_seconds():.3f}s to "
        f"{samples[-1].total_seconds():.3f}s. Each sample includes the agent's own logging lag, "
        "so the smallest is closest to the true offset."
    )
    if skipped:
        basis += f" {skipped} further match(es) were already in progress when the capture began."
    return samples[0], basis


def correlate_session(
    wire_flows: list[WireFlow],
    agent_flows: list[AgentFlow],
    web_requests: list[WebRequest],
    app_flows: list[AppFlow] | None = None,
) -> SessionCorrelation:
    """Join the three views of one session.

    Order matters. Tunnels are matched first on connection identity, because
    that is the only exact key available and it also yields the clock offset.
    Hostnames are then resolved from the wire, and the HAR is attached last -
    the browser's account is the least authoritative about what reached the
    network.
    """
    result = SessionCorrelation()

    # 1. Tunnels: exact join on connection identity. No clock involved beyond
    #    rejecting a recycled source port from an unrelated earlier connection.
    agent_by_identity: dict[tuple[int, str, int], list[AgentFlow]] = defaultdict(list)
    for agent in agent_flows:
        agent_by_identity[agent.identity].append(agent)

    reuse_rejected = 0
    for wire in wire_flows:
        if wire.is_loopback:
            continue
        candidates = agent_by_identity.get(wire.identity)
        if not candidates:
            continue
        agent, rejected = _pick_episode(candidates, wire)
        reuse_rejected += rejected
        if agent is not None:
            result.tunnels.append(TunnelCorrelation(wire=wire, agent=agent))

    result.clock_offset, result.clock_offset_basis = _derive_clock_offset(result.tunnels)
    if reuse_rejected:
        result.notes.append(
            f"{reuse_rejected} connection(s) in the log carried the same source port and "
            "destination as a captured flow but occurred far outside the capture window. "
            "Ephemeral ports are reused, so these were treated as unrelated rather than joined."
        )

    tunnel_identities = {t.identity for t in result.tunnels}
    tunnel_peers = {t.wire.dst_ip for t in result.tunnels}

    # 2. Hostnames from the wire. SNI on the loopback leg means the agent
    #    intercepted the connection locally; SNI on the network leg means the
    #    browser reached the peer itself.
    local_by_host: dict[str, list[WireFlow]] = defaultdict(list)
    direct_by_host: dict[str, list[WireFlow]] = defaultdict(list)
    for flow in wire_flows:
        if not flow.sni:
            continue
        if flow.is_loopback:
            local_by_host[flow.sni].append(flow)
        elif flow.identity not in tunnel_identities and flow.dst_ip not in tunnel_peers:
            direct_by_host[flow.sni].append(flow)

    # 3. The browser's account, grouped by host.
    requests_by_host: dict[str, list[WebRequest]] = defaultdict(list)
    for request in web_requests:
        if request.host:
            requests_by_host[request.host].append(request)

    observed_peers = {flow.dst_ip for flow in wire_flows} | {flow.src_ip for flow in wire_flows}

    for host in sorted(set(local_by_host) | set(direct_by_host) | set(requests_by_host)):
        entry = HostCorrelation(
            host=host,
            requests=sorted(
                requests_by_host.get(host, []),
                key=lambda r: (r.started is None, r.started),
            ),
            local_flows=local_by_host.get(host, []),
            direct_flows=direct_by_host.get(host, []),
        )

        # A server address the browser recorded but which never appears on the
        # wire is synthetic: the agent answered the lookup with an address it
        # owns so it could intercept the connection. Deriving this from the
        # capture avoids asserting any particular vendor address range.
        for request in entry.requests:
            ip = request.server_ip
            if not ip:
                continue
            if ip in observed_peers:
                if ip not in entry.real_peers:
                    entry.real_peers.append(ip)
            elif ip not in entry.synthetic_ips:
                entry.synthetic_ips.append(ip)

        if entry.local_flows:
            entry.steering = Steering.STEERED
            entry.join_strength = JoinStrength.OBSERVED
            basis = (
                f"{len(entry.local_flows)} connection(s) to the agent's local listener "
                f"carried TLS SNI {host}"
            )
            if entry.synthetic_ips:
                basis += (
                    f"; the browser recorded {', '.join(entry.synthetic_ips[:3])}, which "
                    "never appears on the wire"
                )
            entry.steering_basis = basis
        elif entry.direct_flows:
            entry.steering = Steering.DIRECT
            entry.join_strength = JoinStrength.OBSERVED
            peers = sorted({flow.dst_ip for flow in entry.direct_flows})
            entry.steering_basis = (
                f"{len(entry.direct_flows)} connection(s) carried TLS SNI {host} straight to "
                f"{', '.join(peers[:3])}, bypassing the agent's listener"
            )
        else:
            entry.steering = Steering.UNKNOWN
            entry.join_strength = JoinStrength.ASSOCIATED
            entry.steering_basis = (
                "The capture holds no TLS handshake naming this host, so whether it was "
                "steered cannot be determined from these inputs."
            )

        result.hosts.append(entry)

    result.flows = _correlate_flows(
        app_flows or [], wire_flows, agent_flows, requests_by_host, result
    )

    _add_notes(result, wire_flows, agent_flows, web_requests)
    return result


def _correlate_flows(
    app_flows: list[AppFlow],
    wire_flows: list[WireFlow],
    agent_flows: list[AgentFlow],
    requests_by_host: dict[str, list[WebRequest]],
    result: SessionCorrelation,
) -> list[FlowCorrelation]:
    """Follow each intercepted flow through every artefact that saw it.

    The chain is the agent's own: it names the destination the application
    asked for and the source port it used, which is the port the capture sees;
    and it names the HTTP/2 stream it was given, which is the stream the tunnel
    reports carrying.

    Each hop is joined on its own terms and reported at its own strength. A
    source port is a strong key but not a unique one, so where more than one
    captured flow claims it the join is refused rather than guessed - and the
    refusals are counted into a note, because a silently dropped join and a
    join that never existed look identical on screen.
    """
    by_port: dict[int, list[WireFlow]] = defaultdict(list)
    for flow in wire_flows:
        by_port[flow.src_port].append(flow)

    tunnels_by_stream: dict[int, list[tuple[AgentFlow, datetime]]] = defaultdict(list)
    for tunnel in agent_flows:
        for stream, when in tunnel.streams:
            tunnels_by_stream[stream].append((tunnel, when))

    ambiguous_wire = 0
    ambiguous_tunnel = 0
    correlated: list[FlowCorrelation] = []

    for app in app_flows:
        record = FlowCorrelation(
            destination=app.dest,
            src_port=app.src_port,
            app=app,
            requests=list(requests_by_host.get(app.dest, [])),
        )

        candidates = by_port.get(app.src_port, [])
        if len(candidates) == 1:
            record.wire = candidates[0]
            record.wire_strength = JoinStrength.EXACT
            record.wire_basis = (
                f"The agent used source port {app.src_port} for this flow and the capture holds "
                f"exactly one connection from that port: {candidates[0].label}."
            )
        elif candidates:
            ambiguous_wire += 1
            record.wire_basis = (
                f"{len(candidates)} captured connections used source port {app.src_port}, so "
                "which one carried this flow cannot be told from these inputs."
            )
        else:
            record.wire_basis = (
                f"No connection from source port {app.src_port} appears in the capture, so this "
                "flow happened outside the captured window or on another interface."
            )

        if app.stream is not None:
            options = _overlapping(tunnels_by_stream.get(app.stream, []), app)
            if len(options) == 1:
                record.tunnel = options[0]
                record.tunnel_basis = (
                    f"Carried as HTTP/2 stream {app.stream} on {options[0].label}, which reports "
                    "that stream while this flow was open."
                )
            elif options:
                ambiguous_tunnel += 1
                record.tunnel_basis = (
                    f"{len(options)} tunnels report stream {app.stream} over this period. Stream "
                    "numbers restart per connection, so the tunnel cannot be named."
                )
            else:
                record.tunnel_basis = (
                    f"The agent gave this flow stream {app.stream}, but no tunnel in the log "
                    "reports that stream while it was open."
                )
        else:
            record.tunnel_basis = "The agent did not record a stream for this flow."

        correlated.append(record)

    # Flows the capture named but the agent did not.
    #
    # With trace-level logging off the agent writes a destination only when it
    # has a problem to report, so every flow that *worked* was missing from
    # this list entirely - including the ones the user actually came to look
    # at. The capture names them itself, in TLS SNI, alongside the source port
    # and the packets. That is a whole flow with no help from the log, so it
    # belongs here, marked as named by the capture rather than the bundle.
    claimed = {id(f.wire) for f in correlated if f.wire is not None}
    for wire in wire_flows:
        if not wire.sni or id(wire) in claimed:
            continue
        correlated.append(FlowCorrelation(
            destination=wire.sni,
            src_port=wire.src_port,
            wire=wire,
            wire_strength=JoinStrength.OBSERVED,
            wire_basis=(
                f"The capture holds this connection and it carried TLS SNI {wire.sni}: "
                f"{wire.label}, {wire.packets} packet(s)."
            ),
            tunnel_basis=(
                "The agent logged nothing about this flow. With trace-level logging off it "
                "records a destination mainly when it has a problem to report, so silence here "
                "is not a verdict either way."
            ),
            requests=list(requests_by_host.get(wire.sni, [])),
        ))

    # Flows the capture holds come first, because those are the ones that can
    # be shown packet by packet - the strongest evidence this tool produces.
    # Within each group the worst come first, so the ordering is "what can be
    # proven, then what went wrong" rather than one at the expense of the other.
    # Which agent intercepted each flow.
    #
    # The bundle names the flows the ZTA agent handled, and the capture shows
    # which local port those went to. That port *is* the ZTA listener - not by
    # assumption but because the two artefacts agree on the same connections -
    # so any other loopback flow to the same port was intercepted by the same
    # agent. Traffic to a different local port is some other agent, and this
    # will not guess which: the capture engine names vendors from the
    # certificate issuer, which is evidence this join does not read.
    listener_ports: dict[int, int] = defaultdict(int)
    for record in correlated:
        if record.app is not None and record.wire is not None and record.wire.is_loopback:
            listener_ports[record.wire.dst_port] += 1
    zta_listener = max(listener_ports, key=listener_ports.get) if listener_ports else None

    # The address this machine normally sends from. A flow leaving from a
    # different one is the shape of a second adapter, which is how a VPN
    # tunnel appears in a capture taken on the endpoint.
    client_ips: dict[str, int] = defaultdict(int)
    for wire in wire_flows:
        if not wire.is_loopback:
            client_ips[wire.src_ip] += 1
    local_client_ip = max(client_ips, key=client_ips.get) if client_ips else None

    for record in correlated:
        _attribute_interception(record, zta_listener, local_client_ip)

    order = {"problem": 0, "warning": 1, "info": 2}
    correlated.sort(
        key=lambda f: (
            0 if f.wire is not None else 1,
            order[f.severity],
            -(f.app.error_lines if f.app is not None else 0),
            f.destination,
            f.src_port,
        )
    )

    if ambiguous_wire:
        result.notes.append(
            f"{ambiguous_wire} intercepted flow(s) could not be tied to a captured connection "
            "because more than one used the same source port. They are listed with the agent's "
            "account only."
        )
    if ambiguous_tunnel:
        result.notes.append(
            f"{ambiguous_tunnel} intercepted flow(s) could not be tied to a tunnel because "
            "several tunnels reported the same stream number in the same period."
        )
    if app_flows:
        errors = sum(1 for f in app_flows if f.error_lines)
        result.notes.append(
            f"The agent named a destination for {len(app_flows)} flow(s), {errors} of them while "
            "reporting an error. With trace-level logging off it records the destination mainly "
            "when it has a problem to report, so a destination absent from this list is one the "
            "agent logged no problem for - not one that is known to have worked."
        )

    return correlated


def _attribute_interception(
    flow: FlowCorrelation, zta_listener: int | None, local_client_ip: str | None
) -> None:
    """Name what handled this flow, in a fixed order of precedence.

    ZTA, then RA VPN, then Umbrella, then local breakout. The order matters
    because the tests overlap: a flow inside a VPN tunnel still has a real
    destination address, and an Umbrella-steered flow still leaves the machine
    normally. Taking the most specific evidence first stops a weaker signal
    claiming a flow a stronger one already explains.

    Each step states what it saw. Where the evidence only *fits* a product
    rather than naming it, the wording says "consistent with" - the capture
    cannot see a VPN adapter's name, and inventing certainty here would be the
    easiest place in this tool to be confidently wrong.
    """
    from capture_inspector.dns_analysis import PUBLIC_DNS_RESOLVERS
    from capture_inspector.secure_access import describe as describe_ingress

    # 1. ZTA - the bundle names the flow, or it went to the listener the
    #    bundle accounts for. Both are direct evidence, not inference.
    if flow.app is not None:
        flow.intercepted_by = "Cisco Secure Client - Zero Trust Access"
        flow.intercepted_basis = (
            "The bundle's Zero Trust Access log names this flow, so the ZTA agent handled it."
        )
        return

    if flow.wire is None:
        flow.intercepted_basis = "No captured connection, so nothing here shows what handled it."
        return

    if flow.wire.is_loopback and zta_listener is not None and flow.wire.dst_port == zta_listener:
        flow.intercepted_by = "Cisco Secure Client - Zero Trust Access"
        flow.intercepted_basis = (
            f"This connection went to 127.0.0.1:{zta_listener}, the same local listener the "
            "bundle's ZTA log accounts for on other flows."
        )
        return

    peer = flow.wire.dst_ip

    # 2. RA VPN - the packets left through a different local adapter. The
    #    capture cannot read an adapter's name, so this is the shape of a
    #    tunnel rather than proof of one.
    if (
        not flow.wire.is_loopback
        and local_client_ip
        and flow.wire.src_ip != local_client_ip
    ):
        flow.intercepted_by = "consistent with a VPN tunnel (RA VPN)"
        flow.intercepted_basis = (
            f"This connection left from {flow.wire.src_ip}, while the rest of this capture uses "
            f"{local_client_ip}. A second local address is what a VPN tunnel adapter looks like, "
            "though the capture cannot name the adapter, so this is the shape of a tunnel rather "
            "than proof of one."
        )
        return

    # 3. Umbrella - either its resolvers, or a Secure Access ingress. Both are
    #    named addresses, so both can be stated rather than suggested.
    resolver = PUBLIC_DNS_RESOLVERS.get(peer)
    if resolver and ("umbrella" in resolver.lower() or "opendns" in resolver.lower()):
        flow.intercepted_by = "Cisco Umbrella"
        flow.intercepted_basis = (
            f"The connection went to {peer}, a {resolver} resolver, so Umbrella handled it."
        )
        return

    ingress = describe_ingress(peer)
    if ingress:
        flow.intercepted_by = "Cisco Secure Access (network path)"
        flow.intercepted_basis = (
            f"The connection went to {peer}, a {ingress}. It was steered over the network rather "
            "than by a listener on this machine."
        )
        return

    if flow.wire.is_loopback:
        flow.intercepted_by = f"a local agent on 127.0.0.1:{flow.wire.dst_port}"
        flow.intercepted_basis = (
            "The connection was terminated by an agent on this machine, but not on the port the "
            "ZTA log accounts for"
            + (f" ({zta_listener})" if zta_listener is not None else "")
            + ". Which product that is, is written in the certificate it presented - the capture "
            "engine's Certs view names it; this join does not read certificates."
        )
        return

    # 4. Local breakout - nothing above explains it.
    flow.intercepted_by = "local breakout"
    flow.intercepted_basis = (
        f"The application connected straight to {peer}:{flow.wire.dst_port} from "
        f"{flow.wire.src_ip}: no local listener, no recognised Umbrella resolver and no known "
        "Secure Access ingress. Nothing in these inputs steered it. A proxy this build does not "
        "recognise would look the same, so this is what the evidence shows rather than a "
        "guarantee that nothing inspected it."
    )


def _overlapping(
    events: list[tuple[AgentFlow, datetime]], app: AppFlow
) -> list[AgentFlow]:
    """Tunnels that reported this stream while this flow was open.

    Both sides come from the same log, so their clocks agree and no offset is
    involved. The agent writes the app-flow line and the tunnel's line for the
    same event at the same instant, so a small window either side of the flow's
    own lifetime is enough - and much tighter than the tolerance used for
    joins that must cross artefacts.

    Stream numbers restart on every tunnel connection, so this is an
    association rather than an identity. Where it stays ambiguous the caller
    says so instead of choosing.
    """
    if app.first_seen is None or app.last_seen is None:
        return sorted({tunnel for tunnel, _ in events}, key=lambda t: t.label)
    start = app.first_seen - _STREAM_TOLERANCE
    end = app.last_seen + _STREAM_TOLERANCE
    return sorted(
        {tunnel for tunnel, when in events if start <= when <= end},
        key=lambda t: t.label,
    )


def _add_notes(
    result: SessionCorrelation,
    wire_flows: list[WireFlow],
    agent_flows: list[AgentFlow],
    web_requests: list[WebRequest],
) -> None:
    """Record what the inputs could not answer, so silence is never read as health."""
    if not wire_flows:
        result.notes.append("No capture was supplied, so nothing could be confirmed on the wire.")
    if not agent_flows:
        result.notes.append(
            "The bundle's Zero Trust Access log named no connections, so no tunnel could be "
            "attributed to the agent."
        )
    elif not result.tunnels:
        result.notes.append(
            f"The agent named {len(agent_flows)} connection(s) and the capture holds "
            f"{sum(1 for f in wire_flows if not f.is_loopback)} network connection(s), but none "
            "matched on identity. The two artefacts most likely cover different time windows."
        )
    if not web_requests:
        result.notes.append("No HAR was supplied, so no request, status or timing is available.")

    unknown = [h for h in result.hosts if h.steering is Steering.UNKNOWN]
    if unknown:
        result.notes.append(
            f"{len(unknown)} host(s) appear only in the HAR. A capture records TLS handshakes, "
            "so a host with no handshake was either served from cache or reached over a "
            "protocol the capture did not decode."
        )
