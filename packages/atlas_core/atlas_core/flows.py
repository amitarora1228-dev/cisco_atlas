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
    head: tuple[tuple[float, str, int, str, int], ...] = ()
    tail: tuple[tuple[float, str, int, str, int], ...] = ()
    """The opening and closing packets of the connection, as
    ``(epoch, src_ip, src_port, kind, payload_bytes)``. An intercepted flow has
    a real client and a real server, so it has a real packet ladder - these are
    what draws it. The middle of a long flow is elided, and the count says so."""

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
    application asked for, the agent's own account of what it did with that
    connection and why it ended, the packets that carry it, and what the
    browser got back.
    """

    app: AppFlow
    wire: WireFlow | None = None
    wire_strength: JoinStrength = JoinStrength.ASSOCIATED
    wire_basis: str = ""
    tunnel: AgentFlow | None = None
    tunnel_basis: str = ""
    requests: list[WebRequest] = field(default_factory=list)

    @property
    def failures(self) -> list[WebRequest]:
        return [r for r in self.requests if r.failed]

    @property
    def severity(self) -> str:
        """Worst-first ordering, from what is actually recorded."""
        if self.app.reasons or self.failures:
            return "problem"
        if self.app.error_lines:
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
)

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

        if rst in {"1", "True"}:
            kind = "rst"
        elif fin in {"1", "True"}:
            kind = "fin"
        elif is_syn:
            kind = "syn"
        elif syn in {"1", "True"} and is_ack:
            kind = "synack"
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
        event = (moment, src, int(sport), kind, payload_bytes)
        if len(rec["head"]) < _PACKET_EDGE:
            rec["head"].append(event)
        else:
            rec["tail"].append(event)
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
            head=tuple(rec["head"]),
            tail=tuple(rec["tail"]),
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
    """Read the browser's own record of the session."""
    from urllib.parse import urlparse

    with open(har_path, encoding="utf-8", errors="replace") as handle:
        document = json.load(handle)

    entries = document.get("log", {}).get("entries", []) or []
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
        "flows": [_flow_payload(flow) for flow in session.flows],
        "notes": session.notes,
        "sources": session.sources,
    }


# What the agent's own close-reason token means. These describe the token, they
# do not diagnose the cause - the agent says what it did, not why the far end
# behaved as it did, and the difference matters when a reader acts on it.
_REASON_MEANING = {
    "connect_timeout": "the onward connection was not established before the agent gave up",
    "socket_read": "reading from the local application socket failed",
    "socket_write": "writing to the local application socket failed",
    "next_transport_state": "the transport underneath the flow changed state while it was open",
    "tunnel_connect": "the tunnel this flow needed could not be connected",
    "connect_transport": "the agent could not start the onward transport",
}


def _flow_payload(flow: FlowCorrelation) -> dict:
    """One intercepted flow, with every claim carrying the artefact behind it."""
    app = flow.app
    statuses: dict[str, int] = {}
    for request in flow.requests:
        key = str(request.status) if request.status else "no response"
        statuses[key] = statuses.get(key, 0) + 1

    evidence = [{"source": "bundle", "text": f"ZTA log names this flow {app.label}"}]
    if flow.wire is not None:
        evidence.append({"source": "capture", "text": f"{flow.wire.label}, {flow.wire.packets} packet(s)"})
    if flow.tunnel is not None:
        evidence.append({"source": "bundle", "text": f"tunnel {flow.tunnel.label}"})
    if flow.requests:
        evidence.append({
            "source": "har",
            "text": f"{len(flow.requests)} browser request(s) to {app.dest}",
        })

    return {
        "destination": app.dest,
        "label": app.label,
        "severity": flow.severity,
        "protocol": app.proto,
        "src_port": app.src_port,
        "stream": app.stream,
        "first_seen": _iso(app.first_seen),
        "last_seen": _iso(app.last_seen),
        "agent_lines": app.lines,
        "error_lines": app.error_lines,
        "reasons": list(app.reasons),
        "agent_errors": list(app.errors),
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
    }


_PACKET_LABELS = {
    "syn": "SYN",
    "synack": "SYN/ACK",
    "fin": "FIN",
    "rst": "RST",
    "ack": "ACK",
}


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
    return _log_timeline(flow.app)


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
    parts = [
        f"ZTA steering matched {app.dest}, so the agent intercepted the connection and "
        f"handled it on source port {app.src_port}"
    ]

    if flow.wire is not None:
        where = "the agent's local listener" if flow.wire.is_loopback else "the network"
        parts.append(
            f"the capture shows that connection to {where} at {flow.wire.label}, "
            f"{flow.wire.packets} packet(s)"
        )

    if flow.tunnel is not None:
        parts.append(f"it was carried as stream {app.stream} on {flow.tunnel.label}")

    if app.reasons:
        for reason in app.reasons:
            meaning = _REASON_MEANING.get(reason)
            parts.append(
                f"the agent closed it with reason '{reason}'"
                + (f" - {meaning}" if meaning else "")
            )
    elif app.error_lines:
        parts.append(
            f"the agent logged {app.error_lines} error line(s) against it but recorded no "
            "close reason"
        )

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
        record = FlowCorrelation(app=app, requests=list(requests_by_host.get(app.dest, [])))

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

    # Flows the capture holds come first, because those are the ones that can
    # be shown packet by packet - the strongest evidence this tool produces.
    # Within each group the worst come first, so the ordering is "what can be
    # proven, then what went wrong" rather than one at the expense of the other.
    order = {"problem": 0, "warning": 1, "info": 2}
    correlated.sort(
        key=lambda f: (
            0 if f.wire is not None else 1,
            order[f.severity],
            -f.app.error_lines,
            f.app.dest,
            f.app.src_port,
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
