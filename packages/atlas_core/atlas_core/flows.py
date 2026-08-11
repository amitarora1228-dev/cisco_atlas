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
from collections import defaultdict
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

# The agent writes one of these prefixes depending on which transport handled
# the connection. Grepping only for "tcp_" silently misses every multiplexed
# tunnel, which is where the interesting events live.
_AGENT_FLOW_RE = re.compile(
    r"\b(?P<proto>tcp|tls|udp|http2)_(?P<sport>\d{1,5})__(?P<dip>[0-9]{1,3}(?:\.[0-9]{1,3}){3}):(?P<dport>\d{1,5})\b"
)
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

    @property
    def identity(self) -> tuple[int, str, int]:
        return (self.src_port, self.dst_ip, self.dst_port)

    @property
    def label(self) -> str:
        return f"{self.proto}_{self.src_port}__{self.dst_ip}:{self.dst_port}"


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
class SessionCorrelation:
    """The joined result, plus an explicit record of what it could not answer."""

    hosts: list[HostCorrelation] = field(default_factory=list)
    tunnels: list[TunnelCorrelation] = field(default_factory=list)
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
)


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
        )
        for key, runs in sorted(episodes.items())
        for rec in runs
    ]


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
        },
        "clock": {
            "offset_seconds": (
                session.clock_offset.total_seconds() if session.clock_offset is not None else None
            ),
            "basis": session.clock_offset_basis,
        },
        "hosts": sorted(hosts, key=lambda h: (-h["requests"], h["host"])),
        "tunnels": tunnels,
        "notes": session.notes,
        "sources": session.sources,
    }


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

    _add_notes(result, wire_flows, agent_flows, web_requests)
    return result


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
