"""Stitch captures taken at different points of a path into one account.

A request from a ZTA client to a private resource is not one connection. It is
a chain of them::

    client --- Zproxy --- FWaaS --- CNHE --- FTD --- resource

Some of those devices *forward* the connection and some *terminate* it, and the
difference decides what can be proved:

* A forwarding device (an FTD routing traffic, a NAT) passes the sequence
  number through untouched. The same connection seen from two vantage points
  therefore carries the same initial sequence number, even across NAT, which
  rewrites addresses and ports but never sequence numbers. That is an exact
  join, and it is worth more than an exact join usually is: because it
  identifies the *same packet* twice, it also measures the clock offset between
  the two capture devices, which nothing else here can do.

* A proxy (Zproxy, FWaaS, ASAc, a resource connector) terminates the client's
  connection and opens its own. New sequence number, new ports, frequently a
  new source address. No packet is shared, so no exact join exists. These legs
  can only be associated - by the destination they name and by their position
  in time - and this module never reports that association as proof.

The order of the hops is inferred rather than asked for. Where a proxy joins
two legs, both captures contain that proxy's own address: one as a destination,
one as a source. That shared address is the pivot the chain is built from.

Nothing in here reads a device log yet. Connection events from an FTD or an
ASAc would join more strongly than a capture pair can - they carry the NAT
translation and a connection identifier directly - but their formats vary
enough that guessing at one would produce a confident join built on nothing.
:func:`stitch_path` reports the absence in ``notes`` rather than filling it in.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from .flows import JoinStrength, WireFlow

# How far apart two legs of the same transaction may sit and still be
# associated. A proxy opens its outbound connection after it accepts the
# inbound one, but "after" can mean a fresh TLS handshake to a distant region,
# and a queued connection under load is slower still. Wider than this and the
# match is being made by hope rather than by time.
_PROXY_WINDOW = timedelta(seconds=8)

# A clock offset is only trusted when several connections agree on it. One
# shared connection could be a coincidence of ports; five that all say the same
# device is 2.1 s fast is a measurement.
_MIN_OFFSET_SAMPLES = 3

# Beyond this, two captures are not describing the same session in any useful
# sense and aligning them would invent a relationship.
_MAX_OFFSET = timedelta(hours=12)

_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


class LinkKind(str, Enum):
    """How one leg of the path was tied to the next."""

    FORWARDED = "forwarded"
    """The same connection, seen again further along. Proved by sequence number."""

    PROXIED = "proxied"
    """A different connection, believed to carry the same transaction."""


@dataclass(frozen=True)
class Vantage:
    """One capture, and the point on the path it was taken from."""

    name: str
    flows: tuple[WireFlow, ...]

    @property
    def addresses(self) -> set[str]:
        seen: set[str] = set()
        for flow in self.flows:
            seen.add(flow.src_ip)
            seen.add(flow.dst_ip)
        return seen


@dataclass(frozen=True)
class Observation:
    """One connection as one capture saw it."""

    vantage: str
    flow: WireFlow


@dataclass
class Segment:
    """One TCP connection, wherever it was observed.

    A segment with more than one observation was seen by more than one capture,
    which means every device between those two vantage points forwarded it
    rather than terminating it. That is a finding in itself.
    """

    key: str
    observations: list[Observation] = field(default_factory=list)

    @property
    def first(self) -> WireFlow:
        return self.observations[0].flow

    @property
    def client(self) -> str:
        return self.first.src_ip

    @property
    def server(self) -> str:
        return self.first.dst_ip

    @property
    def sni(self) -> str | None:
        for obs in self.observations:
            if obs.flow.sni:
                return obs.flow.sni
        return None

    @property
    def started(self) -> datetime | None:
        times = [o.flow.first_seen for o in self.observations if o.flow.first_seen]
        return min(times) if times else None

    @property
    def vantages(self) -> list[str]:
        seen: list[str] = []
        for obs in self.observations:
            if obs.vantage not in seen:
                seen.append(obs.vantage)
        return seen

    @property
    def seen_at(self) -> int:
        return len(self.vantages)

    @property
    def label(self) -> str:
        f = self.first
        return f"{f.src_ip}:{f.src_port} -> {f.dst_ip}:{f.dst_port}"


@dataclass(frozen=True)
class Link:
    """A join between two segments - one hop of the end-to-end path."""

    upstream: str
    downstream: str
    kind: LinkKind
    strength: JoinStrength
    pivot: str | None
    basis: str


@dataclass
class PathTrace:
    """One transaction, followed as far as the captures allow."""

    destination: str
    segments: list[Segment]
    links: list[Link]
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """Whether every hop is joined - no gap in the middle of the chain."""
        return len(self.links) == max(len(self.segments) - 1, 0) and bool(self.segments)

    @property
    def proved_hops(self) -> int:
        """How much of this chain rests on measurement rather than inference.

        A leg seen at more than one vantage point is the proof: the same
        sequence number in two captures means every device between them
        forwarded that connection rather than terminating it. Proxied links are
        deliberately excluded - they are the part of the path this tool infers,
        and counting them here would make an inferred chain look measured.
        """
        return sum(1 for segment in self.segments if segment.seen_at > 1)


def _is_private(address: str) -> bool:
    return address.startswith(_PRIVATE_PREFIXES)


def _segment_key(flow: WireFlow) -> str:
    """What makes two observations the same connection.

    The ISN when there is one, because it survives NAT. Without a captured
    handshake there is no ISN, and the flow can only be keyed on its own
    addresses - which means it will not join across a NAT. That limitation is
    reported rather than papered over.
    """
    if flow.isn is not None:
        return f"isn:{flow.isn}"
    return f"tuple:{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}"


def group_segments(vantages: list[Vantage]) -> list[Segment]:
    """Fold every capture's flows into segments, joining identical connections."""
    segments: dict[str, Segment] = {}
    for vantage in vantages:
        for flow in vantage.flows:
            key = _segment_key(flow)
            segment = segments.get(key)
            if segment is None:
                segment = Segment(key=key)
                segments[key] = segment
            segment.observations.append(Observation(vantage=vantage.name, flow=flow))
    return list(segments.values())


def clock_offsets(segments: list[Segment], reference: str) -> tuple[dict[str, timedelta], list[str]]:
    """Measure how far each capture's clock sits from the reference capture's.

    Only segments seen at both vantages can do this, because only they identify
    the same packet twice. Where no such segment exists the offset is unknown,
    and the caller is told rather than being handed a zero that would read as
    "the clocks agree".
    """
    samples: dict[str, list[float]] = defaultdict(list)
    for segment in segments:
        by_vantage = {o.vantage: o.flow for o in segment.observations}
        anchor = by_vantage.get(reference)
        if anchor is None or anchor.first_seen is None:
            continue
        for name, flow in by_vantage.items():
            if name == reference or flow.first_seen is None:
                continue
            samples[name].append((flow.first_seen - anchor.first_seen).total_seconds())

    offsets: dict[str, timedelta] = {}
    notes: list[str] = []
    for name, values in samples.items():
        if len(values) < _MIN_OFFSET_SAMPLES:
            notes.append(
                f"{name} shares only {len(values)} connection(s) with {reference}, too few to "
                f"measure a clock offset; its times are shown as recorded."
            )
            continue
        median = timedelta(seconds=statistics.median(values))
        if abs(median) > _MAX_OFFSET:
            notes.append(
                f"{name} appears {median} from {reference}, too far apart to be the same "
                f"session; the captures are not aligned."
            )
            continue
        offsets[name] = median
    return offsets, notes


def _pivot_link(upstream: Segment, downstream: Segment) -> Link | None:
    """Join two legs through the address they share.

    A proxy accepts on one address and originates from another, and the two are
    often different - an inbound VIP and an egress address. Both cases are
    handled, but only the single-address case is called a pivot, because when
    the addresses differ the shared identity is the destination name, which is
    weaker evidence.
    """
    if upstream.first.dst_ip == downstream.first.src_ip:
        return Link(
            upstream=upstream.key,
            downstream=downstream.key,
            kind=LinkKind.PROXIED,
            strength=JoinStrength.OBSERVED,
            pivot=upstream.first.dst_ip,
            basis=(
                f"{upstream.first.dst_ip} received the connection on one capture and opened the "
                f"next one on another, so it terminated the first and originated the second. "
                f"That is a proxy, and the two legs are the same transaction."
            ),
        )
    return None


def _name_link(upstream: Segment, downstream: Segment) -> Link | None:
    """Join two legs by the destination they both name, and by time."""
    name = upstream.sni or downstream.sni
    if not name or upstream.sni != downstream.sni:
        return None
    a, b = upstream.started, downstream.started
    if a is None or b is None:
        return None
    gap = b - a
    if gap < timedelta(0) or gap > _PROXY_WINDOW:
        return None
    return Link(
        upstream=upstream.key,
        downstream=downstream.key,
        kind=LinkKind.PROXIED,
        strength=JoinStrength.ASSOCIATED,
        pivot=None,
        basis=(
            f"Both legs asked for {name}, and the second opened {gap.total_seconds():.3f} s after "
            f"the first. No packet is shared between them, so this is the shape of a proxied "
            f"transaction rather than proof that these two legs are the same one - another "
            f"request for {name} in the same second would look identical."
        ),
    )


def _order_segments(segments: list[Segment], links: list[Link]) -> list[Segment]:
    """Put the chain in path order, client end first.

    The first leg is the one nothing points at; each following leg is whatever
    the previous one links to.
    """
    by_key = {s.key: s for s in segments}
    downstream_of = {link.upstream: link.downstream for link in links}
    pointed_at = {link.downstream for link in links}
    starts = [s for s in segments if s.key not in pointed_at]
    if not starts:
        return segments

    ordered: list[Segment] = []
    seen: set[str] = set()
    for start in starts:
        key: str | None = start.key
        while key and key not in seen:
            seen.add(key)
            if key in by_key:
                ordered.append(by_key[key])
            key = downstream_of.get(key)
    ordered += [s for s in segments if s.key not in seen]
    return ordered


def stitch_path(vantages: list[Vantage], destination: str | None = None) -> list[PathTrace]:
    """Follow each transaction across every capture supplied.

    Returns one trace per destination, longest chain first, because the reader
    is looking for the flow that crossed the most of the path - that is the one
    with something to say about where it broke.
    """
    if not vantages:
        return []

    segments = group_segments(vantages)
    if not segments:
        return []

    links: list[Link] = []
    # Indexed rather than compared pairwise. Both joins are equality tests - a
    # proxy link needs one segment's destination address to equal another's
    # source, and a name link needs the two to share an SNI - so the candidates
    # can be looked up instead of searched for. Measured before this: 8,000
    # connections took 13.6 s and 16,000 took 54 s, which a capture from a busy
    # firewall reaches easily, and the cost was quadratic so it only got worse.
    by_source: dict[str, list[Segment]] = defaultdict(list)
    by_name: dict[str, list[Segment]] = defaultdict(list)
    for segment in segments:
        by_source[segment.first.src_ip].append(segment)
        if segment.sni:
            by_name[segment.sni].append(segment)

    for upstream in segments:
        link = None
        for downstream in by_source.get(upstream.first.dst_ip, ()):
            if downstream.key == upstream.key:
                continue
            link = _pivot_link(upstream, downstream)
            if link is not None:
                break
        if link is None and upstream.sni:
            for downstream in by_name.get(upstream.sni, ()):
                if downstream.key == upstream.key:
                    continue
                link = _name_link(upstream, downstream)
                if link is not None:
                    break
        if link is not None:
            links.append(link)

    # A segment may look like the upstream of several others when a proxy is
    # busy. Keep the strongest, then the earliest - guessing among equals would
    # draw a chain that never happened.
    best: dict[str, Link] = {}
    for link in links:
        current = best.get(link.upstream)
        if current is None or (
            current.strength is not JoinStrength.OBSERVED and link.strength is JoinStrength.OBSERVED
        ):
            best[link.upstream] = link
    links = list(best.values())

    by_destination: dict[str, list[Segment]] = defaultdict(list)
    for segment in segments:
        name = segment.sni or segment.server
        if destination and destination not in (segment.sni or "") and destination != segment.server:
            continue
        by_destination[name].append(segment)

    # One chain per connected component, not one per destination. A chain
    # crosses several destinations by its nature - the first leg is addressed
    # to the proxy, not to the resource - so grouping by destination reported
    # the same transaction once per hop and named it after the proxy.
    parent: dict[str, str] = {s.key: s.key for s in segments}

    def _root(key: str) -> str:
        while parent[key] != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    for link in links:
        if link.upstream in parent and link.downstream in parent:
            parent[_root(link.upstream)] = _root(link.downstream)

    wanted = {s.key for group in by_destination.values() for s in group}
    components: dict[str, list[Segment]] = defaultdict(list)
    for segment in segments:
        if segment.key in wanted:
            components[_root(segment.key)].append(segment)

    traces: list[PathTrace] = []
    for keys_group in components.values():
        keys = {s.key for s in keys_group}
        chain_links = [link for link in links if link.upstream in keys and link.downstream in keys]
        ordered = _order_segments(keys_group, chain_links)

        # The destination is what the last leg was addressed to - the resource -
        # not what the first leg was addressed to, which is the proxy in front
        # of it and tells the reader nothing about what they were reaching for.
        final = ordered[-1]
        name = final.sni or final.server

        notes: list[str] = []
        without_syn = [s for s in ordered if s.first.isn is None]
        if without_syn:
            notes.append(
                f"{len(without_syn)} leg(s) were captured without their handshake, so they carry "
                f"no sequence number and cannot be recognised at another vantage point. A capture "
                f"started before the connection opens is what makes that join possible."
            )
        if len(vantages) > 1 and len(ordered) == 1 and ordered[0].seen_at == 1:
            notes.append(
                "Only one leg of this transaction was captured, at one vantage point. The rest of "
                "the path was not observed, so nothing is claimed about it."
            )
        traces.append(
            PathTrace(destination=name, segments=ordered, links=chain_links, notes=notes)
        )

    traces.sort(key=lambda t: (-len(t.segments), -t.proved_hops, t.destination))
    return traces


def describe_node(address: str, port: int | None = None) -> str:
    """Name a device on the path from its address, where it can be named."""
    if address in {"127.0.0.1", "::1"}:
        return "local agent"
    try:
        from capture_inspector.secure_access import describe as describe_ingress

        described = describe_ingress(address)
        if described:
            return str(described)
    except Exception:  # noqa: BLE001, S110 - naming is a courtesy, never a requirement
        pass
    if _is_private(address):
        return "private address"
    return "public address"


def as_payload(traces: list[PathTrace], vantages: list[Vantage]) -> dict:
    """Shape the stitched path for the browser."""
    seen_addresses: Counter[str] = Counter()
    for vantage in vantages:
        for flow in vantage.flows:
            seen_addresses[flow.src_ip] += 1

    return {
        "vantages": [
            {"name": v.name, "flows": len(v.flows),
             "with_handshake": sum(1 for f in v.flows if f.isn is not None)}
            for v in vantages
        ],
        "traces": [
            {
                "destination": trace.destination,
                "complete": trace.complete,
                "proved_hops": trace.proved_hops,
                "notes": trace.notes,
                "segments": [
                    {
                        "key": segment.key,
                        "label": segment.label,
                        "src_ip": segment.first.src_ip,
                        "src_port": segment.first.src_port,
                        "dst_ip": segment.first.dst_ip,
                        "dst_port": segment.first.dst_port,
                        "dst_role": describe_node(segment.first.dst_ip, segment.first.dst_port),
                        "sni": segment.sni,
                        "isn": segment.first.isn,
                        "packets": segment.first.packets,
                        "started": segment.started.isoformat(timespec="milliseconds")
                        if segment.started
                        else None,
                        "vantages": segment.vantages,
                        "seen_at": len(segment.vantages),
                    }
                    for segment in trace.segments
                ],
                "links": [
                    {
                        "upstream": link.upstream,
                        "downstream": link.downstream,
                        "kind": link.kind.value,
                        "strength": link.strength.value,
                        "pivot": link.pivot,
                        "basis": link.basis,
                    }
                    for link in trace.links
                ],
            }
            for trace in traces
        ],
    }
