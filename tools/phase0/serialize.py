"""Shared serialisation for Phase 0 extractor-parity work.

A ``WireFlow`` is compared across two independent extractors, so it has to be
reduced to something diffable. Ordering of the flow list is *not* part of the
contract - tshark and a hand-written reader may discover flows in a different
order - so dumps are keyed by connection identity rather than by position.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def flow_key(flow: Any) -> str:
    """Identity for one connection, stable across two independent readers.

    The endpoint pair alone is not enough: an ephemeral port is reused within a
    capture, so one pair can hold several connections in succession. The initial
    sequence number distinguishes them and is the natural identity, being the
    one field both readers derive from the same bytes. Orientation is excluded
    deliberately - tshark decides which end is "source" from the first packet it
    saw, and a reader that disagrees should show up as an orientation defect,
    not as a missing flow.
    """
    a = (flow.src_ip, flow.src_port)
    b = (flow.dst_ip, flow.dst_port)
    lo, hi = sorted([a, b])
    isn = flow.isn if flow.isn is not None else "none"
    return f"{lo[0]}:{lo[1]}|{hi[0]}:{hi[1]}|{isn}"


def flow_to_dict(flow: Any) -> dict:
    """Every field of the contract, in a JSON-safe form."""
    return {
        # Tier 1 - read straight from headers.
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "packets": flow.packets,
        "bytes": flow.bytes,
        "first_seen": _iso(flow.first_seen),
        "last_seen": _iso(flow.last_seen),
        "has_syn": flow.has_syn,
        "isn": flow.isn,
        "peer_isn": flow.peer_isn,
        "client_bytes": flow.client_bytes,
        "server_bytes": flow.server_bytes,
        # Tier 2 - TLS, needs record parsing.
        "sni": flow.sni,
        "tls_version": flow.tls_version,
        "alpn": list(flow.alpn),
        "handshake_seen": list(flow.handshake_seen),
        "tls_alerts": list(flow.tls_alerts),
        # Tier 3 - derived analysis, reimplemented rather than read.
        "retransmissions": flow.retransmissions,
        "duplicate_acks": flow.duplicate_acks,
        "zero_windows": flow.zero_windows,
        "out_of_order": flow.out_of_order,
        "rtt_count": len(flow.rtts),
        "rtt_mean": (sum(flow.rtts) / len(flow.rtts)) if flow.rtts else None,
        "handshake_rtt": flow.handshake_rtt,
        # Tier 4 - cleartext HTTP only.
        "http_methods": list(flow.http_methods),
        "http_statuses": list(flow.http_statuses),
        "first_uri": flow.first_uri,
        # Structural, but assigned rather than observed: tshark numbers streams
        # in order of first appearance and any other reader must invent its own.
        # Recorded so numbering can be checked, never used as the join key.
        "stream": flow.stream,
    }


# Which tier each field belongs to, for the fidelity report.
TIERS: dict[str, tuple[str, ...]] = {
    "1-headers": (
        "src_ip", "src_port", "dst_ip", "dst_port", "packets", "bytes",
        "first_seen", "last_seen", "has_syn", "isn", "peer_isn",
        "client_bytes", "server_bytes",
    ),
    "2-tls": ("sni", "tls_version", "alpn", "handshake_seen", "tls_alerts"),
    "3-derived": (
        "retransmissions", "duplicate_acks", "zero_windows", "out_of_order",
        "rtt_count", "rtt_mean", "handshake_rtt",
    ),
    "4-http": ("http_methods", "http_statuses", "first_uri"),
}

# Fields whose exact equality is not required: floats, and counters produced by
# heuristics that two implementations may reasonably disagree about.
TOLERANT: dict[str, float] = {
    "rtt_mean": 0.002,
    "handshake_rtt": 0.002,
    "first_seen": 1.0,
    "last_seen": 1.0,
}
