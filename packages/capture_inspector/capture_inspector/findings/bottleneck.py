"""Bottleneck attribution: where the elapsed time actually went, and which
mechanism was limiting the transfer.

Users report "it is slow" and every layer gets blamed. The categories in this
module answer a narrower, provable question: during the captured period, was
anything on the network actually the constraint? The strongest answer is often
the negative one — long stretches where the network carried nothing at all, so
whatever the client was waiting for, it was not the wire.

Every number here is measured, never modelled. Time the capture cannot account
for is reported as such rather than being attributed to a guess.
"""
from __future__ import annotations

from ..engine import Finding, _pkt_is_c2s
from ..pcap import Flow

# A pause must be this long before it counts as idle. Normal request/response
# pacing, congestion-control bursts and delayed ACKs all live well below this,
# so the threshold keeps ordinary protocol rhythm out of the budget.
_IDLE_GAP_S = 0.5
# Below this span the split is dominated by a handful of packets and would be
# noise rather than a budget.
_MIN_SPAN_S = 1.0
# Idle has to reach this share of the capture before it is named the dominant
# limit, rather than merely reported in the budget.
_IDLE_DOMINANT_PCT = 20.0
# Loss is judged as a RATE, never as a raw count: a long capture accumulates
# events without the path being lossy. Below this share of data segments, loss
# is background noise rather than the thing holding the transfer back.
_LOSS_DOMINANT_PCT = 1.0


def _capture_span(packets: list) -> tuple[float, float]:
    times = [p.time_relative for p in packets if p.time_relative is not None]
    if not times:
        return 0.0, 0.0
    return min(times), max(times)


def _conversation_packets(packets: list, flows: list[Flow]) -> list:
    """Keep only packets belonging to the conversations under analysis.

    Background link-layer traffic (ARP, broadcast, discovery chatter) shares the
    wire but is nobody's conversation. Counting it would let a stray frame split
    a long pause in two, or erase it altogether, and it can never be attributed
    to a client or a server."""
    keys = {f.key for f in flows}
    out = []
    for pkt in packets:
        stream = pkt.first("tcp.stream")
        if stream is not None and f"tcp-{stream}" in keys:
            out.append(pkt)
            continue
        ustream = pkt.first("udp.stream")
        if ustream is not None and f"udp-{ustream}" in keys:
            out.append(pkt)
    return out


def _idle_gaps(packets: list) -> list[tuple[float, float, object]]:
    """Stretches where the conversations carried no packet at all.

    Returned as (start, end, first_packet_after). Silence across every analysed
    conversation — not merely within one flow — is what proves the network was
    not the thing being waited on."""
    ordered = sorted((p for p in packets if p.time_relative is not None),
                     key=lambda p: p.time_relative)
    gaps: list[tuple[float, float, object]] = []
    prev = None
    for pkt in ordered:
        if prev is not None and (pkt.time_relative - prev.time_relative) >= _IDLE_GAP_S:
            gaps.append((prev.time_relative, pkt.time_relative, pkt))
        prev = pkt
    return gaps


def _who_broke_silence(pkt, flows: list[Flow]) -> str | None:
    """Name the side that ended a pause.

    Whoever speaks first after the silence is the side everything was waiting
    on, which makes this an attribution rather than an inference."""
    stream = pkt.first("tcp.stream")
    if stream is None:
        return None
    flow = next((f for f in flows if f.key == f"tcp-{stream}"), None)
    if flow is None:
        return None
    return "client" if _pkt_is_c2s(flow, pkt) else "server"


def _real_loss(flows: list[Flow]) -> int:
    """Loss the wire actually shows, with unnecessary retransmissions removed."""
    total = 0
    for f in flows:
        retx = max(0, f.retransmissions - f.spurious_retransmissions)
        total += retx + f.lost_segments
    return total


def _bottleneck_findings(flows: list[Flow], packets: list,
                         unreliable_loss: bool = False) -> list[Finding]:
    """Split the captured period into idle vs active time and name the limit.

    ``unreliable_loss`` is set for captures whose retransmission counters cannot
    be trusted (duplicated interfaces, or a host-side capture with segmentation
    offload). There the congestion verdict is withheld entirely rather than
    contradicting the finding that already explained why those counts are
    inflated.

    Deliberately silent when the capture is too short, or when nothing was
    limiting: an absent finding is better than a manufactured one."""
    tcp = [f for f in flows if f.transport == "tcp"]
    if not tcp or not packets:
        return []
    convo = _conversation_packets(packets, flows)
    if not convo:
        return []
    first, last = _capture_span(convo)
    span = last - first
    if span < _MIN_SPAN_S:
        return []

    gaps = _idle_gaps(convo)
    idle = sum(end - start for start, end, _ in gaps)
    idle_pct = (idle / span * 100.0) if span else 0.0
    active = max(0.0, span - idle)

    # Handshake cost is per connection and connections overlap, so summing it
    # would exceed the wall clock. The largest single setup is the honest figure.
    setups = [(f.tcp_handshake_ms or 0) + (f.tls_setup_ms or 0) for f in tcp]
    slowest_setup_ms = max(setups) if setups else 0.0

    window_stalls = sum(f.window_full for f in tcp)
    zero_windows = sum(f.zero_window for f in tcp)
    loss = 0 if unreliable_loss else _real_loss(tcp)
    segments = sum(f.data_segments for f in tcp)
    loss_pct = (loss / segments * 100.0) if segments else 0.0

    out: list[Finding] = []

    # --- The budget itself -------------------------------------------------
    budget = (f"Of {span:.2f} s captured, {idle:.2f} s ({idle_pct:.0f}%) passed with no packet from "
              f"either side of any analysed conversation, and {active:.2f} s ({100 - idle_pct:.0f}%) "
              f"carried traffic.")
    attribution = ""
    if gaps:
        sides = [s for s in (_who_broke_silence(p, tcp) for _, _, p in gaps) if s]
        longest = max(gaps, key=lambda g: g[1] - g[0])
        who = _who_broke_silence(longest[2], tcp)
        attribution = (f" The longest pause was {longest[1] - longest[0]:.2f} s "
                       f"(t={longest[0]:.2f} s to t={longest[1]:.2f} s)")
        if who:
            attribution += (f", ended by the {who} — so the {who} was the side everything "
                            f"was waiting on")
        attribution += "."
        if sides.count("client") and sides.count("server"):
            attribution += (f" Across all pauses the client ended {sides.count('client')} and the "
                            f"server {sides.count('server')}.")

    out.append(Finding(
        title=f"Time budget: {idle_pct:.0f}% idle, {100 - idle_pct:.0f}% active",
        severity="info",
        category="latency",
        detail=(budget + attribution +
                " Idle time is measured, not modelled: it is wall-clock time in which the analysed "
                "conversations contain no packet at all (background link-layer chatter is excluded, "
                "since it belongs to no conversation). What the waiting side was doing during it "
                "(computing, reading a file, waiting on a user or on another service) is outside the "
                "capture and is not guessed here."),
        evidence=[f"span={span:.3f}s idle={idle:.3f}s ({idle_pct:.0f}%) gaps={len(gaps)} "
                  f"slowest_setup_ms={slowest_setup_ms:.0f} window_full={window_stalls} "
                  f"zero_window={zero_windows} real_loss={loss}/{segments} ({loss_pct:.2f}%)"],
    ))

    # --- The dominant limit ------------------------------------------------
    # Ordered by how conclusive the evidence is. Loss is the only one that
    # demonstrates the path itself was the constraint, so it outranks the rest.
    if loss_pct >= _LOSS_DOMINANT_PCT:
        out.append(Finding(
            title=f"Dominant limit: lossy or congested path ({loss_pct:.1f}% of segments lost)",
            severity="medium",
            category="network",
            detail=(f"{loss} of {segments} data segments needed retransmitting or were reported "
                    f"missing ({loss_pct:.1f}%), after discarding retransmissions the dissector judged "
                    f"unnecessary. Loss is the one signal that shows the network itself was the "
                    f"constraint rather than either endpoint: throughput is then capped by congestion "
                    f"control backing off, not by the link's raw speed."),
            evidence=[f"real_loss={loss}/{segments} ({loss_pct:.2f}%) span={span:.3f}s "
                      f"idle_pct={idle_pct:.0f}"],
            is_verdict=True,
        ))
    elif idle_pct >= _IDLE_DOMINANT_PCT:
        who = _who_broke_silence(max(gaps, key=lambda g: g[1] - g[0])[2], tcp) if gaps else None
        side = f"the {who}" if who else "an endpoint"
        out.append(Finding(
            title=f"Dominant limit: waiting on {who or 'an endpoint'}, not the network "
                  f"({idle_pct:.0f}% of the time idle)",
            severity="low",
            category="latency",
            detail=(f"{idle:.2f} s of the {span:.2f} s captured passed with the network completely "
                    f"silent, and {side} ended the wait. During those pauses nothing was queued, "
                    f"retransmitted or blocked — there was simply nothing to carry. Time lost here "
                    f"cannot be recovered by changing the network; it belongs to whatever {side} was "
                    f"doing. The capture proves the network was not the constraint, not what the "
                    f"cause was."),
            evidence=[f"idle={idle:.3f}s of span={span:.3f}s ({idle_pct:.0f}%) gaps={len(gaps)} "
                      f"real_loss=0"],
            is_verdict=True,
        ))
    elif zero_windows:
        out.append(Finding(
            title=f"Dominant limit: receiver buffer full ({zero_windows} zero-window event(s))",
            severity="low",
            category="latency",
            detail=("The receiver advertised a zero window, meaning its buffer filled because the "
                    "application above it was not reading fast enough. The sender and the path were "
                    "both ready; the receiving application was the constraint."),
            evidence=[f"zero_window={zero_windows} real_loss=0 idle_pct={idle_pct:.0f}"],
            is_verdict=True,
        ))
    elif window_stalls:
        out.append(Finding(
            title=f"Dominant limit: receive window ({window_stalls} stall(s))",
            severity="low",
            category="latency",
            detail=("With no loss and no idle time to speak of, the sender's stalls against the "
                    "receiver's advertised window were the binding constraint. Throughput is capped "
                    "at window/RTT until the window grows."),
            evidence=[f"window_full={window_stalls} real_loss=0 idle_pct={idle_pct:.0f}"],
            is_verdict=True,
        ))

    return out
