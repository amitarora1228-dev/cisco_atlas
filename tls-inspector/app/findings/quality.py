"""Passive network-quality findings (network-only QoE).

Turns the raw tshark TCP-analysis signals into a readable, explainable verdict
per destination: is there a network problem or not, and where. The methodology
was validated against the Wireshark TCP-analysis documentation, RFC 3550 and
three real captures taken at different capture points:

* Network RTT  = initial_rtt (SYN -> SYN/ACK handshake). The cleanest per-flow
  network round-trip; NOT the average ack_rtt (which is deflated by local ACKs).
* RTT variation (jitter) = deviation of the per-ACK ack_rtt samples. Labelled
  "RTT variation" honestly, since we measure RTT, not one-way RTP transit.
* Real loss = retransmissions - spurious_retransmissions, corroborated by
  duplicate-ACKs, over a denominator of data segments (tcp.len>0). We NEVER
  count tcp.analysis.lost_segment as loss: empirically its ratio to real
  retransmissions swings from 0.1x to 10x depending purely on the capture point
  (endpoint captures with NIC offload manufacture phantom "lost" segments), so
  it is not a trustworthy cross-capture loss metric.
* duplicate-ACKs with no matching retransmission are reported separately as
  UNCONFIRMED reverse-path loss / reordering, never as confirmed loss.

Loopback flows (127.0.0.0/8, ::1) are excluded — they are local IPC, not network.
"""
from __future__ import annotations

import statistics
from typing import Optional

from ..engine import Finding
from ..pcap import Flow
from .base import _is_loopback_ip, _flow_label

# Verdict thresholds.
_Q_LOSS_DEGRADED = 0.5     # % real loss -> degraded
_Q_LOSS_BAD = 2.0          # % real loss -> bad
_Q_JITTER_MS = 30.0        # RTT-variation (jitter) considered unstable
_Q_MIN_JITTER_SAMPLES = 8  # ack_rtt samples needed before a jitter number is trusted
                           # (<8 lets a single local-ACK vs real-RTT pair fake huge jitter)
_Q_MIN_DENOM = 20          # need this many data segments to trust a loss %
_Q_MIN_LOSS_EVENTS = 2     # need this many real loss events to flag a flow
_Q_DUPACK_ONLY = 10        # dup-ACKs with ~no real loss = unconfirmed rev-path
_Q_MIN_FLOWS_OK = 3        # emit the healthy verdict only with enough real flows


def _dst_label(f: Flow) -> str:
    port = f.dst_port
    base = _flow_label(f)
    return f"{base}:{port}" if port else base


def _flow_metrics(f: Flow) -> dict:
    """Compute the honest per-flow network-quality metrics."""
    rtt = f.initial_rtt_ms if f.initial_rtt_ms is not None else f.tcp_handshake_ms
    jitter: Optional[float] = None
    if len(f.ack_rtt_samples) >= _Q_MIN_JITTER_SAMPLES:
        jitter = round(statistics.pstdev(f.ack_rtt_samples), 1)
    real_loss = max(f.retransmissions - f.spurious_retransmissions, 0)
    denom = f.data_segments
    loss_pct: Optional[float] = None
    if denom >= _Q_MIN_DENOM and real_loss:
        loss_pct = round(100.0 * real_loss / denom, 2)
    return {
        "rtt": rtt,
        "jitter": jitter,
        "real_loss": real_loss,
        "denom": denom,
        "loss_pct": loss_pct,
        "dup": f.dup_acks,
        "zwin": f.zero_window,
    }


def _verdict(f: Flow, m: dict) -> tuple[str, str]:
    """Return (severity_class, human sentence) for a problem flow.
    severity_class in {"bad","degraded"}."""
    parts: list[str] = []
    is_bad = False

    if m["loss_pct"] is not None:
        if m["loss_pct"] >= _Q_LOSS_BAD:
            is_bad = True
        parts.append(
            f"{m['loss_pct']}% packet loss "
            f"({m['real_loss']} retransmission{'s' if m['real_loss'] != 1 else ''}"
            f"/{m['denom']} data segments)")
    elif m["real_loss"] >= _Q_MIN_LOSS_EVENTS:
        parts.append(f"{m['real_loss']} real retransmissions")

    if m["dup"] >= _Q_DUPACK_ONLY:
        parts.append(f"{m['dup']} duplicate-ACKs (receiver kept re-requesting data)")

    if m["jitter"] is not None and m["jitter"] >= _Q_JITTER_MS:
        parts.append(f"{m['jitter']}ms RTT variation (unstable)")

    if m["zwin"]:
        parts.append(f"{m['zwin']} zero-window stall(s) (receiver could not keep up)")

    if m["rtt"] is not None:
        parts.append(f"RTT {m['rtt']:.0f}ms")

    sev = "bad" if is_bad else "degraded"
    label = "serious network problem" if is_bad else "degraded"
    return sev, f"{_dst_label(f)}: {', '.join(parts)} \u2014 {label} on this destination"


def _network_quality_findings(flows: list[Flow]) -> list[Finding]:
    """Per-destination network-quality verdict: RTT, RTT variation and real
    (spurious-corrected) packet loss, with dup-ACK-only flows flagged separately
    as unconfirmed reverse-path loss."""
    tcp = [
        f for f in flows
        if f.transport == "tcp"
        and not _is_loopback_ip(f.src_ip) and not _is_loopback_ip(f.dst_ip)
    ]
    if not tcp:
        return []

    problem: list[tuple[str, str, Flow, dict]] = []   # (sev, sentence, flow, metrics)
    dupack_only: list[tuple[Flow, dict]] = []
    jitter_only: list[tuple[Flow, dict]] = []
    rtts: list[float] = []

    for f in tcp:
        m = _flow_metrics(f)
        if m["rtt"] is not None:
            rtts.append(float(m["rtt"]))

        # CONFIRMED problem = real packet loss or a receiver stall. Jitter alone
        # is NOT treated as a confirmed problem: ack_rtt spread conflates genuine
        # network jitter with normal delayed-ACK / bursty-application timing, so
        # it is reported separately as a soft, caveated signal instead.
        real_problem = (
            (m["loss_pct"] is not None and m["loss_pct"] >= _Q_LOSS_DEGRADED)
            or (m["loss_pct"] is None and m["real_loss"] >= _Q_MIN_LOSS_EVENTS)
            or bool(m["zwin"])
        )
        if real_problem:
            sev, sentence = _verdict(f, m)
            problem.append((sev, sentence, f, m))
        elif m["real_loss"] == 0 and m["dup"] >= _Q_DUPACK_ONLY:
            dupack_only.append((f, m))
        elif m["jitter"] is not None and m["jitter"] >= _Q_JITTER_MS:
            jitter_only.append((f, m))

    out: list[Finding] = []

    if problem:
        # worst first: bad before degraded, then by loss %, then by loss events
        problem.sort(key=lambda t: (
            0 if t[0] == "bad" else 1,
            -(t[3]["loss_pct"] or 0),
            -t[3]["real_loss"],
            -(t[3]["jitter"] or 0),
        ))
        n_bad = sum(1 for p in problem if p[0] == "bad")
        worst = problem[:6]
        detail = (
            "Per-destination network quality (transport layer, independent of "
            "TLS/SWG policy). Loss is counted as retransmissions minus spurious "
            "retransmissions and corroborated by duplicate-ACKs; RTT is the "
            "SYN\u2192SYN/ACK handshake time. Affected destinations:\n  \u2022 "
            + "\n  \u2022 ".join(s for _, s, _, _ in worst)
        )
        if len(problem) > len(worst):
            detail += f"\n  \u2022 (+{len(problem) - len(worst)} more)"
        sev = "medium" if n_bad else "low"
        title = (
            f"Network quality: {len(problem)} destination(s) show packet loss"
            + (f" ({n_bad} serious)" if n_bad else "")
        )
        out.append(Finding(
            title=title,
            severity=sev,
            category="network",
            detail=detail,
            evidence=[
                f"{_dst_label(f)} loss={m['loss_pct'] if m['loss_pct'] is not None else m['real_loss']}"
                f" retx={f.retransmissions} spurious={f.spurious_retransmissions}"
                f" dup_ack={m['dup']} jitter_ms={m['jitter']} rtt_ms={m['rtt']}"
                f" data_segments={m['denom']}"
                for _, _, f, m in worst
            ],
        ))

    if dupack_only:
        dupack_only.sort(key=lambda t: -t[1]["dup"])
        top = dupack_only[:6]
        out.append(Finding(
            title=(f"Possible reverse-path loss / reordering on "
                   f"{len(dupack_only)} destination(s) \u2014 unconfirmed"),
            severity="info",
            category="network_info",
            detail=(
                "These flows show many duplicate-ACKs but NO retransmissions in "
                "the direction this capture can see. That points to loss or "
                "reordering on the RETURN path (or packets this single capture "
                "point does not observe) \u2014 it cannot be confirmed as loss from "
                "this capture alone. Destinations:\n  \u2022 "
                + "\n  \u2022 ".join(
                    f"{_dst_label(f)}: {m['dup']} duplicate-ACKs"
                    + (f", RTT {m['rtt']:.0f}ms" if m["rtt"] is not None else "")
                    for f, m in top)
            ),
            evidence=[
                f"{_dst_label(f)} dup_ack={m['dup']} retx={f.retransmissions} rtt_ms={m['rtt']}"
                for f, m in top
            ],
        ))

    if jitter_only:
        jitter_only.sort(key=lambda t: -(t[1]["jitter"] or 0))
        top = jitter_only[:6]
        out.append(Finding(
            title=(f"Elevated RTT variation on {len(jitter_only)} destination(s) "
                   f"\u2014 may be network jitter or normal app/ACK timing"),
            severity="info",
            category="network_info",
            detail=(
                "These flows have a wide spread of per-ACK round-trip times "
                "(\u2265" + f"{_Q_JITTER_MS:.0f}ms, from \u2265{_Q_MIN_JITTER_SAMPLES} "
                "samples) but NO packet loss or receiver stalls. High RTT variation "
                "can mean real network jitter/bufferbloat, but it is just as often "
                "normal for bursty or interactive flows (delayed-ACK timing, "
                "application think-time). It is reported as context, NOT as a "
                "confirmed network problem. Destinations:\n  \u2022 "
                + "\n  \u2022 ".join(
                    f"{_dst_label(f)}: {m['jitter']}ms RTT variation"
                    + (f", RTT {m['rtt']:.0f}ms" if m["rtt"] is not None else "")
                    for f, m in top)
            ),
            evidence=[
                f"{_dst_label(f)} jitter_ms={m['jitter']} ack_rtt_samples={len(f.ack_rtt_samples)} rtt_ms={m['rtt']}"
                for f, m in top
            ],
        ))

    # Positive verdict: enough real flows and nothing flagged = network is healthy.
    if not problem and not jitter_only and len([r for r in rtts]) >= _Q_MIN_FLOWS_OK:
        srtt = sorted(rtts)
        med = statistics.median(srtt)
        p90 = srtt[min(len(srtt) - 1, int(len(srtt) * 0.9))]
        out.append(Finding(
            title="Network quality: healthy \u2014 no packet loss or jitter detected",
            severity="info",
            category="network_info",
            detail=(
                f"Across {len(tcp)} TCP flow(s), no destination showed significant "
                f"packet loss (retransmissions minus spurious), jitter or "
                f"receiver stalls. Network RTT (SYN\u2192SYN/ACK) median "
                f"{med:.0f}ms, p90 {p90:.0f}ms. Any slowness is therefore not a "
                f"transport/network-loss problem."
            ),
            evidence=[f"tcp_flows={len(tcp)} rtt_median_ms={med:.0f} rtt_p90_ms={p90:.0f}"],
        ))

    return out
