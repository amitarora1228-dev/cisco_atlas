"""Tunnelled connections whose behaviour is wrong but whose cause is encrypted.

A CONNECT tunnel carrying TLS 1.3 is opaque by design: the status code, the
error and the payload are all inside. When such a tunnel misbehaves the honest
options are to stay silent or to guess, and both are bad - silence tells the
reader there is nothing wrong, and a guess sends them after a cause the capture
cannot support.

This module takes a third option. It reports the *pattern*, states plainly what
cannot be determined and why, lists what the capture did rule out, and gives the
specific steps that would settle it. It never names a root cause.
"""
from __future__ import annotations

from collections import defaultdict

from ..engine import Finding
from ..pcap import Flow
from .base import _flow_label

# All four conditions must hold together. Each one alone is ordinary: a short
# tunnel may be a completed request, a low return ratio may be an upload, an
# unclosed tunnel may simply outlive the capture, and several connections to one
# service is how browsers work. Together they describe a client that keeps
# asking, keeps being answered with very little, and keeps walking away.
_MIN_ATTEMPTS = 3          # connections to the same service
_WINDOW_S = 10.0           # within this span
_MAX_RETURN_RATIO = 1.0    # bytes back / bytes sent
_MAX_HELD_S = 5.0          # abandoned this quickly


def _service_of(flow: Flow) -> str | None:
    """The service a tunnel was opened for, with CDN node numbering removed.

    rr1---sn-2oaig5-5f.googlevideo.com and rr5---sn-aigl6nsr.googlevideo.com are
    two nodes of one service; counting them separately would hide the retrying.
    """
    target = (flow.connect_target or "").rsplit(":", 1)[0]
    if not target:
        return None
    parts = target.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else target


def _bytes_each_way(flow: Flow) -> tuple[int, int]:
    """Payload sent and received, with duplicated frames counted once.

    A multi-interface capture records the same packet twice; without this the
    ratio would be right by luck rather than by measurement.
    """
    seen: set = set()
    sent = received = 0
    for pkt in flow.packets:
        sig = (pkt.first("tcp.seq"), pkt.first("tcp.ack"),
               pkt.first("tcp.len"), pkt.first("ip.src"))
        if sig in seen:
            continue
        seen.add(sig)
        length = int(pkt.first("tcp.len") or 0)
        if pkt.first("ip.src") == flow.src_ip:
            sent += length
        else:
            received += length
    return sent, received


def _opaque_tunnel_attempts(flows: list[Flow]) -> dict[str, list[dict]]:
    """Established tunnels that returned little and were abandoned unclosed."""
    attempts: dict[str, list[dict]] = defaultdict(list)
    for flow in flows:
        if not flow.is_connect_tunnel or not flow.packets:
            continue
        if not str(flow.connect_status or "").startswith("2"):
            continue          # the tunnel never opened; a different problem
        if flow.fin_count or flow.rst_count:
            continue          # closed properly, so it was not abandoned
        held = flow.packets[-1].time_relative - flow.packets[0].time_relative
        if held > _MAX_HELD_S:
            continue
        sent, received = _bytes_each_way(flow)
        if not sent or received / sent > _MAX_RETURN_RATIO:
            continue
        service = _service_of(flow)
        if not service:
            continue
        attempts[service].append({
            "flow": flow, "sent": sent, "received": received, "held": held,
            "start": flow.packets[0].time_relative,
            "node": _flow_label(flow),
        })
    return attempts


def _capture_ruled_out(flows: list[Flow], unreliable_loss: bool) -> list[str]:
    """What this capture positively measured and found healthy.

    Naming these is half the value of the finding: it stops the reader spending
    a day on the network when the network was measured and was fine. Each entry
    is only emitted when it was actually measured - on a duplicated capture the
    loss counters are inflated, so the loss claim is withheld and said to be
    withheld rather than quietly reported as a number that is wrong.
    """
    notes: list[str] = []

    rtts = [s for f in flows for s in f.ack_rtt_samples]
    if len(rtts) >= 20:
        rtts.sort()
        notes.append(f"round trip to the peer was {rtts[len(rtts) // 2]:.0f} ms "
                     f"at the median over {len(rtts)} samples")

    if unreliable_loss:
        notes.append("packet-loss counters were not trusted here because the same "
                     "traffic was recorded more than once, so loss is neither "
                     "claimed nor excluded")
    else:
        tcp = [f for f in flows if f.transport == "tcp"]
        segments = sum(f.data_segments for f in tcp)
        lost = sum(max(f.retransmissions - f.spurious_retransmissions, 0) for f in tcp)
        if segments >= 200:
            notes.append(f"real packet loss was {100 * lost / segments:.2f}% "
                         f"over {segments:,} data segments")

    if not any(f.client_mss and f.client_mss < 1460 for f in flows):
        notes.append("no reduced-MTU signalling was seen")

    return notes


def _opaque_tunnel_findings(flows: list[Flow], quality_notes: list[str],
                            flow_reports: list | None = None) -> list[Finding]:
    """Report the pattern, the blind spot, and how to remove the blind spot.

    ``quality_notes`` are the things this capture positively ruled out (loss,
    latency, MTU). Naming them is half the value: it stops the reader spending a
    day on the network when the network was measured and is fine.

    ``flow_reports`` lets each participating connection be marked as a problem
    in its own right. Without that the capture-level finding exists but every
    flow still looks healthy, so an "errors only" view shows nothing - which is
    exactly the silence this finding was written to break.
    """
    findings: list[Finding] = []
    reports_by_key = {r.flow.key: r for r in (flow_reports or [])}

    for service, attempts in _opaque_tunnel_attempts(flows).items():
        if len(attempts) < _MIN_ATTEMPTS:
            continue
        attempts.sort(key=lambda a: a["start"])
        span = attempts[-1]["start"] - attempts[0]["start"]
        if span > _WINDOW_S:
            continue

        sent = sum(a["sent"] for a in attempts)
        received = sum(a["received"] for a in attempts)
        nodes = sorted({a["node"] for a in attempts})
        timeline = "  ".join(
            f"{a['start']:.2f}s +{a['held']:.2f}s" for a in attempts[:6])

        ruled_out = (" The capture did rule things out: " + "; ".join(quality_notes) + "."
                     if quality_notes else "")

        findings.append(Finding(
            title=f"Tunnelled connections to {service} behaved abnormally "
                  f"- cause is encrypted",
            severity="high",
            category="tunnel",
            detail=(
                f"{len(attempts)} tunnels to {service} were opened across "
                f"{len(nodes)} endpoint(s) within {span:.1f} s. Every one was "
                f"established (CONNECT 2xx), every one was abandoned within "
                f"{max(a['held'] for a in attempts):.1f} s without being closed, "
                f"and together they returned {received:,} bytes for "
                f"{sent:,} bytes sent. A client that keeps re-opening connections "
                f"and walking away from each one is not receiving what it asked "
                f"for.{ruled_out} "
                f"WHY NO CAUSE IS NAMED: the payload is TLS inside a CONNECT "
                f"tunnel, so the status code, the error and the content are all "
                f"encrypted and no key log was supplied. Rejection by the "
                f"destination, throttling by the intermediary, and the client "
                f"choosing to switch endpoints all look identical from here, and "
                f"this capture cannot separate them. "
                f"TO SETTLE IT: (1) re-capture with SSLKEYLOGFILE set and upload "
                f"the key log with the capture - the real status code becomes "
                f"readable; (2) repeat with this destination bypassed at the "
                f"intermediary, which tells you whether it sits in the path of "
                f"the fault; (3) capture for at least 60 s, since a short capture "
                f"cannot show a transfer failing to sustain."
            ),
            evidence=[
                f"attempts={len(attempts)} endpoints={len(nodes)} span={span:.1f}s "
                f"sent={sent} received={received} return_ratio={received / max(sent, 1):.2f}",
                f"timeline (start +held): {timeline}",
                f"endpoints: {', '.join(nodes[:4])}",
            ],
            flow_key=attempts[0]["flow"].key,
        ))

        # Mark every connection in the pattern, not just the first, so each one
        # is findable on its own and the error column says something true.
        for attempt in attempts:
            report = reports_by_key.get(attempt["flow"].key)
            if report is None:
                continue
            report.findings.append(Finding(
                title="Tunnel opened, then abandoned with almost nothing returned",
                severity="high",
                category="tunnel",
                detail=(
                    f"The tunnel to {attempt['node']} was established, returned "
                    f"{attempt['received']:,} bytes for {attempt['sent']:,} sent, "
                    f"and was dropped after {attempt['held']:.2f} s without being "
                    f"closed. It is one of {len(attempts)} such attempts to "
                    f"{service}; the capture-level finding for {service} explains "
                    f"what was ruled out and how to establish the cause, which is "
                    f"encrypted and cannot be read from this capture."
                ),
                evidence=[f"sent={attempt['sent']} received={attempt['received']} "
                          f"held={attempt['held']:.2f}s connect_status="
                          f"{attempt['flow'].connect_status} fin=0 rst=0"],
                flow_key=attempt["flow"].key,
            ))

    return findings
