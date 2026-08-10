"""Network / transport findings: duplicate-capture detection, TCP packet-loss
health, ICMP Path-MTU-Discovery, TCP MSS / effective-MTU analysis (generic and
Secure Access tunnel baseline), and asymmetric-routing / single-armed-capture
detection. All vendor-agnostic transport signals."""
from __future__ import annotations

from collections import Counter
from typing import Optional

from ..engine import Finding
from ..pcap import Flow
from .base import _is_private_ip, _flow_label

# Capture-wide TCP transport health. Per-flow retransmission findings only fire
# at >=3 events on a SINGLE flow, so loss scattered across many short flows stays
# invisible. This aggregates retransmissions / lost segments / out-of-order /
# duplicate-ACKs across ALL flows so the packet-loss story surfaces at a glance,
# independent of TLS/SWG policy.
_NETH_MIN_RETX = 3        # total retransmissions+lost+ooo to bother reporting
_NETH_LOSS_PCT = 0.5      # % of TCP data packets lost/retransmitted = unhealthy


def _detect_duplicate_capture(packets: list) -> Optional[dict]:
    """Detect a capture recorded on 2+ interfaces at once (the same wire mirrored).

    When tshark merges such a file every packet appears twice — once per
    interface — and TCP analysis flags the second copy as a 'retransmission'.
    That inflates loss counts massively even though the network is healthy. We
    fingerprint it by keying every TCP *data* segment on (stream, seq, len) and
    checking how many identical segments show up under 2+ distinct
    ``frame.interface_id`` values. Real retransmissions repeat on the SAME
    interface, so they never trip this.
    """
    iface_counts: Counter = Counter()
    seen: dict[tuple, set] = {}
    for p in packets:
        iid = p.first("frame.interface_id")
        if iid is None:
            continue
        iface_counts[iid] += 1
        stream = p.first("tcp.stream")
        seq = p.first("tcp.seq")
        tlen_s = p.first("tcp.len")
        try:
            tlen = int(tlen_s) if tlen_s is not None else 0
        except (TypeError, ValueError):
            tlen = 0
        if stream is None or seq is None or tlen <= 0:
            continue  # only data segments carry the retransmission flag
        seen.setdefault((stream, seq, tlen), set()).add(iid)

    if len(iface_counts) < 2 or not seen:
        return None
    duped = sum(1 for ifs in seen.values() if len(ifs) >= 2)
    frac = duped / len(seen)
    if frac < 0.25:
        return None
    return {
        "interfaces": len(iface_counts),
        "iface_counts": dict(iface_counts),
        "dup_fraction": frac,
        "duped_segments": duped,
        "unique_segments": len(seen),
    }


def _duplicate_capture_findings(packets: list) -> tuple[list[Finding], bool]:
    """Surface a duplicate / multi-interface capture and signal that the
    retransmission/loss counters cannot be trusted. Returns (findings, is_dup)."""
    info = _detect_duplicate_capture(packets)
    if not info:
        return [], False
    n = info["interfaces"]
    pct = info["dup_fraction"] * 100
    return [Finding(
        title=f"Duplicate capture: the same traffic was recorded on {n} interfaces at once",
        severity="info",
        category="network",
        detail=(
            f"This file contains {n} capture interfaces that recorded the SAME packets simultaneously "
            f"(about {pct:.0f}% of TCP data segments appear on more than one interface). When the file is "
            f"read, every duplicated packet looks like a 'retransmission' to TCP analysis, so retransmission "
            f"and packet-loss counts are heavily inflated and DO NOT reflect real loss — note there are no "
            f"genuine lost segments behind them. To get accurate transport metrics, re-capture on a single "
            f"interface (or open just one interface in Wireshark). The retransmission-based packet-loss "
            f"finding has been suppressed for this capture because it would be misleading."
        ),
        evidence=[f"capture_interfaces={n} duplicated_segments={info['duped_segments']}/"
                  f"{info['unique_segments']} ({pct:.0f}%)"],
    )], True


def _detect_segmentation_offload(flows: list) -> Optional[dict]:
    """Detect a capture taken on the host ABOVE the NIC, where TCP segmentation
    offload (TSO/LSO/GSO) is still pending.

    TCP may never put more bytes in a segment than the peer advertised as its
    MSS, so a "segment" larger than the largest MSS negotiated on that same
    connection cannot have existed on the wire. What was recorded is the
    super-segment the operating system handed to the NIC, which the hardware
    then splits. Comparing each flow against its OWN advertised MSS keeps this
    exact rather than heuristic."""
    tcp = [f for f in flows if getattr(f, "transport", None) == "tcp"
           and getattr(f, "oversized_segments", 0)]
    if not tcp:
        return None
    affected = sum(f.oversized_segments for f in tcp)
    total = sum(getattr(f, "data_segments", 0) for f in flows
                if getattr(f, "transport", None) == "tcp") or affected
    biggest = max(f.max_tcp_len for f in tcp)
    mss = min((min(f.mss_values) for f in tcp if getattr(f, "mss_values", None)), default=1460)
    return {
        "flows": len(tcp),
        "segments": affected,
        "total": total,
        "biggest": biggest,
        "mss": mss,
        "ratio": biggest / mss if mss else 0,
    }


def _segmentation_offload_findings(flows: list) -> tuple[list[Finding], bool]:
    """Report the offload capture point and signal that reordering counters are
    artifacts. Returns (findings, is_offloaded)."""
    info = _detect_segmentation_offload(flows)
    if not info:
        return [], False
    pct = (info["segments"] / info["total"] * 100) if info["total"] else 0
    return [Finding(
        title="Capture taken on the sending host, before NIC segmentation offload",
        severity="info",
        category="network",
        detail=(
            f"{info['segments']} recorded TCP segments ({pct:.0f}% of the data segments) are larger than the "
            f"{info['mss']}-byte MSS negotiated on their own connection — the biggest is {info['biggest']} bytes, "
            f"about {info['ratio']:.0f}x the MSS. A segment that size cannot exist on the wire, so this file was "
            f"captured on the sending host above the network card, with TCP segmentation offload (TSO/LSO/GSO) "
            f"still pending: the card had yet to split these into real packets. "
            f"Consequences for reading this capture: packet counts and packet sizes are NOT what the network "
            f"carried, and the out-of-order / overlapping-segment events the TCP dissector reports are "
            f"reassembly artifacts of those super-segments rather than real network reordering — the "
            f"out-of-order-only packet-loss finding has been suppressed for that reason. Byte counts, RTT, "
            f"the TLS handshake and genuine loss signals (lost segments, zero window) remain valid. "
            f"To measure real on-wire behaviour, capture on a switch SPAN/TAP, or disable offload on the "
            f"host first."
        ),
        evidence=[f"oversized_segments={info['segments']}/{info['total']} "
                  f"max_tcp_len={info['biggest']} negotiated_mss={info['mss']} "
                  f"flows_affected={info['flows']}"],
    )], True


def _suppress_offload_reordering_findings(flow_reports: list) -> None:
    """On an offloaded (host-side) capture, drop the per-flow 'TCP packet loss /
    retransmissions' findings whose only evidence is out-of-order events. Those
    come from reassembling the super-segments, not from the network. Flows with
    real retransmissions, lost segments or zero windows keep their findings."""
    for rep in flow_reports:
        f = rep.flow
        if not getattr(f, "oversized_segments", 0):
            continue
        if (getattr(f, "retransmissions", 0) or getattr(f, "lost_segments", 0)
                or getattr(f, "zero_window", 0)):
            continue  # a real loss signal — keep it
        rep.findings = [
            fd for fd in rep.findings
            if not (fd.category == "network"
                    and fd.title.startswith("TCP packet loss / retransmissions"))
        ]


def _suppress_dup_retransmission_findings(flow_reports: list) -> None:
    """In a duplicate / multi-interface capture, drop the per-flow
    'TCP packet loss / retransmissions' findings whose loss is purely
    retransmissions / out-of-order (no real lost segments, no zero windows).
    Those are mirrored-packet artifacts; keeping them would flood the report and
    mislabel a healthy network as lossy. Genuine signals (lost segments, zero
    windows) are preserved."""
    for rep in flow_reports:
        f = rep.flow
        if getattr(f, "lost_segments", 0) or getattr(f, "zero_window", 0):
            continue  # has a real loss signal — keep its findings
        rep.findings = [
            fd for fd in rep.findings
            if not (fd.category == "network"
                    and fd.title.startswith("TCP packet loss / retransmissions"))
        ]


def _icmp_pmtud_findings(packets: list) -> list[Finding]:
    """Surface Path MTU Discovery activity that is literally in the capture.

    A router/tunnel that cannot forward a too-large DF-set datagram returns an
    ICMP "fragmentation needed" error carrying the next-hop MTU (RFC 1191:
    IPv4 Type 3 Code 4, low-order 16 bits of the previously-unused ICMP header
    field; RFC 8201/4443: ICMPv6 Type 2 "Packet Too Big"). Seeing these proves
    PMTUD is working and tells us the effective MTU on the path — typically
    reduced below 1500 by Secure Access tunnel encapsulation overhead.

    Reports only observed messages (sources, destinations, MTU values). Does NOT
    infer a blackhole from the absence of ICMP — that is not provable here."""
    events: list[dict] = []
    for pkt in packets:
        is_v4 = pkt.first("icmp.type") == "3" and pkt.first("icmp.code") == "4"
        is_v6 = pkt.first("icmpv6.type") == "2"
        if not (is_v4 or is_v6):
            continue
        mtu_raw = pkt.first("icmp.mtu") if is_v4 else pkt.first("icmpv6.mtu")
        try:
            mtu = int(mtu_raw) if mtu_raw not in (None, "") else 0
        except (ValueError, TypeError):
            mtu = 0
        if is_v4:
            src = pkt.first("ip.src")
            dests = pkt.all("ip.dst")
        else:
            src = pkt.first("ipv6.src")
            dests = pkt.all("ipv6.dst")
        # Outer ip.dst[0] = the client receiving the error; the embedded original
        # datagram adds a 2nd ip.dst = the destination that exceeded the MTU.
        dest = dests[-1] if len(dests) > 1 else None
        events.append({"src": src, "dest": dest, "mtu": mtu, "v6": is_v6})

    if not events:
        return []

    routers = sorted({e["src"] for e in events if e["src"]})
    targets = sorted({e["dest"] for e in events if e["dest"]})
    mtus = sorted({e["mtu"] for e in events if e["mtu"]})
    old_style = any(e["mtu"] == 0 for e in events)
    eff_mtu = min(mtus) if mtus else 0

    router_s = ", ".join(routers[:5]) + (" ..." if len(routers) > 5 else "")
    target_s = ", ".join(targets[:6]) + (" ..." if len(targets) > 6 else "")

    if eff_mtu:
        mss = eff_mtu - 40  # IPv4 + TCP headers (RFC 879); IPv6 would be -60
        gap = 1500 - eff_mtu
        title = (f"Path MTU Discovery active: ICMP 'fragmentation needed' lowering the path MTU "
                 f"to {eff_mtu} bytes")
        mtu_range = f" (range {mtus[0]}-{mtus[-1]})" if len(mtus) > 1 else ""
        mtu_phrase = (f"The next-hop MTU advertised in the ICMP error is {eff_mtu} bytes{mtu_range}, "
                      f"i.e. about {gap} bytes below standard Ethernet (1500). That gap is the "
                      f"encapsulation/overhead of the smallest-MTU hop on the path - this can be any "
                      f"router beyond the ISP, a PPPoE/DSL or carrier link, MPLS, or a tunnel (VPN / "
                      f"Secure Access / SIG); the ICMP does not say which. A sender honouring it should "
                      f"cap TCP MSS at ~{mss} bytes. PMTUD is WORKING here - the path is correctly "
                      f"signalling the size to use, not silently dropping the packets.")
    else:
        title = ("Path MTU Discovery: ICMP 'fragmentation needed' messages seen (next-hop MTU "
                 "not reported)")
        mtu_phrase = ("The ICMP errors do not carry a next-hop MTU value (field = 0), which RFC 1191 "
                      "defines as an unmodified/old-style router; the sender must fall back to a "
                      "conservative MTU for those paths.")

    kind = ("Type 2 'Packet Too Big' (ICMPv6)" if all(e["v6"] for e in events)
            else "Type 3 Code 4 'Destination Unreachable - Fragmentation Needed (DF set)'")
    refs_to = f"They reference traffic to: {target_s}. " if target_s else ""
    old_note = " Some messages were old-style (next-hop MTU = 0)." if old_style and eff_mtu else ""
    detail = (
        f"{len(events)} ICMP {kind} message(s) were captured, sent by {router_s or 'a gateway'} to "
        f"the client. {refs_to}{mtu_phrase}{old_note} Reference: RFC 1191 (Path MTU Discovery), "
        f"RFC 792 (ICMP)."
    )
    mtu_ev = "/".join(str(m) for m in mtus) if mtus else "0"
    evidence = [
        f"icmp_pmtud_messages={len(events)} routers={len(routers)} next_hop_mtu={mtu_ev}"
    ]
    if targets:
        evidence.append("affected_destinations=" + ", ".join(targets[:10]))
    return [Finding(
        title=title,
        severity="info",
        category="network",
        detail=detail,
        evidence=evidence,
    )]


def _client_syn_mss(packets: list):
    """Find the local client's advertised TCP MSS from its initiator SYNs.

    Returns (client_ip, dominant_mss, sorted_distinct_mss, n_destinations) or
    None. The client = the private source IP that opened the most connections;
    the MSS is read from the SYN option (syn=1, ack=0), so it is measured, not
    inferred."""
    by_src: dict[str, list[int]] = {}
    dest_set: dict[str, set] = {}
    for pkt in packets:
        if pkt.first("tcp.flags.syn") not in ("1", "True"):
            continue
        if pkt.first("tcp.flags.ack") in ("1", "True"):
            continue  # SYN-ACK = responder, not the local client
        mss_raw = pkt.first("tcp.options.mss_val")
        if mss_raw in (None, ""):
            continue
        try:
            mss = int(mss_raw)
        except (ValueError, TypeError):
            continue
        src = pkt.first("ip.src") or pkt.first("ipv6.src")
        dst = pkt.first("ip.dst") or pkt.first("ipv6.dst")
        if not src:
            continue
        by_src.setdefault(src, []).append(mss)
        if dst:
            dest_set.setdefault(src, set()).add(dst)

    if not by_src:
        return None
    client = max(
        by_src,
        key=lambda s: (1 if _is_private_ip(s) else 0, len(by_src[s])),
    )
    mss_list = by_src[client]
    if not _is_private_ip(client) or not mss_list:
        return None
    distinct = sorted(set(mss_list))
    dominant = max(distinct, key=lambda m: mss_list.count(m))
    n_dests = len(dest_set.get(client, set()))
    return client, dominant, distinct, n_dests


def _mss_clamp_findings(packets: list) -> list[Finding]:
    """Detect a reduced TCP MSS on the local client's outbound SYNs.

    Standard Ethernet (MTU 1500) yields MSS 1460 (RFC 879: MSS = MTU - 40). When
    the local host advertises a uniformly lower MSS to every destination, the
    effective MTU somewhere on the path is below 1500. The cause can be ANY
    reduced-MTU hop - a router beyond the ISP, a PPPoE/DSL or carrier link, MPLS,
    or a tunnel (VPN / Secure Access / SIG) - applied either by the client's own
    interface MTU or by MSS clamping on the TCP SYN (the fallback used when ICMP
    PMTUD is blocked). MSS is read straight from the SYN option, so this is
    measured, not inferred; the mechanism/location is NOT distinguishable from a
    single capture point."""
    STD_MSS = 1460          # MTU 1500 - 20 IP - 20 TCP
    CLAMP_MAX = 1400        # >= 60 bytes below standard = clearly reduced
    info = _client_syn_mss(packets)
    if not info:
        return []
    client, dominant, distinct, n_dests = info

    # Only report when the client's advertised MSS is clearly below standard and
    # was used toward several destinations (a single odd server is not signal).
    if dominant > CLAMP_MAX or n_dests < 2:
        return []

    eff_mtu = dominant + 40
    gap_mss = STD_MSS - dominant
    spread = f" (values {distinct[0]}-{distinct[-1]})" if len(distinct) > 1 else ""
    detail = (
        f"The local client {client} advertised a TCP MSS of {dominant} bytes{spread} on its SYN to "
        f"{n_dests} destination(s), instead of the standard {STD_MSS} for a 1500-byte Ethernet link. "
        f"By RFC 879 (MSS = MTU - 40) that means an effective send MTU of about {eff_mtu} bytes, "
        f"~{gap_mss} bytes below normal. This proves a reduced MTU somewhere on the path - the cause "
        f"can be ANY lower-MTU hop (a router beyond the ISP, a PPPoE/DSL or carrier link, MPLS) or a "
        f"tunnel (VPN / Secure Access / SIG), applied either by the client's own interface MTU or by "
        f"MSS clamping on the handshake (the fallback when ICMP PMTUD is blocked, RFC 1191). Which one, "
        f"and where, is NOT distinguishable from a single capture point. This is normal and PREVENTS "
        f"fragmentation; it is not packet loss. Reference: RFC 879 / RFC 6691 (TCP MSS)."
    )
    return [Finding(
        title=(f"Reduced TCP MSS ({dominant}) on the client: effective path MTU ~{eff_mtu} bytes "
               f"(reduced-MTU hop on the path)"),
        severity="info",
        category="network",
        detail=detail,
        evidence=[
            f"client={client} advertised_mss={dominant} effective_mtu={eff_mtu} "
            f"standard_mss={STD_MSS} destinations={n_dests} "
            f"distinct_mss={','.join(str(m) for m in distinct)}"
        ],
    )]


def _sa_tunnel_mtu_findings(packets: list) -> list[Finding]:
    """Cisco Secure Access tunnel MTU check (opt-in: user confirmed the capture
    is through a Secure Access tunnel).

    The Secure Access IPsec tunnel baseline is MTU 1390 / TCP MSS 1350: the ~110
    bytes below a 1500 link is the ESP + NAT-T overhead (outer IP, UDP/NAT-T, ESP
    header, IV, padding, trailer and the authentication ICV). We compare the
    client's advertised MSS to that baseline. TCP always adapts via the SYN MSS,
    so the real risk is UDP - which does NOT negotiate a segment size - once the
    effective MTU drops below the tunnel baseline."""
    SA_MTU = 1390
    SA_MSS = 1350
    info = _client_syn_mss(packets)
    if not info:
        return []
    client, dominant, distinct, n_dests = info
    eff_mtu = dominant + 40
    spread = f" (values {distinct[0]}-{distinct[-1]})" if len(distinct) > 1 else ""

    if dominant >= SA_MSS:
        if dominant == SA_MSS:
            severity = "info"
            title = (f"Secure Access tunnel MTU confirmed: client MSS {dominant} "
                     f"(effective MTU ~{eff_mtu}) matches the 1390/1350 baseline")
            detail = (
                f"The client {client} advertised MSS {dominant}{spread} to {n_dests} destination(s) - "
                f"exactly the Cisco Secure Access tunnel baseline (MTU {SA_MTU} / MSS {SA_MSS}). That "
                f"1390 leaves room for the IPsec/ESP + NAT-T overhead (~110 bytes below a 1500 link). "
                f"TCP is sized correctly for the tunnel and will not fragment. This is the healthy, "
                f"expected value.")
        else:
            severity = "info"
            title = (f"Client MSS {dominant} is ABOVE the Secure Access tunnel baseline "
                     f"(expected MSS {SA_MSS} / MTU {SA_MTU})")
            detail = (
                f"The client {client} advertised MSS {dominant}{spread} (effective MTU ~{eff_mtu}), "
                f"higher than the {SA_MSS} typical of a Secure Access IPsec tunnel. Either these flows "
                f"are NOT traversing the tunnel (direct / bypass), or MSS clamping to the tunnel MTU is "
                f"not being applied on this path - in which case large TCP segments could need "
                f"fragmentation once inside the tunnel. Worth confirming the steering / clamp config.")
    else:
        below_udp = eff_mtu < 1280   # IPv6 floor (RFC 8200) / QUIC comfort zone
        severity = "medium" if below_udp else "info"
        title = (f"Client MSS {dominant} is BELOW the Secure Access tunnel baseline "
                 f"(expected MSS {SA_MSS} / MTU {SA_MTU}); effective MTU ~{eff_mtu}")
        detail = (
            f"The client {client} advertised MSS {dominant}{spread} to {n_dests} destination(s) -> "
            f"effective MTU ~{eff_mtu} bytes, LOWER than the {SA_MSS}/{SA_MTU} Secure Access tunnel "
            f"baseline. TCP still adapts via the SYN MSS, but a path MTU this low usually means EXTRA "
            f"overhead stacked on top of the tunnel (a second VPN / tunnel-in-tunnel) or aggressive "
            f"clamping. UDP is where this bites, because UDP does not negotiate a segment size:\n"
            f"- QUIC / HTTP-3 requires the path to carry >=1200-byte UDP payloads (RFC 9000) and never "
            f"IP-fragments; below roughly a 1228-byte MTU the QUIC handshake can fail or fall back to TCP.\n"
            f"- Large DNS-over-UDP responses (EDNS0 / DNSSEC, RFC 6891) fragment and are frequently "
            f"dropped by firewalls, causing resolution failures or forced TCP retries.\n"
            f"- IPv6 has a hard minimum MTU of 1280 (RFC 8200); below that, IPv6 breaks entirely."
            + (f"\nHere the effective MTU ~{eff_mtu} is at/under the 1280 IPv6 floor and QUIC comfort "
               f"zone, so UDP-based apps (QUIC, DNS, media) are at real risk of failing or stalling."
               if below_udp else ""))

    return [Finding(
        title=title,
        severity=severity,
        category="network",
        detail=detail,
        evidence=[
            f"client={client} advertised_mss={dominant} effective_mtu={eff_mtu} "
            f"sa_baseline_mss={SA_MSS} sa_baseline_mtu={SA_MTU} destinations={n_dests} "
            f"distinct_mss={','.join(str(m) for m in distinct)}"
        ],
    )]


def _network_health_findings(flows: list[Flow], duplicate_capture: bool = False,
                             offloaded_capture: bool = False) -> list[Finding]:
    tcp = [f for f in flows if f.transport == "tcp"]
    if not tcp:
        return []
    retx = sum(f.retransmissions for f in tcp)
    lost = sum(f.lost_segments for f in tcp)
    ooo = sum(f.out_of_order for f in tcp)
    dup = sum(f.dup_acks for f in tcp)
    zwin = sum(f.zero_window for f in tcp)
    loss_events = retx + lost + ooo

    # In a duplicate / multi-interface capture, retransmissions and out-of-order
    # are artifacts of the same packet being seen twice. If there is no genuine
    # loss signal behind them (no lost segments, no zero windows), suppress the
    # finding entirely — the dedicated duplicate-capture finding explains it.
    if duplicate_capture and lost == 0 and zwin == 0:
        return []

    # Same reasoning for a host-side capture with segmentation offload: the
    # out-of-order events are super-segment reassembly artifacts. With no real
    # loss behind them there is nothing to report, and the offload finding
    # already explains the capture point.
    if offloaded_capture and retx == 0 and lost == 0 and zwin == 0:
        return []

    if loss_events < _NETH_MIN_RETX and not zwin:
        return []

    affected = [f for f in tcp if (f.retransmissions + f.lost_segments + f.out_of_order)]
    affected.sort(key=lambda f: -(f.retransmissions + f.lost_segments + f.out_of_order))
    worst = "; ".join(
        f"{_flow_label(f)} ("
        + ", ".join(p for p in [
            f"{f.retransmissions} retx" if f.retransmissions else "",
            f"{f.lost_segments} lost" if f.lost_segments else "",
            f"{f.out_of_order} ooo" if f.out_of_order else "",
        ] if p)
        + ")"
        for f in affected[:5]
    )

    parts = []
    if retx:
        parts.append(f"{retx} retransmission{'s' if retx != 1 else ''}")
    if lost:
        parts.append(f"{lost} lost segment{'s' if lost != 1 else ''}")
    if ooo:
        parts.append(f"{ooo} out-of-order packet{'s' if ooo != 1 else ''}")
    if dup:
        parts.append(f"{dup} duplicate-ACK{'s' if dup != 1 else ''}")
    if zwin:
        parts.append(f"{zwin} zero-window event{'s' if zwin != 1 else ''}")
    breakdown = ", ".join(parts)

    sev = "medium" if loss_events >= 5 or zwin else "low"
    caveat = (" NOTE: this is a duplicate / multi-interface capture, so the retransmission and "
              "out-of-order counts are inflated by mirrored packets — only the lost-segment and "
              "zero-window figures here are reliable." if duplicate_capture else "")
    if duplicate_capture:
        sev = "low"
    if offloaded_capture:
        caveat += (" NOTE: this capture was taken on the host before segmentation offload, so the "
                   "out-of-order count reflects super-segment reassembly, not network reordering.")
        sev = "low"
    return [Finding(
        title=f"TCP packet loss across {len(affected)} flow(s): {loss_events} loss event{'s' if loss_events != 1 else ''}",
        severity=sev,
        category="network",
        detail=(f"Across the whole capture: {breakdown}. Retransmissions, lost segments and out-of-order "
                f"packets indicate packet loss on the network path (congestion, a lossy link, or an MTU "
                f"blackhole) — a transport problem, not a TLS/SWG decryption issue. "
                f"Most affected: {worst}.{caveat}" if worst else
                f"Across the whole capture: {breakdown}. These indicate packet loss on the network path "
                f"(congestion or a lossy link) — a transport problem, not a TLS/SWG decryption issue.{caveat}"),
        evidence=[f"total retransmissions={retx} lost_segments={lost} out_of_order={ooo} "
                  f"duplicate_acks={dup} zero_window={zwin} flows_affected={len(affected)}"],
    )]


# Asymmetric routing / single-armed capture detection. We ONLY assert this when
# there is hard, capture-based proof — not from retransmissions alone (those are
# ordinary packet loss). The two honest symptoms a single capture can show:
#   1. ACKed-but-unseen segments (tcp.analysis.ack_lost_segment): the capture
#      witnesses an ACK for data it never saw transmitted, so that direction took
#      a path the capture point does not observe. This is the textbook proof.
#   2. A fully one-way established conversation: a TCP flow with a real handshake
#      attempt but packets in only ONE direction (reported separately, lower
#      confidence — it can also be a silent/dead peer).
_ASYM_MIN_ONEWAY_PKTS = 4    # ignore lone SYN probes / scan noise


def _asymmetric_routing_findings(flows: list[Flow]) -> list[Finding]:
    tcp = [f for f in flows if f.transport == "tcp"]
    if not tcp:
        return []
    out: list[Finding] = []

    # --- Proof 1: ACKs for segments the capture never saw -------------------
    proof = [f for f in tcp if f.ack_lost_segment > 0]
    if proof:
        proof.sort(key=lambda f: -f.ack_lost_segment)
        total = sum(f.ack_lost_segment for f in proof)
        worst = "; ".join(f"{_flow_label(f)} ({f.ack_lost_segment} ACKed-unseen)" for f in proof[:5])
        out.append(Finding(
            title=f"Asymmetric routing confirmed: {total} ACK(s) for never-captured data across {len(proof)} flow(s)",
            severity="medium",
            category="asymmetric_routing",
            detail=(
                f"On {len(proof)} flow(s) the capture saw a TCP acknowledgement for data it never "
                f"witnessed being sent ({total} 'ACKed segment that wasn't captured' event(s)). The "
                f"only way to ACK data you never saw is if that data physically travelled on a path "
                f"this capture point does not observe — i.e. the two directions of the connection take "
                f"different routes (asymmetric routing), or the capture is taken on a single arm / one "
                f"leg of a SPAN. This is direct proof, not an inference. Practical effect: any "
                f"'retransmission'/'lost segment' counts on these flows are partly an artefact of the "
                f"missing direction, NOT necessarily real network loss. Most affected: {worst}."
            ),
            evidence=[f"ack_lost_segment_total={total} flows={len(proof)}"],
        ))

    # --- Proof 2: one-way established conversations -------------------------
    oneway = [
        f for f in tcp
        if f.syn_count and ((f.pkts_c2s >= _ASYM_MIN_ONEWAY_PKTS and f.pkts_s2c == 0)
                            or (f.pkts_s2c >= _ASYM_MIN_ONEWAY_PKTS and f.pkts_c2s == 0))
    ]
    if oneway:
        _c2s = "client\u2192server only"
        _s2c = "server\u2192client only"
        worst = "; ".join(
            f"{_flow_label(f)} ({_c2s if f.pkts_s2c == 0 else _s2c}, "
            f"{max(f.pkts_c2s, f.pkts_s2c)} pkts)"
            for f in oneway[:5]
        )
        out.append(Finding(
            title=f"One-way traffic on {len(oneway)} flow(s): only a single direction captured",
            severity="low",
            category="asymmetric_routing",
            detail=(
                f"{len(oneway)} TCP flow(s) began a handshake but the capture only ever recorded "
                f"packets in ONE direction. That is consistent with asymmetric routing or a "
                f"single-armed capture (the return path isn't on this capture point) — though it can "
                f"also mean the peer was silent/unreachable. Treat as a strong hint to verify the "
                f"capture vantage point and the return route, not as proof on its own. Affected: {worst}."
            ),
            evidence=[f"oneway_flows={len(oneway)}"],
        ))
    return out
