"""Validate the interpreting detections, not the counters.

A counter can be checked against tshark directly. A judgement - "this capture is
duplicated", "this handshake never completed", "this is QUIC" - has to be
checked against ground truth worked out independently, because the whole risk is
that the judgement is confidently wrong.
"""
from __future__ import annotations

import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "capture_inspector"))

from capture_inspector.engine import enrich_flow  # noqa: E402
from capture_inspector.findings.network import (  # noqa: E402
    _detect_duplicate_capture,
    _detect_segmentation_offload,
)
from capture_inspector.pcap import build_flows, find_tshark, run_tshark  # noqa: E402

TSHARK = find_tshark()
VERDICTS: list[tuple[str, bool, str]] = []


def verdict(name: str, ok: bool, detail: str) -> None:
    VERDICTS.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<46} {detail}")


def ground_truth_duplicate(packets) -> tuple[bool, str]:
    """Is the same TCP segment present on more than one interface?

    Worked out from the packets, not from the engine: a segment is identified by
    (stream, seq, len) and a genuine retransmission repeats on the SAME
    interface, so only cross-interface repeats count as duplication.
    """
    per_iface: dict[tuple, set] = defaultdict(set)
    seen_anywhere: dict[tuple, set] = defaultdict(set)
    for pkt in packets:
        stream, seq, ln = (pkt.first("tcp.stream"), pkt.first("tcp.seq"),
                           pkt.first("tcp.len"))
        iface = pkt.first("frame.interface_id")
        if stream is None or seq is None or (ln or "0") == "0":
            continue
        key = (stream, seq, ln)
        per_iface[(iface, *key)].add(pkt.number)
        seen_anywhere[key].add(iface)
    duped = sum(1 for ifs in seen_anywhere.values() if len(ifs) > 1)
    total = len(seen_anywhere) or 1
    return duped / total > 0.5, f"{duped}/{total} data segments on >1 interface"


def tcp_stream(flow) -> str | None:
    """The tcp.stream a flow belongs to.

    Keys look like ``tcp-14`` and ``udp-14``; splitting on the dash alone maps a
    UDP flow onto a TCP stream of the same number, which is how this harness
    first reported 625 reversed flows that were not reversed at all.
    """
    return flow.key[4:] if flow.key.startswith("tcp-") else None


def main(capture: str) -> None:
    print(f"\n{'=' * 88}\n{capture}\n{'=' * 88}")
    packets = run_tshark(capture, TSHARK)
    flows = build_flows(packets)
    for flow in flows:
        enrich_flow(flow)

    # --- 1. duplicate / multi-interface capture ---------------------------
    truth_dup, dup_detail = ground_truth_duplicate(packets)
    info = _detect_duplicate_capture(packets)
    engine_dup = bool(info)
    verdict("duplicate-capture detection", engine_dup == truth_dup,
            f"engine={engine_dup} truth={truth_dup} ({dup_detail})")

    # --- 2. segmentation offload ------------------------------------------
    # Ground truth: a segment larger than the MSS the peer agreed to was never a
    # wire frame.
    over = 0
    for flow in flows:
        if flow.mss_values and flow.max_tcp_len > min(flow.mss_values):
            over += 1
    off = _detect_segmentation_offload(flows)
    verdict("segmentation-offload detection", bool(off) == (over > 0),
            f"engine={bool(off)} flows_with_oversized={over}")

    # --- 3. TLS handshake state -------------------------------------------
    # Ground truth from tshark: which streams carry a ServerHello.
    out = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-Y", "tls.handshake.type == 2",
         "-T", "fields", "-e", "tcp.stream"],
        capture_output=True, text=True, check=False)
    streams_with_sh = {s.strip() for s in out.stdout.split() if s.strip()}
    engine_sh = {tcp_stream(f) for f in flows if f.server_hello and tcp_stream(f)}
    verdict("ServerHello attribution", engine_sh == streams_with_sh,
            f"engine={len(engine_sh)} tshark={len(streams_with_sh)} "
            f"missing={len(streams_with_sh - engine_sh)} extra={len(engine_sh - streams_with_sh)}")

    incomplete = [f for f in flows if f.client_hello and not f.server_hello and tcp_stream(f)]
    truth_incomplete = {tcp_stream(f) for f in flows
                        if f.client_hello and tcp_stream(f)} - streams_with_sh
    verdict("incomplete-handshake detection",
            len(incomplete) == len(truth_incomplete),
            f"engine={len(incomplete)} truth={len(truth_incomplete)}")

    # --- 4. QUIC ----------------------------------------------------------
    quic_frames = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-Y", "quic", "-T", "fields", "-e", "udp.stream"],
        capture_output=True, text=True, check=False)
    truth_quic = {s.strip() for s in quic_frames.stdout.split() if s.strip()}
    engine_quic = sum(1 for f in flows if f.is_quic)
    verdict("QUIC detection", (engine_quic > 0) == (len(truth_quic) > 0),
            f"engine={engine_quic} flows, tshark={len(truth_quic)} udp streams")

    # --- 5. direction attribution -----------------------------------------
    # The client is the SYN sender. Any flow whose recorded src is not the SYN
    # sender would break every directional statement built on it.
    syn_out = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-Y", "tcp.flags.syn==1 && tcp.flags.ack==0",
         "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "tcp.srcport"],
        capture_output=True, text=True, check=False)
    syn_sender = {}
    for line in syn_out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].strip():
            # An ICMP error quotes the original IP/TCP header, so tshark emits
            # both the ICMP sender and the quoted original. The first value is
            # the inner one - the actual client of the connection being reported.
            addresses = [a for a in parts[1].split(",") if a.strip()]
            ports = [p for p in parts[2].split(",") if p.strip()]
            syn_sender.setdefault(parts[0].strip(),
                                  (addresses[0].strip() if addresses else "",
                                   ports[0].strip() if ports else ""))
    wrong = []
    for flow in flows:
        stream = tcp_stream(flow)
        if stream and stream in syn_sender and flow.src_ip:
            ip, port = syn_sender[stream]
            if ip and (flow.src_ip, str(flow.src_port)) != (ip, port):
                wrong.append(flow.key)
    verdict("client/server direction", not wrong,
            f"{len(wrong)} of {len(syn_sender)} SYN-anchored flows reversed")

    # --- 6. SNI attribution -----------------------------------------------
    sni_out = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-Y", "tls.handshake.extensions_server_name",
         "-T", "fields", "-e", "tcp.stream",
         "-e", "tls.handshake.extensions_server_name"],
        capture_output=True, text=True, check=False)
    truth_sni = {}
    for line in sni_out.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
            truth_sni.setdefault(parts[0].strip(), parts[1].split(",")[0].strip())
    mismatched = [
        (f.key, f.sni, truth_sni.get(tcp_stream(f)))
        for f in flows
        if tcp_stream(f) in truth_sni and f.sni != truth_sni[tcp_stream(f)]
    ]
    verdict("SNI attribution", not mismatched,
            f"{len(mismatched)} of {len(truth_sni)} flows disagree")


for path in sys.argv[1:]:
    main(path)

print(f"\n{'=' * 88}")
passed = sum(1 for _n, ok, _d in VERDICTS if ok)
print(f"TOTAL {passed}/{len(VERDICTS)} judgements agree with independent ground truth")
for name, ok, detail in VERDICTS:
    if not ok:
        print(f"   FAILED: {name} -- {detail}")
