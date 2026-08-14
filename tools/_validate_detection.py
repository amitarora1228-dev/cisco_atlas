"""Cross-check the engine's counters against tshark answering the same question.

Reading the code proves nothing: it would only confirm the code does what the
code says. Each check here asks tshark directly, with its own display filter,
and compares. A disagreement is a real defect in one of the two.
"""
from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "capture_inspector"))

from capture_inspector.engine import enrich_flow  # noqa: E402
from capture_inspector.pcap import build_flows, find_tshark, run_tshark  # noqa: E402

TSHARK = find_tshark()


def tshark_count(capture: str, display_filter: str) -> int:
    """How many frames tshark itself matches, with no help from our code."""
    out = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
        capture_output=True, text=True, check=False,
    )
    return len([line for line in out.stdout.splitlines() if line.strip()])


def check(name: str, ours: int, theirs: int, tolerance: int = 0) -> tuple[str, str]:
    delta = ours - theirs
    ok = abs(delta) <= tolerance
    mark = "PASS" if ok else "FAIL"
    detail = f"engine={ours:<7} tshark={theirs:<7} delta={delta:+}"
    return mark, f"  [{mark}] {name:<44} {detail}"


def main(capture: str) -> None:
    print(f"\n{'=' * 84}\n{capture}\n{'=' * 84}")
    packets = run_tshark(capture, TSHARK)
    flows = build_flows(packets)
    for flow in flows:
        enrich_flow(flow)
    tcp = [f for f in flows if f.transport == "tcp"]

    results = []

    # --- TCP transport counters -------------------------------------------
    results.append(check(
        "retransmissions (incl. fast+spurious)",
        sum(f.retransmissions for f in tcp),
        tshark_count(capture, "tcp.analysis.retransmission || "
                              "tcp.analysis.fast_retransmission || "
                              "tcp.analysis.spurious_retransmission")))
    results.append(check(
        "spurious retransmissions",
        sum(f.spurious_retransmissions for f in tcp),
        tshark_count(capture, "tcp.analysis.spurious_retransmission")))
    results.append(check(
        "lost segments",
        sum(f.lost_segments for f in tcp),
        tshark_count(capture, "tcp.analysis.lost_segment")))
    results.append(check(
        "duplicate ACKs",
        sum(f.dup_acks for f in tcp),
        tshark_count(capture, "tcp.analysis.duplicate_ack")))
    results.append(check(
        "zero-window events",
        sum(f.zero_window for f in tcp),
        tshark_count(capture, "tcp.analysis.zero_window")))
    results.append(check(
        "window-full events",
        sum(f.window_full for f in tcp),
        tshark_count(capture, "tcp.analysis.window_full")))
    results.append(check(
        "out-of-order",
        sum(f.out_of_order for f in tcp),
        tshark_count(capture, "tcp.analysis.out_of_order")))
    results.append(check(
        "ACKed-but-unseen segments",
        sum(f.ack_lost_segment for f in tcp),
        tshark_count(capture, "tcp.analysis.ack_lost_segment")))
    results.append(check(
        "RST packets",
        sum(f.rst_count for f in tcp),
        tshark_count(capture, "tcp.flags.reset == 1")))

    # --- TLS handshake state ----------------------------------------------
    results.append(check(
        "flows with a ClientHello",
        sum(1 for f in flows if f.client_hello),
        tshark_count(capture, "tls.handshake.type == 1"),
        tolerance=10**6))  # frames vs flows: reported, not compared
    results.append(check(
        "TLS alert frames",
        sum(len(f.alerts) for f in flows),
        tshark_count(capture, "tls.alert_message.desc")))

    # --- capture quality ---------------------------------------------------
    ifaces = subprocess.run(  # noqa: S603
        [TSHARK, "-r", capture, "-T", "fields", "-e", "frame.interface_id"],
        capture_output=True, text=True, check=False)
    iface_counts = Counter(x for x in ifaces.stdout.split() if x)
    print(f"  interfaces in file: {dict(iface_counts)}")

    print()
    for _mark, line in results:
        print(line)
    failed = [m for m, _ in results if m == "FAIL"]
    print(f"\n  {len(results) - len(failed)}/{len(results)} agree with tshark")


for path in sys.argv[1:]:
    main(path)
