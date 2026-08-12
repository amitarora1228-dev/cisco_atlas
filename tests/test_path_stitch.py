"""Does the path stitcher join what it should, and refuse what it should not?

These captures are built here rather than collected, because the join being
tested is a property of TCP, not of any particular network: a forwarding device
passes the sequence number through, a proxy does not. Writing the packets makes
the initial sequence numbers exact and known, which is the only way to assert
that a join was made for the right reason rather than by luck.

What this cannot test is a real device, and that is stated in
``docs/IMPROVEMENTS.md`` rather than implied to be covered.
"""

from __future__ import annotations

import shutil
import struct
import subprocess

import pytest

from atlas_core.flows import JoinStrength
from atlas_core.path import LinkKind, Vantage, stitch_path
from atlas_core.flows import extract_wire_flows


def _tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, flags: int) -> bytes:
    """One Ethernet/IPv4/TCP frame, with the sequence number we asked for."""
    tcp = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, 0, (5 << 4), flags, 8192, 0, 0
    )
    total = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total, 0, 0, 64, 6, 0,
        bytes(int(p) for p in src_ip.split(".")),
        bytes(int(p) for p in dst_ip.split(".")),
    )
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    return eth + ip + tcp


def _write_pcap(path, packets: list[tuple[float, bytes]]) -> str:
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for when, raw in packets:
            handle.write(
                struct.pack(
                    "<IIII", int(when), int((when - int(when)) * 1_000_000), len(raw), len(raw)
                )
            )
            handle.write(raw)
    return str(path)


SYN = 0x02
SYNACK = 0x12
ACK = 0x10

_HAS_TSHARK = shutil.which("tshark") or shutil.which(
    "/Applications/Wireshark.app/Contents/MacOS/tshark"
)
pytestmark = pytest.mark.skipif(not _HAS_TSHARK, reason="tshark is needed to read the captures")


def _tshark() -> str | None:
    return shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"


def _flows(path: str):
    return tuple(extract_wire_flows(path, tshark_path=_tshark()))


def test_a_forwarded_connection_is_recognised_at_both_vantages(tmp_path):
    """The same connection, seen twice, is one segment - even through NAT.

    The client's address is translated between the two vantage points, so every
    address and port differs. Only the sequence number is the same, which is
    exactly the case the join exists for.
    """
    base = 1_700_000_000.0
    near = _write_pcap(tmp_path / "near.pcap", [
        (base, _tcp_packet("10.1.1.10", "10.2.2.2", 50000, 443, 111_000, SYN)),
        (base + 0.01, _tcp_packet("10.2.2.2", "10.1.1.10", 443, 50000, 222_000, SYNACK)),
    ])
    far = _write_pcap(tmp_path / "far.pcap", [
        (base + 0.004, _tcp_packet("203.0.113.9", "10.2.2.2", 61000, 443, 111_000, SYN)),
        (base + 0.014, _tcp_packet("10.2.2.2", "203.0.113.9", 443, 61000, 222_000, SYNACK)),
    ])

    traces = stitch_path([
        Vantage("client", _flows(near)),
        Vantage("ftd", _flows(far)),
    ])

    assert traces, "the captures share a connection, so there is a path to report"
    segments = traces[0].segments
    assert len(segments) == 1, "one connection seen twice is one segment, not two"
    assert segments[0].vantages == ["client", "ftd"]


def test_a_proxied_leg_is_never_reported_as_proved(tmp_path):
    """A new connection is associated, not joined.

    The proxy terminates one connection and opens another with a sequence
    number of its own. Nothing is shared, so the link must be the weaker kind
    and must say so.
    """
    base = 1_700_000_000.0
    inbound = _write_pcap(tmp_path / "in.pcap", [
        (base, _tcp_packet("10.1.1.10", "10.2.2.2", 50000, 443, 111_000, SYN)),
    ])
    outbound = _write_pcap(tmp_path / "out.pcap", [
        (base + 0.5, _tcp_packet("10.2.2.2", "10.9.9.9", 40000, 443, 999_000, SYN)),
    ])

    traces = stitch_path([
        Vantage("client", _flows(inbound)),
        Vantage("egress", _flows(outbound)),
    ])

    links = [link for trace in traces for link in trace.links]
    assert links, "the proxy's address is in both captures, so the legs must be linked"
    link = links[0]
    assert link.kind is LinkKind.PROXIED
    assert link.strength is not JoinStrength.EXACT, "no packet is shared, so nothing is proved"
    assert link.pivot == "10.2.2.2"


def test_unrelated_captures_are_not_stitched_together(tmp_path):
    """Two captures with nothing in common produce no link.

    This is the failure that would matter most: a path drawn between vantage
    points that never carried the same traffic reads as a finding.
    """
    base = 1_700_000_000.0
    one = _write_pcap(tmp_path / "one.pcap", [
        (base, _tcp_packet("10.1.1.10", "10.4.4.4", 50000, 443, 111_000, SYN)),
    ])
    two = _write_pcap(tmp_path / "two.pcap", [
        (base + 600, _tcp_packet("192.168.5.5", "10.8.8.8", 51000, 443, 777_000, SYN)),
    ])

    traces = stitch_path([
        Vantage("one", _flows(one)),
        Vantage("two", _flows(two)),
    ])

    assert not [link for trace in traces for link in trace.links], (
        "nothing connects these captures, so no hop may be claimed"
    )


def test_a_leg_without_a_handshake_says_why_it_cannot_join(tmp_path):
    """No SYN means no sequence number, which means no join - and a note."""
    base = 1_700_000_000.0
    mid = _write_pcap(tmp_path / "mid.pcap", [
        (base, _tcp_packet("10.1.1.10", "10.2.2.2", 50000, 443, 111_000, ACK)),
        (base + 0.1, _tcp_packet("10.2.2.2", "10.1.1.10", 443, 50000, 222_000, ACK)),
    ])

    traces = stitch_path([Vantage("mid", _flows(mid))])

    assert traces
    assert any("without their handshake" in note for note in traces[0].notes)
