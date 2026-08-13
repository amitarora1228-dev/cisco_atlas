"""When the cause is encrypted, report the pattern - never invent the reason.

The four conditions must hold together. Each one alone is ordinary traffic, and
firing on any single one would flood a normal capture with red.
"""
from __future__ import annotations

from capture_inspector.findings.opaque import (
    _capture_ruled_out,
    _opaque_tunnel_findings,
)
from capture_inspector.pcap import Flow, Packet

CLIENT, PROXY = "10.0.0.5", "35.178.14.215"


def _pkt(n: int, t: float, src: str, length: int) -> Packet:
    return Packet(number=n, time_epoch=1000.0 + t, time_relative=t, length=length + 40,
                  raw={"ip.src": [src], "ip.dst": [PROXY if src == CLIENT else CLIENT],
                       "tcp.seq": [str(n * 100)], "tcp.ack": ["1"],
                       "tcp.len": [str(length)]})


def _tunnel(key: str, target: str, start: float, held: float,
            sent: int, received: int, **attrs) -> Flow:
    packets = [_pkt(1, start, CLIENT, sent), _pkt(2, start + held, PROXY, received)]
    flow = Flow(key=key, transport="tcp", src_ip=CLIENT, dst_ip=PROXY,
                src_port=50000, dst_port=443, packets=packets)
    flow.is_connect_tunnel = True
    flow.connect_target = target
    flow.connect_status = "200"
    for name, value in attrs.items():
        setattr(flow, name, value)
    return flow


def _three_bad_tunnels() -> list[Flow]:
    return [
        _tunnel("t1", "rr1---sn-aaa.googlevideo.com:443", 2.83, 1.5, 28_000, 9_000),
        _tunnel("t2", "rr2---sn-bbb.googlevideo.com:443", 2.97, 1.5, 38_000, 9_600),
        _tunnel("t3", "rr5---sn-ccc.googlevideo.com:443", 3.10, 0.1, 14_000, 5_500),
    ]


def test_the_pattern_is_reported_and_names_no_cause():
    findings = _opaque_tunnel_findings(_three_bad_tunnels(), [])

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.category == "tunnel"
    assert "googlevideo.com" in f.title
    assert "cause is encrypted" in f.title
    # The tool must not assert a reason it cannot see.
    assert "WHY NO CAUSE IS NAMED" in f.detail
    assert "cannot separate them" in f.detail
    assert "SSLKEYLOGFILE" in f.detail


def test_cdn_nodes_of_one_service_are_counted_together():
    """Three node names, one service. Counting them apart would hide the retrying."""
    findings = _opaque_tunnel_findings(_three_bad_tunnels(), [])

    assert "endpoints=3" in findings[0].evidence[0]
    assert "attempts=3" in findings[0].evidence[0]


def test_a_tunnel_that_closed_properly_is_not_abandoned():
    flows = _three_bad_tunnels()
    for f in flows:
        f.fin_count = 2

    assert _opaque_tunnel_findings(flows, []) == []


def test_two_attempts_are_not_a_pattern():
    assert _opaque_tunnel_findings(_three_bad_tunnels()[:2], []) == []


def test_a_healthy_download_ratio_is_not_reported():
    """Receiving far more than was sent is exactly what a working download does."""
    flows = [
        _tunnel("t1", "rr1---sn-aaa.googlevideo.com:443", 2.8, 1.5, 2_000, 900_000),
        _tunnel("t2", "rr2---sn-bbb.googlevideo.com:443", 3.0, 1.5, 2_000, 800_000),
        _tunnel("t3", "rr5---sn-ccc.googlevideo.com:443", 3.2, 0.1, 1_000, 400_000),
    ]

    assert _opaque_tunnel_findings(flows, []) == []


def test_a_tunnel_the_intermediary_refused_is_someone_elses_finding():
    """A non-2xx CONNECT never opened, so this is not the abandoned-tunnel case."""
    flows = _three_bad_tunnels()
    for f in flows:
        f.connect_status = "403"

    assert _opaque_tunnel_findings(flows, []) == []


def test_what_was_ruled_out_is_carried_into_the_finding():
    findings = _opaque_tunnel_findings(
        _three_bad_tunnels(), ["real packet loss was 0.05% over 4,312 data segments"])

    assert "The capture did rule things out" in findings[0].detail
    assert "0.05%" in findings[0].detail


class _Report:
    def __init__(self, flow):
        self.flow = flow
        self.findings: list = []


def test_every_connection_in_the_pattern_is_marked_not_only_the_first():
    """A capture-level finding alone leaves every flow looking healthy, so an
    'errors only' view shows nothing - the silence this exists to break."""
    flows = _three_bad_tunnels()
    reports = [_Report(f) for f in flows]

    _opaque_tunnel_findings(flows, [], reports)

    assert all(r.findings for r in reports), "a flow in the pattern was left clean"
    for report in reports:
        marked = report.findings[0]
        assert marked.severity == "high"
        assert marked.category == "tunnel"
        assert marked.flow_key == report.flow.key


def test_flows_outside_the_pattern_are_left_alone():
    flows = _three_bad_tunnels()
    healthy = _tunnel("ok", "cdn.example.com:443", 5.0, 0.5, 1_000, 500_000)
    healthy.fin_count = 2
    reports = [_Report(f) for f in [*flows, healthy]]

    _opaque_tunnel_findings([*flows, healthy], [], reports)

    assert reports[-1].findings == []


def test_loss_is_neither_claimed_nor_excluded_on_a_duplicated_capture():
    """The counters are inflated when the same packet is recorded twice, so the
    honest move is to say the question was not answered."""
    notes = _capture_ruled_out(_three_bad_tunnels(), unreliable_loss=True)

    joined = " ".join(notes)
    assert "not trusted" in joined
    assert "neither claimed nor excluded" in joined
    assert "%" not in joined


def test_a_clean_capture_states_the_measured_loss():
    flows = _three_bad_tunnels()
    for f in flows:
        f.data_segments = 500
        f.retransmissions = 1
        f.spurious_retransmissions = 0

    notes = " ".join(_capture_ruled_out(flows, unreliable_loss=False))

    # 3 retransmissions across 1,500 data segments.
    assert "real packet loss was 0.20% over 1,500 data segments" in notes


def test_retransmissions_the_dissector_called_unnecessary_are_not_loss():
    flows = _three_bad_tunnels()
    for f in flows:
        f.data_segments = 500
        f.retransmissions = 4
        f.spurious_retransmissions = 4

    notes = " ".join(_capture_ruled_out(flows, unreliable_loss=False))

    assert "real packet loss was 0.00%" in notes
