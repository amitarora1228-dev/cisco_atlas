"""The connection story must not invent a cause it cannot see.

These build flows packet by packet rather than reading a capture, so they run
without tshark and pin the reasoning itself: which layer is blamed, and how
firmly, for each shape of failure.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from capture_inspector.engine import connection_story
from capture_inspector.pcap import Flow, Packet

CLIENT, SERVER = "10.0.0.5", "93.184.216.34"


def _pkt(n: int, t: float, src: str, **raw) -> Packet:
    fields = {"ip.src": [src], "ip.dst": [SERVER if src == CLIENT else CLIENT]}
    fields.update({k.replace("__", "."): [v] for k, v in raw.items()})
    return Packet(number=n, time_epoch=1000.0 + t, time_relative=t, length=60, raw=fields)


def _flow(packets: list[Packet], **attrs) -> Flow:
    flow = Flow(key="tcp:1", transport="tcp", src_ip=CLIENT, dst_ip=SERVER,
                src_port=51000, dst_port=443, packets=packets)
    for key, value in attrs.items():
        setattr(flow, key, value)
    return flow


def _handshake() -> list[Packet]:
    return [
        _pkt(1, 0.000, CLIENT, tcp__flags__syn="1"),
        _pkt(2, 0.013, SERVER, tcp__flags__syn="1", tcp__flags__ack="1"),
        _pkt(3, 0.014, CLIENT, tcp__flags__ack="1"),
    ]


def _layer(story: dict, name: str) -> dict | None:
    return next((x for x in story["layers"] if x["name"] == name), None)


def test_reset_after_an_acknowledged_hello_is_called_a_rejection():
    """The ACK before the RST is the evidence: the peer read the hello, then refused."""
    packets = _handshake() + [
        _pkt(4, 0.015, CLIENT, tls__handshake__type="1", tcp__len="233"),
        _pkt(5, 0.028, SERVER, tcp__flags__ack="1"),
        _pkt(6, 0.034, SERVER, tcp__flags__reset="1"),
    ]
    story = connection_story(_flow(packets, client_hello=True, tcp_handshake_ms=13.0))

    assert _layer(story, "TCP")["status"] == "ok"
    tls = _layer(story, "TLS")
    assert tls["status"] == "fail"
    assert tls["acked_hello"] is True

    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "rejection, not a network fault" in prose
    assert "network path to this destination is working" in prose


def test_reset_without_an_acknowledgement_stays_undecided():
    """Same outcome, weaker evidence - the tool must not claim to know why."""
    packets = _handshake() + [
        _pkt(4, 0.015, CLIENT, tls__handshake__type="1", tcp__len="233"),
        _pkt(5, 0.034, SERVER, tcp__flags__reset="1"),
    ]
    story = connection_story(_flow(packets, client_hello=True, tcp_handshake_ms=13.0))

    tls = _layer(story, "TLS")
    assert tls["status"] == "fail"
    assert tls["acked_hello"] is False

    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "cannot tell" in prose
    assert "rejection, not a network fault" not in prose


def test_a_client_reset_is_never_blamed_on_the_server():
    """The server answered; the client tore it down. Blaming the server would be
    backwards, and claiming no ServerHello was sent would be false."""
    packets = _handshake() + [
        _pkt(4, 0.015, CLIENT, tls__handshake__type="1"),
        _pkt(5, 0.020, SERVER, tcp__flags__ack="1"),
        _pkt(6, 0.030, SERVER, tls__handshake__type="2"),
        _pkt(7, 0.050, CLIENT, tcp__flags__reset="1"),
    ]
    story = connection_story(_flow(packets, client_hello=True, server_hello=True,
                                   tcp_handshake_ms=13.0))

    tls = _layer(story, "TLS")
    assert tls["status"] == "fail"
    assert tls["reset_by"] == "c2s"
    assert tls["server_hello"] is True
    assert tls["acked_hello"] is False, "an ACK means nothing when the client reset"
    assert "reset by the client" in tls["summary"]

    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "it was the CLIENT that reset" in prose
    assert "No ServerHello" not in prose
    assert "rejection, not a network fault" not in prose


def test_steps_are_listed_in_the_order_they_happened():
    """The sequence is the argument; a step out of order misrepresents it."""
    packets = _handshake() + [
        _pkt(4, 0.015, CLIENT, tls__handshake__type="1"),
        _pkt(5, 0.020, SERVER, tcp__flags__ack="1"),
        _pkt(6, 0.030, SERVER, tls__handshake__type="2"),
        _pkt(7, 0.050, CLIENT, tcp__flags__reset="1"),
    ]
    story = connection_story(_flow(packets, client_hello=True, server_hello=True))

    frames = [s["pkt"] for s in _layer(story, "TLS")["steps"] if s.get("pkt")]
    assert frames == sorted(frames), f"steps out of order: {frames}"


def test_completed_handshake_blames_nothing():
    packets = _handshake() + [
        _pkt(4, 0.015, CLIENT, tls__handshake__type="1"),
        _pkt(5, 0.030, SERVER, tls__handshake__type="2"),
        _pkt(6, 0.031, SERVER, tls__handshake__type="11"),
    ]
    story = connection_story(_flow(packets, client_hello=True, server_hello=True,
                                   handshake_complete=True, negotiated_version="TLS 1.3",
                                   tcp_handshake_ms=13.0))

    assert _layer(story, "TLS")["status"] == "ok"
    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "negotiated successfully" in prose
    assert "TLS 1.3" in prose


def test_unanswered_syn_blames_tcp_and_never_reaches_tls():
    story = connection_story(_flow([_pkt(1, 0.0, CLIENT, tcp__flags__syn="1")]))

    assert _layer(story, "TCP")["status"] == "fail"
    assert _layer(story, "TLS") is None
    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "never answered the SYN" in prose
    assert "cannot be separated" in prose


def test_a_blocked_lookup_stops_the_story_at_dns():
    story = connection_story(_flow(
        _handshake(),
        dns_lookup={"name": "blocked.example", "addresses": ["146.112.61.106"],
                    "blocked": True, "block_category": "malware", "rcode": 0},
    ))

    dns = _layer(story, "DNS")
    assert dns["status"] == "fail"
    assert any(step["bad"] for step in dns["steps"])
    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "block address" in prose


def test_a_dns_block_does_not_claim_the_path_to_the_destination_is_healthy():
    """The socket opened against the block page. Saying the path to the
    destination works, or that nothing below DNS was attempted, is false."""
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=41.7,
        dns_lookup={"name": "blocked.example", "addresses": ["146.112.61.116"],
                    "blocked": True, "block_category": "malware", "rcode": 0},
    ))

    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "Nothing below DNS was attempted" not in prose
    assert "path to this destination is working" not in prose
    assert "the address that was returned" in prose
    assert "not the same as a request that was allowed" in prose


def test_retransmission_count_never_exceeds_its_denominator():
    """'5 of 2 data segments' is not a sentence about reality."""
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=13.0, retransmissions=5, data_segments=2))

    fact = next(f for f in _layer(story, "TCP")["facts"] if f["label"] == "Retransmitted")
    assert fact["value"] == "5 segment(s)"

    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=13.0, retransmissions=5, data_segments=400))
    fact = next(f for f in _layer(story, "TCP")["facts"] if f["label"] == "Retransmitted")
    assert fact["value"] == "5 of 400 data segments"


def test_a_healthy_transport_reports_no_problem_facts():
    """Facts must earn their place: a clean layer stays quiet."""
    story = connection_story(_flow(_handshake(), tcp_handshake_ms=13.0,
                                   initial_rtt_ms=13.0))

    tones = {f["tone"] for f in _layer(story, "TCP")["facts"]}
    assert tones <= {"plain"}


def test_an_http_refusal_outranks_anything_inferred_from_an_address():
    """A 403 is the block itself. The story must lead with the server's own
    words rather than with what the DNS answer suggested."""
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=41.7,
        http_requests=[{"packet": 9, "method": "GET",
                        "uri": "http://examplemalwaredomain.com/",
                        "host": "examplemalwaredomain.com"}],
        http_statuses=["403"],
        dns_lookup={"name": "examplemalwaredomain.com", "addresses": ["146.112.61.116"],
                    "blocked": True, "block_category": "malware", "rcode": 0},
    ))

    http = _layer(story, "HTTP")
    assert http["status"] == "fail"
    assert any("403" in s["msg"] and s["bad"] for s in http["steps"])

    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "stated by the server in plain HTTP" in prose
    assert "Both layers agree" in prose


def test_ttl_is_reported_as_distance_not_as_a_raw_number():
    story = connection_story(_flow(_handshake(), tcp_handshake_ms=13.0, server_ttl=117))

    fact = next(f for f in _layer(story, "TCP")["facts"] if f["label"] == "Distance to peer")
    assert fact["value"] == "~11 hop(s)"
    assert "TTL 117" in fact["note"]


def test_a_segment_larger_than_the_agreed_mss_is_flagged_as_not_a_wire_frame():
    """Above the NIC the OS hands over super-segments; calling them packets
    would misrepresent both the count and the timing."""
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=13.0, max_tcp_len=6304, mss_values=[1460, 1452]))

    fact = next(f for f in _layer(story, "TCP")["facts"] if f["label"] == "Largest segment")
    assert fact["value"] == "6304 B vs 1452 B agreed"
    assert "not individual wire frames" in fact["note"]


def test_an_encrypted_client_hello_admits_the_host_cannot_be_named():
    story = connection_story(_flow(
        _handshake() + [_pkt(4, 0.015, CLIENT, tls__handshake__type="1")],
        client_hello=True, has_ech=True, handshake_complete=True))

    fact = next(f for f in _layer(story, "TLS")["facts"]
                if f["label"] == "Encrypted ClientHello")
    assert "cannot be attributed" in fact["note"]


def test_how_the_connection_closed_is_stated():
    reset = connection_story(_flow(_handshake(), tcp_handshake_ms=13.0,
                                   rst_count=1, client_reset=True))
    fact = next(f for f in _layer(reset, "TCP")["facts"] if f["label"] == "Closed by")
    assert fact["value"] == "reset from the client"

    clean = connection_story(_flow(_handshake(), tcp_handshake_ms=13.0, fin_count=2))
    fact = next(f for f in _layer(clean, "TCP")["facts"] if f["label"] == "Closed by")
    assert "orderly" in fact["value"]


def test_a_dns_record_that_names_a_different_host_admits_the_ambiguity():
    """Many names share one block-page address. When the request on the
    connection asked for another host, the DNS record shown may be the wrong
    one, and saying nothing would present a coincidence as a fact."""
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=41.7,
        http_requests=[{"packet": 9, "method": "GET",
                        "uri": "http://www.internetbadguys.com/",
                        "host": "www.internetbadguys.com"}],
        http_statuses=["403"],
        dns_lookup={"name": "examplemalwaredomain.com", "addresses": ["146.112.61.116"],
                    "blocked": True, "block_category": "malware", "rcode": 0},
    ))

    why = _layer(story, "DNS")["why"]
    assert "by address" in why
    assert "www.internetbadguys.com" in why


def test_no_ambiguity_note_when_the_names_agree():
    story = connection_story(_flow(
        _handshake(), tcp_handshake_ms=41.7,
        http_requests=[{"packet": 9, "method": "GET", "uri": "http://a.example/",
                        "host": "a.example"}],
        http_statuses=["200"],
        dns_lookup={"name": "a.example", "addresses": ["93.184.216.34"], "rcode": 0},
    ))

    assert not _layer(story, "DNS")["why"]


class _Cert:
    parse_error = None
    subject_cn = "api.example.com"
    issuer_cn = "Example CA"
    issuer_org = None
    looks_like_proxy_ca = False

    def __init__(self, not_before, not_after, expired):
        self.not_before, self.not_after, self.expired = not_before, not_after, expired


def _tls_flow(capture_epoch: float, **attrs) -> Flow:
    packets = [
        Packet(number=1, time_epoch=capture_epoch, time_relative=0.0, length=60,
               raw={"ip.src": [CLIENT], "ip.dst": [SERVER], "tcp.flags.syn": ["1"]}),
        Packet(number=2, time_epoch=capture_epoch + 0.013, time_relative=0.013, length=60,
               raw={"ip.src": [SERVER], "ip.dst": [CLIENT],
                    "tcp.flags.syn": ["1"], "tcp.flags.ack": ["1"]}),
        Packet(number=3, time_epoch=capture_epoch + 0.015, time_relative=0.015, length=60,
               raw={"ip.src": [CLIENT], "ip.dst": [SERVER], "tls.handshake.type": ["1"]}),
    ]
    return _flow(packets, client_hello=True, tcp_handshake_ms=13.0, **attrs)


def _validity(story) -> dict:
    return next(f for f in _layer(story, "TLS")["facts"]
                if f["label"] == "Certificate validity")


CAPTURED_AT = datetime(2026, 7, 1, 12, 0, tzinfo=UTC).timestamp()


def test_a_certificate_expired_before_the_capture_is_blamed():
    cert = _Cert("2025-06-28T00:00:00+00:00", "2026-06-28T00:00:00+00:00", True)
    fact = _validity(connection_story(_tls_flow(CAPTURED_AT), rep=SimpleNamespace(leaf_cert=cert)))

    assert fact["tone"] == "bad"
    assert "expired 3 day(s) before this connection" in fact["note"]
    assert "issued for 365 days" in fact["note"]


def test_a_certificate_that_lapsed_only_after_the_capture_is_not_flagged():
    """CertInfo.expired is measured at analysis time. A certificate that was
    valid during the capture explains nothing recorded in it, so marking it at
    all would invent a problem that the connection never had."""
    cert = _Cert("2026-06-01T00:00:00+00:00", "2026-07-20T00:00:00+00:00", True)
    fact = _validity(connection_story(_tls_flow(CAPTURED_AT), rep=SimpleNamespace(leaf_cert=cert)))

    assert fact["tone"] == "plain"
    assert fact["note"] == "valid when this connection was made"


def test_a_short_lived_proxy_certificate_is_not_a_warning():
    """An interception proxy mints five-day certificates. One day left is that
    design working, not a certificate about to fail."""
    cert = _Cert("2026-06-28T00:00:00+00:00", "2026-07-03T00:00:00+00:00", True)
    fact = _validity(connection_story(_tls_flow(CAPTURED_AT), rep=SimpleNamespace(leaf_cert=cert)))

    assert fact["tone"] == "plain"
    assert fact["value"] == "2026-06-28 \u2192 2026-07-03"


def test_a_certificate_not_yet_valid_names_the_clock_as_a_suspect():
    cert = _Cert("2026-07-10T00:00:00+00:00", "2027-07-10T00:00:00+00:00", False)
    fact = _validity(connection_story(_tls_flow(CAPTURED_AT), rep=SimpleNamespace(leaf_cert=cert)))

    assert fact["tone"] == "bad"
    assert "not valid yet" in fact["note"]
    assert "clock is behind" in fact["note"]


def test_a_capture_that_starts_mid_session_says_so():
    """No SYN is a gap in the evidence, not a failed handshake."""
    packets = [
        _pkt(1, 0.0, CLIENT, tls__handshake__type="1"),
        _pkt(2, 0.02, SERVER, tls__handshake__type="2"),
    ]
    story = connection_story(_flow(packets, client_hello=True, server_hello=True,
                                   handshake_complete=True))

    tcp = _layer(story, "TCP")
    assert tcp["status"] == "absent"
    assert "not in it" in tcp["why"]
