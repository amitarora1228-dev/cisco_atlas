"""The correlation view tells the same story from a summarised flow.

It is built from ``WireFlow``, which holds counts and a capped set of events
rather than packets, so it covers TCP, the tunnel, TLS, HTTP and the transfer.
It must never claim a layer the model cannot support - DNS above all, because
this pass reads TCP only and a missing DNS layer would otherwise read as a
clean lookup.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from atlas_core.flows import WireFlow, _flow_story

CLIENT, SERVER = "10.0.0.5", "93.184.216.34"
START = datetime(2026, 8, 14, 10, 0, 0)


class _Flow:
    """The part of FlowCorrelation the story reads."""

    def __init__(self, wire: WireFlow, destination: str = "example.com"):
        self.wire = wire
        self.destination = destination


def _wire(**attrs) -> WireFlow:
    events = attrs.pop("events", (
        (0.0, CLIENT, 51000, "syn", 0),
        (0.013, SERVER, 443, "synack", 0),
        (0.014, CLIENT, 51000, "ack", 0),
    ))
    base = {
        "stream": 1, "src_ip": CLIENT, "src_port": 51000,
        "dst_ip": SERVER, "dst_port": 443, "packets": len(events),
        "first_seen": START, "last_seen": START + timedelta(seconds=2),
        "has_syn": True, "handshake_rtt": 0.013, "head": events,
    }
    base.update(attrs)
    return WireFlow(**base)


def _layer(story: dict, name: str) -> dict | None:
    return next((x for x in story["layers"] if x["name"] == name), None)


def test_a_plain_connection_gets_a_tcp_layer_with_its_round_trip():
    story = _flow_story(_Flow(_wire()))

    tcp = _layer(story, "TCP")
    assert tcp["status"] == "ok"
    assert "13.0 ms" in tcp["summary"]


def test_dns_is_never_claimed_because_this_pass_reads_tcp_only():
    story = _flow_story(_Flow(_wire()))

    assert _layer(story, "DNS") is None
    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "DNS is UDP and this pass reads TCP only" in prose


def test_a_completed_handshake_reports_the_negotiated_version():
    story = _flow_story(_Flow(_wire(
        tls_version="TLS 1.3", alpn=("h2",),
        handshake_seen=("clienthello", "serverhello"),
        events=(
            (0.0, CLIENT, 51000, "syn", 0),
            (0.013, SERVER, 443, "synack", 0),
            (0.02, CLIENT, 51000, "clienthello", 517),
            (0.05, SERVER, 443, "serverhello", 1400),
        ))))

    tls = _layer(story, "TLS")
    assert tls["status"] == "ok"
    assert "TLS 1.3" in tls["summary"]
    assert any(f["value"] == "h2" for f in tls["facts"])


def test_a_client_hello_with_no_reply_is_not_called_negotiated():
    story = _flow_story(_Flow(_wire(handshake_seen=("clienthello",))))

    assert _layer(story, "TLS")["status"] == "warn"


def test_a_tls_alert_is_a_failure_with_the_peer_s_own_reason():
    story = _flow_story(_Flow(_wire(
        handshake_seen=("clienthello",), tls_alerts=("bad_certificate",))))

    assert _layer(story, "TLS")["status"] == "fail"
    assert "alert" in " ".join(story["conclusion"]["paragraphs"])


def test_a_refused_connect_tunnel_stops_the_story_there():
    story = _flow_story(_Flow(_wire(
        http_methods=("CONNECT",), http_statuses=("403",),
        first_uri="video.example.com:443")))

    tunnel = _layer(story, "TUNNEL")
    assert tunnel["status"] == "fail"
    assert "refused to open the tunnel" in " ".join(story["conclusion"]["paragraphs"])


def test_a_connect_tunnel_does_not_also_produce_an_http_layer():
    """The 200 belongs to the tunnel, not to a request the user made."""
    story = _flow_story(_Flow(_wire(http_methods=("CONNECT",), http_statuses=("200",))))

    assert _layer(story, "TUNNEL")["status"] == "ok"
    assert _layer(story, "HTTP") is None


def test_a_plain_http_refusal_is_quoted_rather_than_inferred():
    story = _flow_story(_Flow(_wire(
        http_methods=("GET",), http_statuses=("403",),
        first_uri="http://blocked.example/")))

    assert _layer(story, "HTTP")["status"] == "fail"
    prose = " ".join(story["conclusion"]["paragraphs"])
    assert "stated in plain HTTP rather than inferred" in prose


def test_a_stalled_receiver_is_named_as_an_application_problem():
    story = _flow_story(_Flow(_wire(zero_windows=2, client_bytes=500, server_bytes=900_000)))

    assert any(f["tone"] == "bad" for f in _layer(story, "TCP")["facts"])
    assert "application stall, not loss" in " ".join(story["conclusion"]["paragraphs"])


def test_the_transfer_layer_reports_each_direction():
    story = _flow_story(_Flow(_wire(client_bytes=2_000, server_bytes=900_000)))

    transferred = next(f for f in _layer(story, "DATA")["facts"]
                       if f["label"] == "Transferred")
    assert transferred["value"] == "900 KB in, 2 KB out"


def test_a_capture_that_starts_mid_connection_says_so():
    story = _flow_story(_Flow(_wire(has_syn=False, handshake_rtt=None)))

    tcp = _layer(story, "TCP")
    assert tcp["status"] == "absent"
    assert "already open" in tcp["why"]


def test_a_flow_the_capture_never_held_has_no_story():
    assert _flow_story(_Flow(None)) is None
