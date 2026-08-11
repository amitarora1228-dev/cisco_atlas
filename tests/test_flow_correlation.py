"""Flow-level correlation across a bundle, a capture and a HAR.

These tests use synthetic inputs deliberately. Real captures, HARs and DART
bundles must never enter the repository - a capture plus its key log decrypts
the session it recorded - so the fixtures here are hand-written to exercise the
join rules rather than copied from a collection.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from atlas_core.flows import (
    AgentFlow,
    JoinStrength,
    Steering,
    WebRequest,
    WireFlow,
    correlate_session,
    extract_agent_flows,
    extract_web_requests,
)


def _wire(
    stream: int,
    src_port: int,
    dst_ip: str,
    *,
    src_ip: str = "192.168.52.201",
    dst_port: int = 443,
    sni: str | None = None,
    at: datetime | None = None,
    has_syn: bool = True,
) -> WireFlow:
    return WireFlow(
        stream=stream,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        sni=sni,
        packets=10,
        bytes=1000,
        first_seen=at or datetime(2026, 8, 10, 18, 0, 0),
        last_seen=(at or datetime(2026, 8, 10, 18, 0, 0)) + timedelta(seconds=5),
        has_syn=has_syn,
    )


def _agent(src_port: int, dst_ip: str, at: datetime, *, proto: str = "http2") -> AgentFlow:
    return AgentFlow(
        proto=proto,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=443,
        first_seen=at,
        last_seen=at + timedelta(seconds=5),
        lines=4,
    )


# --- reading the agent log -------------------------------------------------


def test_agent_log_flow_ids_are_read_for_every_transport_prefix(tmp_path):
    """The tunnel is logged as http2_, so matching only tcp_ finds nothing.

    This is not a hypothetical: the multiplexed tunnel carries the events worth
    correlating, and it never appears under the tcp_ prefix.
    """
    log = tmp_path / "ZeroTrustAccess.txt"
    log.write_text(
        "2026-08-10 17:59:30.100000 csc_zta_agent[0x1/T] I/ TcpTransport.cpp:59 Connect() "
        "tcp_50000__10.0.0.1:443 opened\n"
        "2026-08-10 17:59:31.100000 csc_zta_agent[0x1/T] I/ Http2Mux.cpp:983 Recv() "
        "http2_59612__35.153.171.158:443 RST received on stream=393 error=5\n"
        "2026-08-10 17:59:32.100000 csc_zta_agent[0x1/T] E/ Http2Mux.cpp:1304 doSend() "
        "http2_59612__35.153.171.158:443 nghttp2 error:Invalid argument\n",
        encoding="utf-8",
    )

    flows = {(f.src_port, f.dst_ip): f for f in extract_agent_flows(str(log))}

    assert (50000, "10.0.0.1") in flows
    tunnel = flows[(59612, "35.153.171.158")]
    assert tunnel.proto == "http2"
    assert tunnel.lines == 2
    assert any("nghttp2" in e for e in tunnel.errors)
    # The flow identifier and the log's own prefix are noise once the line has
    # been attributed to a flow.
    assert "http2_59612" not in tunnel.errors[0]
    assert "csc_zta_agent" not in tunnel.errors[0]


def test_reused_source_port_becomes_two_connections(tmp_path):
    """A log spanning days will reuse ephemeral ports.

    Collapsing both uses into one record would invent a connection that lived
    for hours, and would let a day-old connection match a captured flow.
    """
    log = tmp_path / "ZeroTrustAccess.txt"
    log.write_text(
        "2026-08-10 09:00:00.000000 csc_zta_agent[0x1/T] I/ A.cpp:1 f() "
        "http2_59612__35.153.171.158:443 early\n"
        "2026-08-10 18:00:00.000000 csc_zta_agent[0x1/T] I/ A.cpp:1 f() "
        "http2_59612__35.153.171.158:443 later\n",
        encoding="utf-8",
    )

    flows = extract_agent_flows(str(log))

    assert len(flows) == 2
    assert {f.first_seen.hour for f in flows} == {9, 18}


# --- the tunnel join -------------------------------------------------------


def test_tunnel_joins_on_connection_identity():
    at = datetime(2026, 8, 10, 18, 0, 0)
    wire = _wire(1, 59612, "35.153.171.158", at=at)
    result = correlate_session([wire], [_agent(59612, "35.153.171.158", at)], [])

    assert len(result.tunnels) == 1
    assert result.tunnels[0].strength is JoinStrength.EXACT
    assert result.tunnels[0].agent.label == "http2_59612__35.153.171.158:443"


def test_recycled_port_far_from_the_capture_is_refused_and_reported():
    """Identity alone is not a key once ports have been reused."""
    at = datetime(2026, 8, 10, 18, 0, 0)
    stale = _agent(59612, "35.153.171.158", at - timedelta(hours=9))

    result = correlate_session([_wire(1, 59612, "35.153.171.158", at=at)], [stale], [])

    assert result.tunnels == []
    assert any("reused" in note for note in result.notes)


def test_loopback_flows_are_never_taken_for_tunnels():
    """The browser's leg to the local listener is not a network connection."""
    at = datetime(2026, 8, 10, 18, 0, 0)
    local = _wire(1, 59879, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555, at=at)

    result = correlate_session([local], [_agent(59879, "127.0.0.1", at)], [])

    assert result.tunnels == []


# --- steering --------------------------------------------------------------


def test_local_interception_is_reported_as_steered():
    local = _wire(1, 59879, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555, sni="www.youtube.com")

    result = correlate_session([local], [], [])
    host = result.hosts[0]

    assert host.steering is Steering.STEERED
    assert host.join_strength is JoinStrength.OBSERVED
    assert "www.youtube.com" in host.steering_basis


def test_handshake_straight_to_the_peer_is_reported_as_direct():
    direct = _wire(1, 59504, "142.251.218.142", sni="accounts.youtube.com")

    result = correlate_session([direct], [], [])
    host = result.hosts[0]

    assert host.steering is Steering.DIRECT
    assert "142.251.218.142" in host.steering_basis


def test_host_with_no_handshake_is_unknown_not_assumed_direct():
    """Absence of a handshake is ambiguous, and must not be read as a verdict."""
    request = WebRequest(
        url="https://cached.example/x",
        host="cached.example",
        method="GET",
        status=200,
        server_ip=None,
        started=datetime(2026, 8, 10, 18, 0, 0),
        duration_ms=5.0,
    )

    result = correlate_session([], [], [request])
    host = result.hosts[0]

    assert host.steering is Steering.UNKNOWN
    assert host.join_strength is JoinStrength.ASSOCIATED
    assert any("only in the HAR" in note for note in result.notes)


def test_server_address_absent_from_the_wire_is_reported_as_synthetic():
    """A steered endpoint hands the browser an address it owns.

    Recognising it by absence from the capture avoids asserting any particular
    vendor address range, which would break the moment the range changed.
    """
    local = _wire(1, 59879, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555, sni="www.youtube.com")
    request = WebRequest(
        url="https://www.youtube.com/",
        host="www.youtube.com",
        method="GET",
        status=200,
        server_ip="7.189.58.248",
        started=datetime(2026, 8, 10, 18, 0, 0),
        duration_ms=100.0,
    )

    host = correlate_session([local], [], [request]).hosts[0]

    assert host.synthetic_ips == ["7.189.58.248"]
    assert host.real_peers == []
    assert "never appears on the wire" in host.steering_basis


def test_server_address_seen_on_the_wire_is_not_called_synthetic():
    direct = _wire(1, 59504, "142.251.218.142", sni="accounts.youtube.com")
    request = WebRequest(
        url="https://accounts.youtube.com/",
        host="accounts.youtube.com",
        method="GET",
        status=200,
        server_ip="142.251.218.142",
        started=datetime(2026, 8, 10, 18, 0, 0),
        duration_ms=50.0,
    )

    host = correlate_session([direct], [], [request]).hosts[0]

    assert host.synthetic_ips == []
    assert host.real_peers == ["142.251.218.142"]


# --- the clock -------------------------------------------------------------


def test_offset_is_measured_only_from_captured_handshakes():
    """A flow already running when the capture began dates the capture, not the clock."""
    at = datetime(2026, 8, 10, 18, 0, 0)
    running = _wire(1, 59612, "35.153.171.158", at=at, has_syn=False)
    agent = _agent(59612, "35.153.171.158", at - timedelta(seconds=120))

    result = correlate_session([running], [agent], [])

    assert result.tunnels != []
    assert result.clock_offset is None
    assert "handshake" in result.clock_offset_basis


def test_offset_is_bounded_by_the_earliest_agent_line():
    at = datetime(2026, 8, 10, 18, 0, 0)
    wire = _wire(1, 59612, "35.153.171.158", at=at, has_syn=True)
    agent = _agent(59612, "35.153.171.158", at + timedelta(seconds=6))

    result = correlate_session([wire], [agent], [])

    assert result.clock_offset == timedelta(seconds=6)
    assert "Upper bound" in result.clock_offset_basis


# --- the HAR ---------------------------------------------------------------


def test_har_requests_are_read_with_host_status_and_server_address(tmp_path):
    har = tmp_path / "session.har"
    har.write_text(
        json.dumps(
            {
                "log": {
                    "entries": [
                        {
                            "startedDateTime": "2026-08-10T17:59:35.270-04:00",
                            "time": 123.4,
                            "request": {"method": "get", "url": "https://www.youtube.com/watch"},
                            "response": {"status": 200, "content": {"size": 2048}},
                            "serverIPAddress": "7.189.58.248",
                        },
                        {
                            "startedDateTime": "not a date",
                            "request": {"method": "GET", "url": "https://i.ytimg.com/a.jpg"},
                            "response": {"status": 404, "content": {}},
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    requests = extract_web_requests(str(har))

    assert requests[0].host == "www.youtube.com"
    assert requests[0].method == "GET"
    assert requests[0].server_ip == "7.189.58.248"
    assert requests[0].bytes == 2048
    assert not requests[0].failed
    # A malformed timestamp must lose the timestamp, not the request.
    assert requests[1].started is None
    assert requests[1].failed


@pytest.mark.parametrize("missing", ["capture", "bundle", "har"])
def test_a_missing_artefact_is_recorded_rather_than_glossed_over(missing):
    """Silence must never be readable as health."""
    at = datetime(2026, 8, 10, 18, 0, 0)
    wire = [] if missing == "capture" else [_wire(1, 59612, "35.153.171.158", at=at)]
    agent = [] if missing == "bundle" else [_agent(59612, "35.153.171.158", at)]
    har = (
        []
        if missing == "har"
        else [
            WebRequest(
                url="https://x.example/",
                host="x.example",
                method="GET",
                status=200,
                server_ip=None,
                started=at,
                duration_ms=1.0,
            )
        ]
    )

    result = correlate_session(wire, agent, har)

    assert result.notes, f"a missing {missing} produced no note"


# --- host-named app flows --------------------------------------------------
#
# The agent writes a second, differently punctuated identifier for the flow
# between the application and its own listener, naming the destination the
# application asked for. It is the only place any artefact states both a
# recognisable destination and the source port that leads into the capture.

_APP_LOG = """\
2026-08-10 17:19:53.863412 csc_zta_agent[0x1244/T, 0xda0] E/ AppSocketTransport.cpp:245 \
AppSocketTransport::handleConnectTimeout() tcp:50231__www.example.com 1C0226C8 stream=85 connect timeout
2026-08-10 17:19:53.863500 csc_zta_agent[0x1244/T, 0xda0] I/ Http2MuxTransport.cpp:1220 \
Http2MuxTransport::handleNghttp2StreamCloseCB() http2_50300__198.51.100.7:443 15D54BAC stream=85 code=5
2026-08-10 17:19:53.864430 csc_zta_agent[0x1244/T, 0xda0] E/ AppSocketTransport.cpp:1002 \
AppSocketTransport::handleClose() tcp:50231__www.example.com 1C0226C8 stream=85 closing due to reason: connect_timeout
"""


def _write(tmp_path, text: str) -> str:
    path = tmp_path / "ZeroTrustAccess.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_app_flow_records_destination_port_stream_and_reason(tmp_path):
    from atlas_core.flows import extract_app_flows

    flows = extract_app_flows(_write(tmp_path, _APP_LOG))
    assert len(flows) == 1
    flow = flows[0]
    assert flow.dest == "www.example.com"
    assert flow.src_port == 50231
    assert flow.stream == 85
    assert flow.reasons == ("connect_timeout",)
    assert flow.error_lines == 2
    assert flow.label == "tcp:50231__www.example.com"


def test_app_flow_is_not_confused_with_the_tunnel_identifier(tmp_path):
    """The two identifiers differ only in punctuation; both must be read."""
    from atlas_core.flows import extract_app_flows

    path = _write(tmp_path, _APP_LOG)
    app = extract_app_flows(path)
    tunnels = extract_agent_flows(path)
    assert [f.dest for f in app] == ["www.example.com"]
    assert [t.label for t in tunnels] == ["http2_50300__198.51.100.7:443"]


def test_flow_is_followed_from_destination_through_port_to_the_wire(tmp_path):
    from atlas_core.flows import extract_app_flows

    path = _write(tmp_path, _APP_LOG)
    wire = _wire(1, 50231, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555)
    session = correlate_session(
        [wire],
        extract_agent_flows(path),
        [WebRequest("https://www.example.com/", "www.example.com", "GET", 502, None, None, None)],
        extract_app_flows(path),
    )
    assert len(session.flows) == 1
    flow = session.flows[0]
    assert flow.wire is wire
    assert flow.wire_strength is JoinStrength.EXACT
    assert flow.tunnel is not None and flow.tunnel.label == "http2_50300__198.51.100.7:443"
    assert len(flow.failures) == 1
    assert flow.severity == "problem"


def test_a_reused_source_port_refuses_the_wire_join_and_says_so(tmp_path):
    """Two captured flows from one port cannot both be this flow."""
    from atlas_core.flows import extract_app_flows

    path = _write(tmp_path, _APP_LOG)
    session = correlate_session(
        [_wire(1, 50231, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555),
         _wire(2, 50231, "203.0.113.9")],
        extract_agent_flows(path),
        [],
        extract_app_flows(path),
    )
    flow = session.flows[0]
    assert flow.wire is None
    assert "cannot be told" in flow.wire_basis
    assert any("same source port" in n for n in session.notes)


def test_the_error_only_caveat_is_always_stated(tmp_path):
    """A short list must never be read as a clean bill of health."""
    from atlas_core.flows import as_payload, extract_app_flows

    path = _write(tmp_path, _APP_LOG)
    session = correlate_session([], extract_agent_flows(path), [], extract_app_flows(path))
    payload = as_payload(session)
    assert payload["summary"]["intercepted_flows"] == 1
    assert any("not one that is known to have worked" in n for n in payload["notes"])


def test_explanation_cites_each_artefact_it_used(tmp_path):
    from atlas_core.flows import as_payload, extract_app_flows

    path = _write(tmp_path, _APP_LOG)
    session = correlate_session(
        [_wire(1, 50231, "127.0.0.1", src_ip="127.0.0.1", dst_port=52555)],
        extract_agent_flows(path),
        [WebRequest("https://www.example.com/", "www.example.com", "GET", 200, None, None, None)],
        extract_app_flows(path),
    )
    flow = as_payload(session)["flows"][0]
    assert "www.example.com" in flow["explanation"]
    assert "50231" in flow["explanation"]
    assert "connect_timeout" in flow["explanation"]
    assert {e["source"] for e in flow["evidence"]} == {"bundle", "capture", "har"}
