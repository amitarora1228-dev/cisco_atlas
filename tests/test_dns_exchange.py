"""What a DNS conversation asked for, and what came back.

Address-keyed correlation cannot answer this: it ties a flow's *destination*
back to the name that produced it, so the DNS flow itself - whose destination is
the resolver - was left with nothing to say.
"""

from __future__ import annotations

from capture_inspector.engine import connection_story, enrich_flow
from capture_inspector.pcap import Flow, Packet

CLIENT, RESOLVER = "10.0.0.5", "208.67.222.222"


def _dns_pkt(n: int, t: float, src: str, **raw) -> Packet:
    fields = {"ip.src": [src], "ip.dst": [RESOLVER if src == CLIENT else CLIENT],
              "frame.protocols": ["eth:ethertype:ip:udp:dns"]}
    for key, value in raw.items():
        fields[key.replace("__", ".")] = value if isinstance(value, list) else [value]
    return Packet(number=n, time_epoch=1000.0 + t, time_relative=t, length=90, raw=fields)


def _dns_flow(packets: list[Packet]) -> Flow:
    flow = Flow(key="udp:1", transport="udp", src_ip=CLIENT, dst_ip=RESOLVER,
                src_port=51000, dst_port=53, packets=packets)
    enrich_flow(flow)
    return flow


def _dns_layer(flow: Flow) -> dict:
    story = connection_story(flow)
    return next(x for x in story["layers"] if x["name"] == "DNS")


def _exchange(name: str, qtype: str = "1", **response) -> list[Packet]:
    query = _dns_pkt(1, 0.0, CLIENT, dns__id="0x1234", dns__qry__name=name,
                     dns__qry__type=qtype, dns__flags__response="0")
    if not response:
        return [query]
    return [query, _dns_pkt(2, 0.02, RESOLVER, dns__id="0x1234", dns__qry__name=name,
                            dns__qry__type=qtype, dns__flags__response="1", **response)]


def test_the_addresses_a_name_resolved_to_are_reported():
    flow = _dns_flow(_exchange("example.com", dns__flags__rcode="0",
                               dns__a=["93.184.216.34", "93.184.216.35"]))
    layer = _dns_layer(flow)

    assert layer["status"] == "ok"
    assert "93.184.216.34" in layer["steps"][1]["msg"]
    assert any(f["value"].startswith("93.184.216.34") for f in layer["facts"])


def test_the_resolver_that_answered_is_named():
    flow = _dns_flow(_exchange("example.com", dns__flags__rcode="0", dns__a="93.184.216.34"))

    resolver = _dns_layer(flow)["facts"][0]
    assert resolver["label"] == "Resolver"
    assert RESOLVER in resolver["value"]


def test_a_lookup_answered_by_loopback_is_flagged():
    """Loopback means software on this host answered, not the network."""
    packets = _exchange("example.com", dns__flags__rcode="0", dns__a="93.184.216.34")
    flow = Flow(key="udp:1", transport="udp", src_ip=CLIENT, dst_ip="127.0.0.1",
                src_port=51000, dst_port=53, packets=packets)
    enrich_flow(flow)

    assert _dns_layer(flow)["facts"][0]["tone"] == "warn"


def test_a_cname_chain_is_kept():
    flow = _dns_flow(_exchange("aadcdn.msauth.net", dns__flags__rcode="0",
                               dns__a="13.107.246.67",
                               dns__cname=["a.trafficmanager.net", "b.azureedge.net"]))

    via = next(f for f in _dns_layer(flow)["facts"] if f["label"].endswith("via"))
    assert "a.trafficmanager.net" in via["value"]


def test_nxdomain_is_named_not_shown_as_a_code():
    flow = _dns_flow(_exchange("nope.example", dns__flags__rcode="3"))
    layer = _dns_layer(flow)

    assert layer["status"] == "fail"
    assert "NXDOMAIN" in layer["steps"][1]["msg"]


def test_a_query_with_no_reply_is_not_reported_as_resolved():
    flow = _dns_flow(_exchange("silent.example"))
    layer = _dns_layer(flow)

    assert layer["status"] == "fail"
    assert "unanswered" in layer["summary"]


def test_an_empty_aaaa_answer_is_not_flagged():
    """A name with no IPv6 address answers NODATA. That is ordinary, not a fault."""
    flow = _dns_flow(_exchange("example.com", qtype="28", dns__flags__rcode="0"))
    layer = _dns_layer(flow)

    assert layer["status"] == "ok"
    assert all(f["tone"] != "warn" for f in layer["facts"] if f["label"] != "Resolver")


def test_the_query_type_is_named_rather_than_assumed_to_be_a():
    flow = _dns_flow(_exchange("example.com", qtype="65", dns__flags__rcode="0"))

    assert "Query HTTPS?" in _dns_layer(flow)["steps"][0]["msg"]


def test_several_lookups_on_one_conversation_are_kept_apart():
    """TCP resolvers and pipelined UDP carry many lookups; the transaction ID
    (RFC 1035 s4.1.1) is what makes a query and its reply one exchange."""
    packets = [
        _dns_pkt(1, 0.0, CLIENT, dns__id="0x1", dns__qry__name="one.example",
                 dns__qry__type="1", dns__flags__response="0"),
        _dns_pkt(2, 0.0, CLIENT, dns__id="0x2", dns__qry__name="two.example",
                 dns__qry__type="1", dns__flags__response="0"),
        _dns_pkt(3, 0.02, RESOLVER, dns__id="0x2", dns__qry__name="two.example",
                 dns__qry__type="1", dns__flags__response="1",
                 dns__flags__rcode="0", dns__a="10.1.1.2"),
        _dns_pkt(4, 0.03, RESOLVER, dns__id="0x1", dns__qry__name="one.example",
                 dns__qry__type="1", dns__flags__response="1",
                 dns__flags__rcode="0", dns__a="10.1.1.1"),
    ]
    flow = _dns_flow(packets)

    assert len(flow.dns_exchanges) == 2
    answers = {e["name"]: e["addresses"] for e in flow.dns_exchanges}
    assert answers == {"one.example": ["10.1.1.1"], "two.example": ["10.1.1.2"]}


def test_a_flow_that_is_not_dns_gets_no_exchange():
    flow = Flow(key="tcp:1", transport="tcp", src_ip=CLIENT, dst_ip="93.184.216.34",
                src_port=51000, dst_port=443,
                packets=[Packet(number=1, time_epoch=1000.0, time_relative=0.0, length=60,
                                raw={"ip.src": [CLIENT], "tcp.flags.syn": ["1"]})])
    enrich_flow(flow)

    assert flow.dns_exchanges == []
