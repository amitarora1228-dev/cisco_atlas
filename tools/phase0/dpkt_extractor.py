"""A tshark-free reader for the ``WireFlow`` contract, built on dpkt.

Phase 0 exists to answer one question: can ATLAS read a capture without a
Wireshark binary, closely enough that the correlation layer reaches the same
conclusions? This module is the candidate. It is deliberately written against
the *existing* contract in ``atlas_core.flows.WireFlow`` so that nothing
downstream has to change if it succeeds.

What it does not do is as important as what it does:

* TLS decryption with a key log is not attempted. tshark does that with the
  full Wireshark TLS stack; nothing in pure Python comes close, and pretending
  otherwise would hide a real capability loss.
* ``tcp.analysis.*`` is *derived* by tshark, not read from the wire. The
  counters here are reimplementations of those heuristics and are expected to
  disagree at the margins. Phase 0 measures that disagreement rather than
  assuming it away.
"""
from __future__ import annotations

import gzip
import socket
import struct
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import dpkt

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packages" / "atlas_core"))

from atlas_core.flows import WireFlow  # noqa: E402

_MAX_LADDER = 40
"""How many opening and closing packets to keep, matching ``_PACKET_EDGE`` in
the production reader. Enough to draw a ladder, never proportional to the flow
length."""

_TLS_VERSIONS = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def _open(path: str):
    """Open a capture, transparently decompressing a gzipped one.

    tshark decompresses on the fly, so captures arrive gzipped often enough that
    refusing them would be a regression rather than an edge case.
    """
    with open(path, "rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(path, "rb")
    return open(path, "rb")  # noqa: SIM115 - caller owns the handle


def _reader(handle):
    """pcap or pcapng, decided by the magic number rather than the extension."""
    magic = handle.read(4)
    handle.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(handle)
    return dpkt.pcap.Reader(handle)


def _ip_of(buf: bytes, linktype: int):
    """Pull the IP layer out, whatever the capture was taken on.

    An endpoint capture holds a loopback leg and a physical leg at once, so the
    link layer varies inside one file and cannot be assumed.
    """
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            frame = dpkt.ethernet.Ethernet(buf)
            payload = frame.data
            # 802.1Q: dpkt unwraps this into .data already in recent versions,
            # but a stacked tag can leave a VLAN object behind.
            while isinstance(payload, dpkt.ethernet.VLANtag8021Q):
                payload = payload.data
            return payload
        if linktype in (dpkt.pcap.DLT_NULL, dpkt.pcap.DLT_LOOP):
            return dpkt.loopback.Loopback(buf).data
        if linktype == dpkt.pcap.DLT_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if linktype == dpkt.pcap.DLT_RAW:
            version = (buf[0] >> 4) if buf else 0
            return dpkt.ip.IP(buf) if version == 4 else dpkt.ip6.IP6(buf)
    except Exception:
        return None
    return None


def _addr(raw: bytes) -> str:
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    try:
        return socket.inet_ntop(family, raw)
    except ValueError:
        return raw.hex()


def _sni_and_alpn(payload: bytes) -> tuple[str | None, tuple[str, ...], str | None]:
    """Parse a TLS ClientHello for SNI and ALPN.

    Only the common case - a ClientHello that fits in one segment - is handled.
    A hello split across segments needs stream reassembly, which tshark does and
    this does not; those are counted as misses in the fidelity report rather
    than silently returned as "no SNI".
    """
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None, (), None
        record_code = struct.unpack("!H", payload[1:3])[0]
        # Handshake header: type(1) length(3)
        pos = 5
        if payload[pos] != 0x01:  # not a ClientHello
            return None, (), _TLS_VERSIONS.get(record_code)
        pos += 4
        pos += 2  # client_version
        pos += 32  # random
        if pos >= len(payload):
            return None, (), _TLS_VERSIONS.get(record_code)
        session_len = payload[pos]
        pos += 1 + session_len
        if pos + 2 > len(payload):
            return None, (), _TLS_VERSIONS.get(record_code)
        cipher_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_len
        if pos >= len(payload):
            return None, (), _TLS_VERSIONS.get(record_code)
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None, (), _TLS_VERSIONS.get(record_code)
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(pos + ext_total, len(payload))

        sni: str | None = None
        alpn: list[str] = []
        best = None
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            body = payload[pos:pos + ext_len]
            pos += ext_len
            if ext_type == 0x0000 and len(body) >= 5:  # server_name
                name_len = struct.unpack("!H", body[3:5])[0]
                # Deliberately not the "idna" codec: it validates, and raises on
                # names that are perfectly ordinary on the wire. SNI is carried
                # as ASCII, and a name this tool cannot decode is still worth
                # reporting verbatim rather than losing to an exception.
                sni = body[5:5 + name_len].decode("ascii", errors="replace")
            elif ext_type == 0x0010 and len(body) >= 2:  # ALPN
                inner = body[2:]
                while inner:
                    size = inner[0]
                    alpn.append(inner[1:1 + size].decode("ascii", errors="replace"))
                    inner = inner[1 + size:]
            elif ext_type == 0x002B and len(body) >= 3:  # supported_versions
                # TLS 1.3 negotiates here, not in the record header, which still
                # says 1.2 for compatibility. Taking the record header alone
                # would report every 1.3 connection as 1.2.
                offered = body[1:]
                for index in range(0, len(offered) - 1, 2):
                    code = struct.unpack("!H", offered[index:index + 2])[0]
                    if code in _TLS_VERSIONS and (best is None or code > best):
                        best = code
        version = _TLS_VERSIONS.get(best) if best else _TLS_VERSIONS.get(record_code)
        return sni, tuple(alpn), version
    except Exception:
        return None, (), None


_HANDSHAKE_NAMES = {
    0x01: "clienthello", 0x02: "serverhello", 0x0B: "certificate",
    0x0C: "serverkeyexchange", 0x0E: "serverhellodone",
    0x10: "clientkeyexchange", 0x14: "finished",
}


def extract_wire_flows_dpkt(capture_path: str) -> list[WireFlow]:
    """Read TCP flows out of a capture with no external binary.

    Flows are keyed by the unordered endpoint pair. tshark keys on
    ``tcp.stream``, which it assigns in order of first appearance; that ordering
    is reproduced here so stream numbers line up, but the join used everywhere
    else is the endpoint pair, which is stable across both readers.
    """
    building: dict[tuple, dict] = {}
    order: list[tuple] = []
    generation: dict[tuple, int] = {}

    handle = _open(capture_path)
    try:
        reader = _reader(handle)
        try:
            linktype = reader.datalink()
        except Exception:
            linktype = dpkt.pcap.DLT_EN10MB

        for epoch, buf in reader:
            ip = _ip_of(buf, linktype)
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            src, dst = _addr(ip.src), _addr(ip.dst)
            a, b = (src, tcp.sport), (dst, tcp.dport)
            pair = tuple(sorted([a, b]))

            # An ephemeral port is reused within a capture, so a 5-tuple is not
            # a connection - it is a connection *slot*. A fresh SYN carrying a
            # different initial sequence number opens a new occupant of that
            # slot, and merging the two would fuse unrelated connections into
            # one confident, wrong flow. tshark draws the same distinction with
            # tcp.stream; this reproduces it.
            syn_flag = bool(tcp.flags & dpkt.tcp.TH_SYN)
            ack_flag = bool(tcp.flags & dpkt.tcp.TH_ACK)
            current = generation.setdefault(pair, 0)
            if syn_flag and not ack_flag:
                existing = building.get((pair, current))
                if existing and existing["isn"] is not None and existing["isn"] != tcp.seq:
                    current += 1
                    generation[pair] = current
            key = (pair, current)

            state = building.get(key)
            if state is None:
                state = {
                    "client": None, "server": None, "anchored": False,
                    "packets": 0, "bytes": 0,
                    "first": epoch, "last": epoch, "has_syn": False,
                    "isn": None, "peer_isn": None, "syn_at": None,
                    "sni": None, "alpn": (), "tls_version": None,
                    "handshake": [], "alerts": [],
                    "payload": defaultdict(int),
                    "seen_seq": defaultdict(set), "max_seq": defaultdict(int),
                    "retrans": 0, "dup_ack": 0, "zero_win": 0, "ooo": 0,
                    "last_ack": {}, "ack_repeat": defaultdict(int),
                    "rtts": [], "handshake_rtt": None, "awaiting": defaultdict(dict),
                    "head": [], "tail": [],
                    "http_methods": [], "http_statuses": [], "first_uri": None,
                }
                building[key] = state
                order.append(key)

            syn = bool(tcp.flags & dpkt.tcp.TH_SYN)
            ack = bool(tcp.flags & dpkt.tcp.TH_ACK)
            rst = bool(tcp.flags & dpkt.tcp.TH_RST)
            fin = bool(tcp.flags & dpkt.tcp.TH_FIN)
            body = bytes(tcp.data)
            side = (src, tcp.sport)

            # Getting direction right is not cosmetic: the source port is half
            # the key the agent records, so a flow held the wrong way round
            # simply fails to join. A SYN without an ACK names the client beyond
            # doubt; absent one, the production reader takes the lower port to
            # be the listener, and that rule is reproduced here rather than
            # substituted for - a different tie-break is a different answer.
            if syn and not ack:
                state["client"] = side
                state["server"] = (dst, tcp.dport)
                state["anchored"] = True
                state["has_syn"] = True
                state["isn"] = tcp.seq
                state["syn_at"] = epoch
            elif syn and ack:
                if state["client"] is None:
                    state["client"] = (dst, tcp.dport)
                    state["server"] = side
                state["peer_isn"] = tcp.seq
                if state["syn_at"] is not None and state["handshake_rtt"] is None:
                    state["handshake_rtt"] = epoch - state["syn_at"]
            elif state["client"] is None:
                state["client"] = side
                state["server"] = (dst, tcp.dport)

            if not state["anchored"] and state["client"] and state["server"]:
                if state["client"][1] < state["server"][1]:
                    state["client"], state["server"] = state["server"], state["client"]

            state["packets"] += 1
            state["bytes"] += len(buf)
            state["last"] = epoch
            state["first"] = min(state["first"], epoch)
            state["payload"][side] += len(body)

            if tcp.win == 0 and not rst and not syn:
                state["zero_win"] += 1

            # Retransmission and out-of-order, approximating tshark's heuristics.
            if body or syn or fin:
                span = len(body) + (1 if (syn or fin) else 0)
                if tcp.seq in state["seen_seq"][side]:
                    state["retrans"] += 1
                elif state["max_seq"][side] and tcp.seq < state["max_seq"][side]:
                    state["ooo"] += 1
                state["seen_seq"][side].add(tcp.seq)
                state["max_seq"][side] = max(state["max_seq"][side], tcp.seq + span)
                # Remember when this data ended so the ACK that covers it can be
                # timed. Only the first transmission counts: an ACK for data
                # that was retransmitted measures the retransmission, not a
                # round trip.
                state["awaiting"][side].setdefault(tcp.seq + span, epoch)
            elif ack:
                previous = state["last_ack"].get(side)
                if previous == tcp.ack:
                    state["ack_repeat"][side] += 1
                    if state["ack_repeat"][side] >= 1:
                        state["dup_ack"] += 1
                else:
                    state["ack_repeat"][side] = 0
                state["last_ack"][side] = tcp.ack

            # Round trips, measured only from ACKs arriving *from the peer*. An
            # ACK this host sends measures how fast its own stack replied to
            # data already in memory - microseconds, with no network in it.
            if ack:
                peer = (dst, tcp.dport)
                sent_at = state["awaiting"][peer].pop(tcp.ack, None)
                if sent_at is not None and side != state["client"]:
                    state["rtts"].append(epoch - sent_at)

            if body:
                if state["sni"] is None and body[0] == 0x16:
                    sni, alpn, version = _sni_and_alpn(body)
                    if sni:
                        state["sni"] = sni
                    if alpn:
                        state["alpn"] = alpn
                    if version:
                        state["tls_version"] = version
                if body[0] == 0x16 and len(body) > 5:
                    name = _HANDSHAKE_NAMES.get(body[5])
                    if name and name not in state["handshake"]:
                        state["handshake"].append(name)
                elif body[0] == 0x15:
                    state["alerts"].append("alert")
                else:
                    head = body[:8]
                    for verb in (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"CONNECT"):
                        if head.startswith(verb):
                            method = verb.decode()
                            if method not in state["http_methods"]:
                                state["http_methods"].append(method)
                            if state["first_uri"] is None:
                                parts = body.split(b" ", 2)
                                if len(parts) > 1:
                                    state["first_uri"] = parts[1].decode("ascii", "replace")
                            break
                    if head.startswith(b"HTTP/"):
                        parts = body.split(b" ", 2)
                        if len(parts) > 1:
                            code = parts[1].decode("ascii", "replace")
                            if code not in state["http_statuses"]:
                                state["http_statuses"].append(code)

            kind = "SYN" if syn and not ack else "SYN-ACK" if syn else \
                   "RST" if rst else "FIN" if fin else "ACK" if not body else "DATA"
            rung = (epoch, src, tcp.sport, kind, len(body))
            if len(state["head"]) < _MAX_LADDER:
                state["head"].append(rung)
            state["tail"].append(rung)
            if len(state["tail"]) > _MAX_LADDER:
                state["tail"].pop(0)

    finally:
        handle.close()

    flows: list[WireFlow] = []
    for index, key in enumerate(order):
        state = building[key]
        client = state["client"] or key[0][0]
        server = state["server"] or key[0][1]
        flows.append(WireFlow(
            stream=index,
            src_ip=client[0], src_port=client[1],
            dst_ip=server[0], dst_port=server[1],
            sni=state["sni"],
            packets=state["packets"], bytes=state["bytes"],
            first_seen=datetime.fromtimestamp(state["first"]),
            last_seen=datetime.fromtimestamp(state["last"]),
            has_syn=state["has_syn"],
            isn=state["isn"], peer_isn=state["peer_isn"],
            rtts=tuple(state["rtts"]),
            retransmissions=state["retrans"],
            duplicate_acks=state["dup_ack"],
            zero_windows=state["zero_win"],
            out_of_order=state["ooo"],
            handshake_rtt=state["handshake_rtt"],
            head=tuple(state["head"]), tail=tuple(state["tail"]),
            tls_version=state["tls_version"],
            alpn=tuple(state["alpn"]),
            handshake_seen=tuple(state["handshake"]),
            tls_alerts=tuple(state["alerts"]),
            http_methods=tuple(state["http_methods"]),
            http_statuses=tuple(state["http_statuses"]),
            first_uri=state["first_uri"],
            client_bytes=state["payload"].get(client, 0),
            server_bytes=state["payload"].get(server, 0),
        ))
    return flows
