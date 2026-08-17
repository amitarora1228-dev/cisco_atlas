"""FastAPI server for the Capture Inspector web app."""
from __future__ import annotations

import os
import re
import tempfile
from datetime import datetime, timezone

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .analyze import AnalysisContext, analyze
from .certs import evaluate_at, secure_access_chain
from .certfetch import fetch_certificate
from .dns_analysis import dns_summary
from .engine import Finding
from .engine import _is_loopback
from .engine import connection_story, flow_timeline
from .pcap import find_tshark
from .report import render_report
from .secure_access import lookup_ingress_region

app = FastAPI(title="Capture Inspector", version="1.0.0")

_HERE = os.path.dirname(os.path.abspath(__file__))
_STATIC_DIR = os.path.join(_HERE, "static")

# Upload safety cap. Large captures (above ~80 MB) are decoded in a reduced mode
# by the engine, so we allow files well past that here.
MAX_BYTES = 1024 * 1024 * 1024  # 1 GB safety cap


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    # The page ships absolute asset paths so it works when this engine is served
    # at the origin root. Under ATLAS it is mounted at a prefix, so rewrite them
    # and hand the prefix to the frontend for its API calls. root_path is empty
    # when running standalone, which leaves the markup untouched.
    with open(os.path.join(_STATIC_DIR, "index.html"), encoding="utf-8") as f:
        html = f.read()

    # The markup carries a hand-written ?v= stamp, which never changes when the
    # file does - so a browser goes on serving a cached app.js after an edit,
    # and the edit looks like it had no effect. Restamp with the file's own
    # modification time, the way the ATLAS shell already does for its assets.
    for name in ("app.js", "style.css"):
        stamp = 0
        try:
            stamp = int(os.path.getmtime(os.path.join(_STATIC_DIR, name)))
        except OSError:
            pass
        html = re.sub(
            r'(/static/' + re.escape(name) + r')\?v=\d+',
            r"\g<1>?v=" + str(stamp),
            html,
        )

    prefix = request.scope.get("root_path", "").rstrip("/")
    if prefix:
        html = html.replace('="/static/', f'="{prefix}/static/')
    html = html.replace(
        "</head>", f'<script>window.API_BASE="{prefix}";</script>\n</head>', 1
    )
    return HTMLResponse(html)


@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok",
        "tshark": find_tshark() or "NOT FOUND",
    })


def _decryption_status(f, fr) -> str:
    """Classify a flow's TLS-inspection posture from passively observable facts.

    - "decrypted":   a visible leaf certificate was re-signed by a proxy/SWG CA
                     (e.g. Cisco Secure Access) -> SSL inspection is active.
    - "passthrough": a visible leaf certificate from the real public CA
                     (e.g. DigiCert/Amazon/Microsoft) -> NOT decrypted.
    - "tunnel":      opaque HTTP CONNECT tunnel; payload not decrypted by us.
    - "encrypted":   TLS 1.3 handshake where the certificate is encrypted and
                     therefore invisible to a passive capture (cannot tell).
    - "unknown":     not enough evidence.
    """
    leaf = getattr(fr, "leaf_cert", None)
    if leaf and not leaf.parse_error and (leaf.issuer_cn or leaf.issuer_org):
        if leaf.is_secure_access:
            return "decrypted"
        return "decrypted" if leaf.looks_like_proxy_ca else "passthrough"
    if f.is_connect_tunnel:
        return "tunnel"
    ver = (f.tunnel_tls_version or f.negotiated_version or "")
    if "1.3" in ver:
        return "encrypted"
    return "unknown"


def _sa_chain(fr) -> dict | None:
    """Secure Access chain reference for a flow, or None if not applicable."""
    leaf = getattr(fr, "leaf_cert", None)
    chain = getattr(fr, "cert_chain", None) or []
    if not leaf:
        return None
    info = secure_access_chain(leaf, chain)
    return info if info.get("anchored") else None


def _handshake_ms(f) -> float | None:
    """Best-effort server response time in milliseconds: the gap between the
    client's ClientHello and the server's ServerHello (TLS handshake setup time).
    Returns None when both markers are not present in the capture."""
    t_ch = t_sh = None
    for p in f.packets:
        types = p.all("tls.handshake.type")
        if t_ch is None and "1" in types:
            t_ch = p.time_relative
        if t_sh is None and "2" in types:
            t_sh = p.time_relative
        if t_ch is not None and t_sh is not None:
            break
    if t_ch is not None and t_sh is not None and t_sh >= t_ch:
        return round((t_sh - t_ch) * 1000.0, 1)
    return None


def _finding_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "severity": f.severity,
        "category": f.category,
        "detail": f.detail,
        "evidence": f.evidence,
        "flow_key": f.flow_key,
    }


_HOST_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "ok": 5}


def _strip_port(host: str) -> str:
    """Drop a trailing :port from a host string ('example.com:443' -> 'example.com')."""
    i = host.rfind(":")
    if i > 0 and host[i + 1:].isdigit():
        return host[:i]
    return host


def _primary_hostname(names: set, ip: str):
    """Pick the most representative hostname for a host (concrete, shortest)."""
    cands = [n for n in names if n and n != ip]
    if not cands:
        return None
    cands.sort(key=lambda n: (n.startswith("*"), len(n)))
    return cands[0]


def _ttl_profile(ttl):
    """Turn an observed IP TTL / IPv6 hop-limit into (hop_distance, os_guess).

    Common initial TTLs are 64 (Linux/Unix/macOS/Android/iOS), 128 (Windows) and
    255 (routers/switches/some Unix). The observed value is the initial minus the
    number of routed hops, so the smallest standard initial that is >= the value
    identifies the origin family and the hop count. This is an ESTIMATE — TTLs can
    be rewritten by middleboxes — so callers must label it as such."""
    if ttl is None or ttl <= 0:
        return None, None
    if ttl <= 64:
        initial, os_guess = 64, "Linux / Unix / macOS (est.)"
    elif ttl <= 128:
        initial, os_guess = 128, "Windows (est.)"
    else:
        initial, os_guess = 255, "Network device (est.)"
    return initial - ttl, os_guess


def _build_host_inventory(flows: list[dict]) -> list[dict]:
    """Aggregate the per-flow rows into a per-destination host inventory
    (NetworkMiner-style asset view). Purely derived from the already-built
    flow dicts, so it adds no new parsing and cannot change the analysis."""
    hosts: dict[str, dict] = {}
    for f in flows:
        ip = f.get("dst_ip")
        if not ip:
            continue
        h = hosts.get(ip)
        if h is None:
            h = hosts[ip] = {
                "ip": ip, "hostnames": set(), "ports": set(), "transports": set(),
                "protocols": set(), "tls_versions": set(), "ja3s": set(), "ja3": set(),
                "cert_issuers": set(), "clients": set(), "flow_count": 0, "bytes": 0,
                "pkts": 0, "first_seen": None, "last_seen": None, "proxy_ca": False,
                "first_seen_clock": None, "last_seen_clock": None,
                "intercept_vendor": None, "is_private_access": False, "is_internal": False,
                "block_category": None, "loopback": bool(f.get("loopback")),
                "worst_severity": None, "has_problem": False,
                "bytes_sent": 0, "bytes_recv": 0, "pkts_sent": 0, "pkts_recv": 0,
                "bytes_enc": 0, "bytes_clear": 0,
                "server_ttl": None, "open_ports": set(),
            }
        h["flow_count"] += 1
        for key in ("sni", "tunnel_sni", "resolved_host", "dns_query", "subject"):
            v = f.get(key)
            if v:
                h["hostnames"].add(v)
        ct = f.get("connect_target")
        if ct:
            h["hostnames"].add(_strip_port(ct))
        for s in (f.get("san") or []):
            if s and not s.startswith("*"):
                h["hostnames"].add(s)
        if f.get("dst_port"):
            h["ports"].add(f["dst_port"])
        if f.get("transport"):
            h["transports"].add(f["transport"])
        if f.get("is_quic"):
            h["transports"].add("QUIC")
        if f.get("l7_protocol"):
            h["protocols"].add(f["l7_protocol"])
        alpn = f.get("alpn")
        if alpn:
            if isinstance(alpn, (list, tuple)):
                h["protocols"].update(str(a) for a in alpn if a)
            else:
                h["protocols"].add(str(alpn))
        for key in ("negotiated_version", "tunnel_tls_version"):
            v = f.get(key)
            if v:
                h["tls_versions"].add(v)
        if f.get("ja3s"):
            h["ja3s"].add(f["ja3s"])
        if f.get("ja3"):
            h["ja3"].add(f["ja3"])
        if f.get("issuer"):
            h["cert_issuers"].add(f["issuer"])
        if f.get("src_ip"):
            h["clients"].add(f["src_ip"])
        h["bytes"] += (f.get("bytes_c2s") or 0) + (f.get("bytes_s2c") or 0)
        h["pkts"] += f.get("pkt_count") or 0
        # Directional split from the HOST's perspective (host == dst_ip = server):
        # server->client (s2c) = sent BY the host; client->server (c2s) = received.
        c2s = f.get("bytes_c2s") or 0
        s2c = f.get("bytes_s2c") or 0
        h["bytes_sent"] += s2c
        h["bytes_recv"] += c2s
        h["pkts_sent"] += f.get("pkts_s2c") or 0
        h["pkts_recv"] += f.get("pkts_c2s") or 0
        # Encrypted vs cleartext: a flow counts as encrypted when any TLS/QUIC
        # signal was observed (SNI, negotiated version, JA3, QUIC or a CONNECT
        # tunnel). Otherwise its payload bytes are treated as cleartext.
        encrypted = bool(
            f.get("negotiated_version") or f.get("tunnel_tls_version") or f.get("ja3")
            or f.get("ja3s") or f.get("sni") or f.get("tunnel_sni") or f.get("is_quic")
            or f.get("is_connect_tunnel")
        )
        if encrypted:
            h["bytes_enc"] += c2s + s2c
        else:
            h["bytes_clear"] += c2s + s2c
        tr = f.get("time_rel")
        if tr is not None:
            if h["first_seen"] is None or tr < h["first_seen"]:
                h["first_seen"] = tr
                h["first_seen_clock"] = f.get("time")
            if h["last_seen"] is None or tr > h["last_seen"]:
                h["last_seen"] = tr
                h["last_seen_clock"] = f.get("time")
        if f.get("proxy_ca"):
            h["proxy_ca"] = True
        # Remote-host fingerprints: first observed TTL/hop-limit, and every port
        # the server confirmed open by answering with a SYN/ACK.
        if h["server_ttl"] is None and f.get("server_ttl") is not None:
            h["server_ttl"] = f.get("server_ttl")
        if f.get("server_synack") and f.get("dst_port"):
            h["open_ports"].add(f["dst_port"])
        if f.get("intercept_vendor") and not h["intercept_vendor"]:
            h["intercept_vendor"] = f["intercept_vendor"]
        if f.get("is_private_access"):
            h["is_private_access"] = True
        if f.get("is_internal"):
            h["is_internal"] = True
        if f.get("block_category") and not h["block_category"]:
            h["block_category"] = f["block_category"]
        if f.get("has_problem"):
            h["has_problem"] = True
        sv = f.get("worst_severity")
        if sv and _HOST_SEV_RANK.get(sv, 9) < _HOST_SEV_RANK.get(h["worst_severity"], 9):
            h["worst_severity"] = sv

    # Session direction per IP: incoming = this IP was the destination (someone
    # connected TO it); outgoing = this IP was the source (it initiated). Scans
    # both sides so hosts that both send and receive (e.g. loopback) are correct.
    inout: dict[str, list] = {}
    for f in flows:
        d, s = f.get("dst_ip"), f.get("src_ip")
        if d:
            inout.setdefault(d, [0, 0])[0] += 1
        if s:
            inout.setdefault(s, [0, 0])[1] += 1

    out = []
    for h in hosts.values():
        sess = inout.get(h["ip"], [0, 0])
        total_bytes = h["bytes_enc"] + h["bytes_clear"]
        cleartext_pct = round(100.0 * h["bytes_clear"] / total_bytes, 1) if total_bytes else 0.0
        hop_distance, os_guess = _ttl_profile(h["server_ttl"])
        out.append({
            "ip": h["ip"],
            "primary_host": _primary_hostname(h["hostnames"], h["ip"]),
            "hostnames": sorted(h["hostnames"]),
            "hostname_count": len(h["hostnames"]),
            "ports": sorted(h["ports"]),
            "transports": sorted(h["transports"]),
            "protocols": sorted(h["protocols"]),
            "tls_versions": sorted(h["tls_versions"]),
            "ja3s": sorted(h["ja3s"]),
            "ja3": sorted(h["ja3"]),
            "cert_issuers": sorted(h["cert_issuers"]),
            "clients": sorted(h["clients"]),
            "flow_count": h["flow_count"],
            "bytes": h["bytes"],
            "pkts": h["pkts"],
            "bytes_sent": h["bytes_sent"],
            "bytes_recv": h["bytes_recv"],
            "pkts_sent": h["pkts_sent"],
            "pkts_recv": h["pkts_recv"],
            "bytes_enc": h["bytes_enc"],
            "bytes_clear": h["bytes_clear"],
            "cleartext_pct": cleartext_pct,
            "sessions_in": sess[0],
            "sessions_out": sess[1],
            "ttl": h["server_ttl"],
            "hop_distance": hop_distance,
            "os_guess": os_guess,
            "open_ports": sorted(h["open_ports"]),
            "first_seen": h["first_seen"],
            "last_seen": h["last_seen"],
            "first_seen_clock": h["first_seen_clock"],
            "last_seen_clock": h["last_seen_clock"],
            "proxy_ca": h["proxy_ca"],
            "intercept_vendor": h["intercept_vendor"],
            "is_private_access": h["is_private_access"],
            "is_internal": h["is_internal"],
            "block_category": h["block_category"],
            "loopback": h["loopback"],
            "worst_severity": h["worst_severity"],
            "has_problem": h["has_problem"],
        })
    out.sort(key=lambda x: (_HOST_SEV_RANK.get(x["worst_severity"], 9), -x["bytes"], -x["flow_count"]))
    return out


def _har_rows(result) -> list[dict]:
    """Every HAR entry as a table-friendly row, each flagged as failed or not.

    This used to send only ``har.failed``, which made the flow table read as if
    the browser had done nothing but fail: a 158-entry HAR arrived as 19 rows,
    all of them errors. The table has a "Show only problems" control, so the
    filtering belongs there - and a request that succeeded is evidence too, not
    least because it proves the ones beside it did not.
    """
    if not result.har:
        return []
    failed = {id(e) for e in result.har.failed}
    rows = []
    for e in result.har.entries:
        ts = None
        if e.started:
            try:
                ts = datetime.fromtimestamp(e.started, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
            except (ValueError, OSError, OverflowError):
                ts = None
        rows.append({
            "time": ts,
            "failed": id(e) in failed,
            "host": e.host,
            "url": e.url,
            "method": e.method,
            "status": e.status,
            "status_text": e.status_text,
            "server_ip": e.server_ip,
            "http_version": e.http_version,
            "duration_ms": round(e.duration_ms, 1) if e.duration_ms is not None else None,
            "error": e.error_text,
            "error_label": e.error_label,
            "category": e.error_category,
            "block_type": e.block_type,
            "block_info": e.block_info,
            "t_blocked": round(e.t_blocked, 1) if e.t_blocked is not None else None,
            "t_dns": round(e.t_dns, 1) if e.t_dns is not None else None,
            "t_connect": round(e.t_connect, 1) if e.t_connect is not None else None,
            "t_ssl": round(e.t_ssl, 1) if e.t_ssl is not None else None,
            "t_send": round(e.t_send, 1) if e.t_send is not None else None,
            "t_wait": round(e.t_wait, 1) if e.t_wait is not None else None,
            "t_receive": round(e.t_receive, 1) if e.t_receive is not None else None,
            "req_body_bytes": e.req_body_bytes,
            "resp_body_bytes": e.resp_body_bytes,
            "content_bytes": e.content_bytes,
            "mime_type": e.mime_type,
            "post_mime": e.post_mime,
            "post_bytes": e.post_bytes,
            "query_params": e.query_params,
            "content_type": e.content_type,
            "location": e.location,
            "cache_control": e.cache_control,
            "set_cookie": e.set_cookie,
            "referer": e.referer,
            "origin": e.origin,
            "user_agent": e.user_agent,
            "sent_cookie": e.sent_cookie,
            "sent_auth": e.sent_auth,
            "resource_type": e.resource_type,
            "initiator": e.initiator,
            "req_header_count": e.req_header_count,
            "resp_header_count": e.resp_header_count,
            "via": e.via,
            "server_header": e.server_header,
            "alt_svc": e.alt_svc,
        })
    return rows


def _har_summary(har) -> dict:
    """Aggregate HAR proxy evidence (ingress, proxy nodes, QUIC/HTTP downgrade)."""
    from collections import Counter
    entries = har.entries
    ingress = Counter()
    server_ips = Counter()
    via_present = 0
    quic_stripped = 0
    ver = Counter()
    for e in entries:
        if e.server_ip:
            server_ips[e.server_ip] += 1
            region = lookup_ingress_region(e.server_ip)
            if region:
                ingress[region] += 1
        if e.via:
            via_present += 1
        if (e.alt_svc or "").strip().lower() == "clear":
            quic_stripped += 1
        if e.http_version:
            ver[e.http_version.lower()] += 1
    return {
        "total": len(entries),
        "failed": len(har.failed),
        "proxied_via_secure_access": sum(ingress.values()),
        "ingress_regions": dict(ingress.most_common()),
        "server_ips": dict(server_ips.most_common(8)),
        "via_present": via_present,
        "quic_stripped": quic_stripped,
        "http_versions": dict(ver.most_common()),
    }


@app.post("/api/analyze")
async def api_analyze(
    pcap: UploadFile | None = File(default=None),
    har: UploadFile | None = File(default=None),
    keylog: UploadFile | None = File(default=None),
    domain: str = Form(default=""),
    src_ip: str = Form(default=""),
    dst_ip: str = Form(default=""),
    platform: str = Form(default=""),
    policy: str = Form(default=""),
    expected: str = Form(default=""),
    actual: str = Form(default=""),
    timestamp: str = Form(default=""),
    resolve_certs: str = Form(default=""),
    secure_access: str = Form(default=""),
    sa_tunnel: str = Form(default=""),
) -> JSONResponse:
    if not pcap and not har:
        return JSONResponse({"error": "Provide at least a PCAP/PCAPNG or a HAR file."}, status_code=400)

    sa_mode = secure_access.lower() in ("1", "true", "on", "yes")
    sa_tunnel_on = sa_tunnel.lower() in ("1", "true", "on", "yes")
    ctx = AnalysisContext(
        domain=domain or None, src_ip=src_ip or None, dst_ip=dst_ip or None,
        platform=platform or None, policy=policy or None,
        expected=expected or None, actual=actual or None, timestamp=timestamp or None,
        secure_access_mode=sa_mode, sa_tunnel=sa_tunnel_on,
    )

    pcap_path = None
    tmp_files: list[str] = []
    try:
        if pcap and pcap.filename:
            data = await pcap.read()
            if len(data) > MAX_BYTES:
                return JSONResponse({"error": "PCAP exceeds 1 GB limit."}, status_code=413)
            suffix = ".pcapng" if pcap.filename.lower().endswith("pcapng") else ".pcap"
            fd, pcap_path = tempfile.mkstemp(suffix=suffix)
            os.write(fd, data)
            os.close(fd)
            tmp_files.append(pcap_path)

        har_text = None
        if har and har.filename:
            raw = await har.read()
            if len(raw) > MAX_BYTES:
                return JSONResponse({"error": "HAR exceeds 1 GB limit."}, status_code=413)
            har_text = raw.decode("utf-8", errors="replace")

        keylog_path = None
        if keylog and keylog.filename:
            kdata = await keylog.read()
            if len(kdata) > 16 * 1024 * 1024:
                return JSONResponse({"error": "Key log exceeds 16 MB limit."}, status_code=413)
            fd, keylog_path = tempfile.mkstemp(suffix=".keys")
            os.write(fd, kdata)
            os.close(fd)
            tmp_files.append(keylog_path)

        try:
            result = analyze(pcap_path, har_text, ctx, keylog_path=keylog_path)
        except Exception as exc:  # noqa: BLE001 - surface engine errors to UI
            return JSONResponse({"error": f"Analysis failed: {exc}"}, status_code=500)

        report_text = render_report(result)

        do_resolve = str(resolve_certs).lower() in ("1", "true", "on", "yes")
        resolved_count = 0

        flows = []
        for fr in result.flow_reports:
            f = fr.flow
            # Wall-clock + relative timestamp of the first packet of the flow
            ts_wall = None
            ts_rel = None
            pkt_range = None
            if f.packets:
                try:
                    ts_wall = datetime.fromtimestamp(f.start_time, tz=timezone.utc).strftime("%H:%M:%S.%f")[:-3]
                except (ValueError, OSError, OverflowError):
                    ts_wall = None
                ts_rel = round(f.packets[0].time_relative, 3)
                pkt_range = f"#{f.packets[0].number}\u2013#{f.packets[-1].number}"

            # Worst severity across findings (drives sorting + row colour)
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            worst = min((sev_rank.get(x.severity, 5) for x in fr.findings), default=99)
            worst_sev = next((k for k, v in sev_rank.items() if v == worst), None)
            # A flow is "healthy" only if it has no findings worse than info
            has_problem = any(x.severity in ("critical", "high", "medium", "low") for x in fr.findings)

            # Short human error summary for the table's Error column. Spelled
            # out, not abbreviated: "ooo x25" tells the reader nothing.
            err_bits = []
            for a in f.alerts:
                err_bits.append(f"{a['desc']} ({a['level']})")
            if f.rst_count:
                # A RST is only a "clean" close if a graceful FIN was also seen.
                # A bare RST with no FIN is an abrupt teardown — don't call it normal.
                if not has_problem and f.fin_count:
                    err_bits.append(f"TCP RST \u00d7{f.rst_count} (after FIN — clean close)")
                else:
                    err_bits.append(f"TCP RST \u00d7{f.rst_count}")
            if f.retransmissions:
                err_bits.append(f"{f.retransmissions} packet(s) sent again")
            if f.lost_segments:
                err_bits.append(f"{f.lost_segments} packet(s) lost")
            # Out-of-order is only real when the capture can actually show packet
            # order. On a host-side capture with segmentation offload the
            # "reordering" is the dissector reassembling super-segments that
            # never existed on the wire — reporting it here would contradict the
            # finding that already explained exactly that.
            _reorder_is_artifact = bool(getattr(f, "oversized_segments", 0)) and not (
                f.retransmissions or f.lost_segments or f.zero_window)
            if f.out_of_order and not _reorder_is_artifact:
                err_bits.append(f"{f.out_of_order} packet(s) arrived out of order")
            if f.zero_window:
                err_bits.append(f"receiver full {f.zero_window} time(s)")
            # Lead with the diagnosis when there is one. Raw counters such as
            # "25 packets sent again" can be capture artefacts (duplicated
            # interfaces, segmentation offload), and printing them first buries
            # the finding that explains what actually happened.
            lead = next((x.title for x in fr.findings
                         if x.severity in ("critical", "high", "medium")), None)
            if lead:
                err_bits.insert(0, lead)
            elif not err_bits and fr.findings:
                err_bits.append(fr.findings[0].title)
            error_summary = "; ".join(err_bits) if err_bits else ""

            # Optional active resolution: when the certificate isn't visible on
            # the wire (TLS 1.3 / CONNECT tunnel), look it up live by SNI.
            resolved = None
            if do_resolve and not fr.leaf_cert:
                probe_name = f.tunnel_sni or f.sni or (
                    f.connect_target.rsplit(":", 1)[0] if f.connect_target else None
                )
                if probe_name:
                    ci = fetch_certificate(probe_name)
                    if ci is not None:
                        if ci.parse_error:
                            resolved = {"host": probe_name, "error": ci.parse_error}
                        else:
                            resolved_count += 1
                            resolved = {
                                "host": probe_name,
                                "subject": ci.subject_cn,
                                "issuer": ci.issuer_cn or ci.issuer_org,
                                "san": ci.san_dns,
                                "valid": (f"{ci.not_before} \u2192 {ci.not_after}"),
                                "proxy_ca": ci.looks_like_proxy_ca,
                                "secure_access": ci.is_secure_access and sa_mode,
                            }

            flows.append({
                "key": f.key,
                "time": ts_wall,
                "time_rel": ts_rel,
                "pkt_range": pkt_range,
                "pkt_count": len(f.packets),
                "src": f"{f.src_ip}:{f.src_port}" if f.src_ip else "?",
                "dst": f"{f.dst_ip}:{f.dst_port}" if f.dst_ip else "?",
                "src_ip": f.src_ip,
                "dst_ip": f.dst_ip,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "loopback": _is_loopback(f.src_ip) or _is_loopback(f.dst_ip),
                "intercept_vendor": f.intercept_vendor,
                "chain_outbound_key": f.chain_outbound_key,
                "chain_loopback_key": f.chain_loopback_key,
                "sni": f.sni,
                "connect_target": f.connect_target,
                "connect_status": f.connect_status,
                "connect_phrase": f.connect_phrase,
                "is_connect_tunnel": f.is_connect_tunnel,
                "proxy_ip": f.proxy_ip,
                "proxy_provider": f.proxy_provider if sa_mode else None,
                "is_private_access": f.is_private_access and sa_mode,
                "is_internal": f.is_internal and sa_mode,
                "tunnel_sni": f.tunnel_sni,
                "tunnel_tls_version": f.tunnel_tls_version,
                "tunnel_client_hello": f.tunnel_client_hello,
                "tunnel_server_hello": f.tunnel_server_hello,
                "transport": f.transport,
                "is_quic": f.is_quic,
                "l7_protocol": f.l7_protocol,
                "dns_query": f.dns_query,
                "dns_resolver": f.dns_resolver,
                "resolved_host": f.resolved_host,
                "dns_lookup": f.dns_lookup,
                "dns_exchanges": f.dns_exchanges,
                "tls_status": fr.tls_status,
                "block_category": fr.block_category,
                "response_ms": _handshake_ms(f),
                "tcp_handshake_ms": f.tcp_handshake_ms,
                "tls_setup_ms": f.tls_setup_ms,
                "alpn": f.alpn,
                "negotiated_version": f.negotiated_version,
                "cipher": f.cipher_suite,
                "ja3": f.ja3,
                "ja3s": f.ja3s,
                "key_share_group": f.key_share_group,
                "rst": f.rst_count,
                "retransmissions": f.retransmissions,
                "lost_segments": f.lost_segments,
                "out_of_order": f.out_of_order,
                "dup_acks": f.dup_acks,
                "zero_window": f.zero_window,
                # Performance ceilings: not errors, so they carry no alert or
                # RST. They are exposed per flow so the UI can point at WHERE
                # the slowdown happened instead of only stating that it did.
                "window_full": f.window_full,
                "hello_retry_request": f.hello_retry_request,
                "hrr_offered_groups": f.hrr_offered_groups,
                "hrr_selected_group": f.hrr_selected_group,
                "ack_lost_segment": f.ack_lost_segment,
                "client_mss": f.client_mss,
                "pkts_c2s": f.pkts_c2s,
                "pkts_s2c": f.pkts_s2c,
                "bytes_c2s": f.bytes_c2s,
                "bytes_s2c": f.bytes_s2c,
                "server_ttl": f.server_ttl,
                "server_synack": f.server_synack,
                "timeline": flow_timeline(f),
                "story": connection_story(f, fr),
                "alerts": f.alerts,
                "issuer": (fr.leaf_cert.issuer_cn or fr.leaf_cert.issuer_org) if fr.leaf_cert else None,
                "subject": fr.leaf_cert.subject_cn if fr.leaf_cert else None,
                "san": fr.leaf_cert.san_dns if fr.leaf_cert else [],
                "cert_valid": (f"{fr.leaf_cert.not_before} \u2192 {fr.leaf_cert.not_after}"
                               if fr.leaf_cert and not fr.leaf_cert.parse_error else None),
                # Judged at the time of the traffic, not at the time of analysis:
                # otherwise every capture eventually reports its own certificates
                # as expired simply for having aged.
                "cert_expired": (
                    evaluate_at(fr.leaf_cert,
                                f.packets[0].time_epoch if f.packets else None).status
                    == "expired") if fr.leaf_cert else False,
                "proxy_ca": fr.leaf_cert.looks_like_proxy_ca if fr.leaf_cert else False,
                "secure_access_signed": (fr.leaf_cert.is_secure_access if fr.leaf_cert else False) and sa_mode,
                "secure_access_chain": _sa_chain(fr) if sa_mode else None,
                "inner_cert_decrypted": bool(f.tunnel_certificates_hex) and bool(fr.leaf_cert and fr.leaf_cert.subject_cn),
                "resolved_cert": resolved,
                "decryption_status": _decryption_status(f, fr),
                "worst_severity": worst_sev,
                "has_problem": has_problem,
                "error_summary": error_summary,
                "findings": [_finding_dict(x) for x in fr.findings],
            })

        notes = list(result.notes)
        if do_resolve:
            notes.append(
                f"Online certificate resolution: actively probed SNI hosts and retrieved {resolved_count} "
                f"live certificate(s). These reflect the server's current public certificate, not the on-the-wire "
                f"(possibly SWG-re-signed) copy."
            )

        return JSONResponse({
            "report_text": report_text,
            "reduced": result.reduced,
            "summary": {
                "diagnosis": result.summary_diagnosis,
                "confidence": result.confidence,
                "classifications": result.classifications,
                "primary_evidence": result.primary_evidence,
                "plain_summary": result.plain_summary,
                "plain_impact": result.plain_impact,
                "recommended_action": result.recommended_action,
                "plain_scope": result.plain_scope,
                "plain_secondary": result.plain_secondary,
                "tech_groups": result.tech_groups,
            },
            "flows": flows,
            "hosts": _build_host_inventory(flows),
            "har_entries": _har_rows(result),
            "findings": [_finding_dict(x) for x in result.all_findings],
            "correlations": result.correlations,
            "notes": notes,
            "capture_env": result.capture_env or None,
            "decryption": ({
                "keylog_used": True,
                "inner_tls_recovered": sum(
                    1 for fr in result.flow_reports if fr.flow.tunnel_certificates_hex),
                "tunnels": sum(
                    1 for fr in result.flow_reports if fr.flow.is_connect_tunnel),
            } if keylog_path else None),
            "roaming_report": (result.roaming_report or None) if sa_mode else None,
            # Capture-derived inspection coverage. Not SA-gated: measuring how
            # much of the traffic was inspected needs no vendor assumption, and
            # withholding it would leave the roaming panel showing only the
            # agent's own unusable totals.
            "steering_coverage": result.steering_coverage or None,
            "har_summary": None if not result.har else _har_summary(result.har),
            "dns": {
                "summary": dns_summary(result.dns_records),
                "records": [r.as_dict() for r in result.dns_records],
            },
        })
    finally:
        for p in tmp_files:
            try:
                os.remove(p)
            except OSError:
                pass


@app.get("/api/report", response_class=PlainTextResponse)
def report_placeholder() -> PlainTextResponse:
    return PlainTextResponse("POST to /api/analyze with a pcap and/or har file.")


# Static assets (served last so routes above take precedence)
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
