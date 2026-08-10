"""Latency findings: slow request phases from HAR timings (DNS/connect/TLS/TTFB)
and on-the-wire TCP/TLS handshake latency from PCAP flows."""
from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

from ..engine import Finding
from ..pcap import Flow
from ..har import HarResult
from ..context import AnalysisContext
from .base import _pctl, _flow_label
from .har_findings import _parse_via_nodes

# Latency thresholds (milliseconds). Tuned to surface genuinely slow phases
# without flagging normal web traffic. A SWG that re-terminates TLS inflates the
# connect/SSL/TTFB phases, so these doubling as interception signals is intended.
_LAT_TTFB_MS = 1000.0     # server think-time / time-to-first-byte
_LAT_SSL_MS = 500.0       # TLS handshake duration
_LAT_CONNECT_MS = 800.0   # TCP connect (incl. SSL per HAR spec)
_LAT_DNS_MS = 300.0       # name resolution
_LAT_PCAP_TLS_MS = 600.0  # on-wire ClientHello -> ServerHello
_LAT_PCAP_TCP_MS = 300.0  # on-wire SYN -> SYN/ACK round-trip

# AWS region code -> human geography, for the SWG egress-region latency note.
# Cisco Secure Access SWG nodes run in AWS, and their Via header carries the
# region (e.g. m_proxy_prod_aws_ap-northeast-1_1_1n -> ap-northeast-1).
_AWS_REGION_GEO = {
    "us-east-1": "N. Virginia, USA", "us-east-2": "Ohio, USA",
    "us-west-1": "N. California, USA", "us-west-2": "Oregon, USA",
    "ca-central-1": "Canada (Central)", "sa-east-1": "S\u00e3o Paulo, Brazil",
    "eu-west-1": "Ireland", "eu-west-2": "London, UK", "eu-west-3": "Paris, France",
    "eu-central-1": "Frankfurt, Germany", "eu-central-2": "Zurich, Switzerland",
    "eu-north-1": "Stockholm, Sweden", "eu-south-1": "Milan, Italy",
    "eu-south-2": "Spain", "ap-northeast-1": "Tokyo, Japan",
    "ap-northeast-2": "Seoul, South Korea", "ap-northeast-3": "Osaka, Japan",
    "ap-southeast-1": "Singapore", "ap-southeast-2": "Sydney, Australia",
    "ap-southeast-3": "Jakarta, Indonesia", "ap-south-1": "Mumbai, India",
    "ap-east-1": "Hong Kong", "me-south-1": "Bahrain", "me-central-1": "UAE",
    "af-south-1": "Cape Town, South Africa", "il-central-1": "Tel Aviv, Israel",
}

# ISO country codes seen in Google's `cr=` localization param / ccTLD hosts.
_COUNTRY_NAME = {
    "JP": "Japan", "US": "United States", "GB": "United Kingdom", "UK": "United Kingdom",
    "DE": "Germany", "FR": "France", "ES": "Spain", "IT": "Italy", "NL": "Netherlands",
    "BR": "Brazil", "IN": "India", "AU": "Australia", "CA": "Canada", "KR": "South Korea",
    "SG": "Singapore", "HK": "Hong Kong", "MX": "Mexico", "CH": "Switzerland",
    "SE": "Sweden", "IE": "Ireland", "AE": "United Arab Emirates", "ZA": "South Africa",
    "IL": "Israel", "ID": "Indonesia", "BH": "Bahrain",
}


def _latency_findings_har(har: HarResult) -> list[Finding]:
    """Flag slow HAR requests by timing phase (DNS / connect / TLS / TTFB).

    Uses the per-request `timings` breakdown that browsers already record, so it
    needs no extra capture. Reports aggregate p50/p95 plus the worst offenders."""
    out: list[Finding] = []
    entries = [e for e in har.entries if not e.blocked]
    if not entries:
        return out

    def _slow(attr: str, threshold: float, label: str, category_detail: str, sev: str = "medium"):
        rows = [(getattr(e, attr), e) for e in entries if getattr(e, attr) is not None]
        vals = [v for v, _ in rows]
        bad = [(v, e) for v, e in rows if v >= threshold]
        if not bad:
            return
        bad.sort(key=lambda x: x[0], reverse=True)
        p50 = _pctl(vals, 50)
        p95 = _pctl(vals, 95)
        worst = "; ".join(f"{e.host or e.url} ({round(v)} ms)" for v, e in bad[:5])
        out.append(Finding(
            title=f"Slow {label}: {len(bad)} request(s) \u2265 {round(threshold)} ms (p95 {round(p95)} ms)",
            severity=sev,
            category="latency",
            detail=(f"{len(bad)} of {len(rows)} request(s) spent \u2265 {round(threshold)} ms in the "
                    f"{label} phase (median {round(p50)} ms, p95 {round(p95)} ms). {category_detail} "
                    "Worst: " + worst + "."),
            evidence=[f"{label} p95={round(p95)}ms n_slow={len(bad)}"],
        ))

    _slow("t_wait", _LAT_TTFB_MS, "time-to-first-byte (server wait)",
          "High TTFB points at slow origin/app servers or an inspection hop adding round-trips.")
    _slow("t_ssl", _LAT_SSL_MS, "TLS handshake",
          "A slow TLS handshake often means an extra termination hop (SWG re-encryption) or a "
          "distant server.")
    _slow("t_connect", _LAT_CONNECT_MS, "TCP connect",
          "Slow connects suggest network distance/packet loss to the destination or proxy.", sev="low")
    _slow("t_dns", _LAT_DNS_MS, "DNS resolution",
          "Slow DNS can stall every request; check the resolver / roaming-agent path.", sev="low")
    return out


def _latency_findings_pcap(flows: list[Flow]) -> list[Finding]:
    """Flag slow TCP/TLS setup measured directly on the wire."""
    out: list[Finding] = []

    tls_rows = [(f.tls_setup_ms, f) for f in flows if f.tls_setup_ms is not None]
    tls_bad = [(v, f) for v, f in tls_rows if v >= _LAT_PCAP_TLS_MS]
    if tls_bad:
        tls_bad.sort(key=lambda x: x[0], reverse=True)
        vals = [v for v, _ in tls_rows]
        p95 = _pctl(vals, 95)
        worst = "; ".join(f"{_flow_label(f)} ({round(v)} ms)" for v, f in tls_bad[:5])
        out.append(Finding(
            title=f"Slow TLS handshake on the wire: {len(tls_bad)} flow(s) \u2265 {round(_LAT_PCAP_TLS_MS)} ms",
            severity="medium",
            category="latency",
            detail=(f"{len(tls_bad)} of {len(tls_rows)} TLS flow(s) took \u2265 {round(_LAT_PCAP_TLS_MS)} ms "
                    f"between ClientHello and ServerHello (p95 {round(p95)} ms). A long gap usually means an "
                    "extra TLS-terminating hop (SWG) or a distant server. Worst: " + worst + "."),
            evidence=[f"tls_setup p95={round(p95)}ms n_slow={len(tls_bad)}"],
        ))

    tcp_rows = [(f.tcp_handshake_ms, f) for f in flows if f.tcp_handshake_ms is not None]
    tcp_bad = [(v, f) for v, f in tcp_rows if v >= _LAT_PCAP_TCP_MS]
    if tcp_bad:
        tcp_bad.sort(key=lambda x: x[0], reverse=True)
        vals = [v for v, _ in tcp_rows]
        p95 = _pctl(vals, 95)
        worst = "; ".join(f"{_flow_label(f)} ({round(v)} ms)" for v, f in tcp_bad[:5])
        out.append(Finding(
            title=f"High TCP round-trip: {len(tcp_bad)} flow(s) \u2265 {round(_LAT_PCAP_TCP_MS)} ms SYN\u2192SYN/ACK",
            severity="low",
            category="latency",
            detail=(f"{len(tcp_bad)} of {len(tcp_rows)} flow(s) had a SYN\u2192SYN/ACK round-trip "
                    f"\u2265 {round(_LAT_PCAP_TCP_MS)} ms (p95 {round(p95)} ms), indicating network distance or "
                    "loss to the destination/proxy. Worst: " + worst + "."),
            evidence=[f"tcp_rtt p95={round(p95)}ms n_slow={len(tcp_bad)}"],
        ))
    return out


def _geo_egress_latency_findings(har: HarResult, ctx: AnalysisContext) -> list[Finding]:
    """Possible added latency from a geographically distant SWG egress.

    When the browser egresses through a Cisco Secure Access SWG node in a given
    AWS region (read authoritatively from the Via header, not from geolocating an
    IP), geo-aware services localize the session to THAT region. We corroborate
    the egress geography with signals the origin itself reveals — Google's `cr=`
    country param, a country-code TLD host (google.co.jp), or the egress IP the
    CDN echoes back (googlevideo `ip=`). If the SWG region is far from the user,
    every request detours there and CDNs serve from near the egress, not the user.

    This is framed as POSSIBLE latency (severity low): we cannot know where the
    user physically is, so we report the egress geography and let them verify it.
    """
    entries = [e for e in har.entries
               if not (ctx.domain and e.host and ctx.domain.lower() not in e.host.lower())]
    if not entries:
        return []

    # 1) SWG egress region — authoritative, from the Via proxy-node naming.
    region_c: Counter = Counter()
    for e in entries:
        if e.via:
            for _role, region in _parse_via_nodes(e.via):
                region_c[region] += 1
    if not region_c:
        return []
    region = region_c.most_common(1)[0][0]
    geo = _AWS_REGION_GEO.get(region, region)

    # 2) Corroborating geolocation signals the ORIGIN revealed.
    cr_c: Counter = Counter()        # Google localization country param
    cctld_c: Counter = Counter()     # google.co.<cc> / google.<cc> hosts
    egress_ips: Counter = Counter()  # egress IP echoed by googlevideo `ip=`
    cctld_host = None
    for e in entries:
        q = parse_qs(urlparse(e.url).query)
        for v in q.get("cr", []):
            if v:
                cr_c[v.upper()] += 1
        for v in q.get("ip", []):
            if v:
                egress_ips[v] += 1
        parts = (e.host or "").lower().split(".")
        if len(parts) >= 3 and parts[-2] == "co" and parts[-1].upper() in _COUNTRY_NAME:
            cctld_c[parts[-1].upper()] += 1
            cctld_host = cctld_host or e.host
        elif len(parts) >= 2 and parts[-2] in ("google", "youtube") and parts[-1].upper() in _COUNTRY_NAME:
            cctld_c[parts[-1].upper()] += 1
            cctld_host = cctld_host or e.host

    # Require at least one origin-side corroboration so this only fires when a
    # geo-aware service actually localized the session to the egress region —
    # not on every proxied capture.
    if not (cr_c or cctld_c or egress_ips):
        return []

    loc_country = None
    if cr_c:
        loc_country = cr_c.most_common(1)[0][0]
    elif cctld_c:
        loc_country = cctld_c.most_common(1)[0][0]
    country_name = _COUNTRY_NAME.get(loc_country, loc_country) if loc_country else None

    # Measurable corroboration (not proof of the detour, but relevant context).
    waits = [e.t_wait for e in entries if e.t_wait is not None]
    med_wait = round(_pctl(waits, 50)) if waits else None
    p95_wait = round(_pctl(waits, 95)) if waits else None

    reasons = [
        f"(1) Detour RTT \u2014 every request first travels from your device to the SWG in {geo}, then "
        f"to the origin and back. If you are not physically near {geo}, that detour adds round-trip time "
        "to every single connection.",
        f"(2) CDN mislocation \u2014 geo-aware services (Google, YouTube, Akamai, Cloudflare, \u2026) pick their "
        f"nearest edge from the SWG's egress IP, not yours, so they serve you from servers near {geo}, "
        "compounding the distance.",
    ]
    if country_name:
        reasons.append(
            f"(3) Wrong localization \u2014 the origin localized this session as {country_name}, so you get "
            f"{country_name} language, catalog and geo-restricted content regardless of where you are.")

    detail = (
        f"All proxied traffic in this capture egresses to the internet from a Cisco Secure Access SWG "
        f"node in {geo} (AWS {region}), seen in {sum(region_c.values())} Via header(s). This is expected "
        f"IF your steering intentionally sends traffic to {geo} — but it carries a latency cost worth "
        f"verifying against where you actually are:\n\n" + "\n".join(reasons) + "\n\n"
        f"The egress is CONSISTENT (one region for everything), so nothing breaks — it works, just slower "
        f"and wrong-locale if {geo} is far from you. If {geo} IS your expected egress region, ignore this."
    )

    ev = [f"SWG egress region: {region} ({geo}) \u00d7{sum(region_c.values())} Via node(s)"]
    if cr_c:
        ev.append("Google cr= localization: " + ", ".join(f"{c}\u00d7{n}" for c, n in cr_c.most_common()))
    if cctld_c:
        ev.append(f"country-code TLD host: {cctld_host} ({', '.join(cctld_c)})")
    if egress_ips:
        ev.append("egress IP echoed by CDN (googlevideo ip=): "
                  + ", ".join(f"{ip}\u00d7{n}" for ip, n in egress_ips.most_common(3)))
    if med_wait is not None:
        ev.append(f"observed TTFB: median {med_wait} ms, p95 {p95_wait} ms")

    country_tag = f"; origin localized you as {country_name}" if country_name else ""
    return [Finding(
        title=f"Possible added latency: SWG egress is in {geo}{country_tag}",
        severity="low",
        category="latency",
        detail=detail,
        evidence=ev,
    )]

