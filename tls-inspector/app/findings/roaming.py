"""Roaming findings: Cisco Secure Client / Umbrella roaming-module loopback
interception, the agent's cleartext self-report, and Secure Access SWG ingress
coverage health."""
from __future__ import annotations

from typing import Optional

from ..engine import Finding
from ..pcap import Flow
from ..dns_analysis import DnsRecord, is_block_page_domain, swg_proxy_org
from ..secure_access import lookup_ingress_region, is_secure_access_ingress
from .base import _is_private_ip

_LOOPBACK_IPS = {"127.0.0.1", "::1"}
# Loopback ports the Cisco Secure Client / Umbrella roaming module listens on.
# 5002 is the roaming client's DNS interception listener (KDF kernel redirect):
# the agent grabs the device's normal DNS (53) and proxies it through 127.0.0.1:5002.
_ROAMING_PORTS = {53: "DNS", 80: "HTTP", 443: "HTTPS", 5002: "DNS (roaming KDF listener)"}
# Ports on loopback that represent DNS being handled by the roaming agent.
_ROAMING_DNS_PORTS = {53, 5002}


def _roaming_findings(flows: list[Flow], dns_records: Optional[list[DnsRecord]] = None) -> list[Finding]:
    """Detect Cisco Secure Client Roaming Security module local interception.

    The roaming module installs a listener on the loopback address and redirects
    the device's DNS (UDP/TCP 53) — and on some deployments HTTP/HTTPS (80/443) —
    through 127.0.0.1, so Umbrella / Secure Access policy applies on- and
    off-network. Loopback traffic on those ports is a strong signal the roaming
    agent is installed and steering traffic locally.
    """
    out: list[Finding] = []

    hits: dict[int, set[str]] = {}
    for f in flows:
        if f.dst_ip in _LOOPBACK_IPS and f.dst_port in _ROAMING_PORTS:
            hits.setdefault(f.dst_port, set()).add(f.key)

    if not hits:
        return out

    port_bits = []
    for port in sorted(hits):
        port_bits.append(f"{_ROAMING_PORTS[port]} 127.0.0.1:{port} ({len(hits[port])} flow(s))")
    services = ", ".join(_ROAMING_PORTS[p] for p in sorted(hits))

    evidence = [f"loopback interception: {b}" for b in port_bits]

    # If DNS is being steered through loopback, the captured DNS lookups ARE the
    # queries the roaming agent answered. Surface a few real examples so it's
    # clear *what* is being resolved locally.
    sample_names: list[str] = []
    has_dns = bool(_ROAMING_DNS_PORTS & set(hits))
    if has_dns and dns_records:
        for rec in dns_records:
            n = rec.name
            if not n or n.endswith(".in-addr.arpa") or n.endswith(".ip6.arpa"):
                continue
            if is_block_page_domain(n):
                continue
            if n not in sample_names:
                sample_names.append(n)
            if len(sample_names) >= 6:
                break
        if sample_names:
            total = sum(1 for r in dns_records
                        if r.name and not r.name.endswith(".in-addr.arpa")
                        and not r.name.endswith(".ip6.arpa"))
            shown = ", ".join(sample_names)
            more = f" (+{total - len(sample_names)} more)" if total > len(sample_names) else ""
            evidence.append(f"resolved via the roaming agent, e.g.: {shown}{more}")

    detail = ("Traffic was observed going to the loopback address 127.0.0.1 on "
              + ", ".join(f"port {p} ({_ROAMING_PORTS[p]})" for p in sorted(hits)) + ". "
              "This is how the Cisco Secure Client Roaming Security (Umbrella/Secure Access) "
              "module works: it runs a local listener on loopback and redirects the device's "
              "DNS — and, when web protection is enabled, HTTP/HTTPS — through it so policy is "
              "enforced on- and off-network. Its presence confirms the roaming agent is installed "
              "and actively steering traffic locally (not a fault).")
    if has_dns and sample_names:
        detail += (" The DNS queries handled on loopback are visible in the capture — these are the "
                   "domain names the roaming agent resolved for the device.")
    if 5002 in hits:
        detail += (" Loopback port 5002 specifically is the roaming client's DNS interception listener "
                   "(KDF kernel redirect): the agent captures the device's normal DNS and proxies it "
                   "through 127.0.0.1:5002 before applying Umbrella / Secure Access policy.")

    out.append(Finding(
        title=f"Cisco Secure Client Roaming module active — {services} steered via loopback",
        severity="info",
        category="roaming",
        detail=detail,
        evidence=evidence,
    ))
    return out


def _roaming_report_findings(report: Optional[dict]) -> list[Finding]:
    """Surface the Cisco Secure Client / Umbrella roaming module's self-report.

    The agent emits a cleartext ``STARTMSG`` JSON status datagram on loopback
    (see pcap.extract_roaming_report) that names the SWG / Secure Access proxy
    and org it is bound to and counts how many web connections it has *steered*
    through the SWG versus let *bypass* (go direct). This is the agent telling us
    its own posture in clear — no inference needed — so we highlight it.
    """
    if not report:
        return []

    proxy = report.get("umbrella_proxy")
    org = swg_proxy_org(proxy) if proxy else None
    http = report.get("http_connections")
    https = report.get("https_connections")
    bypassed = report.get("bypassed_connections")
    first = report.get("bypassed_first")
    last = report.get("bypassed_last")

    steered = (http or 0) + (https or 0)

    org_txt = f" (Secure Access org {org})" if org else ""
    title = "Cisco Secure Client roaming self-report"
    if proxy:
        title += f" — SWG {proxy}{org_txt}"

    evidence: list[str] = []
    if proxy:
        evidence.append(f"SWG proxy this client is bound to: {proxy}{org_txt}")
    if steered or bypassed:
        steer_bits = []
        if https is not None:
            steer_bits.append(f"{https:,} HTTPS")
        if http is not None:
            steer_bits.append(f"{http:,} HTTP")
        steered_txt = " + ".join(steer_bits) if steer_bits else "0"
        # Deliberately NO steered-vs-bypassed percentage. The steered counters
        # are explicitly HTTP and HTTPS, while the agent's own description of a
        # bypass covers non-proxyable protocols and internal hosts too. Dividing
        # one by the other would mix two different populations and dress the
        # result up as "% of web", which the wire does not support.
        evidence.append(
            f"Agent's own counters, cumulative since it started (NOT this capture): {steered_txt} "
            f"steered through the SWG, {(bypassed or 0):,} recorded as bypassed (sent direct)"
        )
    # Did the bypass counter move during the capture while steering stayed flat?
    if first is not None and last is not None and last > first:
        evidence.append(
            f"Measured in THIS capture: the bypassed counter grew {first:,} -> {last:,} "
            f"(+{last - first:,}) while the HTTP/HTTPS-steered counters stayed flat — new activity in "
            "this window went direct, not through the SWG."
        )

    detail = (
        "The Cisco Secure Client / Umbrella roaming (web-protection) module publishes a periodic status "
        "message on loopback whose payload is cleartext JSON. It was captured here, so we can read the "
        "agent's own posture directly instead of inferring it: which SWG / Secure Access proxy (and org) "
        "the client is bound to, and its steered-versus-bypassed connection counters. "
        "Two things about these numbers, because they are easy to misread. "
        "First, they are CUMULATIVE since the agent started — they describe its whole lifetime, not the "
        "period you captured. Only the change between two status messages (reported above when it moved) "
        "belongs to this capture. "
        "Second, the counters do not share one population: the steered ones are explicitly HTTP and HTTPS, "
        "whereas a bypass covers anything the module let through untouched — cert-pinned SaaS, internal and "
        "RFC1918 destinations, and protocols it cannot proxy at all such as QUIC/UDP. That is why no "
        "'X% of web bypassed' figure is given: the two counters are not measuring the same thing, and the "
        "wire carries nothing that would let us split the bypassed total by protocol. "
        "A large bypassed count is normal on a corporate LAN, and on its own is not a fault. What matters "
        "is whether a destination you expect to be inspected is going direct — check that against the flows "
        "themselves rather than against this ratio. Also cross-check the proxy/org against the DNS "
        "resolution for this name (region/ingress flapping)."
    )

    return [Finding(
        title=title,
        severity="info",
        category="roaming",
        detail=detail,
        evidence=evidence,
    )]


def _ingress_health_findings(flows: list[Flow], sa_tunnel: bool = False) -> list[Finding]:
    """Check whether TLS traffic actually reaches a Secure Access SWG ingress.

    If the capture has plenty of external HTTPS but none of it lands on a known
    Secure Access ingress IP, the client is very likely bypassing the SWG
    (DIRECT, split-tunnel, or a misapplied PAC) — a high-value signal.

    Exception: in a site-to-site (IPsec) tunnel deployment the endpoint sends
    packets to the REAL origin IPs and the tunnel encapsulation happens downstream
    at the network edge, so a capture taken on the tunnel-source side never shows
    Secure Access ingress IPs. There, "0 via ingress" is EXPECTED, not a bypass,
    so the caller passes sa_tunnel=True to suppress the false alarm.
    """
    out: list[Finding] = []

    tls_flows = [
        f for f in flows
        if (f.client_hello or f.is_connect_tunnel or f.dst_port == 443)
        and f.dst_ip and not _is_private_ip(f.dst_ip)
    ]
    if not tls_flows:
        return out

    via_ingress = [f for f in tls_flows if is_secure_access_ingress(f.proxy_ip or f.dst_ip)]
    regions = sorted({lookup_ingress_region(f.proxy_ip or f.dst_ip) for f in via_ingress} - {None})
    total, through = len(tls_flows), len(via_ingress)

    if through == total:
        out.append(Finding(
            title=f"All HTTPS traffic flows through Secure Access ({through}/{total})"
                  + (f" — {', '.join(regions)}" if regions else ""),
            severity="info",
            category="swg_coverage",
            detail=("Every observed HTTPS flow reaches a known Secure Access SWG ingress, so traffic is being "
                    "steered through Secure Access as expected."),
            evidence=[f"via ingress: {through}/{total}" + (f" regions={regions}" if regions else "")],
        ))
        return out

    # Site-to-site tunnel: destination IPs are the real origins (encapsulation is
    # downstream), so the ingress-IP coverage heuristic does not apply and the
    # absence of ingress IPs must NOT be reported as a bypass.
    if sa_tunnel:
        out.append(Finding(
            title="Site-to-site tunnel: SWG steering is not visible by ingress IP in this capture",
            severity="info",
            category="swg_coverage_info",
            detail=(f"{total - through} of {total} external HTTPS flow(s) go to their real origin IPs rather "
                    "than a Secure Access ingress IP. In a site-to-site (IPsec) tunnel deployment this is "
                    "EXPECTED and is NOT a bypass: the endpoint sends packets to the real destination and the "
                    "tunnel encapsulation happens downstream at the network edge, so a capture taken on the "
                    "tunnel-source side never shows Secure Access ingress IPs — SWG policy is still enforced "
                    "after the tunnel. This ingress-IP coverage check does not apply to tunnel captures; to "
                    "confirm steering look instead for an SWG TLS terminator (shared JA3S) or Secure Access "
                    "DNS enforcement in this same capture."),
            evidence=[f"{total} external HTTPS flows, {through} via a known ingress (site-to-site tunnel mode)"],
        ))
        return out

    if through == 0:
        out.append(Finding(
            title=f"No traffic reaches a Secure Access ingress ({total} HTTPS flow(s) went DIRECT)",
            severity="high",
            category="swg_coverage",
            detail=("None of the observed HTTPS flows landed on a known Cisco Secure Access SWG ingress IP. "
                    "The client appears to be reaching the internet directly, bypassing Secure Access — so no "
                    "SWG policy, URL filtering or decryption is being applied. Check the proxy configuration "
                    "(PAC/WPAD), the Secure Client / module state, or split-tunnel rules."),
            evidence=[f"{total} external HTTPS flows, 0 via a known Secure Access ingress"],
        ))
    else:
        pct = round(100 * through / total)
        out.append(Finding(
            title=f"Partial Secure Access coverage: {through}/{total} HTTPS flows via ingress ({pct}%)",
            severity="medium",
            category="swg_coverage",
            detail=(f"{through} of {total} HTTPS flows reached a Secure Access ingress"
                    + (f" ({', '.join(regions)})" if regions else "")
                    + f", but {total - through} went DIRECT. Mixed coverage usually means a PAC/WPAD rule, "
                    "split-tunnel exclusion, or QUIC fallback is letting some traffic bypass the SWG."),
            evidence=[f"via ingress: {through}/{total}" + (f" regions={regions}" if regions else "")],
        ))
    return out

