"""DNS findings: block-page hits, resolution failures, and Secure Access SWG
explicit-proxy ingress region-flapping."""
from __future__ import annotations

from typing import Optional

from ..engine import Finding
from ..dns_analysis import DnsRecord, is_swg_proxy_host, swg_proxy_org
from ..secure_access import lookup_ingress_region


def _dns_findings(records: list[DnsRecord], secure_access_mode: bool = False) -> list[Finding]:
    """Turn DNS block-page hits and resolution failures into findings.

    Block-page and resolution-failure detection is vendor-agnostic and always
    runs (a troubled client may land on a network that uses Secure Access, and
    the block IP is exactly where the problem is). The SWG explicit-proxy
    region-flip check is Secure Access-specific and only runs in SA mode."""
    out: list[Finding] = []
    for rec in records:
        if rec.blocked:
            out.append(Finding(
                title=f"DNS-blocked by Secure Access: {rec.name} \u2014 {rec.block_category}",
                severity="high",
                category="proxy",
                detail=(f"The Secure Access DNS resolver answered '{rec.name}' with the block-page "
                        f"address {rec.block_ip or '(block page)'}, which means the request was blocked "
                        f"under category: {rec.block_category}. The client never reached the real server; "
                        f"any TLS error downstream is a symptom, not the cause. "
                        f"Review the DNS policy / category rule that matches this destination."),
                evidence=[f"{rec.name} -> {', '.join(rec.addresses) or rec.block_ip} (block page)"]
                         + ([f"CNAME {', '.join(rec.cnames)}"] if rec.cnames else []),
            ))
        elif rec.issue:
            # mDNS / link-local names (.local, _service._tcp.local, .home.arpa)
            # are answered by multicast on the LAN, not by the unicast resolver,
            # so a NO-RESPONSE/SERVFAIL for them is normal background noise — NOT
            # the cause of an Internet/SWG problem. Keep them low so they never
            # become the headline diagnosis.
            local = _is_local_dns_name(rec.name)
            if local:
                sev = "low"
            else:
                sev = "high" if rec.issue in ("SERVFAIL", "NO-RESPONSE") else "medium"
            detail = (f"Resolution of '{rec.name}' failed: {rec.issue_detail}. "
                      f"TLS cannot start until the name resolves, so this fails before any handshake. "
                      f"Check the resolver, split-DNS/conditional forwarders, or whether the domain "
                      f"should be allowed.")
            if local:
                kind = ("a single-label internal hostname (no domain) that only resolves via a local "
                        "search-suffix / NetBIOS / mDNS" if "." not in (rec.name or "").rstrip(".")
                        else "a multicast/link-local name (mDNS / .local / .home.arpa) resolved by "
                             "multicast on the local network")
                detail = (f"'{rec.name}' is {kind}, not by the upstream/Secure Access resolver, so a "
                          f"{rec.issue} for it is expected background noise — it is NOT a sign of an "
                          f"Internet, DNS or SWG problem and does not affect web traffic.")
            out.append(Finding(
                title=f"DNS {rec.issue} for {rec.name}",
                severity=sev,
                category="dns",
                detail=detail,
                evidence=[f"{rec.name}: {rec.issue}"
                          + (f" (rcode={rec.rcode})" if rec.rcode is not None else "")],
            ))
    if secure_access_mode:
        out.extend(_swg_proxy_region_findings(records))
    return out


def _is_local_dns_name(name: Optional[str]) -> bool:
    """True for names the upstream/Secure Access resolver is not expected to
    answer: multicast/link-local (mDNS .local, DNS-SD service labels, .home.arpa)
    and single-label internal hostnames (e.g. an AD host like 'p-addc-001' with
    no dot) that only resolve via a local search-suffix / NetBIOS / mDNS. A
    NO-RESPONSE/SERVFAIL for these is normal LAN background noise."""
    n = (name or "").lower().rstrip(".")
    if not n:
        return False
    if "." not in n:
        return True  # single-label internal hostname, never a public FQDN
    return (n.endswith(".local") or n.endswith(".home.arpa")
            or n.endswith(".localdomain") or "_tcp.local" in n or "_udp.local" in n)


def _swg_proxy_region_findings(records: list[DnsRecord]) -> list[Finding]:
    """Flag Cisco Secure Access explicit SWG proxy hostnames
    (swg-url-proxy-https-*.sigproxy/sseproxy.qq.opendns.com) that resolve to
    ingress IPs in DIFFERENT regions/countries over the capture. The client
    connects to whatever IP it got, so a region flip between lookups lands the
    session on another data center / country — breaking proxy affinity, causing
    auth re-prompts, latency spikes and resets. Resolving to ONE region is logged
    as informational confirmation that the explicit SWG proxy is in use."""
    out: list[Finding] = []
    for rec in records:
        if not is_swg_proxy_host(rec.name):
            continue
        ip_region = {ip: lookup_ingress_region(ip) for ip in rec.addresses}
        known = {ip: r for ip, r in ip_region.items() if r}
        regions = sorted(set(known.values()))
        org = swg_proxy_org(rec.name)
        org_txt = f" (Secure Access org {org})" if org else ""

        # Per-lookup timeline: when did the answered region change?
        timeline: list[str] = []
        last: Optional[tuple] = None
        for resp in rec.proxy_responses:
            rs = sorted({lookup_ingress_region(ip) or "unknown region" for ip in resp["addresses"]})
            key = tuple(rs)
            if key != last:
                timeline.append(f"t+{resp['t']:.1f}s -> {', '.join(rs)}")
                last = key

        if len(regions) >= 2:
            by_region: dict[str, list[str]] = {}
            for ip, r in known.items():
                by_region.setdefault(r, []).append(ip)
            evidence = [f"{rec.name}{org_txt} answered with {len(regions)} regions:"]
            evidence += [f"{r}: {', '.join(by_region[r])}" for r in regions]
            if timeline:
                evidence.append("Resolution timeline: " + "  |  ".join(timeline))
            out.append(Finding(
                title=(f"Secure Access SWG proxy resolves to multiple regions "
                       f"({', '.join(regions)}) \u2014 ingress flapping"),
                severity="high",
                category="proxy",
                detail=(f"The explicit SWG proxy hostname '{rec.name}' was answered with ingress IPs in "
                        f"more than one Secure Access region ({', '.join(regions)}). The client connects to "
                        f"whichever IP DNS returns, so when the answered region changes between lookups the "
                        f"session moves to a different data center / country. That breaks proxy-session "
                        f"affinity and commonly shows up as dropped connections (TCP RST), re-authentication "
                        f"prompts and latency spikes. Expected behavior is a stable answer pointing to the "
                        f"geographically-correct DC. Check DNS for this name (EDNS Client-Subnet, the roaming "
                        f"client's resolver, any split/conditional forwarder or caching layer that could hand "
                        f"back a stale or foreign DC), and confirm only the intended Secure Access region is "
                        f"being advertised for this org."),
                evidence=evidence,
            ))
        elif len(known) == 0 and len({ip for ip in rec.addresses}) >= 2 and len(timeline) >= 2:
            # Resolves to several IPs that we can't map to a known region — still a
            # changing answer, but we can't name the country.
            out.append(Finding(
                title=f"Secure Access SWG proxy resolves to changing ingress IPs for {rec.name}",
                severity="medium",
                category="proxy",
                detail=(f"The explicit SWG proxy hostname '{rec.name}' was answered with several different "
                        f"ingress IPs over the capture, but none mapped to a known Secure Access region (a "
                        f"newer or unlisted data center). A changing proxy IP can still move the session "
                        f"between data centers. Verify which DCs these addresses belong to and whether the "
                        f"answer should be stable."),
                evidence=[f"{rec.name}{org_txt} -> {', '.join(rec.addresses)}"]
                         + (["Resolution timeline: " + "  |  ".join(timeline)] if timeline else []),
            ))
        elif len(regions) == 1:
            out.append(Finding(
                title=f"Secure Access explicit SWG proxy in use \u2014 ingress {regions[0]}",
                severity="info",
                category="proxy",
                detail=(f"The client resolved the explicit SWG proxy hostname '{rec.name}' to the Secure "
                        f"Access ingress in {regions[0]}, and it stayed consistent across the capture. This "
                        f"confirms web traffic is chained to the Secure Web Gateway via explicit proxy."),
                evidence=[f"{rec.name}{org_txt} -> {regions[0]} ({', '.join(known)})"],
            ))
    return out
