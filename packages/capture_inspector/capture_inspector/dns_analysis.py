"""DNS analysis for Cisco Secure Access captures.

Two jobs:

1. **Block-page mapping** — when Secure Access blocks a domain at the DNS layer,
   its resolvers answer with a fixed Anycast IP that encodes *why* it was
   blocked (malware, phishing, content category, etc.). We map those IPs back to
   the human-readable block reason. Source:
   https://securitydocs.cisco.com/docs/csa/olh/120445.dita

2. **DNS health** — surface resolution problems that break TLS before a single
   byte is sent: NXDOMAIN, SERVFAIL, REFUSED, NODATA, and queries that never got
   an answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .pcap import Packet


# --- Cisco Secure Access block-page Anycast IPs ------------------------------
# IPv4 (A) records — each address encodes the block category.
BLOCK_PAGE_IPV4: dict[str, str] = {
    "146.112.61.113": "Domain List (destination/allow-block list)",
    "146.112.61.114": "Command and Control Callback",
    "146.112.61.115": "Content Category or Application",
    "146.112.61.116": "Malware",
    "146.112.61.117": "Phishing",
    "146.112.61.119": "Security Integration / Newly Seen Domain / DNS Tunneling-VPN / "
                      "Potentially Harmful / Dynamic DNS",
}

# IPv6 (AAAA) records. Note ::115 is shared by Domain List and Content Category.
BLOCK_PAGE_IPV6: dict[str, str] = {
    "2620:119:18::113": "Domain List (destination/allow-block list)",
    "2620:119:18::114": "Command and Control Callback",
    "2620:119:18::115": "Domain List or Content Category / Application",
    "2620:119:18::116": "Malware",
    "2620:119:18::117": "Phishing",
    "2620:119:18::119": "Security Integration / Newly Seen Domain / DNS Tunneling-VPN / "
                        "Potentially Harmful / Dynamic DNS",
}

# Hostnames Secure Access uses to render the actual block page.
BLOCK_PAGE_DOMAINS = (
    "block.sse.cisco.com",
    "phishing.block.sse.cisco.com",
    "malware.block.sse.cisco.com",
)

# Cisco Secure Access EXPLICIT SWG PROXY hostnames. When a client is configured
# to chain to the Secure Web Gateway over HTTPS it resolves a name like
#   swg-url-proxy-https-sse.sigproxy.qq.opendns.com           (generic)
#   swg-url-proxy-https-<ORG-ID>.sseproxy.qq.opendns.com      (per-org)
# (<ORG-ID> is the Secure Access organization number). These names are answered
# with the SWG ingress IP the client should connect to. If the SAME name is
# answered with ingress IPs in DIFFERENT regions/countries over the capture, the
# proxy is "flapping" between data centers — a session can land on one country
# then another, breaking proxy affinity. We detect those names here.
SWG_PROXY_HOST_SUFFIXES = (
    ".sigproxy.qq.opendns.com",
    ".sseproxy.qq.opendns.com",
)

# Web-layer (SWG) block-page hosting range. When Secure Access blocks an HTTPS
# request by *web* policy — URL filtering, content category, application control,
# DLP, or an AI-guardrail rule — it serves block.sse.cisco.com from this range
# (e.g. 146.112.199.74 / .78). Unlike the DNS-layer 146.112.61.x addresses, the
# block REASON is NOT encoded in the IP, so all we can say is "web policy block".
SWG_BLOCK_PAGE_PREFIXES = ("146.112.199.",)
SWG_BLOCK_PAGE_IPV6_PREFIXES = ("2620:119:19::", "2620:119:19:")


# Well-known public DNS resolvers. Traffic to any of these IS DNS even when it
# rides on TCP/443 (DoH / DNSCrypt) or 853 (DoT) instead of classic UDP/53 — so
# the Umbrella/OpenDNS roaming client talking to 208.67.222.222:443 is a DNS
# lookup, not web traffic. There is more than one DNS provider in the wild, so
# we map the common ones here.
PUBLIC_DNS_RESOLVERS: dict[str, str] = {
    # Cisco Umbrella / OpenDNS
    "208.67.222.222": "Cisco Umbrella / OpenDNS",
    "208.67.220.220": "Cisco Umbrella / OpenDNS",
    "208.67.222.220": "Cisco Umbrella / OpenDNS",
    "208.67.220.222": "Cisco Umbrella / OpenDNS",
    "208.67.222.123": "OpenDNS FamilyShield",
    "208.67.220.123": "OpenDNS FamilyShield",
    "146.112.41.2": "Cisco Umbrella roaming",
    "2620:119:35::35": "Cisco Umbrella / OpenDNS",
    "2620:119:53::53": "Cisco Umbrella / OpenDNS",
    # Google Public DNS
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    # Cloudflare
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "1.1.1.2": "Cloudflare DNS (malware-blocking)",
    "1.1.1.3": "Cloudflare DNS (family)",
    "2606:4700:4700::1111": "Cloudflare DNS",
    "2606:4700:4700::1001": "Cloudflare DNS",
    # Quad9
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "2620:fe::fe": "Quad9 DNS",
    "2620:fe::9": "Quad9 DNS",
}


def dns_resolver_name(ip: Optional[str]) -> Optional[str]:
    """Return the friendly name of a known public DNS resolver, or None.
    Matches regardless of port, so DoH/DoT (443/853) is recognised too."""
    if not ip:
        return None
    return PUBLIC_DNS_RESOLVERS.get(ip) or PUBLIC_DNS_RESOLVERS.get(ip.lower())


# DNS response codes (rcode) that indicate a resolution failure.
RCODE_LABELS = {
    1: ("FORMERR", "the resolver rejected the query as malformed"),
    2: ("SERVFAIL", "the resolver failed to complete the request (upstream/DNSSEC error)"),
    3: ("NXDOMAIN", "the domain does not exist"),
    4: ("NOTIMP", "the resolver does not support this query type"),
    5: ("REFUSED", "the resolver refused to answer (policy or ACL)"),
}


def block_category_for_ip(ip: str) -> Optional[str]:
    """Return the Secure Access block reason for an answer IP, or None."""
    return BLOCK_PAGE_IPV4.get(ip) or BLOCK_PAGE_IPV6.get(ip.lower())


def is_block_page_domain(host: Optional[str]) -> bool:
    if not host:
        return False
    h = host.lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in BLOCK_PAGE_DOMAINS)


def is_swg_block_ip(ip: Optional[str]) -> bool:
    """True for the web-layer (SWG) block-page hosting range used by
    block.sse.cisco.com (DLP / content / app-control / AI-guardrail blocks)."""
    if not ip:
        return False
    low = ip.lower()
    return (any(ip.startswith(p) for p in SWG_BLOCK_PAGE_PREFIXES)
            or any(low.startswith(p) for p in SWG_BLOCK_PAGE_IPV6_PREFIXES))


def is_swg_proxy_host(name: Optional[str]) -> bool:
    """True if a DNS name is a Cisco Secure Access explicit SWG proxy hostname
    (swg-url-proxy-https-*.sigproxy/sseproxy.qq.opendns.com)."""
    if not name:
        return False
    h = name.lower().rstrip(".")
    return any(h.endswith(s) for s in SWG_PROXY_HOST_SUFFIXES)


def swg_proxy_org(name: Optional[str]) -> Optional[str]:
    """Extract the Secure Access organization id from a per-org SWG proxy host
    (swg-url-proxy-https-<ORG-ID>.sseproxy.qq.opendns.com -> '<ORG-ID>'), or None."""
    if not is_swg_proxy_host(name):
        return None
    label = name.lower().rstrip(".").split(".", 1)[0]      # swg-url-proxy-https-<id>
    token = label.rsplit("-", 1)[-1]
    return token if token.isdigit() else None



@dataclass
class DnsRecord:
    name: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    rcode: Optional[int] = None
    responded: bool = False
    response_time: Optional[float] = None     # dns.time, seconds (query->response)
    first_seen: float = 0.0
    resolver: Optional[str] = None            # IP of the DNS server that answered
    # Derived
    blocked: bool = False
    block_category: Optional[str] = None
    block_ip: Optional[str] = None
    issue: Optional[str] = None               # short label e.g. "NXDOMAIN"
    issue_detail: Optional[str] = None
    # For Secure Access SWG proxy hostnames only: one entry per response, each
    # {"t": relative_time, "addresses": [ips in THAT answer]}. Lets us spot the
    # proxy resolving to different regions/countries at different times.
    proxy_responses: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "addresses": self.addresses,
            "cnames": self.cnames,
            "rcode": self.rcode,
            "responded": self.responded,
            "response_time": self.response_time,
            "resolver": self.resolver,
            "blocked": self.blocked,
            "block_category": self.block_category,
            "block_ip": self.block_ip,
            "issue": self.issue,
            "issue_detail": self.issue_detail,
        }


def _norm(name: str) -> str:
    return name.lower().rstrip(".")


def _is_reverse(name: str) -> bool:
    """Reverse (PTR) lookups — routine, and NXDOMAIN on them is expected noise."""
    return name.endswith(".in-addr.arpa") or name.endswith(".ip6.arpa")


def analyze_dns(packets: list[Packet]) -> list[DnsRecord]:
    """Build per-name DNS records, tagging block-page hits and failures."""
    records: dict[str, DnsRecord] = {}
    queried: dict[str, float] = {}

    for pkt in packets:
        names = pkt.all("dns.qry.name")
        if not names:
            continue
        name = _norm(names[0])
        is_response = pkt.first("dns.flags.response") in ("1", "True", "true")

        if not is_response:
            queried.setdefault(name, pkt.time_relative)
            records.setdefault(name, DnsRecord(name=name, first_seen=pkt.time_relative))
            continue

        rec = records.get(name)
        if rec is None:
            rec = DnsRecord(name=name, first_seen=pkt.time_relative)
            records[name] = rec
        rec.responded = True
        if rec.resolver is None:
            rec.resolver = pkt.first("ip.src") or pkt.first("ipv6.src")

        rcode = pkt.first("dns.flags.rcode")
        if rcode is not None:
            try:
                rec.rcode = int(rcode)
            except (ValueError, TypeError):
                pass

        for a in pkt.all("dns.a"):
            if a not in rec.addresses:
                rec.addresses.append(a)
        for aaaa in pkt.all("dns.aaaa"):
            if aaaa not in rec.addresses:
                rec.addresses.append(aaaa)
        for cn in pkt.all("dns.cname"):
            cn_n = _norm(cn)
            if cn_n not in rec.cnames:
                rec.cnames.append(cn_n)

        # For explicit SWG proxy hostnames, keep THIS response's own answer set
        # (with its timestamp) so we can tell apart per-lookup region flapping.
        if is_swg_proxy_host(name):
            this_resp = pkt.all("dns.a") + pkt.all("dns.aaaa")
            if this_resp:
                rec.proxy_responses.append({"t": pkt.time_relative, "addresses": this_resp})

        t = pkt.first("dns.time")
        if t is not None:
            try:
                rec.response_time = float(t)
            except (ValueError, TypeError):
                pass

    # Tag block-page hits and DNS issues.
    for rec in records.values():
        for ip in rec.addresses:
            cat = block_category_for_ip(ip)
            if cat:
                rec.blocked = True
                rec.block_category = cat
                rec.block_ip = ip
                break
        if not rec.blocked and any(is_block_page_domain(c) for c in rec.cnames):
            rec.blocked = True
            rec.block_category = "Secure Access block page (via CNAME)"

        if rec.rcode and rec.rcode in RCODE_LABELS:
            label, why = RCODE_LABELS[rec.rcode]
            # Reverse-lookup NXDOMAIN is routine; don't flag it as a problem.
            if not (_is_reverse(rec.name) and rec.rcode == 3):
                rec.issue, rec.issue_detail = label, why
        elif not rec.responded and rec.name in queried and not _is_reverse(rec.name):
            rec.issue, rec.issue_detail = "NO-RESPONSE", "the query was sent but no DNS answer was captured (timeout/dropped)"

    # Sort: blocked first, then issues, then by first_seen.
    def sort_key(r: DnsRecord):
        return (0 if r.blocked else (1 if r.issue else 2), r.first_seen)

    return sorted(records.values(), key=sort_key)


def dns_summary(records: list[DnsRecord]) -> dict[str, Any]:
    blocked = [r for r in records if r.blocked]
    issues = [r for r in records if r.issue and not r.blocked]
    return {
        "total": len(records),
        "blocked_count": len(blocked),
        "issue_count": len(issues),
        "blocked": [r.name for r in blocked],
    }
