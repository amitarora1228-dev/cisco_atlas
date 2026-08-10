"""Cisco Secure Access ingress-IP awareness.

Maps an observed IP to a known Cisco Secure Access Secure Web Gateway (SWG)
ingress location, so the analyzer can identify when traffic is flowing through
Secure Access (explicit proxy / proxy-chaining) instead of calling it a generic
"proxy". Source: Network Requirements for Secure Access (ingress IP list).
"""
from __future__ import annotations

import ipaddress
import json
import os
from functools import lru_cache
from typing import Optional

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "secure_access_ingress.json")


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, str], list[tuple[ipaddress.IPv4Network, str]]]:
    """Return (exact_ip -> region, [(network, region)]) lookup structures."""
    exact: dict[str, str] = {}
    nets: list[tuple[ipaddress.IPv4Network, str]] = []
    try:
        with open(_DATA_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return exact, nets
    for region, entries in data.items():
        for entry in entries:
            if "/" in entry:
                try:
                    nets.append((ipaddress.ip_network(entry, strict=False), region))
                except ValueError:
                    continue
            else:
                exact[entry] = region
    return exact, nets


def lookup_ingress_region(ip: Optional[str]) -> Optional[str]:
    """Return the Secure Access ingress region for an IP, or None if unknown."""
    if not ip:
        return None
    exact, nets = _load()
    region = exact.get(ip)
    if region:
        return region
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net, region in nets:
        if addr in net:
            return region
    return None


def is_secure_access_ingress(ip: Optional[str]) -> bool:
    return lookup_ingress_region(ip) is not None


def describe(ip: Optional[str]) -> Optional[str]:
    """Human label, e.g. 'Cisco Secure Access SWG ingress (Germany)'."""
    region = lookup_ingress_region(ip)
    if not region:
        return None
    return f"Cisco Secure Access SWG ingress ({region})"


# --- Private Access (Zero Trust / ZTNA) awareness ----------------------------
# 100.64.0.0/10 is RFC 6598 "Shared Address Space" (carrier-grade NAT / CGNAT),
# range 100.64.0.0 - 100.127.255.255. Cisco Secure Access uses this pool for
# CLIENT-BASED ZERO TRUST / PRIVATE ACCESS (ZTNA): when an endpoint reaches a
# private resource through the Zero Trust proxy ("ZPC"/ZPROXY), the source IP the
# resource sees is drawn from this CGNAT range. This is the Private Access path,
# NOT the Secure Web Gateway (SWG) path — it tunnels arbitrary protocols/ports,
# so SWG web-policy, TLS-decryption and certificate-pinning verdicts do not apply.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

PRIVATE_ACCESS_LABEL = (
    "Cisco Secure Access \u2014 Private Access (Zero Trust / ZTNA, CGNAT 100.64.0.0/10)"
)


def is_private_access(ip: Optional[str]) -> bool:
    """True if the IP is in the 100.64.0.0/10 CGNAT pool Cisco Secure Access uses
    for client-based Zero Trust / Private Access (ZTNA)."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in _CGNAT_NET
    except ValueError:
        return False


# --- Internal (private-to-private) traffic awareness -------------------------
# The Cisco Secure Access roaming agent only steers INTERNET-bound traffic
# through the Secure Web Gateway (SIA). Traffic between two private/internal
# addresses (RFC 1918 LAN, link-local, loopback, IPv6 ULA, or the CGNAT/ZTNA
# pool) never traverses the SWG proxy, so SIA-level verdicts — TLS decryption,
# web-policy blocks and certificate-pinning — simply do not apply to it. We
# detect such flows so we never raise a proxy/SWG "error" on purely internal
# (private->private) connections, which would be a false positive.
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (RFC 3927)
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT / ZTNA (RFC 6598)
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique-local (ULA)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
]


def is_private_ip(ip: Optional[str]) -> bool:
    """True if the IP is a private / non-internet-routable address (RFC 1918,
    link-local, loopback, IPv6 ULA, or the CGNAT/ZTNA pool). Safe on None/bad
    input (returns False)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def is_internal_flow(src_ip: Optional[str], dst_ip: Optional[str]) -> bool:
    """True when BOTH endpoints are private/internal, i.e. the flow is
    private->private LAN/ZTNA traffic that never goes through the Secure Access
    SWG (SIA). On such flows, SWG/decryption/web-policy/pinning verdicts must not
    be applied."""
    return is_private_ip(src_ip) and is_private_ip(dst_ip)
