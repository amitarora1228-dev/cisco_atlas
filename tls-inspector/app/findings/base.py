"""Shared helpers used across multiple finding modules."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from ..pcap import Flow


def _is_private_ip(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


def _is_loopback_ip(ip: Optional[str]) -> bool:
    return bool(ip) and (ip == "::1" or ip.startswith("127."))


def _flow_label(f: Flow) -> str:
    """Best human-readable name for a flow's destination."""
    return (f.tunnel_sni or f.sni or f.resolved_host
            or (f.connect_target or "").rsplit(":", 1)[0]
            or f.dns_query or f.dst_ip or "?")


def _pctl(values: list[float], pct: float) -> float:
    """Simple nearest-rank percentile (no interpolation)."""
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(pct / 100.0 * (len(s) - 1)))))
    return s[k]


def _fmt_clock(epoch: Optional[float]) -> Optional[str]:
    """Format an epoch second as HH:MM:SS (UTC) for attempt timelines."""
    if not epoch:
        return None
    try:
        return datetime.utcfromtimestamp(epoch).strftime("%H:%M:%S")
    except (ValueError, OSError, OverflowError):
        return None
