"""Access-path findings: Cisco Secure Access Private Access (Zero Trust / ZTNA)
traffic on the 100.64.0.0/10 CGNAT pool, and purely internal (private->private)
LAN traffic — both outside the Secure Web Gateway (SIA) scope."""
from __future__ import annotations

from ..engine import Finding
from ..pcap import Flow
from .base import _flow_label, _is_loopback_ip


# Cisco Secure Access Private Access (Zero Trust / ZTNA). Flows whose source or
# destination is in the 100.64.0.0/10 CGNAT pool (RFC 6598) are the Zero Trust
# proxy path to a private resource. They tunnel arbitrary protocols, so they are
# NOT SWG/web traffic and must not be judged with TLS-decryption/pinning logic.
def _private_access_findings(flows: list[Flow]) -> list[Finding]:
    pa = [f for f in flows if getattr(f, "is_private_access", False)]
    if not pa:
        return []
    out: list[Finding] = []
    labels = "; ".join(sorted({_flow_label(f) for f in pa}))[:400]
    out.append(Finding(
        title=f"Cisco Secure Access Private Access (Zero Trust) traffic: {len(pa)} flow(s)",
        severity="info",
        category="private_access",
        detail=(
            f"{len(pa)} flow(s) involve the 100.64.0.0/10 CGNAT range (RFC 6598) that Cisco "
            f"Secure Access uses for client-based Zero Trust / Private Access (ZTNA). This is the "
            f"Zero Trust proxy (ZPC) path to a private resource — it tunnels arbitrary protocols "
            f"and ports, so it is NOT Secure Web Gateway (SWG) web traffic. TLS-decryption, "
            f"web-policy and certificate-pinning verdicts do not apply to these flows; a TCP RST "
            f"here is a normal teardown of the tunneled application, not certificate pinning. "
            f"Destinations: {labels}."
        ),
        evidence=[f"private_access_flows={len(pa)} cgnat=100.64.0.0/10"],
    ))
    return out


def _internal_traffic_findings(flows: list[Flow]) -> list[Finding]:
    """Flag private->private (internal LAN) traffic so it is never mistaken for
    SWG/SIA traffic. The Secure Access roaming agent only steers INTERNET-bound
    traffic through the SWG, so SIA-level verdicts (TLS decryption, web-policy,
    certificate-pinning) do not apply to purely internal flows."""
    internal = [
        f for f in flows
        if getattr(f, "is_internal", False)
        and not getattr(f, "is_private_access", False)   # ZTNA reported separately
        and not (_is_loopback_ip(f.src_ip) or _is_loopback_ip(f.dst_ip))  # roaming reported separately
    ]
    if not internal:
        return []
    labels = "; ".join(sorted({_flow_label(f) for f in internal}))[:400]
    return [Finding(
        title=f"Internal traffic (private \u2192 private): {len(internal)} flow(s) not subject to Secure Access SIA",
        severity="info",
        category="internal_traffic",
        detail=(
            f"{len(internal)} flow(s) are between two private/internal addresses "
            f"(RFC 1918 LAN, link-local, loopback or IPv6 ULA). The Cisco Secure Access "
            f"roaming agent only steers INTERNET-bound traffic through the Secure Web "
            f"Gateway (SIA), so these private\u2192private connections never pass through the "
            f"SWG. TLS-decryption, web-policy and certificate-pinning verdicts therefore do "
            f"NOT apply to them — a TCP RST or reset on an internal flow is an internal "
            f"app/firewall teardown, not a Secure Access policy action. (It may still be "
            f"relevant to Secure Access Private Access / SPA if a Zero Trust resource is "
            f"involved, but not to SIA.) Internal destinations: {labels}."
        ),
        evidence=[f"internal_flows={len(internal)}"],
    )]
