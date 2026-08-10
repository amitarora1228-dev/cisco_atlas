"""TLS interception findings: JA3S clustering — one server-side TLS fingerprint
fronting many distinct destinations is the classic signature of an SWG/proxy
that terminates and re-encrypts TLS (works even on TLS 1.3 with no keylog) — plus
vendor-agnostic detection of a LOCAL interception agent (a loopback TLS flow with
a re-signed certificate) and its probable outbound leg (the interception chain)."""
from __future__ import annotations

from ..engine import Finding
from ..pcap import Flow
from .base import _is_loopback_ip

# JA3S clustering: when one server-side TLS fingerprint fronts many DISTINCT
# destinations, those servers share a single TLS stack — the classic signature
# of a SWG/proxy that terminates and re-encrypts everything. Works even on TLS
# 1.3 with no keylog. (CDN caveat noted in the detail text.)
_JA3S_MIN_DESTS = 5


def _ja3s_findings(flows: list[Flow]) -> list[Finding]:
    out: list[Finding] = []
    clusters: dict[str, set[str]] = {}
    for f in flows:
        if not f.ja3s:
            continue
        dest = f.sni or f.resolved_host or f.dns_query or f.dst_ip
        if not dest:
            continue
        clusters.setdefault(f.ja3s, set()).add(dest)

    ranked = sorted(((j, d) for j, d in clusters.items() if len(d) >= _JA3S_MIN_DESTS),
                    key=lambda kv: len(kv[1]), reverse=True)
    if not ranked:
        return out

    for ja3s, dests in ranked[:3]:
        sample = ", ".join(sorted(dests)[:6])
        out.append(Finding(
            title=f"Single TLS terminator fronts {len(dests)} destinations (shared JA3S)",
            severity="medium",
            category="interception",
            detail=(f"{len(dests)} distinct destinations all answered with the same server-side TLS "
                    f"fingerprint (JA3S {ja3s[:16]}\u2026). One fingerprint across many unrelated hosts means a "
                    "single TLS stack is terminating and re-encrypting the traffic \u2014 the signature of an "
                    "SWG/proxy decrypting TLS, even on TLS 1.3 with no key log. (A shared CDN can also produce "
                    "this; confirm the destinations are unrelated organisations.) Hosts: " + sample + "."),
            evidence=[f"JA3S {ja3s[:16]} -> {len(dests)} dests"],
        ))
    return out


# --- Local interception agent (loopback TLS with a re-signed cert) -----------
# A TLS flow on loopback (127.0.0.1 / ::1) whose leaf certificate is re-signed by
# an interception/middlebox CA proves a LOCAL agent on THIS device is decrypting
# TLS before it leaves the machine — true for ANY vendor. The vendor is named
# from the certificate issuer text; unrecognised issuers are still reported (they
# are exactly the "weird proxy from some other vendor" case worth surfacing).
_CHAIN_WINDOW_S = 10.0  # max |t| gap to correlate a loopback leg to its outbound leg

# issuer-text fragment -> friendly vendor label (first match wins; order matters)
_LOCAL_AGENT_VENDORS: list[tuple[str, str]] = [
    ("cisco secure access", "Cisco Secure Access (Secure Client roaming module)"),
    ("secure access", "Cisco Secure Access (Secure Client roaming module)"),
    ("cisco umbrella", "Cisco Umbrella roaming client"),
    ("umbrella", "Cisco Umbrella roaming client"),
    ("zscaler", "Zscaler Client Connector (ZCC)"),
    ("netskope", "Netskope client"),
    ("skyhigh", "Skyhigh Security (McAfee/MVISION)"),
    ("mcafee", "McAfee / Skyhigh"),
    ("palo alto", "Palo Alto GlobalProtect"),
    ("paloalto", "Palo Alto GlobalProtect"),
    ("forcepoint", "Forcepoint"),
    ("blue coat", "Broadcom/Symantec Blue Coat"),
    ("bluecoat", "Broadcom/Symantec Blue Coat"),
    ("symantec", "Broadcom/Symantec"),
    ("fortigate", "Fortinet FortiGate"),
    ("fortinet", "Fortinet"),
    ("check point", "Check Point"),
    ("checkpoint", "Check Point"),
    ("sophos", "Sophos"),
    ("barracuda", "Barracuda"),
    ("kaspersky", "Kaspersky (AV web-shield)"),
    ("bitdefender", "Bitdefender (AV web-shield)"),
    ("eset", "ESET (AV web-shield)"),
    ("avast", "Avast (AV web-shield)"),
    ("avg ", "AVG (AV web-shield)"),
    ("mitmproxy", "mitmproxy (local MITM proxy)"),
    ("fiddler", "Fiddler (local debugging proxy)"),
    ("charles", "Charles (local debugging proxy)"),
    ("squid", "Squid proxy"),
]


def _flow_host(f: Flow) -> str | None:
    """Best real hostname for a flow: inner/CONNECT SNI, then SNI, then the
    CONNECT target host, then NRB/DNS-resolved name."""
    h = f.tunnel_sni or f.sni
    if not h and f.connect_target:
        h = f.connect_target.rsplit(":", 1)[0]
    if not h:
        h = f.resolved_host or f.dns_query
    if not h and getattr(f, "dns_lookup", None):
        h = f.dns_lookup.get("name")
    h = (h or "").strip().rstrip(".").strip("[]").lower()
    return h or None


def _flow_start(f: Flow) -> float | None:
    pkts = getattr(f, "packets", None)
    if pkts:
        return pkts[0].time_relative
    return None


def _cert_host(leaf) -> str | None:
    """Fallback hostname from a (re-signed) leaf certificate's Subject/SAN. On a
    decrypting proxy the re-signed cert carries the REAL destination name, so this
    recovers the host for loopback legs that carry no SNI/DNS (e.g. the roaming
    listener on 127.0.0.1:5002, or resumed TLS sessions with no ClientHello SNI).
    Prefers a concrete name over a wildcard."""
    if not leaf or getattr(leaf, "parse_error", None):
        return None
    cn = (getattr(leaf, "subject_cn", None) or "").strip().rstrip(".").strip("[]").lower()
    if cn and not cn.startswith("*"):
        return cn
    for s in (getattr(leaf, "san_dns", None) or []):
        s = (s or "").strip().rstrip(".").lower()
        if s and not s.startswith("*"):
            return s
    return cn or None


def _vendor_from_issuer(issuer: str) -> str:
    low = (issuer or "").lower()
    for frag, name in _LOCAL_AGENT_VENDORS:
        if frag in low:
            return name
    return (f"an unrecognized interception CA ('{issuer}')" if issuer
            else "an unrecognized interception CA")


def _local_interception_findings(reports) -> list[Finding]:
    """Detect a local TLS interception agent from loopback flows carrying a
    re-signed certificate, and correlate each to its PROBABLE outbound leg
    (same hostname, close in time) to expose the interception chain. Runs in
    both agnostic and Secure Access mode."""
    # (host, vendor, issuer_display, t, loopback_flow)
    intercepted: list[tuple[str, str, str, float | None, Flow]] = []
    outbound: dict[str, list[tuple[float | None, Flow]]] = {}
    for rep in reports:
        f = rep.flow
        host = _flow_host(f)
        loopback = _is_loopback_ip(f.src_ip) or _is_loopback_ip(f.dst_ip)
        leaf = rep.leaf_cert
        if loopback and leaf and not leaf.parse_error and leaf.looks_like_proxy_ca:
            # No SNI/DNS on many loopback legs (roaming listener on :5002, resumed
            # sessions) — recover the real host from the re-signed cert Subject/SAN.
            host = host or _cert_host(leaf)
            if not host:
                continue
            issuer_display = leaf.issuer_org or leaf.issuer_cn or ""
            # Match on the FULL issuer text (CN + O): the friendly product name
            # often lives in the CN (e.g. "Cisco Secure Access Secondary SubCA")
            # while the O is just "Cisco". is_secure_access is an authoritative
            # positive match for the Cisco SA PKI.
            if getattr(leaf, "is_secure_access", False):
                vendor = "Cisco Secure Access (Secure Client roaming module)"
            else:
                vendor = _vendor_from_issuer(f"{leaf.issuer_cn or ''} {leaf.issuer_org or ''}")
            intercepted.append((host, vendor, issuer_display, _flow_start(f), f))
        elif not loopback and host:
            outbound.setdefault(host, []).append((_flow_start(f), f))

    if not intercepted:
        return []

    by_vendor: dict[str, dict] = {}
    for host, vendor, issuer, t, loop_flow in intercepted:
        g = by_vendor.setdefault(vendor, {"issuers": set(), "hosts": {}, "chains": {}})
        if issuer:
            g["issuers"].add(issuer)
        g["hosts"][host] = g["hosts"].get(host, 0) + 1
        # Stamp the loopback leg itself so the flow ladder can show it is a local
        # interception hop, even when no outbound leg was captured.
        loop_flow.intercept_vendor = vendor
        # Chain: nearest-in-time non-loopback flow to the SAME host.
        best: tuple[float, Flow] | None = None
        for ot, of in outbound.get(host, []):
            if ot is None or t is None:
                continue
            if abs(ot - t) <= _CHAIN_WINDOW_S and (best is None or abs(ot - t) < abs(best[0] - t)):
                best = (ot, of)
        if best is not None:
            g["chains"][host] = best[1]
            # Cross-link the two legs so each flow's ladder can reference the other.
            loop_flow.chain_outbound_key = best[1].key
            best[1].chain_loopback_key = loop_flow.key

    out: list[Finding] = []
    for vendor, g in by_vendor.items():
        hosts = sorted(g["hosts"])
        sample = ", ".join(hosts[:6]) + (f" (+{len(hosts) - 6} more)" if len(hosts) > 6 else "")
        issuer_txt = "; ".join(sorted(g["issuers"])) or "unknown issuer"
        detail = (
            f"A TLS connection on loopback (127.0.0.1 / ::1) presented a certificate re-signed by "
            f"{vendor}. Both endpoints of a loopback flow are the SAME machine, so this proves a local "
            f"interception agent on THIS device is terminating and DECRYPTING TLS before the traffic "
            f"leaves the host (the real destination name is visible because the agent decrypts it "
            f"locally). This is vendor-agnostic evidence of endpoint-based inspection — a SASE/SWG "
            f"roaming client, an antivirus web-shield, or any local MITM proxy. "
            f"{len(hosts)} destination(s) decrypted locally: {sample}."
        )
        evidence = [f"loopback TLS leg, cert issuer: {issuer_txt}"]
        if g["chains"]:
            chained = sorted(g["chains"])
            detail += (" The matching OUTBOUND connection was also captured for: "
                       + ", ".join(chained[:4])
                       + (f" (+{len(chained) - 4} more)" if len(chained) > 4 else "")
                       + " — this is the probable second leg of the chain (app \u2192 local agent \u2192 "
                       "real destination), correlated by hostname + time, NOT cryptographic proof.")
            evidence.append(
                "probable chain (loopback leg \u2192 outbound leg): "
                + "; ".join(f"{h} \u2192 {g['chains'][h].key}" for h in chained[:4])
            )
        out.append(Finding(
            title=f"Local TLS interception on this device \u2014 {vendor}",
            severity="info",
            category="local_interception",
            detail=detail,
            evidence=evidence,
        ))
    return out
