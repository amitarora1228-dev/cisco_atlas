"""Proxy auto-config findings: Web Proxy Auto-Discovery (WPAD) DNS lookups and
PAC / wpad.dat fetches. A failed WPAD/PAC makes clients fall back to DIRECT
(bypassing the Secure Access SWG) or stall."""
from __future__ import annotations

from ..engine import Finding
from ..pcap import Flow
from ..dns_analysis import DnsRecord


def _pac_wpad_findings(dns_records: list[DnsRecord], flows: list[Flow]) -> list[Finding]:
    """Detect Web Proxy Auto-Discovery (WPAD) and PAC-file problems.

    Browsers using 'Automatically detect settings' resolve wpad.<domain> then
    fetch http://wpad.<domain>/wpad.dat. A failed WPAD/PAC lookup makes the
    client fall back to DIRECT (skipping the SWG) or stall — a frequent reason
    traffic isn't going through Secure Access as expected.
    """
    out: list[Finding] = []

    # 1) WPAD DNS lookups.
    for rec in dns_records:
        if rec.name.startswith("wpad.") or rec.name == "wpad":
            if rec.issue:
                out.append(Finding(
                    title=f"WPAD auto-discovery failed: {rec.name} ({rec.issue})",
                    severity="medium",
                    category="proxy",
                    detail=("The client tried WPAD proxy auto-discovery but the DNS lookup failed "
                            f"({rec.issue_detail}). With WPAD unavailable the browser typically falls back to a "
                            "DIRECT connection, bypassing the Secure Access SWG — which can explain why traffic "
                            "isn't being proxied/decrypted. If you use a PAC URL instead of WPAD, this is benign; "
                            "if you rely on WPAD, fix the wpad DNS record / DHCP option 252."),
                    evidence=[f"DNS {rec.name} -> {rec.issue}"],
                ))
            else:
                out.append(Finding(
                    title=f"WPAD auto-discovery in use: {rec.name} resolved",
                    severity="info",
                    category="proxy",
                    detail=("The client is using WPAD proxy auto-discovery and wpad resolved successfully. "
                            "The browser will fetch a wpad.dat PAC file to decide how to reach each destination. "
                            "Verify the PAC points corporate traffic at the Secure Access SWG."),
                    evidence=[f"DNS {rec.name} -> {', '.join(rec.addresses) or 'resolved'}"],
                ))

    # 2) PAC / wpad.dat HTTP fetches and whether they failed.
    for flow in flows:
        for req in flow.http_requests:
            uri = (req.get("uri") or "").lower()
            host = (req.get("host") or "").lower()
            if uri.endswith("wpad.dat") or uri.endswith(".pac") or host.startswith("wpad."):
                failed = any(s in ("403", "404", "407", "500", "502", "503", "504") for s in flow.http_statuses)
                label = req.get("uri") or host
                if failed:
                    out.append(Finding(
                        title=f"PAC/WPAD file fetch failed ({', '.join(flow.http_statuses) or 'no response'})",
                        severity="high",
                        category="proxy",
                        detail=(f"The client requested a proxy auto-config file ({label}) but the fetch failed. "
                                "Without a usable PAC the browser falls back to DIRECT and skips the Secure Access "
                                "SWG, so policy/decryption won't apply. Make the PAC reachable and return HTTP 200 "
                                "with the correct MIME type."),
                        evidence=[f"{req.get('method','GET')} {label} -> {', '.join(flow.http_statuses) or 'no response'}"],
                        flow_key=flow.key,
                    ))
                else:
                    out.append(Finding(
                        title=f"PAC/WPAD file fetched: {label}",
                        severity="info",
                        category="proxy",
                        detail=("The client downloaded a proxy auto-config (PAC) file. This script decides which "
                                "destinations go through the Secure Access SWG vs DIRECT — review it if some "
                                "traffic isn't being proxied as expected."),
                        evidence=[f"{req.get('method','GET')} {label}"],
                        flow_key=flow.key,
                    ))
    return out
