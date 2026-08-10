"""HAR-derived findings: browser-reported errors and HTTP failures, Cisco Secure
Access DLP/web block pages (with attempt counts and timestamps recovered from the
blockinfo token), and standalone proxy proof from HAR alone (ingress IPs, Via
proxy nodes, QUIC/HTTP3 stripping and HTTP downgrade)."""
from __future__ import annotations

import re
from collections import Counter

from ..engine import Finding
from ..har import HarEntry, HarResult
from ..secure_access import lookup_ingress_region
from ..context import AnalysisContext
from .base import _fmt_clock


def _har_findings(har: HarResult, ctx: AnalysisContext) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    # Block attempts are grouped (not dropped): every retry of the same block
    # carries its own timestamp, which is evidence of WHEN it happened, so we
    # keep the count and the per-attempt times instead of deduplicating away.
    block_groups: dict[tuple[str, str, str], list[HarEntry]] = {}
    block_order: list[tuple[str, str, str]] = []
    for e in har.failed:
        if ctx.domain and e.host and ctx.domain.lower() not in e.host.lower():
            continue
        if e.block_type:
            # Group on the original destination recovered from the blockinfo
            # JWT (`url` claim) so the 302, its followed block.sse fetch and
            # every retry collapse into one finding that still counts attempts.
            _bi = e.block_info or {}
            gkey = ("block", _bi.get("original_host") or e.host, e.block_type)
            if gkey not in block_groups:
                block_groups[gkey] = []
                block_order.append(gkey)
            block_groups[gkey].append(e)
            continue
        key = (e.host, e.error_label or str(e.status))
        if key in seen:
            continue
        seen.add(key)

        if e.error_text:
            sev = "high" if e.error_category in {"cert_trust", "public_cert", "pinning_signal", "proxy"} else "medium"
            findings.append(Finding(
                title=f"HAR: {e.error_label} on {e.host}",
                severity=sev,
                category=e.error_category or "network",
                detail=f"Browser reported '{e.error_text}' requesting {e.url}.",
                evidence=[f"host={e.host} status={e.status} error={e.error_text} server_ip={e.server_ip or 'n/a'}"],
            ))
        elif e.status >= 400 or e.blocked:
            cat = "proxy" if e.status in (403, 407, 502, 503, 504) else "network"
            findings.append(Finding(
                title=f"HAR: HTTP {e.status} on {e.host}",
                severity="medium",
                category=cat,
                detail=f"Request to {e.url} returned HTTP {e.status} {e.status_text}.",
                evidence=[f"host={e.host} status={e.status} {e.status_text} server_ip={e.server_ip or 'n/a'}"],
            ))

    # Emit one finding per block destination, keeping the attempt count and the
    # per-attempt timestamps (each retry happened at a specific second — that is
    # evidence we must not throw away).
    for gkey in block_order:
        findings.append(_block_finding(gkey[1], gkey[2], block_groups[gkey]))
    return findings


def _block_finding(orig: str, block_type: str, entries: list[HarEntry]) -> Finding:
    """Build a single Secure Access block finding for one destination, carrying
    the number of attempts and the timestamp of each one."""
    # An "attempt" is the ORIGINAL blocked request, not the followed block-page
    # fetches (the 301/200 to block.sse.cisco.com are part of the same redirect
    # chain, so counting them would triple the real attempt count).
    primary = [e for e in entries if not (e.host or "").lower().endswith("block.sse.cisco.com")]
    attempt_entries = primary or entries
    # Prefer an entry that actually carries the decoded blockinfo for metadata.
    rep = next((e for e in entries if (e.block_info or {}).get("claims")), entries[0])
    bi = rep.block_info or {}
    claims = bi.get("claims") or {}
    orig_url = bi.get("original_url") or rep.url
    upload = any(e.method.upper() in {"POST", "PUT", "PATCH"} for e in attempt_entries)
    rule_id = claims.get("ruleid")
    org_id = claims.get("org")
    fnames = (claims.get("fnames") or "").strip()

    times = sorted(t for t in (_fmt_clock(e.started) for e in attempt_entries) if t)
    attempts = len(attempt_entries)
    count_tag = f" \u00d7{attempts}" if attempts > 1 else ""
    window = ""
    if times:
        window = f" between {times[0]} and {times[-1]}" if times[0] != times[-1] else f" at {times[0]}"

    ev = [f"original request: {rep.method} {orig_url[:160]}",
          f"attempts: {attempts}" + (f" (first {times[0]}, last {times[-1]})" if times else "")]
    if times:
        ev.append("attempt times (UTC): " + ", ".join(times[:40]) + (" ..." if len(times) > 40 else ""))
    if rule_id:
        ev.append(f"DLP rule id={rule_id}" + (f" org={org_id}" if org_id else ""))
    if fnames:
        ev.append(f"uploaded file(s): {fnames}")
    if claims:
        ev.append("blockinfo claims: " + ", ".join(f"{k}={v}" for k, v in claims.items() if v not in ("", None)))

    return Finding(
        title=f"HAR: {block_type} block on {orig}{count_tag}" + (" (upload)" if upload else ""),
        severity="high",
        category="proxy",
        detail=(f"Secure Access blocked {attempts} request(s) by {block_type}"
                + (f" while {rep.method}-ing data to {orig} (likely a file/prompt upload)" if upload else f" to {orig}")
                + (f", matching DLP rule {rule_id}" if rule_id else "")
                + (f" (uploaded: {fnames})" if fnames else "")
                + window
                + ". Each attempt was redirected to the block page (block.sse.cisco.com); "
                "the rule and original destination were recovered from the decoded blockinfo token."),
        evidence=ev,
    )


# --- Via header parsing (Cisco Secure Access proxy nodes) ---
# e.g. "HTTP/1.1 m_proxy_prod_aws_eu-central-1_1_1n, HTTP/1.1 s_proxy_prod_aws_eu-central-1_1_0n"
_VIA_NODE = re.compile(r'([mse])_proxy_[a-z]+_aws_([a-z]+-[a-z]+-\d+)', re.I)
_VIA_ROLE = {"m": "master", "s": "secondary", "e": "egress"}


def _parse_via_nodes(via: str) -> list[tuple[str, str]]:
    """Return list of (role, region) tuples found in a Via header value."""
    out: list[tuple[str, str]] = []
    for m in _VIA_NODE.finditer(via or ""):
        role = _VIA_ROLE.get(m.group(1).lower(), m.group(1).lower())
        out.append((role, m.group(2).lower()))
    return out


def _har_proxy_findings(har: HarResult, ctx: AnalysisContext) -> list[Finding]:
    """Standalone HAR signals proving Secure Access proxying even when no request
    failed: ingress IPs, Via proxy nodes, QUIC/HTTP3 stripping and HTTP downgrade.
    These do NOT require a PCAP — the HAR alone is sufficient evidence.
    """
    findings: list[Finding] = []
    entries = [e for e in har.entries
               if not (ctx.domain and e.host and ctx.domain.lower() not in e.host.lower())]
    if not entries:
        return findings

    total = len(entries)

    # 1) serverIPAddress -> Secure Access ingress
    ingress_hits: Counter = Counter()
    ingress_ips: dict[str, str] = {}
    for e in entries:
        region = lookup_ingress_region(e.server_ip) if e.server_ip else None
        if region:
            ingress_hits[region] += 1
            ingress_ips.setdefault(e.server_ip, region)
    if ingress_hits:
        n = sum(ingress_hits.values())
        regions = ", ".join(f"{r} ({c})" for r, c in ingress_hits.most_common())
        ip_list = ", ".join(f"{ip} [{r}]" for ip, r in list(ingress_ips.items())[:6])
        findings.append(Finding(
            title=(f"All HAR traffic egresses via Cisco Secure Access ({regions})"
                   if n == total else
                   f"{n}/{total} HAR requests egress via Cisco Secure Access ({regions})"),
            severity="info",
            category="tunnel",
            detail=(f"{n} of {total} HAR responses came from Secure Access SWG ingress IP(s), confirming the "
                    f"browser traffic was proxied through Secure Access regardless of HTTP success."),
            evidence=[f"ingress IPs: {ip_list}"],
        ))

    # 2) Via header -> Cisco proxy node roles + region
    roles: Counter = Counter()
    regions_c: Counter = Counter()
    via_count = 0
    via_example = None
    for e in entries:
        if not e.via:
            continue
        via_count += 1
        if via_example is None:
            via_example = e.via
        for role, region in _parse_via_nodes(e.via):
            roles[role] += 1
            regions_c[region] += 1
    if via_count:
        role_txt = ", ".join(f"{r}" for r, _ in roles.most_common()) or "proxy"
        region_txt = ", ".join(f"{r}" for r, _ in regions_c.most_common()) or "unknown"
        findings.append(Finding(
            title=f"Secure Access proxy chain present in Via header (region {region_txt})",
            severity="info",
            category="tunnel",
            detail=(f"{via_count}/{total} responses carry a Via header from Secure Access proxy nodes "
                    f"({role_txt}) in region {region_txt} — independent proof the SWG handled the request."),
            evidence=[f"Via: {via_example}"] if via_example else [],
        ))

    # 3) Alt-Svc stripped (QUIC/HTTP3 prevented so TCP proxy can see traffic)
    cleared = [e for e in entries if (e.alt_svc or "").strip().lower() == "clear"]
    if cleared:
        findings.append(Finding(
            title=f"QUIC/HTTP3 advertisement stripped by proxy ({len(cleared)} responses)",
            severity="info",
            category="quic",
            detail=("The proxy rewrote Alt-Svc to 'clear', preventing the browser from upgrading to QUIC/HTTP3. "
                    "This forces traffic over TCP so the SWG can proxy it — expected SWG behavior, but it disables "
                    "HTTP/3 for these origins."),
            evidence=[f"host={cleared[0].host} alt-svc=clear (x{len(cleared)})"],
        ))

    # 4) HTTP version downgrade (proxy forces HTTP/1.1 on origins that serve h2/h3)
    ver: Counter = Counter((e.http_version or "").lower() for e in entries if e.http_version)
    h1 = ver.get("http/1.1", 0)
    h2 = ver.get("http/2.0", 0) + ver.get("h2", 0)
    if h1 and h1 >= max(1, total // 2) and h1 > h2:
        findings.append(Finding(
            title=f"HTTP/1.1 downgrade through proxy ({h1}/{total} responses)",
            severity="info",
            category="tunnel",
            detail=("Most responses negotiated HTTP/1.1 even though the origins (e.g. chatgpt.com) normally serve "
                    "HTTP/2 or HTTP/3. The explicit proxy terminates and re-issues requests over HTTP/1.1, a common "
                    "side-effect of SWG proxying."),
            evidence=[f"http/1.1={h1} http/2={h2} of {total} responses"],
        ))

    return findings
