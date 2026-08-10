"""Capture-derived steering coverage: what actually got inspected, measured on
the wire rather than taken from the agent's own counters.

The roaming module's self-report gives running totals whose population is not
documented, so a percentage built from them mixes things that are not
comparable. Everything here is instead counted from the capture, with each
category kept separate because they are steered by different mechanisms and a
bypass means something different in each:

* Web        - TCP to 80/443 toward a public destination. The only traffic the
               SWG can proxy, and therefore the only traffic a "web bypass"
               can be measured against.
* DNS        - resolution, steered by the roaming module's local listener. A DNS
               query that goes straight to another resolver escapes Umbrella
               policy even when the web request that follows is inspected.
* Umbrella
  DNS
  transport  - the module forwarding those intercepted queries upstream,
               encrypted, over UDP/443. It looks exactly like HTTPS on the wire
               and is neither: counting it as web would inflate both totals.
* QUIC       - UDP/443 that is NOT that transport. It cannot be proxied at all,
               so it is un-inspectable by construction.

Excluded from every ratio: private/RFC1918 and loopback destinations (the SWG
only handles internet-bound traffic), non-web ports, and the steering
infrastructure itself (the explicit proxy and the SWG ingress).
"""
from __future__ import annotations

from ..engine import Finding
from ..pcap import Flow
from ..dns_analysis import PUBLIC_DNS_RESOLVERS, dns_resolver_name
from ..secure_access import is_secure_access_ingress
from .base import _is_private_ip, _is_loopback_ip

# Resolver addresses operated by Umbrella/OpenDNS. Traffic to these on UDP/443
# is the roaming module's encrypted DNS channel, not web browsing.
_UMBRELLA_RESOLVERS = {ip for ip, name in PUBLIC_DNS_RESOLVERS.items()
                       if "umbrella" in name.lower() or "opendns" in name.lower()}

_WEB_PORTS = {80, 443, 8080}


def _is_multicast(ip: str | None) -> bool:
    """Local name discovery (mDNS 224.0.0.251, LLMNR 224.0.0.252, IPv6 ff02::).

    These never leave the link and are not resolution the module could steer, so
    counting them as "DNS that escaped Umbrella" would invent a bypass."""
    if not ip:
        return False
    if ip.startswith("ff") and ":" in ip:
        return True
    try:
        return 224 <= int(ip.split(".")[0]) <= 239
    except (ValueError, IndexError):
        return False


def _is_umbrella_resolver(ip: str | None) -> bool:
    return bool(ip) and ip in _UMBRELLA_RESOLVERS


def _dest_keys(flow: Flow) -> set[str]:
    """Every name this destination is known by, so the two paths can be matched.

    A CONNECT tunnel names its target by IP when the client resolved DNS itself,
    while the direct connection to the same host is identified by its SNI.
    Comparing one set against the other would never match, and every inspected
    host would be reported as bypassed — so a destination carries both forms and
    counts as the same place if either overlaps."""
    keys: set[str] = set()
    if flow.is_connect_tunnel and flow.connect_target:
        # Only the tunnel target. The address this flow was sent TO is the
        # proxy, which every steered connection shares — including it would
        # merge every steered destination into one and report a single place
        # where dozens were reached.
        keys.add(flow.connect_target.rsplit(":", 1)[0].strip("[]").lower())
        if flow.tunnel_sni:
            keys.add(str(flow.tunnel_sni).lower())
        return keys
    for v in (flow.tunnel_sni, flow.sni, flow.resolved_host, flow.dns_query, flow.dst_ip):
        if v:
            keys.add(str(v).lower())
    return keys


def _is_real_session(flow: Flow) -> bool:
    """Did the capture actually show a web session being attempted here?

    A destination must not be judged on stray packets. A capture that starts or
    ends mid-conversation, or that catches a late ACK or a retransmission,
    leaves addresses on port 443 with no handshake behind them; treating those
    as destinations invents traffic that was never inspected because it was
    never requested. Requiring a ClientHello, a CONNECT or an HTTP request keeps
    the denominator to sessions that genuinely happened."""
    return bool(flow.client_hello or flow.is_connect_tunnel or flow.sni
                or flow.http_statuses or flow.connect_status)


def _steering_coverage_findings(flows: list[Flow], packets: list,
                                sa_tunnel: bool = False,
                                stats_out: dict | None = None) -> list[Finding]:
    """Quantify, per category, how much of what COULD be inspected was.

    ``stats_out``, when given, is filled with the same numbers in structured
    form. The findings list is prose meant to be read one item at a time, which
    is the wrong shape for a summary panel; handing the figures over directly
    lets the UI show them beside the agent's own counters, where the comparison
    actually means something.

    ``sa_tunnel`` marks a site-to-site (IPsec) deployment. There the endpoint
    addresses the real origin and the encapsulation happens downstream, so
    steering leaves no trace a host-side capture can see — every destination
    would look un-inspected. The web verdict is therefore withheld in that mode
    rather than reported as a total bypass. DNS is unaffected: the roaming
    module's local listener is direct evidence either way."""
    steered_keys: set[str] = set()          # every identifier proven steered
    steered_groups: list[set[str]] = []     # one identifier-set per steered destination
    direct_groups: list[set[str]] = []      # one identifier-set per direct destination
    quic_dests: set[str] = set()
    umbrella_dns_flows = 0
    umbrella_ips: set[str] = set()
    web_flows_steered = 0
    web_flows_direct = 0
    # Kept apart rather than lumped together: each is excluded from the ratios
    # for a DIFFERENT reason, and an operator reading the breakdown needs to see
    # which reason applied to how much of the capture.
    loopback_flows = 0      # the agent's own local listener
    internal_flows = 0      # private -> private, never leaves the LAN
    nonweb_flows = 0        # ports the SWG cannot proxy
    stray_flows = 0         # web port, but no session ever observed

    for f in flows:
        dst = f.dst_ip
        # The SWG only ever handles internet-bound traffic. Loopback is the
        # agent's own listener and private ranges never leave the LAN, so
        # neither can be "bypassed".
        if not dst:
            continue
        if _is_loopback_ip(dst):
            loopback_flows += 1
            continue
        if _is_private_ip(dst):
            internal_flows += 1
            continue

        if f.transport == "udp" and (f.dst_port == 443 or f.is_quic):
            # UDP/443 splits in two: the roaming module's encrypted DNS channel,
            # and everything else, which is real QUIC and cannot be proxied.
            if _is_umbrella_resolver(dst):
                umbrella_dns_flows += 1
                umbrella_ips.add(dst)
            else:
                quic_dests.add((f.sni or f.resolved_host or dst).lower())
            continue

        if f.transport != "tcp" or f.dst_port not in _WEB_PORTS:
            nonweb_flows += 1
            continue

        # DNS-over-443 to an Umbrella resolver is the same encrypted channel
        # arriving over TCP. Not web.
        if _is_umbrella_resolver(dst):
            umbrella_dns_flows += 1
            umbrella_ips.add(dst)
            continue

        if f.is_connect_tunnel and f.connect_target:
            # The client explicitly asked the proxy to reach this host: proof of
            # steering for that destination.
            k = _dest_keys(f)
            steered_keys |= k
            steered_groups.append(k)
            web_flows_steered += 1
            continue

        if is_secure_access_ingress(f.proxy_ip or dst):
            # Landed on a known SWG ingress — steered, but the ingress itself is
            # infrastructure and is not a destination to be counted.
            web_flows_steered += 1
            continue

        keys = _dest_keys(f)
        if keys and _is_real_session(f):
            direct_groups.append(keys)
            web_flows_direct += 1
        else:
            stray_flows += 1

    # DNS steering, counted from the queries themselves.
    dns_intercepted = 0
    dns_direct = 0
    direct_resolvers: set[str] = set()
    for pkt in packets:
        if pkt.first("dns.flags.response") != "0":
            continue
        d = pkt.first("ip.dst") or pkt.first("ipv6.dst")
        if not d or _is_multicast(d):
            continue
        if _is_loopback_ip(d):
            dns_intercepted += 1
        elif _is_umbrella_resolver(d):
            dns_intercepted += 1
        else:
            dns_direct += 1
            direct_resolvers.add(d)

    out: list[Finding] = []

    # Destination counts, not just connection counts: the same host opens many
    # connections, so "41 connections" alone says nothing about how many places
    # were actually reached.
    def _merge(groups: list[set[str]]) -> list[set[str]]:
        acc: list[set[str]] = []
        for g in groups:
            hit = next((m for m in acc if m & g), None)
            if hit:
                hit |= g
            else:
                acc.append(set(g))
        return acc

    steered_dests = len(_merge(steered_groups))
    direct_dests = len(_merge(direct_groups))

    # --- Full inventory ------------------------------------------------------
    # Every category the capture was split into, including the ones deliberately
    # left out of the ratios. Without this the percentages are unauditable: the
    # reader cannot see what went into the denominator, what was set aside, or
    # why. It is the breakdown that makes the two figures below checkable rather
    # than something to be taken on trust.
    #
    # Zero rows are KEPT. "QUIC: 0" is a result, not an absence: it says nothing
    # slipped past over a protocol the SWG cannot proxy, which is exactly what
    # someone auditing coverage needs to know. Hiding it forces them to wonder
    # whether it was measured at all.
    _res = ", ".join(sorted(direct_resolvers)[:3])
    _umb = ", ".join(sorted(umbrella_ips)[:2])
    rows = [
        ("DNS taken by the roaming module",
         f"{dns_intercepted} query(ies)", "counted \u2014 DNS policy applied"),
        ("DNS sent to another resolver",
         f"{dns_direct} query(ies)" + (f" \u2192 {_res}" if _res else ""),
         "counted \u2014 escaped DNS policy"),
        ("Umbrella encrypted-DNS channel",
         f"{umbrella_dns_flows} flow(s) on port 443" + (f" \u2192 {_umb}" if _umb else ""),
         "excluded \u2014 neither web nor QUIC"),
        ("QUIC (UDP/443, not the Umbrella channel)",
         f"{len(quic_dests)} destination(s)",
         "counted \u2014 cannot be proxied at all"),
        ("Web steered through the SWG",
         f"{web_flows_steered} connection(s) \u00b7 {steered_dests} destination(s)",
         "counted \u2014 inspected"),
        ("Web going direct",
         f"{web_flows_direct} connection(s) \u00b7 {direct_dests} destination(s)",
         "counted \u2014 judged per destination"),
        ("Loopback (the agent's own listener)",
         f"{loopback_flows} flow(s)", "excluded \u2014 never leaves the device"),
        ("Private / internal destinations",
         f"{internal_flows} flow(s)", "excluded \u2014 the SWG only handles internet traffic"),
        ("Non-web ports",
         f"{nonweb_flows} flow(s)", "excluded \u2014 the SWG cannot proxy them"),
        ("Web ports with no session observed",
         f"{stray_flows} flow(s)", "excluded \u2014 stray packets, nothing was requested"),
    ]
    listed = "; ".join(f"{name}: {count} ({why})" for name, count, why in rows)
    if stats_out is not None:
        stats_out.update({
            "web_steered_flows": web_flows_steered,
            "web_direct_flows": web_flows_direct,
            "dns_intercepted": dns_intercepted,
            "dns_direct": dns_direct,
            "dns_direct_resolvers": sorted(direct_resolvers)[:5],
            "umbrella_dns_flows": umbrella_dns_flows,
            "quic_dests": len(quic_dests),
            "loopback_flows": loopback_flows,
            "internal_flows": internal_flows,
            "nonweb_flows": nonweb_flows,
            "stray_flows": stray_flows,
            "steered_dests": steered_dests,
            "direct_dests": direct_dests,
            "rows": [{"name": n, "count": c, "why": w} for n, c, w in rows],
        })
    umb_note = (" The Umbrella encrypted-DNS flows are worth singling out: they run to an Umbrella/OpenDNS "
                "resolver on port 443, which looks exactly like HTTPS on the wire but is the module "
                "forwarding the queries it intercepted. Counting them as browsing would inflate both the "
                "total and the inspected share." if umbrella_dns_flows else "")
    out.append(Finding(
        title="Traffic breakdown: what could be inspected, and what was left out",
        severity="info",
        category="swg_coverage_info",
        detail=("Every category this capture was split into, so the coverage figures can be checked rather "
                "than taken on trust. " + listed + ". "
                "The exclusions are not an oversight: each one is traffic the SWG was never in a position to "
                "inspect, and counting it would drag the percentage toward a number that says nothing about "
                "whether policy is working." + umb_note),
        evidence=[f"web_steered_flows={web_flows_steered} web_direct_flows={web_flows_direct} "
                  f"dns_intercepted={dns_intercepted} dns_direct={dns_direct} "
                  f"umbrella_dns_flows={umbrella_dns_flows} quic_dests={len(quic_dests)} "
                  f"loopback={loopback_flows} internal={internal_flows} nonweb={nonweb_flows} "
                  f"stray={stray_flows}"],
    ))

    # --- Web -----------------------------------------------------------------
    # A destination reached BOTH ways was inspected, so it is not a bypass. Only
    # destinations never once seen going through the SWG count as excluded —
    # counting "every direct connection" instead would report a host as bypassed
    # while the very same host was being inspected on another connection.
    #
    # Two direct connections belong to the same place when they share any
    # identifier, so the groups are merged before counting; otherwise one host
    # known by both its name and its address would be counted twice.
    merged: list[set[str]] = []
    for grp in direct_groups:
        hit = next((m for m in merged if m & grp), None)
        if hit:
            hit |= grp
        else:
            merged.append(set(grp))
    both = [m for m in merged if m & steered_keys]
    bypassed = [m for m in merged if not (m & steered_keys)]

    denom = len(merged) + len(quic_dests)
    excluded = len(bypassed) + len(quic_dests)
    if denom and not sa_tunnel:
        pct = excluded / denom * 100
        if stats_out is not None:
            stats_out.update({
                "web_total_dests": denom,
                "web_inspected_dests": len(both),
                "web_excluded_dests": len(bypassed),
                "web_excluded_pct": round(pct),
                "web_examples": sorted(min(m, key=len) for m in bypassed)[:5],
            })
        sev = "medium" if pct >= 25 else ("low" if excluded else "info")
        both_txt = ""
        if both:
            both_txt = (f" {len(both)} destination(s) were seen BOTH through the proxy and directly; those "
                        f"count as inspected, since the SWG did see them. Why a host takes both paths is not "
                        f"visible on the wire and is not guessed here.")
        quic_txt = (f" {len(quic_dests)} destination(s) were reached over QUIC, which cannot be proxied at all "
                    f"and is therefore counted as un-inspected." if quic_dests else
                    " No QUIC was present, so nothing was un-inspectable for that reason.")
        examples = ", ".join(sorted(min(m, key=len) for m in bypassed)[:5])
        out.append(Finding(
            title=f"Web inspection coverage: {pct:.0f}% of internet destinations were NOT inspected "
                  f"({excluded} of {denom})",
            severity=sev,
            category="swg_coverage",
            detail=(f"Measured from this capture, not from the agent's counters. Of {denom} internet "
                    f"destination(s) the SWG could have inspected, {len(bypassed)} were never seen going "
                    f"through it."
                    + both_txt + quic_txt +
                    (f" Not inspected: {examples}." if examples else "") +
                    " Private, loopback and non-web traffic is deliberately left out: the SWG only handles "
                    "internet-bound HTTP/HTTPS, so counting LAN or non-web connections would understate "
                    "coverage. Counting is per DESTINATION rather than per connection, because the same host "
                    "commonly opens many connections and some take each path."),
            evidence=[f"destinations: total={len(merged)} inspected={len(both)} not-inspected={len(bypassed)} "
                      f"quic={len(quic_dests)} | flows: steered={web_flows_steered} "
                      f"direct={web_flows_direct} umbrella_dns={umbrella_dns_flows} "
                      f"excluded: loopback={loopback_flows} internal={internal_flows} "
                      f"nonweb={nonweb_flows} stray={stray_flows}"],
        ))

    # --- DNS -----------------------------------------------------------------
    dns_total = dns_intercepted + dns_direct
    if dns_total:
        dpct = dns_direct / dns_total * 100
        if stats_out is not None:
            stats_out.update({
                "dns_total": dns_total,
                "dns_excluded_pct": round(dpct),
            })
        dsev = "medium" if dpct >= 25 else ("low" if dns_direct else "info")
        where = ", ".join(sorted(direct_resolvers)[:5]) if direct_resolvers else ""
        out.append(Finding(
            title=f"DNS inspection coverage: {dpct:.0f}% of queries did NOT go through Umbrella "
                  f"({dns_direct} of {dns_total})",
            severity=dsev,
            category="swg_coverage",
            detail=(f"{dns_intercepted} of {dns_total} DNS query(ies) were taken by the roaming module's local "
                    f"listener (or sent to an Umbrella resolver) and therefore had DNS-layer policy applied. "
                    + (f"{dns_direct} went straight to another resolver ({where}), escaping that policy even if "
                       f"the web request that follows is still inspected. "
                       if dns_direct else "None escaped it. ") +
                    "DNS is counted separately from web on purpose: they are steered by different mechanisms, "
                    "so a device can have full web coverage and no DNS coverage, or the reverse."),
            evidence=[f"dns_intercepted={dns_intercepted} dns_direct={dns_direct} "
                      f"direct_resolvers={sorted(direct_resolvers)[:5]}"],
        ))

    # --- Umbrella's own encrypted DNS channel --------------------------------
    # Reported as a row of the breakdown above rather than as a finding of its
    # own: it is context for the numbers, not a separate observation, and
    # stating it twice only crowds the report.

    return out
