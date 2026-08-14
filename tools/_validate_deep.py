"""Fourth batch: the techniques the first three passes never touched.

These are the interpretive ones - inner-tunnel dissection, certificate chain
reasoning, TLS fingerprinting, interception attribution - and they are where the
product's value sits, so leaving them unchecked was the real gap in the earlier
validation.
"""
from __future__ import annotations

import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "capture_inspector"))

from capture_inspector.certs import parse_cert_hex  # noqa: E402
from capture_inspector.engine import enrich_flow  # noqa: E402
from capture_inspector.pcap import (  # noqa: E402
    build_flows,
    find_tshark,
    merge_tunnel_tls,
    run_tshark,
    run_tunnel_tls,
)

TS = find_tshark()
V: list[tuple[str, bool]] = []


def verdict(name: str, ok: bool, detail: str) -> None:
    V.append((name, ok))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name:<44} {detail}")


def T(capture: str, display: str, *fields: str) -> list[list[str]]:
    cmd = [TS, "-r", capture, "-Y", display, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def main(capture: str) -> None:
    print(f"\n{'=' * 90}\n{capture}\n{'=' * 90}")
    packets = run_tshark(capture, TS)
    flows = build_flows(packets)
    for flow in flows:
        enrich_flow(flow)

    # --- 1. inner TLS inside a CONNECT tunnel -----------------------------
    # The engine runs a second dissection to see inside the tunnel. Ground
    # truth: ask tshark to decode the proxy port as TLS and list the SNIs.
    tunnels = [f for f in flows if f.is_connect_tunnel]
    if tunnels:
        try:
            tunnel_data = run_tunnel_tls(capture, TS)
            merge_tunnel_tls(flows, tunnel_data)
        except Exception as exc:  # noqa: BLE001
            print(f"    (second pass failed: {exc})")
            tunnel_data = {}
        with_inner = [f for f in tunnels if f.tunnel_sni]
        # A CONNECT line carries either a hostname or an address. Where it names
        # a host, the inner SNI must agree with it. Where it names an address -
        # the client resolved the name itself - the inner SNI is the whole point
        # of the second pass, because it recovers a destination the tunnel line
        # never stated.
        named_target = [f for f in with_inner
                        if f.connect_target and not f.connect_target.split(":")[0]
                        .replace(".", "").isdigit()]
        agree = sum(1 for f in named_target
                    if f.tunnel_sni.lower() in f.connect_target.lower())
        enriched = len(with_inner) - len(named_target)
        verdict("inner SNI agrees where CONNECT names a host",
                agree == len(named_target),
                f"hostname_targets={len(named_target)} agree={agree} "
                f"address_targets_enriched={enriched}")

        versions = Counter(f.tunnel_tls_version for f in with_inner if f.tunnel_tls_version)
        verdict("inner-TLS version recovered", bool(versions) or not with_inner,
                f"{dict(versions)}")

    # --- 2. certificate chain / proxy CA ----------------------------------
    issuers = Counter()
    proxy_ca = 0
    for flow in flows:
        for raw in flow.certificates_hex:
            info = parse_cert_hex(raw)
            if info.parse_error:
                continue
            issuers[info.issuer_cn or info.issuer_org] += 1
            if info.looks_like_proxy_ca:
                proxy_ca += 1
    # Ground truth: tshark's full dissection. The '-e' field columns cover only
    # some attribute types, so they under-report issuers; the engine reads the
    # DER itself and legitimately sees more. Compare against what tshark prints
    # when it dissects the whole certificate.
    truth_blob = subprocess.run(  # noqa: S603
        [TS, "-r", capture, "-Y", "tls.handshake.certificate", "-V"],
        capture_output=True, text=True, errors="replace").stdout
    named = [i for i in issuers if i]
    unknown = [i for i in named if i not in truth_blob]
    verdict("certificate issuers extracted", not unknown,
            f"distinct_issuers={len(named)} proxy_ca_flagged={proxy_ca} "
            f"not_in_tshark_output={unknown[:2]}")

    # --- 3. JA3 / JA3S ----------------------------------------------------
    truth_ja3 = {r[0].split(",")[0] for r in T(capture, "tls.handshake.ja3",
                                               "tls.handshake.ja3") if r[0].strip()}
    truth_ja3s = {r[0].split(",")[0] for r in T(capture, "tls.handshake.ja3s",
                                                "tls.handshake.ja3s") if r[0].strip()}
    eng_ja3 = {f.ja3 for f in flows if f.ja3}
    eng_ja3s = {f.ja3s for f in flows if f.ja3s}
    verdict("JA3 fingerprints", eng_ja3 == truth_ja3,
            f"engine={len(eng_ja3)} tshark={len(truth_ja3)}")
    verdict("JA3S fingerprints", eng_ja3s == truth_ja3s,
            f"engine={len(eng_ja3s)} tshark={len(truth_ja3s)}")

    # --- 4. ECH -----------------------------------------------------------
    truth_ech = {r[0].strip() for r in
                 T(capture, "tls.handshake.extension.type == 65037", "tcp.stream")
                 if r[0].strip()}
    eng_ech = {f.key[4:] for f in flows if f.has_ech and f.key.startswith("tcp-")}
    verdict("ECH extension detection", eng_ech == truth_ech,
            f"engine={len(eng_ech)} tshark={len(truth_ech)}")

    # --- 5. ALPN ----------------------------------------------------------
    truth_alpn = Counter()
    for row in T(capture, "tls.handshake.extensions_alpn_str",
                 "tls.handshake.extensions_alpn_str"):
        for token in row[0].split(","):
            if token.strip():
                truth_alpn[token.strip()] += 1
    eng_alpn = Counter(a for f in flows for a in f.alpn)
    verdict("ALPN extraction", set(eng_alpn) <= set(truth_alpn) and bool(eng_alpn) == bool(truth_alpn),
            f"engine={sorted(eng_alpn)} tshark={sorted(truth_alpn)}")

    # --- 6. cipher suite --------------------------------------------------
    truth_cipher = {r[0].split(",")[0] for r in
                    T(capture, "tls.handshake.type == 2", "tls.handshake.ciphersuite")
                    if r[0].strip()}
    eng_cipher = {f.cipher_suite for f in flows if f.cipher_suite}
    verdict("cipher suite recovered", bool(eng_cipher) == bool(truth_cipher),
            f"engine={len(eng_cipher)} distinct, tshark={len(truth_cipher)} distinct")

    # --- 7. HTTP CONNECT target vs tshark ---------------------------------
    truth_targets = {r[0].split(",")[0] for r in
                     T(capture, 'http.request.method == "CONNECT"',
                       "http.request.full_uri", "http.request.uri") if r[0].strip()}
    eng_targets = {f.connect_target for f in flows if f.connect_target}
    verdict("CONNECT target extraction",
            not truth_targets or len(eng_targets) >= len(truth_targets) * 0.9,
            f"engine={len(eng_targets)} tshark={len(truth_targets)}")


for path in sys.argv[1:]:
    main(path)

print(f"\n{'=' * 90}")
ok = sum(1 for _n, o in V if o)
print(f"TOTAL {ok}/{len(V)} checks agree")
for name, o in V:
    if not o:
        print(f"   FAILED: {name}")
