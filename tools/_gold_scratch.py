"""Scratch script (not a test): run current analyzer on the two new captures, dump findings + gaps."""
import sys, time
from collections import Counter
from capture_inspector.analyze import analyze, AnalysisContext

CAPS = {
    "HOTSPOT": r"c:\Users\jmorenoc\Downloads\uploading on mobilephone hotspot  (2).pcapng",
    "QUIC":    r"c:\Users\jmorenoc\Downloads\QUIC disable on LAN packet capture (1).pcapng",
}

for tag, path in CAPS.items():
    print("\n" + "=" * 70)
    print(tag, path)
    print("=" * 70)
    t0 = time.time()
    res = analyze(path, None, AnalysisContext())
    print(f"elapsed {time.time()-t0:.1f}s  reduced={res.reduced}  flows={len(res.flow_reports)}")
    print("diagnosis:", res.summary_diagnosis[:300])
    print("confidence:", res.confidence)

    flows = [fr.flow for fr in res.flow_reports]
    # protocol / channel mix
    quic = [f for f in flows if getattr(f, "is_quic", False)]
    tls = [f for f in flows if f.sni or f.negotiated_version]
    rst = [f for f in flows if f.rst_count]
    print(f"flows: quic={len(quic)} tls={len(tls)} rst={len(rst)}")

    # severities
    sev = Counter(x.severity for x in res.all_findings)
    print("findings sev:", dict(sev))
    # top finding titles
    print("findings:")
    seen = set()
    for x in sorted(res.all_findings, key=lambda f: f.severity):
        key = x.title.split(":")[0]
        if key in seen: continue
        seen.add(key)
        print(f"   [{x.severity}] {x.title[:110]}")
    # notes
    for n in res.notes:
        print("   NOTE:", n[:160])
