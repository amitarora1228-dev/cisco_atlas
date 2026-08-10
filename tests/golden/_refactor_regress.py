"""TEMP regression harness for the analyze.py -> findings/ refactor.

Runs analyze() in-process over a representative capture set in several SA-flag
modes and dumps a NORMALIZED, order-stable signature to JSON. No behavior may
change during the refactor, so `baseline` (before) and `check` (after) must be
byte-identical.

Usage:
    python _refactor_regress.py baseline     # capture golden output
    python _refactor_regress.py check        # compare against golden
"""
import sys
import json
import os

from app.analyze import analyze, AnalysisContext

DL = r"c:\Users\jmorenoc\Downloads"

# (tag, filename, is_har)
CAPS = [
    ("ip_not_set",     "access to server with ip not set.pcapng", False),
    ("quic",           "QUIC disable on LAN packet capture (1).pcapng", False),
    ("ytissue",        "YTIssue.pcapng", False),
    ("dlp_web",        "DLP WEB TEST.pcapng", False),
    ("captura_normal", "captura normal.pcapng", False),
    ("expl_proxy",     "Secure_Access_Explicit_Proxy-44535deb5756.pcap", False),
    ("har_dlp",        "dlp-traffic2.har", True),
    ("har_ivanti",     "www.ivanti.com.har", True),
]

# SA-flag modes to exercise every gated path.
PCAP_MODES = [
    ("agnostic", {}),
    ("sa",       {"secure_access_mode": True}),
    ("sa_tunnel", {"secure_access_mode": True, "sa_tunnel": True}),
]
HAR_MODES = [
    ("agnostic", {}),
    ("sa",       {"secure_access_mode": True}),
]

BASELINE = os.path.join(os.path.dirname(__file__), "_regress_baseline.json")


def _sig_findings(res):
    out = []
    for x in res.all_findings:
        out.append(f"{x.severity}|{x.category}|{x.title}")
    return sorted(out)


def signature(res):
    return {
        "diagnosis": res.summary_diagnosis or "",
        "confidence": res.confidence,
        "reduced": bool(res.reduced),
        "n_flows": len(res.flow_reports),
        "classifications": sorted(res.classifications or []),
        "tech_groups": sorted((g.get("label", "") for g in (res.tech_groups or []))),
        "findings": _sig_findings(res),
        "notes": sorted(res.notes or []),
    }


def run_all():
    result = {}
    for tag, fname, is_har in CAPS:
        path = os.path.join(DL, fname)
        if not os.path.exists(path):
            print(f"  SKIP {tag}: missing {fname}")
            continue
        modes = HAR_MODES if is_har else PCAP_MODES
        for mode_name, kw in modes:
            key = f"{tag}::{mode_name}"
            ctx = AnalysisContext(**kw)
            try:
                if is_har:
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        res = analyze(None, fh.read(), ctx)
                else:
                    res = analyze(path, None, ctx)
                result[key] = signature(res)
                print(f"  OK  {key}  ({len(res.all_findings)} findings)")
            except Exception as e:  # noqa: BLE001
                result[key] = {"ERROR": repr(e)}
                print(f"  ERR {key}: {e!r}")
    return result


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    print(f"== regression {mode} ==")
    current = run_all()
    if mode == "baseline":
        with open(BASELINE, "w", encoding="utf-8") as fh:
            json.dump(current, fh, indent=2, ensure_ascii=False)
        print(f"\nBaseline written: {BASELINE} ({len(current)} runs)")
        return
    # check
    if not os.path.exists(BASELINE):
        print("No baseline; run 'baseline' first.")
        sys.exit(2)
    with open(BASELINE, "r", encoding="utf-8") as fh:
        golden = json.load(fh)
    diffs = 0
    for key in sorted(set(golden) | set(current)):
        g = golden.get(key)
        c = current.get(key)
        if g is None:
            print(f"  NEW run {key}"); diffs += 1; continue
        if c is None:
            print(f"  MISSING run {key}"); diffs += 1; continue
        if g == c:
            continue
        diffs += 1
        print(f"\n### DIFF {key}")
        for field in sorted(set(g) | set(c)):
            gv, cv = g.get(field), c.get(field)
            if gv == cv:
                continue
            if isinstance(gv, list) and isinstance(cv, list):
                gset, cset = set(gv), set(cv)
                removed = sorted(gset - cset)
                added = sorted(cset - gset)
                if removed:
                    print(f"  [{field}] REMOVED:")
                    for r in removed:
                        print(f"     - {r}")
                if added:
                    print(f"  [{field}] ADDED:")
                    for a in added:
                        print(f"     + {a}")
            else:
                print(f"  [{field}] {gv!r} -> {cv!r}")
    if diffs == 0:
        print("\nIDENTICAL — no regressions. ✔")
    else:
        print(f"\n{diffs} run(s) differ. ✘")
        sys.exit(1)


if __name__ == "__main__":
    main()
