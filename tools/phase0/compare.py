"""Run both extractors over the same captures and report where they differ.

Phase 0's exit criterion is not "the new reader works". It is a measured,
field-by-field statement of how far it is from the reader in production, so the
migration is scoped with the losses named rather than discovered later.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "atlas_core"))
sys.path.insert(0, str(ROOT / "packages" / "capture_inspector"))
sys.path.insert(0, str(Path(__file__).parent))

from atlas_core.flows import extract_wire_flows  # noqa: E402
from dpkt_extractor import extract_wire_flows_dpkt  # noqa: E402
from serialize import TIERS, TOLERANT, flow_key, flow_to_dict  # noqa: E402


def _close_enough(field: str, left, right) -> bool:
    if left == right:
        return True
    if left is None or right is None:
        return False
    tolerance = TOLERANT.get(field)
    if tolerance is None:
        return False
    try:
        if field in ("first_seen", "last_seen"):
            from datetime import datetime
            return abs((datetime.fromisoformat(left) - datetime.fromisoformat(right)).total_seconds()) <= tolerance
        return abs(float(left) - float(right)) <= tolerance
    except (TypeError, ValueError):
        return False


def compare(capture: str) -> dict:
    started = time.perf_counter()
    reference = extract_wire_flows(capture)
    tshark_seconds = time.perf_counter() - started

    started = time.perf_counter()
    candidate = extract_wire_flows_dpkt(capture)
    dpkt_seconds = time.perf_counter() - started

    left = {flow_key(f): flow_to_dict(f) for f in reference}
    right = {flow_key(f): flow_to_dict(f) for f in candidate}

    only_tshark = sorted(set(left) - set(right))
    only_dpkt = sorted(set(right) - set(left))
    shared = sorted(set(left) & set(right))

    per_field: dict[str, dict] = {}
    examples: dict[str, list] = {}
    for tier, fields in TIERS.items():
        for field in fields:
            match = 0
            for key in shared:
                if _close_enough(field, left[key][field], right[key][field]):
                    match += 1
                elif len(examples.setdefault(field, [])) < 3:
                    examples[field].append(
                        {"flow": key, "tshark": left[key][field], "dpkt": right[key][field]}
                    )
            per_field[field] = {
                "tier": tier,
                "match": match,
                "of": len(shared),
                "pct": round(100 * match / len(shared), 1) if shared else None,
            }

    return {
        "capture": Path(capture).name,
        "flows": {"tshark": len(reference), "dpkt": len(candidate), "shared": len(shared)},
        "only_tshark": only_tshark[:5],
        "only_dpkt": only_dpkt[:5],
        "seconds": {"tshark": round(tshark_seconds, 2), "dpkt": round(dpkt_seconds, 2)},
        "fields": per_field,
        "examples": examples,
    }


def main(paths: list[str]) -> None:
    reports = []
    for path in paths:
        print(f"\n=== {Path(path).name}")
        try:
            report = compare(path)
        except Exception as exc:  # a reader that cannot open a file is a result
            print(f"  FAILED: {type(exc).__name__}: {exc}")
            reports.append({"capture": Path(path).name, "error": str(exc)})
            continue
        reports.append(report)
        flows = report["flows"]
        print(f"  flows   tshark={flows['tshark']} dpkt={flows['dpkt']} shared={flows['shared']}"
              f"  (+{len(report['only_dpkt'])} dpkt-only, +{len(report['only_tshark'])} tshark-only)")
        print(f"  time    tshark={report['seconds']['tshark']}s dpkt={report['seconds']['dpkt']}s")
        for tier in TIERS:
            fields = {k: v for k, v in report["fields"].items() if v["tier"] == tier}
            worst = sorted(fields.items(), key=lambda kv: (kv[1]["pct"] is None, kv[1]["pct"]))
            summary = ", ".join(f"{k} {v['pct']}%" for k, v in worst[:4])
            print(f"  {tier:<11} {summary}")

    out = Path(__file__).parent / "phase0_report.json"
    out.write_text(json.dumps(reports, indent=2, default=str))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main(sys.argv[1:])
