"""Gate E - does swapping the reader change any conclusion?

Field parity is necessary and not sufficient. A reader can agree on 97% of
fields and still flip a steering verdict, break an exact join, or drop a hop
from a path - and those are the only things a reader of ATLAS actually sees.

This compares the payloads the UI consumes, produced from each extractor in
turn, and reports every difference by path. Anything that is legitimately
allowed to differ is normalised away first, and what that covers is stated
rather than hidden: stream numbering (assigned, not observed) and sub-second
timing noise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packages" / "atlas_core"))
sys.path.insert(0, str(ROOT / "packages" / "capture_inspector"))
sys.path.insert(0, str(Path(__file__).parent))

from atlas_core import path as path_mod  # noqa: E402
from atlas_core.flows import as_payload, correlate_session, extract_wire_flows  # noqa: E402
from atlas_core.path import Vantage, stitch_path  # noqa: E402
from dpkt_extractor import extract_wire_flows_dpkt  # noqa: E402

# Keys whose value is assigned by the reader rather than observed on the wire,
# or which carry sub-second noise. Differences here are not conclusions.
_IGNORED_KEYS = {"stream", "streams", "first_seen", "last_seen", "seconds", "elapsed"}


def _key_lists(value):
    """Re-key list-of-dicts by their own identity before comparing.

    Neither reader promises an order, so comparing position 0 against position 0
    compares two unrelated connections and reports every field as a difference.
    Anything with a natural identity is keyed by it; what is left is sorted.
    """
    if isinstance(value, dict):
        return {k: _key_lists(v) for k, v in value.items()}
    if isinstance(value, list):
        items = [_key_lists(v) for v in value]
        if items and all(isinstance(i, dict) for i in items):
            for field in ("label", "destination", "host", "key", "name"):
                if all(field in i for i in items):
                    keyed = {}
                    for item in items:
                        name = str(item[field])
                        # A key can legitimately repeat; number the duplicates
                        # rather than dropping them.
                        suffix = 0
                        while f"{name}#{suffix}" in keyed:
                            suffix += 1
                        keyed[f"{name}#{suffix}"] = item
                    return keyed
        try:
            return sorted(items, key=lambda i: json.dumps(i, sort_keys=True, default=str))
        except TypeError:
            return items
    return value


def _normalise(value):
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in sorted(value.items()) if k not in _IGNORED_KEYS}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    if isinstance(value, float):
        return round(value, 3)
    return value


def _prepare(payload):
    return _key_lists(_normalise(payload))


def _diff(left, right, where="") -> list[str]:
    """Every place the two payloads disagree, named by path."""
    out: list[str] = []
    if type(left) is not type(right):
        return [f"{where}: type {type(left).__name__} vs {type(right).__name__}"]
    if isinstance(left, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left:
                out.append(f"{where}.{key}: missing in tshark")
            elif key not in right:
                out.append(f"{where}.{key}: missing in dpkt")
            else:
                out += _diff(left[key], right[key], f"{where}.{key}")
    elif isinstance(left, list):
        if len(left) != len(right):
            out.append(f"{where}: length {len(left)} vs {len(right)}")
        for index, (a, b) in enumerate(zip(left, right)):
            out += _diff(a, b, f"{where}[{index}]")
    elif left != right:
        out.append(f"{where}: {left!r} vs {right!r}")
    return out


def run(captures: list[str]) -> None:
    readers = {
        "tshark": extract_wire_flows,
        "dpkt": extract_wire_flows_dpkt,
    }
    flows_by_reader: dict[str, dict[str, list]] = {}
    for name, reader in readers.items():
        flows_by_reader[name] = {}
        for capture in captures:
            flows_by_reader[name][capture] = reader(capture)
            print(f"  {name:<7} {Path(capture).name[:44]:<46} {len(flows_by_reader[name][capture])} flows")

    # --- Conclusion 1: session correlation (steering verdicts, tunnels) -------
    print("\n--- session correlation")
    for capture in captures:
        payloads = {}
        for name in readers:
            session = correlate_session(flows_by_reader[name][capture], [], [])
            payloads[name] = _prepare(json.loads(json.dumps(as_payload(session), default=str)))
        differences = _diff(payloads["tshark"], payloads["dpkt"], Path(capture).name)
        status = "IDENTICAL" if not differences else f"{len(differences)} differences"
        print(f"  {Path(capture).name[:50]:<52} {status}")
        for line in differences[:6]:
            print(f"      {line[:150]}")

    # --- Conclusion 2: path stitching (the ISN join, hop order, offsets) ------
    print("\n--- path stitching across all vantages")
    payloads = {}
    for name in readers:
        vantages = [
            Vantage(name=Path(c).name, flows=tuple(flows_by_reader[name][c]))
            for c in captures
        ]
        traces = stitch_path(vantages)
        payloads[name] = _prepare(
            json.loads(json.dumps(path_mod.as_payload(traces, vantages), default=str))
        )
        proved = sum(t.proved_hops for t in traces)
        complete = sum(1 for t in traces if t.complete)
        print(f"  {name:<7} traces={len(traces)} complete={complete} proved_hops={proved}")

    differences = _diff(payloads["tshark"], payloads["dpkt"], "path")
    print(f"\n  payload: {'IDENTICAL' if not differences else str(len(differences)) + ' differences'}")
    for line in differences[:20]:
        print(f"      {line[:150]}")

    out = Path(__file__).parent / "gate_e_report.json"
    out.write_text(json.dumps({"differences": differences}, indent=2, default=str))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    run(sys.argv[1:])
