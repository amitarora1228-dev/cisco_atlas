"""Record the interactive surface of both UIs so Phase 1 cannot silently drop any.

Neither platform has UI tests, and the Phase 1 constraint is that no capability
disappears. Screenshots cannot be asserted on in CI; this can. It extracts every
control a user can reach - inputs, buttons, selects, and the values of radio
groups that choose an analysis module or check - and writes them to a baseline
that a test compares against.

It deliberately records *identity* (element id, control name, option value),
not layout. Phase 1 is expected to move and restyle things; it is not expected
to remove them.

    python tools/ui_inventory.py --write     # record a new baseline
    python tools/ui_inventory.py             # print the current surface
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "tests" / "golden" / "ui_baseline.json"

SOURCES = {
    "capture": ROOT / "packages/capture_inspector/capture_inspector/static/index.html",
    "bundle": ROOT / "packages/darthawk/templates/index.html",
}

_ID = re.compile(r'\bid="([A-Za-z0-9_:-]+)"')
_NAME = re.compile(r'\bname="([A-Za-z0-9_:-]+)"')
_VALUE = re.compile(r'<input[^>]*\btype="radio"[^>]*\bvalue="([^"]+)"')
_OPTION = re.compile(r"<option[^>]*\bvalue=\"([^\"]*)\"[^>]*>([^<]*)</option>")
_BUTTON_TEXT = re.compile(r"<button[^>]*>\s*([^<{]{2,60}?)\s*<", re.DOTALL)


def _surface(html: str) -> dict:
    """The set of things a user can interact with, order-independent."""
    options = {
        (value.strip() or label.strip())
        for value, label in _OPTION.findall(html)
        if (value.strip() or label.strip())
    }
    return {
        "ids": sorted(set(_ID.findall(html))),
        "control_names": sorted(set(_NAME.findall(html))),
        "radio_values": sorted(set(_VALUE.findall(html))),
        "select_options": sorted(options),
        "button_labels": sorted(
            {t.strip() for t in _BUTTON_TEXT.findall(html) if t.strip()}
        ),
    }


def collect() -> dict:
    surface = {}
    for name, path in SOURCES.items():
        if not path.exists():
            raise SystemExit(f"Missing UI source: {path}")
        surface[name] = _surface(path.read_text(encoding="utf-8"))
    return surface


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="record a new baseline")
    args = parser.parse_args()

    current = collect()
    if args.write:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        total = sum(len(v) for s in current.values() for v in s.values())
        print(f"Recorded {total} UI elements to {BASELINE.relative_to(ROOT)}")
        for name, s in current.items():
            print(f"  {name}: " + ", ".join(f"{k}={len(v)}" for k, v in s.items()))
    else:
        print(json.dumps(current, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
