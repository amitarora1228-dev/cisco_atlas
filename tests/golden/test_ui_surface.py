"""Phase 1 guard: the UI may be restyled and rearranged, but nothing may vanish.

Neither platform has UI tests, so the constraint "preserve all existing
capabilities" is otherwise unverifiable. This compares the current interactive
surface against the baseline recorded before Phase 1 began.

Additions are fine and expected. Removals fail, and the failure names exactly
what went missing.

If an element is removed deliberately, re-record the baseline in the same commit
that removes it:

    python tools/ui_inventory.py --write
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from ui_inventory import BASELINE, collect  # noqa: E402

pytestmark = pytest.mark.golden


@pytest.fixture(scope="module")
def baseline() -> dict:
    if not BASELINE.exists():
        pytest.skip(f"No UI baseline recorded at {BASELINE}")
    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def current() -> dict:
    return collect()


def _missing(baseline: dict, current: dict, module: str, kind: str) -> list[str]:
    return sorted(set(baseline[module][kind]) - set(current.get(module, {}).get(kind, [])))


@pytest.mark.parametrize("module", ["capture", "bundle"])
@pytest.mark.parametrize(
    "kind", ["ids", "control_names", "radio_values", "select_options", "button_labels"]
)
def test_no_ui_element_disappeared(baseline, current, module, kind):
    missing = _missing(baseline, current, module, kind)
    assert not missing, (
        f"{len(missing)} {kind} removed from the {module} UI: {missing}. "
        "Phase 1 may restyle and rearrange, but not remove. If this is "
        "deliberate, re-record with: python tools/ui_inventory.py --write"
    )


def test_every_analysis_module_is_still_offered(baseline, current):
    """The bundle engine's module choices are its whole feature set."""
    before = set(baseline["bundle"]["radio_values"])
    after = set(current["bundle"]["radio_values"])
    assert before <= after, f"Analysis modules no longer offered: {sorted(before - after)}"
