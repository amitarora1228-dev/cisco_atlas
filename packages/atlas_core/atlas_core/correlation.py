"""Shared contract for correlating findings across ATLAS engines.

The two engines observe different halves of the same endpoint:

* ``capture_inspector`` observes **behaviour** — what happened on the wire.
* ``darthawk`` observes **configuration and self-reported state** — what the
  endpoint was set up to do and what its software said about itself.

Neither is sufficient alone. The value of unifying them is detecting where the
two disagree. This module defines the vocabulary that makes that possible; the
detectors themselves arrive in Phase 4 (see ``docs/ARCHITECTURE.md``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EvidenceSource(str, Enum):
    """Where a piece of evidence came from. Never inferred — always recorded."""

    CAPTURE = "capture"
    BUNDLE = "bundle"


class Assertion(str, Enum):
    """What kind of claim a finding makes.

    The distinction is not cosmetic. Presence proves itself and can be reported
    unconditionally. Absence is ambiguous — "no traffic reached the proxy" is a
    fault only if steering was expected — so absence claims require a declared
    expectation before they may be raised.
    """

    PRESENCE = "presence"
    ABSENCE = "absence"
    CONTRADICTION = "contradiction"


@dataclass(frozen=True)
class Evidence:
    """One citable fact, bound to the source that produced it."""

    source: EvidenceSource
    summary: str
    locator: Optional[str] = None
    """Where to look: a file path inside the bundle, or a capture frame/flow key."""


@dataclass
class CorrelatedFinding:
    """A finding that required both engines to produce.

    A correlated finding is only meaningful if it cites both sides, so a reader
    can see which half is measurement and which half is declaration. Construction
    enforces that.
    """

    title: str
    severity: str
    assertion: Assertion
    detail: str
    declared: list[Evidence] = field(default_factory=list)
    observed: list[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.declared or not self.observed:
            raise ValueError(
                "A correlated finding must cite both a declared and an observed "
                "fact; otherwise it belongs to a single engine and should be "
                "raised there instead."
            )


@dataclass
class CorrelationInput:
    """Whatever is available. Either side may be missing."""

    capture_result: Optional[object] = None
    """``capture_inspector.context.AnalysisResult`` when a capture was analysed."""

    bundle_result: Optional[dict] = None
    """DartHawk's extracted bundle facts when a bundle was analysed."""


def correlate(data: CorrelationInput) -> list[CorrelatedFinding]:
    """Produce findings that neither engine could produce alone.

    Degrades to an empty list when only one input is present: with a single
    source there is nothing to contradict, and a weaker guess is not an
    acceptable substitute.

    Detectors are added in Phase 4. The first target is the VPNaaS double
    interception case, for which validated good and bad reference captures
    already exist — see ``packages/capture_inspector/docs/HANDOFF.md`` section 8b.
    """
    if data.capture_result is None or data.bundle_result is None:
        return []
    return []
