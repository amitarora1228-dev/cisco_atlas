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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .facts import BundleFacts, CaptureFacts


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
    locator: str | None = None
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

    bundle: BundleFacts | None = None
    capture: CaptureFacts | None = None


def _identity_join(bundle: BundleFacts, capture: CaptureFacts) -> list[CorrelatedFinding]:
    """Check that both inputs describe the same endpoint.

    This runs before every other correlation, and nothing else is valid without
    it. Correlating a bundle from one machine against a capture from another
    produces confident nonsense: the configuration would be read from one
    endpoint and the behaviour from a different one.

    The organisation ID is the join key. Capture Inspector recovers it from the
    roaming agent's STARTMSG, which names the bound SWG proxy with the org
    encoded in the hostname; DartHawk reads it from the bundle's enrollment
    records. Neither side infers it.
    """
    if not bundle.org_ids or not capture.org_ids:
        # Silence is correct here. A missing org ID means the question cannot be
        # answered, which is not the same as the two disagreeing.
        return []

    shared = set(bundle.org_ids) & set(capture.org_ids)
    declared = [
        Evidence(
            source=EvidenceSource.BUNDLE,
            summary=f"Enrollment records name organisation {', '.join(bundle.org_ids)}",
            locator=bundle.source_name,
        )
    ]
    observed = [
        Evidence(
            source=EvidenceSource.CAPTURE,
            summary=(
                f"Roaming agent is bound to {capture.swg_proxy_host}"
                if capture.swg_proxy_host
                else f"Traffic indicates organisation {', '.join(capture.org_ids)}"
            ),
            locator=capture.source_name,
        )
    ]

    if shared:
        return [
            CorrelatedFinding(
                title=f"Bundle and capture describe the same endpoint (organisation {', '.join(sorted(shared))})",
                severity="info",
                assertion=Assertion.PRESENCE,
                detail=(
                    "The organisation identified in the DART bundle matches the one "
                    "the captured traffic was steered to, so configuration and "
                    "behaviour can be compared directly."
                ),
                declared=declared,
                observed=observed,
            )
        ]

    return [
        CorrelatedFinding(
            title="Bundle and capture are from different organisations - they cannot be compared",
            severity="high",
            assertion=Assertion.CONTRADICTION,
            detail=(
                f"The bundle reports organisation {', '.join(bundle.org_ids)} while the "
                f"capture shows traffic for {', '.join(capture.org_ids)}. Any comparison "
                "of configuration against behaviour would be reading the two from "
                "different endpoints, so no further correlation is attempted."
            ),
            declared=declared,
            observed=observed,
        )
    ]


def correlate(data: CorrelationInput) -> list[CorrelatedFinding]:
    """Produce findings that neither engine could produce alone.

    Degrades to an empty list when only one input is present: with a single
    source there is nothing to contradict, and a weaker guess is not an
    acceptable substitute.

    The identity join runs first and gates everything after it. Later detectors
    are added in Phase 4; the first target is the VPNaaS double interception
    case, for which validated good and bad reference captures already exist -
    see ``packages/capture_inspector/docs/HANDOFF.md`` section 8b.
    """
    if data.bundle is None or data.capture is None:
        return []

    findings = _identity_join(data.bundle, data.capture)
    if any(f.assertion is Assertion.CONTRADICTION for f in findings):
        return findings
    return findings
