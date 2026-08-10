"""Shared contract and correlation layer for Project ATLAS."""
from .correlation import (
    Assertion,
    CorrelatedFinding,
    CorrelationInput,
    Evidence,
    EvidenceSource,
    correlate,
)

__all__ = [
    "Assertion",
    "CorrelatedFinding",
    "CorrelationInput",
    "Evidence",
    "EvidenceSource",
    "correlate",
]

__version__ = "0.1.0"
