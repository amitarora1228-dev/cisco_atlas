"""Analysis context + result dataclasses, shared by the orchestrator
(`analyze.py`) and the finding modules (`app/findings/`).

Kept in their own module so finding functions can type-hint against them without
importing `analyze.py` (which would create a circular import)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .engine import Finding, FlowReport
from .har import HarResult
from .dns_analysis import DnsRecord


@dataclass
class AnalysisContext:
    domain: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    platform: Optional[str] = None
    policy: Optional[str] = None
    expected: Optional[str] = None
    actual: Optional[str] = None
    timestamp: Optional[str] = None
    # Vendor mode. Off by default => the analysis stays AGNOSTIC (no vendor
    # naming). When the user ticks "I use Cisco Secure Access", the SA-specific
    # intelligence (CA/PKI, ingress/egress IPs, Private Access ZTNA, SWG
    # steering, roaming module) is enabled. sa_tunnel additionally turns on the
    # Secure Access tunnel-MTU alert (expected MTU 1390 / MSS 1350).
    secure_access_mode: bool = False
    sa_tunnel: bool = False


@dataclass
class AnalysisResult:
    context: AnalysisContext
    flow_reports: list[FlowReport] = field(default_factory=list)
    har: Optional[HarResult] = None
    har_findings: list[Finding] = field(default_factory=list)
    dns_records: list[DnsRecord] = field(default_factory=list)
    dns_findings: list[Finding] = field(default_factory=list)
    # Capture-wide findings derived from cross-flow analysis: latency/performance
    # (slow timing phases) and JA3S clustering (one TLS terminator fronting many
    # destinations = SWG decryption evidence).
    signal_findings: list[Finding] = field(default_factory=list)
    correlations: list[str] = field(default_factory=list)
    classifications: list[str] = field(default_factory=list)
    summary_diagnosis: str = "Inconclusive"
    confidence: str = "Low"
    primary_evidence: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    corporate_ca_orgs: Counter = field(default_factory=Counter)
    # PcapNG provenance metadata (sniffer OS, capture app, hardware, interfaces).
    capture_env: dict = field(default_factory=dict)
    # Cisco Secure Client / Umbrella roaming module self-report (STARTMSG): the
    # SWG proxy + org it is bound to and its steered-vs-bypassed web counters,
    # mined in clear from loopback IPC. None when no such datagram is present.
    roaming_report: Optional[dict] = None
    # Inspection coverage measured from the capture itself (per destination for
    # web, per query for DNS) plus the full category breakdown behind those
    # figures. Kept structured so the UI can show it beside the agent's own
    # counters, which is the only place the comparison is meaningful.
    steering_coverage: dict = field(default_factory=dict)
    # Plain-language (non-technical) executive narrative + recommended next step.
    plain_summary: str = ""
    plain_impact: str = ""
    recommended_action: str = ""
    plain_scope: str = ""
    plain_secondary: list[str] = field(default_factory=list)
    # Structured technical breakdown: one entry per problem category, with the
    # reason it was flagged. Drives the colour-coded Technical summary.
    tech_groups: list[dict] = field(default_factory=list)
    # True when the capture was too large to decode in full and was reduced to
    # only handshake/control/DNS frames (see pcap.REDUCE_FILTER). In this mode
    # per-flow data-byte totals exclude bulk payload.
    reduced: bool = False

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for fr in self.flow_reports:
            out.extend(fr.findings)
        out.extend(self.har_findings)
        out.extend(self.dns_findings)
        out.extend(self.signal_findings)
        return out
