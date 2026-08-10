"""Facts that both ATLAS engines can express, extracted into one vocabulary.

This is the seam that makes correlation possible. It deliberately does **not**
refactor either engine:

* DartHawk's extractors are already pure functions of an unpacked bundle
  directory, so they are called directly.
* Capture Inspector already returns a structured ``AnalysisResult``, so facts are
  read off it.

Only facts that *both* sides can produce belong here. Everything else stays in
the engine that owns it - a fact that only one side can observe is not a
correlation key, it is a finding, and it belongs where it was detected.
"""
from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass, field
from typing import Any

# DartHawk installs dependencies at import time unless this is set. Nothing in
# ATLAS may reach the network during import.
os.environ.setdefault("DARTHAWK_AUTO_INSTALL", "0")


@dataclass(frozen=True)
class BundleFacts:
    """What the endpoint was configured to do, from a DART bundle."""

    source_name: str
    org_ids: tuple[str, ...] = ()
    secure_client_version: str | None = None
    operating_system: str | None = None
    timezone_name: str | None = None

    @property
    def is_empty(self) -> bool:
        return not (
            self.org_ids
            or self.secure_client_version
            or self.operating_system
            or self.timezone_name
        )


@dataclass(frozen=True)
class CaptureFacts:
    """What the endpoint actually did, from a packet capture."""

    source_name: str
    org_ids: tuple[str, ...] = ()
    swg_proxy_host: str | None = None
    ingress_regions: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.org_ids or self.swg_proxy_host or self.ingress_regions)


@dataclass
class AtlasFacts:
    """Whatever was supplied. Either side may be absent."""

    bundle: BundleFacts | None = None
    capture: CaptureFacts | None = None
    notes: list[str] = field(default_factory=list)


def _safe_extract(zip_path: str, dest: str) -> None:
    """Unpack a ZIP, refusing members that escape the destination.

    DART bundles are uploaded by users. A member named ``../../etc/passwd`` or
    holding an absolute path would otherwise be written outside ``dest``
    (path traversal, CWE-22).
    """
    dest_real = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            target = os.path.realpath(os.path.join(dest_real, member.filename))
            if target != dest_real and not target.startswith(dest_real + os.sep):
                raise ValueError(
                    f"Refusing to extract {member.filename!r}: it resolves outside "
                    "the extraction directory."
                )
        archive.extractall(dest_real)


def _clean(value: Any) -> str | None:
    """Normalise DartHawk's sentinels to None.

    Its extractors report 'Unknown' or '' when an artefact is absent. Carrying
    those through would make ``is_empty`` false for a bundle that yielded
    nothing, and would put the literal word "Unknown" in a finding.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"unknown", "n/a", "none"}:
        return None
    return text


def extract_bundle_facts(bundle_path: str, work_dir: str) -> BundleFacts:
    """Read correlation facts from a DART bundle.

    ``work_dir`` must already exist and is where the archive is unpacked; the
    caller owns its lifetime so results can be inspected after the fact.
    """
    import darthawk

    name = os.path.basename(bundle_path)
    _safe_extract(bundle_path, work_dir)

    # Each extractor is independent, and a bundle missing one artefact is normal
    # rather than an error - so a failure in one must not lose the others.
    def _try(fn_name: str, default: Any = None) -> Any:
        fn = getattr(darthawk, fn_name, None)
        if fn is None:
            return default
        try:
            return fn(work_dir)
        except Exception:  # noqa: BLE001 - a malformed bundle must not abort the rest
            return default

    # extract_org_ids_from_enrollments returns a dict of several categories
    # (org_ids, user_ids, enrollment_urls, ...); only one of them is the org.
    enrollments = _try("extract_org_ids_from_enrollments", {}) or {}
    raw_orgs = enrollments.get("org_ids", []) if isinstance(enrollments, dict) else enrollments

    return BundleFacts(
        source_name=name,
        org_ids=tuple(sorted({c for c in (_clean(o) for o in raw_orgs) if c})),
        secure_client_version=_clean(_try("extract_cisco_secure_client_version_from_bundle")),
        operating_system=_clean(_try("extract_operating_system_from_bundle")),
        timezone_name=_clean(_try("extract_bundle_timezone_name")),
    )


def extract_capture_facts(
    capture_name: str,
    roaming_report: dict | None = None,
    analysis_result: Any | None = None,
) -> CaptureFacts:
    """Read correlation facts from a capture analysis.

    The organisation ID is not sent in the clear anywhere in the traffic; it is
    recoverable only because the roaming agent's ``STARTMSG`` names the SWG proxy
    it is bound to, and the org is encoded in that hostname.
    """
    from capture_inspector.dns_analysis import is_swg_proxy_host, swg_proxy_org
    from capture_inspector.secure_access import lookup_ingress_region

    orgs: set[str] = set()
    proxy_host: str | None = None

    if roaming_report:
        proxy_host = roaming_report.get("umbrella_proxy")
        org = swg_proxy_org(proxy_host)
        if org:
            orgs.add(str(org).strip())

    regions: set[str] = set()
    if analysis_result is not None:
        for record in getattr(analysis_result, "dns_records", []) or []:
            rec_name = getattr(record, "name", None)
            if is_swg_proxy_host(rec_name):
                proxy_host = proxy_host or rec_name
                org = swg_proxy_org(rec_name)
                if org:
                    orgs.add(str(org).strip())
            for ip in getattr(record, "addresses", []) or []:
                region = lookup_ingress_region(ip)
                if region:
                    regions.add(region)

        for report in getattr(analysis_result, "flow_reports", []) or []:
            flow = getattr(report, "flow", None)
            for ip in (getattr(flow, "proxy_ip", None), getattr(flow, "dst_ip", None)):
                region = lookup_ingress_region(ip)
                if region:
                    regions.add(region)

    return CaptureFacts(
        source_name=capture_name,
        org_ids=tuple(sorted(orgs)),
        swg_proxy_host=proxy_host,
        ingress_regions=tuple(sorted(regions)),
    )
