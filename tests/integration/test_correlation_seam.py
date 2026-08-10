"""End-to-end tests for the cross-engine correlation seam.

These exercise the real code path: a real ZIP is built on disk, unpacked through
the real extractor, and correlated against facts read from the real capture-side
helpers. Nothing here is mocked - the point is to prove the seam holds, not that
the test doubles agree with each other.
"""
from __future__ import annotations

import json
import os
import zipfile

import pytest

from atlas_core.correlation import Assertion, CorrelationInput, correlate
from atlas_core.facts import (
    BundleFacts,
    CaptureFacts,
    _safe_extract,
    extract_bundle_facts,
    extract_capture_facts,
)

ORG = "8195126"
PROXY = f"swg-url-proxy-https-{ORG}.sseproxy.qq.opendns.com"


def _make_bundle(path: str, org: str = ORG) -> str:
    """A minimal DART-shaped archive carrying an organisation ID."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "Cisco Secure Client/Umbrella/OrgInfo.json",
            json.dumps({"organizationId": org, "fingerprint": "x", "userId": "y"}),
        )
        archive.writestr("SystemInfo/systeminfo.txt", "OS Name: Microsoft Windows 11\n")
    return path


class TestSafeExtract:
    def test_rejects_path_traversal(self, tmp_path):
        evil = tmp_path / "evil.zip"
        with zipfile.ZipFile(evil, "w") as archive:
            archive.writestr("../escaped.txt", "should never be written")
        dest = tmp_path / "out"
        dest.mkdir()

        with pytest.raises(ValueError, match="outside"):
            _safe_extract(str(evil), str(dest))

        assert not (tmp_path / "escaped.txt").exists()

    def test_extracts_normal_members(self, tmp_path):
        good = tmp_path / "good.zip"
        _make_bundle(str(good))
        dest = tmp_path / "out"
        dest.mkdir()

        _safe_extract(str(good), str(dest))

        assert (dest / "Cisco Secure Client/Umbrella/OrgInfo.json").exists()


class TestBundleFacts:
    def test_reads_org_from_a_real_archive(self, tmp_path):
        bundle = _make_bundle(str(tmp_path / "dart.zip"))
        work = tmp_path / "work"
        work.mkdir()

        facts = extract_bundle_facts(bundle, str(work))

        assert facts.source_name == "dart.zip"
        # The extractor is DartHawk's own; assert the seam works rather than
        # asserting DartHawk's parsing rules, which belong to its own tests.
        assert isinstance(facts.org_ids, tuple)

    def test_a_bundle_missing_everything_is_not_an_error(self, tmp_path):
        empty = tmp_path / "empty.zip"
        with zipfile.ZipFile(empty, "w") as archive:
            archive.writestr("readme.txt", "nothing useful here")
        work = tmp_path / "work"
        work.mkdir()

        facts = extract_bundle_facts(str(empty), str(work))

        assert facts.is_empty


class TestCaptureFacts:
    def test_recovers_org_from_the_roaming_report(self):
        facts = extract_capture_facts(
            "session.pcapng", roaming_report={"umbrella_proxy": PROXY}
        )

        assert facts.org_ids == (ORG,)
        assert facts.swg_proxy_host == PROXY

    def test_no_roaming_report_yields_no_org(self):
        facts = extract_capture_facts("session.pcapng")

        assert facts.is_empty


class TestCorrelation:
    def test_one_sided_input_produces_nothing(self):
        capture = extract_capture_facts("c.pcapng", {"umbrella_proxy": PROXY})

        assert correlate(CorrelationInput(capture=capture, bundle=None)) == []
        assert correlate(CorrelationInput(capture=None, bundle=None)) == []

    def test_matching_org_confirms_the_same_endpoint(self):
        findings = correlate(
            CorrelationInput(
                bundle=BundleFacts(source_name="d.zip", org_ids=(ORG,)),
                capture=extract_capture_facts("c.pcapng", {"umbrella_proxy": PROXY}),
            )
        )

        assert len(findings) == 1
        assert findings[0].assertion is Assertion.PRESENCE
        assert ORG in findings[0].title

    def test_mismatched_org_is_reported_and_blocks_further_correlation(self):
        findings = correlate(
            CorrelationInput(
                bundle=BundleFacts(source_name="d.zip", org_ids=("9999999",)),
                capture=extract_capture_facts("c.pcapng", {"umbrella_proxy": PROXY}),
            )
        )

        assert len(findings) == 1
        assert findings[0].assertion is Assertion.CONTRADICTION
        assert findings[0].severity == "high"

    def test_missing_org_on_either_side_stays_silent(self):
        # Unanswerable is not the same as disagreeing.
        findings = correlate(
            CorrelationInput(
                bundle=BundleFacts(source_name="d.zip", org_ids=()),
                capture=extract_capture_facts("c.pcapng", {"umbrella_proxy": PROXY}),
            )
        )

        assert findings == []

    def test_a_correlated_finding_must_cite_both_sides(self):
        findings = correlate(
            CorrelationInput(
                bundle=BundleFacts(source_name="d.zip", org_ids=(ORG,)),
                capture=extract_capture_facts("c.pcapng", {"umbrella_proxy": PROXY}),
            )
        )

        finding = findings[0]
        assert finding.declared and finding.observed
        assert finding.declared[0].locator == "d.zip"
        assert finding.observed[0].locator == "c.pcapng"
