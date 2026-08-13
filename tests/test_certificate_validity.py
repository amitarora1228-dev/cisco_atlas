"""A certificate is judged once, in one place, against the traffic's own clock.

The rule this pins down was violated twice: the findings engine and the
connection story each decided expiry for themselves, both by comparing against
the time of analysis. Every capture eventually ages past the certificates in it,
so that turns healthy old captures into HIGH-severity certificate incidents.
"""
from __future__ import annotations

from datetime import UTC, datetime

from capture_inspector.certs import CertInfo, evaluate_at

MARCH_6 = datetime(2026, 3, 6, 11, 0, tzinfo=UTC).timestamp()


def _cert(not_before: str, not_after: str) -> CertInfo:
    return CertInfo(subject_cn="client.wns.windows.com",
                    not_before=not_before, not_after=not_after)


def test_a_certificate_still_running_when_captured_is_valid():
    """The real case: captured 6 March, certificate ran to 9 March. Analysed in
    August it looks expired, but nothing was wrong when the packets were sent."""
    window = evaluate_at(
        _cert("2025-03-09T10:37:36+00:00", "2026-03-09T10:37:36+00:00"), MARCH_6)

    assert window.status == "valid"
    assert window.is_problem is False


def test_a_certificate_that_had_already_lapsed_is_expired():
    window = evaluate_at(
        _cert("2025-01-01T00:00:00+00:00", "2026-03-01T00:00:00+00:00"), MARCH_6)

    assert window.status == "expired"
    assert window.days_outside == 5
    assert window.lifetime_days == 424


def test_a_certificate_issued_after_the_capture_is_not_yet_valid():
    window = evaluate_at(
        _cert("2026-03-20T00:00:00+00:00", "2027-03-20T00:00:00+00:00"), MARCH_6)

    assert window.status == "not_yet_valid"
    assert window.days_outside == 13


def test_without_a_moment_to_judge_against_nothing_is_claimed():
    """No timestamp means no verdict - never a silent fallback to 'now'."""
    window = evaluate_at(
        _cert("2025-01-01T00:00:00+00:00", "2026-03-01T00:00:00+00:00"), None)

    assert window.status == "unknown"
    assert window.is_problem is False


def test_an_unparsable_validity_window_is_unknown_not_expired():
    window = evaluate_at(CertInfo(not_before=None, not_after=None), MARCH_6)

    assert window.status == "unknown"
    assert window.is_problem is False


def test_cert_info_no_longer_carries_an_analysis_time_verdict():
    """The fields that invited the bug are gone, so it cannot come back by
    someone reading `cert.expired` and believing it means 'expired then'."""
    cert = CertInfo()

    assert not hasattr(cert, "expired")
    assert not hasattr(cert, "not_yet_valid")
