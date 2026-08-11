"""The tshark field set must degrade, not detonate.

tshark rejects the whole run if any single ``-e`` field is unknown to it, so a
field added in a later Wireshark release turns every analysis into a hard
failure on an older build. This happened for real: ``tls.handshake.ja3`` and
``ja3s`` arrived in Wireshark 3.6, and on the 3.4 build in use every capture
came back as "tshark failed: Some fields aren't valid" - no result at all,
rather than a result missing one check.

These tests assert the version-independent invariant (an unknown field is
identified and dropped, and what survives is genuinely accepted) rather than
pinning a Wireshark version, so they stay true as fields come and go.
"""

import pytest

from capture_inspector.pcap import (
    _FIELDS,
    find_tshark,
    supported_fields,
    unsupported_fields,
)

pytestmark = pytest.mark.skipif(find_tshark() is None, reason="tshark not installed")

_INVENTED = "not.a.real.field"


def test_a_field_this_tshark_does_not_know_is_identified():
    exe = find_tshark()
    assert _INVENTED in unsupported_fields(exe, [*_FIELDS, _INVENTED])


def test_an_unknown_field_is_dropped_and_the_rest_are_kept():
    exe = find_tshark()
    usable, dropped = supported_fields(exe, [*_FIELDS, _INVENTED])

    assert _INVENTED in dropped
    assert _INVENTED not in usable
    # Only the unknown field is lost; a probe that gave up and dropped
    # everything would look like it "passed" while analysing nothing.
    assert set(usable) == set(_FIELDS) - dropped


def test_the_surviving_fields_are_actually_accepted_by_this_tshark():
    """The point of the probe: what it returns must run without error."""
    exe = find_tshark()
    usable, _ = supported_fields(exe, [*_FIELDS, _INVENTED])

    assert not unsupported_fields(exe, usable)


def test_a_field_set_this_tshark_fully_supports_reports_nothing_missing():
    exe = find_tshark()
    assert unsupported_fields(exe, ["frame.number", "ip.src"]) == frozenset()
