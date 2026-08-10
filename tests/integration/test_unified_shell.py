"""The unification claim, as an executable check.

Two web frameworks with different concurrency models (FastAPI/ASGI and
Flask/WSGI) serve from one origin in one process, with neither engine rewritten.
That is the premise the staged unification rests on, so it is guarded here rather
than left as an assertion in a document.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_shell_reports_both_engines(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body["engines"]) == {"capture_inspector", "darthawk"}


def test_capture_inspector_is_mounted(client):
    """The FastAPI engine answers on its own prefix."""
    response = client.get("/capture/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_darthawk_is_mounted_through_wsgi(client):
    """The Flask engine renders its own Jinja template through the WSGI bridge.

    Asserted on markup the engine owns rather than on its product name, which is
    now ATLAS everywhere the user can see it.
    """
    response = client.get("/bundle/")
    assert response.status_code == 200
    assert 'id="dartFile"' in response.text
    assert 'id="moduleSelectionWrap"' in response.text


def test_darthawk_static_assets_survive_the_bridge(client):
    """Flask's static route is prefix-sensitive; regressions here are silent."""
    response = client.get("/bundle/static/css/app.css")
    assert response.status_code == 200


def test_root_serves_the_unified_workspace(client):
    """The root is one page holding both engines, not a redirect into one.

    A single investigation normally spans a DART bundle, a packet capture and
    sometimes a HAR, so the landing page has to carry all of them at once.
    """
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 200
    body = response.text

    # Both engines' markup is present in the same document.
    assert 'id="atlas-engine-capture"' in body
    assert 'id="atlas-engine-bundle"' in body
    # ...including each one's own file input, which is how evidence is handed off.
    assert 'id="dartFile"' in body
    assert "uploadForm" in body


def test_workspace_prefixes_engine_assets(client):
    """Rendered outside its mount, Flask emits root-relative asset URLs.

    Unprefixed, every DartHawk asset would 404 on the composed page and the
    engine would be inert while still looking present.
    """
    body = client.get("/").text
    assert "/bundle/static/js/app.js" in body
    assert "/capture/static/app.js" in body
    assert 'src="/static/js/app.js"' not in body


def test_workspace_sets_the_capture_api_prefix(client):
    """The capture frontend calls its API relative to window.API_BASE.

    Without it the calls fall back to the ATLAS root and the engine reports
    itself as broken rather than merely unmounted.
    """
    assert 'window.API_BASE = "/capture"' in client.get("/").text
