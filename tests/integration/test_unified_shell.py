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
    """The Flask engine renders its own Jinja template through the WSGI bridge."""
    response = client.get("/bundle/")
    assert response.status_code == 200
    assert "DartHawk" in response.text


def test_darthawk_static_assets_survive_the_bridge(client):
    """Flask's static route is prefix-sensitive; regressions here are silent."""
    response = client.get("/bundle/static/css/app.css")
    assert response.status_code == 200


def test_root_redirects_into_an_engine(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert "/bundle/" in response.headers["location"]
