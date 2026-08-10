"""Unified ATLAS web shell.

Hosts both engines behind one origin without rewriting either framework:

* ``capture_inspector`` is a FastAPI (ASGI) application, mounted natively.
* ``darthawk`` is a Flask (WSGI) application, mounted through a WSGI-to-ASGI
  adapter.

This is what makes a staged unification possible rather than a rewrite: each
engine keeps its own framework, routes and templates, and neither is touched.

Import-time note: importing ``darthawk`` triggers its ``ensure_runtime_dependencies``
routine, which runs ``pip install`` unless ``DARTHAWK_AUTO_INSTALL=0`` is set.
Application start-up must never reach the network to install packages, so this
module sets the variable before importing it.
"""
from __future__ import annotations

import logging
import os
import subprocess

os.environ.setdefault("DARTHAWK_AUTO_INSTALL", "0")

from a2wsgi import WSGIMiddleware  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402

from capture_inspector.pcap import find_tshark  # noqa: E402
from capture_inspector.server import app as capture_app  # noqa: E402
from darthawk import app as darthawk_wsgi_app  # noqa: E402

log = logging.getLogger("atlas")

app = FastAPI(
    title="Project ATLAS",
    description="Unified Cisco endpoint and network diagnostics.",
    version="0.1.0",
)


def _tshark_status() -> dict:
    """Locate tshark and read its version.

    ATLAS is deployed directly onto the host rather than as an image, so nothing
    pins the Wireshark version for us. Capture Inspector degrades silently when
    tshark is absent - it simply skips packet analysis - which is indistinguishable
    from a capture with nothing in it. Surfacing the version here turns that into
    something an operator can see.
    """
    path = find_tshark()
    if not path:
        return {"available": False, "path": None, "version": None}
    version = None
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=10
        )
        version = (out.stdout or "").splitlines()[0].strip() or None
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return {"available": True, "path": path, "version": version}


@app.on_event("startup")
def _preflight() -> None:
    tshark = _tshark_status()
    if tshark["available"]:
        log.info("tshark: %s (%s)", tshark["version"] or "unknown version", tshark["path"])
    else:
        log.error(
            "tshark NOT FOUND - packet capture analysis is DISABLED. "
            "DART bundle analysis is unaffected. Install Wireshark and restart."
        )


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/bundle/")


@app.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    """Liveness probe plus the external dependency that cannot be assumed."""
    tshark = _tshark_status()
    return {
        "status": "ok",
        "engines": ["capture_inspector", "darthawk"],
        "tshark": tshark,
        "degraded": [] if tshark["available"] else ["capture_inspector: tshark missing"],
    }


app.mount("/capture", capture_app)
app.mount("/bundle", WSGIMiddleware(darthawk_wsgi_app))
