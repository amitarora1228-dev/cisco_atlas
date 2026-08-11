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

import io
import logging
import os
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

os.environ.setdefault("DARTHAWK_AUTO_INSTALL", "0")

from a2wsgi import WSGIMiddleware  # noqa: E402
from capture_inspector.pcap import find_tshark  # noqa: E402
from capture_inspector.server import app as capture_app  # noqa: E402
from darthawk import app as darthawk_wsgi_app  # noqa: E402
from fastapi import FastAPI, File, UploadFile  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from web.shell.workspace import compose  # noqa: E402

log = logging.getLogger("atlas")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Report the external dependency once, at start-up, where an operator sees it."""
    tshark = _tshark_status()
    if tshark["available"]:
        log.info("tshark: %s (%s)", tshark["version"] or "unknown version", tshark["path"])
    else:
        log.error(
            "tshark NOT FOUND - packet capture analysis is DISABLED. "
            "DART bundle analysis is unaffected. Install Wireshark and restart."
        )
    yield


app = FastAPI(
    title="Project ATLAS",
    description="Unified Cisco endpoint and network diagnostics.",
    version="0.1.0",
    lifespan=lifespan,
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
        # path comes from find_tshark(): shutil.which or a hardcoded install
        # location, never user input. Fixed argument list, no shell.
        out = subprocess.run(  # noqa: S603
            [path, "--version"], capture_output=True, text=True, timeout=10
        )
        version = (out.stdout or "").splitlines()[0].strip() or None
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return {"available": True, "path": path, "version": version}


@app.get("/", include_in_schema=False)
def root() -> HTMLResponse:
    """The unified workspace: both engines, one page, one evidence panel."""
    return HTMLResponse(compose())


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


# Everything the bundle engine can actually answer quickly, without a
# user-supplied target value.
#
# Excluded and why:
#
# * VPN, Umbrella, UZTNA, EDLP - accepted by the engine but not implemented. They
#   return only a payload-received line and the route still carries a placeholder
#   where the parsing would go.
# * Check SIA Flow, Check TCP or UDP Flow, SRV Check - each needs a destination or
#   identifier from the user.
#
# All of them remain available by selecting the module manually.
#
# Each check is tagged with the *kind of question it asks*, because output means
# opposite things depending on that. An error check that produced text is
# reporting failures; a state check that produced text is reporting the
# configuration it found, which is normal. Presenting both as "findings" made a
# fault and a settings dump look identical.
#
# The tag describes the check, not the bundle, so it asserts nothing about the
# data - it is fixed at the same place the check is declared.
#
# The tags below were checked against engine output rather than guessed from the
# check names, and two names proved misleading:
#
# * "Check Configuration Sync" sounds like an error check but returns a
#   statistics report (request/response counts, "Failures since last successful
#   sync: 0"). It produces output on a healthy client.
# * "Check Server Connectivity Errors" always prints a status preamble
#   ("Proxy Connectivity: Ok", flow counts) before any error lines, so it too
#   produces output on a healthy client.
#
# Both are therefore _MIXED: the presence of output proves nothing, and only
# reading the text distinguishes a fault from a normal report. Counting them as
# problems would have made ATLAS claim failures the engine never reported.
_ERRORS = "errors"
_MIXED = "mixed"
_STATE = "state"
_LOGS = "logs"

_BUNDLE_MATRIX: list[tuple[str, str, dict]] = [
    (f"ZTA - {check.removeprefix('Check ')}", kind,
     {"module": "ZTA", "zta_access_mode": "SPA", "spa_check_option": check})
    for check, kind in (
        ("Check Enrollment Errors", _ERRORS),
        ("Check Configuration Sync", _MIXED),
        ("Check Server Connectivity Errors", _MIXED),
        ("Check Trusted Network Detection", _STATE),
        ("Check User Pause Config", _STATE),
        ("Check Inclusions or Exclusions", _STATE),
        ("Check Event Viewer Logs", _LOGS),
    )
] + [("Duo Desktop", _STATE, {"module": "Duo Desktop"})]


# Surfaced to the user so an excluded check is a visible choice, not a silent gap.
_BUNDLE_EXCLUDED: list[dict] = []


@app.post("/atlas/api/bundle/analyze-all", include_in_schema=False)
async def analyze_entire_bundle(file: UploadFile = File(...)) -> JSONResponse:
    """Run every applicable bundle check from a single upload.

    The bundle engine answers one module - and for ZTA one check - per request.
    Driving that matrix from the browser would re-upload the archive once per
    check: twelve checks against a 350 MB bundle is over 4 GB across the wire.
    Uploading once and dispatching in-process avoids that entirely.

    Each check is dispatched through the engine's own test client so its route,
    validation and response building run exactly as they do for a normal
    request; nothing is reimplemented here.
    """
    import darthawk

    payload = await file.read()
    name = file.filename or "bundle.zip"
    results = []

    for label, kind, fields in _BUNDLE_MATRIX:
        data = dict(fields)
        data["file"] = (io.BytesIO(payload), name)
        try:
            with darthawk.app.test_client() as client:
                response = client.post(
                    "/analyze", data=data, content_type="multipart/form-data"
                )
                body = response.get_json(silent=True) or {}
                results.append({
                    "label": label,
                    "kind": kind,
                    "ok": response.status_code == 200,
                    "text": (body.get("details") or "").strip(),
                    "error": body.get("error"),
                })
        except Exception as exc:  # noqa: BLE001 - one failing check must not lose the rest
            results.append(
                {"label": label, "kind": kind, "ok": False, "text": "", "error": str(exc)}
            )

    return JSONResponse({"results": results, "excluded": _BUNDLE_EXCLUDED})


app.mount("/capture", capture_app)
app.mount("/bundle", WSGIMiddleware(darthawk_wsgi_app))

# Shared design tokens, served at the origin root so both engines can link the
# same file regardless of the prefix they are mounted under.
app.mount(
    "/atlas",
    StaticFiles(directory=str(Path(__file__).parent / "shell" / "static")),
    name="atlas-shell",
)
