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


@app.post("/atlas/api/correlate", include_in_schema=False)
async def correlate_session_upload(
    bundle: UploadFile | None = File(None),
    capture: UploadFile | None = File(None),
    har: UploadFile | None = File(None),
) -> JSONResponse:
    """Join a DART bundle, a packet capture and a HAR into one account of a session.

    Every artefact is optional, because a correlation that refuses to run
    without all three would be useless in the common case where only two were
    collected. What cannot be answered from what was supplied is reported in
    ``notes`` rather than left as a gap the reader might mistake for health.

    Uploads are written to a temporary directory that is deleted when the
    request finishes. Nothing is retained: a capture and a bundle together
    identify an endpoint and, with a key log, would decrypt the session they
    recorded.
    """
    import shutil
    import tempfile

    from atlas_core.flows import (
        as_payload,
        correlate_session,
        extract_agent_flows,
        extract_app_flows,
        extract_web_requests,
        extract_wire_flows,
        find_zta_log,
        unpack_bundle,
    )

    if not any((bundle, capture, har)):
        return JSONResponse(
            {"error": "Supply at least one of a DART bundle, a packet capture or a HAR."},
            status_code=400,
        )

    work = tempfile.mkdtemp(prefix="atlas-correlate-")
    try:
        sources: dict[str, str] = {}
        notes: list[str] = []

        async def _spill(upload: UploadFile | None, fallback: str) -> str | None:
            if upload is None:
                return None
            name = os.path.basename(upload.filename or fallback)
            path = os.path.join(work, name)
            with open(path, "wb") as handle:
                shutil.copyfileobj(upload.file, handle)
            return path

        wire_flows = []
        capture_path = await _spill(capture, "capture.pcapng")
        if capture_path:
            sources["capture"] = os.path.basename(capture_path)
            try:
                wire_flows = extract_wire_flows(capture_path)
            except Exception as exc:  # noqa: BLE001 - one unreadable input must not lose the rest
                notes.append(f"The capture could not be read: {exc}")

        agent_flows = []
        app_flows = []
        bundle_path = await _spill(bundle, "bundle.zip")
        if bundle_path:
            sources["bundle"] = os.path.basename(bundle_path)
            try:
                unpacked = unpack_bundle(bundle_path, os.path.join(work, "bundle"))
                zta_log = find_zta_log(unpacked)
                if zta_log:
                    agent_flows = extract_agent_flows(zta_log)
                    app_flows = extract_app_flows(zta_log)
                else:
                    notes.append(
                        "The bundle holds no Zero Trust Access log, so the agent's own account "
                        "of these connections is not available."
                    )
            except Exception as exc:  # noqa: BLE001
                notes.append(f"The bundle could not be read: {exc}")

        web_requests = []
        har_path = await _spill(har, "session.har")
        if har_path:
            sources["har"] = os.path.basename(har_path)
            try:
                web_requests = extract_web_requests(har_path)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"The HAR could not be read: {exc}")

        result = correlate_session(wire_flows, agent_flows, web_requests, app_flows)
        result.sources = sources
        result.notes = notes + result.notes
        return JSONResponse(as_payload(result))
    finally:
        shutil.rmtree(work, ignore_errors=True)


@app.post("/atlas/api/path", include_in_schema=False)
async def stitch_path_upload(files: list[UploadFile] = File(...)) -> JSONResponse:
    """Follow one transaction across captures taken at several points of the path.

    Each file is a vantage point. The order of the hops is not asked for and
    not taken from the filenames: it is inferred from the addresses the
    captures share, because a proxy appears in both the capture before it and
    the capture after it. A path built from filenames would be a path the
    operator drew, not one the packets did.

    Uploads are written to a temporary directory and deleted when the request
    finishes. Captures from several points of a path identify more of an estate
    than any single one of them does, so none is retained.
    """
    import shutil
    import tempfile

    from atlas_core.flows import extract_wire_flows
    from atlas_core.path import Vantage, as_payload, stitch_path

    if not files:
        return JSONResponse({"error": "Supply at least one capture."}, status_code=400)

    work = tempfile.mkdtemp(prefix="atlas-path-")
    try:
        vantages: list[Vantage] = []
        notes: list[str] = []
        for upload in files:
            name = os.path.basename(upload.filename or "capture.pcapng")
            target = os.path.join(work, name)
            with open(target, "wb") as handle:
                shutil.copyfileobj(upload.file, handle)
            try:
                vantages.append(Vantage(name=name, flows=tuple(extract_wire_flows(target))))
            except Exception as exc:  # noqa: BLE001 - one bad file must not lose the others
                notes.append(f"{name} could not be read: {exc}")

        if len(vantages) < 2:
            notes.append(
                "A path needs captures from more than one point to be stitched. With a single "
                "capture only that one vantage point is reported."
            )

        payload = as_payload(stitch_path(vantages), vantages)
        payload["notes"] = notes
        return JSONResponse(payload)
    finally:
        shutil.rmtree(work, ignore_errors=True)


app.mount("/capture", capture_app)
app.mount("/bundle", WSGIMiddleware(darthawk_wsgi_app))

# Shared design tokens, served at the origin root so both engines can link the
# same file regardless of the prefix they are mounted under.
app.mount(
    "/atlas",
    StaticFiles(directory=str(Path(__file__).parent / "shell" / "static")),
    name="atlas-shell",
)
