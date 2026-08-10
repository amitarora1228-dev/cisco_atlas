"""Active certificate resolution by SNI — no extra dependencies.

In TLS 1.3 the server certificate is encrypted and invisible to a passive
capture, but the SNI (hostname) the client requested IS visible in the
ClientHello. This module takes that hostname and opens its own short-lived TLS
connection to the real server to fetch the live certificate, revealing the real
Subject CN / SAN / issuer / validity.

Uses only the Python standard library (``ssl`` + ``socket``); parsing reuses the
already-present ``cryptography`` library via certs.parse_cert_hex.

Caveats surfaced to the caller:
  * This is an ACTIVE probe (outbound connection), opt-in only.
  * It returns the certificate the server presents NOW, which may differ from
    the one at capture time, and is the public certificate — not any SWG-
    re-signed copy seen on the wire.
"""
from __future__ import annotations

import socket
import ssl
from functools import lru_cache
from typing import Optional

from .certs import CertInfo, parse_cert_hex


def _clean_host(sni: Optional[str]) -> Optional[str]:
    if not sni:
        return None
    host = sni.strip().rstrip(".").lower()
    # Drop any ":port" and obvious non-hostnames.
    host = host.split(":", 1)[0]
    if not host or " " in host or "/" in host:
        return None
    return host


@lru_cache(maxsize=512)
def fetch_certificate(sni: str, port: int = 443, timeout: float = 4.0) -> Optional[CertInfo]:
    """Open a TLS connection to ``sni`` and parse the presented leaf certificate.

    Returns a CertInfo (with an explicit ``parse_error`` set on failure) or None
    when the hostname is unusable. Cached so repeated SNIs cost one probe.
    """
    host = _clean_host(sni)
    if not host:
        return None

    # We want the certificate regardless of trust/validity, so disable
    # verification — we are inspecting, not establishing a secure session.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
    except (socket.gaierror, socket.timeout, OSError, ssl.SSLError) as exc:
        info = CertInfo()
        info.parse_error = f"probe failed: {exc.__class__.__name__}: {exc}"
        return info

    if not der:
        info = CertInfo()
        info.parse_error = "no certificate returned"
        return info

    info = parse_cert_hex(der.hex())
    return info
