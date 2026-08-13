"""HAR (HTTP Archive) parser and browser-level error analysis.

HAR files contain request/response metadata, timings and browser error strings,
but NO TLS handshake bytes. We extract what HAR can actually prove (cert/SSL
browser errors, blocked requests, status codes, server IPs, timings) and leave
deep TLS/cert analysis to the PCAP engine.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs


# Secure Access serves its block page on these hosts. When the browser is
# blocked it gets a 3xx/4xx whose Location points here, with the block reason
# encoded in the URL path (/dlp/, /category/...) and a `blockinfo` JWT.
# Security blocks (malware/phishing/botnet) use a per-category SUBDOMAIN
# instead: e.g. malware.block.sse.cisco.com/?url=<domain>&server=<node>.
_BLOCK_PAGE_HOSTS = ("block.sse.cisco.com",)

# Leading sub-domain label of a security block page -> human-readable family.
_BLOCK_SUBDOMAIN_LABELS = {
    "malware": "Malware",
    "phishing": "Phishing",
    "botnet": "Command and Control / Botnet",
    "command": "Command and Control / Botnet",
    "security": "Security policy",
    "block": None,  # bare block.sse.cisco.com -> fall back to path/JWT logic
}

# First path segment of the block-page URL -> human-readable block family.
_BLOCK_PATH_LABELS = {
    "dlp": "Data Loss Prevention (DLP)",
    "aiguardrails": "AI guardrail",
    "ai": "AI guardrail",
    "category": "Content category / URL filtering",
    "contentcategory": "Content category / URL filtering",
    "application": "Application control",
    "appcontrol": "Application control",
    "malware": "Malware",
    "phishing": "Phishing",
    "botnet": "Command and Control / Botnet",
    "security": "Security policy",
}

# HTTP security block pages return a 403 whose HTML body redirects via JS:
#   <script>location.replace("https://malware.block.sse.cisco.com/?url=...")</script>
# The block-page URL lives ONLY in the body, not in any header.
_BODY_BLOCK_REDIRECT = re.compile(
    r"""location\.replace\(\s*['"]([^'"]*block\.sse\.cisco\.com[^'"]*)['"]""",
    re.IGNORECASE,
)


def _extract_body_block_url(body: Optional[str]) -> Optional[str]:
    """Pull a *.block.sse.cisco.com redirect target out of a block-page HTML
    body (the JS `location.replace(...)` used by HTTP security blocks)."""
    if not body or "block.sse.cisco.com" not in body:
        return None
    m = _BODY_BLOCK_REDIRECT.search(body)
    return m.group(1) if m else None


def _b64url_decode(seg: str) -> bytes:
    """Decode a base64url JWT segment, tolerating missing padding."""
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _decode_block_info(location: Optional[str]) -> Optional[dict[str, Any]]:
    """If `location` is a Secure Access block-page URL, return a dict with the
    block family and (when present) the decoded `blockinfo` JWT claims.

    Two shapes are handled:
      * SWG/DLP page  block.sse.cisco.com/<family>/?blockinfo=<JWT>
      * Security page <family>.block.sse.cisco.com/?url=<domain>&server=<node>
    The JWT is signed (HS256) but we only READ the payload — no signature
    verification or secret is needed. Returns None for non-block URLs."""
    if not location:
        return None
    try:
        u = urlparse(location)
    except (ValueError, TypeError):
        return None
    host = (u.hostname or "").lower()
    if not any(host == h or host.endswith("." + h) for h in _BLOCK_PAGE_HOSTS):
        return None

    qs = parse_qs(u.query)
    info: dict[str, Any] = {"url": location}

    # Security block page: category is the leading sub-domain label and the
    # blocked domain + proxy node ride in query params (no JWT).
    sub = host[: -len(".block.sse.cisco.com")] if host.endswith(".block.sse.cisco.com") else ""
    sub_label = _BLOCK_SUBDOMAIN_LABELS.get(sub) if sub else None
    if sub_label:
        info["block_type"] = sub_label
        info["path"] = sub
        orig = qs.get("url", [None])[0]
        if orig:
            orig_host = orig.split("/")[0].split("?")[0].lower()
            info["original_url"] = orig if "://" in orig else "http://" + orig
            info["original_host"] = orig_host or None
    else:
        seg = u.path.strip("/").split("/", 1)[0].lower()
        info["block_type"] = _BLOCK_PATH_LABELS.get(seg, "Web policy")
        info["path"] = seg or None

    server = qs.get("server", [None])[0]
    if server:
        info["server"] = server
    token = qs.get("blockinfo", [None])[0]
    if token and token.count(".") >= 2:
        try:
            payload = json.loads(_b64url_decode(token.split(".")[1]))
            if isinstance(payload, dict):
                info["claims"] = payload
                # The blockinfo JWT carries the ORIGINAL blocked request in the
                # `url` claim (and the block family in `btype`). This is the
                # real destination even on the followed block.sse.cisco.com
                # fetch, so we surface it for naming/dedup downstream.
                orig = payload.get("url")
                if orig:
                    info["original_url"] = orig
                    try:
                        info["original_host"] = (urlparse(orig).hostname or "").lower() or None
                    except (ValueError, TypeError):
                        pass
                btype = str(payload.get("btype") or "").lower()
                if btype and btype in _BLOCK_PATH_LABELS and info.get("block_type") == "Web policy":
                    info["block_type"] = _BLOCK_PATH_LABELS[btype]
        except (ValueError, TypeError, json.JSONDecodeError):
            pass
    return info


# Browser error substrings -> (human label, category)
_BROWSER_ERRORS = {
    "ERR_CERT_AUTHORITY_INVALID": ("Certificate authority not trusted", "cert_trust"),
    "ERR_CERT_COMMON_NAME_INVALID": ("Certificate name mismatch", "public_cert"),
    "ERR_CERT_DATE_INVALID": ("Certificate date invalid (expired/not yet valid)", "public_cert"),
    "ERR_CERT_REVOKED": ("Certificate revoked", "public_cert"),
    "ERR_CERT_INVALID": ("Certificate invalid", "cert_trust"),
    "ERR_SSL_PROTOCOL_ERROR": ("SSL/TLS protocol error", "tls_handshake"),
    "ERR_SSL_VERSION_OR_CIPHER_MISMATCH": ("TLS version / cipher mismatch", "tls_version"),
    "ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN": ("HPKP/pinned key not in chain (pinning)", "pinning_signal"),
    "ERR_CERTIFICATE_TRANSPARENCY_REQUIRED": ("Certificate Transparency required", "cert_trust"),
    "ERR_PROXY_CONNECTION_FAILED": ("Proxy connection failed", "proxy"),
    "ERR_TUNNEL_CONNECTION_FAILED": ("HTTP CONNECT tunnel failed", "proxy"),
    "ERR_CONNECTION_RESET": ("Connection reset", "network"),
    "ERR_CONNECTION_CLOSED": ("Connection closed unexpectedly", "network"),
    "ERR_CONNECTION_TIMED_OUT": ("Connection timed out", "network"),
    "ERR_CONNECTION_REFUSED": ("Connection refused", "network"),
    "ERR_NAME_NOT_RESOLVED": ("DNS resolution failed", "dns"),
    "ERR_QUIC_PROTOCOL_ERROR": ("QUIC protocol error", "quic"),
    "ERR_HTTP2_PROTOCOL_ERROR": ("HTTP/2 protocol error", "tls_handshake"),
    "ERR_EMPTY_RESPONSE": ("Empty response", "proxy"),
    "ERR_FAILED": ("Generic request failure", "network"),
    "ERR_ABORTED": ("Request aborted", "network"),
    "ERR_BLOCKED_BY_CLIENT": ("Blocked by client/extension", "proxy"),
    "ERR_BLOCKED_BY_ADMINISTRATOR": ("Blocked by administrator policy", "proxy"),
}


@dataclass
class HarEntry:
    url: str
    host: str
    method: str
    status: int
    status_text: str
    started: Optional[float]        # epoch seconds
    duration_ms: Optional[float]
    server_ip: Optional[str]
    error_text: Optional[str]
    error_label: Optional[str]
    error_category: Optional[str]
    http_version: Optional[str]
    blocked: bool = False
    scheme: str = "https"
    via: Optional[str] = None            # Via response header (proxy chain)
    server_header: Optional[str] = None  # Server response header
    alt_svc: Optional[str] = None        # Alt-Svc header (QUIC/HTTP3 advertisement)
    # Secure Access block-page redirect (302 -> block.sse.cisco.com). Unlike a
    # PCAP, where this redirect is inside TLS and invisible, the HAR exposes it
    # in clear: the path gives the block family and `blockinfo` is a decodable JWT.
    block_type: Optional[str] = None     # e.g. "Data Loss Prevention (DLP)"
    block_info: Optional[dict] = None    # decoded block-page metadata + JWT claims
    # Per-request timing breakdown (milliseconds) from the HAR `timings` object.
    # -1/None means the phase was not applicable or not measured. `wait` is the
    # server think-time (TTFB); `ssl` is part of `connect` per the HAR spec.
    t_blocked: float | None = None
    t_dns: Optional[float] = None
    t_connect: Optional[float] = None
    t_ssl: Optional[float] = None
    t_send: Optional[float] = None
    t_wait: Optional[float] = None
    t_receive: Optional[float] = None
    # What actually crossed, as opposed to how long it took. A HAR states these
    # exactly, where a capture can only infer them through encryption.
    req_body_bytes: int | None = None
    resp_body_bytes: int | None = None
    content_bytes: int | None = None           # decoded size; > body when compressed
    mime_type: str | None = None
    post_mime: str | None = None               # what was uploaded, if anything
    post_bytes: int | None = None
    query_params: int = 0
    # Response headers worth naming on their own: they answer questions people
    # actually ask of a HAR - who served it, was it cached, was it redirected,
    # and does the answer carry a cookie.
    content_type: str | None = None
    location: str | None = None
    cache_control: str | None = None
    set_cookie: bool = False
    # Request context: what the page was doing when it made this call.
    referer: str | None = None
    origin: str | None = None
    user_agent: str | None = None
    sent_cookie: bool = False
    sent_auth: bool = False
    # Chrome and Edge record why the request happened at all.
    resource_type: str | None = None
    initiator: str | None = None
    # Header counts, so a reader can tell a bare request from a heavy one
    # without the headers themselves being shipped.
    req_header_count: int = 0
    resp_header_count: int = 0


@dataclass
class HarResult:
    entries: list[HarEntry] = field(default_factory=list)
    parse_error: Optional[str] = None

    @property
    def failed(self) -> list[HarEntry]:
        return [e for e in self.entries if e.error_text or e.status == 0 or e.status >= 400 or e.blocked]


def _pos(value: Optional[float]) -> Optional[float]:
    """HAR timing phases use -1 for "not applicable". Keep only real (>=0) values."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v >= 0 else None


def _epoch(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        # HAR uses ISO 8601, often with milliseconds and timezone
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _classify_error(text: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if not text:
        return None, None, None
    upper = text.upper()
    for key, (label, cat) in _BROWSER_ERRORS.items():
        if key in upper:
            return text, label, cat
    return text, "Browser error", "network"


def _header(headers: list[dict], name: str) -> Optional[str]:
    """Case-insensitive lookup of an HTTP header value from HAR header list."""
    target = name.lower()
    for h in headers or []:
        if (h.get("name") or "").lower() == target:
            val = h.get("value")
            return val if val not in (None, "") else None
    return None


def _int_or_none(value: Any) -> int | None:
    """HAR sizes use -1 for "not available"; keep only real (>=0) values."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _initiator_of(entry: dict) -> str | None:
    """Why the browser made this request, when the exporter recorded it."""
    raw = entry.get("_initiator")
    if isinstance(raw, dict):
        kind = raw.get("type")
        url = raw.get("url")
        return f"{kind} \u00b7 {url}" if kind and url else (kind or None)
    return raw if isinstance(raw, str) else None


def parse_har(raw: str) -> HarResult:
    result = HarResult()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        result.parse_error = f"Invalid HAR JSON: {exc}"
        return result

    entries = (((data or {}).get("log") or {}).get("entries")) or []
    for e in entries:
        req = e.get("request", {}) or {}
        resp = e.get("response", {}) or {}
        url = req.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname or ""
        status = resp.get("status", 0) or 0

        # Chrome/Edge store failures under _error or response with status 0
        error_text = e.get("_error") or resp.get("_error")
        if not error_text and status == 0:
            error_text = resp.get("statusText") or "Request failed (status 0)"
        err_text, err_label, err_cat = _classify_error(error_text)

        timings = e.get("timings", {}) or {}
        blocked_flag = False
        # Some exporters mark blocked requests in _blocked / custom fields
        if e.get("_blocked") or (resp.get("statusText") or "").lower() in {"blocked", "blocked by client"}:
            blocked_flag = True

        resp_headers = resp.get("headers", []) or []
        # Secure Access block-page detection. The block can surface in four
        # places, and different browsers/exporters/block-types populate
        # different ones, so we check all of them or we miss real blocks:
        #   1. response.redirectURL  — HAR's canonical redirect field
        #   2. the Location response header (same target)
        #   3. the request URL itself — the entry the browser FOLLOWS after the
        #      302 is a GET to block.sse.cisco.com/<type>/?...blockinfo=..., so
        #      the JWT rides on its own request URL.
        #   4. the response BODY — HTTP security blocks (malware/phishing/
        #      botnet) return a 403 whose HTML body does a JS location.replace
        #      to <family>.block.sse.cisco.com/?url=<domain>&server=<node>.
        block = (_decode_block_info(resp.get("redirectURL"))
                 or _decode_block_info(_header(resp_headers, "location"))
                 or _decode_block_info(url)
                 or _decode_block_info(
                     _extract_body_block_url((resp.get("content") or {}).get("text"))))
        if block:
            blocked_flag = True
            if not err_label:
                err_label = f"Blocked by Secure Access \u2014 {block['block_type']}"
                err_cat = "proxy"
        req_headers = req.get("headers", []) or []
        content = resp.get("content") or {}
        post = req.get("postData") or {}
        mime = (content.get("mimeType") or "").split(";")[0].strip() or None

        result.entries.append(HarEntry(
            url=url,
            host=host,
            method=req.get("method", ""),
            status=status,
            status_text=resp.get("statusText", "") or "",
            started=_epoch(e.get("startedDateTime")),
            duration_ms=e.get("time"),
            server_ip=e.get("serverIPAddress"),
            error_text=err_text,
            error_label=err_label,
            error_category=err_cat,
            http_version=resp.get("httpVersion"),
            blocked=blocked_flag,
            scheme=parsed.scheme or "https",
            via=_header(resp_headers, "via"),
            server_header=_header(resp_headers, "server"),
            alt_svc=_header(resp_headers, "alt-svc"),
            block_type=block["block_type"] if block else None,
            block_info=block,
            t_blocked=_pos(timings.get("blocked")),
            t_dns=_pos(timings.get("dns")),
            t_connect=_pos(timings.get("connect")),
            t_ssl=_pos(timings.get("ssl")),
            t_send=_pos(timings.get("send")),
            t_wait=_pos(timings.get("wait")),
            t_receive=_pos(timings.get("receive")),
            req_body_bytes=_int_or_none(req.get("bodySize")),
            resp_body_bytes=_int_or_none(resp.get("bodySize")),
            content_bytes=_int_or_none(content.get("size")),
            mime_type=mime,
            post_mime=(post.get("mimeType") or "").split(";")[0].strip() or None,
            post_bytes=len(post.get("text") or "") or None,
            query_params=len(req.get("queryString") or []),
            content_type=_header(resp_headers, "content-type"),
            location=_header(resp_headers, "location"),
            cache_control=_header(resp_headers, "cache-control"),
            set_cookie=bool(_header(resp_headers, "set-cookie")),
            referer=_header(req_headers, "referer"),
            origin=_header(req_headers, "origin"),
            user_agent=_header(req_headers, "user-agent"),
            sent_cookie=bool(_header(req_headers, "cookie")),
            sent_auth=bool(_header(req_headers, "authorization")),
            resource_type=e.get("_resourceType"),
            initiator=_initiator_of(e),
            req_header_count=len(req_headers),
            resp_header_count=len(resp_headers),
        ))
    return result
