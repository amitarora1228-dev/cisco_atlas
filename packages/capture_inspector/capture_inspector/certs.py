"""X.509 certificate analysis using the `cryptography` library.

tshark hands us certificate bytes as colon-separated hex (from
`tls.handshake.certificate`). We parse them precisely here to extract issuer,
subject, SAN, validity, and to apply heuristics for detecting a proxy/SWG
that has re-signed traffic with a corporate CA.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID


# --- Known Cisco Secure Access Root CA (the SWG re-signing anchor) -----------
# Re-signed traffic chains up to this root. Matching against it lets us state
# positively (not just heuristically) that a leaf was issued by Secure Access.
SECURE_ACCESS_ROOT = {
    "cn": "Cisco Secure Access Root CA",
    "ski": "7b0ee501ec40ed1d8a2323d7d58254fb498f5865",
    "sha256": "5e4b0e86fcdb405d155e6740553b56ded9c598f9be235797693ab3022e268282",
}
# Issuer/subject fragments that mark a cert as part of the Secure Access PKI
# (Root CA, Secondary SubCA xxx-SG, etc.).
_SECURE_ACCESS_HINTS = ("cisco secure access", "secure access root ca", "secure access secondary subca")


# Well-known public CA issuer-org fragments. Presence does NOT prove anything by
# itself, but absence (i.e. an unknown/corporate-looking issuer) is a signal of
# interception when combined with other evidence.
_PUBLIC_CA_HINTS = {
    "digicert", "let's encrypt", "lets encrypt", "globalsign", "sectigo",
    "comodo", "godaddy", "google trust services", "amazon", "entrust",
    "baltimore", "isrg", "verisign", "thawte", "geotrust", "rapidssl",
    "starfield", "microsoft", "apple", "cloudflare", "buypass", "certum",
    "ssl.com", "actalis", "quovadis", "identrust",
}

# Issuer-org fragments that strongly suggest a corporate / middlebox CA.
_PROXY_CA_HINTS = {
    "zscaler", "netskope", "palo alto", "paloalto", "forcepoint", "bluecoat",
    "blue coat", "symantec web", "fortinet", "fortigate", "cisco umbrella",
    "umbrella", "secure access", "mcafee", "skyhigh", "checkpoint",
    "check point", "sophos", "barracuda", "proxy", "ssl inspection",
    "decrypt", "firewall", "corporate", "internal ca", "mitmproxy", "squid",
}


@dataclass
class CertInfo:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    subject_org: Optional[str] = None
    san_dns: list[str] = field(default_factory=list)
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    is_ca: bool = False
    is_self_signed: bool = False
    serial: Optional[str] = None
    sig_algo: Optional[str] = None
    looks_like_proxy_ca: bool = False
    looks_like_public_ca: bool = False
    ski: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    is_secure_access: bool = False        # issued by / part of Cisco Secure Access PKI
    is_secure_access_root: bool = False   # this cert IS the Secure Access Root CA
    parse_error: Optional[str] = None


@dataclass
class CertWindow:
    """Where a certificate sat in its validity window at one moment in time."""
    status: str                       # valid | expired | not_yet_valid | unknown
    not_before: datetime | None = None
    not_after: datetime | None = None
    at: datetime | None = None
    days_outside: int = 0             # days past expiry, or days before it started
    lifetime_days: int | None = None

    @property
    def is_problem(self) -> bool:
        return self.status in ("expired", "not_yet_valid")


def _parse_stamp(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def evaluate_at(cert: CertInfo, when_epoch: float | None) -> CertWindow:
    """Judge a certificate at the moment it was actually presented.

    This is the only place that decides whether a certificate was expired, and it
    always needs a moment to judge against. Comparing against "now" is a
    different question: every capture eventually ages past the certificates in
    it, so an analysis-time check turns healthy old captures into certificate
    incidents. Pass the timestamp of the traffic being explained.
    """
    starts, ends = _parse_stamp(cert.not_before), _parse_stamp(cert.not_after)
    lifetime = (ends - starts).days if (starts and ends) else None
    if ends is None or when_epoch is None:
        return CertWindow("unknown", starts, ends, None, 0, lifetime)

    at = datetime.fromtimestamp(when_epoch, timezone.utc)
    if at > ends:
        return CertWindow("expired", starts, ends, at, (at - ends).days, lifetime)
    if starts and at < starts:
        return CertWindow("not_yet_valid", starts, ends, at, (starts - at).days, lifetime)
    return CertWindow("valid", starts, ends, at, 0, lifetime)


def _name_attr(name: x509.Name, oid) -> Optional[str]:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def parse_cert_hex(cert_hex: str) -> CertInfo:
    """Parse a single DER certificate provided as colon/space separated hex."""
    info = CertInfo()
    try:
        cleaned = cert_hex.replace(":", "").replace(" ", "").strip()
        der = bytes.fromhex(cleaned)
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as exc:  # noqa: BLE001 - report parse failure, keep going
        info.parse_error = str(exc)
        return info

    info.subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    info.issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    info.issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    info.subject_org = _name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    info.is_self_signed = cert.issuer == cert.subject

    try:
        info.serial = format(cert.serial_number, "x")
    except Exception:
        pass
    try:
        info.sig_algo = cert.signature_algorithm_oid._name  # type: ignore[attr-defined]
    except Exception:
        pass

    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=timezone.utc)
    info.not_before = nb.isoformat()
    info.not_after = na.isoformat()

    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        info.is_ca = bool(bc.ca)  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        info.is_ca = False
    except Exception:
        pass

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        info.san_dns = san.get_values_for_type(x509.DNSName)  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        info.san_dns = []
    except Exception:
        info.san_dns = []

    issuer_blob = " ".join(filter(None, [info.issuer_cn, info.issuer_org])).lower()
    info.looks_like_proxy_ca = any(hint in issuer_blob for hint in _PROXY_CA_HINTS)
    info.looks_like_public_ca = any(hint in issuer_blob for hint in _PUBLIC_CA_HINTS)

    # Fingerprint + Subject Key Identifier, used to positively match the known
    # Cisco Secure Access Root CA.
    try:
        from cryptography.hazmat.primitives import hashes
        info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        pass
    try:
        ski_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value
        info.ski = ski_ext.digest.hex()  # type: ignore[attr-defined]
    except Exception:
        pass

    # Positive Secure Access identification: by issuer/subject text, by SKI, or
    # by the exact root fingerprint.
    subject_blob = " ".join(filter(None, [info.subject_cn, info.subject_org])).lower()
    sa_text = any(h in issuer_blob or h in subject_blob for h in _SECURE_ACCESS_HINTS)
    info.is_secure_access_root = (
        info.fingerprint_sha256 == SECURE_ACCESS_ROOT["sha256"]
        or info.ski == SECURE_ACCESS_ROOT["ski"]
        or (info.is_self_signed and (info.subject_cn or "").strip().lower() == SECURE_ACCESS_ROOT["cn"].lower())
    )
    info.is_secure_access = sa_text or info.is_secure_access_root
    if info.is_secure_access:
        info.looks_like_proxy_ca = True
    return info


def analyze_leaf_chain(cert_hexes: list[str]) -> tuple[Optional[CertInfo], list[CertInfo]]:
    """Parse a certificate chain. Returns (leaf, full_chain).

    The first certificate in a TLS Certificate message is the leaf/end-entity.
    """
    chain = [parse_cert_hex(h) for h in cert_hexes if h]
    leaf = chain[0] if chain else None
    return leaf, chain


def secure_access_chain(leaf: Optional[CertInfo], chain: list[CertInfo]) -> dict:
    """Summarise whether a cert chain is anchored to the Cisco Secure Access PKI.

    Returns a dict with:
      - anchored: True if any cert in the chain is the Secure Access Root CA, or
                  the leaf was issued by a Secure Access (Sub)CA.
      - root_seen: True if the actual Root CA cert was presented in the chain.
      - path: human-readable issuance path, e.g.
              "*.scorecardresearch.com  <-  Secondary SubCA fra-SG  <-  Cisco Secure Access Root CA"
    """
    if not chain:
        return {"anchored": False, "root_seen": False, "path": None}
    root_seen = any(c.is_secure_access_root for c in chain)
    anchored = root_seen or bool(leaf and leaf.is_secure_access)
    path = None
    if anchored:
        parts = []
        for c in chain:
            label = c.subject_cn or c.subject_org or "(unknown)"
            parts.append(label)
        # If the root wasn't presented but the leaf was Secure Access-issued,
        # append the known anchor so the user sees the reference explicitly.
        if not root_seen and leaf and leaf.is_secure_access:
            if leaf.issuer_cn and leaf.issuer_cn not in parts:
                parts.append(leaf.issuer_cn)
            parts.append(SECURE_ACCESS_ROOT["cn"] + " (reference)")
        path = "  <-  ".join(parts)
    return {"anchored": anchored, "root_seen": root_seen, "path": path}

