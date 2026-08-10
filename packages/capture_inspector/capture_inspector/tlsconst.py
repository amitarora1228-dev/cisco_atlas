"""TLS / handshake constant mappings used across the analysis engine."""
from __future__ import annotations

HANDSHAKE_TYPES = {
    "1": "ClientHello",
    "2": "ServerHello",
    "4": "NewSessionTicket",
    "8": "EncryptedExtensions",
    "11": "Certificate",
    "12": "ServerKeyExchange",
    "13": "CertificateRequest",
    "14": "ServerHelloDone",
    "15": "CertificateVerify",
    "16": "ClientKeyExchange",
    "20": "Finished",
}

# tls.handshake.version / tls.record.version values
TLS_VERSIONS = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "768": "SSL 3.0",
    "769": "TLS 1.0",
    "770": "TLS 1.1",
    "771": "TLS 1.2",
    "772": "TLS 1.3",
}

# TLS alert level
ALERT_LEVELS = {"1": "warning", "2": "fatal"}

# TLS alert descriptions (RFC 5246 / 8446)
ALERT_DESCRIPTIONS = {
    "0": "close_notify",
    "10": "unexpected_message",
    "20": "bad_record_mac",
    "21": "decryption_failed",
    "22": "record_overflow",
    "30": "decompression_failure",
    "40": "handshake_failure",
    "41": "no_certificate",
    "42": "bad_certificate",
    "43": "unsupported_certificate",
    "44": "certificate_revoked",
    "45": "certificate_expired",
    "46": "certificate_unknown",
    "47": "illegal_parameter",
    "48": "unknown_ca",
    "49": "access_denied",
    "50": "decode_error",
    "51": "decrypt_error",
    "60": "export_restriction",
    "70": "protocol_version",
    "71": "insufficient_security",
    "80": "internal_error",
    "86": "inappropriate_fallback",
    "90": "user_canceled",
    "100": "no_renegotiation",
    "109": "missing_extension",
    "110": "unsupported_extension",
    "111": "certificate_unobtainable",
    "112": "unrecognized_name",
    "113": "bad_certificate_status_response",
    "115": "unknown_psk_identity",
    "116": "certificate_required",
    "120": "no_application_protocol",
}

# Alerts that typically indicate a certificate-trust / inspection problem.
CERT_TRUST_ALERTS = {
    "bad_certificate", "unsupported_certificate", "certificate_revoked",
    "certificate_expired", "certificate_unknown", "unknown_ca",
    "certificate_required", "decrypt_error", "bad_certificate_status_response",
}

# Common cipher suite id -> name (subset; tshark usually resolves names already).
CIPHER_SUITES = {
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0xc013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "0xc014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "0xc027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "0xc028": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}

# Weak / deprecated negotiated versions worth flagging.
WEAK_VERSIONS = {"SSL 3.0", "TLS 1.0", "TLS 1.1"}

# ECH extension type
ECH_EXTENSION_TYPES = {"65037", "0xfe0d", "64768"}  # encrypted_client_hello


def version_name(value: str | None) -> str | None:
    if value is None:
        return None
    return TLS_VERSIONS.get(value, TLS_VERSIONS.get(value.lower(), value))


def alert_desc(value: str | None) -> str | None:
    if value is None:
        return None
    return ALERT_DESCRIPTIONS.get(value, value)


def alert_level(value: str | None) -> str | None:
    if value is None:
        return None
    return ALERT_LEVELS.get(value, value)
