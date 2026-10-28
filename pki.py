"""Small, educational PKI helpers for the certificate verification demo.

This module intentionally omits production features such as CRL/OCSP checking,
intermediate CA chain validation, and persistent key storage.  It is designed
for a college cryptography mini-project only.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.x509.oid import NameOID

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
Key = Union[rsa.RSAPrivateKey]
MAX_CERT_BYTES = 1_000_000  # 1 MB upload limit
_MIN_CN_LEN = 1
_MAX_CN_LEN = 64


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class VerificationResult:
    """Result returned by verify_certificate."""
    status: str                         # valid | expired | tampered | untrusted | malformed
    message: str
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    fingerprint_sha256: str | None = None
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
    days_remaining: int | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _utc(value: datetime) -> datetime:
    """Ensure a datetime is UTC-aware."""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _validity_bounds(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    """Return UTC-aware (not_valid_before, not_valid_after) regardless of
    cryptography library version."""
    start = getattr(certificate, "not_valid_before_utc", None)
    end = getattr(certificate, "not_valid_after_utc", None)
    if start is None or end is None:
        start = certificate.not_valid_before
        end = certificate.not_valid_after
    return _utc(start), _utc(end)


def _name(common_name: str, organization: str = "PKI Mini Project") -> x509.Name:
    """Build an x509.Name, validating the common name length."""
    clean = common_name.strip()
    if not _MIN_CN_LEN <= len(clean) <= _MAX_CN_LEN:
        raise ValueError(
            f"Common name must be between {_MIN_CN_LEN} and {_MAX_CN_LEN} characters."
        )
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, clean),
    ])


def _fingerprint(certificate: x509.Certificate) -> str:
    """Return the SHA-256 fingerprint of the certificate DER bytes."""
    der = certificate.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))


def _public_key_info(certificate: x509.Certificate) -> tuple[str, int | None]:
    """Return (algorithm_name, key_size_in_bits) for the certificate's public key."""
    pub = certificate.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC ({pub.curve.name})", pub.key_size
    return type(pub).__name__, None


def _days_remaining(valid_until: datetime, now: datetime) -> int:
    """Days remaining until certificate expiry (negative if already expired)."""
    delta = _utc(valid_until) - _utc(now)
    return delta.days


def _certificate_details(
    certificate: x509.Certificate,
    now: datetime | None = None,
) -> dict:
    """Extract human-readable certificate fields for reporting."""
    valid_from, valid_until = _validity_bounds(certificate)
    algo, bits = _public_key_info(certificate)
    check = _utc(now) if now else datetime.now(UTC)
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "X"),
        "valid_from": valid_from.strftime("%Y-%m-%d %H:%M UTC"),
        "valid_until": valid_until.strftime("%Y-%m-%d %H:%M UTC"),
        "fingerprint_sha256": _fingerprint(certificate),
        "public_key_algorithm": algo,
        "public_key_bits": bits,
        "days_remaining": _days_remaining(valid_until, check),
    }


def _load_certificate(data: bytes) -> x509.Certificate:
    """Load a PEM or DER certificate; raise ValueError for invalid data or size."""
    if not data:
        raise ValueError("Certificate data is empty.")
    if len(data) > MAX_CERT_BYTES:
        raise ValueError(
            f"Certificate file is too large ({len(data):,} bytes). "
            f"Maximum allowed is {MAX_CERT_BYTES:,} bytes."
        )
    try:
        return x509.load_pem_x509_certificate(data)
    except (ValueError, Exception):
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except (ValueError, Exception):
        raise ValueError("Data is not a valid PEM or DER X.509 certificate.")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def generate_demo_ca(
    common_name: str = "Mini Project Demo CA",
    days_valid: int = 365,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a new RSA-2048 CA key-pair and a self-signed CA certificate.

    The CA private key is returned to the caller and must never be written to
    disk, displayed in the UI, or offered for download.
    """
    if not 1 <= days_valid <= 3650:
        raise ValueError("CA validity must be between 1 and 3650 days.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = _name(common_name)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def issue_student_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    student_name: str,
    days_valid: int = 90,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Issue a leaf (end-entity) certificate for a student, signed by the demo CA.

    The returned student private key stays in-memory; it is never written to disk.
    """
    if not 1 <= days_valid <= 365:
        raise ValueError("Certificate validity must be between 1 and 365 days.")
    student_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(student_name, "Student Certificate"))
        .issuer_name(ca_certificate.subject)
        .public_key(student_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return student_key, certificate


def certificate_pem(certificate: x509.Certificate) -> bytes:
    """Serialise a certificate to PEM bytes."""
    return certificate.public_bytes(serialization.Encoding.PEM)


def verify_certificate(
    certificate_data: bytes,
    trusted_ca_data: bytes,
    now: datetime | None = None,
) -> VerificationResult:
    """Verify a leaf certificate against one explicitly trusted, self-signed CA.

    Checks performed (in order):
    1. Parse both files; return MALFORMED on failure.
    2. Check the leaf certificate temporal validity.
    3. Check the CA certificate temporal validity.
    4. Verify the issuer/subject relationship.
    5. Verify the CA has the BasicConstraints CA flag set.
    6. Verify the CA uses RSA (the only algorithm supported by this demo).
    7. Verify the RSA PKCS#1 v1.5 signature on the leaf certificate.
    """
    # --- 1. Parse ---
    try:
        certificate = _load_certificate(certificate_data)
        ca_certificate = _load_certificate(trusted_ca_data)
    except ValueError as exc:
        return VerificationResult("malformed", str(exc))

    check_time = _utc(now) if now else datetime.now(UTC)
    details = _certificate_details(certificate, check_time)

    cert_start, cert_end = _validity_bounds(certificate)
    ca_start, ca_end = _validity_bounds(ca_certificate)

    # --- 2. Leaf temporal validity ---
    if not (cert_start <= check_time <= cert_end):
        return VerificationResult(
            "expired",
            "The certificate is outside its validity period.",
            **details,
        )

    # --- 3. CA temporal validity ---
    if not (ca_start <= check_time <= ca_end):
        return VerificationResult(
            "untrusted",
            "The selected CA certificate is outside its own validity period.",
            **details,
        )

    # --- 4. Issuer / subject match ---
    if certificate.issuer != ca_certificate.subject:
        return VerificationResult(
            "untrusted",
            "The certificate issuer does not match the selected trusted CA's subject.",
            **details,
        )

    # --- 5–7. CA constraints and signature ---
    try:
        constraints = ca_certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        if not constraints.ca:
            return VerificationResult(
                "untrusted",
                "The selected issuer certificate does not have the CA flag set.",
                **details,
            )

        ca_public_key = ca_certificate.public_key()
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            return VerificationResult(
                "untrusted",
                "Only RSA CA certificates are supported by this demo.",
                **details,
            )

        ca_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except Exception:
        return VerificationResult(
            "tampered",
            "Certificate signature verification failed; the certificate may have been modified.",
            **details,
        )

    return VerificationResult(
        "valid",
        "Certificate signature, issuer chain, and validity period are all valid.",
        **details,
    )
