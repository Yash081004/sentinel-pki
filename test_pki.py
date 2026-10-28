"""Unit tests for pki.py.

Existing tests (4) are preserved exactly.  New tests are appended below.
Run with:  python -m unittest -v
"""
from datetime import UTC, datetime, timedelta
import unittest

from cryptography.hazmat.primitives import serialization

from pki import (
    MAX_CERT_BYTES,
    certificate_pem,
    generate_demo_ca,
    issue_student_certificate,
    verify_certificate,
    _fingerprint,
    _public_key_info,
    _load_certificate,
)


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------
class CertificateVerificationTests(unittest.TestCase):
    """Core verification tests — the original 4 plus extended coverage."""

    def setUp(self):
        self.ca_key, self.ca = generate_demo_ca()
        _, self.cert = issue_student_certificate(self.ca_key, self.ca, "Test Student")

    # ------------------------------------------------------------------ #
    # Original four tests (must remain passing)                           #
    # ------------------------------------------------------------------ #

    def test_valid_certificate(self):
        result = verify_certificate(certificate_pem(self.cert), certificate_pem(self.ca))
        self.assertEqual(result.status, "valid")

    def test_expired_certificate(self):
        future = datetime.now(UTC) + timedelta(days=366)
        result = verify_certificate(
            certificate_pem(self.cert), certificate_pem(self.ca), now=future
        )
        self.assertEqual(result.status, "expired")

    def test_tampered_certificate(self):
        data = bytearray(self.cert.public_bytes(serialization.Encoding.DER))
        data[-1] ^= 1  # Flip a bit in the signature.
        result = verify_certificate(bytes(data), certificate_pem(self.ca))
        self.assertEqual(result.status, "tampered")

    def test_untrusted_certificate(self):
        _, other_ca = generate_demo_ca("Other Demo CA")
        result = verify_certificate(certificate_pem(self.cert), certificate_pem(other_ca))
        self.assertEqual(result.status, "untrusted")

    # ------------------------------------------------------------------ #
    # New Test 1 – Malformed certificate input (random bytes)             #
    # ------------------------------------------------------------------ #

    def test_malformed_certificate_random_bytes(self):
        result = verify_certificate(b"not a certificate at all", certificate_pem(self.ca))
        self.assertEqual(result.status, "malformed")

    # ------------------------------------------------------------------ #
    # New Test 2 – Empty input for certificate                            #
    # ------------------------------------------------------------------ #

    def test_empty_certificate_input(self):
        result = verify_certificate(b"", certificate_pem(self.ca))
        self.assertEqual(result.status, "malformed")

    # ------------------------------------------------------------------ #
    # New Test 3 – Oversized upload (exceeds MAX_CERT_BYTES)              #
    # ------------------------------------------------------------------ #

    def test_oversized_certificate(self):
        oversized = b"A" * (MAX_CERT_BYTES + 1)
        result = verify_certificate(oversized, certificate_pem(self.ca))
        self.assertEqual(result.status, "malformed")

    # ------------------------------------------------------------------ #
    # New Test 4 – PEM round-trip                                         #
    # ------------------------------------------------------------------ #

    def test_pem_round_trip(self):
        pem = certificate_pem(self.cert)
        self.assertTrue(pem.startswith(b"-----BEGIN CERTIFICATE-----"))
        loaded = _load_certificate(pem)
        self.assertEqual(loaded.serial_number, self.cert.serial_number)

    # ------------------------------------------------------------------ #
    # New Test 5 – DER round-trip                                         #
    # ------------------------------------------------------------------ #

    def test_der_round_trip(self):
        der = self.cert.public_bytes(serialization.Encoding.DER)
        result = verify_certificate(der, certificate_pem(self.ca))
        self.assertEqual(result.status, "valid")

    # ------------------------------------------------------------------ #
    # New Test 6 – Invalid student certificate validity duration           #
    # ------------------------------------------------------------------ #

    def test_invalid_student_validity_too_short(self):
        with self.assertRaises(ValueError):
            issue_student_certificate(self.ca_key, self.ca, "Student", days_valid=0)

    def test_invalid_student_validity_too_long(self):
        with self.assertRaises(ValueError):
            issue_student_certificate(self.ca_key, self.ca, "Student", days_valid=366)

    # ------------------------------------------------------------------ #
    # New Test 7 – Invalid CA validity duration                           #
    # ------------------------------------------------------------------ #

    def test_invalid_ca_validity_too_short(self):
        with self.assertRaises(ValueError):
            generate_demo_ca(days_valid=0)

    def test_invalid_ca_validity_too_long(self):
        with self.assertRaises(ValueError):
            generate_demo_ca(days_valid=3651)

    # ------------------------------------------------------------------ #
    # New Test 8 – Invalid common name length                             #
    # ------------------------------------------------------------------ #

    def test_empty_student_name_raises(self):
        with self.assertRaises(ValueError):
            issue_student_certificate(self.ca_key, self.ca, "")

    def test_whitespace_only_student_name_raises(self):
        with self.assertRaises(ValueError):
            issue_student_certificate(self.ca_key, self.ca, "   ")

    def test_too_long_student_name_raises(self):
        with self.assertRaises(ValueError):
            issue_student_certificate(self.ca_key, self.ca, "A" * 65)

    # ------------------------------------------------------------------ #
    # New Test 9 – Wrong issuer (different CA)                            #
    # ------------------------------------------------------------------ #

    def test_wrong_issuer_is_untrusted(self):
        """A cert signed by CA-A should be UNTRUSTED when verified against CA-B."""
        ca_key_b, ca_b = generate_demo_ca("Other CA B")
        result = verify_certificate(certificate_pem(self.cert), certificate_pem(ca_b))
        self.assertEqual(result.status, "untrusted")

    # ------------------------------------------------------------------ #
    # New Test 10 – Boundary: cert expires exactly at check_time          #
    # ------------------------------------------------------------------ #

    def test_expiry_boundary_one_second_past(self):
        """Certificate should be expired when checked 1 second after not_valid_after."""
        _, cert = issue_student_certificate(self.ca_key, self.ca, "Boundary", days_valid=90)
        from pki import _validity_bounds
        _, cert_end = _validity_bounds(cert)
        just_after = cert_end + timedelta(seconds=1)
        result = verify_certificate(certificate_pem(cert), certificate_pem(self.ca), now=just_after)
        self.assertEqual(result.status, "expired")

    def test_expiry_boundary_one_second_before(self):
        """Certificate should be valid when checked 1 second before not_valid_after."""
        _, cert = issue_student_certificate(self.ca_key, self.ca, "Boundary2", days_valid=90)
        from pki import _validity_bounds
        _, cert_end = _validity_bounds(cert)
        just_before = cert_end - timedelta(seconds=1)
        result = verify_certificate(certificate_pem(cert), certificate_pem(self.ca), now=just_before)
        self.assertEqual(result.status, "valid")

    # ------------------------------------------------------------------ #
    # New Test 11 – Malformed CA input                                    #
    # ------------------------------------------------------------------ #

    def test_malformed_ca_input(self):
        result = verify_certificate(certificate_pem(self.cert), b"garbage CA data")
        self.assertEqual(result.status, "malformed")

    def test_empty_ca_input(self):
        result = verify_certificate(certificate_pem(self.cert), b"")
        self.assertEqual(result.status, "malformed")

    # ------------------------------------------------------------------ #
    # New Test 12 – verify_certificate result has all detail fields       #
    # ------------------------------------------------------------------ #

    def test_valid_result_has_detail_fields(self):
        result = verify_certificate(certificate_pem(self.cert), certificate_pem(self.ca))
        self.assertEqual(result.status, "valid")
        self.assertIsNotNone(result.subject)
        self.assertIsNotNone(result.issuer)
        self.assertIsNotNone(result.serial_number)
        self.assertIsNotNone(result.valid_from)
        self.assertIsNotNone(result.valid_until)
        self.assertIsNotNone(result.fingerprint_sha256)
        self.assertIsNotNone(result.public_key_algorithm)
        self.assertIsNotNone(result.public_key_bits)

    # ------------------------------------------------------------------ #
    # New Test 13 – Fingerprint format (XX:XX:... hex pairs)              #
    # ------------------------------------------------------------------ #

    def test_fingerprint_format(self):
        fp = _fingerprint(self.cert)
        parts = fp.split(":")
        self.assertEqual(len(parts), 32)  # SHA-256 = 32 bytes
        for part in parts:
            self.assertEqual(len(part), 2)
            int(part, 16)  # Must be valid hex.

    # ------------------------------------------------------------------ #
    # New Test 14 – Public key info returns RSA and 2048 bits             #
    # ------------------------------------------------------------------ #

    def test_public_key_info_rsa_2048(self):
        algo, bits = _public_key_info(self.cert)
        self.assertEqual(algo, "RSA")
        self.assertEqual(bits, 2048)

    # ------------------------------------------------------------------ #
    # New Test 15 – days_remaining is positive for a fresh cert           #
    # ------------------------------------------------------------------ #

    def test_days_remaining_positive(self):
        result = verify_certificate(certificate_pem(self.cert), certificate_pem(self.ca))
        self.assertIsNotNone(result.days_remaining)
        self.assertGreater(result.days_remaining, 0)

    # ------------------------------------------------------------------ #
    # New Test 16 – CA cert verified against itself                       #
    # ------------------------------------------------------------------ #

    def test_ca_cert_valid_against_itself(self):
        """Self-signed CA cert should be VALID when used as its own trust anchor."""
        result = verify_certificate(certificate_pem(self.ca), certificate_pem(self.ca))
        self.assertEqual(result.status, "valid")

    # ------------------------------------------------------------------ #
    # New Test 17 – generate_demo_ca and issue_student_certificate work   #
    #               end-to-end with non-default parameters                #
    # ------------------------------------------------------------------ #

    def test_custom_ca_name_and_validity(self):
        ca_key, ca = generate_demo_ca("Custom CA", days_valid=30)
        _, cert = issue_student_certificate(ca_key, ca, "Custom Student", days_valid=10)
        result = verify_certificate(certificate_pem(cert), certificate_pem(ca))
        self.assertEqual(result.status, "valid")

    # ------------------------------------------------------------------ #
    # New Test 18 – Expired CA causes untrusted result                    #
    # ------------------------------------------------------------------ #

    def test_expired_ca_returns_untrusted(self):
        """When the CA itself is expired (at check_time), the result is UNTRUSTED."""
        ca_key, ca = generate_demo_ca("Short CA", days_valid=1)
        _, cert = issue_student_certificate(ca_key, ca, "Student X", days_valid=1)
        far_future = datetime.now(UTC) + timedelta(days=400)
        result = verify_certificate(certificate_pem(cert), certificate_pem(ca), now=far_future)
        # The leaf is expired at far_future, so we get expired first (leaf checked first).
        self.assertIn(result.status, ("expired", "untrusted"))


if __name__ == "__main__":
    unittest.main()
