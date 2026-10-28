# Sentinel PKI — Digital Certificate Verification & Assurance System

A specialized, cybersecurity-focused application for **Cryptography and Network Security — Module 3: Public-Key Management and Digital Certificates**.

**Sentinel PKI** demonstrates RSA key generation, in-memory Certificate Authority (CA) lifecycle management, X.509 certificate issuance, and cryptographic verification through an enterprise security console interface built with Python and Streamlit.

---

## Project Objectives

- Implement an interactive, air-gapped Public-Key Infrastructure (PKI) assurance console.
- Generate RSA-2048 keypairs and self-signed Root CA certificates using Python's `cryptography` library.
- Mint X.509 v3 end-entity certificates with standard cryptographic extensions (`BasicConstraints: ca=False`, `KeyUsage: Digital Signature, Key Encipherment`).
- Execute a rigorous 7-stage cryptographic verification pipeline checking RSA signatures, issuer chains, and temporal boundaries.
- Accurately evaluate and distinguish five core verification outcomes: `VALID`, `EXPIRED`, `TAMPERED`, `UNTRUSTED`, and `MALFORMED`.
- Enforce strict private-key protection: private keys reside solely in volatile process RAM and are never serialized or exported.

---

## Architecture and File Structure

```
Dsp_MiniProject/
├── app.py           — Sentinel PKI Security Console (Sidebar navigation, Dashboard, Issuance, Verification, Demo, Docs)
├── pki.py           — Cryptographic core: RSA key generation, X.509 building, 7-stage verification engine
├── test_pki.py      — Automated test suite (28 unittests covering all verification and boundary states)
├── requirements.txt — Python dependencies (cryptography, streamlit)
└── README.md        — Project technical documentation and runbook
```

All cryptographic operations remain strictly encapsulated inside [`pki.py`](file:///c:/Users/msuja/OneDrive/Desktop/Dsp_MiniProject/pki.py). The front-end [`app.py`](file:///c:/Users/msuja/OneDrive/Desktop/Dsp_MiniProject/app.py) interfaces exclusively through public API functions.

---

## Key Cryptographic Concepts

| Primitive | Role in Sentinel PKI |
| :--- | :--- |
| **RSA 2048-bit** | Asymmetric algorithm. A mathematically linked key pair: public key (open verification) and private key (confidential signing). |
| **Root Authority (CA)** | The designated trust anchor holding the master private signing key. Vouches for client identities. |
| **X.509 v3 Certificate** | Standardized ASN.1 structure binding an identity (Subject DN) to a Public Key, sealed with a CA signature. |
| **SHA-256 Digest** | Cryptographic hash over the To-Be-Signed (TBS) bytes, ensuring integrity against single-bit alterations. |
| **PKCS#1 v1.5** | Asymmetric signature padding scheme applied when computing and verifying RSA signatures. |
| **BasicConstraints** | Critical X.509 extension specifying whether the certificate holder may act as a CA (`ca=True` vs `ca=False`). |
| **KeyUsage** | Critical X.509 extension restricting permitted cryptographic operations (e.g. `keyCertSign`, `digitalSignature`). |

---

## 7-Stage Verification Pipeline

```
  Uploaded Leaf Certificate          Designated Trust Anchor (CA)
            │                                     │
            ▼                                     ▼
 ┌───────────────────────────────────────────────────────────────┐
 │               SENTINEL VERIFICATION PIPELINE                  │
 ├───────────────────────────────────────────────────────────────┤
 │ [1] ASN.1 Structure: Parse PEM/DER encoding (max 1 MB limit)  │
 │ [2] Leaf Temporal Bounds: NotBefore <= Timestamp <= NotAfter  │
 │ [3] CA Temporal Bounds: Verify trust anchor is not expired    │
 │ [4] Issuer Chain Match: Leaf Issuer DN == CA Subject DN       │
 │ [5] CA Authority Flag: Confirm BasicConstraints (ca=True)     │
 │ [6] Key Architecture: Confirm CA Public Key is RSA-2048       │
 │ [7] RSA Signature: Verify PKCS#1 v1.5 SHA-256 digest over TBS │
 └───────────────────────────────┬───────────────────────────────┘
                                 ▼
        [ VALID | EXPIRED | TAMPERED | UNTRUSTED | MALFORMED ]
```

---

## Prerequisites

- **Python**: 3.11 or later
- **Operating System**: Windows with PowerShell
- **Virtual Environment**: Standard Python `venv`

---

## Windows Setup and Run

Open PowerShell in the project directory (`c:\Users\msuja\OneDrive\Desktop\Dsp_MiniProject`) and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If script execution is restricted in your PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then open `http://localhost:8501` in your web browser.

---

## Console Workspace Guide

### 1. Dashboard
- **Telemetry Overview**: Displays real-time status of the in-memory Root CA, total evaluation counters, and issuance metrics.
- **Quick Action Triggers**: Instant navigation to verify or issue certificates.
- **Cryptographic Activity Log**: Real session audit stream tracking every certificate minted or evaluated during the active session.

### 2. Issue Certificate
- Mint a new X.509 credential bound to a student Common Name (1 to 64 characters).
- Configurable validity window (1 to 365 days).
- View full certificate attributes: Subject DN, Serial Number (Hex), Validity, SHA-256 Fingerprint.
- Export as standard `.pem` file.

### 3. Verify Certificate
- Dual-dropzone workspace: Target Certificate and optional Custom CA Trust Anchor.
- Supports both standard PEM (Base64) and raw binary DER formats.
- High-contrast verdict presentation: `VALID`, `EXPIRED`, `TAMPERED`, `UNTRUSTED`, or `MALFORMED`.
- 4-stage visual assurance checklist: Structure, Temporal Bounds, Chain Authority, and RSA Signature.
- Export detailed verification audit report as structured JSON.

### 4. Quick Demo
- One-click end-to-end demonstration executing key generation, CA signing, and cryptographic verification in real time.
- Side-by-side Issuance Manifest and Verification Verdict display.

### 5. About PKI
- Technical briefing covering asymmetric primitives, X.509 standards, digital signatures, and educational scope boundaries.

---

## Test Suite Execution

Run the complete 28-test automated suite using `unittest`:

```powershell
python -m unittest -v
```

### Test Coverage Matrix

| Test Method | Verification Scope | Expected Outcome |
| :--- | :--- | :--- |
| `test_valid_certificate` | Full issuance & verification cycle | `valid` |
| `test_expired_certificate` | Verification timestamp > `not_valid_after` | `expired` |
| `test_tampered_certificate` | Single-bit flip in DER signature bytes | `tampered` |
| `test_untrusted_certificate` | Leaf verified against foreign CA | `untrusted` |
| `test_malformed_certificate_random_bytes` | Arbitrary random non-ASN.1 byte stream | `malformed` |
| `test_empty_certificate_input` | 0-byte certificate input | `malformed` |
| `test_oversized_certificate` | Input payload exceeding 1 MB limit | `malformed` |
| `test_pem_round_trip` | PEM serialization and re-parsing fidelity | Exact match |
| `test_der_round_trip` | Raw DER certificate verification | `valid` |
| `test_invalid_student_validity_too_short` | `days_valid=0` | `ValueError` |
| `test_invalid_student_validity_too_long` | `days_valid=366` | `ValueError` |
| `test_invalid_ca_validity_too_short` | `days_valid=0` | `ValueError` |
| `test_invalid_ca_validity_too_long` | `days_valid=3651` | `ValueError` |
| `test_empty_student_name_raises` | Empty string for Common Name | `ValueError` |
| `test_whitespace_only_student_name_raises` | Whitespace-only Common Name | `ValueError` |
| `test_too_long_student_name_raises` | Common Name > 64 characters | `ValueError` |
| `test_wrong_issuer_is_untrusted` | Cross-issuer verification rejection | `untrusted` |
| `test_expiry_boundary_one_second_past` | Check at `not_valid_after + 1s` | `expired` |
| `test_expiry_boundary_one_second_before` | Check at `not_valid_after - 1s` | `valid` |
| `test_malformed_ca_input` | Non-ASN.1 byte stream as CA anchor | `malformed` |
| `test_empty_ca_input` | 0-byte CA input | `malformed` |
| `test_valid_result_has_detail_fields` | All metadata attributes populated | Verified |
| `test_fingerprint_format` | 32 colon-separated hex octets (SHA-256) | Verified |
| `test_public_key_info_rsa_2048` | Key algorithm `RSA` & bit size `2048` | Verified |
| `test_days_remaining_positive` | Newly issued certificate has positive window | Verified |
| `test_ca_cert_valid_against_itself` | Self-signed Root CA self-verification | `valid` |
| `test_custom_ca_name_and_validity` | Non-default CA parameters verification | `valid` |
| `test_expired_ca_returns_untrusted` | Expired CA trust anchor handling | `expired` / `untrusted` |

---

## Security Scope & Limitations

Sentinel PKI is engineered specifically as an educational demonstration for collegiate Cryptography and Network Security coursework. The following enterprise features are deliberately out of scope:

1. **Certificate Revocation (CRL / OCSP)**: Revocation status is not checked against live responders.
2. **Multi-Tier CA Hierarchies**: Supports direct single-tier Root-to-Leaf verification; intermediate CA chaining is not traversed.
3. **Persistent Key Storage**: CA and client private keys are ephemeral, held strictly in volatile RAM, and discarded upon process termination.
4. **Access Control & Identity Proofing**: Anyone with access to the interface may generate test credentials.
5. **Hardware Security Modules (HSM)**: Cryptographic operations execute in software without PKCS#11 or FIPS 140-2 hardware protection.

---

## Recommended Presentation Walkthrough

1. **Dashboard Overview**: Showcase the cybersecurity console layout, active Root CA parameters, and the live Session Activity Log.
2. **Certificate Issuance**: Mint a certificate for a student name, inspect the generated SHA-256 fingerprint, and download the `.pem` file.
3. **Valid Verification**: Upload the downloaded certificate into the Verification Workspace and demonstrate the `VALID` verdict with the 4-stage assurance checklist.
4. **Tamper Detection**: Open the downloaded `.pem` in a text editor, alter a single Base64 character in the signature block, upload it, and demonstrate the immediate `TAMPERED` detection.
5. **Expiry Boundary**: Demonstrate that certificates outside their temporal bounds trigger `EXPIRED`.
6. **Cross-CA Untrusted Check**: Rotate the demo CA in the sidebar and verify the previous certificate against the new CA to demonstrate `UNTRUSTED`.
7. **JSON Report Export**: Download and inspect the structured JSON verification audit report.
