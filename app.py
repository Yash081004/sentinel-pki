"""Sentinel PKI — Cryptographic Trust & Digital Certificate Verification Console.

A specialized cybersecurity interface for Public-Key Infrastructure (PKI)
lifecycle management, X.509 certificate issuance, and cryptographic verification.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

import streamlit as st

from pki import (
    MAX_CERT_BYTES,
    _certificate_details,
    certificate_pem,
    generate_demo_ca,
    issue_student_certificate,
    verify_certificate,
)

# ---------------------------------------------------------------------------
# Page Configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Sentinel PKI | Assurance Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Session State Initialization
# ---------------------------------------------------------------------------
if "ca_key" not in st.session_state:
    st.session_state.ca_key, st.session_state.ca_certificate = generate_demo_ca()

if "current_page" not in st.session_state:
    st.session_state.current_page = "Dashboard"

if "issued_certs" not in st.session_state:
    st.session_state.issued_certs = []

if "verification_history" not in st.session_state:
    st.session_state.verification_history = []

# ---------------------------------------------------------------------------
# Cybersecurity Design System (Custom CSS)
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {
        --bg-midnight: #070b14;
        --bg-surface: #0d1424;
        --bg-surface-elevated: #121c33;
        --bg-card: #0f182c;
        --border-subtle: #192644;
        --border-accent: #1e3a6a;
        --border-cyan: #00e5ff;
        --cyan-core: #00f0ff;
        --cyan-dim: rgba(0, 240, 255, 0.12);
        --teal-accent: #14b8a6;
        --text-white: #f8fafc;
        --text-secondary: #94a3b8;
        --text-muted: #64748b;
        --status-valid-bg: rgba(16, 185, 129, 0.1);
        --status-valid-border: #10b981;
        --status-valid-text: #34d399;
        --status-expired-bg: rgba(245, 158, 11, 0.1);
        --status-expired-border: #f59e0b;
        --status-expired-text: #fbbf24;
        --status-tampered-bg: rgba(239, 68, 68, 0.1);
        --status-tampered-border: #ef4444;
        --status-tampered-text: #f87171;
        --status-untrusted-bg: rgba(168, 85, 247, 0.1);
        --status-untrusted-border: #a855f7;
        --status-untrusted-text: #c084fc;
        --status-malformed-bg: rgba(100, 116, 139, 0.1);
        --status-malformed-border: #64748b;
        --status-malformed-text: #cbd5e1;
    }

    /* Global resets */
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stApp {
        background-color: var(--bg-midnight);
        color: var(--text-white);
    }

    /* Top header bar */
    header[data-testid="stHeader"] {
        background-color: rgba(7, 11, 20, 0.85);
        backdrop-filter: blur(8px);
        border-bottom: 1px solid var(--border-subtle);
    }

    /* Sidebar console styling */
    [data-testid="stSidebar"] {
        background-color: #090e1a;
        border-right: 1px solid var(--border-subtle);
    }

    [data-testid="stSidebar"] hr {
        border-color: var(--border-subtle);
        margin: 1rem 0;
    }

    /* Radio navigation styling inside sidebar */
    [data-testid="stSidebar"] div[data-testid="stRadio"] > div[role="radiogroup"] {
        gap: 0.35rem;
    }

    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label {
        background: #0c1322;
        border: 1px solid var(--border-subtle);
        border-radius: 6px;
        padding: 0.65rem 0.9rem;
        margin: 0;
        cursor: pointer;
        transition: all 0.15s ease-in-out;
        color: var(--text-secondary);
    }

    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label:hover {
        background: var(--bg-surface-elevated);
        border-color: var(--border-accent);
        color: var(--text-white);
    }

    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label[data-checked="true"],
    [data-testid="stSidebar"] div[data-testid="stRadio"] div[role="radiogroup"] > label:has(input:checked) {
        background: #0f1c36 !important;
        border-color: var(--cyan-core) !important;
        color: var(--cyan-core) !important;
        font-weight: 600;
        box-shadow: 0 0 12px rgba(0, 240, 255, 0.12);
    }

    /* Custom Sentinel Cards */
    .sentinel-card {
        background-color: var(--bg-card);
        border: 1px solid var(--border-subtle);
        border-radius: 8px;
        padding: 1.25rem 1.4rem;
        margin-bottom: 1rem;
        transition: border-color 0.2s ease;
    }

    .sentinel-card:hover {
        border-color: var(--border-accent);
    }

    .sentinel-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 0.75rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border-subtle);
    }

    .sentinel-card-title {
        font-size: 0.85rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--cyan-core);
    }

    /* Banner & Status alerts */
    .status-panel {
        border-radius: 8px;
        padding: 1.25rem 1.5rem;
        margin: 1.25rem 0;
        position: relative;
    }

    .status-panel.valid {
        background-color: var(--status-valid-bg);
        border: 1px solid var(--status-valid-border);
        color: var(--status-valid-text);
    }

    .status-panel.expired {
        background-color: var(--status-expired-bg);
        border: 1px solid var(--status-expired-border);
        color: var(--status-expired-text);
    }

    .status-panel.tampered {
        background-color: var(--status-tampered-bg);
        border: 1px solid var(--status-tampered-border);
        color: var(--status-tampered-text);
    }

    .status-panel.untrusted {
        background-color: var(--status-untrusted-bg);
        border: 1px solid var(--status-untrusted-border);
        color: var(--status-untrusted-text);
    }

    .status-panel.malformed {
        background-color: var(--status-malformed-bg);
        border: 1px solid var(--status-malformed-border);
        color: var(--status-malformed-text);
    }

    .status-chip {
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        font-weight: 700;
        padding: 0.25rem 0.65rem;
        border-radius: 4px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }

    .status-chip.valid { background: #064e3b; color: #34d399; border: 1px solid #10b981; }
    .status-chip.expired { background: #451a03; color: #fbbf24; border: 1px solid #f59e0b; }
    .status-chip.tampered { background: #450a0a; color: #f87171; border: 1px solid #ef4444; }
    .status-chip.untrusted { background: #3b0764; color: #c084fc; border: 1px solid #a855f7; }
    .status-chip.malformed { background: #1e293b; color: #cbd5e1; border: 1px solid #64748b; }

    /* Metadata Table Grid */
    .metadata-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: 0.75rem;
        margin-top: 1rem;
    }

    .metadata-item {
        background: #090e1a;
        border: 1px solid var(--border-subtle);
        border-radius: 6px;
        padding: 0.75rem 1rem;
    }

    .metadata-label {
        font-size: 0.7rem;
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.25rem;
    }

    .metadata-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: var(--text-white);
        word-break: break-all;
    }

    /* Hero Banner */
    .sentinel-hero {
        background: linear-gradient(135deg, #0d1527 0%, #080d1a 100%);
        border: 1px solid var(--border-subtle);
        border-top: 2px solid var(--cyan-core);
        border-radius: 8px;
        padding: 2rem 2.25rem;
        margin-bottom: 1.75rem;
    }

    .sentinel-hero-title {
        font-size: 1.85rem;
        font-weight: 700;
        letter-spacing: -0.02em;
        color: #ffffff;
        margin-bottom: 0.5rem;
    }

    .sentinel-hero-desc {
        color: var(--text-secondary);
        font-size: 0.95rem;
        line-height: 1.5;
        max-width: 720px;
        margin-bottom: 0;
    }

    /* Buttons override */
    button[kind="primary"], .stButton > button {
        border-radius: 6px !important;
        font-weight: 600 !important;
        letter-spacing: 0.02em !important;
        transition: all 0.15s ease !important;
    }

    button[kind="primary"] {
        background: #00d2ff !important;
        color: #050b14 !important;
        border: 1px solid #00f0ff !important;
    }

    button[kind="primary"]:hover {
        background: #38bdf8 !important;
        box-shadow: 0 0 14px rgba(0, 240, 255, 0.35) !important;
    }

    .stButton > button:not([kind="primary"]) {
        background: #0c1424 !important;
        border: 1px solid var(--border-subtle) !important;
        color: var(--text-white) !important;
    }

    .stButton > button:not([kind="primary"]):hover {
        background: #142038 !important;
        border-color: var(--border-accent) !important;
    }

    /* Form Inputs */
    .stTextInput input, .stSelectbox select, .stSlider {
        background-color: #090e1a !important;
        border: 1px solid var(--border-subtle) !important;
        color: var(--text-white) !important;
        border-radius: 6px !important;
    }

    .stTextInput input:focus {
        border-color: var(--cyan-core) !important;
        box-shadow: 0 0 0 1px var(--cyan-core) !important;
    }

    /* File uploader dropzone */
    [data-testid="stFileUploader"] {
        background-color: #0a0f1d;
        border: 1px dashed var(--border-accent);
        border-radius: 8px;
        padding: 1rem;
    }

    /* Expanders */
    [data-testid="stExpander"] {
        background-color: #0c1424 !important;
        border: 1px solid var(--border-subtle) !important;
        border-radius: 6px !important;
    }

    /* Subtle divider */
    hr {
        border-color: var(--border-subtle) !important;
        margin: 1.25rem 0 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Sidebar UI: Product Branding, Navigation, CA Controls
# ---------------------------------------------------------------------------
with st.sidebar:
    # Product Brand Block
    st.markdown(
        """
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <svg width="30" height="30" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 6V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V6L12 2Z"
                      stroke="#00f0ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                      fill="rgba(0, 240, 255, 0.08)"/>
                <circle cx="12" cy="10" r="2.5" stroke="#38bdf8" stroke-width="1.8"/>
                <path d="M12 12.5V16.5M10.5 15H13.5" stroke="#38bdf8" stroke-width="1.8" stroke-linecap="round"/>
            </svg>
            <div>
                <div style="font-weight: 800; font-size: 1.1rem; letter-spacing: 0.06em; color: #ffffff;">SENTINEL PKI</div>
                <div style="font-size: 0.65rem; font-weight: 600; letter-spacing: 0.08em; color: #00f0ff; text-transform: uppercase;">Assurance Console</div>
            </div>
        </div>
        <div style="display: inline-flex; align-items: center; gap: 6px; background: rgba(0, 240, 255, 0.08); border: 1px solid rgba(0, 240, 255, 0.25); border-radius: 4px; padding: 3px 8px; margin-bottom: 18px; font-size: 0.68rem; font-family: 'JetBrains Mono', monospace; color: #38bdf8;">
            <span style="display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: #00f0ff;"></span>
            LOCAL EDUCATIONAL PKI
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Navigation Selection
    nav_options = [
        "Dashboard",
        "Issue Certificate",
        "Verify Certificate",
        "Quick Demo",
        "About PKI",
    ]

    current_idx = (
        nav_options.index(st.session_state.current_page)
        if st.session_state.current_page in nav_options
        else 0
    )

    selected_page = st.radio(
        "Console Navigation",
        nav_options,
        index=current_idx,
        key="nav_selection",
        label_visibility="collapsed",
    )

    # Synchronize navigation state
    if selected_page != st.session_state.current_page:
        st.session_state.current_page = selected_page
        st.rerun()

    st.markdown("---")

    # Trust Anchor Telemetry Panel
    ca_details = _certificate_details(st.session_state.ca_certificate)
    st.markdown(
        f"""
        <div style="margin-bottom: 0.75rem;">
            <div style="font-size: 0.7rem; font-weight: 600; text-transform: uppercase; color: #64748b; letter-spacing: 0.06em; margin-bottom: 0.25rem;">Active Trust Anchor</div>
            <div style="font-size: 0.82rem; font-weight: 600; color: #f8fafc;">Demo Root Authority</div>
            <div style="font-size: 0.72rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">RSA 2048-bit · SHA-256</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ca_pem_bytes = certificate_pem(st.session_state.ca_certificate)
    st.download_button(
        "Export CA Certificate (PEM)",
        data=ca_pem_bytes,
        file_name="sentinel-ca-cert.pem",
        mime="application/x-pem-file",
        use_container_width=True,
        help="Download the active in-memory CA public trust anchor certificate.",
    )

    if st.button("Rotate Demo CA Keypair", use_container_width=True):
        st.session_state.ca_key, st.session_state.ca_certificate = generate_demo_ca()
        st.session_state.pop("student_certificate", None)
        st.success("New Root CA keypair minted for current session.")
        st.rerun()

    st.markdown(
        """
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid #1e293b; border-radius: 6px; padding: 0.7rem 0.8rem; margin-top: 1rem; font-size: 0.7rem; color: #94a3b8; line-height: 1.4;">
            <strong style="color: #cbd5e1;">Cryptographic Notice:</strong>
            Private keys are maintained strictly in volatile process memory and never serialized to storage or exposed in telemetry.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# VIEW: Dashboard
# ---------------------------------------------------------------------------
if st.session_state.current_page == "Dashboard":
    # Hero Unit
    st.markdown(
        """
        <div class="sentinel-hero">
            <div class="sentinel-hero-title">Certificate Trust, Verified.</div>
            <div class="sentinel-hero-desc">
                Sentinel PKI provides automated cryptographic integrity verification, X.509 lifecycle
                management, and root-of-trust assurance for digital identity certificates in an air-gapped demo environment.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Primary Actions Bar
    act_col1, act_col2, act_col3 = st.columns([1, 1, 1.5])
    with act_col1:
        if st.button("Verify a Certificate", type="primary", use_container_width=True):
            st.session_state.current_page = "Verify Certificate"
            st.rerun()
    with act_col2:
        if st.button("Issue New Certificate", use_container_width=True):
            st.session_state.current_page = "Issue Certificate"
            st.rerun()
    with act_col3:
        if st.button("Launch Lifecycle Demo", use_container_width=True):
            st.session_state.current_page = "Quick Demo"
            st.rerun()

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Console Telemetry Panels
    col_ca, col_verif, col_issue = st.columns(3)

    # Panel 1: CA Root Status
    with col_ca:
        st.markdown(
            f"""
            <div class="sentinel-card">
                <div class="sentinel-card-header">
                    <span class="sentinel-card-title">Demo Root CA</span>
                    <span class="status-chip valid">ONLINE</span>
                </div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.5rem;">Subject DN:</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #f8fafc; background: #080d1a; padding: 6px 8px; border-radius: 4px; border: 1px solid #192644; word-break: break-all; margin-bottom: 0.75rem;">
                    {ca_details['subject']}
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #94a3b8; border-top: 1px solid #192644; padding-top: 0.5rem;">
                    <span>Algorithm:</span>
                    <span style="color: #f8fafc; font-family: 'JetBrains Mono', monospace;">RSA 2048-bit</span>
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 0.75rem; color: #94a3b8; margin-top: 0.35rem;">
                    <span>Validity Window:</span>
                    <span style="color: #f8fafc; font-family: 'JetBrains Mono', monospace;">{ca_details['days_remaining']} days</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Panel 2: Real Verification Activity
    with col_verif:
        verif_count = len(st.session_state.verification_history)
        last_verif = (
            st.session_state.verification_history[-1]
            if verif_count > 0
            else None
        )
        last_status_chip = (
            f"<span class='status-chip {last_verif['status'].lower()}'>{last_verif['status'].upper()}</span>"
            if last_verif
            else "<span style='color: #64748b; font-size: 0.75rem;'>None this session</span>"
        )
        st.markdown(
            f"""
            <div class="sentinel-card">
                <div class="sentinel-card-header">
                    <span class="sentinel-card-title">Verification Engine</span>
                    {last_status_chip}
                </div>
                <div style="display: flex; align-items: baseline; gap: 8px; margin-bottom: 0.5rem;">
                    <span style="font-size: 2rem; font-weight: 700; color: #f8fafc;">{verif_count}</span>
                    <span style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Evaluations Logged</span>
                </div>
                <div style="font-size: 0.75rem; color: #94a3b8; border-top: 1px solid #192644; padding-top: 0.5rem;">
                    Last Evaluation Target:
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #f8fafc; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 0.2rem;">
                    {last_verif['subject'] if last_verif else 'No verification executed yet'}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Panel 3: Real Issuance Activity
    with col_issue:
        issued_count = len(st.session_state.issued_certs)
        last_issued = (
            st.session_state.issued_certs[-1] if issued_count > 0 else None
        )
        st.markdown(
            f"""
            <div class="sentinel-card">
                <div class="sentinel-card-header">
                    <span class="sentinel-card-title">Identity Issuance</span>
                    <span class="status-chip valid">READY</span>
                </div>
                <div style="display: flex; align-items: baseline; gap: 8px; margin-bottom: 0.5rem;">
                    <span style="font-size: 2rem; font-weight: 700; color: #f8fafc;">{issued_count}</span>
                    <span style="font-size: 0.75rem; color: #64748b; text-transform: uppercase;">Certificates Minted</span>
                </div>
                <div style="font-size: 0.75rem; color: #94a3b8; border-top: 1px solid #192644; padding-top: 0.5rem;">
                    Most Recent Subject:
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #f8fafc; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 0.2rem;">
                    {last_issued['name'] if last_issued else 'None issued this session'}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Real Activity Audit Stream
    st.markdown("### Session Cryptographic Activity Log")
    if not st.session_state.verification_history and not st.session_state.issued_certs:
        st.markdown(
            """
            <div style="background: #090e1a; border: 1px dashed #1e293b; border-radius: 6px; padding: 1.5rem; text-align: center; color: #64748b; font-size: 0.85rem;">
                No telemetry recorded for this browser session. Navigate to <strong>Verify Certificate</strong> to inspect an X.509 file or <strong>Issue Certificate</strong> to mint a new credential.
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        # Display real session events
        events = []
        for v in st.session_state.verification_history:
            events.append({
                "type": "VERIFICATION",
                "time": v.get("time", "Current Session"),
                "status": v["status"],
                "subject": v["subject"] or "Unknown Subject",
                "message": v["message"],
            })
        for i in st.session_state.issued_certs:
            events.append({
                "type": "ISSUANCE",
                "time": i.get("time", "Current Session"),
                "status": "ISSUED",
                "subject": i["name"],
                "message": f"Minted X.509 certificate valid for {i['days']} days.",
            })

        for ev in reversed(events):
            chip_class = ev["status"].lower() if ev["status"].lower() in ["valid", "expired", "tampered", "untrusted", "malformed"] else "valid"
            st.markdown(
                f"""
                <div style="display: flex; align-items: center; justify-content: space-between; background: #0c1424; border: 1px solid #192644; border-radius: 6px; padding: 0.65rem 1rem; margin-bottom: 0.5rem; font-size: 0.82rem;">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #00f0ff; font-weight: 600;">{ev['type']}</span>
                        <span style="color: #f8fafc; font-weight: 500;">{ev['subject']}</span>
                        <span style="color: #64748b; font-size: 0.75rem;">— {ev['message']}</span>
                    </div>
                    <span class="status-chip {chip_class}">{ev['status']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# VIEW: Issue Certificate
# ---------------------------------------------------------------------------
elif st.session_state.current_page == "Issue Certificate":
    st.markdown("## Issue X.509 Student Certificate")
    st.markdown(
        "Generate a client identity certificate signed by the active Sentinel Root CA. "
        "The certificate is minted with standard PKI parameters (`BasicConstraints: ca=False`, `KeyUsage: Digital Signature, Key Encipherment`)."
    )

    col_form, col_specs = st.columns([1.5, 1])

    with col_form:
        with st.form("issue_credential_form"):
            student_name = st.text_input(
                "Subject Common Name (CN)",
                max_chars=64,
                placeholder="e.g. Asha Sharma",
                help="Enter a unique student name or entity identifier (1 to 64 characters).",
            )
            validity_days = st.slider(
                "Validity Period (Days)",
                min_value=1,
                max_value=365,
                value=90,
                help="Duration in days for which the certificate remains cryptographically valid.",
            )
            submit_issue = st.form_submit_button(
                "Mint & Sign Certificate", type="primary", use_container_width=True
            )

        if submit_issue:
            clean_name = student_name.strip()
            if not clean_name:
                st.error("Validation Error: Subject Common Name cannot be empty or blank.")
            else:
                try:
                    _, new_cert = issue_student_certificate(
                        st.session_state.ca_key,
                        st.session_state.ca_certificate,
                        clean_name,
                        validity_days,
                    )
                    st.session_state.student_certificate = new_cert
                    st.session_state.issued_certs.append({
                        "name": clean_name,
                        "days": validity_days,
                        "time": datetime.now(UTC).strftime("%H:%M:%S UTC"),
                    })
                    st.success(
                        f"Cryptographic certificate minted for CN={clean_name} (valid for {validity_days} days)."
                    )
                except ValueError as exc:
                    st.error(f"Issuance rejected: {exc}")

    with col_specs:
        st.markdown(
            """
            <div class="sentinel-card">
                <div class="sentinel-card-title" style="margin-bottom: 0.75rem;">Cryptographic Profile</div>
                <div style="font-size: 0.75rem; color: #94a3b8; display: flex; flex-direction: column; gap: 0.5rem;">
                    <div><strong>Algorithm:</strong> RSA 2048-bit (e=65537)</div>
                    <div><strong>Signature Digest:</strong> SHA-256 with PKCS#1 v1.5</div>
                    <div><strong>Issuer:</strong> Active Demo Root CA</div>
                    <div><strong>Country:</strong> IN</div>
                    <div><strong>Organization:</strong> Student Certificate</div>
                    <div><strong>Key Usage:</strong> Digital Signature, Key Encipherment</div>
                    <div><strong>Basic Constraints:</strong> CA=FALSE (End-Entity)</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Certificate Details & Download Section
    if "student_certificate" in st.session_state:
        issued_cert = st.session_state.student_certificate
        cert_pem = certificate_pem(issued_cert)
        details = _certificate_details(issued_cert)

        st.markdown("---")
        st.markdown("### Issued Credential Metadata")

        st.markdown(
            f"""
            <div class="metadata-grid">
                <div class="metadata-item">
                    <div class="metadata-label">Subject DN</div>
                    <div class="metadata-value">{details['subject']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Issuer DN</div>
                    <div class="metadata-value">{details['issuer']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Serial Number (Hex)</div>
                    <div class="metadata-value">{details['serial_number']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Valid From</div>
                    <div class="metadata-value">{details['valid_from']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Valid Until</div>
                    <div class="metadata-value">{details['valid_until']}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Public Key</div>
                    <div class="metadata-value">{details['public_key_algorithm']} ({details['public_key_bits']} bits)</div>
                </div>
            </div>
            <div class="metadata-item" style="margin-top: 0.75rem;">
                <div class="metadata-label">SHA-256 Fingerprint</div>
                <div class="metadata-value" style="color: #00f0ff;">{details['fingerprint_sha256']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        dl_col1, dl_col2 = st.columns([1, 2])
        with dl_col1:
            st.download_button(
                "Export Certificate (.pem)",
                data=cert_pem,
                file_name="sentinel-student-cert.pem",
                mime="application/x-pem-file",
                use_container_width=True,
            )

        with st.expander("Inspect Raw PEM Serialization"):
            st.code(cert_pem.decode("utf-8"), language="text")


# ---------------------------------------------------------------------------
# VIEW: Verify Certificate
# ---------------------------------------------------------------------------
elif st.session_state.current_page == "Verify Certificate":
    st.markdown("## Certificate Verification Workspace")
    st.markdown(
        "Execute end-to-end cryptographic integrity verification on an uploaded X.509 certificate. "
        "The verification engine strictly evaluates temporal validity, CA chain authority, and RSA digital signatures."
    )

    up_col1, up_col2 = st.columns(2)
    with up_col1:
        target_file = st.file_uploader(
            "Upload Target Certificate (PEM or DER)",
            type=["pem", "cer", "crt", "der"],
            key="verify_target_file",
            help=f"Accepts X.509 certificates up to {MAX_CERT_BYTES // 1000} KB.",
        )
    with up_col2:
        trust_anchor_file = st.file_uploader(
            "Custom Root CA Anchor (Optional)",
            type=["pem", "cer", "crt", "der"],
            key="verify_ca_file",
            help="Defaults to active Sentinel Demo CA if omitted.",
        )

    verify_trigger = st.button(
        "Execute Cryptographic Verification",
        type="primary",
        disabled=(target_file is None),
        use_container_width=True,
    )

    if verify_trigger and target_file is not None:
        target_bytes = target_file.getvalue()
        ca_bytes = (
            trust_anchor_file.getvalue()
            if trust_anchor_file
            else certificate_pem(st.session_state.ca_certificate)
        )

        result = verify_certificate(target_bytes, ca_bytes)

        # Log to real session history
        st.session_state.verification_history.append({
            "status": result.status.upper(),
            "subject": result.subject or "Unparseable",
            "message": result.message,
            "time": datetime.now(UTC).strftime("%H:%M:%S UTC"),
        })

        # Visual Result Presentation
        status_key = result.status.lower()
        badge_class = status_key if status_key in ["valid", "expired", "tampered", "untrusted", "malformed"] else "malformed"

        diagnostic_reasons = {
            "valid": (
                "Cryptographic signature check passed via RSA PKCS#1 v1.5. "
                "The certificate issuer matches the designated trust anchor, BasicConstraints CA capability is verified, "
                "and the temporal evaluation falls squarely within active validity dates."
            ),
            "expired": (
                "The certificate has failed temporal boundary evaluation. The current verification timestamp (UTC) "
                "is outside the certificate's notValidBefore or notValidAfter constraints."
            ),
            "tampered": (
                "Cryptographic signature verification failed. The RSA signature over the To-Be-Signed (TBS) bytes "
                "does not match the CA's public key, indicating payload mutation or bit-level tampering."
            ),
            "untrusted": (
                "Chain-of-trust verification failed. The certificate's Issuer DN does not match the designated CA Subject DN, "
                "the issuing authority certificate lacks the BasicConstraints CA flag, or the CA itself is expired."
            ),
            "malformed": (
                "Input parsing failed. The supplied byte stream could not be decoded as valid ASN.1 DER or PEM X.509 structure, "
                "or exceeded the enforced upload size ceiling."
            ),
        }

        st.markdown(
            f"""
            <div class="status-panel {badge_class}">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                    <span class="status-chip {badge_class}">VERDICT: {result.status.upper()}</span>
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #94a3b8;">
                        TIMESTAMP: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </span>
                </div>
                <div style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.35rem;">
                    {result.message}
                </div>
                <div style="font-size: 0.85rem; line-height: 1.45; opacity: 0.95;">
                    {diagnostic_reasons.get(status_key, result.message)}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # Verification Pipeline Stage Breakdown
        st.markdown("#### Cryptographic Assurance Checklist")
        chk_parse = "PASS" if status_key != "malformed" else "FAIL"
        chk_dates = "PASS" if status_key not in ["expired", "malformed"] else ("FAIL" if status_key == "expired" else "SKIP")
        chk_issuer = "PASS" if status_key not in ["untrusted", "malformed"] else ("FAIL" if status_key == "untrusted" else "SKIP")
        chk_sig = "PASS" if status_key == "valid" else ("FAIL" if status_key == "tampered" else "SKIP")

        pipe_col1, pipe_col2, pipe_col3, pipe_col4 = st.columns(4)
        for col, title, state in [
            (pipe_col1, "1. Structure & ASN.1", chk_parse),
            (pipe_col2, "2. Temporal Bounds", chk_dates),
            (pipe_col3, "3. Chain & CA Flag", chk_issuer),
            (pipe_col4, "4. RSA Signature", chk_sig),
        ]:
            col_class = "valid" if state == "PASS" else ("tampered" if state == "FAIL" else "malformed")
            with col:
                st.markdown(
                    f"""
                    <div style="background: #090e1a; border: 1px solid #192644; border-radius: 6px; padding: 0.75rem; text-align: center;">
                        <div style="font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 0.25rem;">{title}</div>
                        <span class="status-chip {col_class}">{state}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        # Certificate Details Grid
        if result.subject:
            st.markdown("---")
            st.markdown("#### Certificate Attributes")
            st.markdown(
                f"""
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <div class="metadata-label">Subject DN</div>
                        <div class="metadata-value">{result.subject}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Issuer DN</div>
                        <div class="metadata-value">{result.issuer}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Serial Number (Hex)</div>
                        <div class="metadata-value">{result.serial_number}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Valid From</div>
                        <div class="metadata-value">{result.valid_from}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Valid Until</div>
                        <div class="metadata-value">{result.valid_until}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Days Remaining</div>
                        <div class="metadata-value">{result.days_remaining if result.days_remaining is not None else 'N/A'}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Public Key Spec</div>
                        <div class="metadata-value">{result.public_key_algorithm} ({result.public_key_bits} bits)</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">SHA-256 Digest</div>
                        <div class="metadata-value" style="color: #00f0ff;">{result.fingerprint_sha256}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Verification Report Export
            report_data = {
                "verdict": result.status.upper(),
                "diagnostic_message": result.message,
                "verified_at": datetime.now(UTC).isoformat(),
                "certificate_metadata": {
                    "subject": result.subject,
                    "issuer": result.issuer,
                    "serial_number": result.serial_number,
                    "valid_from": result.valid_from,
                    "valid_until": result.valid_until,
                    "days_remaining": result.days_remaining,
                    "public_key_algorithm": result.public_key_algorithm,
                    "public_key_bits": result.public_key_bits,
                    "fingerprint_sha256": result.fingerprint_sha256,
                },
            }

            st.download_button(
                "Export Verification Report (JSON)",
                data=json.dumps(report_data, indent=2),
                file_name="sentinel-verification-report.json",
                mime="application/json",
            )


# ---------------------------------------------------------------------------
# VIEW: Quick Demo
# ---------------------------------------------------------------------------
elif st.session_state.current_page == "Quick Demo":
    st.markdown("## Automated PKI Lifecycle Demonstration")
    st.markdown(
        "Execute a single-step cryptographic demonstration. Sentinel PKI will mint an ephemeral "
        "X.509 student certificate signed by the active Root CA and immediately dispatch it to the verification pipeline."
    )

    demo_c1, demo_c2 = st.columns([1.5, 1])
    with demo_c1:
        demo_student = st.text_input("Demo Candidate Name", value="Alex Rivera", max_chars=64)
    with demo_c2:
        demo_days = st.slider("Demo Validity (Days)", 1, 365, 30)

    demo_btn = st.button("Execute Demonstration Pipeline", type="primary", use_container_width=True)

    if demo_btn:
        try:
            # Stage 1: Issuance
            _, demo_cert = issue_student_certificate(
                st.session_state.ca_key,
                st.session_state.ca_certificate,
                demo_student,
                demo_days,
            )
            demo_pem = certificate_pem(demo_cert)
            ca_pem = certificate_pem(st.session_state.ca_certificate)

            # Stage 2: Verification
            result = verify_certificate(demo_pem, ca_pem)

            # Log to session
            st.session_state.issued_certs.append({
                "name": demo_student,
                "days": demo_days,
                "time": datetime.now(UTC).strftime("%H:%M:%S UTC"),
            })
            st.session_state.verification_history.append({
                "status": result.status.upper(),
                "subject": result.subject,
                "message": result.message,
                "time": datetime.now(UTC).strftime("%H:%M:%S UTC"),
            })

            st.markdown(
                f"""
                <div class="status-panel valid">
                    <div style="font-weight: 700; font-size: 1.1rem; margin-bottom: 0.25rem;">
                        Demonstration Pipeline Completed: STATUS VALID
                    </div>
                    <div style="font-size: 0.85rem;">
                        Successfully generated RSA keypair, minted X.509 certificate signed by Demo Root CA,
                        and verified cryptographic integrity with 100% assurance.
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            res_c1, res_c2 = st.columns(2)
            with res_c1:
                st.markdown(
                    f"""
                    <div class="sentinel-card">
                        <div class="sentinel-card-header">
                            <span class="sentinel-card-title">1. Issuance Manifest</span>
                            <span class="status-chip valid">MINTED</span>
                        </div>
                        <div style="font-size: 0.78rem; color: #94a3b8; display: flex; flex-direction: column; gap: 0.4rem;">
                            <div><strong>Subject:</strong> {result.subject}</div>
                            <div><strong>Issuer:</strong> {result.issuer}</div>
                            <div><strong>Serial (Hex):</strong> {result.serial_number}</div>
                            <div><strong>Validity:</strong> {result.valid_from} to {result.valid_until}</div>
                            <div><strong>Days Remaining:</strong> {result.days_remaining}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with res_c2:
                st.markdown(
                    f"""
                    <div class="sentinel-card">
                        <div class="sentinel-card-header">
                            <span class="sentinel-card-title">2. Verification Verdict</span>
                            <span class="status-chip valid">VALID</span>
                        </div>
                        <div style="font-size: 0.78rem; color: #94a3b8; display: flex; flex-direction: column; gap: 0.4rem;">
                            <div><strong>Algorithm:</strong> {result.public_key_algorithm} {result.public_key_bits}-bit</div>
                            <div><strong>Signature Scheme:</strong> RSA PKCS#1 v1.5 / SHA-256</div>
                            <div><strong>BasicConstraints:</strong> End-Entity (ca=False)</div>
                            <div><strong>SHA-256 Digest:</strong></div>
                            <div style="color: #00f0ff; font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; word-break: break-all;">
                                {result.fingerprint_sha256}
                            </div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            st.download_button(
                "Download Minted Demo Certificate (.pem)",
                data=demo_pem,
                file_name=f"demo-{demo_student.lower().replace(' ', '-')}.pem",
                mime="application/x-pem-file",
            )

        except ValueError as exc:
            st.error(f"Demonstration pipeline error: {exc}")


# ---------------------------------------------------------------------------
# VIEW: About PKI
# ---------------------------------------------------------------------------
elif st.session_state.current_page == "About PKI":
    st.markdown("## Public-Key Infrastructure Principles")
    st.markdown(
        "Public-Key Infrastructure (PKI) underpins the security of modern internet communication, "
        "enabling identity authentication, data integrity, and non-repudiation across distributed networks."
    )

    tab_arch, tab_verif, tab_scope = st.tabs([
        "Core Primitives",
        "Verification Architecture",
        "Educational Scope & Boundaries",
    ])

    with tab_arch:
        st.markdown(
            """
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-top: 0.75rem;">
                <div class="sentinel-card">
                    <div class="sentinel-card-title">1. Asymmetric Cryptography (RSA)</div>
                    <div style="font-size: 0.8rem; color: #94a3b8; line-height: 1.5; margin-top: 0.5rem;">
                        RSA pairs a public key (distributed openly) with a mathematically linked private key (kept secret).
                        Data encrypted or signed with one key can only be decrypted or verified by the other.
                    </div>
                </div>
                <div class="sentinel-card">
                    <div class="sentinel-card-title">2. Certificate Authority (CA)</div>
                    <div style="font-size: 0.8rem; color: #94a3b8; line-height: 1.5; margin-top: 0.5rem;">
                        The CA acts as an authoritative, trusted third party. By signing digital certificates with its private key,
                        the CA vouches that a specific public key belongs to the entity named in the certificate.
                    </div>
                </div>
                <div class="sentinel-card">
                    <div class="sentinel-card-title">3. X.509 v3 Digital Certificates</div>
                    <div style="font-size: 0.8rem; color: #94a3b8; line-height: 1.5; margin-top: 0.5rem;">
                        Standardized ASN.1 structure binding an identity (Subject DN) to a Public Key, signed by an Issuer.
                        Includes crucial extensions such as <code>BasicConstraints</code> and <code>KeyUsage</code>.
                    </div>
                </div>
                <div class="sentinel-card">
                    <div class="sentinel-card-title">4. Digital Signatures (SHA-256)</div>
                    <div style="font-size: 0.8rem; color: #94a3b8; line-height: 1.5; margin-top: 0.5rem;">
                        A cryptographic hash of the certificate body is signed using the CA's private key.
                        Any alteration of a single bit renders the signature invalid upon verification.
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with tab_verif:
        st.markdown(
            """
            <div class="sentinel-card">
                <div class="sentinel-card-title" style="margin-bottom: 0.75rem;">Sentinel 7-Stage Cryptographic Verification Flow</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #94a3b8; background: #080d1a; padding: 1.25rem; border-radius: 6px; border: 1px solid #192644; line-height: 1.6;">
[Applicant Entity] ─── (Generates RSA-2048 Keypair) ───▶ [Identity Request]<br>
                                                               │<br>
                                                               ▼<br>
[Sentinel Root CA] ◀─── (Signs TBS Payload with CA Secret) ─── [Mint Certificate]<br>
         │<br>
         ▼ (Public CA Cert exported as Trust Anchor)<br>
┌────────────────────────────────────────────────────────────────────────┐<br>
│                      SENTINEL VERIFICATION ENGINE                      │<br>
├────────────────────────────────────────────────────────────────────────┤<br>
│ [1] ASN.1 Structure: Parse PEM/DER encoding (enforces 1 MB limit)      │<br>
│ [2] Leaf Temporal Bounds: NotBefore &lt;= Timestamp &lt;= NotAfter (UTC)    │<br>
│ [3] CA Temporal Bounds: Ensure designated CA is currently valid        │<br>
│ [4] Issuer Alignment: Match Leaf Issuer DN == CA Subject DN            │<br>
│ [5] Authority Constraints: Confirm CA BasicConstraints (ca=True)       │<br>
│ [6] Key Architecture: Verify CA Public Key type is RSA-2048            │<br>
│ [7] Mathematical Signature: Verify PKCS#1 v1.5 RSA Digest over TBS     │<br>
└───────────────────────────────────┬────────────────────────────────────┘<br>
                                    ▼<br>
      [ VALID | EXPIRED | TAMPERED | UNTRUSTED | MALFORMED ]
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            """
            | Verdict State | Cryptographic Rationale |
            | :--- | :--- |
            | <span class="status-chip valid">VALID</span> | Mathematical signature holds, issuer matches trust anchor, temporal window active. |
            | <span class="status-chip expired">EXPIRED</span> | Evaluation timestamp lies outside the certificate's designated validity window. |
            | <span class="status-chip tampered">TAMPERED</span> | Cryptographic RSA signature check failed. Certificate bytes have been altered. |
            | <span class="status-chip untrusted">UNTRUSTED</span> | Issuer mismatch, issuing certificate lacks CA capability, or CA expired. |
            | <span class="status-chip malformed">MALFORMED</span> | Data could not be parsed as valid ASN.1 PEM or DER structure. |
            """,
            unsafe_allow_html=True,
        )

    with tab_scope:
        st.markdown(
            """
            <div class="sentinel-card">
                <div class="sentinel-card-title">Educational Boundaries & Operational Assumptions</div>
                <div style="font-size: 0.82rem; color: #94a3b8; line-height: 1.6; margin-top: 0.5rem;">
                    Sentinel PKI is engineered specifically as a collegiate educational demonstration for
                    <strong>Cryptography and Network Security — Module 3</strong>.
                    The following enterprise features are deliberately omitted from this reference implementation:
                    <ul style="margin-top: 0.5rem; padding-left: 1.25rem;">
                        <li><strong>Revocation Infrastructure:</strong> No Certificate Revocation Lists (CRLs) or Online Certificate Status Protocol (OCSP) responders.</li>
                        <li><strong>Multi-Tier Hierarchies:</strong> Single-tier direct CA-to-Leaf verification; intermediate chains are not traversed.</li>
                        <li><strong>Key Persistence:</strong> Root CA private keys exist solely in volatile process RAM and rotate on server restart.</li>
                        <li><strong>Access Controls:</strong> Role-based access control (RBAC) and certificate request authentication are not enforced.</li>
                        <li><strong>Hardware Protection:</strong> No Hardware Security Module (HSM) or PKCS#11 integration.</li>
                    </ul>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Global Footer
# ---------------------------------------------------------------------------
st.markdown("---")
st.markdown(
    """
    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.72rem; color: #64748b; font-family: 'JetBrains Mono', monospace;">
        <div>SENTINEL PKI // SEC-CONSOLE v2.4</div>
        <div>CNS MODULE 3: PUBLIC-KEY CRYPTOGRAPHY & CERTIFICATES</div>
        <div>AIR-GAPPED DEMO ENVIRONMENT</div>
    </div>
    """,
    unsafe_allow_html=True,
)
