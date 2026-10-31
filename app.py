from __future__ import annotations

import html
import json

import streamlit as st
from analyzer import analyze_message, check_ollama, MODEL, OLLAMA_BASE_URL, ScamShieldError

st.set_page_config(
    page_title="ScamShield AI | Message Safety",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.stApp { background: #0b1220; color: #e8eef8; }
[data-testid="stSidebar"] { background: #101a2c; border-right: 1px solid #25334a; }
.block-container { padding-top: 2rem; max-width: 1240px; }
h1, h2, h3 { font-family: 'Space Grotesk', sans-serif !important; color: #f4f7fb; }
.hero { padding: 1.5rem 1.7rem; border: 1px solid #263954; border-radius: 18px;
        background: linear-gradient(120deg, #14243b 0%, #101a2c 70%); margin-bottom: 1.2rem; }
.eyebrow { color: #61d7c4; font-weight: 700; letter-spacing: .13em; font-size: .75rem; }
.subtle { color: #a8b7cb; }
.panel { background: #111e31; border: 1px solid #293b55; border-radius: 14px; padding: 1rem 1.15rem; margin: .5rem 0 1rem; }
.quote { border-left: 3px solid #f2b84b; padding: .55rem .8rem; background: #1a2638; border-radius: 0 8px 8px 0; margin: .45rem 0; color: #f7e7c1; }
.small { color: #9eb0c7; font-size: .85rem; }
.gauge { border-radius: 14px; padding: 1.1rem 1.3rem; text-align: center; margin-bottom: .8rem; border: 2px solid; }
.gauge h2 { margin: 0; }
.gauge-Low { background: #0d2e24; border-color: #10b981; color: #a7f3d0; }
.gauge-Moderate { background: #3a2a08; border-color: #f59e0b; color: #fde68a; }
.gauge-High { background: #3d1f0a; border-color: #f97316; color: #fdba74; }
.gauge-Critical { background: #3d0f0f; border-color: #ef4444; color: #fca5a5; }
.gauge-Unclear { background: #1f2937; border-color: #9ca3af; color: #d1d5db; }
div.stButton > button[kind="primary"] { background: #18a895; border: 0; color: #061b1a; font-weight: 700; border-radius: 9px; }
div.stButton > button[kind="primary"]:hover { background: #42c8b5; }
[data-testid="stMetric"] { background: #111e31; border: 1px solid #293b55; padding: 1rem; border-radius: 12px; }
hr { border-color: #293b55; }
</style>
""", unsafe_allow_html=True)

@st.cache_data(ttl=30)
def cached_health():
    return check_ollama()


with st.sidebar:
    st.markdown("## 🛡️ ScamShield AI")
    st.caption("Detect. Understand. Stay Safe.")
    st.divider()
    page = st.radio("WORKSPACE", ["Message scanner", "Scam catalogue", "India cyber help"], label_visibility="collapsed")
    st.divider()
    st.markdown("**AI engine**")
    st.code(f"{MODEL}\nOllama local API", language="text")
    st.caption(f"Endpoint: {OLLAMA_BASE_URL}")
    ok, health = cached_health()
    st.markdown(("🟢 " if ok else "🟠 ") + health)
    st.divider()
    st.markdown("**Accessibility**")
    large_text = st.checkbox("Large text")
    high_contrast = st.checkbox("High contrast")
    st.divider()
    st.caption("Privacy note: message text is sent to the configured Ollama server for analysis. Do not submit passwords, OTPs, or unnecessary personal information.")

if large_text:
    st.markdown("<style>.stApp p, .stApp li, .stApp label, .panel, .quote { font-size: 1.2rem !important; }</style>", unsafe_allow_html=True)
if high_contrast:
    st.markdown("<style>.panel, .quote, .hero, [data-testid='stMetric'], textarea, .gauge { border: 2px solid #ffffff !important; } .subtle, .small { color: #ffffff !important; }</style>", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
  <div class="eyebrow">AI-POWERED MESSAGE SAFETY</div>
  <h1 style="font-size:2.55rem;margin:.25rem 0;">ScamShield <span style="color:#55d6c2;">AI</span></h1>
  <div class="subtle">Understand suspicious messages before you act. Clear evidence, cautious assessments, safer next steps.</div>
</div>
""", unsafe_allow_html=True)

if page == "Message scanner":
    left, right = st.columns([1.35, .65], gap="large")
    with left:
        st.subheader("Message scanner")
        st.markdown('<p class="subtle">Paste an SMS, WhatsApp message, email, or other text. Gemma reviews the content for potential warning signs.</p>', unsafe_allow_html=True)
        channel = st.selectbox("Message source (optional)", ["Auto-detect", "SMS", "WhatsApp", "Email", "Social media", "Other"])
        message = st.text_area("Suspicious message", height=230, max_chars=12000,
            placeholder="Paste the message here…\n\nExample: Your parcel is on hold. Pay a small fee using this link…")
        st.caption(f"{len(message)} / 12,000 characters")
        analyse = st.button("🔍  Analyse message", type="primary", use_container_width=True)
    with right:
        st.markdown("### Before you analyse")
        st.markdown("""
        <div class="panel">
        <b>Keep yourself safe</b><br><br>
        • Never share OTPs, PINs, or passwords.<br>
        • Avoid opening unexpected links or files.<br>
        • Verify requests through an official channel you find independently.<br>
        • Remove personal details before pasting where possible.
        </div>
        <div class="panel">
        <b>What the report includes</b><br><br>
        Risk category and indicative score<br>
        Exact text evidence where available<br>
        Plain-language explanations<br>
        Safer next steps and uncertainty
        </div>
        """, unsafe_allow_html=True)

    if analyse:
        if not message.strip():
            st.warning("Please paste a message before analysing.")
        else:
            with st.spinner("Gemma is reviewing the message locally through Ollama…"):
                try:
                    report = analyze_message(message)
                    if channel != "Auto-detect":
                        report["message_type"] = channel
                    st.session_state["last_report"] = report
                    st.session_state["last_message"] = message
                except ScamShieldError as exc:
                    st.error(str(exc))
                except Exception:
                    st.error("An unexpected error occurred. Please try again. If it continues, check the terminal for details.")

    report = st.session_state.get("last_report")
    if report:
        st.divider()
        st.subheader("Analysis report")
        colors = {"Low": "🟢", "Moderate": "🟡", "High": "🟠", "Critical": "🔴", "Unclear": "⚪"}
        level = report["risk_level"]
        st.markdown(
            f'<div class="gauge gauge-{html.escape(level)}"><h2>{colors.get(level, "⚪")} {html.escape(level)} risk</h2>'
            '<div class="small" style="color:inherit;">Awareness indicator only. Not proof either way.</div></div>',
            unsafe_allow_html=True,
        )
        b, c = st.columns(2)
        b.metric("Indicative risk score", f"{report['risk_score']} / 100")
        c.metric("Message type", report["message_type"])
        st.caption("The score is an AI-generated awareness indicator, not a probability that the message is fraudulent.")
        st.markdown("### What Gemma noticed")
        st.markdown(f'<div class="panel">{html.escape(report["summary"])}</div>', unsafe_allow_html=True)

        st.markdown("### Warning signs & evidence")
        if report["warning_signs"]:
            for item in report["warning_signs"]:
                with st.expander(item["title"], expanded=True):
                    if item["evidence"]:
                        st.markdown(f'<div class="quote">“{html.escape(item["evidence"])}”</div>', unsafe_allow_html=True)
                    else:
                        st.caption("No exact quotation was retained for this point.")
                    st.write(item["explanation"])
        else:
            st.info("No specific warning signs were identified in the supplied text. This does not prove the message is safe.")

        x, y = st.columns(2)
        with x:
            st.markdown("### Safer next steps")
            for action in report["safe_actions"]:
                st.markdown(f"- {action}")
        with y:
            st.markdown("### What remains uncertain")
            for item in report["uncertainty"]:
                st.markdown(f"- {item}")

        st.download_button(
            "⬇ Download report (JSON)",
            data=json.dumps(report, indent=2, ensure_ascii=False),
            file_name="scamshield-analysis.json",
            mime="application/json",
        )

elif page == "Scam catalogue":
    st.subheader("Common scam patterns")
    st.markdown('<p class="subtle">A searchable awareness guide. These are pattern examples, not a list of verified current incidents.</p>', unsafe_allow_html=True)
    catalogue = [
        ("OTP / account takeover", "A caller or message asks for an OTP, PIN, password, or screen-sharing access.", "Never disclose authentication codes. Contact the bank or service through its official app or website."),
        ("KYC / account suspension", "A message claims an account will be blocked unless details are updated through a link.", "Do not use the supplied link. Open the official app or type the known website address yourself."),
        ("Parcel / delivery fee", "An unexpected delivery notice asks for a small payment or personal details to release a parcel.", "Check tracking through the courier's official website using a tracking number you already have."),
        ("Prize / reward", "A message says you have won a prize but must pay a fee or provide sensitive information.", "Treat unexpected prizes cautiously. Do not pay to claim an unsolicited reward."),
        ("Job / task scam", "A recruiter promises unusually high earnings for simple tasks and may later request deposits.", "Verify the employer independently. Do not pay to obtain work or withdraw supposed earnings."),
        ("UPI collect request", "A person says you must approve a collect request or enter a UPI PIN to receive money.", "A UPI PIN is used to authorise payments, not to receive money. Decline unexpected requests."),
        ("Impersonation / emergency", "Someone pretends to be a relative, official, or authority and demands urgent money.", "Verify using a previously known phone number and a separate communication channel."),
        ("Investment / guaranteed returns", "A message promises guaranteed or unusually high returns with pressure to act quickly.", "Check registration and claims independently. Never transfer money based only on a message."),
    ]
    query = st.text_input("Search scam patterns", placeholder="Try: OTP, parcel, job, UPI…").lower()
    matches = [item for item in catalogue if query in " ".join(item).lower()]
    if not matches:
        st.info("No matching pattern. Try a broader search term.")
    for title, pattern, action in matches:
        with st.expander(title):
            st.write("**Typical pattern**")
            st.write(pattern)
            st.write("**Safer response**")
            st.write(action)

elif page == "India cyber help":
    st.subheader("Official Indian cyber-safety resources")
    st.markdown('<p class="subtle">Use official channels. If money has been lost to suspected cyber financial fraud, report it immediately.</p>', unsafe_allow_html=True)
    st.markdown("""
    <div class="panel">
    <h3>☎️ Financial cyber fraud helpline: 1930</h3>
    If you have transferred money or suspect financial cyber fraud, call 1930 promptly and follow the official reporting process.
    </div>
    """, unsafe_allow_html=True)
    st.markdown("- **National Cyber Crime Reporting Portal:** https://cybercrime.gov.in/")
    st.markdown("- **CERT-In:** https://www.cert-in.org.in/")
    st.markdown("- **Cyber Swachhta Kendra:** https://www.csk.gov.in/")
    st.info("ScamShield AI is an awareness aid, not a government service, law-enforcement tool, or substitute for official reporting.")

st.divider()
st.markdown("""
<div class="small">
<b>Responsible AI notice:</b> ScamShield AI cannot prove whether a message is fraudulent or verify the sender's identity. Results may be incomplete or incorrect. Always verify independently before taking action. This tool does not contact authorities or block messages.
</div>
""", unsafe_allow_html=True)
