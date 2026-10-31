from __future__ import annotations

import html
import json

import streamlit as st

from analyzer import MODEL, OLLAMA_BASE_URL, ScamShieldError, analyze_message, check_ollama

st.set_page_config(page_title="ScamShield", page_icon="🛡️", layout="centered", initial_sidebar_state="collapsed")


def esc(text: str) -> str:
    """Escape text for safe use inside HTML (and stop Streamlit treating $ as maths)."""
    return html.escape(str(text)).replace("$", "&#36;")


@st.cache_data(ttl=30)
def cached_health():
    return check_ollama()


# ---------- Settings (top right) ----------
top_left, top_right = st.columns([5, 1.4])
with top_left:
    st.markdown('<div class="wordmark">ScamShield</div>', unsafe_allow_html=True)
with top_right:
    with st.popover("Settings", use_container_width=True):
        large_text = st.checkbox("Larger text")
        high_contrast = st.checkbox("High contrast")
        ok, health = cached_health()
        st.caption(("Ready: " if ok else "Not ready: ") + health)
        st.caption(f"Model {MODEL} at {OLLAMA_BASE_URL}")

INK, MUTED, LINE = ("#000000", "#000000", "#000000") if high_contrast else ("#17231D", "#4F5F56", "#CBD6CD")

st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400&family=Bricolage+Grotesque:wght@600;700;800&display=swap');
:root {{ --ink:{INK}; --muted:{MUTED}; --line:{LINE}; --paper:#FFFFFF; --bg:#F2F5F1; --mark:#FFE066; }}
html {{ font-size: {'120%' if large_text else '100%'}; }}
html, body, .stApp, [class*="css"] {{ font-family: 'Atkinson Hyperlegible', 'Segoe UI', sans-serif; color: var(--ink); }}
.stApp {{ background: var(--bg); }}
header[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ max-width: 780px; padding-top: 2rem; padding-bottom: 4rem; }}
.wordmark, h1, h2, h3 {{ font-family: 'Bricolage Grotesque', 'Segoe UI', sans-serif !important; letter-spacing: -0.01em; color: var(--ink); }}
.wordmark {{ font-size: 1.5rem; font-weight: 800; padding-top: .35rem; }}
h1 {{ font-size: 2.3rem !important; line-height: 1.12 !important; font-weight: 800 !important; }}
h2, h3 {{ font-weight: 700 !important; }}
.lede {{ color: var(--muted); font-size: 1.1rem; line-height: 1.55; margin: -.3rem 0 1.2rem; max-width: 34rem; }}
textarea {{ font-size: 1.08rem !important; line-height: 1.6 !important; border: 2px solid var(--ink) !important; border-radius: 10px !important; background: var(--paper) !important; }}
button[kind="primary"], button[data-testid="stBaseButton-primary"] {{ background: var(--ink) !important; color: #fff !important; border: 0 !important; border-radius: 10px !important; font-weight: 700 !important; font-size: 1.08rem !important; padding: .65rem 1.2rem !important; }}
button[kind="secondary"], button[data-testid="stBaseButton-secondary"] {{ border: 1.5px solid var(--line) !important; border-radius: 999px !important; background: transparent !important; color: var(--ink) !important; font-size: .95rem !important; }}
.small-note {{ color: var(--muted); font-size: .95rem; margin-top: .5rem; }}
.verdict {{ border-radius: 14px; padding: 1.3rem 1.4rem; margin: 1.6rem 0 1.4rem; border-left: 10px solid; }}
.verdict h2 {{ margin: 0 0 .35rem; font-size: 1.7rem; }}
.verdict p {{ margin: 0; font-size: 1.1rem; line-height: 1.55; }}
.verdict .meta {{ margin-top: .7rem; font-size: .9rem; opacity: .85; }}
.v-Low {{ background:#E2F1E8; border-color:#2E7D5B; }}
.v-Moderate {{ background:#FFF1CF; border-color:#B7791F; }}
.v-High {{ background:#FFE6D8; border-color:#C2410C; }}
.v-Critical {{ background:#FCE1DD; border-color:#B42318; }}
.v-Unclear {{ background:#E7ECE8; border-color:#6B7A71; }}
.section {{ margin-top: 2rem; }}
.section h3 {{ margin: 0 0 .6rem; font-size: 1.3rem; }}
.msgbox {{ background: var(--paper); border: 1.5px solid var(--line); border-radius: 10px; padding: 1.1rem 1.2rem; font-size: 1.08rem; line-height: 1.85; }}
.msgbox mark {{ background: var(--mark); color: var(--ink); padding: .08em .25em; border-radius: 4px; }}
.msgbox sup {{ font-weight: 700; font-size: .7em; margin-left: .15em; }}
.why {{ display: flex; gap: .8rem; padding: .85rem 0; border-top: 1px solid var(--line); }}
.why:first-of-type {{ border-top: 0; }}
.badge {{ flex: 0 0 1.7rem; height: 1.7rem; border-radius: 50%; background: var(--mark); border: 1.5px solid var(--ink); font-weight: 700; font-size: .9rem; display: flex; align-items: center; justify-content: center; }}
.badge.none {{ background: transparent; border-style: dashed; }}
.why b {{ display: block; margin-bottom: .15rem; }}
.why span {{ color: var(--ink); line-height: 1.55; }}
.why i {{ color: var(--muted); font-size: .92rem; display: block; margin-top: .2rem; }}
.todo {{ list-style: none; padding: 0; margin: 0; }}
.todo li {{ display: flex; gap: .7rem; padding: .5rem 0; line-height: 1.5; font-size: 1.05rem; }}
.todo li::before {{ content: ""; flex: 0 0 1.05rem; height: 1.05rem; margin-top: .25rem; border: 2px solid var(--ink); border-radius: 4px; }}
.help {{ background: var(--ink); color: #fff; border-radius: 14px; padding: 1.2rem 1.4rem; margin-top: 2rem; }}
.help b {{ font-size: 1.25rem; font-family: 'Bricolage Grotesque', sans-serif; }}
.help p {{ margin: .4rem 0 0; line-height: 1.55; }}
.help a {{ color: var(--mark); }}
.unsure {{ color: var(--muted); line-height: 1.6; }}
.unsure li {{ margin-bottom: .3rem; }}
.fine {{ color: var(--muted); font-size: .9rem; line-height: 1.55; margin-top: 3rem; border-top: 1px solid var(--line); padding-top: 1rem; }}
</style>""", unsafe_allow_html=True)

EXAMPLES = {
    "Prize": "Congratulations! You have won a prize. Pay a processing fee immediately to claim it.",
    "Account alert": "Your account will be suspended today. Send your OTP to verify your identity.",
    "College notice": "Dear students, the library will remain closed on Sunday due to scheduled maintenance. Regular hours resume on Monday.",
    "Job offer": "We have an opening for a remote assistant. Please contact us for further details.",
}

HEADLINES = {
    "Low": ("No clear warning signs", "Nothing in this message stands out as a scam. That does not prove it is safe."),
    "Moderate": ("Some warning signs", "A few things in this message are worth a second look before you act."),
    "High": ("Strong warning signs", "This message has several features that scams often use. Do not act on it yet."),
    "Critical": ("Very strong warning signs", "This looks a lot like a known scam pattern. Do not reply, pay, or share anything."),
    "Unclear": ("Not enough to judge", "There is too little here to say either way. Check with the sender in a way you trust."),
}


def set_example(text: str) -> None:
    st.session_state["msg"] = text


def annotate(message: str, signs: list[dict]) -> str:
    spans = []
    for n, sign in enumerate(signs, 1):
        ev = sign["evidence"]
        if not ev:
            continue
        a = message.find(ev)
        if a < 0:
            continue
        b = a + len(ev)
        if any(a < y and b > x for x, y, _ in spans):
            continue
        spans.append((a, b, n))
    spans.sort()
    out, pos = [], 0
    for a, b, n in spans:
        out.append(esc(message[pos:a]))
        out.append(f"<mark>{esc(message[a:b])}<sup>{n}</sup></mark>")
        pos = b
    out.append(esc(message[pos:]))
    return "".join(out).replace("\n", "<br>")


def render_report(report: dict, message: str) -> None:
    level = report["risk_level"]
    head, line = HEADLINES.get(level, HEADLINES["Unclear"])
    kind = report["message_type"]
    kind_text = f" Looks like: {esc(kind)}." if kind not in ("Unknown", "Other") else ""
    st.markdown(
        f'<div class="verdict v-{esc(level)}"><h2>{head}</h2><p>{esc(report["summary"]) or line}</p>'
        f'<div class="meta">Awareness score {report["risk_score"]} out of 100. A guide, not a probability.{kind_text}</div></div>',
        unsafe_allow_html=True,
    )

    signs = report["warning_signs"]
    st.markdown(
        f'<div class="section"><h3>Your message, marked up</h3><div class="msgbox">{annotate(message, signs)}</div></div>',
        unsafe_allow_html=True,
    )

    if signs:
        rows = []
        for n, s in enumerate(signs, 1):
            has_quote = s["evidence"] and s["evidence"] in message
            badge = f'<div class="badge">{n}</div>' if has_quote else '<div class="badge none">·</div>'
            note = "" if has_quote else "<i>Applies to the message as a whole.</i>"
            rows.append(f'<div class="why">{badge}<div><b>{esc(s["title"])}</b><span>{esc(s["explanation"])}</span>{note}</div></div>')
        st.markdown('<div class="section"><h3>Why it looks suspicious</h3>' + "".join(rows) + "</div>", unsafe_allow_html=True)
    else:
        st.markdown('<div class="section"><h3>Why it looks suspicious</h3><p class="unsure">No specific warning signs were found in the text.</p></div>', unsafe_allow_html=True)

    items = "".join(f"<li>{esc(a)}</li>" for a in report["safe_actions"])
    st.markdown(f'<div class="section"><h3>What to do now</h3><ul class="todo">{items}</ul></div>', unsafe_allow_html=True)

    if level in ("Moderate", "High", "Critical"):
        st.markdown(
            '<div class="help"><b>Already paid or shared details? Call 1930.</b>'
            '<p>1930 is India\'s cyber fraud helpline. Call it straight away, then report at '
            '<a href="https://cybercrime.gov.in/" target="_blank">cybercrime.gov.in</a>. Acting fast gives the best chance of stopping a payment.</p></div>',
            unsafe_allow_html=True,
        )

    unsure = "".join(f"<li>{esc(u)}</li>" for u in report["uncertainty"])
    st.markdown(f'<div class="section"><h3>What we can\'t tell</h3><ul class="unsure">{unsure}</ul></div>', unsafe_allow_html=True)

    st.download_button("Save this report", json.dumps(report, indent=2, ensure_ascii=False), "scamshield-report.json", "application/json")


tab_check, tab_scams, tab_help = st.tabs(["Check a message", "Common scams", "Get help"])

def back_to_input(clear: bool) -> None:
    st.session_state["view"] = "input"
    st.session_state["msg"] = "" if clear else st.session_state.get("checked", "")


with tab_check:
    if st.session_state.get("view") == "result" and st.session_state.get("report"):
        # ---------- Result screen ----------
        b1, b2, _ = st.columns([1.4, 1.2, 2])
        b1.button("Check another message", type="primary", on_click=back_to_input, args=(True,), use_container_width=True)
        b2.button("Edit this message", on_click=back_to_input, args=(False,), use_container_width=True)
        render_report(st.session_state["report"], st.session_state["checked"])
    else:
        # ---------- Input screen ----------
        st.markdown("# Got a message that feels off?")
        st.markdown('<p class="lede">Paste it below. ScamShield points out what looks suspicious and what to do next. It runs on this computer, and nothing is saved.</p>', unsafe_allow_html=True)

        st.caption("No message handy? Try an example:")
        cols = st.columns(len(EXAMPLES))
        for col, (label, text) in zip(cols, EXAMPLES.items()):
            col.button(label, on_click=set_example, args=(text,), key=f"ex_{label}", use_container_width=True)

        message = st.text_area("Message to check", key="msg", height=170, max_chars=12000,
                               placeholder="Paste an SMS, WhatsApp message or email here…", label_visibility="collapsed")
        go = st.button("Check this message", type="primary")
        st.markdown('<div class="small-note">Never paste passwords, PINs or OTPs. Remove personal details first if you can.</div>', unsafe_allow_html=True)

        if go:
            if not message.strip():
                st.warning("Paste a message first, then press Check this message.")
            else:
                with st.spinner("Reading the message. The first check can take a minute…"):
                    try:
                        st.session_state["report"] = analyze_message(message)
                        st.session_state["checked"] = message.strip()
                        st.session_state["view"] = "result"
                        st.rerun()
                    except ScamShieldError as exc:
                        st.session_state.pop("report", None)
                        st.error(str(exc))
                    except Exception:
                        st.session_state.pop("report", None)
                        st.error("Something went wrong while checking. Try again. If it keeps happening, look at the terminal window for details.")

with tab_scams:
    st.markdown("# Common scams")
    st.markdown('<p class="lede">Patterns that show up again and again. These are examples of how scams work, not a list of current incidents.</p>', unsafe_allow_html=True)
    catalogue = [
        ("OTP and account takeover", "A call or message asks for your OTP, PIN, password, or to share your screen.", "Never read out a code. Your bank will not ask for it. Contact the bank through its official app or website."),
        ("KYC or account suspended", "A message says your account will be blocked unless you update details through a link.", "Don't use the link. Open the official app, or type the website address yourself."),
        ("Parcel or delivery fee", "An unexpected delivery notice asks for a small payment or personal details.", "Check tracking on the courier's own website with a tracking number you already have."),
        ("Prize or lottery", "You have won something you never entered, but must pay a fee to get it.", "Real prizes don't ask you to pay first. Ignore and delete."),
        ("Job or task scam", "High pay for simple tasks, then a deposit is needed to continue or to withdraw earnings.", "Never pay to get work. Check the employer independently."),
        ("UPI collect request", "Someone says you must approve a request or enter your UPI PIN to receive money.", "You only enter a UPI PIN to send money, never to receive it. Decline."),
        ("Family or official in trouble", "Someone pretends to be a relative, police officer or official and demands money fast.", "Hang up and call back on a number you already know. Real officers don't ask for transfers on video calls."),
        ("Guaranteed returns", "Promises of fixed high returns with pressure to join today.", "No honest investment guarantees high returns. Check registration before you send anything."),
    ]
    q = st.text_input("Search", placeholder="Try: OTP, parcel, job, UPI", label_visibility="collapsed").lower()
    found = [c for c in catalogue if q in " ".join(c).lower()]
    if not found:
        st.info("Nothing matches that search. Try a shorter word.")
    for title, pattern, action in found:
        with st.expander(title):
            st.markdown(f"**How it works.** {pattern}")
            st.markdown(f"**What to do.** {action}")

with tab_help:
    st.markdown("# Get help")
    st.markdown('<p class="lede">If money has gone or you shared sensitive details, move quickly and use official channels.</p>', unsafe_allow_html=True)
    st.markdown('<div class="help"><b>Call 1930</b><p>India\'s cyber financial fraud helpline. Call as soon as you notice a fraudulent payment, then follow the reporting steps.</p></div>', unsafe_allow_html=True)
    st.markdown("")
    st.markdown("- [National Cyber Crime Reporting Portal](https://cybercrime.gov.in/)\n- [CERT-In](https://www.cert-in.org.in/)\n- [Cyber Swachhta Kendra](https://www.csk.gov.in/)")
    st.info("ScamShield is an awareness tool. It is not a government or police service.")

st.markdown('<div class="fine">ScamShield cannot prove a message is a scam or that it is safe, and it cannot check who sent it. Results can be wrong. Always confirm through an official channel you find yourself. This tool does not contact anyone or block messages.</div>', unsafe_allow_html=True)