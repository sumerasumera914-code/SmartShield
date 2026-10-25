"""SmartShield - Scam Message and Suspicious Link Detector (Streamlit app).

Run with:  streamlit run app.py
"""
import os

import joblib
import streamlit as st

from text_utils import clean_text  # needed so the saved model can be loaded
from url_checker import (
    STATUS_OK,
    STATUS_SUSPICIOUS,
    analyze_url,
    check_google_safe_browsing,
)

MODEL_FILE = os.path.join("model", "scam_model.joblib")

SAMPLE_MESSAGES = {
    "Suspicious example 1 (prize)": "WINNER!! You have been selected to receive a 900 pound prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only.",
    "Suspicious example 2 (free offer)": "Congratulations! You won a free entry in our weekly competition. Text WIN to 80086 now to claim your cash prize.",
    "Normal example 1": "Hey, are we still meeting for lunch tomorrow? Let me know what time works for you.",
    "Normal example 2": "I will be late today, please start the meeting without me. See you in 20 minutes.",
}

SAMPLE_URLS = {
    "Suspicious example 1": "http://paypal.account-verify.secure-login.example-site.xyz/update/password?id=12345",
    "Suspicious example 2": "http://192.168.10.5/login/verify-account",
    "Suspicious example 3": "https://bit.ly/3AbCdEf",
    "Normal example 1": "https://www.wikipedia.org/",
    "Normal example 2": "https://github.com/",
}

st.set_page_config(page_title="SmartShield", page_icon="🛡️", layout="centered")


@st.cache_resource
def load_model():
    """Load the trained model once. Returns None if the file is missing or broken."""
    if not os.path.exists(MODEL_FILE):
        return None
    try:
        return joblib.load(MODEL_FILE)
    except Exception:
        return None


def set_message(text):
    st.session_state["message_text"] = text


def set_url(text):
    st.session_state["url_text"] = text


# ---------- Header ----------
st.title("🛡️ SmartShield")
st.subheader("Scam Message and Suspicious Link Detector")
st.write(
    "Paste a message or a link and SmartShield will look for warning signs. "
    "Messages are checked by a **Machine Learning model**. Links are checked by simple **rules**."
)
st.info(
    "⚠️ **Educational prototype.** This tool cannot catch every scam and it can make mistakes. "
    "Never rely on it alone. If you are unsure, do not click links or share OTPs, passwords or bank details."
)

tab_message, tab_link = st.tabs(["💬 Message Checker", "🔗 Link Checker"])

# ---------- Tab 1: Message Checker ----------
with tab_message:
    st.markdown("#### Check a message (SMS, email, chat)")
    st.caption("Method: Machine Learning (TF-IDF + Logistic Regression).")

    if "message_text" not in st.session_state:
        st.session_state["message_text"] = ""

    st.write("Try a sample:")
    cols = st.columns(2)
    for i, (label, text) in enumerate(SAMPLE_MESSAGES.items()):
        cols[i % 2].button(label, key=f"msg_sample_{i}", on_click=set_message, args=(text,), use_container_width=True)

    message = st.text_area("Paste the message here", key="message_text", height=150)

    if st.button("Check Message", type="primary"):
        model = load_model()
        if model is None:
            st.error("The model file was not found or could not be loaded. Please run `python train_model.py` first, then restart the app.")
        elif not message or not message.strip():
            st.warning("Please paste a message first.")
        else:
            try:
                spam_probability = float(model.predict_proba([message])[0][1])
                is_suspicious = spam_probability >= 0.5
            except Exception:
                st.error("Something went wrong while checking this message. Try again with different text.")
            else:
                if is_suspicious:
                    st.error("🚩 **Potentially Suspicious**")
                else:
                    st.success("✅ **Not Flagged**")
                st.progress(spam_probability)
                st.write(f"Model's estimate that this is a scam message: **{spam_probability * 100:.1f}%**")
                st.caption("This number is the model's own estimate. It is not a guarantee.")
                if not is_suspicious:
                    st.warning("**Not Flagged does not mean safe.** Scammers write new kinds of messages all the time, and this model was trained on an older dataset.")

# ---------- Tab 2: Link Checker ----------
with tab_link:
    st.markdown("#### Check a link")
    st.caption("Method: simple rules on the text of the URL. This is NOT Machine Learning. The link is never opened.")

    if "url_text" not in st.session_state:
        st.session_state["url_text"] = ""

    st.write("Try a sample:")
    cols = st.columns(2)
    for i, (label, text) in enumerate(SAMPLE_URLS.items()):
        cols[i % 2].button(label, key=f"url_sample_{i}", on_click=set_url, args=(text,), use_container_width=True)

    url_input = st.text_input("Enter a URL", key="url_text", placeholder="https://example.com/page")

    with st.expander("Optional: Google Safe Browsing check (needs your own free API key)"):
        st.write(
            "If you type a key, the URL text will be sent to Google to check its list of unsafe sites. "
            "Leave this empty to use only the rules. The key is not saved."
        )
        default_key = os.environ.get("SAFE_BROWSING_API_KEY", "")
        api_key = st.text_input("Google Safe Browsing API key", value=default_key, type="password")

    if st.button("Check Link", type="primary"):
        result = analyze_url(url_input)

        if result["status"] == STATUS_SUSPICIOUS:
            st.error(f"🚩 **{result['status']}**")
        elif result["status"] == STATUS_OK:
            st.success(f"✅ **{result['status']}**")
        else:
            st.warning(f"❔ **{result['status']}**")

        for note in result["notes"]:
            st.caption(note)

        if result["warnings"]:
            st.write("**What we noticed:**")
            for warning in result["warnings"]:
                st.write(f"- {warning}")
        elif result["status"] == STATUS_OK:
            st.write("None of our simple rules were triggered.")

        if result["status"] != "Unable to Analyse":
            st.caption("These rules only look at how the URL is written. A link can still be dangerous even with no warning signs, and unusual-looking links can be harmless.")

            if api_key.strip():
                reputation = check_google_safe_browsing(url_input.strip(), api_key.strip())
                if reputation["checked"] and reputation["flagged"]:
                    st.error("🚩 " + reputation["message"])
                elif reputation["checked"]:
                    st.info("ℹ️ " + reputation["message"])
                else:
                    st.warning("⚠️ " + reputation["message"])
            else:
                st.caption("No reputation database was checked (no API key given).")

st.divider()
st.caption("SmartShield • Educational project • Python, Pandas, Scikit-learn, Streamlit")
