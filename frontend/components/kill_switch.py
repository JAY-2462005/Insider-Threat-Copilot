"""Phase 2, Feature 4: Simulated Kill-Switch (DLP / SOAR mock). Frontend-only — no ML pipeline impact."""

import time

import streamlit as st


def init_isolated_users():
    if "isolated_users" not in st.session_state:
        st.session_state.isolated_users = set()


def is_user_isolated(username: str) -> bool:
    init_isolated_users()
    return username in st.session_state.isolated_users


def is_critical_alert(alert) -> bool:
    severity = alert.get("severity") if isinstance(alert, dict) else alert["severity"]
    risk_score = alert.get("risk_score") if isinstance(alert, dict) else alert["risk_score"]
    return severity == "CRITICAL" or float(risk_score) >= 90


def render_neutralized_block(username: str):
    st.success(
        f"🔒 **THREAT NEUTRALIZED:** Access for `{username}` has been revoked via Identity Provider."
    )


def render_revoke_button(alert, key_prefix: str = ""):
    access_id = alert.get("access_id") if isinstance(alert, dict) else alert["access_id"]
    username = alert.get("username") if isinstance(alert, dict) else alert["username"]

    if st.button("🚨 REVOKE ACCESS & ISOLATE", key=f"isolate_{key_prefix}{access_id}", type="primary"):
        init_isolated_users()
        with st.spinner("Initiating Azure AD/Okta Webhook..."):
            time.sleep(1.5)
        st.session_state.isolated_users.add(username)
        st.toast(f"Success: {username} has been locked out.")
        st.rerun()


def count_active_critical(alerts_df):
    """Critical alerts excluding users already isolated (display-only helper)."""
    if alerts_df.empty:
        return 0
    init_isolated_users()
    active = alerts_df[~alerts_df["username"].isin(st.session_state.isolated_users)]
    return int((active["severity"] == "CRITICAL").sum())
