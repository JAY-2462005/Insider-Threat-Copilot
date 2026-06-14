import streamlit as st

from components.copilot import render_copilot_button
from components.kill_switch import (
    count_active_alerts,
    count_active_critical,
    filter_active_alerts,
    init_isolated_users,
    is_critical_alert,
    is_user_isolated,
    render_neutralized_block,
    render_revoke_button,
)
from components.theme import inject_global_css, render_hero
from data_service import (
    clear_data_cache,
    get_alerts_dataframe,
    get_dataset_summary,
    get_events_dataframe,
)

st.set_page_config(
    page_title="TrustGuardian | Insider Threat Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

init_isolated_users()
inject_global_css()

st.sidebar.title("TrustGuardian")
st.sidebar.caption("Insider Threat Detection Platform")
st.sidebar.markdown("---")
st.sidebar.markdown("**Configuration**")

if "threshold" not in st.session_state:
    st.session_state["threshold"] = 70

new_threshold = st.sidebar.slider(
    "Risk Score Threshold",
    0,
    100,
    st.session_state["threshold"],
    5,
)

if st.sidebar.button("Refresh Backend Data"):
    clear_data_cache()

st.session_state["threshold"] = new_threshold

try:
    with st.spinner("Scoring access logs..."):
        events_df = get_events_dataframe()
        alerts_df = get_alerts_dataframe(new_threshold)
        summary = get_dataset_summary(new_threshold)
except FileNotFoundError:
    st.sidebar.error("Data files not found. Run backend/generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.sidebar.error(f"Failed to load backend data: {e}")
    st.stop()

render_hero(
    "TrustGuardian Insider Threat Copilot",
    "AI-powered detection, investigation, and offline SOC copilot for suspicious insider activity — "
    "built for security teams who need explainable alerts and fast response.",
)

if events_df.empty:
    st.info("No backend events are available yet.")
    st.stop()

active_alerts = filter_active_alerts(alerts_df)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events Scored", summary["events"])
col2.metric("Active Alerts", count_active_alerts(alerts_df))
col3.metric("Critical (Active)", count_active_critical(alerts_df))
col4.metric("Users Monitored", summary["users"])

st.markdown("---")

left, right = st.columns([1.2, 1])

with left:
    st.subheader("Highest Priority Incident")
    if active_alerts.empty:
        st.success("No active alerts above the selected threshold.")
    else:
        top_alert = active_alerts.sort_values(by="risk_score", ascending=False).iloc[0]
        top_username = top_alert["username"]
        st.error(
            f"**{top_alert['severity']}** — `{top_username}` ({top_alert['department']})  \n"
            f"Risk **{top_alert['risk_score']}** · Asset `{top_alert.get('data_asset', 'Unknown')}` "
            f"→ `{top_alert.get('destination', 'Unknown')}`"
        )
        if is_critical_alert(top_alert):
            render_revoke_button(top_alert, key_prefix="home_top_")
        if st.button("Ask Copilot about this incident", key="dashboard_detective"):
            st.session_state["detective_prompt"] = (
                f"Why was {top_username} flagged with risk score {top_alert['risk_score']}?"
            )
            st.switch_page("pages/8_Security_Copilot.py")

with right:
    st.subheader("Platform Capabilities")
    st.markdown(
        """
        - **Detection** — Hybrid ML + rule engine with full score breakdown
        - **Alerts Queue** — Severity-based triage with SOC actions
        - **Investigation** — Baseline vs observed behavior analysis
        - **Flight Risk** — Pre-breach watchlist before data exfiltration
        - **Security Copilot** — Offline RAG + local Qwen analyst chat
        - **Kill-Switch** — Simulated account isolation for critical threats
        """
    )

st.markdown("---")
st.subheader("How It Works")
flow_cols = st.columns(5)
steps = [
    ("Ingest", "CSV logs + user profiles"),
    ("Engineer", "Behavioral features"),
    ("Score", "ML + policy rules"),
    ("Alert", "Explainable severity"),
    ("Respond", "Investigate & contain"),
]
for col, (title, desc) in zip(flow_cols, steps):
    col.markdown(f"**{title}**")
    col.caption(desc)

st.markdown("---")
st.subheader("Recent Scored Events")
st.dataframe(
    events_df[
        ["timestamp", "username", "department", "data_asset", "destination", "risk_score", "severity"]
    ]
    .sort_values(by="timestamp", ascending=False)
    .head(12),
    use_container_width=True,
    hide_index=True,
)

st.markdown("---")
render_copilot_button(
    "Open Security Copilot",
    "Summarize this week's critical insider threat incidents",
    key="home_copilot_btn",
)
