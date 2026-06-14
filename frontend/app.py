import streamlit as st

from components.kill_switch import (
    init_isolated_users,
    is_critical_alert,
    is_user_isolated,
    render_neutralized_block,
    render_revoke_button,
)
from data_service import (
    clear_data_cache,
    get_alerts_dataframe,
    get_dataset_summary,
    get_events_dataframe,
)

st.set_page_config(
    page_title="Insider Threat Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_isolated_users()

# Custom CSS
st.markdown("""
    <style>
        .main {
            padding: 2rem;
        }
        .metric-card {
            background-color: #f0f2f6;
            padding: 1.5rem;
            border-radius: 0.5rem;
            margin: 0.5rem 0;
        }
    </style>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🛡️ Insider Threat Copilot")
st.sidebar.markdown("---")
st.sidebar.markdown("### Configuration")

if "threshold" not in st.session_state:
    st.session_state["threshold"] = 70

new_threshold = st.sidebar.slider(
    "Risk Score Threshold", 
    0, 100, 
    st.session_state["threshold"], 5
)

if st.sidebar.button("Refresh Backend Data"):
    clear_data_cache()

st.session_state["threshold"] = new_threshold

try:
    with st.spinner("Analyzing access logs & updating ML predictions..."):
        events_df = get_events_dataframe()
        alerts_df = get_alerts_dataframe(new_threshold)
        summary = get_dataset_summary(new_threshold)
except FileNotFoundError:
    st.sidebar.error("Data files not found. Run backend/generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.sidebar.error(f"Failed to load backend data: {e}")
    st.stop()

# Main content - Home Page
st.title("🛡️ Insider Threat Detection System")

if events_df.empty:
    st.info("No backend events are available yet.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events Scored", summary["events"])
col2.metric("Active Alerts", summary["alerts"])
col3.metric("Critical", summary["critical"])
col4.metric("Users Monitored", summary["users"])

if not alerts_df.empty:
    top_alert = alerts_df.sort_values(by="risk_score", ascending=False).iloc[0]
    top_username = top_alert["username"]

    if is_user_isolated(top_username):
        render_neutralized_block(top_username)
    else:
        st.error(
            f"""
            ### 🚨 Top Incident
            **User:** `{top_username}` | **Department:** `{top_alert['department']}`  
            **Severity:** **{top_alert['severity']}** | **Risk Score:** **{top_alert['risk_score']}**
            """
        )
        if is_critical_alert(top_alert):
            render_revoke_button(top_alert, key_prefix="home_top_")
        
        # Add Data Detective button
        if st.button("🤖 Ask Data Detective about this incident", key="dashboard_detective"):
            st.session_state["detective_prompt"] = f"Explain why {top_username} was flagged with risk score {top_alert['risk_score']} and severity {top_alert['severity']}"
            st.switch_page("pages/7_Data_Detective.py")

    st.markdown("---")

    st.subheader("🔐 SOC Kill-Switch Queue")
    st.caption("Simulated DLP / Azure AD integration — isolate compromised accounts without re-scoring events.")
    for _, alert in alerts_df.sort_values(by="risk_score", ascending=False).head(10).iterrows():
        username = alert["username"]
        if is_user_isolated(username):
            render_neutralized_block(username)
            continue

        icon = "🔴" if alert["severity"] == "CRITICAL" else "🟠" if alert["severity"] == "HIGH" else "🟡"
        with st.container(border=True):
            st.markdown(
                f"{icon} **[{alert['severity']}]** `{alert['timestamp']}` — "
                f"**{username}** ({alert['department']}) | Risk: **{alert['risk_score']}**"
            )
            st.markdown(f"Asset: `{alert.get('data_asset', 'Unknown')}` → `{alert.get('destination', 'Unknown')}`")
            if is_critical_alert(alert):
                render_revoke_button(alert, key_prefix="home_")
    st.markdown("---")
else:
    st.info("✅ No alerts detected above the selected threshold.")
    st.markdown("---")

st.subheader("Recent Backend-Scored Events")
st.dataframe(
    events_df[["timestamp", "username", "department", "data_asset", "destination", "risk_score", "severity"]]
    .sort_values(by="timestamp", ascending=False)
    .head(15),
    use_container_width=True,
    hide_index=True,
)

st.markdown("""
Welcome to the **Insider Threat Copilot** - an AI-powered platform for detecting and investigating 
suspicious insider threats in real-time.

### Key Features
- 🔍 **Real-time Detection**: ML-powered anomaly detection with rule-based scoring
- 📊 **Advanced Analytics**: Comprehensive data access patterns analysis
- 🚨 **Smart Alerts**: Severity-based alert system with recommended actions
- 🔎 **Investigation Tools**: Deep dive into user activities and behavioral patterns
- 🎯 **Threat Simulation (ATO)**: Interactive K-Means peer-group clustering demo
- 🔐 **Simulated Kill-Switch**: One-click account isolation via mock SOAR / Identity Provider
- 🤖 **AI Summary**: Automated insights and threat intelligence
- ✈️ **Flight Risk Radar**: Proactive pre-breach threat prediction
- 🕵️ **Data Detective**: Natural language security investigation copilot

### How it Works
1. **Data Ingestion**: Processes user access logs and profiles
2. **Feature Engineering**: Extracts behavioral and contextual features
3. **Hybrid Scoring**: Combines ML anomaly detection with rule-based logic
4. **Risk Assessment**: Generates explainable risk scores with actionable insights
5. **Alert Generation**: Creates severity-based alerts for SOC response

👈 **Navigate using the sidebar to explore the system.**
""")
