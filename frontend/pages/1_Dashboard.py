import streamlit as st
import plotly.express as px
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from components.kill_switch import (
    count_active_critical,
    init_isolated_users,
    is_critical_alert,
    is_user_isolated,
    render_neutralized_block,
    render_revoke_button,
)
from data_service import get_alerts_dataframe, get_events_dataframe, get_threshold

init_isolated_users()

st.set_page_config(page_title="Dashboard", page_icon="📊", layout="wide")
st.title("📊 Executive Dashboard")

try:
    events_df = get_events_dataframe()
    df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend data: {str(e)}")
    st.stop()

if events_df.empty:
    st.info("No backend events available yet.")
    st.stop()

# --- KPIs ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Backend Events Scored", len(events_df))
col2.metric("Total Flagged Events", len(df))
col3.metric("Critical Alerts", count_active_critical(df))
col4.metric("Avg Risk Score", f"{events_df['risk_score'].mean():.1f}")

st.markdown("---")

# --- TOP INCIDENT & KILL-SWITCH QUEUE ---
if not df.empty:
    top_alert = df.sort_values(by='risk_score', ascending=False).iloc[0]
    top_username = top_alert['username']

    if is_user_isolated(top_username):
        render_neutralized_block(top_username)
    else:
        st.error(
            f"""
            ### 🚨 TOP INCIDENT
            **User:** `{top_username}` | **Department:** `{top_alert['department']}`
            **Severity:** **{top_alert['severity']}** | **Risk Score:** **{top_alert['risk_score']}**
            """
        )
        if is_critical_alert(top_alert):
            render_revoke_button(top_alert, key_prefix="dash_top_")
else:
    st.success("✅ No active alerts above the selected threshold.")

st.markdown("---")

st.subheader("🔐 SOC Kill-Switch — Active Alerts")
if df.empty:
    st.info("No alerts to display.")
else:
    for _, alert in df.sort_values(by='risk_score', ascending=False).iterrows():
        username = alert['username']
        if is_user_isolated(username):
            render_neutralized_block(username)
            continue

        icon = "🔴" if alert['severity'] == "CRITICAL" else "🟠" if alert['severity'] == "HIGH" else "🟡"
        with st.container(border=True):
            st.markdown(
                f"{icon} **[{alert['severity']}]** `{alert['timestamp']}` | "
                f"**{username}** ({alert['department']}) | Risk: **{alert['risk_score']}**"
            )
            st.markdown(f"**Asset:** `{alert.get('data_asset', 'Unknown')}` → **Destination:** `{alert.get('destination', 'Unknown')}`")
            if is_critical_alert(alert):
                render_revoke_button(alert, key_prefix="dash_")

st.markdown("---")

# --- ROW 1: SEVERITY & DESTINATION ---
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("Severity Distribution")
    severity_source = df if not df.empty else events_df
    sev_counts = severity_source['severity'].value_counts().reset_index()
    sev_counts.columns = ['Severity', 'Count']
    color_map = {'CRITICAL': '#ff4b4b', 'HIGH': '#ffa421', 'MEDIUM': '#ffe312', 'LOW': '#00d46a'}
    fig1 = px.bar(sev_counts, x='Severity', y='Count', color='Severity', color_discrete_map=color_map)
    st.plotly_chart(fig1, use_container_width=True)

with col_chart2:
    st.subheader("Destination Risk Profile")
    destination_source = df if not df.empty else events_df
    dest_counts = destination_source['destination'].value_counts().reset_index()
    dest_counts.columns = ['Destination', 'Count']
    fig2 = px.pie(dest_counts, values='Count', names='Destination', hole=0.4)
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("---")

# --- ROW 2: DEPARTMENT & THREAT QUEUE ---
col_chart3, col_queue = st.columns(2)

with col_chart3:
    st.subheader("Department Risk Exposure")
    dept_risk = events_df.groupby('department', as_index=False)['risk_score'].mean()
    dept_risk = dept_risk.sort_values(by='risk_score', ascending=False)
    fig3 = px.bar(dept_risk, x='department', y='risk_score', color='department')
    fig3.update_layout(xaxis_title="Department", yaxis_title="Average Risk Score")
    st.plotly_chart(fig3, use_container_width=True)

with col_queue:
    st.subheader("🚨 Active Threat Queue")
    if df.empty:
        st.success("Queue is clear at the selected threshold.")
    else:
        st.dataframe(
            df[['timestamp', 'username', 'department', 'severity', 'risk_score']].sort_values(by='risk_score', ascending=False),
            use_container_width=True,
            hide_index=True
        )

st.markdown("---")

# --- INVESTIGATION PREVIEW ---
st.subheader("🔍 Investigation Preview")

if df.empty:
    st.info("No alert preview is available because the current threshold has no active alerts.")
else:
    selected_user = st.selectbox("Select User to Investigate:", sorted(df['username'].dropna().unique()))
    alert = df[df['username'] == selected_user].sort_values(by='risk_score', ascending=False).iloc[0]

    inv_col1, inv_col2 = st.columns(2)

    with inv_col1:
        st.markdown("**Why was this flagged?**")
        for reason in alert.get('justification', []):
            st.markdown(f"• {reason}")

    with inv_col2:
        st.markdown("**Recommended Actions:**")
        for action in alert.get('recommended_actions', []):
            st.markdown(f"• {action}")

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("🕒 Incident Timeline")
    st.markdown(
        f"""
        • **{alert['timestamp']}** → Suspicious activity detected
        • **{alert['timestamp']}** → Risk score calculated
        • **{alert['timestamp']}** → Alert escalated as **{alert['severity']}**
        """
    )

    st.markdown("<br>", unsafe_allow_html=True)

    justifications = ", ".join(alert.get('justification', []))
    summary = f"""
    🤖 **AI Copilot Summary**

    `{alert['username']}` from the `{alert['department']}` department triggered a **{alert['severity']}** insider threat alert involving `{alert.get('data_asset', 'Unknown Asset')}`.

    The activity received a risk score of **{alert['risk_score']}** due to: {justifications}.

    Immediate investigation is recommended.
    """
    st.info(summary)
