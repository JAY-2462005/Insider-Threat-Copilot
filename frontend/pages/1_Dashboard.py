import os
import sys

import plotly.express as px
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
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
from components.theme import build_destination_risk_chart, inject_global_css, render_hero
from data_service import get_alerts_dataframe, get_events_dataframe, get_threshold

init_isolated_users()
inject_global_css()

st.set_page_config(page_title="Executive Dashboard", layout="wide")
render_hero(
    "Executive Dashboard",
    "Operational view of active threats, kill-switch queue, and organizational risk exposure.",
)

try:
    events_df = get_events_dataframe()
    alerts_df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"Error loading backend data: {str(e)}")
    st.stop()

if events_df.empty:
    st.info("No backend events available yet.")
    st.stop()

active_alerts = filter_active_alerts(alerts_df)

# Enhanced metrics with icons and better visual hierarchy
col1, col2, col3, col4 = st.columns(4)
col1.metric("📊 Events Scored", len(events_df))
col2.metric("🚨 Active Alerts", count_active_alerts(alerts_df))
col3.metric("🔴 Critical (Active)", count_active_critical(alerts_df))
col4.metric("⚠️ Avg Risk Score", f"{events_df['risk_score'].mean():.1f}")

st.markdown("---")

if not active_alerts.empty:
    top_alert = active_alerts.sort_values(by="risk_score", ascending=False).iloc[0]
    top_username = top_alert["username"]
    st.error(
        f"**Top Incident** — `{top_username}` ({top_alert['department']}) · "
        f"**{top_alert['severity']}** · Risk **{top_alert['risk_score']}**"
    )
    if is_critical_alert(top_alert):
        render_revoke_button(top_alert, key_prefix="dash_top_")
else:
    st.success("No active alerts above the selected threshold.")

st.markdown("---")
st.subheader("SOC Kill-Switch Queue")

if active_alerts.empty:
    st.info("Queue is clear — all critical accounts neutralized or no alerts at this threshold.")
else:
    for _, alert in active_alerts.sort_values(by="risk_score", ascending=False).head(12).iterrows():
        username = alert["username"]
        if is_user_isolated(username):
            render_neutralized_block(username)
            continue

        severity = alert["severity"]
        with st.container(border=True):
            st.markdown(
                f"**[{severity}]** `{alert['timestamp']}` — **{username}** "
                f"({alert['department']}) · Risk **{alert['risk_score']}**"
            )
            st.caption(
                f"Asset: `{alert.get('data_asset', 'Unknown')}` → "
                f"`{alert.get('destination', 'Unknown')}`"
            )
            if is_critical_alert(alert):
                render_revoke_button(alert, key_prefix="dash_")

st.markdown("---")

col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("Severity Distribution")
    severity_source = active_alerts if not active_alerts.empty else events_df
    sev_counts = severity_source["severity"].value_counts().reset_index()
    sev_counts.columns = ["Severity", "Count"]
    color_map = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
    fig1 = px.bar(sev_counts, x="Severity", y="Count", color="Severity", color_discrete_map=color_map)
    fig1.update_layout(showlegend=False, height=320, margin=dict(l=10, r=10, t=10, b=10))
    st.plotly_chart(fig1, use_container_width=True)

with col_chart2:
    st.subheader("Destination Risk Profile")
    dest_source = active_alerts if not active_alerts.empty else events_df
    fig2 = build_destination_risk_chart(dest_source)
    if fig2:
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No destination data available.")

st.markdown("---")

col_chart3, col_queue = st.columns(2)

with col_chart3:
    st.subheader("Department Risk Exposure")
    dept_risk = events_df.groupby("department", as_index=False)["risk_score"].mean()
    dept_risk = dept_risk.sort_values(by="risk_score", ascending=False)
    fig3 = px.bar(dept_risk, x="department", y="risk_score", color="risk_score", color_continuous_scale="Reds")
    fig3.update_layout(
        xaxis_title="Department",
        yaxis_title="Average Risk Score",
        showlegend=False,
        height=320,
        margin=dict(l=10, r=10, t=10, b=10),
    )
    st.plotly_chart(fig3, use_container_width=True)

with col_queue:
    st.subheader("Active Threat Queue")
    if active_alerts.empty:
        st.success("No active alerts in queue.")
    else:
        st.dataframe(
            active_alerts[["timestamp", "username", "department", "severity", "risk_score"]]
            .sort_values(by="risk_score", ascending=False),
            use_container_width=True,
            hide_index=True,
        )

st.markdown("---")
st.subheader("Investigation Preview")

if active_alerts.empty:
    st.info("No alert preview available at the current threshold.")
else:
    selected_user = st.selectbox(
        "Select user to preview",
        sorted(active_alerts["username"].dropna().unique()),
    )
    alert = active_alerts[active_alerts["username"] == selected_user].sort_values(
        by="risk_score", ascending=False
    ).iloc[0]

    inv_col1, inv_col2 = st.columns(2)
    with inv_col1:
        st.markdown("**Contributing factors**")
        for reason in alert.get("justification", []):
            st.markdown(f"- {reason}")
    with inv_col2:
        st.markdown("**Recommended actions**")
        for action in alert.get("recommended_actions", []):
            st.markdown(f"- {action}")

    justifications = ", ".join(alert.get("justification", []))
    st.info(
        f"`{alert['username']}` ({alert['department']}) triggered a **{alert['severity']}** alert "
        f"on `{alert.get('data_asset', 'Unknown')}` with risk **{alert['risk_score']}**. "
        f"Drivers: {justifications or 'see breakdown above'}."
    )
