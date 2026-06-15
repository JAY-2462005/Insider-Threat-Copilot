import os
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from components.theme import (
    build_threat_heatmap,
    enterprise_threat_level_label,
    inject_global_css,
    render_hero,
)
from data_service import get_alerts_dataframe, get_events_dataframe, get_threshold

inject_global_css()
st.set_page_config(page_title="Analytics", layout="wide")
render_hero(
    "Security Analytics",
    "Enterprise threat posture, departmental exposure, and detection trigger analysis.",
)

try:
    events_df = get_events_dataframe()
    alerts_df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"Error loading backend events: {str(e)}")
    st.stop()

if events_df.empty:
    st.info("No backend events available for analytics.")
    st.stop()

heatmap_source = alerts_df if not alerts_df.empty else events_df[events_df["risk_score"] >= 50]

col_gauge, col_hist = st.columns(2)

with col_gauge:
    st.subheader("🎯 Enterprise Threat Level")
    avg_risk = events_df["risk_score"].mean()
    gauge_color = "#dc2626" if avg_risk >= 75 else "#ea580c" if avg_risk >= 50 else "#16a34a"

    fig_gauge = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=avg_risk,
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": gauge_color},
                "steps": [
                    {"range": [0, 30], "color": "rgba(22,163,74,0.12)"},
                    {"range": [30, 50], "color": "rgba(202,138,4,0.12)"},
                    {"range": [50, 75], "color": "rgba(234,88,12,0.12)"},
                    {"range": [75, 100], "color": "rgba(220,38,38,0.15)"},
                ],
            },
        )
    )
    fig_gauge.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.caption(
        f"**What this means:** {enterprise_threat_level_label(avg_risk)}. "
        "It is the average risk score across all scored access events — a single number "
        "leadership can use to track insider-threat pressure over time."
    )

with col_hist:
    st.subheader("📊 Risk Score Distribution")
    fig_hist = px.histogram(events_df, x="risk_score", nbins=20, color_discrete_sequence=["#2563eb"])
    fig_hist.update_layout(height=300, xaxis_title="Risk Score", yaxis_title="Event Count")
    st.plotly_chart(fig_hist, use_container_width=True)

st.markdown("---")

col_heat, col_assets = st.columns(2)

with col_heat:
    st.subheader("🔥 Threat Heatmap")
    st.caption("Department × severity for active alerts (falls back to elevated events if queue is empty).")
    fig_heat = build_threat_heatmap(heatmap_source)
    if fig_heat:
        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("Not enough data to render heatmap.")

with col_assets:
    st.subheader("🎯 Top Threat Assets")
    asset_risk = events_df.groupby("data_asset")["risk_score"].mean().sort_values(ascending=False).head(10).reset_index()
    fig_assets = px.bar(
        asset_risk,
        x="data_asset",
        y="risk_score",
        color="risk_score",
        color_continuous_scale="Reds",
    )
    fig_assets.update_layout(height=380, xaxis_title="Data Asset", yaxis_title="Average Risk Score")
    st.plotly_chart(fig_assets, use_container_width=True)

st.markdown("---")

col_users, col_triggers = st.columns(2)

with col_users:
    st.subheader("👤 Top Risk Users")
    user_risk = events_df.groupby("username")["risk_score"].mean().sort_values(ascending=False).head(10).reset_index()
    fig_users = px.bar(
        user_risk,
        x="risk_score",
        y="username",
        orientation="h",
        color="risk_score",
        color_continuous_scale="Oranges",
    )
    fig_users.update_layout(height=400, yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig_users, use_container_width=True)

with col_triggers:
    st.subheader("⚡ Detection Trigger Frequency")
    all_triggers = []
    for justifications in events_df["justification"].dropna():
        for reason in justifications:
            clean_reason = reason.split(" (+")[0]
            if "Expected Seasonality" not in clean_reason:
                all_triggers.append(clean_reason)

    if all_triggers:
        trigger_df = pd.Series(all_triggers).value_counts().reset_index()
        trigger_df.columns = ["Triggered Rule", "Count"]
        fig_triggers = px.bar(
            trigger_df.head(10),
            x="Count",
            y="Triggered Rule",
            orientation="h",
            color_discrete_sequence=["#4f46e5"],
        )
        fig_triggers.update_layout(height=400, yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig_triggers, use_container_width=True)
    else:
        st.info("No trigger data available.")
