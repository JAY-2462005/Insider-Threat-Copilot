import os
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from components.theme import inject_global_css, render_hero
from data_service import get_alerts, get_alerts_dataframe, get_threshold

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))
    from llm_summary import (
        fallback_executive_summary,
        generate_executive_summary,
        is_gemini_configured,
    )
    GEMINI_AVAILABLE = True
except Exception:
    GEMINI_AVAILABLE = False

inject_global_css()
st.set_page_config(page_title="AI Summary", layout="wide")
render_hero(
    "AI Threat Briefing",
    "Executive-ready summary of the current alert landscape and priority response areas.",
)

try:
    alerts = get_alerts(get_threshold())
    alerts_df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"Error loading backend alerts: {str(e)}")
    st.stop()

if not alerts:
    st.success("No critical threats above threshold. Security posture is healthy.")
    st.stop()

critical = len([a for a in alerts if a["severity"] == "CRITICAL"])
high = len([a for a in alerts if a["severity"] == "HIGH"])
medium = len([a for a in alerts if a["severity"] == "MEDIUM"])
low = len([a for a in alerts if a["severity"] == "LOW"])
avg_risk = sum(a["risk_score"] for a in alerts) / len(alerts)
max_risk = max(a["risk_score"] for a in alerts)

# Enhanced metrics with icons and better layout
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("🚨 Active Alerts", len(alerts))
col2.metric("🔴 Critical", critical, delta_color="inverse")
col3.metric("🟠 High", high, delta_color="inverse")
col4.metric("📊 Avg Risk", f"{avg_risk:.1f}")
col5.metric("⚠️ Max Risk", f"{max_risk:.1f}")

st.markdown("---")

# Executive Threat Level Gauge
col_gauge, col_summary = st.columns([1, 2])

with col_gauge:
    st.subheader("🎯 Enterprise Threat Level")
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
    fig_gauge.update_layout(height=280, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig_gauge, use_container_width=True)
    
    # Threat level interpretation
    if avg_risk >= 75:
        st.error("🔴 **CRITICAL** - Immediate executive attention required")
    elif avg_risk >= 50:
        st.warning("🟠 **ELEVATED** - Enhanced monitoring recommended")
    else:
        st.success("🟢 **MANAGED** - Normal threat levels")

with col_summary:
    st.subheader("📋 Executive Summary")
    if GEMINI_AVAILABLE and is_gemini_configured():
        with st.spinner("🔄 Generating AI-powered briefing..."):
            ai_briefing = generate_executive_summary(alerts)
            st.success(ai_briefing)
    else:
        st.info(fallback_executive_summary(alerts))
        st.caption("💡 Using rule-based briefing. Add GEMINI_API_KEY to .env for AI-enhanced narratives.")

st.markdown("---")

# Enhanced threat patterns with visualization
col_patterns, col_severity = st.columns(2)

with col_patterns:
    st.subheader("🔍 Top Threat Patterns")
    patterns = {}
    for alert in alerts:
        for reason in alert.get("justification", []):
            label = reason.split("(")[0].strip()
            patterns[label] = patterns.get(label, 0) + 1
    
    if patterns:
        pattern_df = pd.DataFrame(
            sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:8],
            columns=["Pattern", "Count"]
        )
        pattern_df["Percentage"] = (pattern_df["Count"] / len(alerts) * 100).round(1)
        
        fig_patterns = px.bar(
            pattern_df,
            x="Count",
            y="Pattern",
            orientation="h",
            color="Percentage",
            color_continuous_scale="Reds",
            title="Threat Pattern Distribution"
        )
        fig_patterns.update_layout(height=350, yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig_patterns, use_container_width=True)
    else:
        st.info("No threat patterns detected.")

with col_severity:
    st.subheader("📊 Severity Distribution")
    severity_data = pd.DataFrame({
        "Severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "Count": [critical, high, medium, low]
    })
    severity_data = severity_data[severity_data["Count"] > 0]
    
    if not severity_data.empty:
        color_map = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#16a34a"}
        fig_severity = px.pie(
            severity_data,
            values="Count",
            names="Severity",
            color="Severity",
            color_discrete_map=color_map,
            hole=0.4
        )
        fig_severity.update_layout(height=350, margin=dict(l=20, r=20, t=30, b=20))
        st.plotly_chart(fig_severity, use_container_width=True)
    else:
        st.info("No severity data available.")

st.markdown("---")

# Risk trend analysis and department breakdown
col_risk, col_dept = st.columns(2)

with col_risk:
    st.subheader("📈 Risk Score Distribution")
    if not alerts_df.empty:
        fig_risk = px.histogram(
            alerts_df,
            x="risk_score",
            nbins=20,
            color_discrete_sequence=["#4f46e5"],
            title="Risk Score Distribution"
        )
        fig_risk.update_layout(height=300, xaxis_title="Risk Score", yaxis_title="Alert Count")
        st.plotly_chart(fig_risk, use_container_width=True)
    else:
        st.info("No risk distribution data available.")

with col_dept:
    st.subheader("🏢 Department Exposure")
    if not alerts_df.empty:
        dept_risk = alerts_df.groupby("department")["risk_score"].mean().sort_values(ascending=False).head(8).reset_index()
        fig_dept = px.bar(
            dept_risk,
            x="risk_score",
            y="department",
            orientation="h",
            color="risk_score",
            color_continuous_scale="Oranges",
            title="Average Risk by Department"
        )
        fig_dept.update_layout(height=300, yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(fig_dept, use_container_width=True)
    else:
        st.info("No department data available.")

st.markdown("---")

# Enhanced priority actions with timeline
col_actions, col_timeline = st.columns([2, 1])

with col_actions:
    st.subheader("⚡ Priority Response Actions")
    recommendations = []
    
    if critical > 0:
        recommendations.append({
            "priority": "🔴 CRITICAL",
            "action": f"Escalate {critical} CRITICAL alerts to SOC Tier-2 immediately for immediate containment.",
            "timeframe": "Within 1 hour"
        })
    if high > 2:
        recommendations.append({
            "priority": "🟠 HIGH",
            "action": f"Review {high} HIGH alerts - assign analysts for investigation within 4 hours.",
            "timeframe": "Within 4 hours"
        })
    if any("Off-hours" in str(a.get("justification", [])) for a in alerts):
        recommendations.append({
            "priority": "🟡 MEDIUM",
            "action": "Review off-hours access policies for affected departments and implement enhanced monitoring.",
            "timeframe": "Within 24 hours"
        })
    if any("USB" in str(a.get("justification", [])) or "External" in str(a.get("justification", [])) for a in alerts):
        recommendations.append({
            "priority": "🟡 MEDIUM",
            "action": "Tighten DLP controls on removable media and external destinations.",
            "timeframe": "Within 48 hours"
        })
    
    if not recommendations:
        recommendations.append({
            "priority": "🟢 LOW",
            "action": "Continue standard monitoring. Current threat levels are manageable.",
            "timeframe": "Ongoing"
        })
    
    for i, rec in enumerate(recommendations, 1):
        with st.container(border=True):
            st.markdown(f"**{rec['priority']}** - {rec['action']}")
            st.caption(f"⏰ Target: {rec['timeframe']}")

with col_timeline:
    st.subheader("🕒 Response Timeline")
    timeline_data = []
    if critical > 0:
        timeline_data.append({"Stage": "Immediate", "Actions": critical, "Color": "🔴"})
    if high > 0:
        timeline_data.append({"Stage": "Today", "Actions": high, "Color": "🟠"})
    if medium > 0:
        timeline_data.append({"Stage": "This Week", "Actions": medium, "Color": "🟡"})
    
    if timeline_data:
        timeline_df = pd.DataFrame(timeline_data)
        fig_timeline = px.scatter(
            timeline_df,
            x="Stage",
            y="Actions",
            size="Actions",
            color="Stage",
            size_max=50,
            title="Response Priority Timeline"
        )
        fig_timeline.update_layout(height=300, showlegend=False)
        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No timeline data available.")

st.markdown("---")

# Key insights and AI recommendations
col_insights, col_recommendations = st.columns(2)

with col_insights:
    st.subheader("💡 Key Insights")
    insights = []
    
    # Generate insights based on data
    if critical > 0:
        insights.append(f"🔴 {critical} critical threats require immediate executive attention")
    if avg_risk > 70:
        insights.append(f"⚠️ Overall threat environment is elevated (avg risk: {avg_risk:.1f})")
    if len(alerts) > 10:
        insights.append(f"📊 High volume of alerts ({len(alerts)}) indicates increased threat activity")
    
    # Top pattern insight
    if patterns:
        top_pattern = max(patterns, key=patterns.get)
        insights.append(f"🎯 Primary threat pattern: '{top_pattern}' ({patterns[top_pattern]} occurrences)")
    
    # Department insight
    if not alerts_df.empty:
        top_dept = alerts_df.groupby("department")["risk_score"].mean().idxmax()
        insights.append(f"🏢 Highest risk department: {top_dept}")
    
    for insight in insights:
        st.info(insight)

with col_recommendations:
    st.subheader("🤖 AI Strategic Recommendations")
    strategic_recs = [
        "📈 Implement automated threat scoring to reduce analyst workload by 40%",
        "🔐 Enhance monitoring for high-risk departments identified in current analysis",
        "🎯 Conduct targeted security awareness training for affected user groups",
        "⚡ Deploy behavioral baselines for early detection of anomalous activities",
        "📊 Establish weekly threat briefing for executive leadership"
    ]
    
    for rec in strategic_recs:
        st.success(rec)

st.markdown("---")
st.caption("🔍 For detailed per-alert analysis, use **Investigation Workbench** or **Security Copilot** for AI-powered queries.")
