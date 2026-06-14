"""Shared UI theme and chart helpers for TrustGuardian."""

import pandas as pd
import plotly.express as px
import streamlit as st

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#16a34a",
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

DESTINATION_RISK = {
    "personal_usb": ("Critical", 5),
    "usb_drive": ("Critical", 5),
    "external_email": ("Critical", 5),
    "external_ip": ("Critical", 5),
    "cloud_storage": ("Elevated", 3),
    "internal_share": ("Standard", 2),
    "local_workstation": ("Standard", 1),
    "local": ("Standard", 1),
}

TIER_COLORS = {
    "Critical": "#dc2626",
    "Elevated": "#ea580c",
    "Standard": "#2563eb",
    "Unknown": "#94a3b8",
}


def inject_global_css():
    st.markdown(
        """
        <style>
        /* Enhanced Hero Section with Animation */
        .tg-hero {
            background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #312e81 100%);
            padding: 2rem 2.5rem;
            border-radius: 16px;
            margin-bottom: 1.5rem;
            color: #f8fafc;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            animation: fadeIn 0.5s ease-in;
        }
        .tg-hero h1 { margin: 0; font-size: 2rem; font-weight: 700; color: #f8fafc; }
        .tg-hero p  { margin: 0.5rem 0 0 0; color: #cbd5e1; font-size: 1rem; line-height: 1.5; }
        
        /* Enhanced Card Styling */
        .tg-card {
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 1rem 1.25rem;
            margin-bottom: 0.75rem;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .tg-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        .tg-muted { color: #64748b; font-size: 0.9rem; }
        
        /* Enhanced Metric Cards */
        div[data-testid="stMetric"] {
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 0.75rem 1rem;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        div[data-testid="stMetric"]:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        /* Enhanced Progress Bars */
        .bar-bg { background:#e2e8f0; border-radius:8px; height:22px; width:100%; margin:3px 0; }
        .bar-fill { border-radius:8px; height:22px; display:flex; align-items:center;
                    padding-left:10px; font-size:0.78rem; font-weight:600; color:white; 
                    animation: slideIn 0.5s ease-out; }
        
        /* Enhanced Phase Cards */
        .phase-card { background:#f8fafc; border-left:4px solid #312e81;
                      border-radius:8px; padding:0.8rem 1rem; margin:0.5rem 0;
                      box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
        
        /* Chat Message Enhancement */
        div[data-testid="stChatMessage"] { max-width:100%!important; }
        
        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes slideIn {
            from { width: 0; }
            to { width: var(--target-width); }
        }
        
        /* Button Enhancements */
        .stButton > button {
            transition: all 0.2s ease;
            border-radius: 8px;
        }
        .stButton > button:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        
        /* Container Enhancement */
        div[data-testid="stContainer"] {
            padding: 0.5rem 0;
        }
        
        /* Enhanced Selectbox */
        .stSelectbox > div > div > select {
            border-radius: 8px;
        }
        
        /* Dataframe Enhancement */
        .dataframe {
            border-radius: 8px;
            overflow: hidden;
        }
        
        /* Alert Enhancement */
        .stAlert {
            border-radius: 12px;
            box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
        }
        
        /* Info Box Enhancement */
        .stInfo {
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
            border-left: 4px solid #0284c7;
            border-radius: 8px;
        }
        
        /* Warning Box Enhancement */
        .stWarning {
            background: linear-gradient(135deg, #fffbeb 0%, #fef3c7 100%);
            border-left: 4px solid #f59e0b;
            border-radius: 8px;
        }
        
        /* Error Box Enhancement */
        .stError {
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
            border-left: 4px solid #dc2626;
            border-radius: 8px;
        }
        
        /* Success Box Enhancement */
        .stSuccess {
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            border-left: 4px solid #16a34a;
            border-radius: 8px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_hero(title: str, subtitle: str):
    st.markdown(
        f'<div class="tg-hero"><h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True,
    )


def build_threat_heatmap(df: pd.DataFrame):
    """Department vs severity heatmap with stable column ordering."""
    if df.empty or "department" not in df.columns or "severity" not in df.columns:
        return None

    heatmap_data = pd.crosstab(df["department"], df["severity"])
    for level in SEVERITY_ORDER:
        if level not in heatmap_data.columns:
            heatmap_data[level] = 0
    heatmap_data = heatmap_data[SEVERITY_ORDER]
    heatmap_data = heatmap_data.sort_index()

    fig = px.imshow(
        heatmap_data,
        text_auto=True,
        aspect="auto",
        color_continuous_scale=["#f8fafc", "#fecaca", "#f87171", "#dc2626"],
        labels=dict(x="Severity", y="Department", color="Alerts"),
    )
    fig.update_layout(
        height=380,
        margin=dict(l=10, r=10, t=30, b=10),
        xaxis_title="Severity",
        yaxis_title="Department",
    )
    return fig


def build_destination_risk_chart(df: pd.DataFrame):
    """Destination volume grouped by exfiltration risk tier."""
    if df.empty or "destination" not in df.columns:
        return None

    working = df.copy()
    working["destination"] = working["destination"].astype(str).str.lower()

    def tier_for(dest):
        return DESTINATION_RISK.get(dest, ("Unknown", 0))[0]

    def weight_for(dest):
        return DESTINATION_RISK.get(dest, ("Unknown", 0))[1]

    working["risk_tier"] = working["destination"].map(tier_for)
    working["risk_weight"] = working["destination"].map(weight_for)

    summary = (
        working.groupby(["risk_tier", "destination"], as_index=False)
        .agg(event_count=("destination", "count"), avg_risk=("risk_score", "mean"), risk_weight=("risk_weight", "first"))
        .sort_values(["risk_weight", "event_count"], ascending=[False, False])
    )

    fig = px.bar(
        summary,
        x="destination",
        y="event_count",
        color="risk_tier",
        color_discrete_map=TIER_COLORS,
        hover_data=["avg_risk", "risk_tier"],
        labels={
            "destination": "Destination",
            "event_count": "Events",
            "avg_risk": "Avg Risk Score",
            "risk_tier": "Risk Tier",
        },
        title="Destination Risk Profile",
    )
    fig.update_layout(
        height=360,
        xaxis_title="Export Destination",
        yaxis_title="Event Count",
        legend_title="Exfiltration Risk",
        margin=dict(l=10, r=10, t=40, b=10),
    )
    return fig


def enterprise_threat_level_label(avg_risk: float) -> str:
    if avg_risk >= 75:
        return "Critical — widespread high-risk activity; immediate SOC review"
    if avg_risk >= 50:
        return "Elevated — notable insider threat pressure across the environment"
    if avg_risk >= 30:
        return "Moderate — mixed activity; continue monitoring"
    return "Stable — most activity within normal baselines"
