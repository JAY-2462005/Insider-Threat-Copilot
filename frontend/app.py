import streamlit as st
import os
import sys

# Add backend to path so we can import the detector
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'backend'))
from detector import get_alerts_for_ui

st.set_page_config(
    page_title="Insider Threat Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

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

# Initialize threshold in session state
if "threshold" not in st.session_state:
    st.session_state["threshold"] = 70

# Dynamic Threshold Slider
new_threshold = st.sidebar.slider(
    "Risk Score Threshold", 
    0, 100, 
    st.session_state["threshold"], 5
)

# Data Paths
logs_path = os.path.join(os.path.dirname(__file__), 'data', 'data_access_logs.csv')
profiles_path = os.path.join(os.path.dirname(__file__), 'data', 'user_profiles.csv')

# Load alerts ONLY if missing OR if the user changes the threshold slider
if 'alerts' not in st.session_state or new_threshold != st.session_state["threshold"]:
    st.session_state["threshold"] = new_threshold
    try:
        with st.spinner("Analyzing access logs & updating ML predictions..."):
            st.session_state['alerts'] = get_alerts_for_ui(logs_path, profiles_path, new_threshold)
    except Exception as e:
        st.sidebar.error(f"Failed to load alerts: {e}")
        st.session_state['alerts'] = []

# Main content - Home Page
st.title("🛡️ Insider Threat Detection System")

# Quick Stats & Top Incident (Immediate visual impact for judges)
alerts = st.session_state.get("alerts", [])
if alerts:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Active Alerts", len(alerts))
    col2.metric("Critical", len([a for a in alerts if a['severity'] == "CRITICAL"]))
    col3.metric("High", len([a for a in alerts if a['severity'] == "HIGH"]))
    col4.metric("Users Monitored", len(set(a['username'] for a in alerts)))
    
    # Top Incident Hook
    top_alert = max(alerts, key=lambda x: x["risk_score"])
    st.error(
        f"""
        ### 🚨 Top Incident
        **User:** `{top_alert['username']}` | **Department:** `{top_alert['department']}`  
        **Severity:** **{top_alert['severity']}** | **Risk Score:** **{top_alert['risk_score']}**
        """
    )
    st.markdown("---")
else:
    st.info("✅ No alerts detected above the selected threshold.")
    st.markdown("---")

st.markdown("""
Welcome to the **Insider Threat Copilot** - an AI-powered platform for detecting and investigating 
suspicious insider threats in real-time.

### Key Features
- 🔍 **Real-time Detection**: ML-powered anomaly detection with rule-based scoring
- 📊 **Advanced Analytics**: Comprehensive data access patterns analysis
- 🚨 **Smart Alerts**: Severity-based alert system with recommended actions
- 🔎 **Investigation Tools**: Deep dive into user activities and behavioral patterns
- 🤖 **AI Summary**: Automated insights and threat intelligence

### How it Works
1. **Data Ingestion**: Processes user access logs and profiles
2. **Feature Engineering**: Extracts behavioral and contextual features
3. **Hybrid Scoring**: Combines ML anomaly detection with rule-based logic
4. **Risk Assessment**: Generates explainable risk scores with actionable insights
5. **Alert Generation**: Creates severity-based alerts for SOC response

👈 **Navigate using the sidebar to explore the system.**
""")