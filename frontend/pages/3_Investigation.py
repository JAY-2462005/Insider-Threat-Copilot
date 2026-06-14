import streamlit as st
import pandas as pd
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from components.copilot import render_copilot_button
from data_service import get_alerts, get_alerts_dataframe, get_threshold, get_events_dataframe

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
    from llm_summary import generate_investigation_narrative, is_gemini_configured
    from flight_risk import generate_flight_risk_n_summary
    GEMINI_AVAILABLE = True
except Exception:
    GEMINI_AVAILABLE = False

st.set_page_config(page_title="Investigation Workbench", page_icon="🔍", layout="wide")

st.title("🔍 Analyst Investigation Workbench")

try:
    alerts = get_alerts(get_threshold())
    df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend alerts: {str(e)}")
    st.stop()

if df.empty:
    st.info("No alerts available at the selected threshold.")
    st.stop()

# --- 2. DEEP DIVE PANEL (Appears when an incident is selected) ---
inspect_id = st.session_state.get('selected_access_id')

if inspect_id and inspect_id in df['access_id'].values:
    st.markdown("---")
    alert = df[df['access_id'] == inspect_id].iloc[0]
    context = alert.get('raw_context', {})
    
    st.error(f"### 🎯 Active Target: `{alert['username']}` | Risk Score: {alert['risk_score']} ({alert['severity']})")
    
    col_left, col_right = st.columns(2)
    
    with col_left:
        # ⭐ THE KILLER FEATURE: Baseline vs Actual
        st.subheader("📊 Baseline vs. Observed Behavior")
        
        # Safely extract time strings
        timestamp_str = str(alert['timestamp'])
        event_time = timestamp_str.split(' ')[1] if ' ' in timestamp_str else timestamp_str
        
        baseline_comparison = pd.DataFrame({
            "Metric": ["Access Time", "Data Volume", "Destination", "Asset Accessed"],
            "Expected (Baseline)": [
                context.get('typical_access_hours', 'Standard Business Hours'),
                f"~{context.get('avg_rowcount_per_query', 100)} rows",
                "Internal Network",
                context.get('approved_data_assets', 'Role Standard')
            ],
            "Observed (Event)": [
                event_time,
                f"{context.get('rowcount', 'Unknown')} rows",
                context.get('destination', 'Unknown'),
                context.get('data_asset', 'Unknown')
            ]
        })
        st.table(baseline_comparison)
        
        # Flight Risk Assessment
        st.subheader("✈️ Pre-Breach Flight Risk Assessment")
        pre_breach_score = alert.get('pre_breach_score', 0)
        pre_breach_level = alert.get('pre_breach_level', 'LOW')
        flight_risk_reasons = alert.get('flight_risk_reasons', [])
        
        # Color-coded risk level
        risk_color = "🟢" if pre_breach_level == 'LOW' else "🟡" if pre_breach_level == 'WATCHLIST' else "🟠" if pre_breach_level == 'ELEVATED' else "🔴"
        
        st.markdown(f"**Risk Level:** {risk_color} **{pre_breach_level}** (Score: {pre_breach_score}/100)")
        
        if flight_risk_reasons:
            st.markdown("**Pre-Breach Indicators:**")
            for reason in flight_risk_reasons:
                st.markdown(f"• {reason}")
        else:
            st.info("No pre-breach indicators detected for this user.")
        
        # Timeline
        st.subheader("🕒 Incident Timeline")
        st.markdown(f"""
        * **{alert['timestamp']}** → `{context.get('query_type', 'ACCESS')}` execution detected.
        * **{alert['timestamp']}** → Payload routed to `{context.get('destination', 'Unknown')}`.
        * **{alert['timestamp']}** → TrustGuardian ML computed Risk Score of **{alert['risk_score']}**.
        * **{alert['timestamp']}** → Alert escalated to SOC as **{alert['severity']}**.
        """)

    with col_right:
        # Risk Breakdown
        st.subheader("🚨 Mathematical Risk Breakdown")
        for reason in alert.get('justification', []):
            st.markdown(f"- {reason}")
            
        # SOC Playbook
        st.subheader("⚡ SOC Playbook")
        for action in alert.get('recommended_actions', []):
            st.warning(action)

    # AI Verdict
    st.subheader("🤖 AI Copilot Verdict")
    
    if GEMINI_AVAILABLE and is_gemini_configured():
        with st.spinner("🔄 Generating AI analysis..."):
            ai_verdict = generate_investigation_narrative(alert.to_dict())
            st.success(ai_verdict)
    else:
        # Fallback to hardcoded verdict
        justifications = ", ".join([j.split(' (+')[0].strip() for j in alert.get('justification', [])])
        ai_verdict = f"""
        `{alert['username']}` significantly deviated from baseline behavior by accessing `{alert.get('data_asset', 'the database')}`
        ({context.get('rowcount', 'data')} records) to `{context.get('destination', 'an unapproved destination')}`.

        Risk factors: **{justifications}**.

        **Immediate SOC intervention recommended.**
        """
        st.info(ai_verdict)
    
    # AI Flight Risk Narrative
    st.subheader("✈️ AI Flight Risk Narrative")
    flight_risk_data = {
        'username': alert.get('username', 'Unknown'),
        'department': alert.get('department', 'Unknown'),
        'pre_breach_score': alert.get('pre_breach_score', 0),
        'pre_breach_level': alert.get('pre_breach_level', 'LOW'),
        'flight_risk_reasons': alert.get('flight_risk_reasons', [])
    }
    
    if GEMINI_AVAILABLE and is_gemini_configured():
        with st.spinner("🔄 Generating flight risk analysis..."):
            try:
                import google.generativeai as genai
                llm_client = genai.GenerativeModel('gemini-pro')
                flight_risk_narrative = generate_flight_risk_n_summary(flight_risk_data, llm_client)
                st.info(flight_risk_narrative)
            except Exception as e:
                # Fallback to template-based narrative
                flight_risk_narrative = generate_flight_risk_n_summary(flight_risk_data)
                st.info(flight_risk_narrative)
    else:
        # Use template-based narrative
        flight_risk_narrative = generate_flight_risk_n_summary(flight_risk_data)
        st.info(flight_risk_narrative)

    col_close, _ = st.columns([1, 4])
    with col_close:
        if st.button("✖️ Close Investigation"):
            st.session_state.pop('selected_access_id', None)
            st.rerun()

st.markdown("---")

# --- 3. SEARCH & FILTER WORKSPACE ---
st.subheader("Search & Filter Events")

col_search, col_dept = st.columns(2)
with col_search:
    search_username = st.text_input("Search by Username", "")
with col_dept:
    search_department = st.selectbox(
        "Filter by Department",
        ["All"] + sorted(df['department'].dropna().unique())
    )

filtered_df = df.copy()
if search_username:
    filtered_df = filtered_df[filtered_df['username'].str.contains(search_username, case=False, na=False)]
if search_department != "All":
    filtered_df = filtered_df[filtered_df['department'] == search_department]

st.subheader(f"High-Risk Activities ({len(filtered_df)} matches)")

# --- 4. INVESTIGATION QUEUE ---
if not filtered_df.empty:
    for _, row in filtered_df.iterrows():
        with st.container(border=True):
            col_info, col_risk, col_btn = st.columns([2, 1, 1])
            
            with col_info:
                st.markdown(f"**User:** `{row.get('username', 'N/A')}` &nbsp; | &nbsp; **Dept:** `{row.get('department', 'N/A')}`")
                st.markdown(f"**Time:** `{row['timestamp']}` &nbsp; | &nbsp; **Asset:** `{row.get('data_asset', 'N/A')}`")
            
            with col_risk:
                st.metric("Risk Score", f"{row['risk_score']:.1f}", delta=row['severity'], delta_color="inverse")
            
            with col_btn:
                st.write("") # Spacing
                if st.button("Investigate Incident", key=f"investigate_{row['access_id']}"):
                    st.session_state['selected_access_id'] = row['access_id']
                    st.rerun()
                if st.button(f"🤖 Ask Copilot: Why was {row.get('username', 'this user')} flagged?", key=f"detective_{row['access_id']}"):
                    st.session_state["detective_prompt"] = f"Why was {row.get('username', 'this user')} flagged with risk score {row['risk_score']}?"
                    st.switch_page("pages/8_Security_Copilot.py")
else:
    st.success("No high-risk activities found matching your filters.")

# --- 5. DATA EXPLORATION ---
st.markdown("<br>", unsafe_allow_html=True)
with st.expander("Explore Raw Dataset"):
    st.dataframe(filtered_df[['access_id', 'timestamp', 'username', 'department', 'data_asset', 'risk_score', 'severity']])

# Render context-aware Copilot button
st.markdown("---")
render_copilot_button(
    "Ask Copilot: Investigate flagged users",
    "Show me all critical incidents",
    key="investigation_copilot_btn",
)
