import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="Dashboard", layout="wide")
st.title("📊 Executive Dashboard")

alerts = st.session_state.get('alerts', [])
if not alerts:
    st.info("No alerts available. Please generate alerts from the backend.")
    st.stop()

df = pd.DataFrame(alerts)

# --- KPIs ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Flagged Events", len(df))
col2.metric("Critical Alerts", len(df[df['severity'] == 'CRITICAL']))
col3.metric("High Alerts", len(df[df['severity'] == 'HIGH']))
col4.metric("Avg Risk Score", f"{df['risk_score'].mean():.1f}")

st.markdown("---")

# --- TOP INCIDENT ---
# BUG FIXED: Added .iloc to prevent runtime crashes
top_alert = df.sort_values(
    by='risk_score',
    ascending=False
).iloc[0]
st.error(
    f"""
    ### 🚨 TOP INCIDENT
    **User:** `{top_alert['username']}` | **Department:** `{top_alert['department']}`  
    **Severity:** **{top_alert['severity']}** | **Risk Score:** **{top_alert['risk_score']}**
    """
)

st.markdown("---")

# --- ROW 1: SEVERITY & DESTINATION ---
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("Severity Distribution")
    sev_counts = df['severity'].value_counts().reset_index()
    sev_counts.columns = ['Severity', 'Count']
    color_map = {'CRITICAL': '#ff4b4b', 'HIGH': '#ffa421', 'MEDIUM': '#ffe312', 'LOW': '#00d46a'}
    fig1 = px.bar(sev_counts, x='Severity', y='Count', color='Severity', color_discrete_map=color_map)
    st.plotly_chart(fig1, use_container_width=True)

with col_chart2:
    st.subheader("Destination Risk Profile")
    df['destination'] = df['raw_context'].apply(lambda x: x.get('destination', 'Unknown') if isinstance(x, dict) else 'Unknown')
    dest_counts = df['destination'].value_counts().reset_index()
    dest_counts.columns = ['Destination', 'Count']
    fig2 = px.pie(dest_counts, values='Count', names='Destination', hole=0.4)
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("---")

# --- ROW 2: DEPARTMENT & THREAT QUEUE ---
col_chart3, col_queue = st.columns(2)

with col_chart3:
    st.subheader("Department Risk Exposure")
    dept_counts = df['department'].value_counts().reset_index()
    dept_counts.columns = ['Department', 'Count']
    fig3 = px.bar(dept_counts, x='Department', y='Count', color='Department')
    st.plotly_chart(fig3, use_container_width=True)

with col_queue:
    st.subheader("🚨 Active Threat Queue")
    st.dataframe(
        df[['timestamp', 'username', 'department', 'severity', 'risk_score']].sort_values(by='risk_score', ascending=False),
        use_container_width=True,
        hide_index=True
    )

st.markdown("---")

# --- INVESTIGATION PREVIEW ---
st.subheader("🔍 Investigation Preview")

selected_user = st.selectbox("Select User to Investigate:", df['username'].unique())
# BUG FIXED: Added .iloc 
alert = df[
    df['username'] == selected_user
].iloc[0]

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

# --- INCIDENT TIMELINE ---
st.subheader("🕒 Incident Timeline")
st.markdown(
    f"""
    • **{alert['timestamp']}** → Suspicious activity detected
    • **{alert['timestamp']}** → Risk score calculated
    • **{alert['timestamp']}** → Alert escalated as **{alert['severity']}**
    """
)

st.markdown("<br>", unsafe_allow_html=True)

# --- AI SUMMARY BOX ---
justifications = ", ".join(alert.get('justification', []))
summary = f"""
🤖 **AI Copilot Summary**

`{alert['username']}` from the `{alert['department']}` department triggered a **{alert['severity']}** insider threat alert involving `{alert.get('data_asset', 'Unknown Asset')}`.

The activity received a risk score of **{alert['risk_score']}** due to: {justifications}.

Immediate investigation is recommended.
"""
st.info(summary)