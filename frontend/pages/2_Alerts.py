import streamlit as st
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_alerts_dataframe, get_threshold

st.set_page_config(page_title="Alerts Queue", page_icon="🚨", layout="wide")
st.title("🚨 Full Threat Queue")

try:
    df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend alerts: {str(e)}")
    st.stop()

if df.empty:
    st.success("✅ No alerts detected above the selected threshold. Queue is clear.")
    st.stop()

# --- Filters ---
st.subheader("Filter Threats")
col1, col2, col3 = st.columns(3)

with col1:
    sev_filter = st.selectbox("Severity", ["ALL"] + sorted(df['severity'].dropna().unique()))
with col2:
    dept_filter = st.selectbox("Department", ["ALL"] + sorted(df['department'].dropna().unique()))
with col3:
    user_filter = st.selectbox("Username", ["ALL"] + sorted(df['username'].dropna().unique()))

# --- Apply Filters ---
filtered_df = df.copy()
if sev_filter != "ALL":
    filtered_df = filtered_df[filtered_df['severity'] == sev_filter]
if dept_filter != "ALL":
    filtered_df = filtered_df[filtered_df['department'] == dept_filter]
if user_filter != "ALL":
    filtered_df = filtered_df[filtered_df['username'] == user_filter]

filtered_df = filtered_df.sort_values(by='risk_score', ascending=False)

st.markdown("---")

# --- Quick Stats & Empty State Handling ---
if filtered_df.empty:
    st.success("✅ No alerts match the selected filters. Queue is clear.")
    st.stop()
else:
    stat1, stat2, stat3 = st.columns(3)
    stat1.metric("Visible Alerts", len(filtered_df))
    stat2.metric("Critical", len(filtered_df[filtered_df['severity'] == "CRITICAL"]))
    stat3.metric("Avg Risk Score", f"{filtered_df['risk_score'].mean():.1f}")

st.markdown("---")

# --- Expandable Rows ---
for _, row in filtered_df.iterrows():
    # Color-code the severity icon
    icon = "🔴" if row['severity'] == "CRITICAL" else "🟠" if row['severity'] == "HIGH" else "🟡"
    
    # 1. Severity Badge & Professional Title
    expander_title = f"{icon} [{row['severity']}] {row['timestamp']} | {row['username']} ({row['department']}) | Risk: {row['risk_score']}"
    
    with st.expander(expander_title):
        # 2 & 3. Data Asset and Timestamp Cards
        st.markdown(f"**Data Asset:** `{row.get('data_asset', 'Unknown')}` &nbsp; | &nbsp; **Incident Time:** `{row['timestamp']}`")
        st.markdown("---")
        
        col_just, col_act = st.columns(2)
        
        with col_just:
            st.markdown("**Triggered Rules:**")
            for reason in row.get('justification', []):
                st.markdown(f"• {reason}")
                
        with col_act:
            st.markdown("**SOC Actions:**")
            for action in row.get('recommended_actions', []):
                st.markdown(f"• {action}")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # 4. Deep Dive Routing
        if st.button("Deep Dive Investigation", key=f"btn_{row['access_id']}"):
            # Save the ID to session state so the Investigation page knows what to load
            st.session_state['selected_access_id'] = row['access_id']
            st.switch_page("pages/3_Investigation.py")
