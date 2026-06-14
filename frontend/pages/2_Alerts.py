import streamlit as st
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from components.kill_switch import (
    count_active_critical,
    filter_active_alerts,
    init_isolated_users,
    is_critical_alert,
    render_revoke_button,
)
from components.copilot import render_copilot_button
from components.theme import inject_global_css, render_hero
from data_service import get_alerts_dataframe, get_threshold

init_isolated_users()
inject_global_css()

st.set_page_config(page_title="Alerts Queue", layout="wide")
render_hero("Alerts Queue", "Filter, triage, and investigate flagged insider-threat events.")

try:
    df = get_alerts_dataframe(get_threshold())
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend alerts: {str(e)}")
    st.stop()

active_df = filter_active_alerts(df)

if active_df.empty and df.empty:
    st.success("No alerts detected above the selected threshold.")
    st.stop()

if active_df.empty and not df.empty:
    st.success("All alerts have been neutralized via kill-switch. Queue is clear.")
    st.stop()

# --- Filters ---
st.subheader("Filters")
col1, col2, col3 = st.columns(3)

with col1:
    sev_filter = st.selectbox("Severity", ["ALL"] + sorted(active_df["severity"].dropna().unique()))
with col2:
    dept_filter = st.selectbox("Department", ["ALL"] + sorted(active_df["department"].dropna().unique()))
with col3:
    user_filter = st.selectbox("Username", ["ALL"] + sorted(active_df["username"].dropna().unique()))

filtered_df = active_df.copy()
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
    st.success("No alerts match the selected filters.")
    st.stop()

# Enhanced metrics with icons and better visual appeal
stat1, stat2, stat3, stat4 = st.columns(4)
stat1.metric("👁️ Visible Alerts", len(filtered_df))
stat2.metric("🔴 Critical", count_active_critical(filtered_df))
stat3.metric("⚠️ Avg Risk", f"{filtered_df['risk_score'].mean():.1f}")
stat4.metric("🚫 Revoked Users", len(df) - len(active_df))

st.markdown("---")

# --- Expandable Rows ---
for _, row in filtered_df.iterrows():
    username = row["username"]

    expander_title = (
        f"[{row['severity']}] {row['timestamp']} | {username} "
        f"({row['department']}) | Risk {row['risk_score']}"
    )

    with st.expander(expander_title):
        if is_critical_alert(row):
            render_revoke_button(row, key_prefix="queue_")
            st.markdown("---")

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
        
        # --- Phase 2: Zero-Trust ChatOps Component ---
        if row.get('chatops_triggered', False):
            st.markdown("---")
            st.info(
                f"🤖 **Zero-Trust ChatOps Interrogation**\n\n"
                f"{row.get('chatops_message', '')}"
            )
            
            # Create columns for ChatOps action buttons
            col_yes, col_no, col_spacer = st.columns([1, 1, 2])
            
            # Initialize session state for this specific alert
            yes_key = f"chatops_yes_{row['access_id']}"
            no_key = f"chatops_no_{row['access_id']}"
            response_key = f"chatops_response_{row['access_id']}"
            
            # Track alert state changes
            if response_key not in st.session_state:
                st.session_state[response_key] = None
            
            with col_yes:
                if st.button("✅ Yes, verify via MFA", key=yes_key):
                    st.session_state[response_key] = "verified"
                    st.toast("✅ User verified. Alert downgraded to False Positive.", icon="✅")
                    st.rerun()
            
            with col_no:
                if st.button("❌ No, I didn't do this", key=no_key):
                    st.session_state[response_key] = "denied"
                    st.error("🚨 CRITICAL: Account Isolation Triggered.")
                    st.rerun()
            
            # Display response state if captured
            if st.session_state.get(response_key) == "verified":
                st.success("✅ **Status:** Alert Downgraded - User MFA Verified")
                st.markdown("This incident has been marked as a false positive.")
            elif st.session_state.get(response_key) == "denied":
                st.error(
                    "🚨 **Status:** CRITICAL - Account Isolation Active\n\n"
                    "**Actions Taken:**\n"
                    "• User account access suspended\n"
                    "• Network egress blocked\n"
                    "• SOC incident response activated\n"
                    "• Forensics and audit logging initiated"
                )
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # 4. Deep Dive Routing
        if st.button("Deep Dive Investigation", key=f"btn_{row['access_id']}"):
            # Save the ID to session state so the Investigation page knows what to load
            st.session_state['selected_access_id'] = row['access_id']
            st.switch_page("pages/3_Investigation.py")
        
        # 5. Data Detective Integration
        if st.button("Ask Copilot", key=f"detective_{row['access_id']}"):
            st.session_state["detective_prompt"] = f"Why was {username} flagged with risk score {row['risk_score']}?"
            st.switch_page("pages/8_Security_Copilot.py")

# Render context-aware Copilot button
st.markdown("---")
render_copilot_button(
    "Review critical alerts in Copilot",
    "Show me all critical incidents",
    key="alerts_copilot_btn",
)
