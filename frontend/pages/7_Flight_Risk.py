import os
import sys

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from components.copilot import render_copilot_button
from components.theme import inject_global_css, render_hero
from data_service import get_events_dataframe, get_flight_risk_data

inject_global_css()
st.set_page_config(page_title="Flight Risk Radar", layout="wide")
render_hero(
    "Flight Risk Radar",
    "Predict insider threats before exfiltration using pre-breach behavioral drift — not breach indicators.",
)

try:
    flight_risk_summary = get_flight_risk_data()
    df = get_events_dataframe()
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend events: {str(e)}")
    st.stop()

if df.empty:
    st.info("No backend events available for flight risk analysis.")
    st.stop()

# --- ROW 1: ENTERPRISE PRESSURE INDEX & DISTRIBUTION ---
col_gauge, col_dist = st.columns(2)

with col_gauge:
    st.subheader("📈 Enterprise Insider Pressure Index")
    avg_pre_breach = flight_risk_summary.get('enterprise_pressure_index', 0)
    
    # Dynamic coloring based on pressure level
    gauge_color = "#ff4b4b" if avg_pre_breach >= 75 else "#ffa421" if avg_pre_breach >= 50 else "#00d46a"
    
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=avg_pre_breach,
        title={'text': "Average Pre-Breach Score"},
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': gauge_color},
            'steps': [
                {'range': [0, 30], 'color': "rgba(0,212,106,0.1)"},
                {'range': [30, 60], 'color': "rgba(255,164,33,0.1)"},
                {'range': [60, 80], 'color': "rgba(255,164,33,0.2)"},
                {'range': [80, 100], 'color': "rgba(255,75,75,0.2)"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    fig_gauge.update_layout(height=350, margin=dict(l=20, r=20, t=50, b=20))
    st.plotly_chart(fig_gauge, use_container_width=True)

with col_dist:
    st.subheader("🎯 Flight Risk Level Distribution")
    
    risk_distribution = flight_risk_summary.get('risk_distribution', {})
    
    if risk_distribution:
        level_counts = pd.DataFrame(list(risk_distribution.items()), columns=['Risk Level', 'Count'])
        
        # Define order and colors
        level_order = ['LOW', 'WATCHLIST', 'ELEVATED', 'HIGH FLIGHT RISK']
        level_colors = {'LOW': '#00d46a', 'WATCHLIST': '#ffa421', 'ELEVATED': '#ff8c00', 'HIGH FLIGHT RISK': '#ff4b4b'}
        
        level_counts = level_counts[level_counts['Risk Level'].isin(level_order)]
        level_counts['Risk Level'] = pd.Categorical(level_counts['Risk Level'], categories=level_order, ordered=True)
        level_counts = level_counts.sort_values('Risk Level')
        
        fig_dist = px.bar(
            level_counts,
            x='Risk Level',
            y='Count',
            color='Risk Level',
            color_discrete_map=level_colors
        )
        fig_dist.update_layout(height=350, xaxis_title="Risk Level", yaxis_title="User Count")
        st.plotly_chart(fig_dist, use_container_width=True)
    else:
        st.info("No risk distribution data available.")

st.markdown("---")

# --- ROW 2: TOP 10 USERS LIKELY TO BREACH ---
st.subheader("🚨 Top 10 Watchlist")

top_risk_users = flight_risk_summary.get('top_risk_users', [])

if not top_risk_users:
    st.info("No flight risk data available.")
else:
    # Create display dataframe
    display_df = pd.DataFrame(top_risk_users)
    display_df = display_df[['username', 'department', 'pre_breach_score', 'pre_breach_level']].copy()
    display_df.columns = ['User', 'Department', 'Score', 'Level']
    
    # Add color coding for levels
    def color_level(level):
        if level == 'HIGH FLIGHT RISK':
            return 'background-color: #ff4b4b; color: white'
        elif level == 'ELEVATED':
            return 'background-color: #ff8c00; color: white'
        elif level == 'WATCHLIST':
            return 'background-color: #ffa421; color: black'
        else:
            return 'background-color: #00d46a; color: black'
    
    styled_df = display_df.style.map(color_level, subset=['Level'])
    st.dataframe(styled_df, use_container_width=True, hide_index=True)

st.markdown("---")

# --- ROW 3: FLIGHT RISK DRIVERS ---
st.subheader("🔍 Flight Risk Drivers")

col_drivers, col_trend = st.columns(2)

with col_drivers:
    st.markdown("**Most Common Flight Risk Indicators**")
    
    # Extract all flight risk reasons
    all_reasons = []
    for reasons in df['flight_risk_reasons'].dropna():
        if isinstance(reasons, list):
            all_reasons.extend(reasons)
    
    if all_reasons:
        reason_counts = pd.Series(all_reasons).value_counts().reset_index()
        reason_counts.columns = ['Risk Indicator', 'Count']
        
        fig_reasons = px.bar(
            reason_counts.head(10),
            x='Count',
            y='Risk Indicator',
            orientation='h',
            color_discrete_sequence=['#8338ec']
        )
        fig_reasons.update_layout(height=400, yaxis={'categoryorder': 'total ascending'})
        st.plotly_chart(fig_reasons, use_container_width=True)
    else:
        st.info("No flight risk indicators detected yet.")

with col_trend:
    st.markdown("**Pre-Breach Score vs Actual Risk Score**")
    
    # Scatter plot comparing pre_breach_score with risk_score
    fig_scatter = px.scatter(
        df.sample(min(500, len(df))),  # Sample for performance
        x='pre_breach_score',
        y='risk_score',
        color='pre_breach_level',
        color_discrete_map={
            'LOW': '#00d46a',
            'WATCHLIST': '#ffa421',
            'ELEVATED': '#ff8c00',
            'HIGH FLIGHT RISK': '#ff4b4b'
        },
        hover_data=['username', 'department'],
        title='Proactive vs Reactive Risk'
    )
    fig_scatter.update_layout(
        height=400,
        xaxis_title="Pre-Breach Score (Proactive)",
        yaxis_title="Risk Score (Reactive)"
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

st.markdown("---")

# --- ROW 4: DETAILED USER INVESTIGATION ---
st.subheader("User Investigation")

if top_risk_users:
    user_risk_df = pd.DataFrame(top_risk_users)
    selected_user = st.selectbox(
        "Select User for Detailed Analysis:",
        user_risk_df.sort_values('pre_breach_score', ascending=False)['username'].tolist()
    )
    
    user_data = df[df['username'] == selected_user].copy()
    if not user_data.empty:
        latest_event = user_data.iloc[0]
        
        col_detail1, col_detail2 = st.columns(2)
        
        with col_detail1:
            st.markdown(f"### 👤 {selected_user}")
            st.markdown(f"**Department:** {latest_event.get('department', 'Unknown')}")
            st.markdown(f"**Pre-Breach Score:** {latest_event.get('pre_breach_score', 0):.1f}")
            st.markdown(f"**Risk Level:** {latest_event.get('pre_breach_level', 'LOW')}")
            st.markdown(f"**Actual Risk Score:** {latest_event.get('risk_score', 0):.1f}")
        
        with col_detail2:
            st.markdown("### 🚩 Flight Risk Indicators")
            reasons = latest_event.get('flight_risk_reasons', [])
            if reasons:
                for reason in reasons:
                    st.markdown(f"• {reason}")
            else:
                st.info("No specific flight risk indicators detected.")
        
        st.markdown("---")
        
        st.markdown("### 📊 User's Recent Activity")
        user_activity = user_data.sort_values('timestamp', ascending=False).head(10)
        
        activity_display = user_activity[[
            'timestamp', 'data_asset', 'destination', 
            'risk_score', 'pre_breach_score', 'pre_breach_level'
        ]].copy()
        activity_display.columns = [
            'Timestamp', 'Data Asset', 'Destination',
            'Risk Score', 'Pre-Breach Score', 'Level'
        ]
        st.dataframe(activity_display, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        if st.button(f"Ask Copilot about {selected_user}", key=f"flight_detective_{selected_user}"):
            st.session_state["detective_prompt"] = f"Why was {selected_user} flagged with pre-breach score {latest_event.get('pre_breach_score', 0)}?"
            st.switch_page("pages/8_Security_Copilot.py")
else:
    st.info("No user data available for detailed analysis.")

st.markdown("---")

# --- FOOTER ---
with st.expander("How pre-breach scoring works"):
    st.markdown(
        """
        Flight Risk analyzes **pre-breach drift only** — early warning signals before data exfiltration:

        - Login time drift from typical access hours
        - High baseline query frequency
        - Exploration of unapproved assets (without risky destinations)
        - HR flight-risk flag and short tenure

        **Levels:** LOW (0–30) · WATCHLIST (31–60) · ELEVATED (61–80) · HIGH FLIGHT RISK (81–100)
        """
    )

render_copilot_button(
    "Ask Copilot: Who should I monitor next week?",
    "Who should I monitor next week?",
    key="flight_copilot_btn",
)
