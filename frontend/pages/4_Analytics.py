import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_events_dataframe

st.set_page_config(page_title="Analytics", page_icon="📈", layout="wide")

st.title("📈 Security Analytics & Insights")

try:
    df = get_events_dataframe()
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend events: {str(e)}")
    st.stop()

if df.empty:
    st.info("No backend events available for analytics.")
    st.stop()

# --- 2. ROW 1: GAUGE & HISTOGRAM ---
col_gauge, col_hist = st.columns(2)

with col_gauge:
    st.subheader("Enterprise Threat Level")
    avg_risk = df['risk_score'].mean()
    
    # Dynamic coloring based on enterprise risk
    gauge_color = "#ff4b4b" if avg_risk >= 75 else "#ffa421" if avg_risk >= 50 else "#00d46a"
    
    fig_gauge = go.Figure(go.Indicator(
    mode="gauge+number",
    value=avg_risk,
    domain={'x': [0, 1], 'y': [0, 1]},
    gauge={
        'axis': {'range': [0, 100]},
        'bar': {'color': gauge_color},
        'steps': [
            {'range': [0, 50], 'color': "rgba(0,212,106,0.1)"},
            {'range': [50, 75], 'color': "rgba(255,164,33,0.1)"},
            {'range': [75, 100], 'color': "rgba(255,75,75,0.1)"}
        ]
    }
    ))
    fig_gauge.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20))
    st.plotly_chart(fig_gauge, use_container_width=True)

with col_hist:
    st.subheader("Risk Score Distribution")
    fig_hist = px.histogram(
        df, 
        x='risk_score', 
        nbins=20,
        color_discrete_sequence=['#4B8BFF']
    )
    fig_hist.update_layout(height=300, xaxis_title="Risk Score", yaxis_title="Event Count")
    st.plotly_chart(fig_hist, use_container_width=True)

st.markdown("---")

# --- 3. ROW 2: HEATMAP & ASSETS ---
col_heat, col_assets = st.columns(2)

with col_heat:
    st.subheader("Threat Heatmap (Dept vs Severity)")
    
    # Create crosstab and ensure ordered columns if they exist
    heatmap_data = pd.crosstab(df['department'], df['severity'])
    ordered_cols = [col for col in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] if col in heatmap_data.columns]
    heatmap_data = heatmap_data[ordered_cols]
    
    fig_heat = px.imshow(
        heatmap_data, 
        text_auto=True, 
        aspect="auto",
        color_continuous_scale="Reds"
    )
    fig_heat.update_layout(height=350)
    st.plotly_chart(fig_heat, use_container_width=True)

with col_assets:
    st.subheader("Top Threat Assets")
    
    asset_risk = df.groupby('data_asset')['risk_score'].mean().sort_values(ascending=False).head(10).reset_index()
    fig_assets = px.bar(
        asset_risk, 
        x='data_asset', 
        y='risk_score',
        color='risk_score',
        color_continuous_scale="Reds"
    )
    fig_assets.update_layout(height=350, xaxis_title="Data Asset", yaxis_title="Average Risk Score")
    st.plotly_chart(fig_assets, use_container_width=True)

st.markdown("---")

# --- 4. ROW 3: TOP USERS & TRIGGER FREQUENCY ---
col_users, col_triggers = st.columns(2)

with col_users:
    st.subheader("Top Risk Users")
    
    user_risk = df.groupby('username')['risk_score'].mean().sort_values(ascending=False).head(10).reset_index()
    fig_users = px.bar(
        user_risk, 
        x='risk_score', 
        y='username', 
        orientation='h',
        color='risk_score',
        color_continuous_scale="Oranges"
    )
    fig_users.update_layout(height=400, yaxis={'categoryorder':'total ascending'})
    st.plotly_chart(fig_users, use_container_width=True)

with col_triggers:
    st.subheader("Threat Trigger Frequency")
    
    # Extract triggered rules dynamically from the justification lists
    all_triggers = []
    for justifications in df['justification'].dropna():
        for reason in justifications:
            # Clean up the string to remove the points (e.g., "Off-hours Access (+15)" -> "Off-hours Access")
            clean_reason = reason.split(" (+")[0]

            if "Expected Seasonality" not in clean_reason:
                all_triggers.append(clean_reason)
                
    if all_triggers:
        trigger_df = pd.Series(all_triggers).value_counts().reset_index()
        trigger_df.columns = ['Triggered Rule', 'Count']
        
        fig_triggers = px.bar(
            trigger_df.head(10), 
            x='Count', 
            y='Triggered Rule', 
            orientation='h',
            color_discrete_sequence=['#8338ec']
        )
        fig_triggers.update_layout(height=400, yaxis={'categoryorder':'total ascending'})
        st.plotly_chart(fig_triggers, use_container_width=True)
    else:
        st.info("No trigger data available to display.")
