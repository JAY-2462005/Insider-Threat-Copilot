import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_events_dataframe

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
from data_detective import investigate

# Try to import Gemini for enhanced summaries
try:
    from llm_summary import is_gemini_configured, _call_or_fallback
    GEMINI_OK = is_gemini_configured()
except Exception:
    GEMINI_OK = False

st.set_page_config(page_title="Security Copilot", page_icon="🛡️", layout="wide")

# --- Custom CSS ---
st.markdown("""
<style>
    .copilot-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 1.5rem;
        color: white;
    }
    .copilot-header h1 { color: white; margin: 0; font-size: 1.8rem; }
    .copilot-header p { color: #a0aec0; margin: 0.3rem 0 0 0; font-size: 0.95rem; }
    .score-bar-bg {
        background-color: #e2e8f0;
        border-radius: 8px;
        height: 24px;
        width: 100%;
        margin: 4px 0;
    }
    .score-bar-fill {
        border-radius: 8px;
        height: 24px;
        display: flex;
        align-items: center;
        padding-left: 10px;
        font-size: 0.8rem;
        font-weight: 600;
        color: white;
    }
    .stat-highlight {
        background: linear-gradient(135deg, #f8f9fa, #e9ecef);
        border-radius: 10px;
        padding: 0.8rem;
        border-left: 4px solid #0f3460;
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.markdown("""
<div class="copilot-header">
    <h1>🛡️ TrustGuardian Security Copilot</h1>
    <p>AI SOC Analyst • Investigate Threats • Explain Alerts • Profile Employees • Predict Risks</p>
</div>
""", unsafe_allow_html=True)

# --- Session State ---
if 'copilot_history' not in st.session_state:
    st.session_state.copilot_history = []

# --- Load Data ---
try:
    df = get_events_dataframe()
except Exception as e:
    st.error(f"❌ Error loading data: {str(e)}")
    st.stop()

# --- Main Layout ---
col_chat, col_results = st.columns([1, 2])

# ==========================================================================
# LEFT PANEL — Chat + Quick Actions
# ==========================================================================
with col_chat:
    st.markdown("### 💬 Investigation Chat")

    # Chat history display
    chat_container = st.container(height=300)
    with chat_container:
        if not st.session_state.copilot_history:
            st.markdown(
                "_🛡️ I'm your AI SOC Analyst. Ask me about threats, "
                "users, alerts, or flight risks._"
            )
        for msg in st.session_state.copilot_history:
            if msg['role'] == 'user':
                st.markdown(f"🧑‍💻 **Analyst:** {msg['content']}")
            else:
                st.markdown(f"🛡️ **Copilot:** {msg['content']}")
            st.markdown("")

    # Quick Action Buttons
    st.markdown("#### ⚡ Quick Actions")
    qc1, qc2 = st.columns(2)
    with qc1:
        if st.button("🔍 Critical USB Incidents", key="qa_usb", use_container_width=True):
            st.session_state["_auto_query"] = "Show me all critical incidents involving USB devices"
            st.rerun()
        if st.button("❓ Explain Top Alert", key="qa_explain", use_container_width=True):
            # Find the highest risk user dynamically
            top_user = df.sort_values('risk_score', ascending=False).iloc[0]['username']
            st.session_state["_auto_query"] = f"Why was {top_user} flagged?"
            st.rerun()
    with qc2:
        if st.button("👤 Profile Top Risk User", key="qa_profile", use_container_width=True):
            top_user = df.sort_values('risk_score', ascending=False).iloc[0]['username']
            st.session_state["_auto_query"] = f"Tell me about {top_user}"
            st.rerun()
        if st.button("✈️ Flight Risk Watchlist", key="qa_flight", use_container_width=True):
            st.session_state["_auto_query"] = "Who should I monitor next week?"
            st.rerun()

    st.markdown("---")

    # Input area
    default_prompt = st.session_state.pop("detective_prompt", "") or st.session_state.pop("_auto_query", "")

    user_question = st.text_area(
        "Ask a security question:",
        placeholder="e.g., Show me contractors who accessed restricted data after hours",
        height=80,
        value=default_prompt,
        key="copilot_input",
    )

    col_send, col_clear = st.columns([3, 1])
    with col_send:
        send = st.button("🔍 Investigate", use_container_width=True, type="primary")
    with col_clear:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.copilot_history = []
            st.rerun()

# ==========================================================================
# PROCESS QUERY
# ==========================================================================
if send and user_question.strip():
    st.session_state.copilot_history.append({'role': 'user', 'content': user_question})
    with st.spinner("🔍 Copilot is investigating..."):
        try:
            result = investigate(user_question, df)

            # Generate a Gemini-powered insight if available
            if GEMINI_OK and result.get('has_results') and result['response_type'] != 'off_topic':
                try:
                    rtype = result['response_type']
                    if rtype == 'threat_investigation':
                        context = f"{result['num_results']} incidents found. Filters: {result.get('filters_applied',[])}"
                        if result.get('evidence'):
                            sample = result['evidence'][:3]
                            context += f". Top events: {sample}"
                        prompt = (
                            f"You are a senior SOC analyst. A security analyst asked: \"{user_question}\"\n"
                            f"Investigation found: {context}\n"
                            f"Write a 3-sentence professional threat assessment. "
                            f"State what was found, assess the risk severity, and recommend immediate actions. "
                            f"Be direct, technical, and actionable."
                        )
                        ai_insight = _call_or_fallback(prompt, 200, "")
                        if ai_insight.strip():
                            result['ai_insight'] = ai_insight.strip()

                    elif rtype == 'employee_profile' and result.get('profile'):
                        p = result['profile']
                        prompt = (
                            f"You are a senior SOC analyst. Write a 3-sentence risk assessment for employee {p['username']}.\n"
                            f"Department: {p['department']}, Access: {p['access_tier']}, "
                            f"Highest Risk: {p['highest_risk_score']:.0f}/100, "
                            f"Events: {p['total_events']}, High-risk events: {p['high_risk_events']}, "
                            f"Destinations: {p.get('destinations_used', [])}, "
                            f"Pre-breach: {p['pre_breach_score']:.0f} ({p['pre_breach_level']}).\n"
                            f"Assess the threat level and recommend actions. Be professional."
                        )
                        ai_insight = _call_or_fallback(prompt, 200, "")
                        if ai_insight.strip():
                            result['ai_insight'] = ai_insight.strip()

                    elif rtype == 'alert_explanation':
                        breakdown_text = ", ".join([f"{b['factor']} (+{b['points']})" for b in result.get('score_breakdown', [])])
                        prompt = (
                            f"You are a SOC analyst explaining an alert to a manager.\n"
                            f"User {result.get('username', '?')} was flagged with risk score {result.get('risk_score', 0):.0f}/100.\n"
                            f"Contributing factors: {breakdown_text}.\n"
                            f"Write a 3-sentence explanation of why this is concerning and what actions to take. "
                            f"Be clear and actionable."
                        )
                        ai_insight = _call_or_fallback(prompt, 200, "")
                        if ai_insight.strip():
                            result['ai_insight'] = ai_insight.strip()
                except Exception:
                    pass  # AI insight is optional, never block on failure

            # Save to history
            summary_preview = result.get('summary', '').split('\n')[0][:120]
            st.session_state.copilot_history.append({
                'role': 'assistant',
                'content': summary_preview,
                'result': result,
            })
        except Exception as e:
            st.session_state.copilot_history.append({
                'role': 'assistant',
                'content': f"❌ Error: {str(e)}",
                'result': None,
            })
    st.rerun()

# ==========================================================================
# RIGHT PANEL — Copilot Findings (renders based on response_type)
# ==========================================================================
with col_results:
    st.markdown("### 📊 Copilot Findings")

    # Get latest result
    latest_result = None
    for msg in reversed(st.session_state.copilot_history):
        if msg['role'] == 'assistant' and msg.get('result'):
            latest_result = msg['result']
            break

    if not latest_result:
        st.info(
            "💡 **Try asking:**\n\n"
            "- *Show me all critical incidents involving USB devices*\n"
            "- *Tell me about user.0009*\n"
            "- *Why was user.0009 flagged?*\n"
            "- *Who should I monitor next week?*\n"
            "- *Show me contractor activity after hours*\n"
            "- *Which employees accessed restricted data?*"
        )
    else:
        rtype = latest_result.get('response_type', '')

        # ==================================================================
        # THREAT INVESTIGATION
        # ==================================================================
        if rtype == 'threat_investigation':
            # Threat summary card
            st.markdown(latest_result.get('summary', ''), unsafe_allow_html=True)

            # AI Insight (Gemini-powered)
            if latest_result.get('ai_insight'):
                st.markdown("---")
                st.markdown("#### 🤖 AI Threat Assessment")
                st.success(latest_result['ai_insight'])

            # Filters applied
            if latest_result.get('filters_applied'):
                with st.expander("🔎 Filters Applied", expanded=False):
                    for f in latest_result['filters_applied']:
                        st.markdown(f"• `{f}`")

            if latest_result.get('has_results') and latest_result.get('evidence'):
                # Mini analytics for the results
                ev_df = pd.DataFrame(latest_result['evidence'])

                if len(ev_df) > 1:
                    st.markdown("---")
                    mc1, mc2, mc3 = st.columns(3)
                    mc1.metric("Incidents Found", latest_result['num_results'])
                    if 'risk_score' in ev_df.columns:
                        mc2.metric("Avg Risk Score", f"{ev_df['risk_score'].mean():.0f}")
                        mc3.metric("Max Risk Score", f"{ev_df['risk_score'].max():.0f}")

                    # Department breakdown chart if >3 incidents
                    if 'department' in ev_df.columns and ev_df['department'].nunique() > 1:
                        dept_counts = ev_df['department'].value_counts()
                        fig_dept = go.Figure(go.Pie(
                            labels=dept_counts.index.tolist(),
                            values=dept_counts.values.tolist(),
                            hole=0.45,
                            marker=dict(colors=['#0f3460', '#1a1a2e', '#16213e', '#e94560', '#533483', '#0f3460']),
                        ))
                        fig_dept.update_layout(
                            height=220, margin=dict(l=10, r=10, t=30, b=10),
                            title="Affected Departments", showlegend=True,
                            legend=dict(font=dict(size=10)),
                        )
                        st.plotly_chart(fig_dept, use_container_width=True)

                # Evidence table
                st.markdown("---")
                st.markdown("#### 📋 Evidence Table")
                col_rename = {c: c.replace('_', ' ').title() for c in ev_df.columns}
                st.dataframe(ev_df.rename(columns=col_rename), use_container_width=True, hide_index=True)

            elif not latest_result.get('has_results'):
                st.warning("No matching incidents found. Try broadening your query.")

            # Recommendations
            if latest_result.get('recommendations'):
                st.markdown("---")
                st.markdown("#### 🎯 Recommended Actions")
                for r in latest_result['recommendations']:
                    st.markdown(f"  {r}")

        # ==================================================================
        # EMPLOYEE PROFILE
        # ==================================================================
        elif rtype == 'employee_profile':
            profile = latest_result.get('profile')
            if profile:
                # Header
                risk_icon = "🔴" if profile['highest_risk_score'] >= 90 else "🟠" if profile['highest_risk_score'] >= 75 else "🟡" if profile['highest_risk_score'] >= 50 else "🟢"
                st.markdown(f"### {risk_icon} Employee Investigation: {profile['username']}")

                # Profile metrics
                pc1, pc2, pc3, pc4 = st.columns(4)
                pc1.metric("Department", profile['department'])
                pc2.metric("Access Tier", profile['access_tier'].title())
                pc3.metric("Highest Risk", f"{profile['highest_risk_score']:.0f}")
                pc4.metric("Total Events", profile['total_events'])

                pm1, pm2, pm3, pm4 = st.columns(4)
                pm1.metric("Avg Risk Score", f"{profile['average_risk_score']:.0f}")
                pm2.metric("Pre-Breach Score", f"{profile['pre_breach_score']:.0f}")
                pm3.metric("Flight Risk", profile['pre_breach_level'])
                pm4.metric("Risk Trend", profile['risk_trend'])

                # AI Insight
                if latest_result.get('ai_insight'):
                    st.markdown("---")
                    st.markdown("#### 🤖 AI Risk Assessment")
                    st.success(latest_result['ai_insight'])

                # Severity breakdown gauge
                sev = profile.get('severity_breakdown', {})
                if sev:
                    st.markdown("---")
                    st.markdown("#### 📊 Event Severity Distribution")
                    sev_cols = st.columns(len(sev))
                    sev_colors = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                    for i, (level, count) in enumerate(sev.items()):
                        sev_cols[i].metric(f"{sev_colors.get(level, '⚪')} {level}", count)

                # Destinations & Assets side by side
                dests = profile.get('destinations_used', [])
                assets = profile.get('assets_accessed', [])
                if dests or assets:
                    st.markdown("---")
                    dc, ac = st.columns(2)
                    with dc:
                        st.markdown("#### 🌐 Destinations Used")
                        for d in dests:
                            risk_icon = "🔴" if any(x in d.lower() for x in ['usb', 'external', 'personal']) else "🟢"
                            st.markdown(f"  {risk_icon} `{d}`")
                    with ac:
                        st.markdown("#### 📁 Assets Accessed")
                        for a in assets:
                            st.markdown(f"  📄 `{a}`")

                # Activity table
                if latest_result.get('evidence'):
                    st.markdown("---")
                    st.markdown("#### 📋 Recent Activities")
                    ev_df = pd.DataFrame(latest_result['evidence'])
                    col_rename = {c: c.replace('_', ' ').title() for c in ev_df.columns}
                    st.dataframe(ev_df.rename(columns=col_rename), use_container_width=True, hide_index=True)
            else:
                st.warning(latest_result.get('summary', 'No profile data.'))

            if latest_result.get('recommendations'):
                st.markdown("---")
                st.markdown("#### 🎯 Recommended Actions")
                for r in latest_result['recommendations']:
                    st.markdown(f"  {r}")

        # ==================================================================
        # ALERT EXPLANATION
        # ==================================================================
        elif rtype == 'alert_explanation':
            username = latest_result.get('username', '?')
            risk_score = latest_result.get('risk_score', 0)

            # Header with risk gauge
            risk_icon = "🔴" if risk_score >= 90 else "🟠" if risk_score >= 75 else "🟡" if risk_score >= 50 else "🟢"
            st.markdown(f"### {risk_icon} Alert Explanation: {username}")
            st.markdown(f"**Risk Score: {risk_score:.0f}/100**")

            # Risk gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_score,
                domain={'x': [0, 1], 'y': [0, 1]},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': '#ff4b4b' if risk_score >= 75 else '#ffa421' if risk_score >= 50 else '#00d46a'},
                    'steps': [
                        {'range': [0, 50], 'color': 'rgba(0,212,106,0.1)'},
                        {'range': [50, 75], 'color': 'rgba(255,164,33,0.1)'},
                        {'range': [75, 100], 'color': 'rgba(255,75,75,0.1)'},
                    ],
                    'threshold': {'line': {'color': 'red', 'width': 3}, 'thickness': 0.75, 'value': 75},
                }
            ))
            fig_gauge.update_layout(height=200, margin=dict(l=20, r=20, t=30, b=10))
            st.plotly_chart(fig_gauge, use_container_width=True)

            # AI Insight
            if latest_result.get('ai_insight'):
                st.markdown("#### 🤖 AI Explanation")
                st.success(latest_result['ai_insight'])

            # Score breakdown with visual bars
            breakdown = latest_result.get('score_breakdown', [])
            if breakdown:
                st.markdown("---")
                st.markdown("#### 📊 Contributing Factors")
                max_pts = max((b['points'] for b in breakdown), default=1) or 1
                for b in breakdown:
                    pct = min(int((b['points'] / max_pts) * 100), 100)
                    color = "#ff4b4b" if b['points'] >= 25 else "#ffa421" if b['points'] >= 15 else "#00d46a"
                    st.markdown(f"**✓ {b['factor']}** — +{b['points']} pts")
                    st.markdown(
                        f'<div class="score-bar-bg"><div class="score-bar-fill" '
                        f'style="width:{max(pct, 15)}%;background-color:{color};">'
                        f'+{b["points"]}</div></div>',
                        unsafe_allow_html=True,
                    )
                    st.markdown("")

            # Event details
            details = latest_result.get('event_details', {})
            if details:
                st.markdown("---")
                st.markdown("#### 🔍 Flagged Event Details")
                for k, v in details.items():
                    label = k.replace('_', ' ').title()
                    st.markdown(f"• **{label}:** `{v}`")

            if latest_result.get('recommendations'):
                st.markdown("---")
                st.markdown("#### 🎯 Recommended Actions")
                for r in latest_result['recommendations']:
                    st.markdown(f"  {r}")

        # ==================================================================
        # FLIGHT RISK
        # ==================================================================
        elif rtype == 'flight_risk':
            st.markdown(latest_result.get('summary', ''), unsafe_allow_html=True)

            watchlist = latest_result.get('watchlist', [])
            if watchlist:
                st.markdown("---")
                st.markdown("#### 🎯 Watchlist — Users to Monitor")

                for i, w in enumerate(watchlist[:5], 1):
                    level = w['pre_breach_level']
                    icon = "🔴" if level == "HIGH FLIGHT RISK" else "🟠" if level == "ELEVATED" else "🟡" if level == "WATCHLIST" else "🟢"
                    with st.container(border=True):
                        wc1, wc2, wc3 = st.columns([3, 1, 1])
                        wc1.markdown(f"**{icon} #{i} {w['username']}** — {w['department']} | Level: **{level}**")
                        wc2.metric("Pre-Breach", f"{w['pre_breach_score']:.0f}", label_visibility="collapsed")
                        wc3.metric("Risk Score", f"{w['risk_score']:.0f}", label_visibility="collapsed")
                        reasons = w.get('reasons', [])
                        if reasons:
                            # Show top 3 unique reasons
                            unique_reasons = list(dict.fromkeys(reasons))[:3]
                            st.caption("📌 " + " • ".join(unique_reasons))

                # Show remaining as a compact table
                if len(watchlist) > 5:
                    st.markdown("---")
                    remaining = watchlist[5:]
                    rem_df = pd.DataFrame([{
                        'User': w['username'],
                        'Department': w['department'],
                        'Pre-Breach Score': f"{w['pre_breach_score']:.0f}",
                        'Level': w['pre_breach_level'],
                    } for w in remaining])
                    st.dataframe(rem_df, use_container_width=True, hide_index=True)

            # Risk distribution
            risk_dist = latest_result.get('risk_distribution', {})
            if risk_dist:
                st.markdown("---")
                st.markdown("#### 📊 Risk Level Distribution")
                level_order = ['LOW', 'WATCHLIST', 'ELEVATED', 'HIGH FLIGHT RISK']
                colors_map = {'LOW': '#00d46a', 'WATCHLIST': '#ffa421', 'ELEVATED': '#ff8c00', 'HIGH FLIGHT RISK': '#ff4b4b'}
                labels = [l for l in level_order if l in risk_dist]
                values = [risk_dist[l] for l in labels]
                colors = [colors_map.get(l, '#888') for l in labels]

                fig_dist = go.Figure(go.Bar(
                    x=labels, y=values,
                    marker_color=colors,
                    text=values, textposition='auto',
                ))
                fig_dist.update_layout(
                    height=250, margin=dict(l=10, r=10, t=30, b=10),
                    xaxis_title="Risk Level", yaxis_title="User Count",
                )
                st.plotly_chart(fig_dist, use_container_width=True)

            if latest_result.get('recommendations'):
                st.markdown("---")
                st.markdown("#### 🎯 Suggested Interventions")
                for r in latest_result['recommendations']:
                    st.markdown(f"  {r}")

        # ==================================================================
        # OFF-TOPIC
        # ==================================================================
        elif rtype == 'off_topic':
            st.warning(latest_result.get('summary', 'Please ask a security-related question.'))

# --- Footer ---
st.markdown("---")
st.caption(
    "🛡️ TrustGuardian Security Copilot — AI-powered SOC analyst for insider threat investigation. "
    "All analysis is performed on your local security data."
)
