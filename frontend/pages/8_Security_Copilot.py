"""
TrustGuardian Security Copilot — Real-time AI SOC Chatbot.
Uses st.chat_input + st.chat_message for a genuine conversational experience.
Rich inline findings rendered per response type.
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_events_dataframe

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
from data_detective import investigate

# Optional Gemini for AI-powered narrative polish
try:
    from llm_summary import is_gemini_configured, _call_or_fallback
    GEMINI_OK = is_gemini_configured()
except Exception:
    GEMINI_OK = False

st.set_page_config(page_title="Security Copilot", page_icon="🛡️", layout="wide")

# ── Custom CSS ────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .copilot-hero {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 1.4rem 2rem;
        border-radius: 14px;
        margin-bottom: 1rem;
        color: white;
        text-align: center;
    }
    .copilot-hero h1 { color: #f8f8f8; margin: 0; font-size: 1.6rem; letter-spacing: 0.03em; }
    .copilot-hero p  { color: #a0aec0; margin: 0.2rem 0 0 0; font-size: 0.9rem; }
    .score-bar-bg { background:#e2e8f0; border-radius:8px; height:22px; width:100%; margin:3px 0; }
    .score-bar-fill { border-radius:8px; height:22px; display:flex; align-items:center;
                      padding-left:10px; font-size:0.78rem; font-weight:600; color:white; }
    div[data-testid="stChatMessage"] { max-width: 100% !important; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="copilot-hero">
    <h1>🛡️ TrustGuardian Security Copilot</h1>
    <p>AI SOC Analyst — ask anything about threats, users, alerts, or risks in plain English</p>
</div>
""", unsafe_allow_html=True)

# ── Session State ─────────────────────────────────────────────────────────
if "copilot_messages" not in st.session_state:
    st.session_state.copilot_messages = []

# ── Load Data ─────────────────────────────────────────────────────────────
try:
    df = get_events_dataframe()
except Exception as e:
    st.error(f"❌ Could not load security data: {e}")
    st.stop()

# ── Quick Action Chips ────────────────────────────────────────────────────
top_user = df.sort_values("risk_score", ascending=False).iloc[0]["username"] if not df.empty else "user.0001"

st.markdown("##### ⚡ Quick Actions")
qa_cols = st.columns(4)
quick_queries = [
    ("🔍 Critical USB incidents", "Show me all critical incidents involving USB devices"),
    ("👤 Profile " + top_user, f"Tell me about {top_user}"),
    ("❓ Why was " + top_user + " flagged?", f"Why was {top_user} flagged?"),
    ("✈️ Flight risk watchlist", "Who should I monitor next week?"),
]
for i, (label, prompt) in enumerate(quick_queries):
    if qa_cols[i].button(label, key=f"qa_{i}", use_container_width=True):
        st.session_state["_pending_query"] = prompt
        st.rerun()

st.markdown("---")


# ═══════════════════════════════════════════════════════════════════════════
# HELPER: Generate optional Gemini narrative
# ═══════════════════════════════════════════════════════════════════════════
def _get_ai_narrative(question: str, result: dict) -> str:
    """Get a Gemini-powered 3-sentence SOC narrative. Returns '' on failure."""
    if not GEMINI_OK or not result.get("has_results"):
        return ""
    try:
        rtype = result["response_type"]
        if rtype == "threat_investigation":
            ctx = f"{result['num_results']} incidents. Filters: {result.get('filters_applied',[])}."
            if result.get("evidence"):
                ctx += f" Top user: {result['evidence'][0].get('username','?')}"
            prompt = (
                f"You are a senior SOC analyst. An analyst asked: \"{question}\"\n"
                f"Finding: {ctx}\n"
                f"Write a crisp 3-sentence threat assessment. State what was found, "
                f"assess severity, recommend immediate actions. Be direct and technical."
            )
        elif rtype == "employee_profile" and result.get("profile"):
            p = result["profile"]
            prompt = (
                f"Write a 3-sentence insider-threat risk assessment for {p['username']} "
                f"(dept={p['department']}, access={p['access_tier']}, peak_risk={p['highest_risk_score']:.0f}/100, "
                f"events={p['total_events']}, pre_breach={p['pre_breach_score']:.0f}/{p['pre_breach_level']}). "
                f"Assess the threat level and recommend actions. Be professional and concise."
            )
        elif rtype == "alert_explanation":
            bd = ", ".join([f"{b['factor']}(+{b['points']})" for b in result.get("score_breakdown", [])])
            prompt = (
                f"Explain to a SOC manager why {result.get('username','?')} was flagged at "
                f"risk {result.get('risk_score',0):.0f}/100. Factors: {bd}. "
                f"Write 3 sentences: what happened, why it's concerning, what to do next."
            )
        elif rtype == "flight_risk":
            top3 = [f"{w['username']}({w['pre_breach_score']:.0f})" for w in result.get("watchlist", [])[:3]]
            prompt = (
                f"Top flight-risk users: {', '.join(top3)}. "
                f"Write a 3-sentence pre-breach advisory for a SOC team. Be actionable."
            )
        else:
            return ""
        return _call_or_fallback(prompt, 250, "").strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# HELPER: Render rich findings INLINE inside a chat message
# ═══════════════════════════════════════════════════════════════════════════
def render_findings(result: dict):
    """Render structured findings inside the current st.chat_message context."""
    rtype = result.get("response_type", "")

    # ── OFF-TOPIC ─────────────────────────────────────────────────────
    if rtype == "off_topic":
        st.info(result.get("summary", "I can only help with security questions."))
        return

    # ── THREAT INVESTIGATION ──────────────────────────────────────────
    if rtype == "threat_investigation":
        st.markdown(result.get("summary", ""))

        # AI narrative
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Assessment:** {ai}")

        # Metrics row
        if result.get("has_results"):
            ev_df = pd.DataFrame(result["evidence"])
            m1, m2, m3 = st.columns(3)
            m1.metric("Incidents", result["num_results"])
            if "risk_score" in ev_df.columns and len(ev_df):
                m2.metric("Avg Risk", f"{ev_df['risk_score'].mean():.0f}")
                m3.metric("Max Risk", f"{ev_df['risk_score'].max():.0f}")

            # Department pie (if diverse)
            if "department" in ev_df.columns and ev_df["department"].nunique() > 1:
                dc = ev_df["department"].value_counts()
                fig = go.Figure(go.Pie(labels=dc.index.tolist(), values=dc.values.tolist(),
                                       hole=0.45,
                                       marker=dict(colors=["#302b63","#24243e","#e94560","#0f3460","#533483"])))
                fig.update_layout(height=230, margin=dict(l=5,r=5,t=25,b=5), title="Departments Affected",
                                  showlegend=True, legend=dict(font=dict(size=10)))
                st.plotly_chart(fig, use_container_width=True)

            # Evidence table
            with st.expander(f"📋 Evidence Table ({len(ev_df)} rows)", expanded=True):
                rename = {c: c.replace("_", " ").title() for c in ev_df.columns}
                st.dataframe(ev_df.rename(columns=rename), use_container_width=True, hide_index=True)

            # Filters
            if result.get("filters_applied"):
                with st.expander("🔎 Filters Applied"):
                    for f in result["filters_applied"]:
                        st.markdown(f"• `{f}`")

        # Recommendations
        if result.get("recommendations"):
            st.markdown("**🎯 Recommended Actions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── EMPLOYEE PROFILE ──────────────────────────────────────────────
    if rtype == "employee_profile":
        profile = result.get("profile")
        if not profile:
            st.warning(result.get("summary", "User not found."))
            return

        risk_icon = "🔴" if profile["highest_risk_score"] >= 90 else "🟠" if profile["highest_risk_score"] >= 75 else "🟡" if profile["highest_risk_score"] >= 50 else "🟢"
        st.markdown(f"### {risk_icon} {profile['username']} — {profile['department']}")

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Access Tier", profile["access_tier"].title())
        c2.metric("Peak Risk", f"{profile['highest_risk_score']:.0f}")
        c3.metric("Events", profile["total_events"])
        c4.metric("Trend", profile["risk_trend"])

        c5, c6, c7 = st.columns(3)
        c5.metric("Avg Risk", f"{profile['average_risk_score']:.0f}")
        c6.metric("Pre-Breach", f"{profile['pre_breach_score']:.0f}")
        c7.metric("Flight Risk", profile["pre_breach_level"])

        # AI narrative
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Risk Assessment:** {ai}")

        # Severity breakdown
        sev = profile.get("severity_breakdown", {})
        if sev:
            sev_colors = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            cols = st.columns(len(sev))
            for i, (level, count) in enumerate(sev.items()):
                cols[i].metric(f"{sev_colors.get(level, '⚪')} {level}", count)

        # Destinations + Assets
        dests = profile.get("destinations_used", [])
        assets = profile.get("assets_accessed", [])
        if dests or assets:
            dc, ac = st.columns(2)
            with dc:
                st.markdown("**🌐 Destinations:**")
                for d in dests:
                    ico = "🔴" if any(x in d.lower() for x in ["usb","external","personal"]) else "🟢"
                    st.markdown(f" {ico} `{d}`")
            with ac:
                st.markdown("**📁 Assets:**")
                for a in assets:
                    st.markdown(f" 📄 `{a}`")

        # Activity table
        if result.get("evidence"):
            with st.expander("📋 Recent Activities", expanded=True):
                ev_df = pd.DataFrame(result["evidence"])
                rename = {c: c.replace("_", " ").title() for c in ev_df.columns}
                st.dataframe(ev_df.rename(columns=rename), use_container_width=True, hide_index=True)

        if result.get("recommendations"):
            st.markdown("**🎯 Recommended Actions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── ALERT EXPLANATION ─────────────────────────────────────────────
    if rtype == "alert_explanation":
        username = result.get("username", "?")
        risk_score = result.get("risk_score", 0)
        risk_icon = "🔴" if risk_score >= 90 else "🟠" if risk_score >= 75 else "🟡" if risk_score >= 50 else "🟢"

        st.markdown(f"### {risk_icon} Alert: {username} — Risk {risk_score:.0f}/100")

        # Gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=risk_score,
            gauge={"axis": {"range": [0, 100]},
                   "bar": {"color": "#ff4b4b" if risk_score >= 75 else "#ffa421" if risk_score >= 50 else "#00d46a"},
                   "steps": [{"range": [0,50], "color": "rgba(0,212,106,0.1)"},
                             {"range": [50,75], "color": "rgba(255,164,33,0.1)"},
                             {"range": [75,100], "color": "rgba(255,75,75,0.1)"}],
                   "threshold": {"line": {"color": "red", "width": 3}, "thickness": 0.75, "value": 75}}
        ))
        fig.update_layout(height=190, margin=dict(l=20,r=20,t=25,b=5))
        st.plotly_chart(fig, use_container_width=True)

        # AI narrative
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Explanation:** {ai}")

        # Score breakdown bars
        breakdown = result.get("score_breakdown", [])
        if breakdown:
            st.markdown("**📊 Contributing Factors:**")
            max_pts = max((b["points"] for b in breakdown), default=1) or 1
            for b in breakdown:
                pct = max(int((b["points"] / max_pts) * 100), 15)
                color = "#ff4b4b" if b["points"] >= 25 else "#ffa421" if b["points"] >= 15 else "#00d46a"
                st.markdown(f"**✓ {b['factor']}** — +{b['points']} pts")
                st.markdown(
                    f'<div class="score-bar-bg"><div class="score-bar-fill" '
                    f'style="width:{pct}%;background-color:{color};">+{b["points"]}</div></div>',
                    unsafe_allow_html=True)

        # Event details
        details = result.get("event_details", {})
        if details:
            with st.expander("🔍 Flagged Event Details", expanded=True):
                for k, v in details.items():
                    st.markdown(f"• **{k.replace('_',' ').title()}:** `{v}`")

        if result.get("recommendations"):
            st.markdown("**🎯 Recommended Actions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── FLIGHT RISK ───────────────────────────────────────────────────
    if rtype == "flight_risk":
        st.markdown(result.get("summary", ""))

        # AI narrative
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Advisory:** {ai}")

        watchlist = result.get("watchlist", [])
        if watchlist:
            st.markdown("**🎯 Watchlist — Users to Monitor:**")
            for i, w in enumerate(watchlist[:7], 1):
                level = w["pre_breach_level"]
                ico = "🔴" if level == "HIGH FLIGHT RISK" else "🟠" if level == "ELEVATED" else "🟡" if level == "WATCHLIST" else "🟢"
                with st.container(border=True):
                    wc1, wc2, wc3 = st.columns([3, 1, 1])
                    wc1.markdown(f"**{ico} #{i} {w['username']}** — {w['department']}")
                    wc2.metric("Pre-Breach", f"{w['pre_breach_score']:.0f}", label_visibility="collapsed")
                    wc3.metric("Risk", f"{w['risk_score']:.0f}", label_visibility="collapsed")
                    reasons = list(dict.fromkeys(w.get("reasons", [])))[:3]
                    if reasons:
                        st.caption("📌 " + " • ".join(reasons))

        # Risk distribution chart
        risk_dist = result.get("risk_distribution", {})
        if risk_dist:
            level_order = ["LOW", "WATCHLIST", "ELEVATED", "HIGH FLIGHT RISK"]
            cmap = {"LOW": "#00d46a", "WATCHLIST": "#ffa421", "ELEVATED": "#ff8c00", "HIGH FLIGHT RISK": "#ff4b4b"}
            labs = [l for l in level_order if l in risk_dist]
            vals = [risk_dist[l] for l in labs]
            fig = go.Figure(go.Bar(x=labs, y=vals, marker_color=[cmap.get(l,"#888") for l in labs],
                                   text=vals, textposition="auto"))
            fig.update_layout(height=240, margin=dict(l=10,r=10,t=25,b=10),
                              xaxis_title="Risk Level", yaxis_title="Users")
            st.plotly_chart(fig, use_container_width=True)

        if result.get("recommendations"):
            st.markdown("**🎯 Suggested Interventions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return


# ═══════════════════════════════════════════════════════════════════════════
# PROCESS a query: investigate + optional AI narrative + render
# ═══════════════════════════════════════════════════════════════════════════
def process_query(question: str):
    """Run the backend, get AI narrative, save to history, and trigger render."""
    # Save user message
    st.session_state.copilot_messages.append({"role": "user", "content": question})

    result = investigate(question, df)
    ai_narrative = _get_ai_narrative(question, result)
    if ai_narrative:
        result["ai_narrative"] = ai_narrative

    st.session_state.copilot_messages.append({
        "role": "assistant",
        "content": result.get("summary", ""),
        "result": result,
    })


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-PROCESS pending queries from quick-actions / other pages
# ═══════════════════════════════════════════════════════════════════════════
pending = st.session_state.pop("_pending_query", None) or st.session_state.pop("detective_prompt", None)
if pending:
    process_query(pending)
    st.rerun()   # rerun so the chat renders the new messages


# ═══════════════════════════════════════════════════════════════════════════
# RENDER chat history  (st.chat_message for real chatbot feel)
# ═══════════════════════════════════════════════════════════════════════════
if not st.session_state.copilot_messages:
    # Welcome state
    with st.chat_message("assistant", avatar="🛡️"):
        st.markdown(
            "**Welcome, Analyst.** I'm your AI Security Copilot.\n\n"
            "Ask me anything about your insider-threat data in **plain English**:\n\n"
            "• *\"Show me all critical incidents involving USB devices\"*\n\n"
            "• *\"Tell me about user.0058\"*\n\n"
            "• *\"Why was user.0009 flagged?\"*\n\n"
            "• *\"Who should I monitor next week?\"*\n\n"
            "• *\"Show me contractors who accessed restricted data after hours\"*\n\n"
            "Or use the **Quick Action** buttons above."
        )
else:
    for msg in st.session_state.copilot_messages:
        if msg["role"] == "user":
            with st.chat_message("user", avatar="🧑‍💻"):
                st.markdown(msg["content"])
        else:
            with st.chat_message("assistant", avatar="🛡️"):
                result = msg.get("result")
                if result:
                    render_findings(result)
                else:
                    st.markdown(msg["content"])


# ═══════════════════════════════════════════════════════════════════════════
# CHAT INPUT (real chatbot input bar at the bottom)
# ═══════════════════════════════════════════════════════════════════════════
user_input = st.chat_input("Ask a security question…")
if user_input:
    process_query(user_input)
    st.rerun()


# ── Clear conversation button ────────────────────────────────────────────
if st.session_state.copilot_messages:
    if st.button("🗑️ Clear Conversation", key="clear_chat"):
        st.session_state.copilot_messages = []
        st.rerun()

# ── Footer ────────────────────────────────────────────────────────────────
st.markdown("---")
st.caption(
    "🛡️ TrustGuardian Security Copilot • All analysis is performed on your local security data • "
    "AI narratives powered by Gemini (optional)"
)
