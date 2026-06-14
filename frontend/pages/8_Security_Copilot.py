"""
TrustGuardian Security Copilot — Real-time AI SOC Chatbot.
Uses st.chat_input + st.chat_message for a genuine conversational experience.
Rich inline findings rendered per response type. Unique keys on every widget.
"""
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import sys
import os
import uuid

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_events_dataframe

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
from data_detective import investigate

# Optional Gemini
try:
    from llm_summary import is_gemini_configured, _call_or_fallback
    GEMINI_OK = is_gemini_configured()
except Exception:
    GEMINI_OK = False

st.set_page_config(page_title="Security Copilot", page_icon="🛡️", layout="wide")

# ── CSS ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .copilot-hero {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        padding: 1.3rem 2rem; border-radius: 14px; margin-bottom: 1rem;
        color: white; text-align: center;
    }
    .copilot-hero h1 { color:#f8f8f8; margin:0; font-size:1.6rem; }
    .copilot-hero p  { color:#a0aec0; margin:0.2rem 0 0 0; font-size:0.88rem; }
    .bar-bg { background:#e2e8f0; border-radius:8px; height:22px; width:100%; margin:3px 0; }
    .bar-fill { border-radius:8px; height:22px; display:flex; align-items:center;
                padding-left:10px; font-size:0.78rem; font-weight:600; color:white; }
    div[data-testid="stChatMessage"] { max-width:100%!important; }
    .phase-card { background:#f8f9fa; border-left:4px solid #302b63;
                  border-radius:8px; padding:0.8rem 1rem; margin:0.5rem 0; }
</style>
""", unsafe_allow_html=True)

# ── Header ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="copilot-hero">
    <h1>🛡️ TrustGuardian Security Copilot</h1>
    <p>AI SOC Analyst — ask anything about threats, users, alerts, risks, or SOC procedures</p>
</div>
""", unsafe_allow_html=True)

# ── State ─────────────────────────────────────────────────────────────────
if "copilot_messages" not in st.session_state:
    st.session_state.copilot_messages = []

# ── Data ──────────────────────────────────────────────────────────────────
try:
    df = get_events_dataframe()
except Exception as e:
    st.error(f"❌ Could not load security data: {e}")
    st.stop()

top_user = df.sort_values("risk_score", ascending=False).iloc[0]["username"] if not df.empty else "user.0001"

# ── Quick Actions ─────────────────────────────────────────────────────────
st.markdown("##### ⚡ Quick Actions")
qa = st.columns(5)
qas = [
    ("🔍 USB Incidents", "Show me all critical incidents involving USB devices"),
    ("👤 Profile " + top_user, f"Tell me about {top_user}"),
    ("❓ Explain Alert", f"Why was {top_user} flagged?"),
    ("✈️ Flight Risk", "Who should I monitor next week?"),
    ("📋 SOC Procedures", "What needs to be done if a user is flagged?"),
]
for i, (label, prompt) in enumerate(qas):
    if qa[i].button(label, key=f"qa_{i}", use_container_width=True):
        st.session_state["_pending_query"] = prompt
        st.rerun()
st.markdown("---")


# ═══════════════════════════════════════════════════════════════════════════
# AI NARRATIVE HELPER
# ═══════════════════════════════════════════════════════════════════════════
def _get_ai_narrative(question: str, result: dict) -> str:
    if not GEMINI_OK or not result.get("has_results"):
        return ""
    try:
        rt = result["response_type"]
        if rt == "threat_investigation":
            ctx = f"{result['num_results']} incidents. Filters: {result.get('filters_applied',[])}."
            prompt = (f"Senior SOC analyst. Analyst asked: \"{question}\"\nFinding: {ctx}\n"
                      f"Write 3-sentence threat assessment. Be direct and technical.")
        elif rt == "employee_profile" and result.get("profile"):
            p = result["profile"]
            prompt = (f"3-sentence risk assessment for {p['username']} "
                      f"(dept={p['department']}, peak_risk={p['highest_risk_score']:.0f}/100, "
                      f"events={p['total_events']}, pre_breach={p['pre_breach_level']}). Be concise.")
        elif rt == "alert_explanation":
            bd = ", ".join([f"{b['factor']}(+{b['points']})" for b in result.get("score_breakdown",[])])
            prompt = (f"Explain to SOC manager: {result.get('username','?')} flagged at "
                      f"risk {result.get('risk_score',0):.0f}/100. Factors: {bd}. 3 sentences.")
        elif rt == "flight_risk":
            top3 = [f"{w['username']}({w['pre_breach_score']:.0f})" for w in result.get("watchlist",[])[:3]]
            prompt = f"Top flight-risk users: {', '.join(top3)}. 3-sentence pre-breach advisory."
        elif rt == "security_advisory":
            prompt = (f"SOC analyst answering: \"{question}\"\n"
                      f"Provide a 3-sentence professional answer about insider threat response. "
                      f"Reference NIST/MITRE frameworks. Be actionable.")
        else:
            return ""
        return _call_or_fallback(prompt, 250, "").strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# RENDER FINDINGS — unique key per message via `idx`
# ═══════════════════════════════════════════════════════════════════════════
def render_findings(result: dict, idx: int):
    """Render structured findings inside a chat message. idx = message index for unique keys."""
    rt = result.get("response_type", "")

    # ── OFF-TOPIC ─────────────────────────────────────────────────────
    if rt == "off_topic":
        st.info(result.get("summary", "I can only help with security questions."))
        return

    # ── THREAT INVESTIGATION ──────────────────────────────────────────
    if rt == "threat_investigation":
        st.markdown(result.get("summary", ""))
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Assessment:** {ai}")

        if result.get("has_results"):
            ev_df = pd.DataFrame(result["evidence"])
            m1, m2, m3 = st.columns(3)
            m1.metric("Incidents", result["num_results"])
            if "risk_score" in ev_df.columns and len(ev_df):
                m2.metric("Avg Risk", f"{ev_df['risk_score'].mean():.0f}")
                m3.metric("Max Risk", f"{ev_df['risk_score'].max():.0f}")

            if "department" in ev_df.columns and ev_df["department"].nunique() > 1:
                dc = ev_df["department"].value_counts()
                fig = go.Figure(go.Pie(labels=dc.index.tolist(), values=dc.values.tolist(), hole=0.45,
                                       marker=dict(colors=["#302b63","#24243e","#e94560","#0f3460","#533483"])))
                fig.update_layout(height=220, margin=dict(l=5,r=5,t=25,b=5), title="Departments Affected",
                                  showlegend=True, legend=dict(font=dict(size=10)))
                st.plotly_chart(fig, use_container_width=True, key=f"pie_{idx}")

            with st.expander(f"📋 Evidence Table ({len(ev_df)} rows)", expanded=True):
                st.dataframe(ev_df.rename(columns={c: c.replace("_"," ").title() for c in ev_df.columns}),
                             use_container_width=True, hide_index=True, key=f"tbl_{idx}")

            if result.get("filters_applied"):
                with st.expander("🔎 Filters Applied"):
                    for f in result["filters_applied"]:
                        st.markdown(f"• `{f}`")
        else:
            st.warning("No matching incidents. Try broadening your query.")

        if result.get("recommendations"):
            st.markdown("**🎯 Recommended Actions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── EMPLOYEE PROFILE ──────────────────────────────────────────────
    if rt == "employee_profile":
        profile = result.get("profile")
        if not profile:
            st.warning(result.get("summary", "User not found."))
            return
        risk_icon = "🔴" if profile["highest_risk_score"] >= 90 else "🟠" if profile["highest_risk_score"] >= 75 else "🟡" if profile["highest_risk_score"] >= 50 else "🟢"
        st.markdown(f"### {risk_icon} {profile['username']} — {profile['department']}")

        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Access", profile["access_tier"].title())
        c2.metric("Peak Risk", f"{profile['highest_risk_score']:.0f}")
        c3.metric("Events", profile["total_events"])
        c4.metric("Trend", profile["risk_trend"])
        c5,c6,c7 = st.columns(3)
        c5.metric("Avg Risk", f"{profile['average_risk_score']:.0f}")
        c6.metric("Pre-Breach", f"{profile['pre_breach_score']:.0f}")
        c7.metric("Flight Risk", profile["pre_breach_level"])

        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Risk Assessment:** {ai}")

        sev = profile.get("severity_breakdown", {})
        if sev:
            cols = st.columns(len(sev))
            icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
            for i,(lv,ct) in enumerate(sev.items()):
                cols[i].metric(f"{icons.get(lv,'⚪')} {lv}", ct)

        dests = profile.get("destinations_used", [])
        assets = profile.get("assets_accessed", [])
        if dests or assets:
            dc2, ac2 = st.columns(2)
            with dc2:
                st.markdown("**🌐 Destinations:**")
                for d in dests:
                    ic = "🔴" if any(x in d.lower() for x in ["usb","external","personal"]) else "🟢"
                    st.markdown(f" {ic} `{d}`")
            with ac2:
                st.markdown("**📁 Assets:**")
                for a in assets:
                    st.markdown(f" 📄 `{a}`")

        if result.get("evidence"):
            with st.expander("📋 Recent Activities", expanded=True):
                ev_df = pd.DataFrame(result["evidence"])
                st.dataframe(ev_df.rename(columns={c: c.replace("_"," ").title() for c in ev_df.columns}),
                             use_container_width=True, hide_index=True, key=f"prof_tbl_{idx}")

        if result.get("recommendations"):
            st.markdown("**🎯 Recommended Actions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── ALERT EXPLANATION ─────────────────────────────────────────────
    if rt == "alert_explanation":
        username = result.get("username", "?")
        risk_score = result.get("risk_score", 0)
        ri = "🔴" if risk_score >= 90 else "🟠" if risk_score >= 75 else "🟡" if risk_score >= 50 else "🟢"
        st.markdown(f"### {ri} Alert: {username} — Risk {risk_score:.0f}/100")

        fig = go.Figure(go.Indicator(
            mode="gauge+number", value=risk_score,
            gauge={"axis":{"range":[0,100]},
                   "bar":{"color":"#ff4b4b" if risk_score>=75 else "#ffa421" if risk_score>=50 else "#00d46a"},
                   "steps":[{"range":[0,50],"color":"rgba(0,212,106,0.1)"},
                            {"range":[50,75],"color":"rgba(255,164,33,0.1)"},
                            {"range":[75,100],"color":"rgba(255,75,75,0.1)"}],
                   "threshold":{"line":{"color":"red","width":3},"thickness":0.75,"value":75}}
        ))
        fig.update_layout(height=190, margin=dict(l=20,r=20,t=25,b=5))
        st.plotly_chart(fig, use_container_width=True, key=f"gauge_{idx}")

        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Explanation:** {ai}")

        breakdown = result.get("score_breakdown", [])
        if breakdown:
            st.markdown("**📊 Contributing Factors:**")
            mx = max((b["points"] for b in breakdown), default=1) or 1
            for b in breakdown:
                pct = max(int((b["points"]/mx)*100), 15)
                clr = "#ff4b4b" if b["points"]>=25 else "#ffa421" if b["points"]>=15 else "#00d46a"
                st.markdown(f"**✓ {b['factor']}** — +{b['points']} pts")
                st.markdown(f'<div class="bar-bg"><div class="bar-fill" style="width:{pct}%;background-color:{clr};">+{b["points"]}</div></div>', unsafe_allow_html=True)

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
    if rt == "flight_risk":
        st.markdown(result.get("summary", ""))
        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Advisory:** {ai}")

        watchlist = result.get("watchlist", [])
        if watchlist:
            st.markdown("**🎯 Watchlist — Users to Monitor:**")
            for i, w in enumerate(watchlist[:7], 1):
                lv = w["pre_breach_level"]
                ic = "🔴" if lv=="HIGH FLIGHT RISK" else "🟠" if lv=="ELEVATED" else "🟡" if lv=="WATCHLIST" else "🟢"
                with st.container(border=True):
                    wc1,wc2,wc3 = st.columns([3,1,1])
                    wc1.markdown(f"**{ic} #{i} {w['username']}** — {w['department']}")
                    wc2.metric("Pre-Breach", f"{w['pre_breach_score']:.0f}", label_visibility="collapsed")
                    wc3.metric("Risk", f"{w['risk_score']:.0f}", label_visibility="collapsed")
                    reasons = list(dict.fromkeys(w.get("reasons",[])))[:3]
                    if reasons:
                        st.caption("📌 " + " • ".join(reasons))

        risk_dist = result.get("risk_distribution", {})
        if risk_dist:
            lo = ["LOW","WATCHLIST","ELEVATED","HIGH FLIGHT RISK"]
            cm = {"LOW":"#00d46a","WATCHLIST":"#ffa421","ELEVATED":"#ff8c00","HIGH FLIGHT RISK":"#ff4b4b"}
            ls = [l for l in lo if l in risk_dist]
            vs = [risk_dist[l] for l in ls]
            fig = go.Figure(go.Bar(x=ls, y=vs, marker_color=[cm.get(l,"#888") for l in ls],
                                   text=vs, textposition="auto"))
            fig.update_layout(height=240, margin=dict(l=10,r=10,t=25,b=10),
                              xaxis_title="Risk Level", yaxis_title="Users")
            st.plotly_chart(fig, use_container_width=True, key=f"flight_bar_{idx}")

        if result.get("recommendations"):
            st.markdown("**🎯 Suggested Interventions:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return

    # ── SECURITY ADVISORY ─────────────────────────────────────────────
    if rt == "security_advisory":
        st.markdown(result.get("summary", ""))

        ai = result.get("ai_narrative", "")
        if ai:
            st.success(f"🤖 **AI Insight:** {ai}")

        stages = result.get("stages", [])
        for s in stages:
            st.markdown(f"""<div class="phase-card">
                <b>{s['icon']} {s['phase']}</b>
            </div>""", unsafe_allow_html=True)
            for action in s["actions"]:
                st.markdown(f"  • {action}")
            st.markdown("")

        if result.get("recommendations"):
            st.markdown("---")
            st.markdown("**📚 Further Reading:**")
            for r in result["recommendations"]:
                st.markdown(f"  {r}")
        return


# ═══════════════════════════════════════════════════════════════════════════
# PROCESS QUERY
# ═══════════════════════════════════════════════════════════════════════════
def process_query(question: str):
    st.session_state.copilot_messages.append({"role": "user", "content": question})
    result = investigate(question, df)
    ai = _get_ai_narrative(question, result)
    if ai:
        result["ai_narrative"] = ai
    st.session_state.copilot_messages.append({"role": "assistant", "content": result.get("summary",""), "result": result})


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-PROCESS pending queries
# ═══════════════════════════════════════════════════════════════════════════
pending = st.session_state.pop("_pending_query", None) or st.session_state.pop("detective_prompt", None)
if pending:
    process_query(pending)
    st.rerun()


# ═══════════════════════════════════════════════════════════════════════════
# RENDER CHAT
# ═══════════════════════════════════════════════════════════════════════════
if not st.session_state.copilot_messages:
    with st.chat_message("assistant", avatar="🛡️"):
        st.markdown(
            "**Welcome, Analyst.** I'm your AI Security Copilot.\n\n"
            "Ask me anything in **plain English**:\n\n"
            "| Query Type | Example |\n"
            "|---|---|\n"
            "| 🔍 **Investigate** | *Show me medium risk flagged users* |\n"
            "| 👤 **Profile** | *Tell me about user.0058* |\n"
            "| ❓ **Explain** | *Why was user.0009 flagged?* |\n"
            "| ✈️ **Predict** | *Who should I monitor next week?* |\n"
            "| 📋 **Procedures** | *What to do if a user is flagged?* |\n"
            "| ⚖️ **Consequences** | *What are the consequences of being flagged?* |\n"
            "| 🛡️ **Best Practices** | *What are the best practices for insider threats?* |\n\n"
            "Or use the **Quick Action** buttons above."
        )
else:
    for msg_idx, msg in enumerate(st.session_state.copilot_messages):
        if msg["role"] == "user":
            with st.chat_message("user", avatar="🧑‍💻"):
                st.markdown(msg["content"])
        else:
            with st.chat_message("assistant", avatar="🛡️"):
                result = msg.get("result")
                if result:
                    render_findings(result, msg_idx)
                else:
                    st.markdown(msg["content"])


# ═══════════════════════════════════════════════════════════════════════════
# CHAT INPUT
# ═══════════════════════════════════════════════════════════════════════════
user_input = st.chat_input("Ask a security question…")
if user_input:
    process_query(user_input)
    st.rerun()


# ── Clear ─────────────────────────────────────────────────────────────────
if st.session_state.copilot_messages:
    if st.button("🗑️ Clear Conversation", key="clear_chat"):
        st.session_state.copilot_messages = []
        st.rerun()

st.markdown("---")
st.caption("🛡️ TrustGuardian Security Copilot • Local data analysis • AI narratives powered by Gemini (optional)")
