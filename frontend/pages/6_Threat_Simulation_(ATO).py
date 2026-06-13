import os
import sys

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from data_service import get_ato_simulation

st.set_page_config(page_title="Threat Simulation (ATO)", page_icon="🎯", layout="wide")

DARK = dict(
    template="plotly_dark",
    plot_bgcolor="#0e1117",
    paper_bgcolor="#0e1117",
    font=dict(color="#fafafa"),
)

SEVERITY_COLOR = {"CRITICAL": "#ff006e", "HIGH": "#ff4b4b", "MEDIUM": "#ffa421", "LOW": "#00d46a"}
CLUSTER_COLOR = {
    "9-to-5ers": "#4B8BFF",
    "Heavy Lifters (Admins)": "#ff4b4b",
    "Data Crunchers (Finance)": "#00d46a",
    "Contractors": "#ffa421",
    "⚠️ COMPROMISED": "#ff006e",
    "Role Peer Centroid": "#a78bfa",
}


def _compute_drift(user_row, role_row):
    q_delta = abs(user_row["avg_queries_per_day"] - role_row["median_queries"]) / max(role_row["median_queries"], 1)
    r_delta = abs(user_row["avg_rowcount_per_query"] - role_row["median_rows"]) / max(role_row["median_rows"], 1)
    return min(100.0, round((q_delta + r_delta) * 35, 1))


def _apply_scenario(profile_row, scenario, role_row):
    mutated = profile_row.copy()
    mutated["avg_queries_per_day"] = float(role_row["median_queries"]) * scenario["query_multiplier"]
    mutated["avg_rowcount_per_query"] = float(role_row["median_rows"]) * scenario["row_multiplier"]
    mutated["typical_access_hours"] = scenario["hours_override"]
    mutated["user_cluster"] = "⚠️ COMPROMISED"
    return mutated


st.title("🎯 Account Takeover — Role-Peer Simulation Lab")
st.markdown(
    """
    This lab models **Account Takeover (ATO)** by comparing each user against one of
    **13 job-role peer groups**, then replaying real injected attack patterns from your
    access logs. Pick a scenario, choose a victim, and watch behavioral drift unfold.
    """
)

try:
    ctx = get_ato_simulation()
except FileNotFoundError:
    st.error("❌ Data files not found. Run `backend/generate_ps4_data.py` first.")
    st.stop()
except Exception as exc:
    st.error(f"❌ Failed to load simulation context: {exc}")
    st.stop()

profiles_df = pd.DataFrame(ctx["profiles"])
role_stats_df = pd.DataFrame(ctx["role_stats"])
scenarios = ctx["scenarios"]
role_count = ctx["role_count"]

if profiles_df.empty:
    st.info("No user profile data available.")
    st.stop()

# --- KPI strip ---
k1, k2, k3, k4 = st.columns(4)
k1.metric("Job-Role Peer Groups", role_count)
k2.metric("Attack Scenarios", len(scenarios))
k3.metric("Users Profiled", len(profiles_df))
k4.metric("Injected Threat Events", sum(s["event_count"] for s in scenarios.values()))

st.markdown("---")

# --- 13-role peer baseline ---
st.subheader("📋 Role-Peer Baselines")
st.caption("Each of the 13 job titles forms an independent peer group for behavioral comparison.")

role_chart_df = role_stats_df.sort_values("median_queries", ascending=True)
fig_roles = px.bar(
    role_chart_df,
    x="median_queries",
    y="job_title",
    orientation="h",
    color="median_rows",
    color_continuous_scale=["#1e3a5f", "#4B8BFF", "#ff006e"],
    labels={"median_queries": "Median Queries / Day", "median_rows": "Median Rows / Query", "job_title": "Job Role"},
    title=f"Query Volume by Job Role ({role_count} peer groups)",
    hover_data=["user_count", "median_tenure"],
)
fig_roles.update_layout(**DARK, height=max(420, role_count * 32), coloraxis_showscale=True)
st.plotly_chart(fig_roles, use_container_width=True)

st.markdown("---")

# --- Scenario + victim controls ---
st.subheader("🧪 Configure Attack Scenario")

if "ato_scenario" not in st.session_state:
    st.session_state.ato_scenario = "INTERN_RESTRICTED_ACCESS"
if "ato_running" not in st.session_state:
    st.session_state.ato_running = False
if "ato_phase" not in st.session_state:
    st.session_state.ato_phase = 0

scenario_keys = list(scenarios.keys())
scenario_labels = {k: f"{scenarios[k]['icon']} {scenarios[k]['label']}" for k in scenario_keys}

ctrl_left, ctrl_right = st.columns([1, 1])

with ctrl_left:
    selected_marker = st.selectbox(
        "Attack vector (from access log anomaly markers)",
        scenario_keys,
        format_func=lambda k: scenario_labels[k],
        key="ato_scenario_select",
    )
    scenario = scenarios[selected_marker]
    st.info(
        f"**{scenario['icon']} {scenario['label']}** ({scenario['severity']})  \n"
        f"{scenario['description']}  \n"
        f"Signals: {', '.join(scenario['signals'])}  \n"
        f"Events in dataset: **{scenario['event_count']}**"
    )

with ctrl_right:
    candidates = ctx["scenario_users"].get(selected_marker, [])
    role_filter = st.selectbox(
        "Filter by job role",
        ["All roles"] + ctx["job_roles"],
    )
    if candidates:
        cand_df = pd.DataFrame(candidates)
        if role_filter != "All roles":
            cand_df = cand_df[cand_df["job_title"] == role_filter]
        if cand_df.empty:
            cand_df = pd.DataFrame(candidates)
        victim_options = [
            f"{row['username']} — {row['job_title']} ({row['department']}, {int(row['event_count'])} events)"
            for _, row in cand_df.iterrows()
        ]
        victim_idx = st.selectbox("Compromised account (from real log data)", range(len(victim_options)), format_func=lambda i: victim_options[i])
        victim_meta = cand_df.iloc[victim_idx].to_dict()
        victim_id = victim_meta["user_id"]
    else:
        fallback = profiles_df[profiles_df["access_tier"].astype(str).str.lower().isin(["junior", "intern"])]
        if fallback.empty:
            fallback = profiles_df
        victim_row = fallback.iloc[0]
        victim_id = victim_row["user_id"]
        victim_meta = {
            "user_id": victim_id,
            "username": victim_row["username"],
            "job_title": victim_row["job_title"],
            "department": victim_row["department"],
        }
        st.warning("No log events for this scenario — using a synthetic intern profile.")

    victim_profile = profiles_df[profiles_df["user_id"] == victim_id].iloc[0]
    role_row = role_stats_df[role_stats_df["job_title"] == victim_profile["job_title"]].iloc[0]

btn_run, btn_reset, btn_advance = st.columns(3)
with btn_run:
    if st.button("▶ Run ATO Simulation", type="primary", use_container_width=True):
        st.session_state.ato_running = True
        st.session_state.ato_phase = 1
        st.session_state.ato_scenario = selected_marker
with btn_reset:
    if st.button("↺ Reset Baseline", use_container_width=True):
        st.session_state.ato_running = False
        st.session_state.ato_phase = 0
with btn_advance:
    if st.button("⏭ Advance Phase", use_container_width=True, disabled=not st.session_state.ato_running):
        st.session_state.ato_phase = min(3, st.session_state.ato_phase + 1)

PHASES = ["Baseline", "Credential Abuse", "Data Staging", "Exfiltration Alert"]
phase_idx = st.session_state.ato_phase if st.session_state.ato_running else 0
st.progress(phase_idx / 3, text=f"Phase {phase_idx}/3 — {PHASES[phase_idx]}")

st.markdown("---")

# --- Build simulation dataframe ---
sim_df = profiles_df.copy()
compromised = _apply_scenario(victim_profile, scenario, role_row)

if st.session_state.ato_running:
    target_idx = sim_df[sim_df["user_id"] == victim_id].index[0]
    progress = phase_idx / 3.0
    sim_df.loc[target_idx, "avg_queries_per_day"] = (
        victim_profile["avg_queries_per_day"]
        + (compromised["avg_queries_per_day"] - victim_profile["avg_queries_per_day"]) * progress
    )
    sim_df.loc[target_idx, "avg_rowcount_per_query"] = (
        victim_profile["avg_rowcount_per_query"]
        + (compromised["avg_rowcount_per_query"] - victim_profile["avg_rowcount_per_query"]) * progress
    )
    if progress >= 1:
        sim_df.loc[target_idx, "user_cluster"] = "⚠️ COMPROMISED"
    sim_df.loc[target_idx, "username"] = f"{victim_profile['username']} ⚠️"

baseline_drift = _compute_drift(victim_profile, role_row)
attack_drift = _compute_drift(compromised, role_row)
current_row = sim_df[sim_df["user_id"] == victim_id].iloc[0]
live_drift = _compute_drift(current_row, role_row)

m1, m2, m3, m4 = st.columns(4)
m1.metric("Victim", victim_meta["username"])
m2.metric("Peer Group", victim_meta["job_title"])
m3.metric("Behavioral Drift", f"{live_drift}%", delta=f"+{live_drift - baseline_drift:.1f}% vs baseline" if st.session_state.ato_running else None)
m4.metric("Alert Threshold", "75%", delta="BREACHED" if live_drift >= 75 else "Normal", delta_color="inverse" if live_drift >= 75 else "off")

viz_left, viz_right = st.columns(2)

with viz_left:
    st.subheader("Peer-Group Constellation")
    fig_scatter = px.scatter(
        sim_df,
        x="avg_queries_per_day",
        y="avg_rowcount_per_query",
        color="user_cluster",
        size="tier_num",
        hover_name="username",
        hover_data=["job_title", "department", "access_tier"],
        labels={
            "avg_queries_per_day": "Avg Queries / Day",
            "avg_rowcount_per_query": "Avg Rows / Query",
        },
        color_discrete_map=CLUSTER_COLOR,
    )

    role_peers = sim_df[sim_df["job_title"] == victim_profile["job_title"]]
    centroid_x = role_peers["avg_queries_per_day"].median()
    centroid_y = role_peers["avg_rowcount_per_query"].median()
    fig_scatter.add_trace(
        go.Scatter(
            x=[centroid_x],
            y=[centroid_y],
            mode="markers+text",
            marker=dict(size=18, symbol="star", color="#a78bfa", line=dict(width=2, color="#fff")),
            text=[f"{victim_profile['job_title']} centroid"],
            textposition="top center",
            name="Role Peer Centroid",
            showlegend=True,
        )
    )

    if st.session_state.ato_running:
        fig_scatter.add_trace(
            go.Scatter(
                x=[victim_profile["avg_queries_per_day"], current_row["avg_queries_per_day"]],
                y=[victim_profile["avg_rowcount_per_query"], current_row["avg_rowcount_per_query"]],
                mode="lines+markers",
                line=dict(color="#ff006e", width=3, dash="dot"),
                marker=dict(size=[10, 16], color=["#4B8BFF", "#ff006e"]),
                name="Drift path",
            )
        )

    fig_scatter.update_layout(**DARK, height=460, legend=dict(bgcolor="rgba(0,0,0,0)"))
    st.plotly_chart(fig_scatter, use_container_width=True)

with viz_right:
    st.subheader("Role vs. Attacker Profile")
    radar_labels = ["Queries/Day", "Rows/Query", "Tenure", "Access Tier"]
    role_vals = [
        float(role_row["median_queries"]),
        float(role_row["median_rows"]),
        float(role_row["median_tenure"]),
        float(profiles_df[profiles_df["job_title"] == victim_profile["job_title"]]["tier_num"].median()),
    ]
    user_vals = [
        float(current_row["avg_queries_per_day"]),
        float(current_row["avg_rowcount_per_query"]),
        float(victim_profile["tenure_months"]),
        float(victim_profile["tier_num"]),
    ]
    max_vals = [max(a, b, 1) for a, b in zip(role_vals, user_vals)]

    fig_radar = go.Figure()
    fig_radar.add_trace(
        go.Scatterpolar(
            r=[v / m * 100 for v, m in zip(role_vals, max_vals)],
            theta=radar_labels,
            fill="toself",
            name=f"{victim_profile['job_title']} peer median",
            line_color="#4B8BFF",
        )
    )
    fig_radar.add_trace(
        go.Scatterpolar(
            r=[v / m * 100 for v, m in zip(user_vals, max_vals)],
            theta=radar_labels,
            fill="toself",
            name="Current (simulated) behavior",
            line_color="#ff006e" if st.session_state.ato_running else "#4B8BFF",
        )
    )
    fig_radar.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        **DARK,
        height=460,
        title="Normalized behavioral fingerprint",
    )
    st.plotly_chart(fig_radar, use_container_width=True)

# --- Drift gauge ---
st.subheader("Behavioral Drift Score")
fig_gauge = go.Figure(
    go.Indicator(
        mode="gauge+number+delta",
        value=live_drift,
        delta={"reference": baseline_drift, "relative": False},
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Distance from role peer group"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#ff006e" if live_drift >= 75 else "#ffa421" if live_drift >= 50 else "#00d46a"},
            "steps": [
                {"range": [0, 50], "color": "rgba(0,212,106,0.12)"},
                {"range": [50, 75], "color": "rgba(255,164,33,0.12)"},
                {"range": [75, 100], "color": "rgba(255,0,110,0.18)"},
            ],
            "threshold": {"line": {"color": "#ff006e", "width": 4}, "thickness": 0.8, "value": 75},
        },
    )
)
fig_gauge.update_layout(**DARK, height=220, margin=dict(l=20, r=20, t=50, b=10))
st.plotly_chart(fig_gauge, use_container_width=True)

# --- Event replay from real logs ---
st.markdown("---")
st.subheader("📼 Live Event Replay (from access logs)")
events = ctx["scenario_events"].get(selected_marker, [])
if events:
    events_df = pd.DataFrame(events)
    user_events = events_df[events_df["user_id"] == victim_id].copy()
    if user_events.empty:
        user_events = events_df.head(8)
    display_cols = [
        "timestamp", "username", "job_title", "data_asset", "data_sensitivity",
        "query_type", "rowcount", "destination", "anomaly_marker",
    ]
    display_cols = [c for c in display_cols if c in user_events.columns]
    st.dataframe(
        user_events[display_cols].sort_values("timestamp"),
        use_container_width=True,
        hide_index=True,
    )

    if "timestamp" in user_events.columns and "rowcount" in user_events.columns:
        user_events["timestamp"] = pd.to_datetime(user_events["timestamp"])
        fig_timeline = px.scatter(
            user_events.sort_values("timestamp"),
            x="timestamp",
            y="rowcount",
            color="destination",
            size="rowcount",
            hover_data=["data_asset", "query_type", "data_sensitivity"],
            title="Exfiltration timeline — row volume over time",
            labels={"rowcount": "Rows accessed", "timestamp": "Time"},
        )
        fig_timeline.update_layout(**DARK, height=340)
        st.plotly_chart(fig_timeline, use_container_width=True)
else:
    st.info("No events recorded for this scenario marker.")

# --- Alert banner ---
if st.session_state.ato_running and live_drift >= 75:
    st.error(
        f"**CRITICAL — Account Takeover Detected**  \n"
        f"`{victim_meta['username']}` ({victim_meta['job_title']}) has abandoned the "
        f"**{victim_profile['job_title']}** peer group. Drift score **{live_drift}%** exceeds the 75% SOC threshold.  \n"
        f"Attack pattern: **{scenario['label']}** — recommended: isolate session, revoke tokens, force MFA reset."
    )
elif st.session_state.ato_running:
    st.warning(
        f"Simulation in progress — `{victim_meta['username']}` drifting from "
        f"**{victim_profile['job_title']}** peers ({live_drift}% / 75% threshold)."
    )
else:
    st.success(
        f"Baseline established for `{victim_meta['username']}` in the **{victim_profile['job_title']}** "
        f"peer group ({role_row['user_count']} users). Select a scenario and run the simulation."
    )
