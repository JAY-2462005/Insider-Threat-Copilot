from pathlib import Path
import sys

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"
DATA_DIR = PROJECT_ROOT / "data"
LOGS_PATH = DATA_DIR / "data_access_logs.csv"
PROFILES_PATH = DATA_DIR / "user_profiles.csv"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from detector import get_alerts_for_ui, get_scored_events_for_ui  # noqa: E402


EVENT_COLUMNS = [
    "access_id",
    "timestamp",
    "username",
    "department",
    "data_asset",
    "risk_score",
    "severity",
    "justification",
    "recommended_actions",
    "rowcount",
    "destination",
    "query_type",
    "raw_context",
]


@st.cache_data(show_spinner=False)
def _load_scored_events(logs_path: str, profiles_path: str):
    return get_scored_events_for_ui(logs_path, profiles_path)


@st.cache_data(show_spinner=False)
def _load_alerts(logs_path: str, profiles_path: str, threshold: int):
    return get_alerts_for_ui(logs_path, profiles_path, threshold)


def clear_data_cache():
    _load_scored_events.clear()
    _load_alerts.clear()
    st.session_state.pop("alerts", None)
    st.session_state.pop("events", None)


def get_data_paths():
    return {
        "logs": LOGS_PATH,
        "profiles": PROFILES_PATH,
    }


def get_threshold():
    return int(st.session_state.get("threshold", 70))


def get_scored_events():
    events = _load_scored_events(str(LOGS_PATH), str(PROFILES_PATH))
    st.session_state["events"] = events
    return events


def get_alerts(threshold=None):
    threshold = get_threshold() if threshold is None else int(threshold)
    alerts = _load_alerts(str(LOGS_PATH), str(PROFILES_PATH), threshold)
    st.session_state["threshold"] = threshold
    st.session_state["alerts"] = alerts
    return alerts


def get_events_dataframe():
    return pd.DataFrame(get_scored_events(), columns=EVENT_COLUMNS)


def get_alerts_dataframe(threshold=None):
    return pd.DataFrame(get_alerts(threshold), columns=EVENT_COLUMNS)


def get_dataset_summary(threshold=None):
    events_df = get_events_dataframe()
    alerts_df = get_alerts_dataframe(threshold)

    if events_df.empty:
        return {
            "events": 0,
            "alerts": 0,
            "critical": 0,
            "high": 0,
            "users": 0,
            "avg_risk": 0.0,
        }

    return {
        "events": len(events_df),
        "alerts": len(alerts_df),
        "critical": int((alerts_df["severity"] == "CRITICAL").sum()) if not alerts_df.empty else 0,
        "high": int((alerts_df["severity"] == "HIGH").sum()) if not alerts_df.empty else 0,
        "users": int(events_df["username"].nunique()),
        "avg_risk": float(events_df["risk_score"].mean()),
    }
