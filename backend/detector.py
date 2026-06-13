import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import json
import os
from pathlib import Path
from flight_risk import calculate_flight_risk, get_flight_risk_summary

def load_and_merge_data(logs_path, profiles_path):
    """Loads CSVs and merges them on user_id safely."""
    logs = pd.read_csv(logs_path, parse_dates=['timestamp'])
    profiles = pd.read_csv(profiles_path)
    
    overlap_cols = ['username', 'department']
    logs = logs.drop(columns=[col for col in overlap_cols if col in logs.columns], errors='ignore')
    
    df = logs.merge(profiles, on='user_id', how='left')
    return df

def feature_engineering(df):
    """Engineers features explicitly based on the PS4 data schema."""
    
    def is_off_hours(row):
        try:
            if pd.isna(row.get('typical_access_hours')):
                return 0
            hour = row['timestamp'].hour
            start, end = map(int, str(row['typical_access_hours']).split('-'))
            if start <= hour < end:
                return 0 
            return 1 
        except:
            return 0 
            
    df['is_off_hours'] = df.apply(is_off_hours, axis=1)
    
    avg_rowcount = df['avg_rowcount_per_query'].fillna(100) + 0.1 
    df['volume_multiplier'] = df['rowcount'].fillna(0) / avg_rowcount
    
    sensitivity_map = {'low': 1, 'medium': 2, 'high': 3, 'restricted': 4}
    df['sensitivity_score'] = df['data_sensitivity'].astype(str).str.lower().map(sensitivity_map).fillna(1)
    
    df['is_high_risk_employee'] = df['high_risk_flag'].apply(
        lambda x: 1 if str(x).lower() in ['true', '1', 'yes', 't'] else 0
    )

    def check_unapproved_access(row):
        try:
            if pd.isna(row.get('data_asset')) or pd.isna(row.get('approved_data_assets')):
                return 0
            asset = str(row['data_asset']).lower()
            approved = str(row['approved_data_assets']).lower()
            if asset in approved or 'all' in approved:
                return 0 
            return 1 
        except:
            return 0
            
    df['unapproved_asset_access'] = df.apply(check_unapproved_access, axis=1)

    dest_risk_map = {
        'local': 1, 'local_workstation': 1, 'internal_share': 1, 
        'cloud': 2, 'cloud_storage': 2, 
        'usb': 4, 'usb_drive': 4, 'personal_usb': 5, 
        'external_email': 5, 'external_ip': 5
    }
    df['destination_risk'] = df['destination'].astype(str).str.lower().map(dest_risk_map).fillna(2)

    def is_month_end_finance(row):
        try:
            is_finance = 'finance' in str(row.get('department', '')).lower()
            is_month_end = row['timestamp'].day >= 25
            if is_finance and is_month_end:
                return 1 
            return 0
        except:
            return 0
        
    df['is_expected_seasonality'] = df.apply(is_month_end_finance, axis=1)
    
    def junior_restricted(row):
        try:
            is_junior = str(row.get('access_tier', '')).lower() in ['junior', 'intern']
            is_restricted = row['sensitivity_score'] >= 4  # Strict restricted logic
            if is_junior and is_restricted:
                return 1
            return 0
        except:
            return 0
            
    df['junior_restricted_access'] = df.apply(junior_restricted, axis=1)

    return df

def train_and_predict(df):
    """Generates a Hybrid Risk Score + ChatOps Logic for 100% explainability."""
    features = [
        'is_off_hours', 
        'volume_multiplier', 
        'sensitivity_score', 
        'is_high_risk_employee',
        'unapproved_asset_access',
        'destination_risk',
        'is_expected_seasonality',
        'junior_restricted_access'
    ]
    
    X = df[features].fillna(0)
    
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    df['anomaly_label'] = iso_forest.fit_predict(X)
    raw_scores = iso_forest.decision_function(X)
    
    min_score = raw_scores.min()
    max_score = raw_scores.max()
    
    if max_score == min_score:
        df['ml_score'] = 10.0
    else:
        df['ml_score'] = 20 - (((raw_scores - min_score) / (max_score - min_score)) * 20)
    
    def calculate_rule_score(row):
        score = 0
        breakdown = {}
        
        if row.get('destination_risk', 0) >= 4:
            score += 30
            breakdown['High-Risk Destination (USB/External)'] = 30
            
        if row.get('sensitivity_score', 0) == 3:
            score += 15
            breakdown['High Sensitivity Data'] = 15
        elif row.get('sensitivity_score', 0) >= 4:
            score += 20
            breakdown['Restricted Data'] = 20
            
        # Safely handle potential empty rowcounts
        rowcount_val = row.get('rowcount', 0)
        if pd.isna(rowcount_val): 
            rowcount_val = 0
            
        if rowcount_val >= 50000:
            score += 25
            breakdown[f"Extreme Bulk Export ({int(rowcount_val)} records)"] = 25
        elif row.get('volume_multiplier', 0) > 10:
            score += 20
            breakdown[f"Large Export ({row.get('volume_multiplier', 0):.1f}x typical)"] = 20
        elif row.get('volume_multiplier', 0) > 5:
            score += 10
            breakdown[f"Moderate Volume Spike ({row.get('volume_multiplier', 0):.1f}x typical)"] = 10
            
        if row.get('is_off_hours') == 1:
            score += 15
            breakdown['Off-hours Access'] = 15
            
        if row.get('is_high_risk_employee') == 1:
            score += 15
            breakdown['HR High-Risk Employee Flag'] = 15
            
        if row.get('unapproved_asset_access') == 1:
            score += 20
            breakdown['Unapproved Asset Accessed'] = 20
            
        if row.get('junior_restricted_access') == 1:
            score += 20
            breakdown['Junior Staff Policy Violation'] = 20
            
        return score, breakdown

    # Explicitly unpacking using standard Python to avoid DataFrame sequence bugs
    rule_scores = []
    score_breakdowns = []
    
    for _, row in df.iterrows():
        s, b = calculate_rule_score(row)
        rule_scores.append(float(s))
        score_breakdowns.append(b)
        
    df['rule_score'] = rule_scores
    df['score_breakdown'] = score_breakdowns
    
    df['risk_score'] = (0.8 * df['rule_score']) + (1.2 * df['ml_score'])
    
    mask_seasonality = (df['is_expected_seasonality'] == 1) & (df['destination_risk'] <= 2)
    df.loc[mask_seasonality, 'risk_score'] *= 0.5 

    df['risk_score'] = df['risk_score'].clip(lower=0, upper=100.0)

    # --- FRONTEND PROTECTIONS: Safely build iterables ---
    def build_justification(row):
        reasons = []
        breakdown = row.get('score_breakdown', {})
        for reason, points in breakdown.items():
            reasons.append(f"{reason} (+{points})")
            
        ml_contrib = round(row.get('ml_score', 0) * 1.2, 1)
        if ml_contrib > 5:
            reasons.append(f"Behavioral ML Anomaly Detected (+{ml_contrib})")
            
        if row.get('is_expected_seasonality') == 1 and row.get('destination_risk', 0) <= 2:
            reasons.append("Expected Seasonality Suppression (-50% Penalty)")
            
        return reasons

    def build_actions(row):
        score = row.get('risk_score', 0)
        if score >= 90:
            return ["Disable account immediately", "Block export destination", "Escalate to SOC", "Review last 72 hours"]
        elif score >= 75:
            return ["Manager review", "Investigate user activity", "Monitor closely"]
        elif score >= 50:
            return ["Monitor activity", "Verify business justification"]
        else:
            return ["No immediate action"]

    # --- ZERO-TRUST CHATOPS LOGIC ---
    def should_trigger_chatops(row):
        try:
            risk_score = row.get('risk_score', 0)
            destination_risk = row.get('destination_risk', 999)
            return (70 <= risk_score <= 89) and (destination_risk <= 2)
        except:
            return False

    def get_chatops_message(row):
        try:
            username = row.get('username', 'User')
            data_asset = row.get('data_asset', 'a data asset')
            return f"Hi {username}, our Zero-Trust system detected an unusually large data pull from {data_asset}. Are you currently performing authorized business tasks?"
        except:
            return ""

    # Drop columns if they mistakenly exist in the CSV to prevent overwrite errors
    for col in ['justification', 'recommended_actions', 'chatops_triggered', 'chatops_message']:
        if col in df.columns:
            df = df.drop(columns=[col])

    # Guarantee valid generation for the UI
    df['justification'] = df.apply(build_justification, axis=1)
    df['recommended_actions'] = df.apply(build_actions, axis=1)
    df['chatops_triggered'] = df.apply(should_trigger_chatops, axis=1)
    df['chatops_message'] = df.apply(lambda row: get_chatops_message(row) if row.get('chatops_triggered', False) else "", axis=1)

    # --- PHASE 3: Proactive Flight Risk Prediction ---
    df = calculate_flight_risk(df)

    return df

def evaluate_model(df, threshold=70):
    """
    Compares the engine's predictions against the ground truth labels 
    to calculate Precision, Recall, F1 Score, and Confusion Matrix.
    """
    if 'anomaly_marker' not in df.columns:
        print("No ground truth labels found in dataset. Skipping evaluation.")
        return

    # Ground Truth: 1 if anomaly_marker is NOT null, 0 if it is normal
    y_true = df['anomaly_marker'].notna().astype(int)
    
    # Prediction: 1 if our risk_score crossed the threshold, 0 if safe
    y_pred = (df['risk_score'] >= threshold).astype(int)

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Calculate False Positives and False Negatives for context
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    print("\n" + "="*50)
    print(" 🏆 HACKATHON EVALUATION METRICS 🏆")
    print("="*50)
    print(f"Target Threshold:   Risk Score >= {threshold}")
    print(f"Total Events:       {len(df)}")
    print(f"Actual Anomalies:   {sum(y_true)}")
    print("-" * 50)
    print(f"Precision:          {precision:.2%} (Target: > 75%)")
    print(f"Recall:             {recall:.2%} (Target: > 70%)")
    print(f"F1 Score:           {f1:.3f}  (Target: > 0.72)")
    print("-" * 50)
    print(" 📊 CONFUSION MATRIX 📊")
    print("-" * 50)
    print(f"                     | Predicted Safe (0) | Predicted Threat (1)")
    print(f"---------------------|--------------------|---------------------")
    print(f" Actual Safe (0)     | TN: {tn:<14} | FP: {fp:<14}")
    print(f" Actual Threat (1)   | FN: {fn:<14} | TP: {tp:<14}")
    print("="*50 + "\n")

def get_clustering_simulation_data(profiles_path=None):
    """
    Standalone peer-group clustering for ATO threat simulation.
    """
    if profiles_path is None:
        profiles_path = Path(__file__).resolve().parent.parent / "data" / "user_profiles.csv"
    else:
        profiles_path = Path(profiles_path)

    df = pd.read_csv(profiles_path)

    tier_map = {
        "junior": 1,
        "contractor": 2,
        "standard": 3,
        "senior": 4,
        "admin": 5,
        "executive": 6,
    }
    df["tier_num"] = (
        df["access_tier"]
        .astype(str)
        .str.lower()
        .map(tier_map)
        .fillna(3)
        .astype(int)
    )

    feature_cols = ["tier_num", "avg_queries_per_day", "avg_rowcount_per_query"]
    scaled_features = StandardScaler().fit_transform(df[feature_cols].fillna(0))

    kmeans = KMeans(n_clusters=4, random_state=42)
    df["user_cluster_id"] = kmeans.fit_predict(scaled_features)

    cluster_names = {
        0: "9-to-5ers",
        1: "Heavy Lifters (Admins)",
        2: "Data Crunchers (Finance)",
        3: "Contractors",
    }
    df["user_cluster"] = df["user_cluster_id"].map(cluster_names)

    return df.fillna("").to_dict(orient="records")

ATO_SCENARIOS = {
    "NIGHT_BULK_EXPORT_CRITICAL": {
        "label": "Midnight USB Exfiltration",
        "icon": "🌑",
        "severity": "CRITICAL",
        "description": "Restricted data copied to personal USB between 00:00–04:59 with 50K–250K rows.",
        "signals": ["Off-hours access", "personal_usb destination", "restricted sensitivity"],
        "query_multiplier": 4.0,
        "row_multiplier": 120.0,
        "hours_override": "0-4",
    },
    "INTERN_RESTRICTED_ACCESS": {
        "label": "Intern Privilege Escalation",
        "icon": "🎓",
        "severity": "HIGH",
        "description": "Junior role accessing restricted assets and routing data to external email.",
        "signals": ["Role/asset mismatch", "restricted PII", "external_email"],
        "query_multiplier": 3.5,
        "row_multiplier": 25.0,
        "hours_override": "8-18",
    },
    "OFF_HOURS_BULK_EXPORT": {
        "label": "Off-Hours Bulk Export",
        "icon": "🌙",
        "severity": "HIGH",
        "description": "Mass cloud export during 00:00–05:59 — 20K–80K rows outside typical hours.",
        "signals": ["Pre-dawn activity", "cloud_storage", "bulk EXPORT"],
        "query_multiplier": 3.0,
        "row_multiplier": 80.0,
        "hours_override": "0-5",
    },
    "FLIGHT_RISK_EXFILTRATION": {
        "label": "Flight-Risk Data Theft",
        "icon": "✈️",
        "severity": "CRITICAL",
        "description": "High-risk flagged employee pushes 10K–50K rows to external email in business hours.",
        "signals": ["high_risk_flag user", "external_email", "volume spike"],
        "query_multiplier": 5.0,
        "row_multiplier": 60.0,
        "hours_override": "8-18",
    },
}

def get_ato_simulation_context(profiles_path=None, logs_path=None):
    """
    Role-peer baselines, attack scenarios, and exemplar events for the ATO simulation UI.
    """
    if profiles_path is None:
        profiles_path = Path(__file__).resolve().parent.parent / "data" / "user_profiles.csv"
    else:
        profiles_path = Path(profiles_path)

    if logs_path is None:
        logs_path = Path(__file__).resolve().parent.parent / "data" / "data_access_logs.csv"
    else:
        logs_path = Path(logs_path)

    profiles = pd.read_csv(profiles_path)
    logs = pd.read_csv(logs_path)
    merged = logs.merge(profiles, on="user_id", how="left", suffixes=("", "_profile"))

    role_stats = (
        profiles.groupby("job_title", as_index=False)
        .agg(
            user_count=("user_id", "count"),
            median_queries=("avg_queries_per_day", "median"),
            median_rows=("avg_rowcount_per_query", "median"),
            median_tenure=("tenure_months", "median"),
        )
        .sort_values("user_count", ascending=False)
    )

    scenario_users = {}
    scenario_events = {}
    for marker, meta in ATO_SCENARIOS.items():
        events = merged[merged["anomaly_marker"] == marker].copy()
        scenario_events[marker] = events.sort_values("timestamp").fillna("").to_dict(orient="records")
        if events.empty:
            scenario_users[marker] = []
            continue
        users = (
            events.groupby(["user_id", "username", "job_title", "department"], as_index=False)
            .agg(event_count=("access_id", "count"), max_rows=("rowcount", "max"))
            .sort_values(["event_count", "max_rows"], ascending=False)
        )
        scenario_users[marker] = users.fillna("").to_dict(orient="records")

    cluster_records = get_clustering_simulation_data(profiles_path)

    return {
        "role_count": int(profiles["job_title"].nunique()),
        "job_roles": sorted(profiles["job_title"].unique().tolist()),
        "role_stats": role_stats.fillna("").to_dict(orient="records"),
        "scenarios": {
            marker: {**meta, "marker": marker, "event_count": len(scenario_events.get(marker, []))}
            for marker, meta in ATO_SCENARIOS.items()
        },
        "scenario_users": scenario_users,
        "scenario_events": scenario_events,
        "profiles": cluster_records,
    }

def get_alerts_for_ui(logs_path, profiles_path, threshold=70):
    """Called by the UI to fetch highly explainable real-time alerts."""
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    
    alerts_df = df[df['risk_score'] >= threshold].copy()
    alerts_df = alerts_df.sort_values(by='risk_score', ascending=False)
    
    alerts_list = []
    for _, row in alerts_df.iterrows():
        # Determine Severity based on threshold tiers
        if row['risk_score'] >= 90:
            severity = "CRITICAL"
        elif row['risk_score'] >= 75:
            severity = "HIGH"
        elif row['risk_score'] >= 50:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        alert = {
            "access_id": str(row.get('access_id', 'UNKNOWN')),
            "timestamp": str(row['timestamp']),
            "user_id": str(row['user_id']),
            "username": str(row.get('username', 'UNKNOWN')),
            "department": str(row.get('department', 'UNKNOWN')),
            "data_asset": str(row.get('data_asset', 'UNKNOWN')),
            "risk_score": round(row['risk_score'], 1),
            "severity": severity,
            "justification": row['justification'],
            "recommended_actions": row['recommended_actions'],
            "chatops_triggered": bool(row.get('chatops_triggered', False)),
            "chatops_message": str(row.get('chatops_message', '')),
            "pre_breach_score": round(row.get('pre_breach_score', 0), 1),
            "pre_breach_level": str(row.get('pre_breach_level', 'LOW')),
            "flight_risk_reasons": row.get('flight_risk_reasons', []),
            "raw_context": row.fillna("").to_dict() 
        }
        alerts_list.append(alert)
        
    return alerts_list

def get_scored_events_for_ui(logs_path, profiles_path):
    """Called by the UI to fetch all events with their calculated risk scores."""
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    
    df = df.sort_values(by='timestamp', ascending=False)
    df['timestamp'] = df['timestamp'].astype(str)
    
    if 'chatops_triggered' not in df.columns:
        df['chatops_triggered'] = False
    if 'chatops_message' not in df.columns:
        df['chatops_message'] = ""
    if 'pre_breach_score' not in df.columns:
        df['pre_breach_score'] = 0
    if 'pre_breach_level' not in df.columns:
        df['pre_breach_level'] = 'LOW'
    if 'flight_risk_reasons' not in df.columns:
        df['flight_risk_reasons'] = []
    
    df['chatops_triggered'] = df['chatops_triggered'].fillna(False).astype(bool)
    df['chatops_message'] = df['chatops_message'].fillna('').astype(str)
    df['pre_breach_score'] = df['pre_breach_score'].fillna(0).astype(float)
    df['pre_breach_level'] = df['pre_breach_level'].fillna('LOW').astype(str)
    
    events_list = df.fillna("").to_dict(orient='records')
    
    for event in events_list:
        event['chatops_triggered'] = bool(event.get('chatops_triggered', False))
        event['chatops_message'] = str(event.get('chatops_message', ''))
        event['pre_breach_score'] = float(event.get('pre_breach_score', 0))
        event['pre_breach_level'] = str(event.get('pre_breach_level', 'LOW'))
        if not isinstance(event.get('flight_risk_reasons'), list):
            event['flight_risk_reasons'] = []
    
    return events_list

if __name__ == "__main__":
    project_root = Path(__file__).resolve().parent.parent
    logs = project_root / "data" / "data_access_logs.csv"
    profs = project_root / "data" / "user_profiles.csv"
    
    if os.path.exists(logs) and os.path.exists(profs):
        df = load_and_merge_data(logs, profs)
        df = feature_engineering(df)
        df = train_and_predict(df)
        
        alerts = get_alerts_for_ui(logs, profs, threshold=70)
        print(f"🚨 Detected {len(alerts)} Alerts over threshold! 🚨\n")
        
        # Printing only the top alert to prevent terminal overflow
        if alerts:
            print("--- TOP ALERT JSON FEED (For Streamlit UI) ---")
            print(json.dumps(alerts, indent=2, default=str))
            print("\n")
            
        evaluate_model(df, threshold=70)
    else:
        print("Please place the CSV files in the data/ directory.")