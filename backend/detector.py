import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import json
import os
from pathlib import Path

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
            is_restricted = row['sensitivity_score'] >= 4  
            if is_junior and is_restricted:
                return 1
            return 0
        except:
            return 0
            
    df['junior_restricted_access'] = df.apply(junior_restricted, axis=1)

    return df

def train_and_predict(df):
    """Generates a Hybrid Risk Score (Rules + ML + Context) for 100% explainability."""
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
        
        if row['destination_risk'] >= 4:
            score += 30
            breakdown['High-Risk Destination (USB/External)'] = 30
            
        if row['sensitivity_score'] == 3:
            score += 15
            breakdown['High Sensitivity Data'] = 15
        elif row['sensitivity_score'] >= 4:
            score += 20
            breakdown['Restricted Data'] = 20
            
        # Tiered Volume Thresholds targeting exact prompt requirements
        if row['rowcount'] >= 50000:
            score += 25
            breakdown[f"Extreme Bulk Export ({int(row['rowcount'])} records)"] = 25
        elif row['volume_multiplier'] > 10:
            score += 20
            breakdown[f"Large Export ({row['volume_multiplier']:.1f}x typical)"] = 20
        elif row['volume_multiplier'] > 5:
            score += 10
            breakdown[f"Moderate Volume Spike ({row['volume_multiplier']:.1f}x typical)"] = 10
            
        if row['is_off_hours'] == 1:
            score += 15
            breakdown['Off-hours Access'] = 15
            
        if row['is_high_risk_employee'] == 1:
            score += 15
            breakdown['HR High-Risk Employee Flag'] = 15
            
        if row['unapproved_asset_access'] == 1:
            score += 20
            breakdown['Unapproved Asset Accessed'] = 20
            
        if row['junior_restricted_access'] == 1:
            score += 20
            breakdown['Junior Staff Policy Violation'] = 20
            
        return score, breakdown

    # Fixed Tuple Unpacking
    rule_results = df.apply(calculate_rule_score, axis=1)

    df['rule_score'] = rule_results.apply(lambda x: x[0])

    df['score_breakdown'] = rule_results.apply(lambda x: x[1])
    
    df['risk_score'] = (0.8 * df['rule_score']) + (1.2 * df['ml_score'])
    
    mask_seasonality = (df['is_expected_seasonality'] == 1) & (df['destination_risk'] <= 2)
    df.loc[mask_seasonality, 'risk_score'] *= 0.5 

    df['risk_score'] = df['risk_score'].clip(lower=0, upper=100.0)

    return df

def classify_risk(score):
    """Return the SOC severity and recommended actions for a risk score."""
    if score >= 90:
        return "CRITICAL", [
            "Disable account immediately",
            "Block export destination",
            "Escalate to SOC",
            "Review last 72 hours"
        ]
    if score >= 75:
        return "HIGH", [
            "Manager review",
            "Investigate user activity",
            "Monitor closely"
        ]
    if score >= 50:
        return "MEDIUM", [
            "Monitor activity",
            "Verify business justification"
        ]
    return "LOW", [
        "No immediate action"
    ]


def _json_safe(value):
    """Convert pandas/numpy values into Streamlit-friendly primitives."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, pd.Timestamp):
        return str(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, np.floating):
        return float(value)
    if isinstance(value, np.bool_):
        return bool(value)
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    return value


def _format_ui_event(row):
    reasons = []
    breakdown = row.get('score_breakdown', {})

    if isinstance(breakdown, dict):
        for reason, points in breakdown.items():
            reasons.append(f"{reason} (+{points})")

    ml_contrib = round(float(row.get('ml_score', 0)) * 1.2, 1)
    if ml_contrib > 5:
        reasons.append(f"Behavioral ML Anomaly Detected (+{ml_contrib})")

    if row.get('is_expected_seasonality') == 1 and row.get('destination_risk', 0) <= 2:
        reasons.append("Expected Seasonality Suppression (-50% Penalty)")

    score = float(row.get('risk_score', 0))
    severity, actions = classify_risk(score)
    raw_context = {str(k): _json_safe(v) for k, v in row.to_dict().items()}

    return {
        "access_id": str(row.get('access_id', 'UNKNOWN')),
        "timestamp": str(row.get('timestamp', 'UNKNOWN')),
        "username": str(row.get('username', 'UNKNOWN')),
        "department": str(row.get('department', 'UNKNOWN')),
        "data_asset": str(row.get('data_asset', 'UNKNOWN')),
        "risk_score": round(score, 1),
        "severity": severity,
        "justification": reasons,
        "recommended_actions": actions,
        "rowcount": _json_safe(row.get('rowcount', 0)),
        "destination": str(row.get('destination', 'UNKNOWN')),
        "query_type": str(row.get('query_type', 'UNKNOWN')),
        "raw_context": raw_context
    }


def get_scored_events_for_ui(logs_path, profiles_path):
    """Called by the UI to fetch every backend-scored access event."""
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    df = df.sort_values(by='risk_score', ascending=False)
    return [_format_ui_event(row) for _, row in df.iterrows()]


def get_alerts_for_ui(logs_path, profiles_path, threshold=70):
    """Called by the UI to fetch highly explainable alerts over the threshold."""
    return [
        event for event in get_scored_events_for_ui(logs_path, profiles_path)
        if event['risk_score'] >= threshold
    ]

if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[1]
    logs = project_root / "data" / "data_access_logs.csv"
    profs = project_root / "data" / "user_profiles.csv"
    
    if os.path.exists(logs) and os.path.exists(profs):
        alerts = get_alerts_for_ui(logs, profs, threshold=70)
        print(f"Detected {len(alerts)} Alerts over threshold!")
        if alerts:
            print(json.dumps(alerts, indent=2, default=str))
    else:
        print("Please place the CSV files in the data/ directory.")
