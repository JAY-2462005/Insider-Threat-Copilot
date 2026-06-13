import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
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
            is_restricted = row['sensitivity_score'] >= 3
            if is_junior and is_restricted:
                return 1
            return 0
        except:
            return 0
            
    df['junior_restricted_access'] = df.apply(junior_restricted, axis=1)

    return df

def train_and_predict(df):
    """Runs Isolation Forest and generates a Context-Aware Risk Score 0-100."""
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
    df['risk_score'] = 100 - (((raw_scores - min_score) / (max_score - min_score)) * 100)
    
    mask_seasonality = (df['is_expected_seasonality'] == 1) & (df['destination_risk'] <= 2)
    df.loc[mask_seasonality, 'risk_score'] *= 0.5 

    mask_critical = (df['destination_risk'] >= 4) & ((df['is_high_risk_employee'] == 1) | (df['unapproved_asset_access'] == 1))
    df.loc[mask_critical, 'risk_score'] = 99.0
    
    df['risk_score'] = df['risk_score'].clip(lower=0, upper=100.0)

    # --- FIX FOR FRONTEND ITERABLE ERRORS ('justification' & 'recommended_actions') ---
    def get_reasons(row):
        reasons = []
        if row.get('is_off_hours') == 1:
            reasons.append(f"Off-hours access (Typical: {row.get('typical_access_hours', 'Unknown')})")
        if row.get('volume_multiplier', 0) > 3:
            reasons.append(f"Exported {row.get('volume_multiplier', 0):.1f}x their baseline volume")
        if row.get('destination_risk', 0) >= 4:
            reasons.append(f"Exfiltration risk: Data moved to {row.get('destination', 'External')}")
        if row.get('unapproved_asset_access') == 1:
            reasons.append(f"First-time/Unapproved access to {row.get('data_asset')}")
        if row.get('junior_restricted_access') == 1:
            reasons.append(f"Policy Violation: Junior staff accessing restricted data")
        return reasons

    def get_actions(row):
        actions = []
        if row.get('destination_risk', 0) >= 4:
            actions.append("Isolate endpoint and block external transfers.")
        if row.get('unapproved_asset_access') == 1:
            actions.append("Immediately revoke access to unauthorized data assets.")
        if row.get('volume_multiplier', 0) > 3:
            actions.append("Implement temporary data export rate limiting.")
        if row.get('junior_restricted_access') == 1:
            actions.append("Audit IAM policies for junior access tiers.")
        
        # Fallback action if high risk but no specific rule triggered
        if not actions and row.get('risk_score', 0) >= 70:
            actions.append("Review user session logs and contact line manager.")
            
        return actions

    # Drop the columns if they mistakenly exist in the CSV as empty float fields
    if 'justification' in df.columns:
        df = df.drop(columns=['justification'])
    if 'recommended_actions' in df.columns:
        df = df.drop(columns=['recommended_actions'])

    # Guarantee these are valid lists for every row
    df['justification'] = df.apply(get_reasons, axis=1)
    df['recommended_actions'] = df.apply(get_actions, axis=1)

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


def get_alerts_for_ui(logs_path, profiles_path, threshold=70):
    """Called by the UI to fetch real-time alerts."""
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    
    alerts_df = df[df['risk_score'] >= threshold].copy()
    alerts_df = alerts_df.sort_values(by='risk_score', ascending=False)
    
    alerts_list = []
    for _, row in alerts_df.iterrows():
        alert = {
            "access_id": str(row.get('access_id', 'UNKNOWN')),
            "timestamp": str(row['timestamp']),
            "user_id": str(row['user_id']),
            "username": str(row.get('username', 'UNKNOWN')),
            "department": str(row.get('department', 'UNKNOWN')),
            "data_asset": str(row.get('data_asset', 'UNKNOWN')),
            "risk_score": round(row['risk_score'], 1),
            "severity": "CRITICAL" if row['risk_score'] >= 90 else "HIGH",
            "justification": row['justification'],          # Guaranteed list
            "recommended_actions": row['recommended_actions'], # Guaranteed list
            "raw_context": row.fillna("").to_dict() 
        }
        alerts_list.append(alert)
        
    return alerts_list


def get_scored_events_for_ui(logs_path, profiles_path):
    """Called by the UI to fetch all events with their calculated risk scores."""
    df = load_and_merge_data(logs_path, profiles_path)
    df = feature_engineering(df)
    df = train_and_predict(df)
    
    # Sort by most recent first
    df = df.sort_values(by='timestamp', ascending=False)
    
    # Convert timestamps to strings so they are JSON serializable for the frontend
    df['timestamp'] = df['timestamp'].astype(str)
    
    # Convert the entire dataframe to a list of dictionaries
    return df.fillna("").to_dict(orient='records')


if __name__ == "__main__":
    # Corrected path resolution using .parent.parent to avoid TypeError
    project_root = Path(__file__).resolve().parent.parent
    logs = project_root / "data" / "data_access_logs.csv"
    profs = project_root / "data" / "user_profiles.csv"
    
    if os.path.exists(logs) and os.path.exists(profs):
        # 1. First, process the data to get the dataframe
        df = load_and_merge_data(logs, profs)
        df = feature_engineering(df)
        df = train_and_predict(df)
        
        # 2. Print the top alert as a sanity check FIRST
        alerts = get_alerts_for_ui(logs, profs, threshold=70)
        if alerts:
            print("🚨 TOP ALERT JSON FEED (For Streamlit UI) 🚨")
            print(json.dumps(alerts, indent=2, default=str))
            print("\n")
            
        # 3. Run the evaluation to print the metrics and Confusion Matrix LAST
        evaluate_model(df, threshold=70)
        
    else:
        print("Please place the CSV files in the data/ directory.")
