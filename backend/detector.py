import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
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

    # --- PANDAS BUG FIX: Explicitly unpacking using standard Python to avoid DataFrame sequence bugs ---
    rule_scores = []
    score_breakdowns = []
    
    for _, row in df.iterrows():
        s, b = calculate_rule_score(row)
        rule_scores.append(float(s))
        score_breakdowns.append(b)
        
    df['rule_score'] = rule_scores
    df['score_breakdown'] = score_breakdowns
    # -------------------------------------------------------------------------------------------------
    
    df['risk_score'] = (0.8 * df['rule_score']) + (1.2 * df['ml_score'])
    
    mask_seasonality = (df['is_expected_seasonality'] == 1) & (df['destination_risk'] <= 2)
    df.loc[mask_seasonality, 'risk_score'] *= 0.5 

    mask_critical = (df['destination_risk'] >= 4) & ((df['is_high_risk_employee'] == 1) | (df['unapproved_asset_access'] == 1))
    df.loc[mask_critical, 'risk_score'] = 99.0
    
    df['risk_score'] = df['risk_score'].clip(lower=0, upper=100.0)

    # --- FRONTEND PROTECTIONS: Safely build iterables for ALL rows ---
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

    # Drop columns if they mistakenly exist in the CSV as empty float fields
    for col in ['justification', 'recommended_actions']:
        if col in df.columns:
            df = df.drop(columns=[col])

    # Guarantee these are valid lists for every row so the frontend never crashes
    df['justification'] = df.apply(build_justification, axis=1)
    df['recommended_actions'] = df.apply(build_actions, axis=1)

    return df

def evaluate_model(df, threshold=70):
    """
    Compares the engine's predictions against the ground truth labels 
    to calculate Precision, Recall, F1 Score, and Confusion Matrix.
    """
    if 'anomaly_marker' not in df.columns