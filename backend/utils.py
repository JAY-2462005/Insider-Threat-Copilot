"""
Utility functions for the Insider Threat Detection system.
"""

import pandas as pd
from typing import Dict, List, Tuple
import json


def validate_csv_files(logs_path: str, profiles_path: str) -> Tuple[bool, str]:
    """
    Validate that required CSV files exist and contain expected columns.
    
    Args:
        logs_path: Path to data_access_logs.csv
        profiles_path: Path to user_profiles.csv
    
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        # Check if files exist
        import os
        if not os.path.exists(logs_path):
            return False, f"Logs file not found: {logs_path}"
        if not os.path.exists(profiles_path):
            return False, f"Profiles file not found: {profiles_path}"
        
        # Load and validate structure
        logs = pd.read_csv(logs_path, nrows=1)
        profiles = pd.read_csv(profiles_path, nrows=1)
        
        required_log_cols = ['user_id', 'timestamp', 'data_asset', 'rowcount', 'destination']
        required_profile_cols = ['user_id', 'department']
        
        missing_log_cols = [col for col in required_log_cols if col not in logs.columns]
        missing_profile_cols = [col for col in required_profile_cols if col not in profiles.columns]
        
        if missing_log_cols or missing_profile_cols:
            return False, f"Missing columns: logs={missing_log_cols}, profiles={missing_profile_cols}"
        
        return True, "Files are valid"
    
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def export_alerts_to_json(alerts: List[Dict], output_path: str) -> bool:
    """
    Export alerts to JSON file.
    
    Args:
        alerts: List of alert dictionaries
        output_path: Path to save JSON file
    
    Returns:
        Success status
    """
    try:
        with open(output_path, 'w') as f:
            json.dump(alerts, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"Error exporting alerts: {e}")
        return False


def get_severity_color(severity: str) -> str:
    """Get color code for severity level."""
    severity_colors = {
        'CRITICAL': '#FF0000',
        'HIGH': '#FF9800',
        'MEDIUM': '#FFC107',
        'LOW': '#4CAF50'
    }
    return severity_colors.get(severity, '#999999')


def format_timestamp(ts) -> str:
    """Format timestamp for display."""
    if pd.isna(ts):
        return "N/A"
    return str(ts)


def calculate_statistics(df: pd.DataFrame) -> Dict:
    """Calculate overall statistics from the dataframe."""
    return {
        'total_records': len(df),
        'unique_users': df['user_id'].nunique(),
        'unique_assets': df.get('data_asset', pd.Series()).nunique(),
        'avg_risk_score': df.get('risk_score', pd.Series()).mean(),
        'max_risk_score': df.get('risk_score', pd.Series()).max(),
        'min_risk_score': df.get('risk_score', pd.Series()).min(),
    }


def get_user_profile_summary(df: pd.DataFrame, user_id: str) -> Dict:
    """Get a summary of a user's activity and risk profile."""
    user_data = df[df['user_id'] == user_id]
    
    if user_data.empty:
        return {'error': 'User not found'}
    
    return {
        'user_id': user_id,
        'username': user_data['username'].iloc[0] if 'username' in user_data.columns else 'N/A',
        'department': user_data['department'].iloc[0] if 'department' in user_data.columns else 'N/A',
        'total_activities': len(user_data),
        'avg_risk_score': user_data.get('risk_score', pd.Series()).mean(),
        'max_risk_score': user_data.get('risk_score', pd.Series()).max(),
        'high_risk_activities': len(user_data[user_data['risk_score'] > 70]) if 'risk_score' in user_data.columns else 0,
        'unique_assets_accessed': user_data.get('data_asset', pd.Series()).nunique(),
    }
