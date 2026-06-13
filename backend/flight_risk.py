import pandas as pd
import numpy as np


def calculate_flight_risk(df):
    """
    Calculates proactive flight risk prediction based on behavior drift.
    
    Returns:
        df with additional columns:
        - pre_breach_score: 0-100 risk score
        - pre_breach_level: LOW, WATCHLIST, ELEVATED, HIGH FLIGHT RISK
        - flight_risk_reasons: list of reasons for the risk score
    """
    
    # Initialize new columns
    df['pre_breach_score'] = 0
    df['pre_breach_level'] = 'LOW'
    df['flight_risk_reasons'] = [[] for _ in range(len(df))]
    
    # Calculate drift features and scores for each row
    for idx, row in df.iterrows():
        reasons = []
        score = 0
        
        # 1. HR Risk Score (+20 if high_risk_flag is True)
        hr_score = 0
        if pd.notna(row.get('high_risk_flag')):
            if str(row['high_risk_flag']).lower() in ['true', '1', 'yes', 't']:
                hr_score = 20
                reasons.append("HR flight-risk flag present")
        score += hr_score
        
        # 2. Tenure Score (+10 if tenure < 6 months)
        tenure_score = 0
        if pd.notna(row.get('tenure_months')):
            if row['tenure_months'] < 6:
                tenure_score = 10
                reasons.append(f"Tenure < 6 months ({row['tenure_months']} months)")
        score += tenure_score
        
        # 3. Login Time Drift Score
        login_shift_score = 0
        if pd.notna(row.get('timestamp')) and pd.notna(row.get('typical_access_hours')):
            try:
                actual_hour = row['timestamp'].hour
                typical_hours = str(row['typical_access_hours'])
                if '-' in typical_hours:
                    start_hour, end_hour = map(int, typical_hours.split('-'))
                    # Calculate shift from typical start time
                    minutes_shift = abs((actual_hour - start_hour) * 60)
                    
                    if minutes_shift > 0:
                        if minutes_shift <= 15:
                            login_shift_score = 5
                        elif minutes_shift <= 30:
                            login_shift_score = 10
                        elif minutes_shift <= 60:
                            login_shift_score = 15
                        else:
                            login_shift_score = 20
                        
                        if login_shift_score > 0:
                            reasons.append(f"Login pattern shifted by {minutes_shift} minutes")
            except:
                pass
        score += login_shift_score
        
        # 4. Volume Drift Score
        volume_shift_score = 0
        if pd.notna(row.get('rowcount')) and pd.notna(row.get('avg_rowcount_per_query')):
            try:
                baseline = row['avg_rowcount_per_query']
                if baseline > 0:
                    volume_multiplier = row['rowcount'] / baseline
                    
                    if volume_multiplier >= 1.5:
                        if volume_multiplier < 3:
                            volume_shift_score = 5
                        elif volume_multiplier < 5:
                            volume_shift_score = 10
                        elif volume_multiplier < 10:
                            volume_shift_score = 20
                        else:
                            volume_shift_score = 25
                        
                        if volume_shift_score > 0:
                            reasons.append(f"Volume increased {volume_multiplier:.1f}× baseline")
            except:
                pass
        score += volume_shift_score
        
        # 5. Asset Drift Score (+20 if unapproved asset access)
        asset_shift_score = 0
        if pd.notna(row.get('data_asset')) and pd.notna(row.get('approved_data_assets')):
            try:
                asset = str(row['data_asset']).lower()
                approved = str(row['approved_data_assets']).lower()
                if asset not in approved and 'all' not in approved:
                    asset_shift_score = 20
                    reasons.append(f"Unapproved access to {row['data_asset']}")
            except:
                pass
        score += asset_shift_score
        
        # 6. Destination Drift Score (+15 for unusual destinations)
        destination_shift_score = 0
        if pd.notna(row.get('destination')):
            try:
                dest = str(row['destination']).lower()
                risky_destinations = ['cloud_storage', 'external_email', 'external_ip', 'usb', 'usb_drive', 'personal_usb']
                if any(risky in dest for risky in risky_destinations):
                    destination_shift_score = 15
                    reasons.append(f"Unusual destination: {row['destination']}")
            except:
                pass
        score += destination_shift_score
        
        # Clip score to 0-100
        df.at[idx, 'pre_breach_score'] = min(max(score, 0), 100)
        df.at[idx, 'flight_risk_reasons'] = reasons
        
        # Determine risk level
        if score <= 30:
            df.at[idx, 'pre_breach_level'] = 'LOW'
        elif score <= 60:
            df.at[idx, 'pre_breach_level'] = 'WATCHLIST'
        elif score <= 80:
            df.at[idx, 'pre_breach_level'] = 'ELEVATED'
        else:
            df.at[idx, 'pre_breach_level'] = 'HIGH FLIGHT RISK'
    
    return df


def get_flight_risk_summary(df):
    """
    Returns a summary of flight risk across all users.
    
    Returns:
        Dictionary with:
        - top_risk_users: Top 10 users by pre_breach_score
        - enterprise_pressure_index: Average pre_breach score
        - risk_distribution: Count of users by risk level
    """
    # Get the latest event for each user (highest pre_breach_score)
    user_risk = df.groupby(['user_id', 'username', 'department']).agg({
        'pre_breach_score': 'max',
        'pre_breach_level': lambda x: x.mode()[0] if len(x.mode()) > 0 else 'LOW'
    }).reset_index()
    
    # Sort by score descending
    user_risk = user_risk.sort_values('pre_breach_score', ascending=False)
    
    # Top 10 users
    top_risk_users = user_risk.head(10).to_dict(orient='records')
    
    # Enterprise pressure index (average score)
    enterprise_pressure_index = user_risk['pre_breach_score'].mean()
    
    # Risk distribution
    risk_distribution = user_risk['pre_breach_level'].value_counts().to_dict()
    
    return {
        'top_risk_users': top_risk_users,
        'enterprise_pressure_index': round(enterprise_pressure_index, 1),
        'risk_distribution': risk_distribution
    }
