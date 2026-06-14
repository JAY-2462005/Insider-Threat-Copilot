import pandas as pd
import numpy as np
import json
from pathlib import Path


def calculate_flight_risk(df):
    """
    Calculates proactive flight risk prediction based on PRE-BREACH behavior drift only.
    Removes actual breach indicators (destination, volume spikes) to focus on early warning signs.
    Returns USER-LEVEL flight risk scores aggregated across all events.

    Returns:
        df with additional columns:
        - pre_breach_score: 0-100 risk score (user-level, same for all events of a user)
        - pre_breach_level: LOW, WATCHLIST, ELEVATED, HIGH FLIGHT RISK
        - flight_risk_reasons: list of reasons for the risk score
    """

    # First, calculate per-event drift scores
    df['event_pre_breach_score'] = 0
    df['event_flight_risk_reasons'] = [[] for _ in range(len(df))]

    for idx, row in df.iterrows():
        reasons = []
        score = 0

        # 1. HR Risk Score (+20 if high_risk_flag is True) - PRE-BREACH indicator
        hr_score = 0
        if pd.notna(row.get('high_risk_flag')):
            if str(row['high_risk_flag']).lower() in ['true', '1', 'yes', 't']:
                hr_score = 20
                reasons.append("HR flight-risk flag present")
        score += hr_score

        # 2. Tenure Score (+10 if tenure < 6 months) - PRE-BREACH indicator
        tenure_score = 0
        if pd.notna(row.get('tenure_months')):
            if row['tenure_months'] < 6:
                tenure_score = 10
                reasons.append(f"Tenure < 6 months ({row['tenure_months']} months)")
        score += tenure_score

        # 3. Login Time Drift Score - PRE-BREACH behavioral indicator
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

        # 4. Access Frequency Drift - PRE-BREACH behavioral indicator
        access_freq_score = 0
        if pd.notna(row.get('avg_queries_per_day')):
            if row['avg_queries_per_day'] > 20:
                access_freq_score = 10
                reasons.append(f"High access frequency ({row['avg_queries_per_day']} queries/day baseline)")
        score += access_freq_score

        # 5. Asset Access Pattern Drift - PRE-BREACH indicator (exploring new assets, not exfiltration)
        asset_exploration_score = 0
        if pd.notna(row.get('data_asset')) and pd.notna(row.get('approved_data_assets')):
            try:
                asset = str(row['data_asset']).lower()
                approved = str(row['approved_data_assets']).lower()
                # Only flag if it's unapproved but NOT a high-risk destination (to avoid breach indicators)
                if asset not in approved and 'all' not in approved:
                    dest = str(row.get('destination', '')).lower()
                    risky_destinations = ['cloud_storage', 'external_email', 'external_ip', 'usb', 'usb_drive', 'personal_usb']
                    if not any(risky in dest for risky in risky_destinations):
                        asset_exploration_score = 15
                        reasons.append(f"Exploring unapproved asset: {row['data_asset']}")
            except:
                pass
        score += asset_exploration_score

        # Clip score to 0-100
        df.at[idx, 'event_pre_breach_score'] = min(max(score, 0), 100)
        df.at[idx, 'event_flight_risk_reasons'] = reasons

    # Now aggregate to USER-LEVEL by taking the maximum score per user
    user_risk = df.groupby(['user_id']).agg({
        'event_pre_breach_score': 'max',
        'event_flight_risk_reasons': lambda x: list(set([item for sublist in x for item in sublist]))  # Merge unique reasons
    }).reset_index()

    # Map user-level scores back to all events
    user_risk_dict = user_risk.set_index('user_id').to_dict('index')

    # Initialize final columns
    df['pre_breach_score'] = 0
    df['pre_breach_level'] = 'LOW'
    df['flight_risk_reasons'] = [[] for _ in range(len(df))]

    for idx, row in df.iterrows():
        user_id = row['user_id']
        if user_id in user_risk_dict:
            user_score = user_risk_dict[user_id]['event_pre_breach_score']
            user_reasons = user_risk_dict[user_id]['event_flight_risk_reasons']
            
            df.at[idx, 'pre_breach_score'] = user_score
            df.at[idx, 'flight_risk_reasons'] = user_reasons
            
            # Determine risk level
            if user_score <= 30:
                df.at[idx, 'pre_breach_level'] = 'LOW'
            elif user_score <= 60:
                df.at[idx, 'pre_breach_level'] = 'WATCHLIST'
            elif user_score <= 80:
                df.at[idx, 'pre_breach_level'] = 'ELEVATED'
            else:
                df.at[idx, 'pre_breach_level'] = 'HIGH FLIGHT RISK'

    # Drop temporary event-level columns
    df = df.drop(columns=['event_pre_breach_score', 'event_flight_risk_reasons'], errors='ignore')

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


def generate_flight_risk_n_summary(user_data, llm_client=None):
    """
    Generates an AI-powered narrative explanation of flight risk for a specific user.
    
    Args:
        user_data: Dictionary containing user's flight risk information
        llm_client: Optional LLM client for generating narratives
    
    Returns:
        String containing the AI-generated flight risk narrative
    """
    if not user_data:
        return "No flight risk data available for this user."
    
    username = user_data.get('username', 'Unknown')
    department = user_data.get('department', 'Unknown')
    pre_breach_score = user_data.get('pre_breach_score', 0)
    pre_breach_level = user_data.get('pre_breach_level', 'LOW')
    flight_risk_reasons = user_data.get('flight_risk_reasons', [])
    
    # If no LLM client provided, return a template-based summary
    if llm_client is None:
        reasons_text = ", ".join(flight_risk_reasons) if flight_risk_reasons else "No specific indicators detected"
        
        summary = f"""
**Flight Risk Assessment for {username}**

**Department:** {department}
**Risk Level:** {pre_breach_level}
**Pre-Breach Score:** {pre_breach_score}/100

**Key Risk Indicators:**
{reasons_text}

**Assessment:"""
        
        if pre_breach_score >= 80:
            summary += f"""
{username} is at HIGH FLIGHT RISK. This user exhibits multiple behavioral patterns that typically precede insider threats. Immediate intervention is recommended, including manager review and enhanced monitoring."""
        elif pre_breach_score >= 60:
            summary += f"""
{username} shows ELEVATED flight risk indicators. Behavioral drift patterns suggest potential insider threat development. Close monitoring and periodic review are advised."""
        elif pre_breach_score >= 30:
            summary += f"""
{username} is on the WATCHLIST for flight risk. Minor behavioral shifts have been detected. Continue monitoring for further changes."""
        else:
            summary += f"""
{username} shows LOW flight risk indicators. Current behavior patterns are within normal parameters."""
        
        return summary
    
    # If LLM client is provided, use it for more sophisticated narrative
    try:
        prompt = f"""
You are an insider threat analyst. Generate a concise flight risk assessment for the following user:

User: {username}
Department: {department}
Pre-Breach Score: {pre_breach_score}/100
Risk Level: {pre_breach_level}
Risk Indicators: {', '.join(flight_risk_reasons) if flight_risk_reasons else 'None detected'}

Provide a 2-3 sentence assessment explaining:
1. Why this user has their current risk level
2. What specific behaviors are concerning
3. What actions should be taken

Keep it professional and actionable.
"""
        
        response = llm_client.generate_content(prompt)
        return response.text
    except Exception as e:
        # Fallback to template if LLM fails
        reasons_text = ", ".join(flight_risk_reasons) if flight_risk_reasons else "No specific indicators detected"
        return f"""
**Flight Risk Assessment for {username}**
Risk Level: {pre_breach_level} ({pre_breach_score}/100)
Indicators: {reasons_text}
Note: AI narrative generation unavailable. Using template-based assessment.
"""
