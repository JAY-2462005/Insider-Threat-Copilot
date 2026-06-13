import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import os

# Set seed for reproducible hackathon demos
random.seed(42)
np.random.seed(42)

def generate_profiles(num_users=100):
    departments = ['Finance', 'IT', 'Engineering', 'HR', 'Marketing', 'Sales']
    tiers = ['junior', 'standard', 'senior', 'admin', 'executive', 'contractor']
    
    profiles = []
    for i in range(1, num_users + 1):
        dept = random.choice(departments)
        tier = random.choices(
            tiers,
            weights=[25, 40, 15, 8, 5, 7],
            k=1
        )[0]
        
        # Base attributes on tier
        if tier == 'junior':
            title = 'Intern'
            hours = '9-17'
            avg_rows = random.randint(10, 100)
            assets = 'Public_Data'
        elif tier == 'admin':
            title = 'System Admin'
            hours = '0-24'
            avg_rows = random.randint(1000, 5000)
            assets = 'ALL'
        elif tier == 'executive':
            title = f'VP of {dept}'
            hours = '8-20'
            avg_rows = random.randint(100, 500)
            assets = 'ALL'
        else:
            title = f'{dept} Specialist'
            hours = '8-18'
            avg_rows = random.randint(50, 1000)
            assets = f'{dept}_DB|Shared_Drive'

        profiles.append({
            'user_id': f'USR-{i:04d}',
            'username': f'user.{i:04d}',
            'department': dept,
            'job_title': title,
            'tenure_months': random.randint(1, 120),
            'approved_data_assets': assets,
            'avg_queries_per_day': round(random.uniform(2.0, 30.0), 1),
            'typical_access_hours': hours,
            'avg_rowcount_per_query': avg_rows,
            'high_risk_flag': random.random() < 0.05, # 5% of users are flight risks
            'equipment': 'company_laptop' if tier != 'contractor' else 'contractor_machine',
            'access_tier': tier
        })
        
    return pd.DataFrame(profiles)

def generate_logs(profiles_df, num_events=1500, anomaly_rate=0.10):
    start_date = datetime(2026, 4, 1)
    end_date = datetime(2026, 4, 30)
    
    assets = ['GL_Ledger', 'Customer_DB', 'Source_Code', 'Payroll', 'Marketing_Assets', 'PII_Database']
    destinations = ['local_workstation', 'internal_share', 'cloud_storage', 'usb_drive', 'personal_usb', 'external_email']
    sensitivities = ['low', 'medium', 'high', 'restricted']
    
    logs = []
    users = profiles_df.to_dict('records')
    
    num_anomalies = int(num_events * anomaly_rate)
    anomaly_indices = set(random.sample(range(num_events), num_anomalies))
    
    for i in range(num_events):
        user = random.choice(users)
        is_anomaly = i in anomaly_indices
        
        # Baseline normal generation
        log_time = start_date + timedelta(
            days=random.randint(0, 29),
            hours=random.randint(9, 16), # Normal hours
            minutes=random.randint(0, 59)
        )
        
        rowcount = int(user['avg_rowcount_per_query'] * random.uniform(0.5, 1.5))
        destination = random.choices(
            destinations[:3],
            weights=[60, 30, 10],
            k=1
        )[0]
        sensitivity = random.choices(sensitivities[:2], weights=[80, 20], k=1)[0]
        marker = None
        
        if is_anomaly:
            # Weighted, realistic scenario distribution
            scenario = random.choices([1, 2, 3, 4], weights=[10, 20, 30, 40], k=1)[0]

            if scenario == 1: # Midnight Bulk USB Export (Critical)
                log_time = log_time.replace(
                    hour=random.choice([0, 1, 2, 3, 4])
                )
                rowcount = random.randint(50000, 250000)
                destination = 'personal_usb'
                sensitivity = 'restricted'
                marker = 'NIGHT_BULK_EXPORT_CRITICAL'
                
            elif scenario == 2: # Intern accessing Restricted PII (High)
                interns = [u for u in users if u['access_tier'] == 'junior']
                if interns: user = random.choice(interns)
                sensitivity = 'restricted'
                destination = 'external_email'
                marker = 'INTERN_RESTRICTED_ACCESS'
                
            elif scenario == 3: # Off-hours Massive Export (High)
                log_time = log_time.replace(hour=random.choice(range(0, 6)))
                rowcount = random.randint(20000, 80000)
                destination = 'cloud_storage'
                marker = 'OFF_HOURS_BULK_EXPORT'
                
            elif scenario == 4: # High Risk Employee Exfiltration
                high_risks = [u for u in users if u['high_risk_flag']]
                if high_risks: user = random.choice(high_risks)
                rowcount = random.randint(10000, 50000)
                destination = 'external_email'
                marker = 'FLIGHT_RISK_EXFILTRATION'

        logs.append({
            'access_id': f'ACC-{i:06d}',
            'timestamp': log_time.strftime('%Y-%m-%d %H:%M:%S'),
            'user_id': user['user_id'],
            'username': user['username'],
            'department': user['department'],
            'data_asset': random.choice(assets),
            'data_sensitivity': sensitivity,
            'query_type': random.choice(['SELECT', 'EXPORT', 'API']),
            'rowcount': rowcount,
            'access_method': random.choice(['SQL', 'BI_Tool', 'API']),
            'destination': destination,
            'status': 'success',
            'anomaly_marker': marker
        })

    # Sort logs chronologically
    logs_df = pd.DataFrame(logs)
    logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
    logs_df = logs_df.sort_values('timestamp').reset_index(drop=True)
    return logs_df

if __name__ == "__main__":
    print("🚀 Generating Enterprise Synthetic Dataset...")
    
    os.makedirs('../data', exist_ok=True)
    
    # 1. Generate 100 Profiles
    profiles_df = generate_profiles(100)
    profiles_df.to_csv('../data/user_profiles.csv', index=False)
    print(f"✅ Generated {len(profiles_df)} User Profiles")
    
    # 2. Generate 1500 Events (~10% anomalies)
    logs_df = generate_logs(profiles_df, 1500, 0.10)
    logs_df.to_csv('../data/data_access_logs.csv', index=False)
    
    anomaly_count = logs_df['anomaly_marker'].notna().sum()
    print(f"✅ Generated {len(logs_df)} Access Logs (Includes {anomaly_count} injected threats)")
    print("Ready for evaluation!")