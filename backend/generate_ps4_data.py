import pandas as pd
import os

os.makedirs('../data', exist_ok=True)

# User Profiles strictly using PS4 Schema
profiles = pd.DataFrame({
    'user_id': ['USR-0245', 'USR-1847', 'USR-0003'],
    'username': ['alice.smith', 'bob.jones', 'diana.intern'],
    'department': ['Finance', 'IT', 'Marketing'],
    'job_title': ['Senior Analyst', 'System Admin', 'Intern'],
    'tenure_months': [48, 3, 1],
    'approved_data_assets': ['GL_Ledger|AR_System', 'ALL', 'Public_Campaigns'],
    'avg_queries_per_day': [12.5, 25.0, 5.0],
    'typical_access_hours': ['9-17', '8-18', '10-16'],
    'avg_rowcount_per_query': [450, 1000, 50],
    'high_risk_flag': [False, True, False],
    'equipment': ['company_laptop', 'contractor_machine', 'company_laptop'],
    'access_tier': ['senior', 'admin', 'junior']
})
profiles.to_csv('../data/user_profiles.csv', index=False)

# Access Logs strictly using PS4 Schema
logs = pd.DataFrame({
    'access_id': ['ACC-001', 'ACC-002', 'ACC-003'],
    'timestamp': ['2026-04-15 14:23:45', '2026-04-28 22:47:12', '2026-04-16 03:15:33'],
    'user_id': ['USR-0245', 'USR-0245', 'USR-1847'],
    'username': ['alice.smith', 'alice.smith', 'bob.jones'],
    'department': ['Finance', 'Finance', 'IT'],
    'data_asset': ['GL_Ledger', 'GL_Ledger', 'PII_Database'],
    'data_sensitivity': ['high', 'high', 'restricted'],
    'query_type': ['SELECT', 'EXPORT', 'EXPORT'],
    'rowcount': [150, 50000, 50000], 
    'access_method': ['SQL', 'BI_Tool', 'API'],
    'destination': ['local_workstation', 'internal_share', 'personal_usb'],
    'status': ['success', 'success', 'success'],
    'anomaly_marker': [None, None, 'NIGHT_BULK_EXPORT_CRITICAL']
})
logs.to_csv('../data/data_access_logs.csv', index=False)
print("Data generated! You are ready to run detector.py")