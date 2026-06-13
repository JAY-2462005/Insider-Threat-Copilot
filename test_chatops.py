#!/usr/bin/env python
"""Quick test script to verify ChatOps fields are being generated."""

from pathlib import Path
from backend.detector import get_alerts_for_ui

project_root = Path('.')
logs = project_root / 'data' / 'data_access_logs.csv'
profs = project_root / 'data' / 'user_profiles.csv'

alerts = get_alerts_for_ui(str(logs), str(profs), threshold=70)

print('\n📊 Alerts with ChatOps data:')
print(f'Total Alerts: {len(alerts)}')

if alerts:
    # Show sample alert
    sample = alerts[0]
    print('\n🎯 First Alert Sample:')
    print(f"  Username: {sample.get('username')}")
    print(f"  Risk Score: {sample.get('risk_score')}")
    print(f"  Severity: {sample.get('severity')}")
    print(f"  Destination: {sample.get('destination')}")
    print(f"  Data Asset: {sample.get('data_asset')}")
    
    print('\n🤖 ChatOps Fields:')
    print(f"  chatops_triggered: {sample.get('chatops_triggered', 'NOT FOUND')}")
    print(f"  chatops_message: {sample.get('chatops_message', 'NOT FOUND')}")
    
    # Count how many have ChatOps triggered
    chatops_count = sum(1 for alert in alerts if alert.get('chatops_triggered', False))
    print(f'\n📈 Statistics:')
    print(f"  Total alerts with ChatOps triggered: {chatops_count}/{len(alerts)}")
    
    # Show example of alert with ChatOps
    chatops_alerts = [a for a in alerts if a.get('chatops_triggered', False)]
    if chatops_alerts:
        print('\n✅ Example ChatOps Alert:')
        example = chatops_alerts[0]
        print(f"  User: {example['username']}")
        print(f"  Risk Score: {example['risk_score']}")
        print(f"  Message: {example['chatops_message']}")
else:
    print("❌ No alerts generated!")
