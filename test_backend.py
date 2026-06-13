#!/usr/bin/env python
"""Test script to verify ChatOps fields are generated in backend."""

import sys
import os
sys.path.insert(0, 'backend')

try:
    from detector import get_alerts_for_ui, get_scored_events_for_ui
    
    print("=" * 60)
    print("Testing Backend ChatOps Implementation")
    print("=" * 60)
    
    # Test get_alerts_for_ui
    print("\n1. Testing get_alerts_for_ui...")
    alerts = get_alerts_for_ui('data/data_access_logs.csv', 'data/user_profiles.csv', threshold=70)
    print(f"   Total alerts (threshold=70): {len(alerts)}")
    
    if alerts:
        alert = alerts[0]
        print(f"\n   First Alert Keys: {sorted(list(alert.keys()))}")
        print(f"   - chatops_triggered: {alert.get('chatops_triggered')} (type: {type(alert.get('chatops_triggered')).__name__})")
        print(f"   - chatops_message: {alert.get('chatops_message')[:80] if alert.get('chatops_message') else 'Empty'}...")
        print(f"   - Risk Score: {alert.get('risk_score')}")
        print(f"   - Severity: {alert.get('severity')}")
        
        # Count how many have ChatOps triggered
        chatops_count = sum(1 for a in alerts if a.get('chatops_triggered', False))
        print(f"\n   Alerts with ChatOps triggered: {chatops_count} / {len(alerts)}")
        
        # Show an example of one with ChatOps triggered
        for alert in alerts:
            if alert.get('chatops_triggered', False):
                print(f"\n   Example ChatOps Alert:")
                print(f"   - Username: {alert.get('username')}")
                print(f"   - Risk Score: {alert.get('risk_score')}")
                print(f"   - Message: {alert.get('chatops_message')}")
                break
    
    # Test get_scored_events_for_ui
    print("\n2. Testing get_scored_events_for_ui...")
    events = get_scored_events_for_ui('data/data_access_logs.csv', 'data/user_profiles.csv')
    print(f"   Total events: {len(events)}")
    
    if events:
        event = events[0]
        print(f"\n   First Event Keys: {sorted(list(event.keys()))}")
        if 'chatops_triggered' in event:
            print(f"   - chatops_triggered: {event.get('chatops_triggered')} ✓")
        else:
            print(f"   - chatops_triggered: MISSING ✗")
        if 'chatops_message' in event:
            print(f"   - chatops_message: {event.get('chatops_message')[:80] if event.get('chatops_message') else 'Empty'}... ✓")
        else:
            print(f"   - chatops_message: MISSING ✗")
        
        # Count ChatOps in events
        chatops_events = sum(1 for e in events if e.get('chatops_triggered', False))
        print(f"\n   Events with ChatOps triggered: {chatops_events} / {len(events)}")
    
    print("\n" + "=" * 60)
    print("✅ Backend test completed successfully!")
    print("=" * 60)
    
except Exception as e:
    import traceback
    print(f"\n❌ Error during testing: {e}")
    traceback.print_exc()
    sys.exit(1)
