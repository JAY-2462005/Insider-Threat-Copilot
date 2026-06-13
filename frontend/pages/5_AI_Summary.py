import streamlit as st
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_alerts, get_threshold

try:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
    from llm_summary import (
        fallback_executive_summary,
        generate_executive_summary,
        generate_investigation_narrative,
        is_gemini_configured,
    )
    GEMINI_AVAILABLE = True
except Exception:
    GEMINI_AVAILABLE = False

st.set_page_config(page_title="AI Summary", page_icon="🤖", layout="wide")

st.title("🤖 AI-Powered Threat Intelligence")

try:
    alerts = get_alerts(get_threshold())
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading backend alerts: {str(e)}")
    st.stop()

# Executive Summary
st.subheader("📋 Executive Summary")

if not alerts:
    st.success("✅ No critical threats detected. Security posture is healthy.")
elif GEMINI_AVAILABLE and is_gemini_configured():
    with st.spinner("🔄 Generating executive summary..."):
        exec_summary = generate_executive_summary(alerts)
        st.success(exec_summary)
elif GEMINI_AVAILABLE:
    st.info(fallback_executive_summary(alerts))
else:
    st.info("Executive summary requires Gemini API. Using fallback statistics.")

# Statistics
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Total Threats", len(alerts))

with col2:
    critical = len([a for a in alerts if a['severity'] == 'CRITICAL'])
    st.metric("CRITICAL", critical)

with col3:
    high = len([a for a in alerts if a['severity'] == 'HIGH'])
    st.metric("HIGH Risk", high)

st.markdown("---")

# Common Threat Patterns
st.subheader("🔍 Common Threat Patterns")

threat_patterns = {}
for alert in alerts:
    for reason in alert.get('justification', []):
        pattern = reason.split('(')[0].strip()
        threat_patterns[pattern] = threat_patterns.get(pattern, 0) + 1

sorted_patterns = sorted(threat_patterns.items(), key=lambda x: x[1], reverse=True)

for pattern, count in sorted_patterns[:10]:
    percentage = (count / len(alerts)) * 100
    st.markdown(f"**{pattern}** ({count} occurrences, {percentage:.1f}%)")
    st.progress(min(percentage / 100, 1.0))

if not sorted_patterns:
    st.info("No threat patterns above the selected threshold.")

st.markdown("---")

# Risk Hotspots
st.subheader("🔥 Risk Hotspots")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**By Department:**")
    dept_alerts = {}
    for alert in alerts:
        dept = alert.get('department', 'Unknown')
        dept_alerts[dept] = dept_alerts.get(dept, 0) + 1
    
    for dept, count in sorted(dept_alerts.items(), key=lambda x: x[1], reverse=True):
        st.markdown(f"- {dept}: {count} threats")

with col2:
    st.markdown("**By Data Asset:**")
    asset_alerts = {}
    for alert in alerts:
        asset = alert.get('data_asset', 'Unknown')
        asset_alerts[asset] = asset_alerts.get(asset, 0) + 1
    
    for asset, count in sorted(asset_alerts.items(), key=lambda x: x[1], reverse=True)[:8]:
        st.markdown(f"- {asset}: {count} access attempts")

st.markdown("---")

# Recommendations
st.subheader("💡 AI-Generated Recommendations")

if GEMINI_AVAILABLE and is_gemini_configured():
    st.info("✅ Recommendations are powered by Gemini LLM analysis (see Executive Summary above)")
else:
    st.info("Manual recommendation engine (Gemini not available)")

# Manual fallback recommendations
recommendations = []

if len([a for a in alerts if a['severity'] == 'CRITICAL']) > 0:
    recommendations.append("🚨 **IMMEDIATE ACTION**: Critical threats detected. Escalate to SOC immediately.")

off_hours_count = len([a for a in alerts if 'Off-hours Access' in str(a.get('justification', []))])
if off_hours_count > 0:
    recommendations.append(f"🌙 {off_hours_count} threats involve off-hours access. Enforce stricter policies.")

bulk_export_count = len([a for a in alerts if 'Bulk Export' in str(a.get('justification', []))])
if bulk_export_count > 0:
    recommendations.append(f"📦 {bulk_export_count} threats involve bulk exports. Review data exfiltration controls.")

if not recommendations:
    recommendations.append("✅ Continue monitoring. Current threat levels are manageable.")

for rec in recommendations:
    st.warning(rec)

st.markdown("---")

# Detailed Threat Analysis
st.subheader("📊 Detailed Threat Narratives")

with st.expander("View All Alerts with AI Analysis", expanded=False):
    for idx, alert in enumerate(alerts[:5]):  # Show first 5
        st.markdown(f"### Alert {idx + 1}: {alert['username']} - {alert['severity']}")
        
        if GEMINI_AVAILABLE and is_gemini_configured():
            if st.button("Generate Narrative", key=f"narrative_{alert['access_id']}"):
                with st.spinner(f"Analyzing alert {idx + 1}..."):
                    narrative = generate_investigation_narrative(alert)
                    st.success(narrative)
            else:
                st.info(f"{alert['username']}: Risk Score {alert['risk_score']:.1f}")
        else:
            st.info(f"{alert['username']}: Risk Score {alert['risk_score']:.1f}")
            for reason in alert.get('justification', []):
                st.markdown(f"- {reason}")
        
        st.markdown("---")

# Next Steps
st.subheader("📍 Recommended Next Steps")

st.markdown("""
1. **Prioritize Investigation**: Focus on CRITICAL and HIGH severity alerts
2. **Interview Users**: Verify business justification for flagged activities
3. **Access Audit**: Review recent permission grants
4. **Policy Enforcement**: Implement controls for detected patterns
5. **Continuous Monitoring**: Enable real-time alerts for similar patterns
""")

if st.button("🔄 Refresh Analysis"):
    st.rerun()
    print("Ready for evaluation!")
