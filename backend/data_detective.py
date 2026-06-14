"""
TrustGuardian Security Copilot — Backend Engine
4-specialist AI SOC Analyst: Investigate, Explain, Profile, Predict.
All core logic is deterministic. Gemini is optional for summary polish only.
"""

import re
import pandas as pd
import json
from typing import Dict, List, Any, Optional
from enum import Enum


# ---------------------------------------------------------------------------
# Intent Classification
# ---------------------------------------------------------------------------

class Intent(Enum):
    THREAT_INVESTIGATION = "threat_investigation"
    EMPLOYEE_PROFILE = "employee_profile"
    ALERT_EXPLANATION = "alert_explanation"
    FLIGHT_RISK = "flight_risk"
    OFF_TOPIC = "off_topic"


# Username pattern: user.0001 – user.9999
_USERNAME_RE = re.compile(r'user[.\s_-]?(\d{4})', re.IGNORECASE)

_THREAT_KEYWORDS = [
    'show', 'incidents', 'usb', 'pii', 'critical', 'high', 'restricted',
    'exported', 'accessed', 'off-hours', 'off hours', 'weekend', 'contractor',
    'external', 'email', 'cloud', 'bulk', 'export', 'destination',
    'department', 'data', 'events', 'activities', 'queries', 'records',
    'payroll', 'source_code', 'customer', 'sensitive', 'medium',
]

_EXPLAIN_KEYWORDS = [
    'why', 'flagged', 'explain', 'alert', 'caused', 'reason', 'how come',
    'contributing', 'breakdown', 'score of',
]

_FLIGHT_KEYWORDS = [
    'monitor', 'flight risk', 'predict', 'watchlist', 'breach',
    'next week', 'likely', 'future', 'proactive', 'watch list',
    'pre-breach', 'pre breach', 'dangerous', 'intervention',
]

_PROFILE_KEYWORDS = [
    'tell me about', 'who is', 'profile', 'employee', 'activity',
    'what has', 'been doing', 'recently', 'history', 'about user',
]


def classify_intent(question: str) -> Intent:
    """Classify user question into one of 4 specialist intents (or off-topic)."""
    q = question.lower().strip()

    has_username = bool(_USERNAME_RE.search(q))

    # 1. Alert Explanation — "why was user.XXXX flagged?"
    if has_username and any(kw in q for kw in _EXPLAIN_KEYWORDS):
        return Intent.ALERT_EXPLANATION

    # 2. Employee Profile — "tell me about user.XXXX"
    if has_username and any(kw in q for kw in _PROFILE_KEYWORDS):
        return Intent.EMPLOYEE_PROFILE

    # 3. If username present but no clear intent, default to profile
    if has_username:
        # Check if it's more of a "why" question
        if any(kw in q for kw in ['why', 'explain', 'flagged', 'reason']):
            return Intent.ALERT_EXPLANATION
        return Intent.EMPLOYEE_PROFILE

    # 4. Flight Risk — predictive queries
    if any(kw in q for kw in _FLIGHT_KEYWORDS):
        return Intent.FLIGHT_RISK

    # 5. Threat Investigation — broadest category
    if any(kw in q for kw in _THREAT_KEYWORDS):
        return Intent.THREAT_INVESTIGATION

    # 6. Off-topic
    return Intent.OFF_TOPIC


def _extract_username(question: str) -> Optional[str]:
    """Extract username like user.0058 from question text."""
    m = _USERNAME_RE.search(question)
    if m:
        return f"user.{m.group(1)}"
    return None


# ---------------------------------------------------------------------------
# Helper: ensure severity column exists
# ---------------------------------------------------------------------------

def _ensure_severity(df: pd.DataFrame) -> pd.DataFrame:
    """Compute severity from risk_score if severity column is missing or empty."""
    if 'severity' not in df.columns or (df['severity'].astype(str).str.strip() == '').all():
        def _sev(score):
            if score >= 90:
                return 'CRITICAL'
            elif score >= 75:
                return 'HIGH'
            elif score >= 50:
                return 'MEDIUM'
            return 'LOW'
        df = df.copy()
        df['severity'] = df['risk_score'].apply(_sev)
    return df


# ---------------------------------------------------------------------------
# Specialist 1: Threat Investigator
# ---------------------------------------------------------------------------

def investigate_threats(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Filter security events based on the question and return structured evidence."""
    df = _ensure_severity(df)
    q = question.lower()
    mask = pd.Series([True] * len(df), index=df.index)
    filters_applied = []

    # --- Destination filters ---
    if 'usb' in q or 'removable' in q:
        dest_keywords = ['usb', 'personal_usb', 'usb_drive']
        mask &= df['destination'].astype(str).str.lower().isin(dest_keywords)
        filters_applied.append("destination: USB/removable")

    if 'external' in q and 'email' in q:
        mask &= df['destination'].astype(str).str.lower() == 'external_email'
        filters_applied.append("destination: external_email")

    if 'cloud' in q and 'usb' not in q and 'email' not in q:
        mask &= df['destination'].astype(str).str.lower() == 'cloud_storage'
        filters_applied.append("destination: cloud_storage")

    # --- Severity filters (use risk_score thresholds) ---
    if 'critical' in q:
        mask &= df['risk_score'] >= 90
        filters_applied.append("severity: CRITICAL (risk_score >= 90)")
    elif 'high' in q and 'risk' not in q:
        mask &= df['risk_score'] >= 75
        filters_applied.append("severity: HIGH+ (risk_score >= 75)")

    # --- Data sensitivity ---
    if 'restricted' in q:
        if 'data_sensitivity' in df.columns:
            mask &= df['data_sensitivity'].astype(str).str.lower() == 'restricted'
            filters_applied.append("data_sensitivity: restricted")
    if 'pii' in q:
        if 'data_asset' in df.columns:
            mask &= df['data_asset'].astype(str).str.lower().str.contains('pii')
            filters_applied.append("data_asset: PII")

    # --- Department filters (use word boundaries to avoid 'critical' matching 'it') ---
    departments = ['finance', 'engineering', 'hr', 'it', 'marketing', 'sales']
    for dept in departments:
        if re.search(r'\b' + re.escape(dept) + r'\b', q):
            mask &= df['department'].astype(str).str.lower() == dept
            filters_applied.append(f"department: {dept.title()}")
            break

    # --- Access tier ---
    if 'contractor' in q:
        if 'access_tier' in df.columns:
            mask &= df['access_tier'].astype(str).str.lower() == 'contractor'
            filters_applied.append("access_tier: contractor")

    # --- Time filters ---
    if 'off-hours' in q or 'off hours' in q or 'after hours' in q or 'after business' in q:
        if 'is_off_hours' in df.columns:
            mask &= df['is_off_hours'] == 1
            filters_applied.append("is_off_hours: True")

    if 'weekend' in q:
        if 'timestamp' in df.columns:
            try:
                ts = pd.to_datetime(df['timestamp'], errors='coerce')
                mask &= ts.dt.dayofweek >= 5
                filters_applied.append("day: weekend")
            except Exception:
                pass

    # --- Data asset filters ---
    assets = ['payroll', 'source_code', 'customer_db', 'gl_ledger', 'marketing_assets', 'pii_database']
    for asset in assets:
        if asset.replace('_', ' ') in q or asset in q:
            mask &= df['data_asset'].astype(str).str.lower().str.contains(asset.split('_')[0])
            filters_applied.append(f"data_asset: {asset}")
            break

    # --- Bulk export ---
    if 'bulk' in q or 'large' in q or 'mass' in q:
        if 'rowcount' in df.columns:
            mask &= df['rowcount'] > 10000
            filters_applied.append("rowcount: >10000")

    # Apply filters
    results_df = df[mask].copy()

    # If no filters matched, apply a sensible default rather than returning everything
    if not filters_applied:
        # Return high-risk events as a sensible default
        results_df = df[df['risk_score'] >= 70].copy()
        filters_applied.append("risk_score >= 70 (default: high-risk events)")

    results_df = results_df.sort_values('risk_score', ascending=False)
    num_results = len(results_df)

    # --- Build threat summary ---
    summary_parts = []
    if num_results == 0:
        summary_parts.append("No matching incidents found for your query.")
    else:
        summary_parts.append(f"**{num_results} incident{'s' if num_results != 1 else ''}** detected.")

        if 'username' in results_df.columns and not results_df.empty:
            top_user = results_df.iloc[0]['username']
            top_score = results_df.iloc[0]['risk_score']
            summary_parts.append(f"Highest risk user: **{top_user}** (score: {top_score:.0f})")

        if 'risk_score' in results_df.columns:
            avg_risk = results_df['risk_score'].mean()
            summary_parts.append(f"Average risk score: **{avg_risk:.0f}**")

        if 'department' in results_df.columns:
            top_depts = results_df['department'].value_counts().head(3)
            dept_str = ", ".join([f"{d} ({c})" for d, c in top_depts.items()])
            summary_parts.append(f"Affected departments: {dept_str}")

    summary = "\n\n".join(summary_parts)

    # --- Evidence table ---
    display_cols = ['username', 'department', 'data_asset', 'destination', 'risk_score', 'severity', 'timestamp']
    available_cols = [c for c in display_cols if c in results_df.columns]
    evidence = results_df[available_cols].head(20).copy()
    if 'timestamp' in evidence.columns:
        evidence['timestamp'] = evidence['timestamp'].astype(str)

    # --- Recommendations ---
    recommendations = _generate_threat_recommendations(results_df)

    return {
        'response_type': 'threat_investigation',
        'question': question,
        'summary': summary,
        'num_results': num_results,
        'filters_applied': filters_applied,
        'evidence': evidence.to_dict('records'),
        'recommendations': recommendations,
        'has_results': num_results > 0,
    }


def _generate_threat_recommendations(df: pd.DataFrame) -> List[str]:
    """Generate contextual recommendations based on threat findings."""
    recs = []
    if df.empty:
        return ["Adjust query parameters and retry."]

    if 'destination' in df.columns:
        usb = df[df['destination'].astype(str).str.lower().str.contains('usb', na=False)]
        if not usb.empty:
            recs.append("🔒 Disable removable media access for affected users")
            recs.append("🔍 Review USB device usage logs for data exfiltration patterns")

        ext = df[df['destination'].astype(str).str.lower().str.contains('external', na=False)]
        if not ext.empty:
            recs.append("📧 Block external email destinations and review DLP policies")

    if 'risk_score' in df.columns and (df['risk_score'] >= 90).any():
        recs.append("🚨 Escalate to SOC Tier-2 for immediate investigation")

    if 'is_off_hours' in df.columns and (df['is_off_hours'] == 1).any():
        recs.append("🌙 Investigate off-hours access patterns for potential insider threat")

    if 'access_tier' in df.columns:
        if (df['access_tier'].astype(str).str.lower() == 'contractor').any():
            recs.append("👥 Review contractor access privileges and business justification")

    if not recs:
        recs.append("📋 Review flagged activities and verify business justification")
        recs.append("🔍 Cross-reference with user access permissions")
        recs.append("📝 Document findings for audit trail")

    return recs


# ---------------------------------------------------------------------------
# Specialist 2: Employee Investigator
# ---------------------------------------------------------------------------

def profile_employee(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Build a 360-degree employee investigation profile."""
    df = _ensure_severity(df)
    username = _extract_username(question)

    if not username:
        return {
            'response_type': 'employee_profile',
            'question': question,
            'summary': "Could not identify a username. Please use format: user.XXXX",
            'has_results': False,
            'profile': None,
            'evidence': [],
            'recommendations': [],
        }

    user_df = df[df['username'].astype(str).str.lower() == username.lower()].copy()

    if user_df.empty:
        return {
            'response_type': 'employee_profile',
            'question': question,
            'summary': f"No records found for **{username}**.",
            'has_results': False,
            'profile': None,
            'evidence': [],
            'recommendations': [],
        }

    user_df = user_df.sort_values('risk_score', ascending=False)
    top = user_df.iloc[0]

    # Build profile
    profile = {
        'username': username,
        'department': str(top.get('department', 'Unknown')),
        'access_tier': str(top.get('access_tier', 'Unknown')),
        'total_events': len(user_df),
        'highest_risk_score': float(user_df['risk_score'].max()),
        'average_risk_score': round(float(user_df['risk_score'].mean()), 1),
        'pre_breach_score': float(top.get('pre_breach_score', 0)),
        'pre_breach_level': str(top.get('pre_breach_level', 'LOW')),
    }

    # Unique destinations and assets
    if 'destination' in user_df.columns:
        profile['destinations_used'] = user_df['destination'].dropna().unique().tolist()
    if 'data_asset' in user_df.columns:
        profile['assets_accessed'] = user_df['data_asset'].dropna().unique().tolist()
    if 'severity' in user_df.columns:
        sev_counts = user_df['severity'].value_counts().to_dict()
        profile['severity_breakdown'] = sev_counts

    # Risk trend
    high_risk_count = len(user_df[user_df['risk_score'] >= 70])
    profile['high_risk_events'] = high_risk_count
    if high_risk_count > 3:
        profile['risk_trend'] = "⚠️ Escalating"
    elif high_risk_count > 1:
        profile['risk_trend'] = "📈 Moderate"
    else:
        profile['risk_trend'] = "✅ Stable"

    # Summary
    summary = (
        f"**Employee Investigation Report: {username}**\n\n"
        f"Department: **{profile['department']}** | Access Tier: **{profile['access_tier']}**\n\n"
        f"Highest Risk Score: **{profile['highest_risk_score']:.0f}** | "
        f"Risk Trend: {profile['risk_trend']}\n\n"
        f"Total Events: **{profile['total_events']}** | "
        f"High-Risk Events: **{profile['high_risk_events']}**"
    )

    # Evidence — recent activities
    display_cols = ['timestamp', 'data_asset', 'destination', 'risk_score', 'severity']
    available_cols = [c for c in display_cols if c in user_df.columns]
    evidence = user_df[available_cols].head(10).copy()
    if 'timestamp' in evidence.columns:
        evidence['timestamp'] = evidence['timestamp'].astype(str)

    # Recommendations
    recs = []
    if profile['highest_risk_score'] >= 90:
        recs.append("🚨 Immediate account review and manager notification required")
    if profile['pre_breach_level'] in ('ELEVATED', 'HIGH FLIGHT RISK'):
        recs.append("✈️ User flagged as flight risk — enhanced monitoring recommended")
    if 'usb' in str(profile.get('destinations_used', '')).lower() or 'personal_usb' in str(profile.get('destinations_used', '')).lower():
        recs.append("🔒 Review removable media access for this user")
    if profile['high_risk_events'] > 3:
        recs.append("📋 Escalate to SOC for comprehensive investigation")
    if not recs:
        recs.append("✅ Continue routine monitoring")

    return {
        'response_type': 'employee_profile',
        'question': question,
        'summary': summary,
        'has_results': True,
        'profile': profile,
        'evidence': evidence.to_dict('records'),
        'recommendations': recs,
    }


# ---------------------------------------------------------------------------
# Specialist 3: Alert Explainer
# ---------------------------------------------------------------------------

def explain_alert(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Explain why a specific user was flagged with a score breakdown."""
    df = _ensure_severity(df)
    username = _extract_username(question)

    if not username:
        return {
            'response_type': 'alert_explanation',
            'question': question,
            'summary': "Could not identify a username. Please use format: user.XXXX",
            'has_results': False,
            'score_breakdown': [],
            'evidence': [],
            'recommendations': [],
        }

    user_df = df[df['username'].astype(str).str.lower() == username.lower()].copy()

    if user_df.empty:
        return {
            'response_type': 'alert_explanation',
            'question': question,
            'summary': f"No records found for **{username}**.",
            'has_results': False,
            'score_breakdown': [],
            'evidence': [],
            'recommendations': [],
        }

    # Get highest-risk event for this user
    user_df = user_df.sort_values('risk_score', ascending=False)
    top_event = user_df.iloc[0]
    risk_score = float(top_event.get('risk_score', 0))

    # --- Build score breakdown ---
    breakdown = []

    # Check justification field (from detector.py)
    justifications = top_event.get('justification', [])
    if isinstance(justifications, list) and justifications:
        for j in justifications:
            # Parse "Reason (+points)" format
            parts = str(j).rsplit('(+', 1)
            reason = parts[0].strip()
            points = 0
            if len(parts) == 2:
                try:
                    points = int(parts[1].replace(')', '').strip())
                except ValueError:
                    points = 0
            breakdown.append({'factor': reason, 'points': points})
    else:
        # Reconstruct breakdown from event data
        dest = str(top_event.get('destination', '')).lower()
        if any(x in dest for x in ['usb', 'personal_usb', 'external']):
            breakdown.append({'factor': 'High-Risk Destination (USB/External)', 'points': 30})

        sens = str(top_event.get('data_sensitivity', '')).lower()
        if sens == 'restricted':
            breakdown.append({'factor': 'Restricted Data Access', 'points': 20})
        elif sens == 'high':
            breakdown.append({'factor': 'High Sensitivity Data', 'points': 15})

        if top_event.get('is_off_hours', 0) == 1:
            breakdown.append({'factor': 'Off-hours Access', 'points': 15})

        rowcount = top_event.get('rowcount', 0)
        if pd.notna(rowcount) and rowcount >= 50000:
            breakdown.append({'factor': f'Extreme Bulk Export ({int(rowcount)} records)', 'points': 25})
        elif pd.notna(rowcount) and rowcount >= 10000:
            breakdown.append({'factor': f'Large Export ({int(rowcount)} records)', 'points': 20})

        pre_breach = str(top_event.get('pre_breach_level', '')).upper()
        if pre_breach in ('ELEVATED', 'HIGH FLIGHT RISK'):
            breakdown.append({'factor': 'Flight Risk Flag', 'points': 15})

    # Sort by points descending
    breakdown.sort(key=lambda x: x['points'], reverse=True)

    # Summary
    total_factors = len(breakdown)
    summary = (
        f"**Alert Explanation for {username}**\n\n"
        f"Risk Score: **{risk_score:.0f}/100**\n\n"
        f"**{total_factors} contributing factor{'s' if total_factors != 1 else ''}** identified:"
    )

    # Evidence — the flagged event details
    display_cols = ['timestamp', 'data_asset', 'destination', 'risk_score', 'severity', 'department']
    available_cols = [c for c in display_cols if c in pd.DataFrame([top_event]).columns]
    event_details = {c: str(top_event.get(c, '')) for c in available_cols}

    # Recommendations
    recs = []
    if risk_score >= 90:
        recs.append("🚨 Disable account immediately and escalate to SOC Tier-2")
    elif risk_score >= 75:
        recs.append("📋 Manager review and enhanced monitoring required")
    if any('usb' in b['factor'].lower() or 'external' in b['factor'].lower() for b in breakdown):
        recs.append("🔒 Review and restrict data export destinations")
    if any('off-hours' in b['factor'].lower() for b in breakdown):
        recs.append("⏰ Verify if off-hours access was authorized")
    if any('bulk' in b['factor'].lower() or 'large' in b['factor'].lower() for b in breakdown):
        recs.append("📊 Review DLP controls for bulk data movement")
    if not recs:
        recs.append("📋 Continue monitoring and document findings")

    return {
        'response_type': 'alert_explanation',
        'question': question,
        'summary': summary,
        'has_results': True,
        'risk_score': risk_score,
        'username': username,
        'score_breakdown': breakdown,
        'event_details': event_details,
        'evidence': [event_details],
        'recommendations': recs,
    }


# ---------------------------------------------------------------------------
# Specialist 4: Flight Risk Analyst
# ---------------------------------------------------------------------------

def analyze_flight_risk(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze and predict future insider risk using flight risk data."""

    # Aggregate to user-level (max pre_breach_score per user)
    if 'pre_breach_score' not in df.columns:
        return {
            'response_type': 'flight_risk',
            'question': question,
            'summary': "Flight risk data is not available.",
            'has_results': False,
            'watchlist': [],
            'risk_distribution': {},
            'recommendations': [],
        }

    user_risk = df.groupby(['username', 'department']).agg(
        pre_breach_score=('pre_breach_score', 'max'),
        risk_score=('risk_score', 'max'),
        pre_breach_level=('pre_breach_level', 'first'),
        event_count=('username', 'count'),
    ).reset_index()

    # Get flight risk reasons (from first row of each user)
    user_reasons = {}
    for username in user_risk['username'].unique():
        user_rows = df[df['username'] == username]
        reasons = user_rows['flight_risk_reasons'].dropna().iloc[0] if 'flight_risk_reasons' in user_rows.columns and not user_rows['flight_risk_reasons'].dropna().empty else []
        if isinstance(reasons, list):
            user_reasons[username] = reasons
        else:
            user_reasons[username] = []

    user_risk = user_risk.sort_values('pre_breach_score', ascending=False)

    # Top watchlist users
    watchlist = []
    for _, row in user_risk.head(10).iterrows():
        watchlist.append({
            'username': row['username'],
            'department': row['department'],
            'pre_breach_score': float(row['pre_breach_score']),
            'pre_breach_level': row['pre_breach_level'],
            'risk_score': float(row['risk_score']),
            'reasons': user_reasons.get(row['username'], []),
        })

    # Risk distribution
    risk_dist = user_risk['pre_breach_level'].value_counts().to_dict()

    # Summary
    high_risk_count = len(user_risk[user_risk['pre_breach_score'] >= 60])
    top_user = watchlist[0] if watchlist else None
    summary_parts = [f"**Flight Risk Radar Analysis**"]
    if top_user:
        summary_parts.append(
            f"**{high_risk_count} user{'s' if high_risk_count != 1 else ''}** with elevated or high flight risk detected."
        )
        summary_parts.append(
            f"Highest risk: **{top_user['username']}** "
            f"(pre-breach score: {top_user['pre_breach_score']:.0f})"
        )
    else:
        summary_parts.append("No significant flight risk detected.")

    summary = "\n\n".join(summary_parts)

    # Recommendations
    recs = []
    if high_risk_count > 0:
        recs.append("🔔 Place high-risk users under enhanced monitoring")
        recs.append("👤 Schedule manager check-ins for elevated-risk employees")
    if any(w['pre_breach_score'] >= 80 for w in watchlist):
        recs.append("🚨 Immediate intervention recommended for HIGH FLIGHT RISK users")
    recs.append("📊 Review DLP policies for proactive data protection")
    recs.append("📋 Cross-reference with HR for recent performance reviews or exit signals")

    return {
        'response_type': 'flight_risk',
        'question': question,
        'summary': summary,
        'has_results': bool(watchlist),
        'watchlist': watchlist,
        'risk_distribution': risk_dist,
        'recommendations': recs,
    }


# ---------------------------------------------------------------------------
# Main Router
# ---------------------------------------------------------------------------

def investigate(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """
    Main entry point. Classifies intent and dispatches to the appropriate specialist.
    """
    intent = classify_intent(question)

    if intent == Intent.THREAT_INVESTIGATION:
        return investigate_threats(question, df)

    elif intent == Intent.EMPLOYEE_PROFILE:
        return profile_employee(question, df)

    elif intent == Intent.ALERT_EXPLANATION:
        return explain_alert(question, df)

    elif intent == Intent.FLIGHT_RISK:
        return analyze_flight_risk(question, df)

    else:
        # OFF_TOPIC — reject gracefully
        return {
            'response_type': 'off_topic',
            'question': question,
            'summary': (
                "🛡️ **I'm TrustGuardian Security Copilot** — an AI SOC Analyst.\n\n"
                "I can help you with:\n\n"
                "• 🔍 **Investigate threats** — \"Show me critical USB incidents\"\n\n"
                "• 👤 **Profile employees** — \"Tell me about user.0058\"\n\n"
                "• ❓ **Explain alerts** — \"Why was user.0058 flagged?\"\n\n"
                "• ✈️ **Predict risks** — \"Who should I monitor next week?\"\n\n"
                "Please ask a security-related question."
            ),
            'has_results': False,
            'evidence': [],
            'recommendations': [],
        }
