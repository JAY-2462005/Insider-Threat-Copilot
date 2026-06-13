"""
Gemini-backed SOC summaries with deterministic fallbacks.

The Streamlit frontend imports this module on several pages, so Gemini setup must
stay lazy. Importing this file should never consume quota or break the app.
"""

from functools import lru_cache
import os
from pathlib import Path
from typing import Dict, List

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

DEFAULT_MODEL = "gemini-3.5-flash"


class GeminiUnavailableError(RuntimeError):
    """Raised when Gemini cannot be called safely."""


def is_gemini_configured() -> bool:
    return bool(os.getenv("GEMINI_API_KEY"))


def get_gemini_model_name() -> str:
    return os.getenv("GEMINI_MODEL", DEFAULT_MODEL)


def _import_genai():
    try:
        from google import genai
        from google.genai import types
    except ImportError as exc:
        raise GeminiUnavailableError(
            "google-genai is not installed. Run: pip install -r requirements.txt"
        ) from exc

    return genai, types


@lru_cache(maxsize=1)
def _get_client():
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise GeminiUnavailableError("GEMINI_API_KEY is not configured in .env.")

    genai, _ = _import_genai()
    return genai.Client(api_key=api_key)


@lru_cache(maxsize=128)
def _generate_text(prompt: str, max_output_tokens: int, model_name: str) -> str:
    _, types = _import_genai()
    response = _get_client().models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            max_output_tokens=max_output_tokens,
            temperature=0.3,
        ),
    )

    text = getattr(response, "text", "")
    if not text:
        raise GeminiUnavailableError("Gemini returned an empty response.")

    return text.strip()


def _friendly_error(error: Exception) -> str:
    message = str(error)
    lower_message = message.lower()

    if (
        "429" in message
        or "quota" in lower_message
        or "resource_exhausted" in lower_message
        or "rate limit" in lower_message
    ):
        return "Gemini quota or rate limit was reached, so the app is showing a cached/rule-based summary instead."

    if "api key" in lower_message or "permission" in lower_message or "403" in message:
        return "Gemini rejected the API key or permissions, so the app is showing a rule-based summary instead."

    return f"Gemini is unavailable right now, so the app is showing a rule-based summary instead. Detail: {message}"


def _top_patterns(alerts: List[Dict], limit: int = 3):
    threat_patterns = {}
    for alert in alerts:
        for reason in alert.get("justification", []):
            pattern = reason.split("(")[0].strip()
            threat_patterns[pattern] = threat_patterns.get(pattern, 0) + 1

    return sorted(threat_patterns.items(), key=lambda x: x[1], reverse=True)[:limit]


def fallback_investigation_narrative(alert: Dict) -> str:
    context = alert.get("raw_context", {})
    justifications = ", ".join(
        reason.split(" (+")[0].strip()
        for reason in alert.get("justification", [])
    ) or "behavioral deviation from baseline"

    return (
        f"{alert.get('username', 'The user')} from {alert.get('department', 'an unknown department')} "
        f"triggered a {alert.get('severity', 'UNKNOWN')} insider-threat alert after accessing "
        f"{alert.get('data_asset', 'an unknown asset')} at {alert.get('timestamp', 'an unknown time')}. "
        f"The event involved {context.get('rowcount', alert.get('rowcount', 'unknown'))} records "
        f"sent to {context.get('destination', alert.get('destination', 'an unknown destination'))}, "
        f"with risk factors including {justifications}. "
        "SOC should verify business justification, review recent access history, and apply the recommended containment actions."
    )


def fallback_executive_summary(alerts: List[Dict]) -> str:
    if not alerts:
        return "No critical threats detected. Security posture is healthy."

    critical_count = len([a for a in alerts if a.get("severity") == "CRITICAL"])
    high_count = len([a for a in alerts if a.get("severity") == "HIGH"])
    avg_score = sum(float(a.get("risk_score", 0)) for a in alerts) / len(alerts)
    patterns = _top_patterns(alerts)
    pattern_text = ", ".join(f"{pattern} ({count})" for pattern, count in patterns) or "mixed behavioral anomalies"

    departments = {}
    for alert in alerts:
        dept = alert.get("department", "Unknown")
        departments[dept] = departments.get(dept, 0) + 1

    top_department = max(departments, key=departments.get) if departments else "Unknown"

    return (
        f"{len(alerts)} events exceed the current alert threshold, including {critical_count} critical "
        f"and {high_count} high-severity alerts. Average alert risk is {avg_score:.1f}/100, "
        f"with the highest concentration in {top_department}. The most common risk patterns are {pattern_text}. "
        "Leadership should prioritize critical investigations, validate business need for unusual data movement, "
        "and review access controls for the affected departments and assets."
    )


def fallback_incident_timeline(alert: Dict) -> str:
    context = alert.get("raw_context", {})
    timestamp = alert.get("timestamp", "the recorded event time")
    return (
        f"At {timestamp}, {alert.get('username', 'the user')} executed "
        f"{context.get('query_type', alert.get('query_type', 'a data access operation'))} against "
        f"{alert.get('data_asset', 'an unknown asset')}. The event moved "
        f"{context.get('rowcount', alert.get('rowcount', 'unknown'))} records to "
        f"{context.get('destination', alert.get('destination', 'an unknown destination'))} and was scored "
        f"{alert.get('risk_score', 0):.1f}/100, causing escalation as {alert.get('severity', 'UNKNOWN')}."
    )


def _call_or_fallback(prompt: str, max_output_tokens: int, fallback_text: str) -> str:
    try:
        return _generate_text(prompt, max_output_tokens, get_gemini_model_name())
    except Exception as exc:
        return f"{_friendly_error(exc)}\n\n{fallback_text}"


def generate_investigation_narrative(alert: Dict) -> str:
    """
    Generate a professional SOC analyst narrative for an alert.
    Falls back locally if Gemini is unavailable or quota-limited.
    """
    prompt = f"""You are a senior SOC (Security Operations Center) analyst at a Fortune 500 company.
A potential insider threat has been detected. Generate a concise, professional investigation summary.

ALERT DATA:
- User: {alert.get('username', 'Unknown')}
- Department: {alert.get('department', 'Unknown')}
- Risk Score: {alert.get('risk_score', 0):.1f}/100
- Severity: {alert.get('severity', 'UNKNOWN')}
- Data Accessed: {alert.get('data_asset', 'Unknown')}
- Risk Factors:
{chr(10).join(['  - ' + str(r) for r in alert.get('justification', [])])}

TASK:
Write a 3-4 sentence professional summary that:
1. Describes what happened
2. Explains why it is risky
3. Recommends immediate SOC actions

Keep it concise, technical, and actionable. No sensationalism."""

    return _call_or_fallback(
        prompt,
        max_output_tokens=300,
        fallback_text=fallback_investigation_narrative(alert),
    )


def generate_executive_summary(alerts: List[Dict]) -> str:
    """
    Generate an executive-level security posture report.
    Falls back locally if Gemini is unavailable or quota-limited.
    """
    if not alerts:
        return fallback_executive_summary(alerts)

    critical_count = len([a for a in alerts if a.get("severity") == "CRITICAL"])
    high_count = len([a for a in alerts if a.get("severity") == "HIGH"])
    avg_score = sum(float(a.get("risk_score", 0)) for a in alerts) / len(alerts)
    top_patterns = _top_patterns(alerts, limit=5)

    dept_alerts = {}
    for alert in alerts:
        dept = alert.get("department", "Unknown")
        dept_alerts[dept] = dept_alerts.get(dept, 0) + 1

    prompt = f"""You are a Chief Information Security Officer preparing a security briefing.
Summarize the insider-threat landscape for executive leadership.

THREAT SUMMARY:
- Total Threats Detected: {len(alerts)}
- Critical Alerts: {critical_count}
- High-Risk Alerts: {high_count}
- Average Risk Score: {avg_score:.1f}/100

TOP THREAT PATTERNS:
{chr(10).join([f'- {pattern}: {count} incidents' for pattern, count in top_patterns])}

AFFECTED DEPARTMENTS:
{chr(10).join([f'- {dept}: {count} alerts' for dept, count in sorted(dept_alerts.items(), key=lambda x: x[1], reverse=True)[:5]])}

TASK:
Write a 4-5 sentence executive summary that:
1. Summarizes the current threat landscape
2. Highlights primary risk factors
3. Recommends strategic actions
4. Assesses overall security posture

Use clear, non-technical language suitable for C-level executives."""

    return _call_or_fallback(
        prompt,
        max_output_tokens=400,
        fallback_text=fallback_executive_summary(alerts),
    )


def generate_incident_timeline(alert: Dict) -> str:
    """
    Generate a timeline narrative for an incident.
    Falls back locally if Gemini is unavailable or quota-limited.
    """
    context = alert.get("raw_context", {})
    prompt = f"""You are a forensic analyst reconstructing an incident timeline.

INCIDENT DATA:
- User: {alert.get('username', 'Unknown')}
- Timestamp: {alert.get('timestamp', 'Unknown')}
- Data Asset: {alert.get('data_asset', 'Unknown')}
- Rowcount: {context.get('rowcount', 'Unknown')} records
- Destination: {context.get('destination', 'Unknown')}
- Risk Score: {alert.get('risk_score', 0):.1f}/100

TASK:
Write a detailed incident timeline in 2-3 sentences that reconstructs what likely happened,
including suspicious timing, data volume, and destination indicators."""

    return _call_or_fallback(
        prompt,
        max_output_tokens=250,
        fallback_text=fallback_incident_timeline(alert),
    )


def test_gemini_connection():
    """Test if Gemini is configured correctly. This consumes one Gemini request."""
    try:
        response = _generate_text(
            "Say Gemini is ready in one short sentence.",
            50,
            get_gemini_model_name(),
        )
        return True, response
    except Exception as exc:
        return False, _friendly_error(exc)


if __name__ == "__main__":
    success, message = test_gemini_connection()
    status = "Connected" if success else "Unavailable"
    print(f"Gemini {status}: {message}")
