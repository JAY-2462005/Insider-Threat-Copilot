"""
TrustGuardian RAG Copilot — Pandas retrieval + local Qwen via Ollama.

Architecture:
    question → retrieve_context() → build_prompt() → ask_qwen() → structured response
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

import pandas as pd

from data_detective import (
    Intent,
    advise_security,
    analyze_flight_risk,
    classify_intent,
    explain_alert,
    investigate_threats,
    profile_employee,
    _ensure_severity,
    _extract_username,
    _generate_threat_recommendations,
)

DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
_USERNAME_RE = re.compile(r"user[.\s_-]?(\d{4})", re.IGNORECASE)

EVIDENCE_COLUMNS = [
    "username",
    "department",
    "data_asset",
    "destination",
    "risk_score",
    "severity",
    "timestamp",
    "rowcount",
    "pre_breach_score",
    "pre_breach_level",
]


def is_ollama_available() -> bool:
    """Return True when Ollama is running and the configured model is present."""
    try:
        import ollama

        models = ollama.list().get("models", [])
        model_names = {m.get("model", m.get("name", "")) for m in models}
        target = DEFAULT_MODEL.split(":")[0]
        return any(name.startswith(target) for name in model_names)
    except Exception:
        return _ollama_model_available_via_http()


def _ollama_model_available_via_http() -> bool:
    try:
        with urllib.request.urlopen(f"{OLLAMA_HOST}/api/tags", timeout=2) as response:
            payload = json.loads(response.read().decode("utf-8"))
        target = DEFAULT_MODEL.split(":")[0]
        for model in payload.get("models", []):
            name = model.get("name", "")
            if name.startswith(target):
                return True
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError):
        return False
    return False


def _ask_qwen_http(prompt: str, model: Optional[str] = None) -> str:
    payload = {
        "model": model or DEFAULT_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 320},
    }
    request = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode("utf-8"))
    return body.get("message", {}).get("content", "").strip()


def retrieve_context(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """
    Pandas-based retrieval layer.

    Routes the question to the right specialist, returns structured evidence
    compatible with the Security Copilot UI.
    """
    df = _ensure_severity(df)
    intent = classify_intent(question)
    q = question.lower()

    usernames = _extract_all_usernames(question)
    if len(usernames) >= 2 or ("compare" in q and usernames):
        return _compare_users(question, df, usernames)

    if intent == Intent.THREAT_INVESTIGATION:
        return investigate_threats(question, df)
    if intent == Intent.EMPLOYEE_PROFILE:
        return profile_employee(question, df)
    if intent == Intent.ALERT_EXPLANATION:
        return explain_alert(question, df)
    if intent == Intent.FLIGHT_RISK:
        return analyze_flight_risk(question, df)
    if intent == Intent.SECURITY_ADVISORY:
        return advise_security(question, df)

    return {
        "response_type": "off_topic",
        "question": question,
        "summary": (
            "I'm TrustGuardian Security Copilot — an offline SOC analyst.\n\n"
            "Try:\n"
            "• Show contractors with critical alerts\n"
            "• Explain why user.0058 is suspicious\n"
            "• Which department generated most alerts?\n"
            "• Who has high flight risk?\n"
            "• Compare user.0058 and user.0092\n"
            "• Summarize this week's incidents"
        ),
        "has_results": False,
        "evidence": [],
        "recommendations": [],
    }


def _extract_all_usernames(question: str) -> List[str]:
    return [f"user.{match.group(1)}" for match in _USERNAME_RE.finditer(question)]


def _compare_users(question: str, df: pd.DataFrame, usernames: List[str]) -> Dict[str, Any]:
    """Side-by-side comparison for two or more users."""
    users = usernames[:2]
    frames = []
    profiles = []

    for username in users:
        user_df = df[df["username"].astype(str).str.lower() == username.lower()].copy()
        if user_df.empty:
            continue
        user_df = user_df.sort_values("risk_score", ascending=False)
        top = user_df.iloc[0]
        profiles.append(
            {
                "username": username,
                "department": str(top.get("department", "Unknown")),
                "peak_risk": float(user_df["risk_score"].max()),
                "avg_risk": round(float(user_df["risk_score"].mean()), 1),
                "events": len(user_df),
                "pre_breach_score": float(top.get("pre_breach_score", 0)),
                "pre_breach_level": str(top.get("pre_breach_level", "LOW")),
            }
        )
        cols = [c for c in EVIDENCE_COLUMNS if c in user_df.columns]
        sample = user_df[cols].head(5).copy()
        if "timestamp" in sample.columns:
            sample["timestamp"] = sample["timestamp"].astype(str)
        frames.extend(sample.to_dict("records"))

    if not profiles:
        return {
            "response_type": "user_comparison",
            "question": question,
            "summary": "No matching users found for comparison.",
            "has_results": False,
            "profiles": [],
            "evidence": [],
            "recommendations": [],
        }

    higher = max(profiles, key=lambda p: p["peak_risk"])
    summary = (
        f"Comparison of **{profiles[0]['username']}**"
        + (f" vs **{profiles[1]['username']}**" if len(profiles) > 1 else "")
        + f". Highest peak risk: **{higher['username']}** ({higher['peak_risk']:.0f}/100)."
    )

    return {
        "response_type": "user_comparison",
        "question": question,
        "summary": summary,
        "has_results": True,
        "profiles": profiles,
        "evidence": frames,
        "recommendations": _generate_threat_recommendations(
            df[df["username"].astype(str).str.lower().isin([u.lower() for u in users])]
        ),
    }


def _format_row(row: Dict[str, Any]) -> str:
    parts = []
    for key in EVIDENCE_COLUMNS:
        value = row.get(key, "")
        if value != "" and value is not None:
            label = key.replace("_", " ").title()
            parts.append(f"{label}: {value}")
    return " | ".join(parts)


def _format_evidence(result: Dict[str, Any]) -> str:
    """Convert structured retrieval output into plain-text evidence for the LLM."""
    lines: List[str] = []
    response_type = result.get("response_type", "")

    if response_type == "employee_profile" and result.get("profile"):
        profile = result["profile"]
        lines.append(f"User: {profile.get('username')}")
        lines.append(f"Department: {profile.get('department')}")
        lines.append(f"Access Tier: {profile.get('access_tier')}")
        lines.append(f"Highest Risk Score: {profile.get('highest_risk_score')}")
        lines.append(f"Average Risk Score: {profile.get('average_risk_score')}")
        lines.append(f"High-Risk Events: {profile.get('high_risk_events')}")
        lines.append(f"Pre-Breach Level: {profile.get('pre_breach_level')}")
        lines.append(f"Destinations Used: {profile.get('destinations_used', [])}")
        lines.append(f"Assets Accessed: {profile.get('assets_accessed', [])}")

    elif response_type == "alert_explanation":
        lines.append(f"User: {result.get('username')}")
        lines.append(f"Risk Score: {result.get('risk_score')}")
        for item in result.get("score_breakdown", []):
            lines.append(f"Factor: {item.get('factor')} (+{item.get('points')} pts)")
        for key, value in result.get("event_details", {}).items():
            lines.append(f"{key}: {value}")

    elif response_type == "flight_risk":
        for user in result.get("watchlist", [])[:8]:
            reasons = ", ".join(user.get("reasons", [])[:3])
            lines.append(
                f"User: {user.get('username')} | Department: {user.get('department')} | "
                f"Pre-Breach: {user.get('pre_breach_score')} | Risk: {user.get('risk_score')} | "
                f"Reasons: {reasons}"
            )

    elif response_type == "user_comparison":
        for profile in result.get("profiles", []):
            lines.append(
                f"User: {profile['username']} | Department: {profile['department']} | "
                f"Peak Risk: {profile['peak_risk']} | Avg Risk: {profile['avg_risk']} | "
                f"Events: {profile['events']} | Pre-Breach: {profile['pre_breach_level']}"
            )

    elif response_type == "security_advisory":
        for stage in result.get("stages", []):
            lines.append(f"{stage.get('phase')}: {', '.join(stage.get('actions', []))}")

    else:
        if result.get("filters_applied"):
            lines.append("Filters Applied: " + "; ".join(result["filters_applied"]))
        lines.append(f"Incident Count: {result.get('num_results', len(result.get('evidence', [])))}")

    for row in result.get("evidence", [])[:12]:
        if isinstance(row, dict):
            lines.append(_format_row(row))

    if not lines:
        return "No matching evidence rows were retrieved."

    return "\n".join(lines)


def build_prompt(question: str, evidence: str, response_type: str = "") -> str:
    """Build a grounded SOC prompt for Qwen."""
    role_hint = {
        "threat_investigation": "Summarize the incident pattern and affected users.",
        "employee_profile": "Assess this employee's insider-threat posture.",
        "alert_explanation": "Explain why this alert was triggered.",
        "flight_risk": "Recommend proactive monitoring for the highest-risk users.",
        "user_comparison": "Compare the users and identify which one needs escalation first.",
        "security_advisory": "Answer the SOC procedure question using the evidence context.",
    }.get(response_type, "Answer like a SOC analyst.")

    return f"""You are TrustGuardian, an offline SOC analyst copilot.

Rules:
- Answer ONLY using the evidence below.
- Do NOT invent users, assets, timestamps, or risk scores.
- Be concise, technical, and actionable.
- Write 3 to 5 sentences.
- {role_hint}

Question:
{question}

Evidence:
{evidence}

Analyst Summary:"""


def ask_qwen(prompt: str, model: Optional[str] = None) -> str:
    """Call local Qwen through Ollama. Returns empty string if unavailable."""
    try:
        import ollama

        response = ollama.chat(
            model=model or DEFAULT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.2, "num_predict": 320},
        )
        text = response.get("message", {}).get("content", "").strip()
        if text:
            return text
    except Exception:
        pass

    try:
        return _ask_qwen_http(prompt, model=model)
    except Exception:
        return ""


def _fallback_narrative(result: Dict[str, Any]) -> str:
    """Deterministic narrative when Ollama is unavailable."""
    response_type = result.get("response_type", "")
    if response_type == "alert_explanation" and result.get("username"):
        factors = ", ".join(item["factor"] for item in result.get("score_breakdown", [])[:4])
        return (
            f"{result['username']} triggered a high-risk alert at "
            f"{result.get('risk_score', 0):.0f}/100 due to {factors or 'multiple risk factors'}. "
            "SOC should verify business justification, review recent exports, and apply containment actions."
        )
    if response_type == "employee_profile" and result.get("profile"):
        profile = result["profile"]
        return (
            f"{profile['username']} in {profile['department']} shows a peak risk of "
            f"{profile['highest_risk_score']:.0f}/100 across {profile['total_events']} events. "
            f"Pre-breach level is {profile['pre_breach_level']}. Continue enhanced monitoring if risk remains elevated."
        )
    if response_type == "flight_risk" and result.get("watchlist"):
        top = result["watchlist"][0]
        return (
            f"The highest flight-risk user is {top['username']} with a pre-breach score of "
            f"{top['pre_breach_score']:.0f}. Prioritize manager check-ins, DLP review, and proactive monitoring."
        )
    if response_type == "user_comparison" and result.get("profiles"):
        profiles = result["profiles"]
        return (
            f"{profiles[0]['username']} peaks at {profiles[0]['peak_risk']:.0f}/100"
            + (
                f", while {profiles[1]['username']} peaks at {profiles[1]['peak_risk']:.0f}/100."
                if len(profiles) > 1
                else "."
            )
            + " Escalate the user with the higher peak risk and overlapping risky destinations first."
        )
    return result.get("summary", "Review the evidence table and apply the recommended SOC actions.")


def ask_copilot(question: str, df: pd.DataFrame, use_llm: bool = True) -> Dict[str, Any]:
    """
    Main entry point for the Security Copilot.

    Returns narrative, evidence rows, recommendations, and metadata for the UI.
    """
    result = retrieve_context(question, df)
    evidence_text = _format_evidence(result)
    prompt = build_prompt(question, evidence_text, result.get("response_type", ""))

    narrative = ""
    llm_provider = "rule-based"
    if use_llm and result.get("has_results") and result.get("response_type") != "off_topic":
        narrative = ask_qwen(prompt)
        if narrative:
            llm_provider = "qwen-local"

    if not narrative:
        narrative = _fallback_narrative(result)

    result["narrative"] = narrative
    result["ai_narrative"] = narrative
    result["llm_provider"] = llm_provider
    result["prompt_preview"] = prompt[:500] + ("..." if len(prompt) > 500 else "")
    return result


def investigate(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """Backward-compatible alias used by the frontend."""
    return ask_copilot(question, df)


if __name__ == "__main__":
    from pathlib import Path

    from detector import load_and_merge_data, feature_engineering, train_and_predict

    project_root = Path(__file__).resolve().parents[1]
    logs = project_root / "data" / "data_access_logs.csv"
    profiles = project_root / "data" / "user_profiles.csv"

    if not logs.exists() or not profiles.exists():
        print("Place CSV files in data/ first.")
        raise SystemExit(1)

    frame = load_and_merge_data(str(logs), str(profiles))
    frame = feature_engineering(frame)
    frame = train_and_predict(frame)
    frame = _ensure_severity(frame)

    sample_question = "Why was user.0058 flagged?"
    print(f"Ollama available: {is_ollama_available()}")
    print(f"Model: {DEFAULT_MODEL}\n")

    answer = ask_copilot(sample_question, frame)
    print("Question:", sample_question)
    print("Provider:", answer.get("llm_provider"))
    print("Narrative:", answer.get("narrative"))
    print("Evidence rows:", len(answer.get("evidence", [])))
