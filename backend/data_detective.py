"""
TrustGuardian Data Detective
Natural language query interface for security investigation
"""

import pandas as pd
import json
from typing import Dict, List, Any, Optional
import os
from pathlib import Path

try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Load Gemini API key from environment
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
if GEMINI_AVAILABLE and GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)


def parse_question(question: str, available_columns: List[str]) -> Dict[str, Any]:
    """
    Convert natural language question into structured JSON filters using Gemini.
    
    Args:
        question: Natural language question from analyst
        available_columns: List of available column names in the dataset
        
    Returns:
        Dictionary with filter conditions
    """
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
        # Fallback: simple keyword matching
        return _parse_question_fallback(question, available_columns)
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""You are a security data query translator. Convert natural language questions into JSON filters.

Available columns: {', '.join(available_columns)}

Column descriptions:
- username: Employee username
- department: Department name (Finance, IT, Engineering, HR, Marketing, Sales)
- access_tier: Access level (junior, standard, senior, admin, executive, contractor)
- data_sensitivity: Data sensitivity (low, medium, high, restricted)
- data_asset: Data asset name
- timestamp: Event timestamp
- risk_score: Calculated risk score (0-100)
- severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
- destination: Data destination (local, cloud, usb, external_email, etc.)
- query_type: Query type (SELECT, EXPORT, INSERT, UPDATE, DELETE)
- rowcount: Number of rows affected
- is_off_hours: Whether access was outside business hours (0 or 1)
- pre_breach_score: Flight risk pre-breach score (0-100)
- pre_breach_level: Flight risk level (LOW, WATCHLIST, ELEVATED, HIGH FLIGHT RISK)

Return ONLY valid JSON. No explanations.

Examples:
Question: "Show me contractors who accessed restricted data this weekend"
JSON: {{"access_tier": "contractor", "data_sensitivity": "restricted", "is_weekend": true}}

Question: "Who exported more than 10000 records after business hours?"
JSON: {{"rowcount_gt": 10000, "is_off_hours": 1, "query_type": "EXPORT"}}

Question: "Show me all critical incidents"
JSON: {{"severity": "CRITICAL"}}

Question: "Which employees have high flight risk?"
JSON: {{"pre_breach_level": "HIGH FLIGHT RISK"}}

Now convert this question:
Question: "{question}"

JSON:"""

        response = model.generate_content(prompt)
        json_str = response.text.strip()
        
        # Clean up any markdown code blocks
        if json_str.startswith('```'):
            json_str = json_str.replace('```json', '').replace('```', '').strip()
        
        filters = json.loads(json_str)
        return filters
        
    except Exception as e:
        print(f"Gemini parsing error: {e}")
        return _parse_question_fallback(question, available_columns)


def _parse_question_fallback(question: str, available_columns: List[str]) -> Dict[str, Any]:
    """
    Fallback simple keyword-based parsing when Gemini is unavailable.
    """
    question_lower = question.lower()
    filters = {}
    
    # Simple keyword matching
    if 'contractor' in question_lower:
        filters['access_tier'] = 'contractor'
    if 'restricted' in question_lower:
        filters['data_sensitivity'] = 'restricted'
    if 'critical' in question_lower:
        filters['severity'] = 'CRITICAL'
    if 'high' in question_lower and 'risk' in question_lower:
        filters['severity'] = 'HIGH'
    if 'usb' in question_lower or 'removable' in question_lower:
        filters['destination'] = 'usb'
    if 'weekend' in question_lower:
        filters['is_weekend'] = True
    if 'flight' in question_lower and 'risk' in question_lower:
        filters['pre_breach_level'] = 'HIGH FLIGHT RISK'
    
    return filters


def execute_filters(df: pd.DataFrame, filters: Dict[str, Any]) -> pd.DataFrame:
    """
    Execute JSON filters on pandas dataframe.
    
    Args:
        df: Input dataframe with security events
        filters: Dictionary of filter conditions from parse_question()
        
    Returns:
        Filtered dataframe
    """
    if not filters:
        return df
    
    mask = pd.Series([True] * len(df), index=df.index)
    
    for key, value in filters.items():
        if key not in df.columns and key not in ['is_weekend', 'rowcount_gt', 'rowcount_lt']:
            continue
            
        if key == 'is_weekend':
            if value:
                mask &= (df['timestamp'].dt.dayofweek >= 5)
        elif key == 'rowcount_gt':
            if 'rowcount' in df.columns:
                mask &= (df['rowcount'] > value)
        elif key == 'rowcount_lt':
            if 'rowcount' in df.columns:
                mask &= (df['rowcount'] < value)
        elif key == 'risk_score_gt':
            if 'risk_score' in df.columns:
                mask &= (df['risk_score'] > value)
        elif key == 'risk_score_lt':
            if 'risk_score' in df.columns:
                mask &= (df['risk_score'] < value)
        elif key == 'pre_breach_score_gt':
            if 'pre_breach_score' in df.columns:
                mask &= (df['pre_breach_score'] > value)
        else:
            # Direct column match
            if key in df.columns:
                if isinstance(value, list):
                    mask &= df[key].isin(value)
                else:
                    mask &= (df[key] == value)
    
    return df[mask]


def generate_summary(question: str, results_df: pd.DataFrame, num_results: int) -> str:
    """
    Generate executive summary of findings using Gemini.
    
    Args:
        question: Original natural language question
        results_df: Filtered results dataframe
        num_results: Number of results found
        
    Returns:
        Human-readable summary narrative
    """
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
        # Fallback summary
        return _generate_summary_fallback(question, num_results)
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        
        # Get sample of results for context
        if not results_df.empty:
            sample_data = results_df.head(5)[['username', 'department', 'data_asset', 'risk_score', 'timestamp']].to_dict('records')
            sample_str = json.dumps(sample_data, indent=2, default=str)
        else:
            sample_str = "No results found"
        
        prompt = f"""You are a security investigation assistant. Write an executive summary of the findings.

Question: "{question}"

Results found: {num_results}

Sample data:
{sample_str}

Write a concise, professional summary (2-3 sentences) that:
1. States what was found
2. Highlights any concerning patterns
3. Suggests appropriate next steps

Be direct and actionable. No conversational filler."""

        response = model.generate_content(prompt)
        return response.text.strip()
        
    except Exception as e:
        print(f"Gemini summary error: {e}")
        return _generate_summary_fallback(question, num_results)


def _generate_summary_fallback(question: str, num_results: int) -> str:
    """
    Fallback summary when Gemini is unavailable.
    """
    if num_results == 0:
        return "No matching activities were found based on your query criteria."
    elif num_results == 1:
        return f"Found 1 matching activity. Review the details below for investigation."
    else:
        return f"Found {num_results} matching activities. These should be reviewed for potential security concerns."


def generate_contextual_recommendations(results_df: pd.DataFrame) -> List[str]:
    """
    Generate contextual recommended actions based on result characteristics.
    
    Args:
        results_df: Filtered results dataframe
        
    Returns:
        List of recommended actions
    """
    recommendations = []
    
    if results_df.empty:
        return recommendations
    
    # Check for USB/removable media
    if 'destination' in results_df.columns:
        usb_keywords = ['usb', 'removable', 'external', 'personal']
        usb_results = results_df[results_df['destination'].astype(str).str.lower().str.contains('|'.join(usb_keywords), na=False)]
        if not usb_results.empty:
            recommendations.append("🔒 Disable removable media access for affected users")
            recommendations.append("🔍 Review USB device usage logs for data exfiltration patterns")
    
    # Check for contractors
    if 'access_tier' in results_df.columns:
        contractor_results = results_df[results_df['access_tier'].astype(str).str.lower() == 'contractor']
        if not contractor_results.empty:
            recommendations.append("👥 Review contractor access privileges and business justification")
            recommendations.append("📋 Verify contractor compliance with data handling policies")
    
    # Check for PII/sensitive data
    if 'data_sensitivity' in results_df.columns:
        pii_keywords = ['restricted', 'high', 'pii']
        pii_results = results_df[results_df['data_sensitivity'].astype(str).str.lower().str.contains('|'.join(pii_keywords), na=False)]
        if not pii_results.empty:
            recommendations.append("⚠️ Escalate to compliance teams for PII access review")
            recommendations.append("📝 Document PII access for audit trail requirements")
    
    # Check for high risk scores
    if 'risk_score' in results_df.columns:
        high_risk_results = results_df[results_df['risk_score'] >= 75]
        if not high_risk_results.empty:
            recommendations.append("🚨 Immediate SOC review recommended for high-risk activities")
            recommendations.append("🔔 Consider implementing additional monitoring for affected users")
    
    # Check for off-hours access
    if 'is_off_hours' in results_df.columns:
        off_hours_results = results_df[results_df['is_off_hours'] == 1]
        if not off_hours_results.empty:
            recommendations.append("🌙 Investigate off-hours access patterns for potential insider threat")
            recommendations.append("⏰ Verify if off-hours access was authorized")
    
    # Default recommendation if no specific patterns found
    if not recommendations:
        recommendations.append("📋 Review the activities above for security relevance")
        recommendations.append("🔍 Cross-reference with user access permissions")
        recommendations.append("📝 Document findings for audit trail")
    
    return recommendations


def get_available_columns(df: pd.DataFrame) -> List[str]:
    """
    Get list of available columns for query parsing.
    """
    return df.columns.tolist()


def investigate(question: str, df: pd.DataFrame) -> Dict[str, Any]:
    """
    Complete investigation pipeline: parse, filter, summarize.
    
    Args:
        question: Natural language question
        df: Input dataframe with security events
        
    Returns:
        Dictionary with results, summary, and metadata
    """
    available_columns = get_available_columns(df)
    
    # Step 1: Parse question into filters
    filters = parse_question(question, available_columns)
    
    # Step 2: Execute filters
    results_df = execute_filters(df, filters)
    num_results = len(results_df)
    
    # Step 3: Generate summary
    summary = generate_summary(question, results_df, num_results)
    
    # Step 4: Generate contextual recommendations
    recommendations = generate_contextual_recommendations(results_df)
    
    # Step 5: Prepare results for display
    if not results_df.empty:
        # Select key columns for display
        display_columns = ['username', 'department', 'data_asset', 'risk_score', 'timestamp', 'severity']
        available_display_cols = [col for col in display_columns if col in results_df.columns]
        results_display = results_df[available_display_cols].head(20).copy()
        
        # Convert timestamp to string for JSON serialization
        if 'timestamp' in results_display.columns:
            results_display['timestamp'] = results_display['timestamp'].astype(str)
        
        results_list = results_display.to_dict('records')
    else:
        results_list = []
    
    return {
        'question': question,
        'filters_applied': filters,
        'num_results': num_results,
        'summary': summary,
        'recommendations': recommendations,
        'results': results_list,
        'has_results': num_results > 0
    }
