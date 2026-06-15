"""Streamlit component: context-aware Copilot navigation buttons (replaces floating widget)."""
import streamlit as st


def render_copilot_button(label: str, prompt: str, key: str = "copilot_nav"):
    """
    Render a styled 'Ask Copilot' button that navigates to Security Copilot with a pre-filled prompt.

    Args:
        label: Button label text (e.g., "Explain today's critical incidents")
        prompt: The query to auto-fill in the Security Copilot
        key: Unique key for the Streamlit button
    """
    if st.button(label, key=key, use_container_width=True):
        st.session_state["detective_prompt"] = prompt
        st.switch_page("pages/8_Security_Copilot.py")
