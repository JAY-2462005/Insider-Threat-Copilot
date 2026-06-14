import streamlit as st
import pandas as pd
import sys
import os
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from data_service import get_events_dataframe

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'backend')))
from data_detective import investigate

st.set_page_config(page_title="Data Detective", page_icon="🤖", layout="wide")

st.title("🤖 TrustGuardian Data Detective")
st.markdown("### Natural Language Security Investigation")

# Initialize chat history in session state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []
if 'data_loaded' not in st.session_state:
    st.session_state.data_loaded = False

# Load data
try:
    df = get_events_dataframe()
    st.session_state.data_loaded = True
except FileNotFoundError:
    st.error("❌ Data files not found. Please run generate_ps4_data.py first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading data: {str(e)}")
    st.stop()

# Main layout
col_chat, col_results = st.columns([1, 2])

with col_chat:
    st.subheader("💬 Investigation Chat")
    
    # Chat history container
    chat_container = st.container()
    
    with chat_container:
        for i, message in enumerate(st.session_state.chat_history):
            if message['role'] == 'user':
                st.markdown(f"""
                <div style='background-color: #e3f2fd; padding: 10px; border-radius: 10px; margin: 10px 0;'>
                <strong>You:</strong> {message['content']}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style='background-color: #f5f5f5; padding: 10px; border-radius: 10px; margin: 10px 0;'>
                <strong>🤖 TrustGuardian:</strong> {message['content']}
                </div>
                """, unsafe_allow_html=True)
    
    # Input area
    st.markdown("---")
    
    # Check for pre-filled prompt from other pages
    default_prompt = st.session_state.get("detective_prompt", "")
    if default_prompt:
        st.session_state["detective_prompt"] = ""  # Clear after use
    
    user_question = st.text_area(
        "Ask a security question:",
        placeholder="e.g., Show me contractors who accessed restricted data this weekend",
        height=100,
        key="user_input",
        value=default_prompt
    )
    
    col_send, col_clear = st.columns([3, 1])
    
    with col_send:
        send_button = st.button("🔍 Investigate", use_container_width=True, type="primary")
    
    with col_clear:
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()

with col_results:
    st.subheader("📊 Investigation Results")
    
    if not st.session_state.chat_history:
        st.info("""
        💡 **Sample Questions to Try:**
        
        - Show me all critical incidents involving USB devices
        - Which employees accessed PII after business hours?
        - Who has a pre-breach score above 70?
        - Show me all high-risk employees with restricted access
        - Show contractor activity this weekend
        - Which department generated the most alerts?
        - Show me flight-risk users accessing restricted assets
        """)
    else:
        # Display the most recent investigation results
        latest_message = st.session_state.chat_history[-1]
        if latest_message['role'] == 'assistant' and 'results' in latest_message:
            results_data = latest_message['results']
            
            # Summary
            st.markdown(f"**Summary:** {results_data['summary']}")
            st.markdown(f"**Results Found:** {results_data['num_results']}")
            
            if results_data['has_results']:
                # Results table
                results_df = pd.DataFrame(results_data['results'])
                
                # Format for display
                display_cols = ['username', 'department', 'data_asset', 'risk_score', 'timestamp']
                available_cols = [col for col in display_cols if col in results_df.columns]
                
                if available_cols:
                    display_df = results_df[available_cols].copy()
                    display_df.columns = [col.replace('_', ' ').title() for col in display_df.columns]
                    st.dataframe(display_df, use_container_width=True, hide_index=True)
                
                # Recommended actions based on results
                st.markdown("---")
                st.markdown("### 🎯 Recommended Actions")
                
                if 'recommendations' in results_data and results_data['recommendations']:
                    for recommendation in results_data['recommendations']:
                        st.markdown(f"• {recommendation}")
                elif results_data['num_results'] > 0:
                    st.markdown("• Review the activities above for security relevance")
                    st.markdown("• Cross-reference with user access permissions")
                    st.markdown("• Document findings for audit trail")
            else:
                st.warning("No matching activities found. Try adjusting your query terms.")

# Handle send button
if send_button and user_question.strip():
    # Add user message to chat history
    st.session_state.chat_history.append({
        'role': 'user',
        'content': user_question
    })
    
    # Run investigation
    with st.spinner("🔍 Investigating..."):
        try:
            investigation_result = investigate(user_question, df)
            
            # Format response
            response_text = investigation_result['summary']
            
            # Add assistant message to chat history
            st.session_state.chat_history.append({
                'role': 'assistant',
                'content': response_text,
                'results': investigation_result
            })
            
            st.rerun()
            
        except Exception as e:
            st.session_state.chat_history.append({
                'role': 'assistant',
                'content': f"❌ Error during investigation: {str(e)}",
                'results': None
            })
            st.rerun()

# Add footer with usage tips
st.markdown("---")
st.info("""
🔍 **How Data Detective Works:**

1. **Ask in plain English** - No need to know SQL or complex filter syntax
2. **AI translates** - Gemini converts your question into structured data filters
3. **Backend executes** - TrustGuardian applies filters to your security data
4. **Results summarized** - Get instant, actionable insights with recommended actions

**Note:** Data Detective uses your existing security data. It does not access external databases or execute code directly.
""")
