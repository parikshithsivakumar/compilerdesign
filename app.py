# app.py
import streamlit as st
import graphviz
import traceback
import os
from openai import AzureOpenAI
from dotenv import load_dotenv

# --- Import analyzers ---
from analyzer.security import AstToDot
from analyzer.optimization.optimizer import Optimizer

# --- Load .env ---
load_dotenv()

# --- Streamlit Config ---
st.set_page_config(
    layout="wide",
    page_title="Visual Program Analyzer",
    page_icon="🔬"
)

# --- Custom CSS ---
st.markdown("""
<style>
.block-container { padding: 2rem; }
.analysis-card {
    background-color: #0E1117;
    border: 1px solid #31333F;
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    transition: box-shadow 0.3s ease;
}
.analysis-card:hover { box-shadow: 0 6px 16px rgba(0, 0, 0, 0.4); }
.card-header { font-size: 1.25rem; font-weight: 600; color: #FAFAFA; margin-bottom: 0.5rem; }
.card-location { font-size: 0.9rem; color: #888; margin-bottom: 1rem; font-family: 'monospace'; }
.gpt-header { font-size: 1.1rem; font-weight: 600; color: #00A2FF; margin-top: 1.5rem; margin-bottom: 0.5rem;
              border-top: 1px dashed #31333F; padding-top: 1rem; }
</style>
""", unsafe_allow_html=True)

# --- App Title ---
st.title("Visual Program Analyzer 🔬")
st.caption("Analyze C code for security risks and compiler optimizations.")
st.divider()

# --- Azure OpenAI Configuration ---
api_key = os.environ.get("AZURE_API_KEY")
api_endpoint = os.environ.get("AZURE_API_ENDPOINT")
deployment_name = os.environ.get("AZURE_DEPLOYMENT_NAME")

client = None
if api_endpoint and api_key and deployment_name:
    try:
        client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-01",
            azure_endpoint=api_endpoint
        )
        st.sidebar.success("✅ Azure Client Configured")
    except Exception as e:
        st.sidebar.error(f"Error configuring Azure: {e}")
else:
    st.sidebar.warning("⚠️ Azure credentials not found. Check your .env file.")

# --- Cached Analyzer for Security ---
@st.cache_resource
def get_security_converter():
    return AstToDot()

security_converter = get_security_converter()

# --- Azure Helper Functions ---
@st.cache_data
def get_azure_openai_security_suggestion(bug_type, bug_code, func_name):
    if func_name in ["printf", "puts", "log_message"]:
        return None
    system_prompt = """
    You are an expert C code security auditor.
    Explain the security risk, suggest a safer version, and why it’s safer.
    Use Markdown.
    """
    user_prompt = f"""
    The tool flagged this line:
    ```c
    {bug_code}
    ```
    It classified this risk as: "{bug_type}"
    """
    if not client:
        return "Error: Azure client not configured."
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error calling Azure: {e}"

@st.cache_data
def get_azure_openai_optimization_suggestion(opt_type, code_snippet):
    system_prompt = """
    You are an expert compiler engineer.
    Explain the optimization opportunity, show an optimized version, and why it’s faster.
    Use Markdown.
    """
    user_prompt = f"""
    The tool flagged this line:
    ```c
    {code_snippet}
    ```
    It classified this optimization opportunity as: "{opt_type}"
    """
    if not client:
        return "Error: Azure client not configured."
    try:
        response = client.chat.completions.create(
            model=deployment_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error calling Azure: {e}"

# --- Streamlit Session ---
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None

# --- Layout ---
col1, col2 = st.columns([1, 1.2], gap="large")

# --- Column 1: Code Input ---
with col1:
    st.header("C Code Editor")
    c_code = st.text_area(
        "Paste your C code:",
        height=800,
        value="""#include <string.h>
#include <stdlib.h>

void process_data(int user_id, char* input) {
    char buffer[100];
    strcpy(buffer, input);
    int unused_var = 123;
    int z = 5 + 0;
    return;
}"""
    )

    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        submit_button = st.button("Submit Analysis", use_container_width=True, type="primary")
    with btn_col2:
        edit_button = st.button("Clear & Edit New", use_container_width=True)

# --- Column 2: Analysis Results ---
with col2:
    st.header("Analysis & Visualization")

    if submit_button:
        try:
            with st.spinner("Running analyses..."):
                # Security and Optimizer analysis
                dot_code, bugs_found = security_converter.generate_dot_and_bugs(c_code)
                optimizations_found = Optimizer.from_code(c_code)

            # Store results
            st.session_state.analysis_results = {
                "dot_code": dot_code,
                "bugs_found": bugs_found,
                "optimizations_found": optimizations_found
            }

        except Exception as e:
            st.error(f"Error analyzing code: {e}")
            st.code(traceback.format_exc())

    if edit_button:
        st.session_state.analysis_results = None
        st.rerun()

    if st.session_state.analysis_results:
        results = st.session_state.analysis_results
        tab1, tab2, tab3 = st.tabs(["🔒 Security", "⚙️ Optimization", "🌳 AST"])

        # --- Tab 1: Security ---
        with tab1:
            st.metric("Potential Risks Found", len(results['bugs_found']))
            st.divider()
            if results['bugs_found']:
                for i, bug in enumerate(results['bugs_found']):
                    st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-header">Risk #{i+1}: {bug["bug_type"]}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-location">Line {bug["node"].location.line}</div>', unsafe_allow_html=True)
                    st.code(bug['source_text'], language="c")
                    if client:
                        st.markdown('<div class="gpt-header">GPT-4 Analysis:</div>', unsafe_allow_html=True)
                        suggestion = get_azure_openai_security_suggestion(
                            bug_type=bug['bug_type'],
                            bug_code=bug['source_text'],
                            func_name=bug['node'].spelling
                        )
                        if suggestion:
                            st.markdown(suggestion)
                    st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.success("🎉 No security risks found!")

        # --- Tab 2: Optimization ---
        with tab2:
            st.metric("Optimization Opportunities", len(results['optimizations_found']))
            st.divider()
            if results['optimizations_found']:
                for i, opt in enumerate(results['optimizations_found']):
                    st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-header">Opportunity #{i+1}: {opt["opt_type"]}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-location">Line {opt["line"]}</div>', unsafe_allow_html=True)
                    st.code(opt["suggestion"], language="c")
                    if client:
                        st.markdown('<div class="gpt-header">GPT-4 Explanation:</div>', unsafe_allow_html=True)
                        suggestion = get_azure_openai_optimization_suggestion(
                            opt_type=opt['opt_type'],
                            code_snippet=opt['suggestion']
                        )
                        if suggestion:
                            st.markdown(suggestion)
                    st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.success("🎉 No optimizations found.")

        # --- Tab 3: AST Visualization ---
        with tab3:
            st.subheader("Abstract Syntax Tree (AST)")
            if results['dot_code']:
                try:
                    graph = graphviz.Source(results['dot_code'])
                    svg = graph.pipe(format="svg").decode("utf-8")
                    st.image(svg)
                    with st.expander("Show DOT Source"):
                        st.code(results['dot_code'], language="dot")
                except Exception as e:
                    st.error(f"Graphviz error: {e}")
            else:
                st.info("No AST to display.")
    else:
        st.info("Paste your C code and click 'Submit Analysis' to begin.")
