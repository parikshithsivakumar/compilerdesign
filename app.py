# app.py
import streamlit as st
import graphviz
import traceback
import os
import subprocess
import tempfile
from openai import AzureOpenAI
from dotenv import load_dotenv

# --- Our Project Analyzers ---
from analyzer.security import AstToDot
from analyzer.optimization.optimizer import Optimizer

# --- Load all variables from .env file ---
load_dotenv()

# --- Ensure Clang binaries are found ---
os.environ["PATH"] += os.pathsep + '/usr/bin'

# --- Read keys securely from .env ---
api_key = os.environ.get("AZURE_API_KEY")
api_endpoint = os.environ.get("AZURE_API_ENDPOINT")
deployment_name = os.environ.get("AZURE_DEPLOYMENT_NAME")

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

st.title("Visual Program Analyzer 🔬")
st.caption("A modern tool to analyze C code for security and optimization using GPT-4 and LLVM.")
st.divider()

# --- Azure OpenAI Configuration ---
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
    st.sidebar.warning("Azure credentials not found. Check your .env file.")

# --- Cached analyzers ---
@st.cache_resource
def get_security_converter():
    return AstToDot()

@st.cache_resource
def get_optimizer():
    return Optimizer()

security_converter = get_security_converter()
optimizer = get_optimizer()

# --- Azure helper functions ---
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
    Explain the optimization opportunity, give optimized code, and why it’s faster.
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

# --- NEW: LLVM optimization helper ---
def run_llvm_optimizations(c_code: str):
    """
    Uses LLVM to generate and optimize IR.
    Returns (before_IR, after_IR)
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            c_path = os.path.join(tmpdir, "input.c")
            ll_path = os.path.join(tmpdir, "input.ll")
            opt_path = os.path.join(tmpdir, "optimized.ll")

            # Write C source
            with open(c_path, "w") as f:
                f.write(c_code)

            # Generate LLVM IR
            subprocess.run(["clang", "-O0", "-emit-llvm", "-S", c_path, "-o", ll_path],
                           check=True, capture_output=True)

            # Run LLVM passes
            subprocess.run(["opt", "-S", ll_path, "-o", opt_path,
                            "-passes=mem2reg,dce,instcombine,gvn,licm"],
                           check=True, capture_output=True)

            # Read results
            with open(ll_path) as f: before_ir = f.read()
            with open(opt_path) as f: after_ir = f.read()
            return before_ir, after_ir
    except subprocess.CalledProcessError as e:
        return (f"LLVM error:\n{e.stderr.decode('utf-8')}", "")
    except Exception as e:
        return (f"Error running LLVM: {e}", "")

# --- Streamlit session management ---
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None

# --- Layout ---
col1, col2 = st.columns([1, 1.2], gap="large")

# --- Column 1: Code Editor ---
with col1:
    st.header("C Code Editor")
    c_code = st.text_area("Paste your C code:", height=800, value="""#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

int is_admin(int user_id);
void delete_file(const char* f);

int test_optimizations(int a, int b) {
    int buffer_size = 1024 * 4;
    int x = 10;
    int y = buffer_size + a;
    int c = a + b;
    int d = 20;
    int e = a + b;
    int total = 0;
    int max_val = 100;
    for (int i = 0; i < 10; i++) {
        int invariant_calc = max_val * 2;
        total = total + i + invariant_calc;
    }
    return c + e + total;
}

void process_data(int user_id, char* input) {
    is_admin(user_id);
    delete_file("system.db");
    char buffer[100];
    strcpy(buffer, input);
    char *api_key = "sk_live_12345";
    char *data = (char*)malloc(1024);
    data[0] = 'A';
    int fd = open("logfile.txt", 1, 0777);
    free(data);
    data[1] = 'B';
    if (user_id < 0) { goto error_handler; }
error_handler:
    return;
}
""")

    btn_col1, btn_col2 = st.columns(2)
    with btn_col1:
        submit_button = st.button("Submit Analysis", use_container_width=True, type="primary")
    with btn_col2:
        edit_button = st.button("Clear & Edit New", use_container_width=True)

# --- Column 2: Results ---
with col2:
    st.header("Analysis & Visualization")

    if submit_button:
        try:
            with st.spinner("Running analyses..."):
                dot_code, bugs_found = security_converter.generate_dot_and_bugs(c_code)
                optimizations_found = optimizer.analyze(c_code)
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
        tab1, tab2, tab3 = st.tabs(["🔒 Security", "📈 Optimization", "🌳 AST"])

        # --- Tab 1: Security ---
        with tab1:
            st.metric("Potential Risks Found", f"🔴 {len(results['bugs_found'])}")
            st.divider()
            if results['bugs_found']:
                for i, bug in enumerate(results['bugs_found']):
                    st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-header">Risk #{i+1}: {bug["bug_type"]}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-location">Line {bug["node"].location.line}</div>', unsafe_allow_html=True)
                    st.code(bug['source_text'], language="c")
                    if client:
                        st.markdown('<div class="gpt-header">GPT-4\'s Analysis:</div>', unsafe_allow_html=True)
                        suggestion = get_azure_openai_security_suggestion(
                            bug_type=bug['bug_type'],
                            bug_code=bug['source_text'],
                            func_name=bug['node'].spelling
                        )
                        if suggestion:
                            st.markdown(suggestion)
                    st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.success("🎉 No risks found!")

        # --- Tab 2: Optimization ---
        with tab2:
            st.metric("Optimization Opportunities", f"🟢 {len(results['optimizations_found'])}")
            st.divider()
            if results['optimizations_found']:
                for i, opt in enumerate(results['optimizations_found']):
                    st.markdown('<div class="analysis-card">', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-header">Opportunity #{i+1}: {opt["opt_type"]}</div>', unsafe_allow_html=True)
                    st.markdown(f'<div class="card-location">Line {opt["line"]}</div>', unsafe_allow_html=True)
                    st.code(opt['source_text'], language="c")
                    st.info(f"**Suggestion:** {opt['suggestion']}")
                    if client:
                        st.markdown('<div class="gpt-header">GPT-4 Explanation:</div>', unsafe_allow_html=True)
                        suggestion = get_azure_openai_optimization_suggestion(
                            opt_type=opt['opt_type'],
                            code_snippet=opt['source_text']
                        )
                        if suggestion:
                            st.markdown(suggestion)
                    st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.success("🎉 No simple optimizations found.")

            # --- LLVM IR before/after ---
            st.subheader("LLVM IR Optimization (Real Compiler Passes)")
            with st.spinner("Generating and optimizing LLVM IR..."):
                before_ir, after_ir = run_llvm_optimizations(c_code)
            tabs_ir = st.tabs(["🔍 Before Optimization (IR)", "⚙️ After Optimization (IR)"])
            with tabs_ir[0]:
                st.code(before_ir, language="llvm")
            with tabs_ir[1]:
                st.code(after_ir, language="llvm")

        # --- Tab 3: AST Graph ---
        with tab3:
            st.subheader("Abstract Syntax Tree")
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
